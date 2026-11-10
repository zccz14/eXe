//! Keeping a device current without a person visiting it.
//!
//! The check is a pull and the answer is signed: `manifest.json` next to
//! `manifest.json.sig`, verified against the release key compiled into this
//! binary (see `exe_core::release`). Then one bare binary is downloaded, checked
//! against the checksum the manifest names, run once (`exe version`) to prove it
//! actually executes, and swapped in as a *rename* — never a rewrite, because
//! macOS kills a process whose mapped pages change underneath it.
//!
//! The swap is deliberately short: back up what is running, write down a `trial`,
//! move the new file into place, and leave. Whoever supervises the device —
//! launchd, systemd, the macOS app, the logon task — starts the same path again,
//! which is now the new version. If that process does not stay up (`STABLE`), the
//! next start puts the backup back and blocks the version, so a broken release
//! costs one restart instead of a device.
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use exe_core::release::{self, ReleaseFile, ReleaseManifest};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::config::{self, Config};
use crate::service;

/// The version this binary is; every other version is compared with it.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// How long a freshly installed binary has to stay up before the update counts.
/// Far shorter than a release cycle, long enough that a crash loop cannot be
/// mistaken for a slow start.
const STABLE: Duration = Duration::from_secs(90);

/// The second start of a trial version is the rollback trigger: the first one
/// either died before confirming, or is still inside `STABLE`.
const ATTEMPTS: u32 = 2;

/// A version that failed here is never tried again — the next release is a
/// different bet. Small on purpose: this is a memory, not a history.
const BLOCKED_KEPT: usize = 8;

/// Who is calling: the device process itself, or a CLI next to a running device.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// This process *is* the device; leaving is what starts the new binary.
    Daemon,
    /// A human typed `exe upgrade`; the device that has to move is elsewhere.
    Manual,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    /// Installed and running for the first time: waiting to prove itself.
    Trial,
    /// Running, with nothing left to prove.
    #[default]
    Ok,
    /// The backup was put back, and `to` is blocked.
    RolledBack,
}

/// `update.json`: the one file that has to survive a restart between the two
/// binaries, so it carries both the rollback material and what the last check saw.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    phase: Phase,
    /// The version that was running before the swap; also the backup's name.
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    at: u64,
    #[serde(default)]
    backup: Option<String>,
    /// Versions this device rolled back from.
    #[serde(default)]
    blocked: Vec<String>,
    #[serde(default)]
    checked_at: u64,
    #[serde(default)]
    seen: String,
}

fn state_path() -> PathBuf {
    config::config_dir().join("update.json")
}

fn backup_dir() -> PathBuf {
    config::config_dir().join("bin")
}

fn load_state() -> State {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_state(state: &State) -> Result<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(state)?))?;
    Ok(())
}

/// The release asset suffix for this machine, mirroring `scripts/install.sh` and
/// the matrix in `release.yml`. `None` when no prebuilt binary exists for this
/// platform — a device nobody publishes for must not try to update itself.
fn target() -> Option<&'static str> {
    if cfg!(target_env = "musl") {
        return None;
    }
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => return None,
    })
}

/// The bare binary the updater wants: no archive to unpack, nothing to guess
/// about paths, one checksum to check.
pub fn asset_name() -> Option<String> {
    target().map(|target| format!("exe-{target}.bin"))
}

pub fn supported() -> bool {
    asset_name().is_some()
}

fn current_exe() -> Result<PathBuf> {
    let path = std::env::current_exe().context("could not find this binary")?;
    Ok(path.canonicalize().unwrap_or(path))
}

/// The newest release a relay publishes with a signature this binary accepts.
pub async fn latest(
    http: &reqwest::Client,
    endpoints: &[String],
) -> Result<(String, ReleaseManifest)> {
    let mut failures = Vec::new();
    for endpoint in endpoints {
        match signed_manifest(http, endpoint).await {
            Ok(manifest) => return Ok((endpoint.clone(), manifest)),
            Err(error) => failures.push(format!("{endpoint}: {error:#}")),
        }
    }
    bail!(
        "no relay published a signed release ({})",
        failures.join("; ")
    )
}

async fn signed_manifest(http: &reqwest::Client, endpoint: &str) -> Result<ReleaseManifest> {
    // The bytes and the signature over those bytes, in that order: the manifest
    // is never parsed before it is known who wrote it.
    let manifest = http
        .get(format!("{endpoint}/api/releases/manifest.json"))
        .timeout(Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let signature = http
        .get(format!("{endpoint}/api/releases/manifest.json.sig"))
        .timeout(Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(release::verify_manifest(&manifest, &signature)?)
}

/// Downloads one release, proves it is what the signature says, and swaps it in.
pub async fn install(
    http: &reqwest::Client,
    endpoint: &str,
    manifest: &ReleaseManifest,
    mode: Mode,
) -> Result<()> {
    let Some(name) = asset_name() else {
        bail!(
            "no prebuilt binary for {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };
    let Some(asset) = manifest.file(&name).cloned() else {
        bail!("release {} does not publish {name}", manifest.version);
    };
    let url = format!("{endpoint}/download/{name}");
    let bytes = http
        .get(&url)
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .with_context(|| format!("could not download {url}"))?
        .error_for_status()?
        .bytes()
        .await?;
    check(&asset, &bytes)?;

    let current = current_exe()?;
    let staged = current.with_file_name(format!(".exe.new.{}", std::process::id()));
    std::fs::write(&staged, &bytes)
        .with_context(|| format!("could not write {}", staged.display()))?;
    executable(&staged)?;
    if let Err(error) = run_once(&staged, &manifest.version) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }

    let backup = backup_dir().join(format!("exe-{CURRENT}"));
    if let Some(parent) = backup.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(&current, &backup)
        .with_context(|| format!("could not back up this binary to {}", backup.display()))?;
    executable(&backup)?;

    let mut state = load_state();
    state.phase = Phase::Trial;
    state.from = CURRENT.to_owned();
    state.to = manifest.version.clone();
    state.attempts = 0;
    state.at = exe_core::unix_now();
    state.backup = Some(backup.display().to_string());
    save_state(&state)?;

    swap(&staged, &current)?;
    info!(
        from = CURRENT,
        to = manifest.version.as_str(),
        "installed; handing over to the new binary"
    );
    hand_over(&current, mode)
}

/// The signed manifest is the authority for both the length and the content.
fn check(asset: &ReleaseFile, bytes: &[u8]) -> Result<()> {
    if asset.size != 0 && bytes.len() as u64 != asset.size {
        bail!(
            "{} is {} bytes, the signed manifest says {}",
            asset.name,
            bytes.len(),
            asset.size
        );
    }
    let Some(expected) = asset.sha256.as_deref() else {
        bail!("{} is listed without a checksum", asset.name);
    };
    if !expected.eq_ignore_ascii_case(&exe_core::sha256_hex(bytes)) {
        bail!("{} does not match its signed checksum", asset.name);
    }
    Ok(())
}

/// A binary that cannot even say its own version is not a binary that may replace
/// one that runs: this catches a truncated download and the wrong architecture
/// before the device has moved anywhere.
fn run_once(staged: &Path, version: &str) -> Result<()> {
    let output = Command::new(staged)
        .arg("version")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("{} does not run here", staged.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || printed != format!("exe {version}") {
        bail!(
            "{} does not run as {version}: {} {}",
            staged.display(),
            printed,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// The move itself. A rename is the only thing that never leaves a half-written
/// binary at the path a supervisor is about to exec.
fn swap(staged: &Path, current: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        // Windows refuses to replace or delete a running image, but it does allow
        // renaming it: the process keeps its handle while the path becomes free.
        let name = current
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("exe");
        let retired = current.with_file_name(format!("{name}.old.{}", std::process::id()));
        std::fs::rename(current, &retired)
            .with_context(|| format!("could not move {} aside", current.display()))?;
    }
    std::fs::rename(staged, current)
        .with_context(|| format!("could not move {} into place", staged.display()))?;
    Ok(())
}

/// Ends this process where that is what starts the new binary.
fn hand_over(current: &Path, mode: Mode) -> Result<()> {
    if mode == Mode::Manual {
        return bounce();
    }
    // Someone is watching this output (`exe run` in a terminal): they decide when
    // the device restarts, and nothing is lost by leaving the old inode running.
    if std::io::stdout().is_terminal() {
        println!("installed; restart it when ready: `exe restart` or `exe`");
        return Ok(());
    }
    match supervisor() {
        // Leaving *is* the restart: one of these is running this very process and
        // will start the same path again.
        Supervisor::Service | Supervisor::App => {
            info!("leaving so the supervisor starts the new binary");
            std::process::exit(0);
        }
        // A logon task, a container, or a supervisor of the user's own: start the
        // replacement here, because nothing else will.
        Supervisor::None => {
            spawn_replacement(current)?;
            std::process::exit(0);
        }
    }
}

/// Who will start this path again when this process leaves.
///
/// Both answers matter: exiting with nobody to restart leaves the device offline,
/// and starting a replacement *under* a supervisor races that supervisor for the
/// address lock — the loser then reports "already owns this address", which the
/// macOS app reads as "hand the device over" and stops supervising for good.
enum Supervisor {
    /// launchd `KeepAlive` / systemd `Restart=always`, and it is running us.
    Service,
    /// The macOS app hosts the device as a child process and restarts it.
    App,
    None,
}

fn supervisor() -> Supervisor {
    if matches!(
        service::detect(),
        service::Kind::LaunchAgent | service::Kind::SystemdUser
    ) && service::state() == "running"
    {
        return Supervisor::Service;
    }
    #[cfg(target_os = "macos")]
    if hosted_by_app() {
        return Supervisor::App;
    }
    Supervisor::None
}

/// The parent of a device the app hosts is the bundle executable itself, so the
/// process table is the honest answer: a launchd unit and an app-hosted device
/// are otherwise indistinguishable from inside (`service::state()` is
/// "not installed" for both).
#[cfg(target_os = "macos")]
fn hosted_by_app() -> bool {
    let parent = unsafe { libc::getppid() };
    std::process::Command::new("ps")
        .args(["-o", "comm=", "-p", &parent.to_string()])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .map(|command| command.ends_with("exe.app/Contents/MacOS/exe-app"))
        .unwrap_or(false)
}

fn spawn_replacement(current: &Path) -> Result<()> {
    let mut command = Command::new(current);
    command
        .arg("__relaunch")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // A windowless task must not grow a console just because it restarted.
        command.creation_flags(0x0800_0000);
    }
    command
        .spawn()
        .with_context(|| format!("could not start {}", current.display()))?;
    Ok(())
}

/// `exe upgrade` next to a running device: the process that has to move is not
/// this one, so bounce whatever holds the address.
fn bounce() -> Result<()> {
    if service::state() == "running" {
        service::stop()?;
        service::start()?;
        println!("restarted     the background service");
        return Ok(());
    }
    match crate::lock::holder() {
        Some(pid) => {
            #[cfg(unix)]
            {
                // The app, the shell or whatever started it decides what happens
                // next; a supervisor starts the new file, a terminal prints the
                // command back.
                unsafe { libc::kill(pid as i32, libc::SIGTERM) };
                println!("restarted     asked the running device (pid {pid}) to stop");
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
                service::stop()?;
                service::start()?;
                println!("restarted     the logon task");
            }
            Ok(())
        }
        None => {
            println!("done          nothing is running here; the new version starts next time");
            Ok(())
        }
    }
}

/// Called once at the start of `exe run`: settles a pending upgrade before the
/// device registers, so the first thing the relay hears is the version it will
/// be keeping.
pub fn begin_trial() -> Result<()> {
    let mut state = load_state();
    if state.phase != Phase::Trial {
        return Ok(());
    }
    if state.to != CURRENT {
        // Something else put this binary here (a re-install, a swap that never
        // happened). There is nothing to confirm and nothing to undo.
        warn!(
            trial = state.to.as_str(),
            running = CURRENT,
            "the trial version is not the one running; forgetting it"
        );
        state.phase = Phase::Ok;
        return save_state(&state);
    }
    state.attempts += 1;
    if state.attempts >= ATTEMPTS {
        return rollback(&mut state);
    }
    save_state(&state)?;
    tokio::spawn(confirm());
    Ok(())
}

/// The version proved itself by staying up; what is left is bookkeeping.
async fn confirm() {
    tokio::time::sleep(STABLE).await;
    let mut state = load_state();
    if state.phase != Phase::Trial || state.to != CURRENT {
        return;
    }
    state.phase = Phase::Ok;
    state.attempts = 0;
    match save_state(&state) {
        Ok(()) => info!(version = CURRENT, "update confirmed: still running"),
        Err(error) => warn!(%error, "could not record that the update is good"),
    }
}

/// Puts the backup back and blocks the version that failed here.
fn rollback(state: &mut State) -> Result<()> {
    let Some(backup) = state.backup.clone().map(PathBuf::from) else {
        state.phase = Phase::Ok;
        save_state(state)?;
        bail!("the new version did not stay up and no backup was recorded");
    };
    let current = current_exe()?;
    let staged = current.with_file_name(format!(".exe.revert.{}", std::process::id()));
    std::fs::copy(&backup, &staged)
        .with_context(|| format!("could not read the backup at {}", backup.display()))?;
    executable(&staged)?;
    swap(&staged, &current)?;

    state.phase = Phase::RolledBack;
    state.blocked.push(state.to.clone());
    if state.blocked.len() > BLOCKED_KEPT {
        state.blocked.remove(0);
    }
    state.attempts = 0;
    save_state(state)?;
    error!(
        version = state.to.as_str(),
        back_to = state.from.as_str(),
        "the new version did not stay up; rolled back and blocked it"
    );
    hand_over(&current, Mode::Daemon)
}

/// True while a call is being executed. The swap ends this process, and a call
/// cut in half is a call the caller has to guess about.
pub type Busy = Arc<dyn Fn() -> bool + Send + Sync>;

/// The background check `exe run` keeps. One small GET an hour; a release reaches
/// a device while the person who cut it is still watching.
pub async fn serve(http: reqwest::Client, endpoints: Vec<String>, interval: Duration, busy: Busy) {
    // Not the first thing a fresh start does: registering and opening the stream
    // come first, and a device that just came up has nothing to install anyway.
    tokio::time::sleep(settle(interval)).await;
    loop {
        match attempt(&http, &endpoints, &busy).await {
            Ok(()) => {}
            Err(error) => warn!(%error, "update check failed"),
        }
        tokio::time::sleep(interval).await;
    }
}

fn settle(interval: Duration) -> Duration {
    (interval / 12)
        .max(Duration::from_secs(120))
        .min(Duration::from_secs(600))
}

async fn attempt(http: &reqwest::Client, endpoints: &[String], busy: &Busy) -> Result<()> {
    let (endpoint, manifest) = latest(http, endpoints).await?;
    let mut state = load_state();
    state.checked_at = exe_core::unix_now();
    state.seen = manifest.version.clone();
    save_state(&state)?;
    if !release::is_newer(&manifest.version, CURRENT) {
        debug!(
            version = manifest.version.as_str(),
            "this device is current"
        );
        return Ok(());
    }
    if state.blocked.contains(&manifest.version) {
        warn!(
            version = manifest.version.as_str(),
            "skipping a version this device already rolled back from"
        );
        return Ok(());
    }
    if state.phase == Phase::Trial && state.to == manifest.version {
        debug!(
            version = manifest.version.as_str(),
            "installed already; waiting for the restart"
        );
        return Ok(());
    }
    // Let a call finish first: the swap ends this process.
    for _ in 0..20 {
        if !busy() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
    if busy() {
        info!("postponing the update: a call is still running");
        return Ok(());
    }
    info!(
        from = CURRENT,
        to = manifest.version.as_str(),
        "a newer release is published; installing"
    );
    install(http, &endpoint, &manifest, Mode::Daemon).await
}

/// One line for `exe status`: what the device is set to do and where it stands.
pub fn summary(config: &Config) -> String {
    let state = load_state();
    let mut line = if config.update.auto {
        format!("auto, every {}", human(config.update.interval_seconds))
    } else {
        "manual (`exe upgrade`)".to_owned()
    };
    if !state.seen.is_empty() {
        let ago = exe_core::unix_now().saturating_sub(state.checked_at);
        line.push_str(&format!(", last seen v{} {} ago", state.seen, human(ago)));
    }
    match state.phase {
        Phase::Trial => line.push_str(&format!(", v{} installed, unconfirmed", state.to)),
        Phase::RolledBack => line.push_str(&format!(", v{} rolled back", state.to)),
        Phase::Ok => {}
    }
    line
}

fn human(seconds: u64) -> String {
    match seconds {
        0..=90 => format!("{seconds}s"),
        91..=3599 => format!("{}m", (seconds + 30) / 60),
        _ => format!("{}h", (seconds + 1800) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_asset_name_matches_the_release_matrix() {
        if !supported() {
            return;
        }
        let name = asset_name().unwrap();
        assert!(name.starts_with("exe-") && name.ends_with(".bin"), "{name}");
        assert!(!name.contains(' '));
    }

    #[test]
    fn a_checksum_mismatch_is_refused() {
        let asset = ReleaseFile {
            name: "exe-x.bin".into(),
            size: 3,
            sha256: Some("00".repeat(32)),
        };
        assert!(check(&asset, b"abc").is_err(), "wrong digest");
        let good = ReleaseFile {
            name: "exe-x.bin".into(),
            size: 3,
            sha256: Some(exe_core::sha256_hex(b"abc")),
        };
        assert!(check(&good, b"abc").is_ok());
        let short = ReleaseFile {
            name: "exe-x.bin".into(),
            size: 4,
            sha256: Some(exe_core::sha256_hex(b"abc")),
        };
        assert!(check(&short, b"abc").is_err(), "truncated download");
    }

    #[test]
    fn durations_read_like_a_schedule() {
        assert_eq!(human(45), "45s");
        assert_eq!(human(3600), "1h");
        assert_eq!(human(1800), "30m");
    }
}

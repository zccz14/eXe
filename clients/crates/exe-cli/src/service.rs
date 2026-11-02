//! The device is a background service; `exe` is the setup, not the daemon.
//!
//! Every platform calls this thing something else and gets a different detail
//! wrong, so the shape of the answer is fixed here once:
//!
//! - **Linux** — a `systemd --user` unit. `enable-linger` is attempted so the
//!   device comes back after a reboot without anyone logging in; without it the
//!   unit only starts with the user's session.
//! - **macOS** — a LaunchAgent, never a root daemon: what a device needs (the
//!   screen, the keyboard, the user's own files) only exists in the user's GUI
//!   session, and TCC grants are per-user anyway.
//! - **Windows** — a task that runs at logon, for the same reason: a service
//!   lives in session 0 and cannot touch the desktop.
//! - **Anything else** (containers, Alpine) — no supervisor. `exe run` stays in
//!   the foreground and that is the correct answer there.
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LABEL: &str = "io.ntnl.exe";
const UNIT: &str = "exe.service";
const TASK: &str = "exe";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SystemdUser,
    LaunchAgent,
    ScheduledTask,
    None,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::SystemdUser => "systemd --user",
            Kind::LaunchAgent => "launchd agent",
            Kind::ScheduledTask => "logon task",
            Kind::None => "none",
        }
    }
}

pub fn log_path() -> PathBuf {
    crate::config::config_dir().join("exe.log")
}

fn home() -> PathBuf {
    PathBuf::from(
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into()),
    )
}

fn unit_path() -> PathBuf {
    home()
        .join(".config")
        .join("systemd")
        .join("user")
        .join(UNIT)
}

fn plist_path() -> PathBuf {
    home()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

pub fn detect() -> Kind {
    if cfg!(windows) {
        return Kind::ScheduledTask;
    }
    if cfg!(target_os = "macos") {
        return Kind::LaunchAgent;
    }
    if cfg!(unix) && Path::new("/run/systemd/system").exists() {
        return Kind::SystemdUser;
    }
    Kind::None
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("could not run `{program}`"))?;
    if !output.status.success() {
        bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn quiet(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn config_env() -> Option<String> {
    std::env::var("EXE_CONFIG_DIR")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Installs the supervisor entry and starts it. Returns the kind that was used.
pub fn install(exe: &Path) -> Result<Kind> {
    let kind = detect();
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let exe = exe.display().to_string();
    let log = log_path();
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match kind {
        Kind::SystemdUser => {
            let mut unit = format!(
                "[Unit]\nDescription=eXe device\nAfter=network-online.target\n\n\
                 [Service]\nExecStart=\"{exe}\" run\nRestart=always\nRestartSec=5\n\
                 StandardOutput=append:{log}\nStandardError=append:{log}\n",
                log = log.display()
            );
            if let Some(dir) = config_env() {
                unit.push_str(&format!("Environment=EXE_CONFIG_DIR={dir}\n"));
            }
            unit.push_str("\n[Install]\nWantedBy=default.target\n");
            let path = unit_path();
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, unit)?;
            run("systemctl", &["--user", "daemon-reload"])?;
            run("systemctl", &["--user", "enable", "--now", UNIT])?;
            // Best effort: without lingering, a user unit only runs while the
            // user is logged in. Not fatal — the device just needs a session.
            let _ = quiet("loginctl", &["enable-linger"]);
            Ok(kind)
        }
        Kind::LaunchAgent => {
            let mut environment = String::new();
            if let Some(dir) = config_env() {
                environment = format!(
                    "  <key>EnvironmentVariables</key>\n  <dict><key>EXE_CONFIG_DIR</key><string>{dir}</string></dict>\n"
                );
            }
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
{environment}</dict>
</plist>
"#,
                label = LABEL,
                exe = exe,
                log = log.display(),
            );
            let path = plist_path();
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(&path, plist)?;
            let domain = format!("gui/{}", uid());
            let _ = quiet("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
            if run(
                "launchctl",
                &["bootstrap", &domain, &path.display().to_string()],
            )
            .is_err()
            {
                // Older systems only know the legacy spelling.
                run("launchctl", &["load", "-w", &path.display().to_string()])?;
            }
            Ok(kind)
        }
        Kind::ScheduledTask => {
            let command = format!("\"{exe}\" run");
            run(
                "schtasks",
                &[
                    "/Create", "/F", "/SC", "ONLOGON", "/TN", TASK, "/TR", &command,
                ],
            )?;
            let _ = quiet("schtasks", &["/Run", "/TN", TASK]);
            Ok(kind)
        }
        Kind::None => Ok(kind),
    }
}

pub fn uninstall() -> Result<()> {
    match detect() {
        Kind::SystemdUser => {
            let _ = quiet("systemctl", &["--user", "disable", "--now", UNIT]);
            let path = unit_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            let _ = quiet("systemctl", &["--user", "daemon-reload"]);
            Ok(())
        }
        Kind::LaunchAgent => {
            let domain = format!("gui/{}", uid());
            let _ = quiet("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
            let path = plist_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            Ok(())
        }
        Kind::ScheduledTask => {
            let _ = quiet("schtasks", &["/End", "/TN", TASK]);
            let _ = quiet("schtasks", &["/Delete", "/F", "/TN", TASK]);
            Ok(())
        }
        Kind::None => Ok(()),
    }
}

pub fn start() -> Result<()> {
    match detect() {
        Kind::SystemdUser => run("systemctl", &["--user", "start", UNIT]).map(|_| ()),
        Kind::LaunchAgent => {
            let domain = format!("gui/{}", uid());
            let path = plist_path();
            if !path.exists() {
                bail!("the service is not installed; run `exe` first");
            }
            run(
                "launchctl",
                &["bootstrap", &domain, &path.display().to_string()],
            )
            .map(|_| ())
        }
        Kind::ScheduledTask => run("schtasks", &["/Run", "/TN", TASK]).map(|_| ()),
        Kind::None => bail!("no service manager here; run `exe run` in the foreground"),
    }
}

pub fn stop() -> Result<()> {
    match detect() {
        Kind::SystemdUser => run("systemctl", &["--user", "stop", UNIT]).map(|_| ()),
        Kind::LaunchAgent => {
            let domain = format!("gui/{}", uid());
            run("launchctl", &["bootout", &format!("{domain}/{LABEL}")]).map(|_| ())
        }
        Kind::ScheduledTask => run("schtasks", &["/End", "/TN", TASK]).map(|_| ()),
        Kind::None => bail!("no service manager here"),
    }
}

/// `running`, `stopped`, or `not installed` — plus the supervisor's own name.
pub fn state() -> String {
    match detect() {
        Kind::SystemdUser => {
            if !unit_path().exists() {
                return "not installed".into();
            }
            let active = Command::new("systemctl")
                .args(["--user", "is-active", UNIT])
                .stdin(Stdio::null())
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
                .unwrap_or_default();
            if active == "active" {
                "running".into()
            } else if active.is_empty() {
                "unknown".into()
            } else {
                active
            }
        }
        Kind::LaunchAgent => {
            if !plist_path().exists() {
                return "not installed".into();
            }
            let domain = format!("gui/{}", uid());
            if quiet("launchctl", &["print", &format!("{domain}/{LABEL}")]) {
                "running".into()
            } else {
                "stopped".into()
            }
        }
        Kind::ScheduledTask => {
            let out = Command::new("schtasks")
                .args(["/Query", "/TN", TASK])
                .stdin(Stdio::null())
                .output();
            match out {
                Ok(out) if out.status.success() => "running".into(),
                Ok(_) => "not installed".into(),
                Err(_) => "unknown".into(),
            }
        }
        Kind::None => "not available".into(),
    }
}

#[cfg(unix)]
fn uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn uid() -> u32 {
    0
}

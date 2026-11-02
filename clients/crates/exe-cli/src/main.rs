use anyhow::{bail, Context, Result};
use exe::{config, lock, logs, mcp, run, service};
use exe_core::protocol::request_headers;
use exe_core::{parse_address, Identity};
use std::io::IsTerminal;

const HELP: &str = "\
exe — eXe client

USAGE:
    exe                      Set this machine up as a device: create its key, install
                             the background service, start it, and report whether the
                             relay can see it. Safe to run again at any time.
    exe --trust <address>    The same, and allow calls from these caller addresses.
    exe status               Address, trust list, service state and what the relay sees.
    exe trust <address>      Allow calls signed by this address (hot: no restart).
    exe untrust <address>    Stop allowing calls from this address (hot).
    exe logs [-f]            Read the device log; -f follows it.
    exe start | stop | restart
    exe doctor               Check the key, the trust list and relay reachability.
    exe uninstall [--purge]  Remove the background service (and, with --purge, this key).
    exe run                  Run in the foreground: containers, or your own supervisor.
    exe mcp init             Create the caller key used by `exe mcp`, and print its address.
    exe mcp                  Serve MCP on stdio for an agent harness (it spawns this).
    exe forget               Delete this device's key.
    exe version
";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // A service writes to a file: colour escapes there are noise in `exe logs`.
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // `exe --trust <address>` is the setup path with an argument.
    let mut trust: Vec<String> = Vec::new();
    while let Some(position) = args.iter().position(|arg| arg == "--trust") {
        if position + 1 >= args.len() {
            bail!("--trust needs an address");
        }
        trust.push(args.remove(position + 1));
        args.remove(position);
    }
    let command = args.first().cloned().unwrap_or_default();
    match command.as_str() {
        "" => setup(trust).await,
        "status" => status().await,
        "trust" => trust_command(args[1..].to_vec()),
        "untrust" => untrust_command(args[1..].to_vec()),
        "logs" => logs_command(args.get(1).map(String::as_str) == Some("-f")),
        "start" => service::start(),
        "stop" => service::stop(),
        "restart" => {
            service::stop()?;
            service::start()
        }
        "uninstall" => uninstall(args.iter().any(|arg| arg == "--purge")),
        "run" => {
            let (cfg, created) = config::load_or_create()?;
            announce(&cfg, created);
            run::run(cfg).await
        }
        "mcp" => match args.get(1).map(String::as_str) {
            Some("init") => mcp_command(true).await,
            None => mcp_command(false).await,
            Some(other) => bail!("unknown `exe mcp {other}`; try `exe mcp init`"),
        },
        "init" => {
            // Kept for scripts that only want a key; `exe` does the whole setup.
            let (cfg, created) = config::load_or_create()?;
            announce(&cfg, created);
            Ok(())
        }
        "doctor" => doctor().await,
        "forget" => {
            let path = config::config_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
                println!("Removed {}.", path.display());
                println!("The address stays callable until it is removed from every caller.");
                println!("Run `exe` for a new key.");
            } else {
                println!("No configuration at {}.", path.display());
            }
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("exe {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => {
            eprintln!("unknown command `{other}`\n");
            print!("{HELP}");
            std::process::exit(2);
        }
    }
}

/// The whole first-run experience: key, service, proof. Idempotent on purpose —
/// when something is wrong this is the first command a person types.
async fn setup(trust: Vec<String>) -> Result<()> {
    let (mut cfg, created) = config::load_or_create()?;
    if !trust.is_empty() {
        allow(&mut cfg, &trust)?;
        config::save(&cfg)?;
    }
    announce(&cfg, created);

    // The service itself holds the lock, so "someone holds it" is only a problem
    // when it is not the service: that is a foreground `exe run`, and installing
    // over it would fight for the address. When the service is the holder,
    // reinstalling is exactly how an upgrade switches binaries — bootout,
    // bootstrap, new process, same key.
    if lock::holder().is_some() && service::state() != "running" {
        println!("service       a foreground `exe run` is holding this address");
        println!("              stop it first (Ctrl-C), then run `exe` again");
        return Ok(());
    }
    let exe = std::env::current_exe().context("could not find this binary")?;
    let kind = service::install(&exe)?;
    if kind == service::Kind::None {
        println!("service       none on this system — run `exe run` in the foreground");
        println!("              (containers and systems without systemd/launchd)");
        return Ok(());
    }
    println!("service       installed and started ({})", kind.label());

    let seen = wait_until_registered(&cfg, std::time::Duration::from_secs(20)).await;
    match seen {
        Some(true) => println!("relay         registered and online"),
        Some(false) => println!("relay         registered, not online yet — check `exe logs`"),
        None => println!("relay         not visible yet — check `exe logs`"),
    }
    println!("log           {}", logs::path().display());
    println!();
    if cfg.trust.is_empty() {
        println!("  Next: a caller must be allowed before anything can run here.");
        println!("        `exe --trust <caller address>` — or paste this device into the console:");
        println!("        {}", cfg.address()?);
    } else {
        println!("  Next: paste this device address into the caller:");
        println!("        {}", cfg.address()?);
    }
    Ok(())
}

fn allow(cfg: &mut config::Config, addresses: &[String]) -> Result<()> {
    for address in addresses {
        parse_address(address).map_err(|_| anyhow::anyhow!("`{address}` is not an eXe address"))?;
        if !cfg.trust.contains(address) {
            cfg.trust.push(address.clone());
        }
    }
    Ok(())
}

/// Adding a caller is hot: the running device re-reads its list and re-registers,
/// so the relay's copy of `trust` is fresh without anyone restarting anything.
fn trust_command(addresses: Vec<String>) -> Result<()> {
    if addresses.is_empty() {
        bail!("usage: exe trust <address> [address...]");
    }
    let (mut cfg, _) = config::load_or_create()?;
    allow(&mut cfg, &addresses)?;
    config::save(&cfg)?;
    println!("trust = {:?}", cfg.trust);
    match signal_reload() {
        Some(pid) => println!("Reloaded the running device (pid {pid})."),
        None => println!("No device is running; it will pick this up when it starts."),
    }
    Ok(())
}

/// The other half of `trust`, and the one the threat model leans on: revocation
/// is local, immediate, and never something the relay can do.
fn untrust_command(addresses: Vec<String>) -> Result<()> {
    if addresses.is_empty() {
        bail!("usage: exe untrust <address> [address...]");
    }
    let (mut cfg, _) = config::load_or_create()?;
    let before = cfg.trust.len();
    cfg.trust.retain(|entry| !addresses.contains(entry));
    if cfg.trust.len() == before {
        println!("None of those addresses were allowed.");
    }
    config::save(&cfg)?;
    println!("trust = {:?}", cfg.trust);
    match signal_reload() {
        Some(pid) => println!("Reloaded the running device (pid {pid})."),
        None => println!("No device is running; it will pick this up when it starts."),
    }
    Ok(())
}

fn signal_reload() -> Option<u32> {
    let pid = lock::holder()?;
    #[cfg(unix)]
    {
        if unsafe { libc::kill(pid as i32, libc::SIGHUP) } == 0 {
            return Some(pid);
        }
        None
    }
    #[cfg(not(unix))]
    {
        // No SIGHUP here: bounce the supervisor instead.
        let _ = service::stop();
        let _ = service::start();
        Some(pid)
    }
}

fn logs_command(follow: bool) -> Result<()> {
    if follow {
        return logs::follow(std::io::stdout());
    }
    println!("{}", logs::tail(80)?);
    Ok(())
}

fn uninstall(purge: bool) -> Result<()> {
    service::uninstall()?;
    println!("service       removed");
    if purge {
        for path in [
            config::config_path(),
            mcp::path(),
            logs::path(),
            config::config_dir().join("run.lock"),
        ] {
            if path.exists() {
                std::fs::remove_file(&path)?;
                println!("removed       {}", path.display());
            }
        }
        println!();
        println!("  Gone locally. Two things stay:");
        println!("    - the address is still registered at the relay (it expires on its own)");
        println!("    - every caller that lists this device still lists it");
    } else {
        println!("config        kept at {}", config::config_path().display());
        println!("              `exe uninstall --purge` also deletes the key");
    }
    Ok(())
}

/// `exe mcp init` explains; `exe mcp` serves. Nothing is printed on stdout while
/// serving — stdout is the protocol.
async fn mcp_command(init_only: bool) -> Result<()> {
    let (cfg, _created) = mcp::load_or_create()?;
    let address = cfg.identity()?.address();
    // While serving, stdout is the protocol: every word of this goes to stderr.
    let say = |line: String| {
        if init_only {
            println!("{line}");
        } else {
            eprintln!("{line}");
        }
    };
    say(String::new());
    say(format!("  This caller:  \x1b[1m{address}\x1b[0m"));
    say(format!("  Config:       {}", mcp::path().display()));
    if cfg.devices.is_empty() {
        say("  Devices:      none yet — add `label = \"<device address>\"` under [devices]".into());
    } else {
        say(format!(
            "  Devices:      {}",
            cfg.devices.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    say(String::new());
    say(format!(
        "  Allow this caller on each device:  exe trust {address}"
    ));
    say(format!(
        "  Point a harness at it:             claude mcp add {} -- {} mcp",
        cfg.tool_prefix,
        std::env::current_exe()?.display()
    ));
    if init_only {
        return Ok(());
    }
    mcp::serve().await
}

fn announce(cfg: &config::Config, created: bool) {
    let address = cfg.address().unwrap_or_else(|_| "<invalid secret>".into());
    println!();
    if created {
        println!(
            "  Generated a new key at {}",
            config::config_path().display()
        );
    }
    println!("  This device:  \x1b[1m{address}\x1b[0m");
    println!("  Relay:        {}", cfg.endpoints().join(", "));
    if cfg.trust.is_empty() {
        println!("  Callers:      (none — every call will be refused)");
    } else {
        println!("  Callers:      {}", cfg.trust.join(", "));
    }
    println!();
}

async fn wait_until_registered(cfg: &config::Config, budget: std::time::Duration) -> Option<bool> {
    let identity = cfg.identity().ok()?;
    let started = std::time::Instant::now();
    loop {
        if let Some(view) = probe_device(cfg, &identity).await {
            if view.0 {
                return Some(view.1);
            }
        }
        if started.elapsed() > budget {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// `(registered, online, platform)` straight from the relay.
async fn probe_device(
    cfg: &config::Config,
    identity: &Identity,
) -> Option<(bool, bool, Option<String>)> {
    let http = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    for endpoint in cfg.endpoints() {
        if let Ok(response) = http
            .get(format!("{endpoint}/api/health"))
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
        {
            if !response.status().is_success() {
                continue;
            }
        } else {
            continue;
        }
        let path = format!("/api/devices/{}", identity.address());
        let mut request = http.get(format!("{endpoint}{path}"));
        for (name, value) in request_headers(identity, "GET", &path) {
            request = request.header(name, value);
        }
        let response = request
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        let value: serde_json::Value = response.json().await.ok()?;
        return Some((
            value["registered"].as_bool().unwrap_or(false),
            value["online"].as_bool().unwrap_or(false),
            value["platform"].as_str().map(str::to_owned),
        ));
    }
    None
}

async fn status() -> Result<()> {
    let Ok(cfg) = config::load() else {
        println!("no key yet; run `exe` to set this machine up");
        return Ok(());
    };
    let identity = cfg.identity()?;
    println!("config        {}", config::config_path().display());
    println!("address       {}", identity.address());
    println!("endpoints     {}", cfg.endpoints().join(", "));
    if cfg.trust.is_empty() {
        println!("callers       (none — every call will be refused)");
    }
    for address in &cfg.trust {
        let label = if parse_address(address).is_ok() {
            ""
        } else {
            " (invalid)"
        };
        println!("caller        {address}{label}");
    }
    println!(
        "service       {} ({})",
        service::state(),
        service::detect().label()
    );
    match lock::holder() {
        Some(pid) => println!("running       pid {pid}"),
        None => println!("running       no process on this address"),
    }
    match probe_device(&cfg, &identity).await {
        Some((registered, online, platform)) => {
            println!(
                "relay         registered={registered} online={online}{}",
                platform
                    .map(|p| format!(" platform={p}"))
                    .unwrap_or_default()
            );
        }
        None => println!("relay         unreachable"),
    }
    println!("log           {}", logs::path().display());
    Ok(())
}

async fn doctor() -> Result<()> {
    println!("exe {}", env!("CARGO_PKG_VERSION"));
    let cfg = config::load()?;
    let identity = cfg.identity()?;
    println!("key           ok ({})", config::config_path().display());
    println!("address       {}", identity.address());

    let broken = cfg.check_trust();
    if broken.is_empty() {
        println!("trust         ok ({} entries)", cfg.trust.len());
    } else {
        println!("trust         INVALID entries: {broken:?}");
    }
    if cfg.trust.is_empty() {
        println!("trust         empty — every call will be refused");
    }

    let client = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    for endpoint in cfg.endpoints() {
        let started = std::time::Instant::now();
        match client
            .get(format!("{endpoint}/api/health"))
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => println!(
                "endpoint      {endpoint} ok ({} ms)",
                started.elapsed().as_millis()
            ),
            Ok(response) => println!("endpoint      {endpoint} responded {}", response.status()),
            Err(error) => println!("endpoint      {endpoint} unreachable: {error}"),
        }
    }
    println!(
        "service       {} ({})",
        service::state(),
        service::detect().label()
    );
    Ok(())
}

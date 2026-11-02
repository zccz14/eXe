use anyhow::{bail, Result};
use exe::{config, run};
use exe_core::parse_address;
use exe_core::policy::Policy;
use exe_core::protocol::PolicyDecision;

const HELP: &str = "\
exe — eXe device agent

USAGE:
    exe run              Self-register and serve calls (creates the key on first run)
    exe init             Create the key/config and print this device's address
    exe trust <address>  Allow calls signed by this address (repeatable)
    exe status           Show address, trust list and relay
    exe doctor           Check key, trust, policy and relay reachability
    exe policy           Print the local policy path and contents
    exe forget           Delete the local key (the console can still call this address)
    exe version          Print the agent version
";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "run".into());
    match command.as_str() {
        "run" => {
            config::ensure_policy()?;
            let (cfg, created) = config::load_or_create()?;
            announce(&cfg, created);
            run::run(cfg).await
        }
        "init" => {
            config::ensure_policy()?;
            let (cfg, created) = config::load_or_create()?;
            announce(&cfg, created);
            println!("  Policy:  {}", config::policy_path().display());
            println!();
            println!("  Next: add the address above in the console, then give this device the");
            println!("  console's address with `exe trust <address>` and run `exe run`.");
            Ok(())
        }
        "trust" => {
            let wanted: Vec<String> = args.collect();
            if wanted.is_empty() {
                bail!("usage: exe trust <address> [address...]");
            }
            for address in &wanted {
                parse_address(address)
                    .map_err(|_| anyhow::anyhow!("`{address}` is not an eXe address"))?;
            }
            let (mut cfg, _) = config::load_or_create()?;
            for address in wanted {
                if !cfg.trust.contains(&address) {
                    cfg.trust.push(address);
                }
            }
            config::save(&cfg)?;
            println!("trust = {:?}", cfg.trust);
            println!("Restart `exe run` for the new list to take effect.");
            Ok(())
        }
        "status" => status(),
        "doctor" => doctor().await,
        "policy" => {
            let path = config::ensure_policy()?;
            println!("{}", path.display());
            print!("{}", std::fs::read_to_string(path)?);
            Ok(())
        }
        "forget" => {
            let path = config::config_path();
            if path.exists() {
                std::fs::remove_file(&path)?;
                println!("Removed {}.", path.display());
                println!("The address stays callable until it is removed from the console;");
                println!("run `exe init` for a new key.");
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
    println!("  Relay:        {}", cfg.cloud);
    if cfg.trust.is_empty() {
        println!("  Trust:        (empty — every call will be refused)");
        println!("                run `exe trust <issuer address>` to allow one");
    } else {
        println!("  Trust:        {}", cfg.trust.join(", "));
    }
    println!();
}

fn status() -> Result<()> {
    match config::load() {
        Ok(cfg) => {
            println!("config        {}", config::config_path().display());
            println!("address       {}", cfg.address()?);
            println!("relay         {}", cfg.cloud);
            println!("label         {}", cfg.label);
            if cfg.trust.is_empty() {
                println!("trust         (empty)");
            } else {
                for (index, address) in cfg.trust.iter().enumerate() {
                    let label = if parse_address(address).is_ok() {
                        ""
                    } else {
                        " (invalid)"
                    };
                    println!("trust[{index}]      {address}{label}");
                }
            }
            println!("policy        {}", config::policy_path().display());
        }
        Err(_) => println!("no key yet; run `exe init`"),
    }
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

    let policy_path = config::ensure_policy()?;
    let policy = Policy::parse(&std::fs::read_to_string(&policy_path)?)?;
    println!(
        "policy        {} (allow {:?}, deny {:?})",
        policy_path.display(),
        policy.allow,
        policy.deny
    );
    if policy.decide("echo") != PolicyDecision::Allow {
        bail!("policy denies `echo`; the console cannot verify this device");
    }

    let client = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match client.get(format!("{}/api/health", cfg.cloud)).send().await {
        Ok(response) if response.status().is_success() => {
            println!("relay         reachable ({})", cfg.cloud)
        }
        Ok(response) => println!(
            "relay         responded {} ({})",
            response.status(),
            cfg.cloud
        ),
        Err(error) => println!("relay         unreachable: {error}"),
    }
    Ok(())
}

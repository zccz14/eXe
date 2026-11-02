use anyhow::{bail, Result};
use exe::{config, pair, run};
use exe_core::policy::Policy;

const HELP: &str = "\
exe — eXe device agent

USAGE:
    exe run           Pair this device if needed, then keep the event stream open
    exe pair          Force a new pairing (replaces the stored configuration)
    exe status        Show configuration, identity and last known state
    exe doctor        Check configuration, policy, reachability and SAS agreement
    exe policy        Print the local policy path and contents
    exe forget        Delete local credentials (the console still sees the device)
    exe version       Print the agent version
";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let command = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let client = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    match command.as_str() {
        "run" => {
            config::ensure_policy()?;
            let cfg = match config::load() {
                Ok(cfg) => cfg,
                Err(_) => {
                    let base = base_url()?;
                    pair::pair(&client, &base, announce_cli).await?
                }
            };
            run::run(cfg).await
        }
        "pair" => {
            config::ensure_policy()?;
            let cfg = pair::pair(&client, &base_url()?, announce_cli).await?;
            println!(
                "  Paired as device {}. Run `exe run` to start serving.",
                cfg.device_id
            );
            Ok(())
        }
        "status" => status(),
        "doctor" => doctor(&client).await,
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
                println!(
                    "Removed {}. Revoke the device in the console to stop future calls.",
                    path.display()
                );
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

fn announce_cli(code: &str, verify_uri: &str) {
    println!();
    println!("  Pairing code:  \x1b[1m{code}\x1b[0m");
    println!("  Approve at:    {verify_uri}");
    println!();
    println!("  Only approve this code yourself. Never approve a code someone sent you.");
    println!();
}

fn base_url() -> Result<String> {
    match std::env::var("EXE_BASE_URL") {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim_end_matches('/').to_owned()),
        _ => match config::load() {
            Ok(cfg) => Ok(cfg.base_url),
            Err(_) => Ok(config::DEFAULT_BASE_URL.to_owned()),
        },
    }
}

fn status() -> Result<()> {
    let path = config::config_path();
    match config::load() {
        Ok(cfg) => {
            let keys = cfg.keys()?;
            println!("config        {}", path.display());
            println!("worker        {}", cfg.base_url);
            println!("device        {}", cfg.device_id);
            println!("account       {}", cfg.account_id);
            println!("label         {}", cfg.label);
            println!(
                "sas           {}",
                exe_core::protocol::sas(&cfg.account_sig_pub, &keys.sig_pub())
            );
            println!("device key    {}", keys.sig_pub());
            println!("policy        {}", config::policy_path().display());
        }
        Err(_) => println!("not paired; run `exe run` to obtain a pairing code"),
    }
    Ok(())
}

async fn doctor(client: &reqwest::Client) -> Result<()> {
    println!("exe {}", env!("CARGO_PKG_VERSION"));
    let cfg = config::load()?;
    let keys = cfg.keys()?;
    println!("config        ok ({})", config::config_path().display());
    println!("device key    {}", keys.sig_pub());
    let expected = exe_core::protocol::sas(&cfg.account_sig_pub, &keys.sig_pub());
    println!("sas           {expected} (stored {})", cfg.sas);
    if expected != cfg.sas {
        println!("sas           MISMATCH — re-pair this device");
    }
    let policy_path = config::ensure_policy()?;
    let policy = Policy::parse(&std::fs::read_to_string(&policy_path)?)?;
    println!(
        "policy        {} (allow {:?}, deny {:?})",
        policy_path.display(),
        policy.allow,
        policy.deny
    );
    let health = client
        .get(format!("{}/api/health", cfg.base_url))
        .send()
        .await;
    match health {
        Ok(response) if response.status().is_success() => {
            println!("worker        reachable ({})", cfg.base_url)
        }
        Ok(response) => println!(
            "worker        responded {} ({})",
            response.status(),
            cfg.base_url
        ),
        Err(error) => println!("worker        unreachable: {error}"),
    }
    if policy.decide("echo") != exe_core::protocol::PolicyDecision::Allow {
        bail!("policy denies `echo`; the console cannot verify this device");
    }
    Ok(())
}

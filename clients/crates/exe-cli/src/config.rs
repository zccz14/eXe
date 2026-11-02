use std::path::PathBuf;

use anyhow::{Context, Result};
use exe_core::{parse_address, Identity};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CLOUD: &str = "https://exe.ntnl.io";

/// The whole device configuration. There is no token and no pairing record:
/// the secret *is* the identity, and trust is a list a human edits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Relay base URL.
    pub cloud: String,
    /// base58(seed32 || pub32). Never leaves this machine.
    pub secret: String,
    /// Issuer addresses whose calls this device will run. Anyone can write here;
    /// only the human at this machine decides who is on the list.
    #[serde(default)]
    pub trust: Vec<String>,
}

impl Config {
    pub fn identity(&self) -> Result<Identity> {
        Identity::from_secret(&self.secret).context("secret is not base58(seed32 || pub32)")
    }
    pub fn address(&self) -> Result<String> {
        Ok(self.identity()?.address())
    }
    /// Trust entries are addresses, but a typo should be reported, not silently ignored.
    pub fn check_trust(&self) -> Vec<String> {
        self.trust
            .iter()
            .filter(|entry| parse_address(entry).is_err())
            .cloned()
            .collect()
    }
}

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EXE_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("exe");
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("exe")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}
pub fn load() -> Result<Config> {
    let path = config_path();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("no configuration at {}; run `exe init`", path.display()))?;
    Ok(toml::from_str(&text)?)
}

/// Generates a key on first use: a device addresses itself, nobody hands it one.
pub fn load_or_create() -> Result<(Config, bool)> {
    match load() {
        Ok(config) => Ok((config, false)),
        Err(error) if error.downcast_ref::<std::io::Error>().is_some() => {
            let config = Config {
                cloud: std::env::var("EXE_CLOUD")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_CLOUD.to_owned())
                    .trim_end_matches('/')
                    .to_owned(),
                secret: Identity::generate().secret(),
                trust: Vec::new(),
            };
            save(&config)?;
            Ok((config, true))
        }
        Err(error) => Err(error),
    }
}

pub fn save(config: &Config) -> Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    let path = config_path();
    let text = toml::to_string_pretty(config)?;
    std::fs::write(&path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

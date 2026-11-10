use std::path::PathBuf;

use anyhow::{Context, Result};
use exe_core::{parse_address, Identity};
use serde::{Deserialize, Serialize};

/// Where a fresh device looks for the relay, in preference order. Both reach the
/// same relay by different routes; no signature covers the hostname, so a device
/// may use any of them and its identity is unchanged.
pub const DEFAULT_ENDPOINTS: [&str; 2] = ["https://exe.ntnl.io", "https://exe.ntnl.top"];

/// The whole device configuration. There is no token and no pairing record:
/// the secret *is* the identity, and trust is a list a human edits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Relay endpoints, in preference order. They must all reach the same relay:
    /// a call delivered through one is settled through another.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Older configurations carried a single `cloud`. Still read, never written,
    /// so a device that upgrades keeps working without editing its file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<String>,
    /// base58(seed32 || pub32). Never leaves this machine.
    pub secret: String,
    /// Issuer addresses whose calls this device will run. Anyone can write here;
    /// only the human at this machine decides who is on the list.
    #[serde(default)]
    pub trust: Vec<String>,
    /// How the device keeps itself current. On by default: a device that needs
    /// someone to visit it to stay current is not current, it is abandoned.
    #[serde(default)]
    pub update: Update,
}

/// The `[update]` section. A device upgrades itself from signed releases; the
/// only decisions left are whether to, and how often to look.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    #[serde(default = "yes")]
    pub auto: bool,
    #[serde(default = "hourly")]
    pub interval_seconds: u64,
}

fn yes() -> bool {
    true
}

fn hourly() -> u64 {
    3600
}

impl Default for Update {
    fn default() -> Self {
        Update {
            auto: yes(),
            interval_seconds: hourly(),
        }
    }
}

/// A base URL per entry, trimmed: a trailing slash would double up in a join.
pub fn split_endpoints(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|entry| entry.trim().trim_end_matches('/').to_owned())
        .filter(|entry| !entry.is_empty())
        .collect()
}

impl Config {
    /// Every endpoint this device may use, in preference order. Old files with a
    /// single `cloud`, and files with nothing at all, both end up here.
    pub fn endpoints(&self) -> Vec<String> {
        let configured: Vec<String> = self
            .endpoints
            .iter()
            .flat_map(|entry| split_endpoints(entry))
            .collect();
        if !configured.is_empty() {
            return configured;
        }
        if let Some(cloud) = &self.cloud {
            let legacy = split_endpoints(cloud);
            if !legacy.is_empty() {
                return legacy;
            }
        }
        split_endpoints(&DEFAULT_ENDPOINTS.join(","))
    }

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
            let endpoints = std::env::var("EXE_CLOUD")
                .ok()
                .map(|value| split_endpoints(&value))
                .filter(|listed| !listed.is_empty())
                .unwrap_or_else(|| split_endpoints(&DEFAULT_ENDPOINTS.join(",")));
            let config = Config {
                endpoints,
                cloud: None,
                secret: Identity::generate().secret(),
                trust: Vec::new(),
                update: Update::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn a_config_may_name_one_endpoint_or_many() {
        let single = parse("secret = \"s\"\ncloud = \"https://example.test/\"\n");
        assert_eq!(single.endpoints(), vec!["https://example.test"]);

        let many = parse("secret = \"s\"\nendpoints = [\"https://a.test\", \"https://b.test/\"]\n");
        assert_eq!(
            many.endpoints(),
            vec!["https://a.test", "https://b.test"],
            "order is preference, and a trailing slash is trimmed"
        );

        let empty = parse("secret = \"s\"\n");
        assert_eq!(
            empty.endpoints(),
            split_endpoints(&DEFAULT_ENDPOINTS.join(","))
        );
    }

    #[test]
    fn a_new_config_writes_endpoints_and_never_cloud() {
        let config = Config {
            endpoints: split_endpoints(&DEFAULT_ENDPOINTS.join(",")),
            cloud: None,
            secret: "s".into(),
            trust: Vec::new(),
            update: Update::default(),
        };
        let text = toml::to_string_pretty(&config).unwrap();
        assert!(text.contains("endpoints = ["));
        assert!(!text.contains("cloud"), "the legacy key is read-only");
    }
}

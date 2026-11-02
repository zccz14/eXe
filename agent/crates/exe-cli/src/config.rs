use std::path::PathBuf;

use anyhow::{Context, Result};
use exe_core::{b64u, unb64u, DeviceKeys};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BASE_URL: &str = "https://exe.ntnl.io";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub base_url: String,
    pub device_id: String,
    pub account_id: String,
    pub token: String,
    pub sig_seed: String,
    pub kex_seed: String,
    pub account_sig_pub: String,
    pub account_kex_pub: String,
    pub sas: String,
    pub label: String,
    pub paired_at: u64,
}

impl Config {
    pub fn keys(&self) -> Result<DeviceKeys> {
        let seed: [u8; 32] = hex::decode(&self.sig_seed)
            .context("sig_seed is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("sig_seed must be 32 bytes"))?;
        let kex: [u8; 32] = hex::decode(&self.kex_seed)
            .context("kex_seed is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("kex_seed must be 32 bytes"))?;
        Ok(DeviceKeys {
            sig: exe_core::KeyPair::from_seed(seed),
            kex: exe_core::crypto::KexPair::from_secret(kex),
        })
    }

    pub fn account_sig_key(&self) -> Result<Vec<u8>> {
        unb64u(&self.account_sig_pub)
            .map_err(|_| anyhow::anyhow!("account_sig_pub is not base64url"))
    }
    pub fn account_kex_key(&self) -> Result<Vec<u8>> {
        unb64u(&self.account_kex_pub)
            .map_err(|_| anyhow::anyhow!("account_kex_pub is not base64url"))
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
pub fn policy_path() -> PathBuf {
    config_dir().join("policy.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no configuration at {}; run `exe run` to pair this device",
            path.display()
        )
    })?;
    Ok(toml::from_str(&text)?)
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

pub fn ensure_policy() -> Result<std::path::PathBuf> {
    let path = policy_path();
    if !path.exists() {
        std::fs::create_dir_all(config_dir())?;
        std::fs::write(&path, exe_core::policy::DEFAULT_TOML)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(path)
}

pub fn hostname() -> String {
    std::env::var("EXE_HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
        })
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown-host".into())
}

pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

pub fn new_secret() -> String {
    b64u(&exe_core::crypto::random_bytes::<32>())
}

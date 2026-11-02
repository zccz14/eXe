use anyhow::{anyhow, bail, Context, Result};
use exe_core::protocol::Approval;
use exe_core::{sha256_hex, DeviceKeys};
use serde::Deserialize;
use serde_json::json;

use crate::config::{self, Config};

#[derive(Deserialize)]
struct StartResponse {
    pairing_id: String,
    user_code: String,
    expires_at: u64,
    interval: u64,
    verify_uri: String,
}

#[derive(Deserialize)]
struct PollResponse {
    status: String,
    device_id: Option<String>,
    account_id: Option<String>,
    approval: Option<Approval>,
}

pub async fn pair(
    client: &reqwest::Client,
    base_url: &str,
    announce: impl Fn(&str, &str),
) -> Result<Config> {
    let keys = DeviceKeys::generate();
    let token = config::new_secret();
    let secret = config::new_secret();
    let start: StartResponse = client
        .post(format!("{base_url}/v1/pairings"))
        .json(&json!({
            "dev_sig_pub": keys.sig_pub(),
            "dev_kex_pub": keys.kex_pub(),
            "secret_hash": sha256_hex(secret.as_bytes()),
            "token_hash": sha256_hex(token.as_bytes()),
            "hostname": config::hostname(),
            "platform": config::platform(),
            "version": env!("CARGO_PKG_VERSION"),
        }))
        .send()
        .await
        .context("could not reach the eXe worker")?
        .error_for_status()
        .context("the worker rejected this pairing request")?
        .json()
        .await?;

    announce(&start.user_code, &start.verify_uri);

    let interval = std::cmp::max(start.interval / 1000, 3);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        if config::now() > start.expires_at + 30 {
            bail!("pairing code expired; run `exe run` again for a new code");
        }
        let response = client
            .get(format!("{base_url}/v1/pairings/{}", start.pairing_id))
            .bearer_auth(&secret)
            .send()
            .await?;
        if response.status().as_u16() == 202 {
            continue;
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("pairing failed ({status}): {text}");
        }
        let poll: PollResponse = response.json().await?;
        match poll.status.as_str() {
            "denied" => bail!("the pairing was denied in the console"),
            "pending" => continue,
            "approved" => {}
            other => bail!("unexpected pairing status `{other}`"),
        }
        let approval = poll
            .approval
            .ok_or_else(|| anyhow!("approval payload missing"))?;
        approval.verify(&keys)?;
        let sas = exe_core::protocol::sas(&approval.account_sig_pub, &keys.sig_pub());
        let account = poll
            .account_id
            .clone()
            .unwrap_or_else(|| approval.account_id.clone());
        let device_id = poll
            .device_id
            .clone()
            .unwrap_or_else(|| approval.device_id.clone());

        println!(
            "  Approved for account {}",
            &account[..8.min(account.len())]
        );
        println!("  Verify this SAS matches the console: \x1b[1m{sas}\x1b[0m");
        println!("  If it does not match, run `exe forget` and pair again.");
        println!();

        let config = Config {
            base_url: base_url.trim_end_matches('/').to_owned(),
            device_id,
            account_id: account,
            token,
            sig_seed: hex_lower(&keys.sig.seed),
            kex_seed: hex_lower(&keys.kex.secret),
            account_sig_pub: approval.account_sig_pub.clone(),
            account_kex_pub: approval.account_kex_pub.clone(),
            sas,
            label: config::hostname(),
            paired_at: config::now(),
        };
        config::save(&config)?;
        println!("  Saved {} (0600).", config::config_path().display());
        return Ok(config);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

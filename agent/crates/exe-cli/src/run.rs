use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use exe_core::policy::Policy;
use exe_core::protocol::{sas, CallEnvelope, Event, ResultEnvelope};
use exe_core::DeviceKeys;
use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{self, Config};

type Tasks = Arc<Mutex<HashMap<String, JoinHandle<()>>>>;

pub async fn run(config: Config) -> Result<()> {
    let keys = config.keys()?;
    let account_sig_pub = config.account_sig_key()?;
    let account_kex_pub = config.account_kex_key()?;
    let policy = Policy::parse(&std::fs::read_to_string(config::ensure_policy()?)?)?;

    let local_sas = sas(&config.account_sig_pub, &keys.sig_pub());
    if local_sas != config.sas {
        warn!("local SAS {local_sas} differs from the stored one {}; re-pair if that was not expected", config.sas);
    }
    info!(
        device = config.device_id.as_str(),
        account = config.account_id.as_str(),
        sas = local_sas.as_str(),
        allow = ?policy.allow,
        "eXe agent starting"
    );

    let client = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let tasks: Tasks = Arc::default();
    let boot = uuid::Uuid::new_v4().to_string();

    let _heartbeat = {
        let client = client.clone();
        let config = config.clone();
        tokio::spawn(async move {
            loop {
                let url = format!(
                    "{}/v1/devices/{}/heartbeat",
                    config.base_url, config.device_id
                );
                match client.post(&url).bearer_auth(&config.token).send().await {
                    Ok(response) if !response.status().is_success() => {
                        warn!(status = %response.status(), "heartbeat rejected")
                    }
                    Ok(_) => {}
                    Err(error) => warn!(%error, "heartbeat failed"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        })
    };

    let mut backoff = 1u64;
    loop {
        match listen(
            &client,
            &config,
            &keys,
            &account_sig_pub,
            &account_kex_pub,
            &policy,
            &boot,
            &tasks,
        )
        .await
        {
            Ok(()) => backoff = 1,
            Err(error) => {
                warn!(%error, "event stream ended; reconnecting");
                backoff = (backoff * 2).min(30);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn listen(
    client: &reqwest::Client,
    config: &Config,
    keys: &DeviceKeys,
    account_sig_pub: &[u8],
    account_kex_pub: &[u8],
    policy: &Policy,
    boot: &str,
    tasks: &Tasks,
) -> Result<()> {
    let url = format!("{}/v1/devices/{}/events", config.base_url, config.device_id);
    let response = client
        .get(&url)
        .bearer_auth(&config.token)
        .header("x-exe-boot-id", boot)
        .header("x-exe-version", env!("CARGO_PKG_VERSION"))
        .send()
        .await
        .context("could not open the event stream")?;
    if !response.status().is_success() {
        bail!("event stream rejected with {}", response.status());
    }
    info!("subscribed to device events");

    let mut stream = response.bytes_stream();
    let mut buffer: Vec<u8> = Vec::with_capacity(8192);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("event stream failed")?;
        buffer.extend_from_slice(&chunk);
        while let Some(position) = find_frame_end(&buffer) {
            let frame: Vec<u8> = buffer.drain(..position + 2).collect();
            if let Some((event, data)) = parse_frame(&frame[..position]) {
                if let Some(event) = Event::parse(&event, &data) {
                    handle(
                        event,
                        client,
                        config,
                        keys,
                        account_sig_pub,
                        account_kex_pub,
                        policy,
                        tasks,
                    )
                    .await;
                }
            }
        }
    }
    Ok(())
}

fn find_frame_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|pair| pair == b"\n\n")
}

fn parse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event = String::from("message");
    let mut data = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event = value.trim().to_owned();
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value.trim_start());
        }
    }
    Some((event, data))
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    event: Event,
    client: &reqwest::Client,
    config: &Config,
    keys: &DeviceKeys,
    account_sig_pub: &[u8],
    account_kex_pub: &[u8],
    policy: &Policy,
    tasks: &Tasks,
) {
    match event {
        Event::Hello | Event::Heartbeat => {}
        Event::Cancel(call_id) => {
            let mut tasks = tasks.lock().await;
            if let Some(task) = tasks.remove(&call_id) {
                task.abort();
                info!(
                    call = call_id.as_str(),
                    "execution cancelled by the console"
                );
            }
        }
        Event::Call(call) => {
            if let Err(error) = call.verify(account_sig_pub, &config.device_id, config::now()) {
                warn!(call = call.id.as_str(), %error, "rejected a call that failed verification");
                return;
            }
            let mut tasks = tasks.lock().await;
            if tasks.contains_key(&call.id) {
                warn!(call = call.id.as_str(), "duplicate delivery ignored");
                return;
            }
            let client = client.clone();
            let config = config.clone();
            let keys = keys.clone();
            let policy = policy.clone();
            let account_kex_pub = account_kex_pub.to_vec();
            let call_id = call.id.clone();
            let task = tokio::spawn(async move {
                execute_call(&client, &config, &keys, &account_kex_pub, &policy, call).await;
            });
            tasks.insert(call_id, task);
        }
    }
}

async fn execute_call(
    client: &reqwest::Client,
    config: &Config,
    keys: &DeviceKeys,
    account_kex_pub: &[u8],
    policy: &Policy,
    call: CallEnvelope,
) {
    let base = format!(
        "{}/v1/devices/{}/calls/{}",
        config.base_url, config.device_id, call.id
    );
    let _ = client
        .post(format!("{base}/received"))
        .bearer_auth(&config.token)
        .send()
        .await;
    info!(
        call = call.id.as_str(),
        tool = call.name.as_str(),
        "executing"
    );
    let plaintext = crate::exec::execute(policy, &call).await;
    let ok = serde_json::from_str::<serde_json::Value>(&plaintext)
        .ok()
        .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    match ResultEnvelope::build(
        &call.id,
        &config.device_id,
        ok,
        account_kex_pub,
        &plaintext,
        keys,
    ) {
        Ok(envelope) => {
            let response = client
                .post(format!("{base}/result"))
                .bearer_auth(&config.token)
                .json(&envelope)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    info!(call = call.id.as_str(), "result delivered")
                }
                Ok(response) => {
                    warn!(call = call.id.as_str(), status = %response.status(), "result rejected")
                }
                Err(error) => warn!(call = call.id.as_str(), %error, "result upload failed"),
            }
        }
        Err(error) => warn!(call = call.id.as_str(), %error, "could not seal the result"),
    }
}

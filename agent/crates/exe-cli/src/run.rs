use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use exe_core::protocol::{request_headers, Event, ResultEnvelope};
use exe_core::{unix_now, CallEnvelope, Identity};
use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{self, Config};

type Tasks = Arc<Mutex<HashMap<String, JoinHandle<()>>>>;

/// Delivery is at-least-once: a lost receipt makes the relay send the same
/// `call_id` again. The envelope is remembered before it is uploaded, so a
/// repeat is answered from memory instead of running the tool twice.
const REMEMBERED_RESULTS: usize = 256;

#[derive(Default)]
struct ResultCache {
    order: VecDeque<String>,
    envelopes: HashMap<String, String>,
}

impl ResultCache {
    fn get(&self, call_id: &str) -> Option<String> {
        self.envelopes.get(call_id).cloned()
    }
    fn insert(&mut self, call_id: String, envelope: String) {
        if self.envelopes.insert(call_id.clone(), envelope).is_none() {
            self.order.push_back(call_id);
        }
        while self.order.len() > REMEMBERED_RESULTS {
            if let Some(oldest) = self.order.pop_front() {
                self.envelopes.remove(&oldest);
            }
        }
    }
}

#[derive(Clone)]
struct Agent {
    client: reqwest::Client,
    cloud: String,
    identity: Identity,
    trust: Vec<String>,
    /// This process, not this device: a restart changes it. The relay uses it to
    /// tell "the process that took your call is gone" from "it is still working",
    /// and to refuse to re-deliver a call whose side effects may already exist.
    run_id: String,
    tasks: Tasks,
    results: Arc<Mutex<ResultCache>>,
}

pub async fn run(config: Config) -> Result<()> {
    let identity = config.identity()?;
    let bad_trust = config.check_trust();
    if !bad_trust.is_empty() {
        bail!("trust contains entries that are not eXe addresses: {bad_trust:?}");
    }
    if config.trust.is_empty() {
        warn!("trust is empty: this device will refuse every call until `exe trust <address>` names an issuer");
    }
    info!(
        address = identity.address().as_str(),
        cloud = config.cloud.as_str(),
        trust = ?config.trust,
        "eXe agent starting"
    );

    let agent = Agent {
        client: reqwest::Client::builder()
            .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
            .build()?,
        cloud: config.cloud.clone(),
        identity,
        trust: config.trust.clone(),
        run_id: uuid::Uuid::now_v7().to_string(),
        tasks: Arc::default(),
        results: Arc::default(),
    };

    let mut backoff = 1u64;
    loop {
        match agent.register().await {
            Ok(()) => {}
            Err(error) => warn!(%error, "self-registration failed; will retry"),
        }
        match agent.listen().await {
            Ok(()) => backoff = 1,
            Err(error) => {
                warn!(%error, "event stream ended; reconnecting");
                backoff = (backoff * 2).min(30);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
    }
}

fn signed(
    mut request: reqwest::RequestBuilder,
    identity: &Identity,
    method: &str,
    path: &str,
) -> reqwest::RequestBuilder {
    for (name, value) in request_headers(identity, method, path) {
        request = request.header(name, value);
    }
    request
}

impl Agent {
    /// The device announces itself with its own signature; there is no token.
    async fn register(&self) -> Result<()> {
        let path = format!("/v1/devices/{}", self.identity.address());
        let request = signed(
            self.client
                .put(format!("{}{path}", self.cloud))
                .json(&serde_json::json!({
                    "hostname": config::hostname(),
                    "platform": config::platform(),
                    "version": env!("CARGO_PKG_VERSION"),
                    // The relay gets a copy of who this device trusts so it can
                    // drop calls the device would refuse anyway. The copy can only
                    // make it send less; this process still checks every call.
                    "trust": self.trust.join(","),
                    "run_id": self.run_id.as_str(),
                })),
            &self.identity,
            "PUT",
            &path,
        );
        let response = request.send().await.context("could not reach the relay")?;
        if !response.status().is_success() {
            bail!("registration rejected with {}", response.status());
        }
        info!("registered with the relay");
        Ok(())
    }

    async fn listen(&self) -> Result<()> {
        let path = format!("/v1/devices/{}/stream", self.identity.address());
        let request = signed(
            self.client.get(format!("{}{path}", self.cloud)),
            &self.identity,
            "GET",
            &path,
        );
        let response = request
            .send()
            .await
            .context("could not open the event stream")?;
        if !response.status().is_success() {
            bail!("event stream rejected with {}", response.status());
        }
        info!("subscribed to the event stream");

        let mut stream = response.bytes_stream();
        let mut buffer: Vec<u8> = Vec::with_capacity(8192);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("event stream failed")?;
            buffer.extend_from_slice(&chunk);
            while let Some(position) = find_frame_end(&buffer) {
                let frame: Vec<u8> = buffer.drain(..position + 2).collect();
                if let Some((event, data)) = parse_frame(&frame[..position]) {
                    if let Some(event) = Event::parse(&event, &data) {
                        self.handle(event).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle(&self, event: Event) {
        match event {
            Event::Hello | Event::Heartbeat => {}
            Event::Cancel(call_id) => {
                let mut tasks = self.tasks.lock().await;
                if let Some(task) = tasks.remove(&call_id) {
                    task.abort();
                    info!(
                        call = call_id.as_str(),
                        "execution cancelled by the console"
                    );
                }
            }
            Event::Call(call) => {
                if let Err(error) = call.verify(&self.trust, &self.identity.address(), unix_now()) {
                    warn!(call = call.call_id.as_str(), %error, "rejected a call that failed verification");
                    return;
                }
                let mut tasks = self.tasks.lock().await;
                if tasks.contains_key(&call.call_id) {
                    info!(
                        call = call.call_id.as_str(),
                        "already executing; duplicate delivery ignored"
                    );
                    return;
                }
                if self.results.lock().await.get(&call.call_id).is_some() {
                    info!(
                        call = call.call_id.as_str(),
                        "duplicate delivery; replaying the stored result"
                    );
                    let agent = self.clone();
                    tokio::spawn(async move { agent.replay(&call).await });
                    return;
                }
                let agent = self.clone();
                let call_id = call.call_id.clone();
                let running = self.tasks.clone();
                let closing = call_id.clone();
                let handle = tokio::spawn(async move {
                    agent.execute(call).await;
                    running.lock().await.remove(&closing);
                });
                tasks.insert(call_id, handle);
            }
        }
    }

    async fn replay(&self, call: &CallEnvelope) {
        let Some(envelope) = self.results.lock().await.get(&call.call_id) else {
            return;
        };
        let path = format!(
            "/v1/devices/{}/calls/{}/result",
            self.identity.address(),
            call.call_id
        );
        let request = signed(
            self.client
                .post(format!("{}{path}", self.cloud))
                .body(envelope),
            &self.identity,
            "POST",
            &path,
        );
        match request
            .header("content-type", "application/json")
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                info!(call = call.call_id.as_str(), "stored result re-delivered")
            }
            Ok(response) => {
                warn!(call = call.call_id.as_str(), status = %response.status(), "replayed result rejected")
            }
            Err(error) => warn!(call = call.call_id.as_str(), %error, "replayed result failed"),
        }
    }

    async fn execute(&self, call: CallEnvelope) {
        let base = format!(
            "/v1/devices/{}/calls/{}",
            self.identity.address(),
            call.call_id
        );
        let receipt = signed(
            self.client.post(format!("{}{base}/received", self.cloud)),
            &self.identity,
            "POST",
            &format!("{base}/received"),
        );
        let _ = receipt.send().await;

        let sealed = match call.open(&self.identity) {
            Ok(sealed) => sealed,
            Err(error) => {
                warn!(call = call.call_id.as_str(), %error, "could not open the sealed command");
                return;
            }
        };
        info!(
            call = call.call_id.as_str(),
            tool = sealed.name.as_str(),
            "executing"
        );
        let plaintext = crate::exec::execute(&sealed.name, &sealed.args).await;
        let ok = serde_json::from_str::<serde_json::Value>(&plaintext)
            .ok()
            .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
            .unwrap_or(false);
        let envelope =
            match ResultEnvelope::build(&self.identity, &call, ok, &plaintext, unix_now()) {
                Ok(envelope) => envelope,
                Err(error) => {
                    warn!(call = call.call_id.as_str(), %error, "could not seal the result");
                    return;
                }
            };
        let body = match serde_json::to_string(&envelope) {
            Ok(body) => body,
            Err(error) => {
                warn!(call = call.call_id.as_str(), %error, "could not encode the result");
                return;
            }
        };
        // Remember before uploading: a crash between here and the POST must not
        // turn a re-delivery into a second execution.
        self.results
            .lock()
            .await
            .insert(call.call_id.clone(), body.clone());

        let request = signed(
            self.client
                .post(format!("{}{base}/result", self.cloud))
                .body(body),
            &self.identity,
            "POST",
            &format!("{base}/result"),
        );
        match request
            .header("content-type", "application/json")
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                info!(call = call.call_id.as_str(), "result delivered")
            }
            Ok(response) => {
                warn!(call = call.call_id.as_str(), status = %response.status(), "result rejected")
            }
            Err(error) => warn!(call = call.call_id.as_str(), %error, "result upload failed"),
        }
    }
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

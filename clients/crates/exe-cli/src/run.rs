use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use anyhow::{bail, Context, Result};
use exe_core::protocol::{request_headers, seal_blob, Event, ResultEnvelope};
use exe_core::{unix_now, CallEnvelope, Identity};
use futures_util::StreamExt;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{self, Config};

type Tasks = Arc<Mutex<HashMap<String, JoinHandle<()>>>>;

/// Delivery is at-least-once: a lost receipt makes the relay send the same
/// `call_id` again. The envelope is remembered before it is uploaded, so a
/// repeat is answered from memory instead of running the tool twice.
const REMEMBERED_RESULTS: usize = 256;

/// What travels back inline. This is a reader's budget, not a storage one: a
/// result is meant to land in a model's context, where a few tens of kilobytes
/// is already a lot to read. Anything past this is attached and stays one click
/// away, so the inline path never has to grow with the database.
const INLINE_RESULT_BYTES: usize = 64 * 1024;

/// A truncated answer still shows its head: most commands say what matters in
/// the first screen, and a pointer with no preview forces a round trip to learn
/// anything at all. stdout gets the room; stderr only needs to be enough to see
/// the error.
const PREVIEW_BYTES: usize = 32 * 1024;
const PREVIEW_STDERR_BYTES: usize = 8 * 1024;

/// The first `limit` bytes of a string, never splitting a character.
fn head(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// What the row says instead of the bytes: the outcome, the head of each stream,
/// and a pointer. `blob` carries either the attachment's size or the reason
/// there is none.
fn summarise(full: &str, ok: bool, note: serde_json::Value) -> String {
    let value: serde_json::Value = serde_json::from_str(full).unwrap_or(serde_json::Value::Null);
    let output = value.get("output");
    let stream = |field: &str| -> &str {
        output
            .and_then(|value| value.get(field))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    };
    serde_json::json!({
        "ok": ok,
        "output": {
            "tool": output.and_then(|value| value.get("tool")).cloned().unwrap_or(serde_json::json!("shell")),
            "exit_code": output.and_then(|value| value.get("exit_code")).cloned().unwrap_or(serde_json::Value::Null),
            "stdout": head(stream("stdout"), PREVIEW_BYTES),
            "stderr": head(stream("stderr"), PREVIEW_STDERR_BYTES),
            "truncated": true,
            "stdout_bytes": stream("stdout").len(),
            "stderr_bytes": stream("stderr").len(),
        },
        "blob": note,
    })
    .to_string()
}

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
struct Client {
    client: reqwest::Client,
    cloud: String,
    identity: Identity,
    /// Reloaded on SIGHUP so a new caller needs no restart.
    trust: Arc<RwLock<Vec<String>>>,
    /// This process, not this device: a restart changes it. The relay uses it to
    /// tell "the process that took your call is gone" from "it is still working",
    /// and to refuse to re-deliver a call whose side effects may already exist.
    run_id: String,
    tasks: Tasks,
    results: Arc<Mutex<ResultCache>>,
}

pub async fn run(config: Config) -> Result<()> {
    // A service has no terminal: the previous generation of the log is kept, and
    // a second process on this address is refused before it can run anything twice.
    crate::logs::rotate();
    let _lock = crate::lock::acquire()?;
    let identity = config.identity()?;
    let bad_trust = config.check_trust();
    if !bad_trust.is_empty() {
        bail!("trust contains entries that are not eXe addresses: {bad_trust:?}");
    }
    if config.trust.is_empty() {
        warn!("trust is empty: this device will refuse every call until `exe trust <address>` names an caller");
    }
    let endpoints = config.endpoints();
    info!(
        address = identity.address().as_str(),
        endpoints = ?endpoints,
        trust = ?config.trust,
        "eXe client starting"
    );

    let http = reqwest::Client::builder()
        .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let run_id = uuid::Uuid::now_v7().to_string();
    let tasks: Tasks = Arc::default();
    let results: Arc<Mutex<ResultCache>> = Arc::default();

    let trust: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(config.trust.clone()));
    // Adding a caller edits the file; the device re-reads it, re-registers, and
    // reconnects. Restarting by hand was the step people skipped.
    let reload = Arc::new(Notify::new());
    #[cfg(unix)]
    {
        let trust = trust.clone();
        let notify = reload.clone();
        tokio::spawn(async move {
            let Ok(mut hangup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while hangup.recv().await.is_some() {
                match config::load() {
                    Ok(fresh) => {
                        let count = fresh.trust.len();
                        if let Ok(mut current) = trust.write() {
                            *current = fresh.trust.clone();
                        }
                        info!(callers = count, "trust reloaded; re-registering");
                        notify.notify_one();
                    }
                    Err(error) => warn!(%error, "could not reload the configuration"),
                }
            }
        });
    }
    let mut backoff = 1u64;
    // `None` means "pick an endpoint again": at startup, and after anything that
    // looks like the route rather than the request being the problem.
    let mut current: Option<String> = None;
    loop {
        if current.is_none() {
            current = probe(&http, &endpoints).await;
            match current.as_deref() {
                Some(base) => info!(endpoint = base, "chose the fastest relay endpoint"),
                None => warn!("no relay endpoint answered; will keep trying"),
            }
        }
        let Some(cloud) = current.clone() else {
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
            continue;
        };
        let client = Client {
            client: http.clone(),
            cloud,
            identity: identity.clone(),
            trust: trust.clone(),
            run_id: run_id.clone(),
            tasks: tasks.clone(),
            results: results.clone(),
        };
        if let Err(error) = client.register().await {
            warn!(%error, "self-registration failed; will retry");
            current = None;
            backoff = (backoff * 2).min(30);
        } else {
            match client.listen(&reload).await {
                // The relay closes a stream on purpose after fifteen minutes;
                // that is a normal cycle, not a reason to change endpoints.
                Ok(()) => backoff = 1,
                Err(error) => {
                    warn!(%error, "event stream ended; reconnecting");
                    backoff = (backoff * 2).min(30);
                    current = None;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
    }
}

/// Probes every endpoint at once and keeps the quickest one that is really an
/// eXe relay. A captive portal that answers 200 with HTML is not an endpoint.
async fn probe(http: &reqwest::Client, endpoints: &[String]) -> Option<String> {
    let attempts = endpoints.iter().map(|base| async move {
        let started = std::time::Instant::now();
        let response = http
            .get(format!("{base}/api/health"))
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let healthy = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|value| {
                value
                    .get("service")
                    .and_then(|value| value.as_str())
                    .map(|service| service == "exe")
            })
            .unwrap_or(false);
        healthy.then(|| (started.elapsed(), base.clone()))
    });
    futures_util::future::join_all(attempts)
        .await
        .into_iter()
        .flatten()
        .min_by_key(|(elapsed, _)| *elapsed)
        .map(|(_, base)| base)
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

impl Client {
    /// The device announces itself with its own signature; there is no token.
    async fn register(&self) -> Result<()> {
        let path = format!("/v1/devices/{}", self.identity.address());
        let request = signed(
            self.client
                .put(format!("{}{path}", self.cloud))
                .json(&serde_json::json!({
                    "platform": config::platform(),
                    "version": env!("CARGO_PKG_VERSION"),
                    // The relay gets a copy of who this device trusts so it can
                    // drop calls the device would refuse anyway. The copy can only
                    // make it send less; this process still checks every call.
                    "trust": self.trust.read().map(|list| list.join(",")).unwrap_or_default(),
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

    async fn listen(&self, reload: &Notify) -> Result<()> {
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
        loop {
            tokio::select! {
                // Dropping the stream and coming back through the loop is the
                // cheapest way to re-register with a fresh trust list.
                _ = reload.notified() => return Ok(()),
                chunk = stream.next() => {
                    let Some(chunk) = chunk else { return Ok(()) };
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
            }
        }
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
                let trust = self
                    .trust
                    .read()
                    .map(|list| list.clone())
                    .unwrap_or_default();
                if let Err(error) = call.verify(&trust, &self.identity.address(), unix_now()) {
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
                    let client = self.clone();
                    tokio::spawn(async move { client.replay(&call).await });
                    return;
                }
                let client = self.clone();
                let call_id = call.call_id.clone();
                let running = self.tasks.clone();
                let closing = call_id.clone();
                let handle = tokio::spawn(async move {
                    client.execute(call).await;
                    running.lock().await.remove(&closing);
                });
                tasks.insert(call_id, handle);
            }
        }
    }

    /// Uploads the sealed outcome as an attachment. The relay stores opaque
    /// bytes; the console is the only party that can open them.
    async fn upload_blob(
        &self,
        call: &CallEnvelope,
        plaintext: &[u8],
        issued_at: u64,
    ) -> Result<usize> {
        let sealed = seal_blob(call, plaintext, issued_at)?;
        let path = format!(
            "/v1/devices/{}/calls/{}/blob",
            self.identity.address(),
            call.call_id
        );
        let request = signed(
            self.client
                .put(format!("{}{path}", self.cloud))
                .header("content-type", "application/octet-stream")
                .body(sealed.clone()),
            &self.identity,
            "PUT",
            &path,
        );
        let response = request.send().await.context("could not reach the relay")?;
        if !response.status().is_success() {
            bail!("relay refused the attachment with {}", response.status());
        }
        Ok(sealed.len())
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
        let full = crate::exec::execute(&sealed.name, &sealed.args, call.expires_at).await;
        let ok = serde_json::from_str::<serde_json::Value>(&full)
            .ok()
            .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
            .unwrap_or(false);
        // Too big for one row: seal it as an attachment, upload it, and let the
        // row carry the pointer. A failed upload is still answered — truncated,
        // and with the reason — because silence is worse than a short answer.
        // One timestamp for the whole answer. The attachment's AAD and the result
        // envelope's AAD must agree, and an upload can take seconds — asking the
        // clock twice is how a slow upload becomes an undecryptable result.
        let issued_at = unix_now();
        let plaintext = if full.len() > INLINE_RESULT_BYTES {
            match self.upload_blob(&call, full.as_bytes(), issued_at).await {
                Ok(bytes) => {
                    info!(call = call.call_id.as_str(), bytes, "result attached");
                    summarise(&full, ok, serde_json::json!({ "bytes": bytes }))
                }
                Err(error) => {
                    warn!(call = call.call_id.as_str(), %error, "could not attach the result; answering truncated");
                    summarise(&full, ok, serde_json::json!({ "error": error.to_string() }))
                }
            }
        } else {
            full
        };
        let envelope = match ResultEnvelope::build(&self.identity, &call, ok, &plaintext, issued_at)
        {
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

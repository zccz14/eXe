//! `exe mcp` — the caller half, spoken as an MCP server on stdio.
//!
//! This is the only way eXe gets into an agent harness that never heard of eXe:
//! the harness spawns this process and hands the model a few tools. The key lives
//! in this machine's configuration, never in the harness's, and never at the relay
//! — the relay stays a blind queue either way.
//!
//! Tools are namespaced (`exe_bash`, not `bash`) because a harness offers one flat
//! list: every agent already owns a shell, and a bridge that files built-ins first
//! would shadow a bare `bash` before the model ever sees it.
use anyhow::{bail, Context, Result};
use exe_core::protocol::{open_blob, request_headers, CallEnvelope, ResultEnvelope};
use exe_core::{unix_now, Identity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const DEFAULT_TTL_SECONDS: u64 = 600;
const MAX_TTL_SECONDS: u64 = 3600;
const MAX_IMAGE_BASE64: usize = 6 * 1024 * 1024;
const SUPPORTED_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

// --- configuration -----------------------------------------------------------

fn default_prefix() -> String {
    "exe".into()
}

/// The caller's whole configuration: one key, a relay, and the devices it may
/// reach. One key is one address, so making the blast radius smaller means
/// running this file with fewer devices in it — not a smaller command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Older files carried a single `cloud`; still read, never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<String>,
    pub secret: String,
    #[serde(default = "default_prefix")]
    pub tool_prefix: String,
    /// label -> device address. The relay has no address book, so this list is
    /// the operator's own.
    #[serde(default)]
    pub devices: BTreeMap<String, String>,
}

impl Config {
    pub fn endpoints(&self) -> Vec<String> {
        let configured: Vec<String> = self
            .endpoints
            .iter()
            .flat_map(|entry| crate::config::split_endpoints(entry))
            .collect();
        if !configured.is_empty() {
            return configured;
        }
        if let Some(cloud) = &self.cloud {
            let legacy = crate::config::split_endpoints(cloud);
            if !legacy.is_empty() {
                return legacy;
            }
        }
        crate::config::split_endpoints(&crate::config::DEFAULT_ENDPOINTS.join(","))
    }

    pub fn identity(&self) -> Result<Identity> {
        Identity::from_secret(&self.secret).context("secret is not base58(seed32 || pub32)")
    }
}

pub fn path() -> PathBuf {
    crate::config::config_dir().join("mcp.toml")
}

pub fn load() -> Result<Config> {
    let path = self::path();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("no caller configuration at {}", path.display()))?;
    Ok(toml::from_str(&text)?)
}

pub fn load_or_create() -> Result<(Config, bool)> {
    match load() {
        Ok(config) => Ok((config, false)),
        Err(_) => {
            let config = Config {
                endpoints: crate::config::split_endpoints(
                    &crate::config::DEFAULT_ENDPOINTS.join(","),
                ),
                cloud: None,
                secret: Identity::generate().secret(),
                tool_prefix: default_prefix(),
                devices: BTreeMap::new(),
            };
            save(&config)?;
            Ok((config, true))
        }
    }
}

pub fn save(config: &Config) -> Result<()> {
    let dir = crate::config::config_dir();
    std::fs::create_dir_all(&dir)?;
    let path = self::path();
    std::fs::write(&path, toml::to_string_pretty(config)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// --- relay client ------------------------------------------------------------

#[derive(Debug, Default)]
struct DeviceStatus {
    registered: bool,
    online: bool,
    platform: Option<String>,
    version: Option<String>,
    last_seen_at: Option<i64>,
}

#[derive(Debug)]
struct Outcome {
    /// The device's own answer, already opened.
    body: Value,
    /// An answer too big for the row, already opened.
    attachment: Option<Vec<u8>>,
}

struct Caller {
    http: reqwest::Client,
    /// Resolved on first use, not at startup: a harness spawns this process at
    /// login, and a relay that is briefly unreachable must not look like a dead
    /// MCP server.
    cloud: tokio::sync::Mutex<Option<String>>,
    identity: Identity,
    config: Config,
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

impl Caller {
    async fn new(config: Config) -> Result<Self> {
        let identity = config.identity()?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("exe/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            cloud: tokio::sync::Mutex::new(None),
            identity,
            config,
        })
    }

    /// The first endpoint that answers as an eXe relay, remembered once found.
    async fn base(&self) -> Result<String> {
        if let Some(cloud) = self.cloud.lock().await.clone() {
            return Ok(cloud);
        }
        for endpoint in self.config.endpoints() {
            let healthy = match self
                .http
                .get(format!("{endpoint}/api/health"))
                .timeout(std::time::Duration::from_secs(3))
                .send()
                .await
            {
                Ok(response) => match response.json::<Value>().await {
                    Ok(value) => value["service"] == json!("exe"),
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if healthy {
                *self.cloud.lock().await = Some(endpoint.clone());
                return Ok(endpoint);
            }
        }
        bail!("no relay answered at {:?}", self.config.endpoints())
    }

    fn address(&self) -> String {
        self.identity.address()
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let cloud = self.base().await?;
        let request = signed(
            self.http.get(format!("{cloud}{path}")),
            &self.identity,
            "GET",
            path,
        );
        let response = request.send().await.context("could not reach the relay")?;
        if !response.status().is_success() {
            bail!("relay answered {}", response.status());
        }
        Ok(response.json().await?)
    }

    async fn device(&self, address: &str) -> Result<DeviceStatus> {
        let value = self.get_json(&format!("/api/devices/{address}")).await?;
        Ok(DeviceStatus {
            registered: value["registered"].as_bool().unwrap_or(false),
            online: value["online"].as_bool().unwrap_or(false),
            platform: value["platform"].as_str().map(str::to_owned),
            version: value["version"].as_str().map(str::to_owned),
            last_seen_at: value["last_seen_at"].as_i64(),
        })
    }

    /// One call: seal, queue, wait, open. The waiting is the caller's problem,
    /// which is why the relay can stay a queue and a poll.
    async fn call(
        &self,
        device: &str,
        tool: &str,
        args: Value,
        ttl: u64,
        cancel: Arc<AtomicBool>,
    ) -> Result<Outcome> {
        let issued_at = unix_now();
        let expires_at = issued_at + ttl.min(MAX_TTL_SECONDS);
        let call_id = uuid::Uuid::new_v4().simple().to_string();
        let plaintext = serde_json::to_vec(&json!({ "name": tool, "args": args.to_string() }))?;
        let envelope = CallEnvelope::build(
            &self.identity,
            device,
            &call_id,
            &plaintext,
            issued_at,
            expires_at,
        )?;

        let path = format!("/api/devices/{device}/calls");
        let cloud = self.base().await?;
        let request = signed(
            self.http
                .post(format!("{cloud}{path}"))
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&envelope)?),
            &self.identity,
            "POST",
            &path,
        );
        let response = request.send().await.context("could not reach the relay")?;
        if !response.status().is_success() {
            let reason = response.text().await.unwrap_or_default();
            bail!("the relay refused the call: {}", reason.trim());
        }

        let detail_path = format!("/api/calls/{call_id}");
        let started = std::time::Instant::now();
        let mut wait = std::time::Duration::from_millis(150);
        loop {
            if cancel.load(Ordering::Relaxed) {
                self.cancel(&call_id).await;
                bail!("cancelled by the caller");
            }
            if started.elapsed() > std::time::Duration::from_secs(ttl.min(MAX_TTL_SECONDS) + 30) {
                bail!("no answer before the call expired");
            }
            let detail = self.get_json(&detail_path).await?;
            let status = detail["call"]["status"].as_str().unwrap_or("queued");
            match status {
                "queued" | "received" => {}
                "succeeded" | "failed" => return self.settle(&envelope, &detail).await,
                "cancelled" => bail!("the call was cancelled"),
                "expired" => bail!("the call expired before the device answered"),
                "lost" => bail!(
                    "the device process that took this call is gone and it never answered: \
                     the command may have run. Do not retry blindly."
                ),
                other => bail!("unexpected call status `{other}`"),
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(std::time::Duration::from_millis(600));
        }
    }

    async fn cancel(&self, call_id: &str) {
        let path = format!("/api/calls/{call_id}/cancel");
        let Ok(cloud) = self.base().await else { return };
        let request = signed(
            self.http.post(format!("{cloud}{path}")),
            &self.identity,
            "POST",
            &path,
        );
        let _ = request.send().await;
    }

    async fn settle(&self, envelope: &CallEnvelope, detail: &Value) -> Result<Outcome> {
        let result: ResultEnvelope = serde_json::from_value(detail["result"].clone())
            .context("the relay has no result for a settled call")?;
        result.verify(&envelope.device)?;
        let plaintext = result.open(&self.identity, envelope)?;
        let body: Value = serde_json::from_slice(&plaintext).unwrap_or(Value::Null);
        let mut attachment = None;
        if detail["call"]["blob_bytes"].as_u64().unwrap_or(0) > 0 {
            let path = format!("/api/calls/{}/blob", envelope.call_id);
            let cloud = self.base().await?;
            let request = signed(
                self.http.get(format!("{cloud}{path}")),
                &self.identity,
                "GET",
                &path,
            );
            let response = request.send().await?;
            if response.status().is_success() {
                let raw = response.bytes().await?;
                attachment = Some(open_blob(envelope, &self.identity, result.issued_at, &raw)?);
            }
        }
        Ok(Outcome { body, attachment })
    }
}

// --- tools -------------------------------------------------------------------

fn tool_list(prefix: &str, devices: &BTreeMap<String, String>) -> Value {
    let labels: Vec<&String> = devices.keys().collect();
    let mut device_schema = json!({
        "type": "string",
        "description": "Device label, exactly as `{prefix}_devices` reports it."
    });
    if !labels.is_empty() {
        device_schema["enum"] = json!(labels);
    }
    json!([
        {
            "name": format!("{prefix}_devices"),
            "description": "List the devices this machine can reach through eXe, with whether \
                            each one is registered and online. Call this first; every other \
                            tool needs a device label from here.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": format!("{prefix}_bash"),
            "description": "Run a shell command on a REMOTE device — not on this machine and not \
                            in the caller's sandbox. The command runs as the device's own user, \
                            with no sandbox and no confirmation. Prefer one command that does the \
                            whole job (`cd x && a && b`) over many small ones: every call is a \
                            round trip through the relay.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": device_schema,
                    "command": { "type": "string", "description": "The command line, run with `sh -c` (or `cmd /C` on Windows)." },
                    "cwd": { "type": "string", "description": "Working directory on the device." },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "How long the command may run. Defaults to 60s and is \
                                        capped by the call's own lifetime; ask for what you need."
                    }
                },
                "required": ["device", "command"],
                "additionalProperties": false
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": format!("{prefix}_image"),
            "description": "Read an image file on a REMOTE device and return it as an image. \
                            Useful for screenshots: take one with the shell tool, then read it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "device": device_schema,
                    "path": { "type": "string", "description": "Absolute path of a png, jpeg, webp or gif on the device." }
                },
                "required": ["device", "path"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        }
    ])
}

fn failed(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": true })
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn mime_of(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}

fn address_of(config: &Config, device: &str) -> Result<String> {
    match config.devices.get(device) {
        Some(address) => Ok(address.clone()),
        None => bail!(
            "unknown device `{device}`; configured: {:?}",
            config.devices.keys().collect::<Vec<_>>()
        ),
    }
}

async fn call_tool(caller: &Caller, name: &str, args: &Value, cancel: Arc<AtomicBool>) -> Value {
    let config = &caller.config;
    let prefix = &config.tool_prefix;
    if name == format!("{prefix}_devices") {
        let mut rows = Vec::new();
        for (label, address) in &config.devices {
            match caller.device(address).await {
                Ok(status) => rows.push(json!({
                    "device": label,
                    "address": address,
                    "registered": status.registered,
                    "online": status.online,
                    "platform": status.platform,
                    "version": status.version,
                    "last_seen_at": status.last_seen_at,
                })),
                Err(error) => rows.push(json!({
                    "device": label,
                    "address": address,
                    "error": error.to_string(),
                })),
            }
        }
        let status = DeviceStatus::default();
        let _ = status;
        return json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&rows).unwrap_or_default() }],
            "structuredContent": { "devices": rows },
        });
    }

    let Some(device) = args.get("device").and_then(Value::as_str) else {
        return failed("`device` is required; call the devices tool first");
    };
    let address = match address_of(config, device) {
        Ok(address) => address,
        Err(error) => return failed(format!("exe: {error}")),
    };

    if name == format!("{prefix}_bash") {
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return failed("`command` is required");
        };
        let mut call_args = json!({ "command": command });
        if let Some(cwd) = args.get("cwd").and_then(Value::as_str) {
            call_args["cwd"] = json!(cwd);
        }
        let mut ttl = DEFAULT_TTL_SECONDS;
        if let Some(seconds) = args.get("timeout_seconds").and_then(Value::as_u64) {
            call_args["timeout_seconds"] = json!(seconds);
            ttl = seconds.saturating_add(60).min(MAX_TTL_SECONDS);
        }
        return match caller.call(&address, "shell", call_args, ttl, cancel).await {
            Ok(outcome) => shell_result(device, command, outcome),
            Err(error) => failed(format!("exe: {error}")),
        };
    }

    if name == format!("{prefix}_image") {
        let Some(path) = args.get("path").and_then(Value::as_str) else {
            return failed("`path` is required");
        };
        // One round trip: the device base64s the file, and the relay's attachment
        // path carries it whole. `tr -d` keeps the payload on one line so the JSON
        // string stays valid whatever the platform's base64 defaults are.
        let command = format!("base64 < {} | tr -d '\\n'", sh_quote(path));
        let call_args = json!({ "command": command, "timeout_seconds": 120 });
        return match caller.call(&address, "shell", call_args, 180, cancel).await {
            Ok(outcome) => image_result(device, path, outcome),
            Err(error) => failed(format!("exe: {error}")),
        };
    }

    failed(format!("exe: unknown tool `{name}`"))
}

/// The device's answer, whole.
///
/// A result too big for one row travels as an attachment — and the attachment is
/// the device's entire answer, the same JSON document `exec` produced, sealed.
/// It is not a stream of stdout: the JSON that wraps the stream comes with it.
/// Treating it as the stream is how a picture became an invalid base64 string
/// the moment it grew past the inline budget.
fn whole(outcome: Outcome) -> Value {
    match outcome.attachment {
        Some(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value @ Value::Object(_)) => value,
            _ => outcome.body,
        },
        None => outcome.body,
    }
}

fn shell_result(device: &str, command: &str, outcome: Outcome) -> Value {
    let body = whole(outcome);
    let ok = body["ok"].as_bool().unwrap_or(false);
    let output = &body["output"];
    let code = output["exit_code"].as_i64().unwrap_or(-1);
    let stdout = output["stdout"].as_str().unwrap_or_default();
    let stderr = output["stderr"].as_str().unwrap_or_default();
    let truncated = output["truncated"].as_bool().unwrap_or(false);
    let mut text = format!("[{device}] $ {command}\nexit {code}\n{stdout}");
    if !stderr.is_empty() {
        text.push_str("\n--- stderr ---\n");
        text.push_str(stderr);
    }
    if truncated {
        text.push_str("\n[output truncated by the device]");
    }
    if body["code"].as_str() == Some("timeout") {
        text.push_str("\n[the device killed the command at its timeout]");
    }
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "device": device,
            "command": command,
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
        },
        "isError": !ok,
    })
}

fn image_result(device: &str, path: &str, outcome: Outcome) -> Value {
    let body = whole(outcome);
    let output = &body["output"];
    let base64: String = output["stdout"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    // The row carries a preview when the answer was too big to sit in it. A
    // preview of base64 is still base64 — short, and pretending to be a
    // picture. Say what happened instead of handing over the first 32 KiB.
    if output["truncated"].as_bool().unwrap_or(false) {
        let reason = body["blob"]["error"]
            .as_str()
            .map(|error| format!(" ({error})"))
            .unwrap_or_default();
        return failed(format!(
            "exe: {path} did not arrive whole — the device had to cut the answer to a \
             preview{reason}. Downscale it on the device first."
        ));
    }
    if base64.is_empty() {
        return failed(format!(
            "exe: {device} returned nothing for {path} (not a file, or base64 is missing there)"
        ));
    }
    if base64.len() > MAX_IMAGE_BASE64 {
        return failed(format!(
            "exe: {path} is too large to hand over as an image ({} bytes base64). \
             Downscale it on the device first.",
            base64.len()
        ));
    }
    json!({
        "content": [
            { "type": "image", "data": base64, "mimeType": mime_of(path) },
            { "type": "text", "text": format!("[{device}] {path}") }
        ],
        "structuredContent": { "device": device, "path": path, "bytes_base64": base64.len() },
    })
}

// --- stdio protocol ----------------------------------------------------------

fn supported_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) if SUPPORTED_VERSIONS.contains(&version) => "2025-06-18",
        _ => "2025-06-18",
    }
}

fn initialize_result(requested: Option<&str>) -> Value {
    json!({
        "protocolVersion": supported_version(requested),
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "exe", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Tools run on your own devices through eXe, not on this machine. \
                         Start with the devices tool, then pass its labels as `device`."
    })
}

/// Answers one message. Requests get a reply; notifications do not.
async fn handle(caller: &Caller, message: &Value, cancel: Arc<AtomicBool>) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let config = &caller.config;
    let result = match method {
        "initialize" => Some(initialize_result(
            params.get("protocolVersion").and_then(Value::as_str),
        )),
        "tools/list" => Some(json!({
            "tools": tool_list(&config.tool_prefix, &config.devices)
        })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            Some(call_tool(caller, &name, &args, cancel).await)
        }
        "ping" => Some(json!({})),
        _ => None,
    };
    match (id, result) {
        (Some(id), Some(result)) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
        (Some(id), None) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })),
        (None, _) => None,
    }
}

/// `exe mcp`: serve until stdin closes. Everything non-protocol goes to stderr —
/// stdout is the wire.
pub async fn serve() -> Result<()> {
    let (config, created) = load_or_create()?;
    if created {
        eprintln!("exe mcp: created {}", path().display());
        eprintln!(
            "exe mcp: this caller's address is {}",
            config.identity()?.address()
        );
        eprintln!("exe mcp: add it to each device with `exe trust <address>`");
    }
    let caller = Caller::new(config).await?;
    eprintln!(
        "exe mcp: caller {}, {} device(s), relay {:?}",
        caller.address(),
        caller.config.devices.len(),
        caller.config.endpoints()
    );

    let out = Arc::new(Mutex::new(std::io::stdout()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(line) if !line.trim().is_empty() => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let in_flight: Arc<Mutex<BTreeMap<String, Arc<AtomicBool>>>> = Arc::default();
    let caller = Arc::new(caller);

    while let Some(line) = rx.recv().await {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == "notifications/cancelled" {
            let request = message["params"]["requestId"].to_string();
            if let Some(flag) = in_flight.lock().unwrap().get(&request) {
                flag.store(true, Ordering::Relaxed);
            }
            continue;
        }
        if method.starts_with("notifications/") {
            continue;
        }
        let request = message.get("id").cloned();
        if method == "tools/call" {
            let cancel = Arc::new(AtomicBool::new(false));
            if let Some(id) = &request {
                in_flight
                    .lock()
                    .unwrap()
                    .insert(id.to_string(), cancel.clone());
            }
            let caller = caller.clone();
            let out = out.clone();
            let in_flight = in_flight.clone();
            let message = message.clone();
            tokio::spawn(async move {
                if let Some(reply) = handle(&caller, &message, cancel).await {
                    let mut guard = out.lock().unwrap();
                    let _ = writeln!(guard, "{reply}");
                    let _ = guard.flush();
                }
                if let Some(id) = request {
                    in_flight.lock().unwrap().remove(&id.to_string());
                }
            });
            continue;
        }
        if let Some(reply) = handle(&caller, &message, Arc::new(AtomicBool::new(false))).await {
            let mut guard = out.lock().unwrap();
            let _ = writeln!(guard, "{reply}");
            let _ = guard.flush();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_carry_the_prefix_and_a_bare_name_never_escapes() {
        let devices = BTreeMap::new();
        let tools = tool_list("exe", &devices);
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["exe_devices", "exe_bash", "exe_image"]);
        for name in names {
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{name}"
            );
            assert!(name.len() <= 64, "{name}");
        }
    }

    #[test]
    fn the_prefix_is_configurable_because_two_pools_may_coexist() {
        let tools = tool_list("work", &BTreeMap::new());
        assert_eq!(tools[1]["name"], "work_bash");
    }

    /// A result past the inline budget, as the relay delivers it: the row is a
    /// preview with a pointer, the attachment is the device's whole answer.
    fn attached(answer: Value) -> Outcome {
        let stdout = answer["output"]["stdout"].as_str().unwrap_or_default();
        let full = answer.to_string();
        Outcome {
            body: json!({
                "ok": answer["ok"],
                "output": {
                    "tool": "shell",
                    "exit_code": 0,
                    "stdout": stdout.chars().take(64).collect::<String>(),
                    "stderr": "",
                    "truncated": true,
                    "stdout_bytes": stdout.len(),
                },
                "blob": { "bytes": full.len() },
            }),
            attachment: Some(full.into_bytes()),
        }
    }

    fn answer(stdout: &str) -> Value {
        json!({ "ok": true, "output": { "tool": "shell", "exit_code": 0, "stdout": stdout, "stderr": "" } })
    }

    /// The bug this test exists for: past 64 KiB inline, the picture came back
    /// as the JSON document that wrapped it, and the harness said "Invalid
    /// Base64 string". A big picture must arrive as the same bytes a small one
    /// does.
    #[test]
    fn a_big_picture_arrives_whole_rather_than_as_the_json_around_it() {
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
        let result = image_result("box", "/tmp/dot.png", attached(answer(png)));
        assert_eq!(result["isError"], Value::Null);
        assert_eq!(result["content"][0]["type"], "image");
        assert_eq!(result["content"][0]["data"], png);
        assert_eq!(result["content"][0]["mimeType"], "image/png");
        assert_eq!(result["structuredContent"]["bytes_base64"], png.len());
    }

    /// The other half: when the attachment never arrived, the row's preview is
    /// a truncated picture. Naming that beats shipping 32 KiB of base64 that
    /// decodes to nonsense.
    #[test]
    fn a_picture_that_could_not_be_attached_is_named_as_such() {
        let outcome = Outcome {
            body: json!({
                "ok": true,
                "output": {
                    "tool": "shell",
                    "exit_code": 0,
                    "stdout": "iVBORw0KGgo",
                    "stderr": "",
                    "truncated": true,
                    "stdout_bytes": 10_000_000,
                },
                "blob": { "error": "an attachment may not exceed 16777216 bytes" },
            }),
            attachment: None,
        };
        let result = image_result("box", "/tmp/big.png", outcome);
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("did not arrive whole"), "{text}");
        assert!(text.contains("16777216"), "{text}");
    }

    /// `exe_bash` had the same mistake: a large answer's text was the answer's
    /// JSON, not the answer.
    #[test]
    fn a_big_bash_answer_keeps_its_own_text() {
        let result = shell_result("box", "printf hello", attached(answer("hello")));
        assert_eq!(result["structuredContent"]["stdout"], "hello");
        assert_eq!(result["structuredContent"]["truncated"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "[box] $ printf hello\nexit 0\nhello");
    }

    /// A small answer never had an attachment, and still does not need one.
    #[test]
    fn a_small_answer_is_read_from_the_row() {
        let outcome = Outcome {
            body: answer("hi"),
            attachment: None,
        };
        let result = shell_result("box", "printf hi", outcome);
        assert_eq!(result["structuredContent"]["stdout"], "hi");
        assert_eq!(result["structuredContent"]["truncated"], false);
    }

    #[test]
    fn a_path_with_a_quote_cannot_break_out_of_the_shell() {
        assert_eq!(sh_quote("/tmp/a b.png"), "'/tmp/a b.png'");
        assert_eq!(sh_quote("/tmp/it's.png"), r#"'/tmp/it'\''s.png'"#);
    }
}

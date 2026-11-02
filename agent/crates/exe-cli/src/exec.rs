use exe_core::policy::Policy;
use exe_core::protocol::PolicyDecision;
use serde_json::{json, Value};

fn failure(code: &str, error: &str) -> String {
    json!({ "ok": false, "code": code, "error": error }).to_string()
}

fn truncate(bytes: &[u8], limit: usize) -> String {
    let slice = if bytes.len() > limit {
        &bytes[..limit]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

/// Runs one verified, decrypted command under the local policy.
pub async fn execute(policy: &Policy, name: &str, args: &str) -> String {
    match policy.decide(name) {
        PolicyDecision::Deny(reason) => return failure("policy_denied", &reason),
        PolicyDecision::Allow => {}
    }
    let args: Value = match serde_json::from_str(args) {
        Ok(value @ Value::Object(_)) => value,
        _ => return failure("invalid_args", "arguments must be a JSON object"),
    };
    match name {
        "echo" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or_default();
            json!({ "ok": true, "output": { "tool": "echo", "text": text } }).to_string()
        }
        "sleep" => {
            let seconds = args.get("seconds").and_then(Value::as_u64).unwrap_or(1).min(policy.max_runtime_seconds);
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            json!({ "ok": true, "output": { "tool": "sleep", "seconds": seconds } }).to_string()
        }
        "sysinfo" => json!({
            "ok": true,
            "output": {
                "tool": "sysinfo",
                "hostname": crate::config::hostname(),
                "platform": crate::config::platform(),
                "agent_version": env!("CARGO_PKG_VERSION"),
                "policy": { "allow": policy.allow, "deny": policy.deny, "max_runtime_seconds": policy.max_runtime_seconds }
            }
        })
        .to_string(),
        "bash" => bash(policy, &args).await,
        other => failure("unknown_tool", &format!("`{other}` is not implemented by this agent")),
    }
}

async fn bash(policy: &Policy, args: &Value) -> String {
    let Some(command) = args.get("command").and_then(Value::as_str) else {
        return failure("invalid_args", "bash requires a `command` string");
    };
    let mut process = tokio::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" });
    if cfg!(windows) {
        process.arg("/C").arg(command);
    } else {
        process.arg("-c").arg(command);
    }
    if let Some(dir) = args
        .get("cwd")
        .and_then(Value::as_str)
        .or(policy.workdir.as_deref())
    {
        process.current_dir(dir);
    }
    process.kill_on_drop(true);
    process
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return failure("spawn_failed", &error.to_string()),
    };
    let limit = policy.max_runtime_seconds;
    match tokio::time::timeout(
        std::time::Duration::from_secs(limit),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(output)) => json!({
            "ok": output.status.success(),
            "output": {
                "tool": "bash",
                "exit_code": output.status.code(),
                "stdout": truncate(&output.stdout, policy.max_output_bytes),
                "stderr": truncate(&output.stderr, policy.max_output_bytes),
            }
        })
        .to_string(),
        Ok(Err(error)) => failure("exec_failed", &error.to_string()),
        Err(_) => failure(
            "timeout",
            &format!("command exceeded {limit}s and was killed"),
        ),
    }
}

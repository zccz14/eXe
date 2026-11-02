use serde_json::{json, Value};

/// Execution hygiene, not permission: one call cannot run forever or return an
/// unbounded amount of output. Fixed on purpose — the trust list is the only gate.
const MAX_RUNTIME_SECONDS: u64 = 60;
const MAX_OUTPUT_BYTES: usize = 262_144;

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

/// Runs one verified, decrypted command. A signature from an address in `trust`
/// is the whole authorization: there is no second, local permission list, and no
/// tool registry either — the agent offers exactly one verb, a shell.
pub async fn execute(name: &str, args: &str) -> String {
    let args: Value = match serde_json::from_str(args) {
        Ok(value @ Value::Object(_)) => value,
        _ => return failure("invalid_args", "arguments must be a JSON object"),
    };
    match name {
        "shell" => shell(&args).await,
        other => failure(
            "unknown_tool",
            &format!("`{other}` is not implemented by this agent"),
        ),
    }
}

/// One verb: `command` goes to the platform's own shell (`sh -c` on Unix,
/// `cmd /C` on Windows), which is why the name is `shell` and not `bash`.
async fn shell(args: &Value) -> String {
    let Some(command) = args.get("command").and_then(Value::as_str) else {
        return failure("invalid_args", "shell requires a `command` string");
    };
    let mut process = tokio::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" });
    if cfg!(windows) {
        process.arg("/C").arg(command);
    } else {
        process.arg("-c").arg(command);
    }
    if let Some(dir) = args.get("cwd").and_then(Value::as_str) {
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
    let limit = MAX_RUNTIME_SECONDS;
    match tokio::time::timeout(
        std::time::Duration::from_secs(limit),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(output)) => json!({
            "ok": output.status.success(),
            "output": {
                "tool": "shell",
                "exit_code": output.status.code(),
                "stdout": truncate(&output.stdout, MAX_OUTPUT_BYTES),
                "stderr": truncate(&output.stderr, MAX_OUTPUT_BYTES),
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

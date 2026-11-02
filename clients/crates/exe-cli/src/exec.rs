use serde_json::{json, Value};
use std::time::Duration;

/// Hygiene, not permission — but only half of it is fixed.
///
/// Output is bounded because a device must not buffer unbounded bytes, and
/// because a result is meant to land in a model's context: 10 MB is already far
/// more than anyone reads.
///
/// Time is the caller's business. `timeout_seconds` is an ordinary argument, and
/// the only ceiling is the call's own expiry — a command can never outlive the
/// envelope that carries it, so no second limit is invented here.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;
const MAX_OUTPUT_BYTES: usize = 10_000_000;

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
/// tool registry either — the client offers exactly one verb, a shell.
pub async fn execute(name: &str, args: &str, expires_at: u64) -> String {
    let args: Value = match serde_json::from_str(args) {
        Ok(value @ Value::Object(_)) => value,
        _ => return failure("invalid_args", "arguments must be a JSON object"),
    };
    match name {
        "shell" => shell(&args, expires_at).await,
        other => failure(
            "unknown_tool",
            &format!("`{other}` is not implemented by this client"),
        ),
    }
}

/// The caller asks, the envelope answers: whatever `timeout_seconds` says, the
/// command cannot run past the moment the call itself expires.
fn budget(args: &Value, expires_at: u64, now: u64) -> Result<Duration, &'static str> {
    let asked = match args.get("timeout_seconds") {
        None => DEFAULT_TIMEOUT_SECONDS,
        Some(value) => value
            .as_u64()
            .filter(|seconds| *seconds >= 1)
            .ok_or("timeout_seconds must be a positive number of seconds")?,
    };
    let left = expires_at.saturating_sub(now).max(1);
    Ok(Duration::from_secs(asked.min(left)))
}

/// Kills the whole tree on the way out — timeout or cancellation alike.
///
/// `kill_on_drop` only reaches the process we spawned, and what a caller runs is
/// a shell with children: `sh -c 'make'`. Leaving those behind would make a
/// cancelled call a call that merely stopped listening.
struct ProcessGroup(Option<u32>);

impl ProcessGroup {
    fn of(pid: Option<u32>) -> Self {
        Self(pid)
    }
    fn disarm(mut self) {
        self.0 = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let Some(pid) = self.0 else { return };
        let group = -(pid as i32);
        // SIGTERM first so a child can clean up, then SIGKILL: this runs on the
        // timeout path, where the answer is already "you ran too long".
        unsafe { libc::kill(group, libc::SIGTERM) };
        std::thread::sleep(Duration::from_millis(200));
        unsafe { libc::kill(group, libc::SIGKILL) };
    }
}

#[cfg(windows)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let Some(pid) = self.0 else { return };
        let _ = std::process::Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// One verb: `command` goes to the platform's own shell (`sh -c` on Unix,
/// `cmd /C` on Windows), which is why the name is `shell` and not `bash`.
async fn shell(args: &Value, expires_at: u64) -> String {
    let Some(command) = args.get("command").and_then(Value::as_str) else {
        return failure("invalid_args", "shell requires a `command` string");
    };
    let limit = match budget(args, expires_at, exe_core::unix_now()) {
        Ok(limit) => limit,
        Err(error) => return failure("invalid_args", error),
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
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group, so the whole tree can be signalled at once.
        process.as_std_mut().process_group(0);
    }
    let child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return failure("spawn_failed", &error.to_string()),
    };
    let guard = ProcessGroup::of(child.id());
    match tokio::time::timeout(limit, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            guard.disarm();
            let stdout_bytes = output.stdout.len().min(MAX_OUTPUT_BYTES);
            let stderr_bytes = output.stderr.len().min(MAX_OUTPUT_BYTES - stdout_bytes);
            json!({
                "ok": output.status.success(),
                "output": {
                    "tool": "shell",
                    "exit_code": output.status.code(),
                    "stdout": truncate(&output.stdout, stdout_bytes),
                    "stderr": truncate(&output.stderr, stderr_bytes),
                }
            })
            .to_string()
        }
        Ok(Err(error)) => failure("exec_failed", &error.to_string()),
        Err(_) => failure(
            "timeout",
            &format!("command exceeded {}s and was killed", limit.as_secs()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_may_ask_for_more_than_a_minute() {
        let asked = json!({ "command": "true", "timeout_seconds": 900 });
        assert_eq!(
            budget(&asked, exe_core::unix_now() + 3600, exe_core::unix_now()).unwrap(),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn the_envelope_is_the_ceiling() {
        let now = exe_core::unix_now();
        let asked = json!({ "command": "true", "timeout_seconds": 900 });
        assert_eq!(
            budget(&asked, now + 30, now).unwrap(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn the_default_stays_at_one_minute() {
        let now = exe_core::unix_now();
        assert_eq!(
            budget(&json!({ "command": "true" }), now + 3600, now).unwrap(),
            Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)
        );
    }

    #[test]
    fn a_timeout_must_be_a_positive_integer() {
        let now = exe_core::unix_now();
        for bad in [json!(0), json!(-1), json!("soon"), json!(1.5)] {
            let args = json!({ "command": "true", "timeout_seconds": bad });
            assert!(
                budget(&args, now + 3600, now).is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn a_timeout_kills_the_command_it_promised_to_kill() {
        let args = json!({ "command": "sleep 30", "timeout_seconds": 1 }).to_string();
        let started = std::time::Instant::now();
        let result = execute("shell", &args, exe_core::unix_now() + 60).await;
        assert!(result.contains("timeout"), "{result}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn exit_codes_and_streams_come_back() {
        let args = json!({ "command": "echo out; echo err >&2; exit 3" }).to_string();
        let result = execute("shell", &args, exe_core::unix_now() + 60).await;
        let value: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(value["output"]["exit_code"], 3);
        assert_eq!(value["output"]["stdout"], "out\n");
        assert_eq!(value["output"]["stderr"], "err\n");
    }
}

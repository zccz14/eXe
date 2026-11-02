//! C ABI for mobile shells. Both the Android app and the iOS app call these
//! three functions and otherwise reuse the desktop trust logic verbatim.
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;

use exe::{config, pair, run};

fn read(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the caller contract is a NUL-terminated UTF-8 string.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn export(value: String) -> *mut c_char {
    CString::new(value)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn exe_agent_version() -> *mut c_char {
    export(env!("CARGO_PKG_VERSION").to_owned())
}

/// Frees a string returned by this library.
///
/// # Safety
/// `value` must come from `exe_agent_version` and be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn exe_agent_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

pub(crate) fn run_inner(dir: PathBuf, base_url: String) -> i32 {
    std::env::set_var("EXE_CONFIG_DIR", &dir);
    if let Err(error) = config::ensure_policy() {
        tracing::error!(%error, "could not write the default policy");
        return 3;
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "could not start the runtime");
            return 4;
        }
    };
    runtime.block_on(async {
        let client = match reqwest::Client::builder()
            .user_agent(concat!("exe-mobile/", env!("CARGO_PKG_VERSION")))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "could not build the HTTP client");
                return 5;
            }
        };
        let cfg = match config::load() {
            Ok(cfg) => cfg,
            Err(_) => {
                let announced = dir.clone();
                match pair::pair(&client, base_url.trim_end_matches('/'), |code, uri| {
                    let _ =
                        std::fs::write(announced.join("pairing.txt"), format!("{code}\n{uri}\n"));
                })
                .await
                {
                    Ok(cfg) => cfg,
                    Err(error) => {
                        tracing::error!(%error, "pairing failed");
                        return 6;
                    }
                }
            }
        };
        let _ = std::fs::remove_file(dir.join("pairing.txt"));
        match run::run(cfg).await {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(%error, "agent stopped");
                7
            }
        }
    })
}

/// Blocks forever serving calls. `config_dir` holds config.toml, policy.toml and,
/// while pairing, a `pairing.txt` the shell reads to show the code.
///
/// # Safety
/// Both pointers must be valid NUL-terminated strings for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn exe_agent_run(config_dir: *const c_char, base_url: *const c_char) -> i32 {
    let (Some(config_dir), Some(base_url)) = (read(config_dir), read(base_url)) else {
        return 2;
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    run_inner(PathBuf::from(config_dir), base_url)
}

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JClass, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    /// `io.ntnl.exe.Agent.nativeRun(configDir, baseUrl)` — the JNI entry the APK calls.
    #[no_mangle]
    pub extern "system" fn Java_io_ntnl_exe_Agent_nativeRun<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config_dir: JString<'local>,
        base_url: JString<'local>,
    ) -> jint {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_target(false)
            .init();
        let dir: String = match env.get_string(&config_dir) {
            Ok(value) => value.into(),
            Err(_) => return 1,
        };
        let base: String = match env.get_string(&base_url) {
            Ok(value) => value.into(),
            Err(_) => return 1,
        };
        crate::run_inner(std::path::PathBuf::from(dir), base) as jint
    }
}

//! C ABI for mobile shells. Both the Android app and the iOS app call these
//! functions and otherwise reuse the desktop trust logic verbatim.
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;

use exe::{config, run};

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

/// The address this device signs with. The shell shows it so a human can add it
/// to the console; there is nothing to pair and no code to read out.
///
/// # Safety
/// `config_dir` must be a valid NUL-terminated string; the result must be freed
/// with `exe_agent_free`.
#[no_mangle]
pub unsafe extern "C" fn exe_agent_address(config_dir: *const c_char) -> *mut c_char {
    let Some(dir) = read(config_dir) else {
        return std::ptr::null_mut();
    };
    std::env::set_var("EXE_CONFIG_DIR", &dir);
    match config::load_or_create().and_then(|(cfg, _)| cfg.address()) {
        Ok(address) => export(address),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a string returned by this library.
///
/// # Safety
/// `value` must come from this library and be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn exe_agent_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

pub(crate) fn run_inner(dir: PathBuf, cloud: String) -> i32 {
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
        let cfg = match config::load_or_create() {
            Ok((mut cfg, _)) => {
                if !cloud.trim().is_empty() {
                    cfg.cloud = cloud.trim_end_matches('/').to_owned();
                    if let Err(error) = config::save(&cfg) {
                        tracing::error!(%error, "could not update the relay address");
                    }
                }
                cfg
            }
            Err(error) => {
                tracing::error!(%error, "could not create the device key");
                return 6;
            }
        };
        match cfg.address() {
            Ok(address) => {
                let _ = std::fs::write(dir.join("address.txt"), format!("{address}\n"));
                tracing::info!(address = address.as_str(), "eXe device address");
            }
            Err(error) => {
                tracing::error!(%error, "the stored secret is unusable");
                return 6;
            }
        }
        match run::run(cfg).await {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(%error, "agent stopped");
                7
            }
        }
    })
}

/// Blocks forever serving calls. `config_dir` holds config.toml, policy.toml and
/// an `address.txt` the shell reads to show this device's address.
///
/// # Safety
/// Both pointers must be valid NUL-terminated strings for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn exe_agent_run(config_dir: *const c_char, cloud: *const c_char) -> i32 {
    let (Some(config_dir), Some(cloud)) = (read(config_dir), read(cloud)) else {
        return 2;
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    run_inner(PathBuf::from(config_dir), cloud)
}

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JClass, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    /// `io.ntnl.exe.Agent.nativeRun(configDir, cloud)` — the JNI entry the APK calls.
    #[no_mangle]
    pub extern "system" fn Java_io_ntnl_exe_Agent_nativeRun<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config_dir: JString<'local>,
        cloud: JString<'local>,
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
        let relay: String = match env.get_string(&cloud) {
            Ok(value) => value.into(),
            Err(_) => return 1,
        };
        crate::run_inner(std::path::PathBuf::from(dir), relay) as jint
    }

    /// `io.ntnl.exe.Agent.nativeAddress(configDir)` — the address to paste into the console.
    #[no_mangle]
    pub extern "system" fn Java_io_ntnl_exe_Agent_nativeAddress<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        config_dir: JString<'local>,
    ) -> jni::sys::jstring {
        let dir: String = match env.get_string(&config_dir) {
            Ok(value) => value.into(),
            Err(_) => return std::ptr::null_mut(),
        };
        std::env::set_var("EXE_CONFIG_DIR", &dir);
        match crate::config::load_or_create().and_then(|(cfg, _)| cfg.address()) {
            Ok(address) => match env.new_string(address) {
                Ok(value) => value.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        }
    }
}

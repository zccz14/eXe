//! One device address, one running process.
//!
//! Idempotency lives in memory — the set of calls executing right now and the
//! results already sealed — so two processes on one configuration would execute
//! the same call twice: the relay pushes a call to every stream that address
//! opened, and neither process can see the other's memory.
//!
//! That used to be unlikely. A background service makes it the normal case: setup
//! starts one, and a human who read the old instructions types `exe run`.
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub struct Lock {
    _file: File,
}

fn lock_path() -> PathBuf {
    crate::config::config_dir().join("run.lock")
}

fn read_pid(path: &PathBuf) -> String {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };
    let mut text = String::new();
    let _ = file.read_to_string(&mut text);
    text.trim().to_owned()
}

/// The pid recorded by whoever holds the address, if anyone does.
pub fn holder() -> Option<u32> {
    let path = lock_path();
    let text = read_pid(&path);
    text.trim().parse().ok()
}

/// Holds an exclusive lock for the life of the returned value. Dropping it (or
/// the process ending) releases the address.
pub fn acquire() -> Result<Lock> {
    let path = lock_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let file = {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("could not open {}", path.display()))?;
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let pid = read_pid(&path);
            if pid.is_empty() {
                bail!("another `exe run` already owns this address");
            }
            bail!("another `exe run` already owns this address (pid {pid})");
        }
        file
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        // Windows refuses a second open with no sharing, which is the lock.
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .share_mode(0)
            .open(&path)
        {
            Ok(file) => file,
            Err(_) => {
                let pid = read_pid(&path);
                if pid.is_empty() {
                    bail!("another `exe run` already owns this address");
                }
                bail!("another `exe run` already owns this address (pid {pid})");
            }
        }
    };
    #[cfg(not(any(unix, windows)))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)?;

    let mut file = file;
    let _ = file.set_len(0);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = writeln!(file, "{}", std::process::id());
    let _ = file.flush();
    Ok(Lock { _file: file })
}

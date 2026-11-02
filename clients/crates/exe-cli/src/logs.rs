//! Where a background device writes, and how to read it back.
//!
//! A service has no terminal, so the log is the only place a failure can be
//! seen. It is capped at one generation — a device left running for a year must
//! not fill a disk.
use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

pub fn path() -> std::path::PathBuf {
    crate::service::log_path()
}

/// Called once at daemon start: the previous generation is kept as `.1`.
pub fn rotate() {
    let path = self::path();
    let Ok(meta) = std::fs::metadata(&path) else {
        return;
    };
    if meta.len() <= MAX_LOG_BYTES {
        return;
    }
    let _ = std::fs::rename(&path, path.with_extension("log.1"));
}

pub fn tail(lines: usize) -> Result<String> {
    let path = self::path();
    let mut text = String::new();
    std::fs::File::open(&path)
        .with_context(|| format!("no log at {}", path.display()))?
        .read_to_string(&mut text)?;
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    Ok(all[start..].join("\n"))
}

/// `exe logs -f`: print what is there, then follow.
pub fn follow(mut out: impl std::io::Write) -> Result<()> {
    let path = self::path();
    let mut file =
        std::fs::File::open(&path).with_context(|| format!("no log at {}", path.display()))?;
    let mut offset = 0u64;
    loop {
        file.seek(SeekFrom::Start(offset))?;
        let mut fresh = String::new();
        let read = file.read_to_string(&mut fresh)?;
        if read > 0 {
            offset += read as u64;
            out.write_all(fresh.as_bytes())?;
            out.flush()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

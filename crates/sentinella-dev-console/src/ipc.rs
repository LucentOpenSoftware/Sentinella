//! Synchronous named-pipe JSON-RPC client to the installed Sentinella
//! daemon. Mirrors the framing used by gui/src-tauri/src/daemon_client.rs
//! (4-byte big-endian length prefix + JSON body) but stays synchronous —
//! the dev-console doesn't need tokio for one-shot dev queries.
//!
//! Auth: reads the IPC secret from `<ProgramData>\Sentinella\state\ipc_secret`
//! exactly like the production GUI does. The file is intentionally
//! world-readable per the R3 ACL fix; we are not bypassing anything.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

pub const PIPE_NAME: &str = r"\\.\pipe\sentinelld";

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Rpc { code: i32, message: String },
    /// Reserved for the snapshot-mode path (read state without a live
    /// daemon). Kept in the enum so the UI/caller boundary is stable.
    #[allow(dead_code)]
    NoSecret,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "pipe i/o: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Rpc { code, message } => write!(f, "rpc {code}: {message}"),
            Self::NoSecret => write!(f, "IPC secret file not found (daemon not installed/running?)"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}

/// Resolve the installed ProgramData root for Sentinella state.
pub fn programdata_root() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(pd).join("Sentinella")
}

/// Load the IPC secret from disk. Returns `None` if the file is missing
/// or shorter than the 32-char minimum the daemon enforces.
pub fn load_secret() -> Option<String> {
    let path = programdata_root().join("state").join("ipc_secret");
    let s = std::fs::read_to_string(path).ok()?;
    let trimmed = s.trim().to_string();
    if trimmed.len() >= 32 { Some(trimmed) } else { None }
}

/// Open the named pipe with a brief retry (in case the daemon is mid-restart).
fn open_pipe() -> Result<std::fs::File, Error> {
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..6 {
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(150 * (attempt + 1)));
            }
        }
    }
    Err(Error::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "pipe not available")
    })))
}

/// Issue a JSON-RPC call and return the `result` field. Adds `auth` to
/// params automatically when a secret is available — methods that don't
/// require auth ignore it.
pub fn call(method: &str, mut params: Value) -> Result<Value, Error> {
    if let Some(secret) = load_secret() {
        if let Value::Object(ref mut map) = params {
            map.insert("auth".into(), Value::String(secret));
        } else {
            params = json!({ "auth": secret });
        }
    }

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&request)?;
    let mut pipe = open_pipe()?;

    let len = (body.len() as u32).to_be_bytes();
    pipe.write_all(&len)?;
    pipe.write_all(&body)?;
    pipe.flush()?;

    let mut resp_len = [0u8; 4];
    pipe.read_exact(&mut resp_len)?;
    let n = u32::from_be_bytes(resp_len) as usize;
    if n > 16 * 1024 * 1024 {
        return Err(Error::Io(std::io::Error::other(format!("response too large: {n}"))));
    }
    let mut buf = vec![0u8; n];
    pipe.read_exact(&mut buf)?;

    let resp: Value = serde_json::from_slice(&buf)?;
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
        let msg = err.get("message").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        return Err(Error::Rpc { code, message: msg });
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Convenience: call with `null` params.
pub fn call_simple(method: &str) -> Result<Value, Error> {
    call(method, Value::Null)
}

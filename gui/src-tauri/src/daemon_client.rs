//! Named-pipe client for talking to sentinelld.
//!
//! Each call opens a fresh connection, sends one JSON-RPC request,
//! reads one response, and closes.

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

const PIPE_NAME: &str = r"\\.\pipe\sentinelld";
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Errors from talking to the daemon.
#[derive(Debug)]
pub enum DaemonError {
    NotRunning,
    Io(std::io::Error),
    Json(serde_json::Error),
    Rpc { code: i32, message: String },
    Timeout(&'static str),
    InvalidFrame(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => write!(f, "Daemon not running — is sentinelld started?"),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
            Self::Timeout(op) => write!(f, "Daemon IPC timeout during {op}"),
            Self::InvalidFrame(msg) => write!(f, "Invalid daemon response frame: {msg}"),
        }
    }
}

impl From<std::io::Error> for DaemonError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<serde_json::Error> for DaemonError {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}
impl From<DaemonError> for String {
    fn from(e: DaemonError) -> String { e.to_string() }
}

/// Send a JSON-RPC request to the daemon and return the `result` value.
/// Retries on PIPE_BUSY (error 231) up to 3 times with backoff.
pub async fn call(method: &str, params: Value) -> Result<Value, DaemonError> {
    // Connect to named pipe with retry on busy.
    let mut pipe = {
        let mut last_err = None;
        let mut connected = None;
        for attempt in 0..4 {
            match tokio::net::windows::named_pipe::ClientOptions::new()
                .open(PIPE_NAME)
            {
                Ok(p) => { connected = Some(p); break; }
                Err(e) => {
                    let code = e.raw_os_error().unwrap_or(0);
                    if code == 2 || e.kind() == std::io::ErrorKind::NotFound {
                        // Pipe doesn't exist → daemon not running.
                        return Err(DaemonError::NotRunning);
                    }
                    if code == 231 && attempt < 3 {
                        // PIPE_BUSY → daemon running but all instances occupied.
                        // Retry after short backoff.
                        std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(DaemonError::Io(e));
                }
            }
        }
        match connected {
            Some(p) => p,
            None => return Err(DaemonError::Io(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "pipe busy after retries")
            }))),
        }
    };

    // Build JSON-RPC request.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let payload = serde_json::to_vec(&req)?;
    if payload.is_empty() {
        return Err(DaemonError::InvalidFrame("zero-length request".into()));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(DaemonError::InvalidFrame(format!(
            "request is {} bytes; limit is {MAX_FRAME_SIZE}",
            payload.len()
        )));
    }

    // Write length-prefixed frame.
    timeout(IPC_TIMEOUT, pipe.write_all(&(payload.len() as u32).to_be_bytes()))
        .await
        .map_err(|_| DaemonError::Timeout("write length"))??;
    timeout(IPC_TIMEOUT, pipe.write_all(&payload))
        .await
        .map_err(|_| DaemonError::Timeout("write payload"))??;

    // Read length-prefixed response.
    let mut len_buf = [0u8; 4];
    timeout(IPC_TIMEOUT, pipe.read_exact(&mut len_buf))
        .await
        .map_err(|_| DaemonError::Timeout("read length"))??;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 {
        return Err(DaemonError::InvalidFrame("zero-length response".into()));
    }
    if resp_len > MAX_FRAME_SIZE {
        return Err(DaemonError::InvalidFrame(format!(
            "{resp_len} bytes exceeds {MAX_FRAME_SIZE} byte limit"
        )));
    }
    let mut resp_buf = vec![0u8; resp_len];
    timeout(IPC_TIMEOUT, pipe.read_exact(&mut resp_buf))
        .await
        .map_err(|_| DaemonError::Timeout("read payload"))??;

    let resp: Value = serde_json::from_slice(&resp_buf)?;

    // Check for RPC error.
    if let Some(err) = resp.get("error") {
        return Err(DaemonError::Rpc {
            code: err.get("code").and_then(|v| v.as_i64()).unwrap_or(-1) as i32,
            message: err.get("message").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
        });
    }

    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Call with no params.
pub async fn call_simple(method: &str) -> Result<Value, DaemonError> {
    call(method, Value::Null).await
}

/// Send an authenticated request for dangerous local-only operations.
/// If the secret hasn't loaded yet (daemon still starting up), waits up to
/// 5 seconds polling for the secret file to appear before giving up.
pub async fn call_auth(method: &str, params: Value) -> Result<Value, DaemonError> {
    // Try up to 10 times (5 seconds total) to get a non-empty secret.
    // The daemon may not have written it yet on first boot.
    let mut attempts = 0;
    loop {
        let secret = crate::ipc_auth::secret();
        if !secret.is_empty() {
            return call_auth_inner(method, params, secret).await;
        }
        attempts += 1;
        if attempts >= 10 {
            return Err(DaemonError::Rpc {
                code: -32099,
                message: "IPC secret unavailable — daemon may still be starting (wait a few seconds and retry)".into(),
            });
        }
        // Invalidate cache so next call re-reads from disk.
        crate::ipc_auth::invalidate_cache();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn call_auth_inner(method: &str, mut params: Value, secret: &str) -> Result<Value, DaemonError> {
    match &mut params {
        Value::Object(map) => {
            map.insert("auth".into(), Value::String(secret.to_string()));
        }
        _ => {
            params = serde_json::json!({"auth": secret});
        }
    }
    call(method, params).await
}

/// Call with a serializable params struct.
#[allow(dead_code)]
pub async fn call_with<P: Serialize>(method: &str, params: &P) -> Result<Value, DaemonError> {
    call(method, serde_json::to_value(params).unwrap_or(Value::Null)).await
}

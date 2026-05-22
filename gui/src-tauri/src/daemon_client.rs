//! Named-pipe client for talking to sentinelld.
//!
//! Each call opens a fresh connection, sends one JSON-RPC request,
//! reads one response, and closes.

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PIPE_NAME: &str = r"\\.\pipe\sentinelld";

/// Errors from talking to the daemon.
#[derive(Debug)]
pub enum DaemonError {
    NotRunning,
    Io(std::io::Error),
    Json(serde_json::Error),
    Rpc { code: i32, message: String },
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => write!(f, "Daemon not running — is sentinelld started?"),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
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
pub async fn call(method: &str, params: Value) -> Result<Value, DaemonError> {
    // Connect to named pipe.
    let mut pipe = match tokio::net::windows::named_pipe::ClientOptions::new()
        .open(PIPE_NAME)
    {
        Ok(p) => p,
        Err(e) => {
            let code = e.raw_os_error().unwrap_or(0);
            // 2 = FILE_NOT_FOUND, 231 = PIPE_BUSY
            if code == 2 || code == 231 || e.kind() == std::io::ErrorKind::NotFound {
                return Err(DaemonError::NotRunning);
            }
            return Err(DaemonError::Io(e));
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

    // Write length-prefixed frame.
    pipe.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    pipe.write_all(&payload).await?;

    // Read length-prefixed response.
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    pipe.read_exact(&mut resp_buf).await?;

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

/// Call with a serializable params struct.
#[allow(dead_code)]
pub async fn call_with<P: Serialize>(method: &str, params: &P) -> Result<Value, DaemonError> {
    call(method, serde_json::to_value(params).unwrap_or(Value::Null)).await
}

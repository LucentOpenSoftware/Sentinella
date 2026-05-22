//! IPC server — JSON-RPC 2.0 over named pipe (Windows) or Unix socket.

use std::sync::Arc;
use anyhow::Result;
use sentinella_ipc_proto::*;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

mod state;
pub use state::AppState;

/// The IPC server.
pub struct Server {
    state: Arc<AppState>,
}

impl Server {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Arc::new(AppState::new()),
        })
    }

    pub async fn run(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        { self.run_named_pipe().await }
        #[cfg(not(target_os = "windows"))]
        { self.run_unix_socket().await }
    }

    #[cfg(target_os = "windows")]
    async fn run_named_pipe(&self) -> Result<()> {
        use tokio::net::windows::named_pipe::ServerOptions;
        let pipe_name = sentinella_common::IPC_PIPE_NAME;
        info!(pipe = pipe_name, "listening on named pipe");

        loop {
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(pipe_name)?;
            server.connect().await?;
            debug!("client connected");
            let st = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(server, &st).await {
                    warn!(%e, "client session ended with error");
                }
            });
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn run_unix_socket(&self) -> Result<()> {
        use tokio::net::UnixListener;
        let sock_path = sentinella_common::IPC_SOCKET_PATH;
        let _ = std::fs::remove_file(sock_path);
        if let Some(p) = std::path::Path::new(sock_path).parent() {
            std::fs::create_dir_all(p)?;
        }
        let listener = UnixListener::bind(sock_path)?;
        info!(path = sock_path, "listening on unix socket");

        loop {
            let (stream, _) = listener.accept().await?;
            debug!("client connected");
            let st = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, &st).await {
                    warn!(%e, "client session ended with error");
                }
            });
        }
    }
}

async fn handle_connection<S>(mut stream: S, state: &AppState) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    loop {
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len > MAX_FRAME_SIZE {
            error!(frame_len, "oversized frame, dropping client");
            return Ok(());
        }

        let mut payload = vec![0u8; frame_len];
        stream.read_exact(&mut payload).await?;

        let response = match serde_json::from_slice::<RpcRequest>(&payload) {
            Ok(req) => dispatch(&req, state).await,
            Err(e) => {
                warn!(%e, "malformed request");
                serde_json::to_vec(&RpcErrorResponse::err(
                    0, error_codes::PARSE_ERROR, format!("parse error: {e}"),
                ))?
            }
        };

        let resp_len = (response.len() as u32).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
    }
}

async fn dispatch(req: &RpcRequest, state: &AppState) -> Vec<u8> {
    debug!(method = %req.method, id = req.id, "dispatch");
    state.record_request();

    let result: Result<Value, (i32, String)> = match req.method.as_str() {
        // ── Engine ──────────────────────────────────────────
        "engine.status" => Ok(serde_json::to_value(state.engine_status()).unwrap()),
        "engine.reload" => {
            Ok(serde_json::to_value(engine::ReloadResult { ok: true }).unwrap())
        }

        // ── Scan ────────────────────────────────────────────
        "scan.start" => {
            let scan_type = req.params.get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("quick");
            let job_id = state.start_scan(scan_type);
            Ok(serde_json::to_value(scan::ScanStarted { job_id }).unwrap())
        }
        "scan.status" => Ok(serde_json::to_value(state.scan_status()).unwrap()),
        "scan.history" => Ok(serde_json::to_value(state.scan_history()).unwrap()),

        // ── Quarantine ──────────────────────────────────────
        "quarantine.list" => Ok(serde_json::to_value(state.quarantine_list()).unwrap()),

        // ── Watcher ─────────────────────────────────────────
        "watcher.status" => Ok(serde_json::to_value(state.watcher_status()).unwrap()),

        // ── Update ──────────────────────────────────────────
        "update.status" => Ok(serde_json::to_value(state.update_status()).unwrap()),
        "update.start" => {
            state.start_update();
            Ok(serde_json::to_value(serde_json::json!({"ok": true})).unwrap())
        }

        // ── Activity ────────────────────────────────────────
        "activity.list" => Ok(serde_json::to_value(state.activity_list()).unwrap()),

        // ── Runtime stats ───────────────────────────────────
        "stats.runtime" => Ok(serde_json::to_value(state.runtime_stats()).unwrap()),

        _ => Err((
            error_codes::METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method),
        )),
    };

    match result {
        Ok(val) => serde_json::to_vec(&RpcResponse::ok(req.id, val)).unwrap(),
        Err((code, msg)) => {
            serde_json::to_vec(&RpcErrorResponse::err(req.id, code, msg)).unwrap()
        }
    }
}

//! IPC server — JSON-RPC 2.0 over named pipe (Windows) or Unix socket.
//!
//! Security hardening:
//! - Frame size bounds (min 2, max 16 MiB)
//! - Method name length limit (64 chars)
//! - catch_unwind around dispatch to prevent daemon crash
//! - Graceful error responses for all failure modes

use anyhow::Result;
use sentinella_ipc_proto::*;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

mod state;
pub use state::{AppState, unify_detection_filtered};

/// Min valid JSON-RPC frame: `{}`
const MIN_FRAME_SIZE: usize = 2;

#[cfg(target_os = "windows")]
struct PipeSecurity {
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
    attrs: windows::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(target_os = "windows")]
impl PipeSecurity {
    fn new() -> Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        };
        use windows::core::PCWSTR;

        // SYSTEM + Administrators: full access.
        // Authenticated Users: read+write (connect + IPC only).
        // Critical ops still gated by IPC auth + challenge token + elevation check.
        let mut wide: Vec<u16> = std::ffi::OsStr::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_mut_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        Ok(Self { descriptor, attrs })
    }
}

#[cfg(target_os = "windows")]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                self.descriptor.0,
            ));
        }
    }
}

#[cfg(target_os = "windows")]
fn create_pipe_server(
    pipe_name: &str,
    first_instance: bool,
    security: &PipeSecurity,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_instance);
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&security.attrs as *const windows::Win32::Security::SECURITY_ATTRIBUTES)
                .cast_mut()
                .cast(),
        )
    }
}

pub struct Server {
    state: Arc<AppState>,
}

impl Server {
    pub fn with_engine(
        dll_dir: Option<PathBuf>,
        db_dir: Option<PathBuf>,
        database: Option<crate::db::Database>,
    ) -> Result<Self> {
        Ok(Self {
            state: Arc::new(AppState::new(dll_dir, db_dir, database)),
        })
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    pub async fn run(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.run_named_pipe().await
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.run_unix_socket().await
        }
    }

    #[cfg(target_os = "windows")]
    async fn run_named_pipe(&self) -> Result<()> {
        let pipe_name = sentinella_common::IPC_PIPE_NAME;
        info!(pipe = pipe_name, "listening on named pipe");
        let pipe_security = PipeSecurity::new()?;

        // Create first pipe instance.
        let mut server = create_pipe_server(pipe_name, true, &pipe_security)?;

        loop {
            // Wait for client connection.
            if let Err(e) = server.connect().await {
                // Brief backoff before recreating — prevents tight retry under contention.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                self.state.record_ipc_error();
                debug!(%e, "pipe connect error, recreating");
                server = match create_pipe_server(pipe_name, false, &pipe_security) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(%e, "failed to recreate pipe, backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                };
                continue;
            }

            // IMMEDIATELY create next pipe instance BEFORE handling connection.
            // This eliminates the PIPE_BUSY window — a new listener is always ready.
            let connected_pipe = server;
            server = match create_pipe_server(pipe_name, false, &pipe_security) {
                Ok(s) => s,
                Err(e) => {
                    error!(%e, "failed to create next pipe instance");
                    // Handle the current connection anyway, then retry.
                    let st = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(connected_pipe, st).await {
                            warn!(%e, "client session error");
                        }
                    });
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    server = create_pipe_server(pipe_name, false, &pipe_security)?;
                    continue;
                }
            };

            // Spawn handler for connected client.
            debug!("client connected");
            let st = Arc::clone(&self.state);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(connected_pipe, st).await {
                    warn!(%e, "client session error");
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
                if let Err(e) = handle_connection(stream, st).await {
                    warn!(%e, "client session error");
                }
            });
        }
    }
}

/// Per-connection idle timeout — drop stalled connections.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Per-read timeout — prevent slow-read attacks.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn handle_connection<S>(mut stream: S, state: Arc<AppState>) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    loop {
        // Idle timeout — disconnect if no new request within CONNECTION_TIMEOUT.
        match tokio::time::timeout(CONNECTION_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("client idle timeout");
                return Ok(());
            }
        }

        let frame_len = u32::from_be_bytes(len_buf) as usize;

        // Frame size validation.
        if frame_len < MIN_FRAME_SIZE {
            warn!(frame_len, "frame too small, dropping");
            return Ok(());
        }
        if frame_len > MAX_FRAME_SIZE {
            error!(frame_len, "frame too large, dropping");
            return Ok(());
        }

        let mut payload = vec![0u8; frame_len];
        // Read timeout — prevent slow-read DoS.
        match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                warn!("client read timeout during payload");
                return Ok(());
            }
        }

        // Parse and dispatch with panic protection.
        let response = match serde_json::from_slice::<RpcRequest>(&payload) {
            Ok(ref req) => {
                // Method name length limit.
                if req.method.len() > 64 {
                    serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_REQUEST,
                        "method name too long",
                    ))
                    .unwrap_or_default()
                } else {
                    // Catch panics in dispatch to prevent daemon crash.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // We can't use async inside catch_unwind easily,
                        // so dispatch is sync-safe (all our handlers are sync anyway).
                        dispatch_sync(req, &state)
                    })) {
                        Ok(resp) => resp,
                        Err(_) => {
                            error!(method = %req.method, "PANIC in dispatch handler — recovered");
                            serde_json::to_vec(&RpcErrorResponse::err(
                                req.id,
                                error_codes::INTERNAL_ERROR,
                                "internal error (recovered from panic)",
                            ))
                            .unwrap_or_default()
                        }
                    }
                }
            }
            Err(e) => {
                warn!(%e, "malformed JSON-RPC request");
                serde_json::to_vec(&RpcErrorResponse::err(
                    0,
                    error_codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                ))
                .unwrap_or_default()
            }
        };

        if response.is_empty() {
            // Fallback if serialization itself failed.
            let fallback = b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32603,\"message\":\"internal serialization error\"}}";
            let len = (fallback.len() as u32).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(fallback).await?;
        } else {
            let resp_len = (response.len() as u32).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&response).await?;
        }
    }
}

/// Synchronous dispatch — all handlers are sync (no async needed).
fn dispatch_sync(req: &RpcRequest, state: &Arc<AppState>) -> Vec<u8> {
    debug!(method = %req.method, id = req.id, "dispatch");
    state.record_request();

    let result: Result<Value, (i32, String)> = match req.method.as_str() {
        "engine.status" => ok_json(state.engine_status()),
        "engine.reload" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC engine reload required".to_string(),
                ))
                .unwrap_or_default();
            }
            match state.reload_engine() {
                Ok(sigs) => Ok(serde_json::json!({"ok": true, "signatures": sigs})),
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        "scan.start" => {
            let scan_type = req
                .params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("quick");
            // Full/startup scans require auth (resource-intensive).
            if matches!(scan_type, "full" | "startup") {
                let auth = req
                    .params
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !state.validate_ipc_auth(auth) {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_PARAMS,
                        "full/startup scans require IPC authentication".to_string(),
                    ))
                    .unwrap_or_default();
                }
            }
            let target = req.params.get("target").and_then(|v| v.as_str());
            // Validate target path if provided.
            if let Some(t) = target {
                if t.is_empty() {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_PARAMS,
                        "empty target path",
                    ))
                    .unwrap_or_default();
                }
                if t.len() > 4096 {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_PARAMS,
                        "target path too long",
                    ))
                    .unwrap_or_default();
                }
            }
            ok_json(state.start_scan(scan_type, target))
        }
        "scan.status" => ok_json(state.scan_status()),
        "scan.history" => ok_json(state.scan_history()),
        "scan.cancel" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC scan cancel required".to_string(),
                ))
                .unwrap_or_default();
            }
            let status = state.scan_status();
            if status.running || status.state == "queued" || status.state == "pending" {
                let cancelled = state.cancel_scan();
                state.log_activity("warning", "scan", "Scan cancelled by user", "", None);
                Ok(serde_json::json!({"ok": cancelled}))
            } else {
                // Scan already completed — not an error, just nothing to cancel.
                Ok(serde_json::json!({"ok": true, "note": "scan already completed"}))
            }
        }

        "quarantine.list" => {
            let rows = state.quarantine_list();
            let items: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    let vault_path = std::path::Path::new(&r.vault_path);
                    let vault_ok = vault_path.exists()
                        && vault_path
                            .metadata()
                            .map(|m| m.len() >= 12)
                            .unwrap_or(false);
                    serde_json::json!({
                        "id": r.quarantine_id,
                        "original_path": r.original_path,
                        "original_size": r.original_size,
                        "signature": r.virus_name,
                        "sha256": r.sha256,
                        "quarantined_at": r.quarantined_at,
                        "restorable": vault_ok && r.status == "quarantined",
                        "scan_id": r.scan_id,
                    })
                })
                .collect();
            ok_json(items)
        }
        "quarantine.add" => {
            // Dangerous command: this moves a file into encrypted quarantine and
            // deletes the original. Require the same one-shot challenge used by
            // restore/delete so arbitrary IPC clients cannot quarantine files
            // without first passing the guarded flow.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine add"}),
                )
            } else {
                let path = req
                    .params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let virus = req
                    .params
                    .get("virus_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let scan_id = req
                    .params
                    .get("scan_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match state.quarantine_file(path, virus, scan_id) {
                    Ok(r) => ok_json(r),
                    Err(e) => Ok(serde_json::json!({"error": e})),
                }
            }
        }
        "quarantine.restore" => {
            // Dangerous command — requires valid challenge token.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine restore"}),
                )
            } else {
                let id = req.params.get("id").and_then(|v| v.as_str()).unwrap_or("");
                match state.quarantine_restore(id) {
                    Ok(path) => Ok(serde_json::json!({"ok": true, "restored_to": path})),
                    Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                }
            }
        }
        "quarantine.delete" => {
            // Dangerous — permanently destroys quarantined file. Requires challenge token.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine delete"}),
                )
            } else {
                let id = req.params.get("id").and_then(|v| v.as_str()).unwrap_or("");
                match state.quarantine_delete(id) {
                    Ok(()) => Ok(serde_json::json!({"ok": true})),
                    Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                }
            }
        }

        "calibration.report_safe" => {
            // Record a restored file as likely false positive.
            let auth = req.params.get("auth").and_then(|v| v.as_str()).unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC update required".to_string(),
                ))
                .unwrap_or_default();
            }
            let quarantine_id = req.params.get("quarantine_id").and_then(|v| v.as_str()).unwrap_or("");
            let sha256 = req.params.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            let file_path = req.params.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
            let detection_name = req.params.get("detection_name").and_then(|v| v.as_str()).unwrap_or("");

            if sha256.is_empty() || file_path.is_empty() {
                Ok(serde_json::json!({"ok": false, "error": "missing sha256 or file_path"}))
            } else {
                let now = chrono::Utc::now().timestamp();
                let event = crate::calibration::RestoreEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_event_id: quarantine_id.to_string(),
                    timestamp: now,
                    file_path: file_path.to_string(),
                    file_hash: sha256.to_string(),
                    fp_category: crate::calibration::guess_fp_category(file_path),
                    user_notes: None,
                };
                state.calibration_record_restore(event);

                tracing::info!(
                    sha256 = sha256,
                    detection = detection_name,
                    category = crate::calibration::guess_fp_category(file_path).as_str(),
                    "calibration: file reported as safe by user"
                );

                Ok(serde_json::json!({"ok": true}))
            }
        }

        "runtime.status" => {
            // Runtime intelligence diagnostics — PLM + PowerShell + AMSI.
            let diag = state.runtime_intelligence_diagnostics();
            Ok(diag)
        }

        "runtime.scan_buffer" => {
            // Dev/test: scan a runtime buffer through ASTRA runtime pipeline.
            let auth = req.params.get("auth").and_then(|v| v.as_str()).unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id, error_codes::INVALID_PARAMS,
                    "authenticated IPC required".to_string(),
                )).unwrap_or_default();
            }

            let content_b64 = req.params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let language = req.params.get("language").and_then(|v| v.as_str()).unwrap_or("other");
            let source_app = req.params.get("source_app").and_then(|v| v.as_str()).unwrap_or("dev-inject");
            let content_name = req.params.get("content_name").and_then(|v| v.as_str()).unwrap_or("manual");

            // Decode base64 content or use raw UTF-8.
            let content = if content_b64.is_empty() {
                vec![]
            } else {
                // Try raw UTF-8 first (for plain text injection).
                content_b64.as_bytes().to_vec()
            };

            if content.is_empty() {
                Ok(serde_json::json!({"ok": false, "error": "empty content"}))
            } else {
                let buffer = crate::amsi::RuntimeBuffer {
                    source_app: source_app.to_string(),
                    source_pid: 0,
                    content_name: content_name.to_string(),
                    language: crate::amsi::ScriptLanguage::from_app_name(
                        &format!("{language}.exe")
                    ),
                    content,
                    original_size: content_b64.len(),
                    timestamp: chrono::Utc::now().timestamp(),
                };

                let result = crate::amsi::scan_runtime_buffer(&buffer, state.argus());

                // PLM correlation: check if source process has suspicious lineage.
                let plm_boost = if let Some(plm) = state.plm() {
                    if buffer.source_pid > 0 {
                        let chain = plm.graph.get_chain(buffer.source_pid);
                        chain.chain_suspicion
                    } else { 0 }
                } else { 0 };

                let total_score = result.score.saturating_add(plm_boost).min(100);

                Ok(serde_json::json!({
                    "ok": true,
                    "score": total_score,
                    "runtime_score": result.score,
                    "plm_boost": plm_boost,
                    "should_block": result.should_block,
                    "findings_count": result.findings.len(),
                    "scan_duration_us": result.scan_duration_us,
                    "language": format!("{:?}", buffer.language),
                    "findings": result.findings.iter().map(|f| {
                        serde_json::json!({
                            "layer": f.layer.display_name(),
                            "weight": f.weight,
                            "description": f.description,
                        })
                    }).collect::<Vec<_>>(),
                }))
            }
        }

        "detections.list" => {
            let scan_id = req
                .params
                .get("scan_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if scan_id.is_empty() {
                // Return recent detections across all scans.
                if let Ok(db_guard) = state.db_ref().lock() {
                    if let Some(ref db) = *db_guard {
                        ok_json(db.recent_detections(50))
                    } else {
                        Ok(serde_json::json!([]))
                    }
                } else {
                    Ok(serde_json::json!([]))
                }
            } else {
                if let Ok(db_guard) = state.db_ref().lock() {
                    if let Some(ref db) = *db_guard {
                        ok_json(db.detections_for_scan(scan_id))
                    } else {
                        Ok(serde_json::json!([]))
                    }
                } else {
                    Ok(serde_json::json!([]))
                }
            }
        }

        "watcher.status" => ok_json(state.watcher_status()),
        "idle_scanner.status" => ok_json(state.idle_scanner_stats()),
        "update.status" => ok_json(state.update_status()),
        "update.start" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC update required".to_string(),
                ))
                .unwrap_or_default();
            }
            let r = AppState::start_update(state);
            Ok(r)
        }
        "activity.list" => ok_json(state.activity_list()),
        "activity.log" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC activity log required".to_string(),
                ))
                .unwrap_or_default();
            }
            let bounded = |name: &str, fallback: &str, max: usize| -> String {
                req.params
                    .get(name)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(fallback)
                    .chars()
                    .take(max)
                    .collect()
            };
            let severity = bounded("severity", "info", 24);
            let category = bounded("category", "ipc", 48);
            let title = bounded("title", "Activity event", 160);
            let message = bounded("message", "", 512);
            state.log_activity(&severity, &category, &title, &message, None);
            Ok(serde_json::json!({"ok": true}))
        }
        "stats.runtime" => ok_json(state.runtime_stats()),

        // ARGUS heuristic analysis (requires auth — file content probing).
        "argus.analyze" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for ARGUS analysis".to_string(),
                ))
                .unwrap_or_default();
            }
            let target = req.params.get("path").and_then(|v| v.as_str());
            match target {
                Some(p) => {
                    let path = std::path::Path::new(p);
                    if path.exists() {
                        let verdict = state.argus().analyze_file(path);
                        ok_json(verdict)
                    } else {
                        Ok(serde_json::json!({"error": "File not found"}))
                    }
                }
                None => Ok(serde_json::json!({"error": "Missing 'path' parameter"})),
            }
        }

        // ARGUS verdict history.
        "argus.verdicts" => {
            let scan_id = req.params.get("scan_id").and_then(|v| v.as_str());
            let db_guard = state.db_ref().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref db) = *db_guard {
                let rows = match scan_id {
                    Some(id) => db.argus_verdicts_for_scan(id),
                    None => db.recent_argus_verdicts(50),
                };
                ok_json(rows)
            } else {
                Ok(serde_json::json!([]))
            }
        }

        "argus.version" => {
            let stats = state.argus().stats();
            Ok(serde_json::json!({
                "engine": "ARGUS",
                "version": argus::ENGINE_VERSION,
                "layers": [
                    "signatures", "mime_validation", "structural_analysis",
                    "packer_detection", "script_analysis", "pattern_detection",
                    "file_deception", "ioc_correlation", "yara_rules",
                    "reputation", "authenticode"
                ],
                "stats": stats
            }))
        }

        // ARGUS reload — hot-reload YARA rules + IOC hashes.
        "argus.reload" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC ARGUS reload required".to_string(),
                ))
                .unwrap_or_default();
            }
            let yara_dirs = vec![
                std::path::PathBuf::from("runtime/argus/rules/yara"),
                std::path::PathBuf::from("runtime/rules"),
            ];
            let yara_result = state.argus().yara.load_rules_on_large_stack(&yara_dirs);
            let yara_msg = match yara_result {
                Ok(count) => format!("{count} YARA rules reloaded"),
                Err(e) => format!("YARA reload error: {e}"),
            };

            // Reload IOC hashes.
            let ioc_paths = [
                std::path::PathBuf::from("runtime/rules/ioc_hashes.txt"),
                std::path::PathBuf::from("runtime/argus/rules/ioc/ioc_hashes.txt"),
            ];
            let mut ioc_count = 0u64;
            for p in &ioc_paths {
                if p.exists() {
                    if let Ok(c) = state.argus().ioc.load_from_file(p) {
                        ioc_count = c;
                        break;
                    }
                }
            }

            state.log_activity(
                "info",
                "argus",
                "ARGUS intelligence reloaded",
                &yara_msg,
                None,
            );
            Ok(serde_json::json!({
                "ok": true,
                "yara_rules": state.argus().yara.rule_count(),
                "ioc_hashes": ioc_count,
                "message": yara_msg,
            }))
        }

        // ARGUS intelligence packs — read manifest and return pack info.
        "argus.packs" => {
            let manifest_paths = [std::path::PathBuf::from(
                "runtime/argus/manifests/pack_manifest.json",
            )];
            let mut packs = serde_json::json!([]);
            for mp in &manifest_paths {
                if mp.exists() {
                    if let Ok(content) = std::fs::read_to_string(mp) {
                        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(p) = manifest.get("packs") {
                                packs = p.clone();
                            }
                        }
                    }
                }
            }
            let stats = state.argus().stats();
            Ok(serde_json::json!({
                "packs": packs,
                "total_yara_rules": stats.yara_rules_loaded,
                "total_ioc_hashes": stats.ioc_hashes_loaded,
                "reputation_entries": argus::layers::reputation::reputation_count(),
                "engine_version": argus::ENGINE_VERSION,
            }))
        }

        // ── Memory Scanner ──────────────────────────────────
        "memory.list_processes" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC memory access required".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(crate::memory_scanner::list_processes())
        }

        "memory.scan_process" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC memory access required".to_string(),
                ))
                .unwrap_or_default();
            }
            let pid = req.params.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if pid == 0 {
                Ok(serde_json::json!({"error": "pid required"}))
            } else {
                let result = crate::memory_scanner::scan_process(pid, state.argus());
                state.log_activity(
                    if result.findings.is_empty() {
                        "info"
                    } else {
                        "warning"
                    },
                    "memory_scan",
                    &format!("Memory scan: {} (PID {})", result.process_name, pid),
                    &format!(
                        "{} regions, {} findings",
                        result.regions_scanned,
                        result.findings.len()
                    ),
                    None,
                );
                ok_json(result)
            }
        }

        "settings.get" => {
            let config = crate::config::Config::load(None).unwrap_or_default();
            ok_json(config)
        }
        // Challenge token — GUI requests before dangerous commands.
        "security.challenge" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC challenge required".to_string(),
                ))
                .unwrap_or_default();
            }
            let token = state.generate_challenge_token();
            Ok(serde_json::json!({"token": token}))
        }

        "settings.set" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings update required".to_string(),
                ))
                .unwrap_or_default();
            }
            match serde_json::from_value::<crate::config::Config>(req.params.clone()) {
                Ok(mut config) => {
                    // Security-critical fields preserved from current config.
                    // These can only be changed via protection.set_critical (requires
                    // challenge token + UAC elevation on GUI side).
                    let current = crate::config::Config::load(None).unwrap_or_default();
                    config.realtime_enabled = current.realtime_enabled;
                    config.auto_quarantine = current.auto_quarantine;
                    state.load_detection_exclusions(config.excluded_detections.clone());

                    // Log any settings change for audit trail.
                    state.log_activity(
                        "info",
                        "settings",
                        "Configuration updated via IPC",
                        "",
                        None,
                    );

                    let path = std::path::PathBuf::from("runtime/config/sentinelld.toml");
                    match config.save(&path) {
                        Ok(()) => Ok(serde_json::json!({"ok": true})),
                        Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                    }
                }
                Err(e) => {
                    Ok(serde_json::json!({"ok": false, "error": format!("invalid config: {e}")}))
                }
            }
        }

        "health" => Ok(serde_json::json!({
            "status": "ok",
            "version": sentinella_common::PRODUCT_VERSION,
            "uptime_secs": state.uptime_secs(),
            "user_disabled": state.is_user_disabled(),
            "daemon_mode": state.daemon_mode(),
            "audit_mode": state.is_audit_mode(),
            "memory_pressure": state.pressure_state(),
        })),

        // ── Protection critical settings (requires challenge token) ──
        // Changes realtime_enabled, auto_quarantine, or pauses protection.
        // GUI must request UAC elevation before calling this.
        "protection.set_critical" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required — call security.challenge first".to_string(),
                ))
                .unwrap_or_default();
            }

            let mut config = crate::config::Config::load(None).unwrap_or_default();
            let mut changes = Vec::new();

            if let Some(v) = req.params.get("realtime_enabled").and_then(|v| v.as_bool()) {
                config.realtime_enabled = v;
                changes.push(format!("realtime_enabled={v}"));
                if !v {
                    // Stop watcher immediately.
                    state.disable_protection();
                } else if !state.is_user_disabled() {
                    state.enable_protection();
                }
            }
            if let Some(v) = req.params.get("auto_quarantine").and_then(|v| v.as_bool()) {
                config.auto_quarantine = v;
                changes.push(format!("auto_quarantine={v}"));
            }

            let path = std::path::PathBuf::from("runtime/config/sentinelld.toml");
            match config.save(&path) {
                Ok(()) => {
                    state.log_activity(
                        "warning",
                        "protection",
                        &format!("Critical setting changed: {}", changes.join(", ")),
                        "Requires administrator elevation",
                        None,
                    );
                    Ok(serde_json::json!({"ok": true, "changes": changes}))
                }
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        // Quick protection pause/resume (uses disable_protection/enable_protection state).
        "protection.disable" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required".to_string(),
                ))
                .unwrap_or_default();
            }
            state.disable_protection();
            state.log_activity(
                "warning",
                "protection",
                "Protection paused by user",
                "",
                None,
            );
            Ok(serde_json::json!({"ok": true, "state": "user_disabled"}))
        }

        "protection.enable" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required".to_string(),
                ))
                .unwrap_or_default();
            }
            state.enable_protection();
            state.log_activity("info", "protection", "Protection resumed by user", "", None);
            Ok(serde_json::json!({"ok": true, "state": "restoring"}))
        }

        // Diagnostics snapshot — no file contents, no secrets, no personal data.
        "diagnostics.export" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC diagnostics export required".to_string(),
                ))
                .unwrap_or_default();
            }
            let stats = state.runtime_stats();
            let engine = state.engine_status();
            let idle = state.idle_scanner_stats();
            let watcher = state.watcher_status();
            let argus_stats = state.argus().stats();

            // Recent errors from activity log (last 10 warnings/errors only).
            let recent_errors: Vec<serde_json::Value> = {
                let db_guard = state.db_ref().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref db) = *db_guard {
                    db.recent_activity(50)
                        .into_iter()
                        .filter(|a| {
                            a.severity == "warning"
                                || a.severity == "critical"
                                || a.severity == "error"
                        })
                        .take(10)
                        .map(|a| {
                            serde_json::json!({
                                "timestamp": a.timestamp,
                                "severity": a.severity,
                                "category": a.category,
                                "title": a.title,
                            })
                        })
                        .collect()
                } else {
                    vec![]
                }
            };

            // Quarantine metadata only (no file contents).
            let quarantine_summary: Vec<serde_json::Value> = state
                .quarantine_list()
                .into_iter()
                .take(20)
                .map(|r| {
                    serde_json::json!({
                        "signature": r.virus_name,
                        "quarantined_at": r.quarantined_at,
                        "original_size": r.original_size,
                        "status": r.status,
                    })
                })
                .collect();

            let last_scan_perf = state.last_scan_perf_json();
            let footprint = state.capture_footprint();

            Ok(serde_json::json!({
                "version": sentinella_common::PRODUCT_VERSION,
                "daemon_mode": state.daemon_mode(),
                "audit_mode": state.is_audit_mode(),
                "excluded_detections": state.detection_exclusions(),
                "engine_version": engine.engine_version,
                "argus_version": argus::ENGINE_VERSION,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "uptime_secs": stats.uptime_secs,
                "protection_state": stats.protection_state,
                "protection_detail": stats.protection_detail,
                "engine_state": engine.state,
                "signature_count": engine.signature_count,
                "argus_layers": argus_stats.active_layers,
                "argus_yara_rules": argus_stats.yara_rules_loaded,
                "argus_files_analyzed": argus_stats.files_analyzed,
                "argus_worker": state.argus_worker_diagnostics(),
                "orchestrator": state.orchestrator_diagnostics(),
                "watcher_active": watcher.enabled,
                "watcher_mode": watcher.mode,
                "idle_scanner": idle,
                "cache_hits": stats.cache_hits,
                "cache_misses": stats.cache_misses,
                "cache_entries": stats.cache_entries,
                "recent_errors": recent_errors,
                "quarantine_count": quarantine_summary.len(),
                "quarantine_summary": quarantine_summary,
                "last_scan_performance": last_scan_perf,
                "footprint": footprint,
                "fish": state.fish_diagnostics(),
                "resilience": state.resilience_diagnostics(),
                "memory_pressure": state.pressure_policy(),
                "generated_at": chrono::Utc::now().to_rfc3339(),
            }))
        }

        _ => Err((
            error_codes::METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method),
        )),
    };

    match result {
        Ok(val) => serde_json::to_vec(&RpcResponse::ok(req.id, val)).unwrap_or_default(),
        Err((code, msg)) => {
            serde_json::to_vec(&RpcErrorResponse::err(req.id, code, msg)).unwrap_or_default()
        }
    }
}

/// Helper: serialize a value into Ok(Value), catching serialization errors.
fn ok_json<T: serde::Serialize>(val: T) -> Result<Value, (i32, String)> {
    serde_json::to_value(val).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("serialization error: {e}"),
        )
    })
}

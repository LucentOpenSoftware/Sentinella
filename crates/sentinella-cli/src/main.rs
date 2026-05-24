//! `sentinella` CLI — command-line interface to the Sentinella daemon.
//!
//! Usage:
//!   sentinella status          — show engine status
//!   sentinella scan <path>     — request a scan
//!   sentinella update          — trigger signature update
//!   sentinella quarantine list — list quarantined items

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use sentinella_ipc_proto::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

const IPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "sentinella", about = "Sentinella antivirus CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show engine status.
    Status,
    /// Scan file(s) or a folder.
    Scan {
        /// Paths to scan (files or folders).
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Run a quick scan (Downloads, Desktop, Temp).
    QuickScan,
    /// Show scan status.
    ScanStatus,
    /// Cancel running scan.
    CancelScan,
    /// Quarantine a file.
    Quarantine {
        /// File path to quarantine.
        path: String,
        /// Virus name.
        #[arg(long, default_value = "Manual")]
        virus: String,
    },
    /// List quarantined items.
    QuarantineList,
    /// Restore a quarantined item.
    QuarantineRestore {
        /// Quarantine ID.
        id: String,
    },
    /// Delete a quarantined item permanently.
    QuarantineDelete {
        /// Quarantine ID.
        id: String,
    },
    /// Trigger a signature update.
    Update,
    /// Show runtime diagnostics.
    Diag,
    /// Show recent activity events.
    Activity,
    /// Show daemon configuration.
    Config,
    /// Show version information.
    Version,
    /// Disable real-time protection (requires admin).
    DisableRealtime,
    /// Enable real-time protection (requires admin).
    EnableRealtime,
    /// Pause all protection (requires admin).
    PauseProtection,
    /// Resume all protection (requires admin).
    ResumeProtection,
    /// Scan a script/runtime buffer through ASTRA runtime analysis.
    RuntimeScan {
        /// Script file to scan.
        path: std::path::PathBuf,
        /// Script language (powershell, jscript, vbscript, other).
        #[arg(long, default_value = "powershell")]
        language: String,
        /// Emit JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Export scan report as JSON.
    ExportReport {
        /// Output file path.
        #[arg(default_value = "sentinella-report.json")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let resp = send_request("engine.status", serde_json::Value::Null).await?;
            if let Some(r) = resp.get("result") {
                println!("  Sentinella Daemon Status");
                println!("  ========================");
                println!(
                    "  Engine:      {}",
                    r.get("state").and_then(|v| v.as_str()).unwrap_or("?")
                );
                println!(
                    "  Version:     {}",
                    r.get("engine_version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                );
                println!(
                    "  Signatures:  {}",
                    r.get("signature_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Protocol:    v{}",
                    r.get("protocol_version")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                if let Some(ts) = r.get("last_update").and_then(|v| v.as_i64()) {
                    println!(
                        "  Last update: {}",
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or("Unknown".into())
                    );
                } else {
                    println!("  Last update: Never");
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        Commands::Scan { paths } => {
            for path in &paths {
                let scan_type = if std::path::Path::new(path).is_dir() {
                    "folder"
                } else {
                    "file"
                };
                let params = serde_json::json!({ "type": scan_type, "target": path });
                let resp = send_request("scan.start", params).await?;
                if let Some(r) = resp.get("result") {
                    let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    if status == "running" {
                        println!(
                            "  Scan started (job {})",
                            r.get("job_id").and_then(|v| v.as_str()).unwrap_or("?")
                        );
                        println!("  Use 'sentinella scan-status' to track progress.");
                    } else if let Some(result) = r.get("result") {
                        let infected = result
                            .get("infected")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if infected {
                            println!(
                                "  THREAT: {} in {}",
                                result
                                    .get("virus_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?"),
                                path
                            );
                        } else {
                            println!("  CLEAN: {}", path);
                        }
                    } else if let Some(err) = r.get("error") {
                        println!("  ERROR: {}", err.as_str().unwrap_or("unknown"));
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }
        }
        Commands::QuickScan => {
            let params = serde_json::json!({"type": "quick"});
            let resp = send_request("scan.start", params).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::ScanStatus => {
            let resp = send_request("scan.status", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::CancelScan => {
            let resp = send_request("scan.cancel", ipc_auth_params()?).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Quarantine { path, virus } => {
            let token = request_challenge_token().await?;
            let params = serde_json::json!({"path": path, "virus_name": virus, "scan_id": "", "token": token});
            let resp = send_request("quarantine.add", params).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::QuarantineList => {
            let resp = send_request("quarantine.list", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::QuarantineRestore { id } => {
            let token = request_challenge_token().await?;
            let resp = send_request(
                "quarantine.restore",
                serde_json::json!({"id": id, "token": token}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::QuarantineDelete { id } => {
            let token = request_challenge_token().await?;
            let resp = send_request(
                "quarantine.delete",
                serde_json::json!({"id": id, "token": token}),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Update => {
            let resp = send_request("update.start", ipc_auth_params()?).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Diag => {
            let resp = send_request("stats.runtime", serde_json::Value::Null).await?;
            if let Some(r) = resp.get("result") {
                println!("  Sentinella Diagnostics");
                println!("  =====================");
                println!(
                    "  Uptime:        {}",
                    r.get("uptime_human")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                );
                println!(
                    "  Engine:        {}",
                    if r.get("engine_loaded")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        "Loaded"
                    } else {
                        "Not loaded"
                    }
                );
                println!(
                    "  Signatures:    {}",
                    r.get("signature_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Scans done:    {}",
                    r.get("scans_completed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Threats found: {}",
                    r.get("threats_found_total")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  IPC requests:  {}",
                    r.get("ipc_requests_served")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Quarantine:    {} items",
                    r.get("quarantine_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                );
                println!(
                    "  Watcher:       {}",
                    if r.get("watcher_active")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        "Active"
                    } else {
                        "Inactive"
                    }
                );
                println!(
                    "  DB stale:      {}",
                    if r.get("db_stale").and_then(|v| v.as_bool()).unwrap_or(false) {
                        format!(
                            "Yes ({} hours)",
                            r.get("db_stale_hours")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        )
                    } else {
                        "No".into()
                    }
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        Commands::Activity => {
            let resp = send_request("activity.list", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Config => {
            let resp = send_request("settings.get", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Version => {
            println!("  Sentinella CLI v{}", sentinella_common::PRODUCT_VERSION);
            println!("  Built with ClamAV engine integration");
            println!("  License: GPLv2");
        }
        Commands::DisableRealtime => {
            let token = request_challenge_token().await?;
            let resp = send_request("protection.set_critical", serde_json::json!({
                "token": token, "realtime_enabled": false
            })).await?;
            if resp.get("result").and_then(|r| r.get("ok")).and_then(|v| v.as_bool()) == Some(true) {
                println!("  Real-time protection disabled.");
            } else {
                let err = resp.get("result").and_then(|r| r.get("error")).and_then(|v| v.as_str()).unwrap_or("unknown");
                eprintln!("  Failed: {err}");
            }
        }
        Commands::EnableRealtime => {
            let token = request_challenge_token().await?;
            let resp = send_request("protection.set_critical", serde_json::json!({
                "token": token, "realtime_enabled": true
            })).await?;
            if resp.get("result").and_then(|r| r.get("ok")).and_then(|v| v.as_bool()) == Some(true) {
                println!("  Real-time protection enabled.");
            } else {
                let err = resp.get("result").and_then(|r| r.get("error")).and_then(|v| v.as_str()).unwrap_or("unknown");
                eprintln!("  Failed: {err}");
            }
        }
        Commands::PauseProtection => {
            let token = request_challenge_token().await?;
            let resp = send_request("protection.disable", serde_json::json!({"token": token})).await?;
            if resp.get("result").and_then(|r| r.get("ok")).and_then(|v| v.as_bool()) == Some(true) {
                println!("  Protection paused.");
            } else {
                let err = resp.get("result").and_then(|r| r.get("error")).and_then(|v| v.as_str()).unwrap_or("unknown");
                eprintln!("  Failed: {err}");
            }
        }
        Commands::ResumeProtection => {
            let token = request_challenge_token().await?;
            let resp = send_request("protection.enable", serde_json::json!({"token": token})).await?;
            if resp.get("result").and_then(|r| r.get("ok")).and_then(|v| v.as_bool()) == Some(true) {
                println!("  Protection resumed.");
            } else {
                let err = resp.get("result").and_then(|r| r.get("error")).and_then(|v| v.as_str()).unwrap_or("unknown");
                eprintln!("  Failed: {err}");
            }
        }
        Commands::RuntimeScan { path, language, json } => {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
            let auth_params = ipc_auth_params()?;
            let auth_val = auth_params.get("auth").cloned().unwrap_or(serde_json::Value::Null);
            let resp = send_request("runtime.scan_buffer", serde_json::json!({
                "auth": auth_val,
                "content": content,
                "language": language,
                "source_app": "sentinella-cli",
                "content_name": path.file_name().unwrap_or_default().to_string_lossy(),
            })).await?;

            if let Some(r) = resp.get("result") {
                if json {
                    println!("{}", serde_json::to_string_pretty(r)?);
                } else {
                    let score = r.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
                    let findings = r.get("findings_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let duration = r.get("scan_duration_us").and_then(|v| v.as_u64()).unwrap_or(0);
                    let lang = r.get("language").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("  ASTRA Runtime Analysis");
                    println!("  ======================");
                    println!("  File:      {}", path.display());
                    println!("  Language:  {lang}");
                    println!("  Score:     {score}/100");
                    println!("  Findings:  {findings}");
                    println!("  Duration:  {duration}us");
                    if let Some(block) = r.get("should_block").and_then(|v| v.as_bool()) {
                        if block { println!("  VERDICT:   BLOCK (high confidence malicious)"); }
                        else { println!("  VERDICT:   OBSERVE"); }
                    }
                }
            }
        }
        Commands::ExportReport { output } => {
            let status = send_request("engine.status", serde_json::Value::Null).await?;
            let stats = send_request("stats.runtime", serde_json::Value::Null).await?;
            let history = send_request("scan.history", serde_json::Value::Null).await?;
            let quarantine = send_request("quarantine.list", serde_json::Value::Null).await?;

            let report = serde_json::json!({
                "report_type": "sentinella_scan_report",
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "engine": status.get("result"),
                "runtime": stats.get("result"),
                "scan_history": history.get("result"),
                "quarantine": quarantine.get("result"),
            });

            std::fs::write(&output, serde_json::to_string_pretty(&report)?)?;
            println!("  Report saved to: {output}");
        }
    }

    Ok(())
}

async fn request_challenge_token() -> Result<String> {
    let resp = send_request("security.challenge", ipc_auth_params()?).await?;
    let token = resp
        .get("result")
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("daemon did not return a challenge token"))?;
    Ok(token.to_string())
}

fn ipc_auth_params() -> Result<serde_json::Value> {
    let auth = std::env::var("SENTINELLA_IPC_SECRET").map_err(|_| {
        anyhow::anyhow!("SENTINELLA_IPC_SECRET required for authenticated commands")
    })?;
    Ok(serde_json::json!({"auth": auth}))
}

/// Connect to the daemon, send a single request, return the response.
async fn send_request(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let req = RpcRequest {
        jsonrpc: JSONRPC_VERSION.into(),
        id: 1,
        method: method.into(),
        params,
    };

    let payload = serde_json::to_vec(&req)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_SIZE {
        bail!("request frame size invalid");
    }

    #[cfg(target_os = "windows")]
    let response = {
        use tokio::net::windows::named_pipe::ClientOptions;
        let mut client = ClientOptions::new().open(sentinella_common::IPC_PIPE_NAME)?;

        // Write length-prefixed request.
        let len_bytes = (payload.len() as u32).to_be_bytes();
        timeout(IPC_TIMEOUT, client.write_all(&len_bytes)).await??;
        timeout(IPC_TIMEOUT, client.write_all(&payload)).await??;

        // Read length-prefixed response.
        let mut len_buf = [0u8; 4];
        timeout(IPC_TIMEOUT, client.read_exact(&mut len_buf)).await??;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > MAX_FRAME_SIZE {
            bail!("response frame size invalid: {resp_len}");
        }
        let mut resp_buf = vec![0u8; resp_len];
        timeout(IPC_TIMEOUT, client.read_exact(&mut resp_buf)).await??;
        serde_json::from_slice::<serde_json::Value>(&resp_buf)?
    };

    #[cfg(not(target_os = "windows"))]
    let response = {
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(sentinella_common::IPC_SOCKET_PATH).await?;

        let len_bytes = (payload.len() as u32).to_be_bytes();
        timeout(IPC_TIMEOUT, stream.write_all(&len_bytes)).await??;
        timeout(IPC_TIMEOUT, stream.write_all(&payload)).await??;

        let mut len_buf = [0u8; 4];
        timeout(IPC_TIMEOUT, stream.read_exact(&mut len_buf)).await??;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > MAX_FRAME_SIZE {
            bail!("response frame size invalid: {resp_len}");
        }
        let mut resp_buf = vec![0u8; resp_len];
        timeout(IPC_TIMEOUT, stream.read_exact(&mut resp_buf)).await??;
        serde_json::from_slice::<serde_json::Value>(&resp_buf)?
    };

    Ok(response)
}

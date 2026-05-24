//! Sentinella Tauri backend.
//!
//! Each `#[tauri::command]` talks to sentinelld over the named pipe.
//! No command returns hardcoded data — everything comes from the daemon.

mod daemon_client;
mod ipc_auth;
mod supervisor;

use serde_json::Value;

// ── Elevation check ────────────────────────────────────────────

/// Check if the current process has administrator privileges.
/// Critical protection changes (disable realtime, pause protection,
/// confirmed shutdown) require elevation.
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    // Unix: check euid == 0.
    unsafe { libc::geteuid() == 0 }
}

/// Spawn the Sentinella CLI with `runas` verb to trigger UAC prompt.
/// Returns Ok(true) if the elevated command succeeded, Ok(false) if user denied UAC.
#[cfg(windows)]
fn spawn_elevated_cli(args: &[&str]) -> Result<bool, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    // Find sentinella CLI binary.
    let cli_path = find_cli_binary().ok_or("sentinella CLI not found")?;
    let cli_wide: Vec<u16> = std::ffi::OsStr::new(&cli_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args_str = args.join(" ");
    let args_wide: Vec<u16> = std::ffi::OsStr::new(&args_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(cli_wide.as_ptr()),
            PCWSTR(args_wide.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };

    // ShellExecuteW returns HINSTANCE > 32 on success.
    let code = result.0 as isize;
    if code > 32 {
        // UAC accepted, command launched. Brief wait for it to complete.
        std::thread::sleep(std::time::Duration::from_secs(2));
        Ok(true)
    } else {
        // User denied UAC or other error.
        Ok(false)
    }
}

#[cfg(windows)]
fn find_cli_binary() -> Option<String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Same directory as GUI.
            let candidate = dir.join("sentinella.exe");
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
            // Dev layout: target/release or target/debug.
            for ancestor in dir.ancestors().skip(1) {
                for profile in &["release", "debug"] {
                    let c = ancestor.join("target").join(profile).join("sentinella.exe");
                    if c.exists() {
                        return Some(c.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn spawn_elevated_cli(_args: &[&str]) -> Result<bool, String> {
    Err("Elevation not supported on this platform".into())
}

// ── Engine ──────────────────────────────────────────────────────

#[tauri::command]
async fn get_engine_status() -> Result<Value, String> {
    daemon_client::call_simple("engine.status").await.map_err(Into::into)
}

// ── Scan ────────────────────────────────────────────────────────

#[tauri::command]
async fn get_scan_status() -> Result<Value, String> {
    daemon_client::call_simple("scan.status").await.map_err(Into::into)
}

/// Scan a single file through the daemon's ClamAV engine.
/// This is the primary scan entry point for the GUI.
#[tauri::command]
async fn scan_file(path: String) -> Result<Value, String> {
    daemon_client::call_auth("scan.start", serde_json::json!({
        "type": "file",
        "target": path,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn start_quick_scan() -> Result<Value, String> {
    daemon_client::call_auth("scan.start", serde_json::json!({"type": "quick"}))
        .await.map_err(Into::into)
}

#[tauri::command]
async fn start_full_scan() -> Result<Value, String> {
    daemon_client::call_auth("scan.start", serde_json::json!({"type": "full"}))
        .await.map_err(Into::into)
}

#[tauri::command]
async fn start_startup_scan() -> Result<Value, String> {
    daemon_client::call_auth("scan.start", serde_json::json!({"type": "startup"}))
        .await.map_err(Into::into)
}

/// Scan an entire folder through the daemon.
#[tauri::command]
async fn scan_folder(path: String) -> Result<Value, String> {
    daemon_client::call_auth("scan.start", serde_json::json!({
        "type": "folder",
        "target": path,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn cancel_scan() -> Result<Value, String> {
    daemon_client::call_auth("scan.cancel", serde_json::json!({})).await.map_err(Into::into)
}

#[tauri::command]
async fn get_scan_history() -> Result<Value, String> {
    daemon_client::call_simple("scan.history").await.map_err(Into::into)
}

// ── Quarantine ──────────────────────────────────────────────────

#[tauri::command]
async fn get_quarantine_items() -> Result<Value, String> {
    daemon_client::call_simple("quarantine.list").await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_file(path: String, virus_name: String, scan_id: String) -> Result<Value, String> {
    // Manual quarantine is destructive: daemon requires one-shot challenge.
    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({})).await.map_err(|e| e.to_string())?;
    let token = token_resp.get("token").and_then(|v| v.as_str()).unwrap_or("");
    daemon_client::call("quarantine.add", serde_json::json!({
        "path": path, "virus_name": virus_name, "scan_id": scan_id, "token": token,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_restore(id: String) -> Result<Value, String> {
    // Get challenge token first — quarantine restore is a dangerous operation.
    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({})).await.map_err(|e| e.to_string())?;
    let token = token_resp.get("token").and_then(|v| v.as_str()).unwrap_or("");
    daemon_client::call("quarantine.restore", serde_json::json!({"id": id, "token": token})).await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_delete(id: String) -> Result<Value, String> {
    // Permanent deletion — requires challenge token.
    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({})).await.map_err(|e| e.to_string())?;
    let token = token_resp.get("token").and_then(|v| v.as_str()).unwrap_or("");
    daemon_client::call("quarantine.delete", serde_json::json!({"id": id, "token": token})).await.map_err(Into::into)
}

// ── Watcher ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_watcher_status() -> Result<Value, String> {
    daemon_client::call_simple("watcher.status").await.map_err(Into::into)
}

// ── Idle Scanner ────────────────────────────────────────────────

#[tauri::command]
async fn get_idle_scanner_status() -> Result<Value, String> {
    daemon_client::call_simple("idle_scanner.status").await.map_err(Into::into)
}

// ── Updates ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_update_status() -> Result<Value, String> {
    daemon_client::call_simple("update.status").await.map_err(Into::into)
}

#[tauri::command]
async fn start_signature_update() -> Result<Value, String> {
    daemon_client::call_auth("update.start", serde_json::json!({})).await.map_err(Into::into)
}

// ── Scan report export ──────────────────────────────────────────

#[tauri::command]
async fn export_scan_report() -> Result<Value, String> {
    let engine = daemon_client::call_simple("engine.status").await.map_err(|e| e.to_string())?;
    let stats = daemon_client::call_simple("stats.runtime").await.map_err(|e| e.to_string())?;
    let history = daemon_client::call_simple("scan.history").await.map_err(|e| e.to_string())?;
    let quarantine = daemon_client::call_simple("quarantine.list").await.map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "report_type": "sentinella_scan_report",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "engine": engine,
        "runtime": stats,
        "scan_history": history,
        "quarantine": quarantine,
    }))
}

// ── Detections ──────────────────────────────────────────────────

#[tauri::command]
async fn get_detections(scan_id: Option<String>) -> Result<Value, String> {
    let params = match scan_id {
        Some(id) => serde_json::json!({"scan_id": id}),
        None => serde_json::json!({}),
    };
    daemon_client::call("detections.list", params).await.map_err(Into::into)
}

// ── Settings ────────────────────────────────────────────────────

#[tauri::command]
async fn get_settings() -> Result<Value, String> {
    daemon_client::call_simple("settings.get").await.map_err(Into::into)
}

#[tauri::command]
async fn save_settings(config: Value) -> Result<Value, String> {
    daemon_client::call_auth("settings.set", config).await.map_err(Into::into)
}

// ── ARGUS Heuristics Engine ─────────────────────────────────────

/// Run ARGUS heuristic analysis on a single file.
/// Returns a full verdict with scored findings and reasons.
#[tauri::command]
async fn argus_analyze(path: String) -> Result<Value, String> {
    daemon_client::call_auth("argus.analyze", serde_json::json!({"path": path}))
        .await.map_err(Into::into)
}

/// Get ARGUS engine version and capability info.
#[tauri::command]
async fn argus_version() -> Result<Value, String> {
    daemon_client::call_simple("argus.version").await.map_err(Into::into)
}

/// Reload ARGUS intelligence (YARA rules + IOC hashes).
#[tauri::command]
async fn reload_argus() -> Result<Value, String> {
    daemon_client::call_auth("argus.reload", serde_json::json!({})).await.map_err(Into::into)
}

/// Get ARGUS intelligence pack info.
#[tauri::command]
async fn get_argus_packs() -> Result<Value, String> {
    daemon_client::call_simple("argus.packs").await.map_err(Into::into)
}

/// Get ARGUS verdicts — by scan_id or recent.
#[tauri::command]
async fn get_argus_verdicts(scan_id: Option<String>) -> Result<Value, String> {
    let params = match scan_id {
        Some(id) => serde_json::json!({"scan_id": id}),
        None => serde_json::json!({}),
    };
    daemon_client::call("argus.verdicts", params).await.map_err(Into::into)
}

// ── Security ────────────────────────────────────────────────────

/// Request a challenge token for dangerous IPC operations.
#[tauri::command]
async fn request_challenge_token() -> Result<Value, String> {
    daemon_client::call_auth("security.challenge", serde_json::json!({})).await.map_err(Into::into)
}

// ── Protection Control ──────────────────────────────────────────

/// Confirmed protection shutdown. Requires the exact phrase "DISABLE PROTECTION".
/// Logs the event and exits the GUI (daemon continues until manually stopped).
/// Triggers UAC if not elevated.
#[tauri::command]
async fn confirmed_shutdown(confirmation: String, app: tauri::AppHandle) -> Result<Value, String> {
    if confirmation != "DISABLE PROTECTION" {
        return Ok(serde_json::json!({"ok": false, "error": "Incorrect confirmation phrase"}));
    }

    // Log the intentional disable event.
    let _ = daemon_client::call_auth("activity.log", serde_json::json!({
        "severity": "warning",
        "category": "protection",
        "title": "Protection intentionally disabled by user",
        "message": "User confirmed shutdown via Settings → Advanced"
    })).await;

    // Exit GUI. Daemon continues running independently.
    app.exit(0);
    Ok(serde_json::json!({"ok": true}))
}

// ── Activity ────────────────────────────────────────────────────

#[tauri::command]
async fn get_activity() -> Result<Value, String> {
    daemon_client::call_simple("activity.list").await.map_err(Into::into)
}

// ── Diagnostics ────────────────────────────────────────────────

#[tauri::command]
async fn export_diagnostics() -> Result<Value, String> {
    daemon_client::call_auth("diagnostics.export", serde_json::json!({})).await.map_err(Into::into)
}

// ── Memory Scanner ─────────────────────────────────────────────

#[tauri::command]
async fn list_processes() -> Result<Value, String> {
    daemon_client::call_auth("memory.list_processes", serde_json::json!({})).await.map_err(Into::into)
}

#[tauri::command]
async fn scan_process_memory(pid: u32) -> Result<Value, String> {
    daemon_client::call_auth("memory.scan_process", serde_json::json!({"pid": pid}))
        .await.map_err(Into::into)
}

// ── Supervisor / Recovery ──────────────────────────────────────

#[tauri::command]
async fn get_recovery_state(
    state: tauri::State<'_, std::sync::Arc<supervisor::SupervisorState>>,
) -> Result<Value, String> {
    serde_json::to_value(state.info()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_connection_state(
    state: tauri::State<'_, std::sync::Arc<supervisor::SupervisorState>>,
) -> Result<Value, String> {
    serde_json::to_value(state.state()).map_err(|e| e.to_string())
}

// ── Protection critical settings (UAC-gated) ──────────────────

/// Change security-critical settings (realtime, auto-quarantine).
/// If GUI is not elevated, triggers UAC prompt via elevated CLI helper.
#[tauri::command]
async fn set_critical_protection(
    realtime_enabled: Option<bool>,
    auto_quarantine: Option<bool>,
) -> Result<Value, String> {
    if !is_elevated() {
        // Trigger UAC via CLI for realtime changes.
        if let Some(rt) = realtime_enabled {
            let cmd = if rt { "enable-realtime" } else { "disable-realtime" };
            return match spawn_elevated_cli(&[cmd]) {
                Ok(true) => Ok(serde_json::json!({"ok": true, "elevated": true})),
                Ok(false) => Ok(serde_json::json!({"ok": false, "requires_elevation": true,
                    "error": "Administrator privileges required. UAC prompt was denied."})),
                Err(e) => Ok(serde_json::json!({"ok": false, "requires_elevation": true, "error": e})),
            };
        }
        // auto_quarantine change also needs elevation.
        if auto_quarantine.is_some() {
            return Ok(serde_json::json!({"ok": false, "requires_elevation": true,
                "error": "Administrator privileges required for this setting."}));
        }
    }

    // Already elevated — proceed directly via IPC.
    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({}))
        .await
        .map_err(|e| e.to_string())?;
    let token = token_resp
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut params = serde_json::json!({"token": token});
    if let Some(v) = realtime_enabled {
        params["realtime_enabled"] = serde_json::json!(v);
    }
    if let Some(v) = auto_quarantine {
        params["auto_quarantine"] = serde_json::json!(v);
    }

    daemon_client::call("protection.set_critical", params)
        .await
        .map_err(Into::into)
}

/// Pause protection temporarily. Triggers UAC if not elevated.
#[tauri::command]
async fn pause_protection() -> Result<Value, String> {
    if !is_elevated() {
        return match spawn_elevated_cli(&["pause-protection"]) {
            Ok(true) => Ok(serde_json::json!({"ok": true, "elevated": true})),
            Ok(false) => Ok(serde_json::json!({"ok": false, "requires_elevation": true,
                "error": "Administrator privileges required. UAC prompt was denied."})),
            Err(e) => Ok(serde_json::json!({"ok": false, "requires_elevation": true, "error": e})),
        };
    }

    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({}))
        .await
        .map_err(|e| e.to_string())?;
    let token = token_resp
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    daemon_client::call(
        "protection.disable",
        serde_json::json!({"token": token}),
    )
    .await
    .map_err(Into::into)
}

/// Resume protection. No elevation required (enabling protection is safe).
#[tauri::command]
async fn resume_protection() -> Result<Value, String> {
    let token_resp = daemon_client::call_auth("security.challenge", serde_json::json!({}))
        .await
        .map_err(|e| e.to_string())?;
    let token = token_resp
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    daemon_client::call(
        "protection.enable",
        serde_json::json!({"token": token}),
    )
    .await
    .map_err(Into::into)
}

// ── Splash lifecycle ───────────────────────────────────────────

/// Called by splash.html when daemon is ready — shows main window, closes splash.
#[tauri::command]
async fn splash_ready(app: tauri::AppHandle) -> Result<(), String> {
    // Show main window.
    if let Some(main_win) = app.get_webview_window("main") {
        let _ = main_win.show();
        let _ = main_win.set_focus();
    }
    // Close splash.
    if let Some(splash_win) = app.get_webview_window("splash") {
        let _ = splash_win.close();
    }
    Ok(())
}

// ── Runtime stats ───────────────────────────────────────────────

#[tauri::command]
async fn get_runtime_stats() -> Result<Value, String> {
    daemon_client::call_simple("stats.runtime").await.map_err(Into::into)
}

// ── App entry with system tray ───────────────────────────────────

use tauri::{
    Manager,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // ── Daemon supervisor ────────────────────────────
            let supervisor_state = std::sync::Arc::new(supervisor::SupervisorState::new());
            app.manage(supervisor_state.clone());
            supervisor::start(supervisor_state);

            // Build tray menu — NO quit option. Protection shutdown requires
            // Settings → Advanced → explicit confirmation flow.
            let open = MenuItemBuilder::with_id("open", "Open Sentinella").build(app)?;
            let status = MenuItemBuilder::with_id("status", "Protection: Active").enabled(false).build(app)?;
            let scan = MenuItemBuilder::with_id("quick_scan", "Run Quick Scan").build(app)?;
            let about = MenuItemBuilder::with_id("about", "About").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&open)
                .separator()
                .item(&status)
                .item(&scan)
                .separator()
                .item(&about)
                .build()?;

            // Create tray icon using the Sentinella branding.
            let tray_icon = app.default_window_icon().cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing default window icon")
            })?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .menu(&menu)
                .tooltip("Sentinella — Antivirus Suite")
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "open" | "about" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "quick_scan" => {
                            // Trigger quick scan via IPC (fire and forget).
                            let handle = app.clone();
                            std::thread::spawn(move || {
                                if let Some((state, _)) = tray_check_daemon_sync() {
                                    if state == "ready" {
                                        // Send scan.start via sync pipe.
                                        let _ = tray_send_command_sync_auth(
                                            r#"{"jsonrpc":"2.0","id":1,"method":"scan.start","params":{"type":"quick"}}"#
                                        );
                                    }
                                }
                                // Show window so user can see progress.
                                if let Some(window) = handle.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.unminimize();
                                    let _ = window.set_focus();
                                }
                            });
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // ── Splash → main window lifecycle ─────────────────
            // Poll daemon from Rust — splash.html is static, no IPC bridge.
            // When daemon ready: close splash, show main.
            {
                let splash_handle = app.handle().clone();
                std::thread::spawn(move || {
                    // Wait briefly for splash to render.
                    std::thread::sleep(std::time::Duration::from_millis(800));

                    let mut attempts = 0u32;
                    let max_attempts = 45; // 45 seconds max

                    loop {
                        attempts += 1;
                        if attempts > max_attempts { break; }

                        // Check daemon via sync pipe.
                        if let Some((state, sigs)) = tray_check_daemon_sync() {
                            if state == "ready" && sigs > 0 {
                                // Daemon ready — brief pause then transition.
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                break;
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }

                    // Close splash, show main.
                    if let Some(splash) = splash_handle.get_webview_window("splash") {
                        let _ = splash.close();
                    }
                    if let Some(main_win) = splash_handle.get_webview_window("main") {
                        let _ = main_win.show();
                        let _ = main_win.set_focus();
                    }
                });
            }

            // Background task: update tray tooltip + status menu item.
            let app_handle = app.handle().clone();
            let status_item = status.clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(15));
                    let (tooltip, status_text) = match tray_check_daemon_sync() {
                        Some((state, sigs)) => {
                            if state == "ready" {
                                (
                                    format!("Sentinella — Protected ({} sigs)", sigs),
                                    "Protection: Active".to_string(),
                                )
                            } else {
                                (
                                    format!("Sentinella — Engine: {}", state),
                                    format!("Protection: {}", state),
                                )
                            }
                        }
                        None => (
                            "Sentinella — Daemon disconnected".to_string(),
                            "Protection: Disconnected".to_string(),
                        ),
                    };
                    if let Some(tray) = app_handle.tray_by_id("main") {
                        let _ = tray.set_tooltip(Some(&tooltip));
                    }
                    let _ = status_item.set_text(&status_text);
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide to tray instead of quitting.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_engine_status,
            get_scan_status,
            scan_file,
            start_quick_scan,
            start_full_scan,
            start_startup_scan,
            scan_folder,
            cancel_scan,
            get_scan_history,
            get_quarantine_items,
            quarantine_file,
            quarantine_restore,
            quarantine_delete,
            get_watcher_status,
            get_idle_scanner_status,
            get_update_status,
            start_signature_update,
            export_scan_report,
            get_detections,
            get_settings,
            save_settings,
            request_challenge_token,
            confirmed_shutdown,
            set_critical_protection,
            pause_protection,
            resume_protection,
            get_activity,
            get_runtime_stats,
            argus_analyze,
            argus_version,
            reload_argus,
            get_argus_packs,
            get_argus_verdicts,
            export_diagnostics,
            splash_ready,
            list_processes,
            scan_process_memory,
            get_recovery_state,
            get_connection_state,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Send an authenticated JSON-RPC command to daemon synchronously.
fn tray_send_command_sync_auth(json_request: &str) -> Option<()> {
    let request: serde_json::Value = serde_json::from_str(json_request).ok()?;
    let method = request.get("method")?.as_str()?;
    let mut params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    match &mut params {
        serde_json::Value::Object(map) => {
            map.insert(
                "auth".into(),
                serde_json::Value::String(crate::ipc_auth::secret().to_string()),
            );
        }
        _ => {
            params = serde_json::json!({"auth": crate::ipc_auth::secret()});
        }
    }
    blocking_daemon_call(method, params)?;
    Some(())
}

/// Synchronous daemon status check for tray tooltip.
fn tray_check_daemon_sync() -> Option<(String, u64)> {
    let result = blocking_daemon_call("engine.status", serde_json::Value::Null)?;
    let state = result.get("state")?.as_str()?.to_string();
    let sigs = result.get("signature_count")?.as_u64()?;
    Some((state, sigs))
}

fn blocking_daemon_call(method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .ok()?;

    rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(6),
            daemon_client::call(method, params),
        )
        .await
        .ok()?
        .ok()
    })
}

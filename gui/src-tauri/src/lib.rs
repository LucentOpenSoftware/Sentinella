//! Sentinella Tauri backend.
//!
//! Each `#[tauri::command]` talks to sentinelld over the named pipe.
//! No command returns hardcoded data — everything comes from the daemon.

mod daemon_client;
mod fullscreen_reporter;
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
            // Packaged Tauri layouts.
            for candidate in [
                dir.join("resources").join("daemon").join("sentinella-cli.exe"),
                dir.join("daemon").join("sentinella-cli.exe"),
                dir.join("sentinella-cli.exe"),
                dir.join("sentinella.exe"),
            ] {
                if candidate.exists() {
                    return Some(candidate.to_string_lossy().to_string());
                }
            }
            // Dev layout: target/release or target/debug.
            for ancestor in dir.ancestors().skip(1) {
                for profile in &["release", "debug"] {
                    for c in [
                        ancestor
                            .join("target")
                            .join(profile)
                            .join("sentinella.exe"),
                        ancestor
                            .join("target")
                            .join(profile)
                            .join("sentinella-cli.exe"),
                    ] {
                        if c.exists() {
                            return Some(c.to_string_lossy().to_string());
                        }
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
    // R7-LETHAL: daemon now requires auth — list leaks SHA-256 of every
    // caught malware + original file paths, which is attack-staging intel.
    daemon_client::call_auth("quarantine.list", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn quarantine_file(path: String, virus_name: String, scan_id: String) -> Result<Value, String> {
    // Manual quarantine is destructive: daemon requires one-shot challenge.
    // Adversary A2: token is bound to the method scope it's issued for.
    let token = daemon_client::challenge_token("quarantine.add").await.map_err(|e| e.to_string())?;
    daemon_client::call("quarantine.add", serde_json::json!({
        "path": path, "virus_name": virus_name, "scan_id": scan_id, "token": token,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_restore(id: String) -> Result<Value, String> {
    // Get challenge token first — quarantine restore is a dangerous operation.
    let token = daemon_client::challenge_token("quarantine.restore").await.map_err(|e| e.to_string())?;
    daemon_client::call("quarantine.restore", serde_json::json!({"id": id, "token": token})).await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_delete(id: String) -> Result<Value, String> {
    // Permanent deletion — requires challenge token.
    let token = daemon_client::challenge_token("quarantine.delete").await.map_err(|e| e.to_string())?;
    daemon_client::call("quarantine.delete", serde_json::json!({"id": id, "token": token})).await.map_err(Into::into)
}

/// Report a restored quarantine item as safe (likely false positive).
/// Records evidence in the calibration database for FP tuning.
#[tauri::command]
async fn report_safe(
    quarantine_id: String,
    sha256: String,
    file_path: String,
    detection_name: String,
) -> Result<Value, String> {
    daemon_client::call_auth("calibration.report_safe", serde_json::json!({
        "quarantine_id": quarantine_id,
        "sha256": sha256,
        "file_path": file_path,
        "detection_name": detection_name,
    })).await.map_err(Into::into)
}

// ── Watcher ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_watcher_status() -> Result<Value, String> {
    // Scanner-B Finding 2: response now auth-gated (watched_roots leak).
    daemon_client::call_auth("watcher.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

// ── Idle Scanner ────────────────────────────────────────────────

#[tauri::command]
async fn get_idle_scanner_status() -> Result<Value, String> {
    // Scanner-B Finding 3: response now auth-gated (current_target leak).
    daemon_client::call_auth("idle_scanner.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

// ── Updates ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_update_status() -> Result<Value, String> {
    daemon_client::call_simple("update.status").await.map_err(Into::into)
}

#[tauri::command]
async fn start_signature_update() -> Result<Value, String> {
    // R4-LETHAL-4: daemon requires auth (force-reload would open scan-blind window).
    daemon_client::call_auth("update.start", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

// ── Scan report export ──────────────────────────────────────────

#[tauri::command]
async fn export_scan_report() -> Result<Value, String> {
    let engine = daemon_client::call_simple("engine.status").await.map_err(|e| e.to_string())?;
    let stats = daemon_client::call_simple("stats.runtime").await.map_err(|e| e.to_string())?;
    let history = daemon_client::call_simple("scan.history").await.map_err(|e| e.to_string())?;
    // R7-LETHAL: quarantine list now requires auth.
    let quarantine = daemon_client::call_auth("quarantine.list", serde_json::json!({}))
        .await
        .map_err(|e| e.to_string())?;

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
    // R7-LETHAL: detections.list now requires auth (intel leak).
    daemon_client::call_auth("detections.list", params)
        .await
        .map_err(Into::into)
}

// ── Settings ────────────────────────────────────────────────────

#[tauri::command]
async fn get_settings() -> Result<Value, String> {
    // R4-LETHAL-6: settings.get now requires auth (leaks exclusion + trusted_hashes).
    daemon_client::call_auth("settings.get", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn save_settings(mut config: Value) -> Result<Value, String> {
    // Scanner-B Finding 1: settings.set now requires a one-shot challenge
    // token in addition to the IPC secret. Fetch one and inject before send.
    let token = daemon_client::challenge_token("settings.set").await.map_err(|e| e.to_string())?;
    if let Value::Object(ref mut map) = config {
        map.insert("token".into(), Value::String(token));
    } else {
        // Caller passed a non-object — wrap so the daemon receives the token.
        config = serde_json::json!({"token": token, "value": config});
    }
    daemon_client::call_auth("settings.set", config).await.map_err(Into::into)
}

// ── v0.1.8 elevation helpers (Settings critical fields) ──────

/// Returns true if the GUI process is running with administrator
/// privileges. Used by the Settings page to decide whether to lock
/// the kill-vector fields and show the "Restart as Administrator"
/// banner. Matches the daemon-side trust model: kill-vector
/// mutations also require an elevated caller end-to-end.
#[tauri::command]
fn is_elevated_check() -> bool {
    is_elevated()
}

/// Spawn a NEW elevated copy of the Sentinella GUI exe, then exit
/// the current (unelevated) process so only one Sentinella window
/// remains. Used by the Settings page's "Restart as Administrator"
/// button. Mirrors the dev-console's relaunch-as-admin flow.
///
/// v0.1.9 audit MED-9 — proper race fix:
///
/// v0.1.8 tried to win the race against `tauri_plugin_single_instance`
/// by sleeping 50 ms before calling `app.exit(0)`, hoping the parent's
/// mutex would release before the elevated child's mutex check ran.
/// That logic is INVERTED: the sleep actively DELAYS mutex release.
/// On a cold-cache laptop with AV inspecting newly-touched DLLs, the
/// parent's Tauri teardown (webview destroy → plugin teardown → tokio
/// runtime shutdown) commonly exceeds 100-300 ms while the elevated
/// child's cold-start-to-mutex-check is 200-600 ms. The window where
/// the child loses is real and timing-dependent.
///
/// v0.1.9 fix: pass `--elevated-restart` as a CLI argument when
/// spawning the elevated copy. The single-instance plugin callback in
/// the elevated process detects this argument and treats itself as a
/// LEGITIMATE second instance (no focus-existing dedup). The race is
/// now structurally impossible — even if the parent is still alive
/// when the child checks the mutex, the child doesn't dedup itself
/// because the arg explicitly opts out. The parent still exits via
/// `app.exit(0)` for cleanliness, but timing no longer matters.
///
/// `ShellExecuteW` with the "runas" verb is synchronous on the UAC
/// dialog — does not return until the user dismisses it. So when we
/// exit, we already know UAC outcome.
#[cfg(windows)]
#[tauri::command]
fn restart_as_admin(app: tauri::AppHandle) -> Result<Value, String> {
    if is_elevated() {
        return Ok(serde_json::json!({"ok": true, "already_elevated": true}));
    }
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_wide: Vec<u16> = std::ffi::OsStr::new(&exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // The handshake: child checks for this arg in the single-instance
    // callback and skips the focus-existing branch.
    let args: Vec<u16> = std::ffi::OsStr::new(ELEVATED_RESTART_ARG)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            PCWSTR(args.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = result.0 as isize;
    if code > 32 {
        // UAC accepted. Parent must die FAST so the OS releases its
        // single_instance named mutex before the elevated child
        // hits its check. The previous app.exit(0) approach triggered
        // a graceful Tauri unwind (webview destroy → plugin teardown
        // → tokio shutdown) that held the mutex for hundreds of ms;
        // the elevated child reached its dedup check first and
        // exited as a duplicate.
        //
        // std::process::exit terminates immediately — OS reaps all
        // handles (incl. the mutex) within microseconds. The IPC
        // response is sacrificed but the UI is dying anyway.
        //
        // Defence in depth: the elevated child ALSO skips the
        // single_instance plugin entirely at its main() entry (see
        // lib.rs::run), so even if the OS were slow at releasing,
        // the child can't dedup itself against the parent.
        let _ = app; // keep param for future use; not needed for the exit path
        std::thread::spawn(|| {
            // 50 ms to give ShellExecuteW callers a moment to dispatch
            // before the response is truncated. Empirically reliable
            // even on cold-cache disks since std::process::exit doesn't
            // block on Tauri teardown.
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::process::exit(0);
        });
        Ok(serde_json::json!({"ok": true}))
    } else if code == 5 {
        // SE_ERR_ACCESSDENIED — UAC denied.
        Ok(serde_json::json!({"ok": false, "error": "User denied UAC prompt"}))
    } else {
        Ok(serde_json::json!({"ok": false, "error": format!("ShellExecuteW failed with code {code}")}))
    }
}

/// CLI argument the parent passes to the elevated child so the
/// single-instance plugin in the child knows to skip the
/// focus-existing dedup. v0.1.9 audit MED-9. Keep in lockstep with
/// the matching check in the single_instance callback below.
pub const ELEVATED_RESTART_ARG: &str = "--elevated-restart";

#[cfg(not(windows))]
#[tauri::command]
fn restart_as_admin() -> Result<Value, String> {
    Ok(serde_json::json!({"ok": false, "error": "Elevation not supported on this platform"}))
}

// ── v0.1.8 FullConfig surface (Settings page expansion) ─────────

/// Fetch the full daemon configuration — every TOML knob, structured.
/// Used by the v0.1.8 Settings page tabs. Returns FullConfig JSON
/// (with developer.password_sha256 already excluded by the proto type).
#[tauri::command]
async fn get_full_settings() -> Result<Value, String> {
    daemon_client::call_auth("settings.get_full", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

/// Defaults snapshot for "reset to default" buttons. Pure — never
/// touches the on-disk config, just returns FullConfig::default().
#[tauri::command]
async fn get_default_settings() -> Result<Value, String> {
    daemon_client::call_auth("settings.get_defaults", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

/// Map of field path → RestartRequirement. Drives the per-field
/// "needs restart" pill and the footer "Restart now" batch button.
#[tauri::command]
async fn get_restart_requirements() -> Result<Value, String> {
    daemon_client::call_auth("settings.restart_requirements", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

/// Save NON-critical fields. Kill-vector fields must use
/// `set_critical_settings` (UAC-gated). The daemon rejects the whole
/// request with INSUFFICIENT_PRIVILEGE if any critical field differs
/// from the current value — surface that error to the user verbatim.
#[tauri::command]
async fn save_full_settings(mut config: Value) -> Result<Value, String> {
    let token = daemon_client::challenge_token("settings.set_full").await.map_err(|e| e.to_string())?;
    if let Value::Object(ref mut map) = config {
        map.insert("token".into(), Value::String(token));
    } else {
        config = serde_json::json!({"token": token, "value": config});
    }
    daemon_client::call_auth("settings.set_full", config).await.map_err(Into::into)
}

/// Change kill-vector settings (exclusions, watched roots, trusted
/// hashes, etc.). Requires the GUI to be running elevated — if not,
/// returns `{ok: false, requires_elevation: true}` and the GUI shows
/// a "Restart as Administrator" prompt. We do NOT silently relaunch:
/// any per-op UAC prompt path would have to round-trip through a CLI
/// stub that accepts JSON, which is fragile compared to the
/// admin-relaunch flow the dev-console established.
#[tauri::command]
async fn set_critical_settings(mut params: Value) -> Result<Value, String> {
    if !is_elevated() {
        return Ok(serde_json::json!({
            "ok": false,
            "requires_elevation": true,
            "error": "Administrator privileges required. Run Sentinella as Administrator to change these settings.",
        }));
    }
    let token = daemon_client::challenge_token("protection.set_critical").await.map_err(|e| e.to_string())?;
    if let Value::Object(ref mut map) = params {
        map.insert("token".into(), Value::String(token));
    } else {
        params = serde_json::json!({"token": token});
    }
    daemon_client::call("protection.set_critical", params)
        .await
        .map_err(Into::into)
}

// ── Developer mode (local-only perf telemetry, v0.1.6) ──────────

/// Read developer-mode status (never returns the password hash).
#[tauri::command]
async fn get_developer_status() -> Result<Value, String> {
    daemon_client::call_auth("dev.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

/// Toggle developer mode. The plaintext password is verified daemon-side
/// against the provisioned hash; it is never persisted by the GUI.
#[tauri::command]
async fn set_developer_mode(
    password: String,
    enabled: bool,
    telemetry_enabled: Option<bool>,
) -> Result<Value, String> {
    let mut params = serde_json::json!({ "password": password, "enabled": enabled });
    if let Some(t) = telemetry_enabled {
        params["telemetry_enabled"] = serde_json::json!(t);
    }
    daemon_client::call_auth("dev.set_developer_mode", params)
        .await
        .map_err(Into::into)
}

/// Run the ARGUS hardware-parity benchmark (developer mode only). Returns the
/// report JSON; the daemon also appends it to the local perf-telemetry file.
#[tauri::command]
async fn run_benchmark(passes: Option<u32>) -> Result<Value, String> {
    let params = serde_json::json!({ "passes": passes.unwrap_or(3) });
    daemon_client::call_auth("benchmark.run", params)
        .await
        .map_err(Into::into)
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
///
/// v0.1.7 audit promoted argus.reload to PrivilegedMutation in
/// policy.rs (Adversary A3 fix — chaining argus.reload with
/// update.start + engine.reload could multiply the reload-stacking
/// budget). The GUI command was never updated to fetch a challenge
/// token, so the button gave "RPC error -32602: challenge token
/// required for ARGUS reload" every time. Fix: fetch a one-shot
/// challenge token and inject it before the call, same pattern as
/// settings.set / engine.reload.
#[tauri::command]
async fn reload_argus() -> Result<Value, String> {
    let token = daemon_client::challenge_token("argus.reload")
        .await
        .map_err(|e| e.to_string())?;
    daemon_client::call_auth("argus.reload", serde_json::json!({"token": token}))
        .await
        .map_err(Into::into)
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

/// Request a challenge token for a specific dangerous IPC method.
/// Adversary A2: tokens are method-scoped on the daemon side — callers MUST
/// declare which method the token is for, and the daemon will reject any
/// attempt to use it against a different method.
#[tauri::command]
async fn request_challenge_token(method: String) -> Result<Value, String> {
    daemon_client::call_auth(
        "security.challenge",
        serde_json::json!({ "method": method }),
    )
    .await
    .map_err(Into::into)
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
    // R7-LETHAL: activity.list now requires auth (leaks scan history + settings changes).
    daemon_client::call_auth("activity.list", serde_json::json!({}))
        .await
        .map_err(Into::into)
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
    let token = daemon_client::challenge_token("protection.set_critical").await.map_err(|e| e.to_string())?;

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

    let token = daemon_client::challenge_token("protection.disable").await.map_err(|e| e.to_string())?;
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
    let token = daemon_client::challenge_token("protection.enable").await.map_err(|e| e.to_string())?;
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

#[tauri::command]
async fn get_runtime_intelligence() -> Result<Value, String> {
    // Adversary A1: runtime.status now requires auth — handler used to leak
    // PLM/ETW/ps_bridge/trust diagnostics to any local caller.
    daemon_client::call_auth("runtime.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn get_trust_status() -> Result<Value, String> {
    // R7-LETHAL: trust.status now requires auth (leaks trusted signer list).
    daemon_client::call_auth("trust.status", serde_json::json!({}))
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn get_signature_sources() -> Result<Value, String> {
    daemon_client::call_simple("sources.status").await.map_err(Into::into)
}

#[tauri::command]
async fn set_signature_source(provider_id: String) -> Result<Value, String> {
    // Provider change is security-sensitive — requires challenge token.
    let token = daemon_client::challenge_token("sources.set").await.map_err(|e| e.to_string())?;
    daemon_client::call("sources.set", serde_json::json!({
        "provider": provider_id,
        "challenge_token": token,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn rollback_signature_source() -> Result<Value, String> {
    let token = daemon_client::challenge_token("sources.rollback").await.map_err(|e| e.to_string())?;
    daemon_client::call("sources.rollback", serde_json::json!({
        "challenge_token": token,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn update_signature_source() -> Result<Value, String> {
    let token = daemon_client::challenge_token("sources.update").await.map_err(|e| e.to_string())?;
    daemon_client::call("sources.update", serde_json::json!({
        "challenge_token": token,
    })).await.map_err(Into::into)
}

#[tauri::command]
async fn quarantine_restore_as(id: String, dest: String) -> Result<Value, String> {
    let token = daemon_client::challenge_token("quarantine.restore_as").await.map_err(|e| e.to_string())?;
    daemon_client::call("quarantine.restore_as", serde_json::json!({
        "id": id, "dest": dest, "token": token,
    })).await.map_err(Into::into)
}

// ── App entry with system tray ───────────────────────────────────

use tauri::{
    Manager,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Detect --minimized flag (autostart at login → tray only, no UI).
    let start_minimized = std::env::args().any(|a| a == "--minimized");

    // v0.1.9 user-reported fix (replaces the broken v0.1.9 init-time
    // single-instance bypass): the elevated child has to skip the
    // single_instance plugin at ITS OWN startup, not in the parent's
    // callback. The plugin's dedup logic kills the second instance
    // BEFORE the parent's callback fires — checking args in the
    // callback (the v0.1.9 first attempt) only informed the parent,
    // too late for the child which had already exited.
    //
    // Correct fix: detect --elevated-restart at the child's main()
    // entry and conditionally skip the single_instance plugin
    // registration. The child becomes its own canonical instance.
    let elevated_restart =
        std::env::args().any(|a| a == ELEVATED_RESTART_ARG);

    let mut builder = tauri::Builder::default();
    if !elevated_restart {
        // Normal startup: register single-instance dedup as before.
        // If a second Sentinella.exe launches (e.g. user double-clicks
        // Start Menu shortcut after autostart already ran), focus the
        // existing main window instead of spawning a duplicate.
        // Without this: two supervisors, two tray icons (second fails
        // silent), two tokio runtimes polling daemon — wasted resources
        // + UX confusion.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            use tauri::Manager;
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
        }));
    } else {
        log::info!(
            "elevated restart detected (CLI arg present) — single_instance plugin SKIPPED for this process"
        );
    }
    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            // ── Daemon supervisor ────────────────────────────
            let supervisor_state = std::sync::Arc::new(supervisor::SupervisorState::new());
            app.manage(supervisor_state.clone());
            supervisor::start(supervisor_state);

            // ── v0.1.9 Phase 4: GUI-session fullscreen reporter ──
            // Daemon is in session 0 and can't see foreground windows;
            // we are in the user session and can. Push the verdict every
            // 5s so the idle scanner's pause-on-fullscreen actually
            // works for real games. Fully fail-safe — see module docs.
            fullscreen_reporter::spawn();

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
            // Minimized autostart: close splash + main never shown, only tray.
            // Normal launch: show splash → wait for daemon → swap to main.
            if start_minimized {
                // Close splash window (it's hidden but exists) — frees resources.
                if let Some(splash) = app.get_webview_window("splash") {
                    let _ = splash.close();
                }
                // Main window stays hidden (visible: false in config).
                // User opens it via tray "Open Sentinella" menu.
            } else {
                // Show splash (it's created hidden by default now).
                if let Some(splash) = app.get_webview_window("splash") {
                    let _ = splash.show();
                    let _ = splash.set_focus();
                }
                let splash_handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(800));

                    let mut attempts = 0u32;
                    let max_attempts = 15;

                    loop {
                        attempts += 1;
                        if attempts > max_attempts { break; }
                        if tray_check_daemon_sync().is_some() {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }

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
            report_safe,
            get_watcher_status,
            get_idle_scanner_status,
            get_update_status,
            start_signature_update,
            export_scan_report,
            get_detections,
            get_settings,
            save_settings,
            // v0.1.8 FullConfig surface — Settings page expansion
            is_elevated_check,
            restart_as_admin,
            get_full_settings,
            get_default_settings,
            get_restart_requirements,
            save_full_settings,
            set_critical_settings,
            get_developer_status,
            set_developer_mode,
            run_benchmark,
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
            get_runtime_intelligence,
            get_trust_status,
            get_signature_sources,
            set_signature_source,
            rollback_signature_source,
            update_signature_source,
            quarantine_restore_as,
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

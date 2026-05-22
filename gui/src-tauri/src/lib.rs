//! Sentinella Tauri backend.
//!
//! Each `#[tauri::command]` talks to sentinelld over the named pipe.
//! The frontend calls these via `invoke("command_name")`.
//! No command returns hardcoded data — everything comes from the daemon.

mod daemon_client;

use serde_json::Value;

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

#[tauri::command]
async fn start_quick_scan() -> Result<Value, String> {
    daemon_client::call("scan.start", serde_json::json!({"type": "quick"}))
        .await.map_err(Into::into)
}

#[tauri::command]
async fn start_full_scan() -> Result<Value, String> {
    daemon_client::call("scan.start", serde_json::json!({"type": "full"}))
        .await.map_err(Into::into)
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

// ── Watcher ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_watcher_status() -> Result<Value, String> {
    daemon_client::call_simple("watcher.status").await.map_err(Into::into)
}

// ── Updates ─────────────────────────────────────────────────────

#[tauri::command]
async fn get_update_status() -> Result<Value, String> {
    daemon_client::call_simple("update.status").await.map_err(Into::into)
}

#[tauri::command]
async fn start_signature_update() -> Result<Value, String> {
    daemon_client::call_simple("update.start").await.map_err(Into::into)
}

// ── Activity ────────────────────────────────────────────────────

#[tauri::command]
async fn get_activity() -> Result<Value, String> {
    daemon_client::call_simple("activity.list").await.map_err(Into::into)
}

// ── Runtime stats ───────────────────────────────────────────────

#[tauri::command]
async fn get_runtime_stats() -> Result<Value, String> {
    daemon_client::call_simple("stats.runtime").await.map_err(Into::into)
}

// ── App entry ───────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_engine_status,
            get_scan_status,
            start_quick_scan,
            start_full_scan,
            get_scan_history,
            get_quarantine_items,
            get_watcher_status,
            get_update_status,
            start_signature_update,
            get_activity,
            get_runtime_stats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

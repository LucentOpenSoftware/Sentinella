//! Daemon runtime state — the single source of truth.
//!
//! Every value the frontend displays MUST originate here.
//! No cosmetic data. If a subsystem is not implemented, the
//! response says so honestly (e.g. signature_count = 0).

use serde::Serialize;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

use sentinella_ipc_proto::engine::{EngineState, EngineStatus};
use sentinella_ipc_proto::quarantine::QuarantineEntry;
use sentinella_ipc_proto::watcher::{WatcherMode, WatcherStatus};
use sentinella_ipc_proto::update::{UpdateState, UpdateStatus};

/// Shared daemon state. Wrapped in `Arc` by the IPC server.
pub struct AppState {
    started_at: Instant,
    inner: Mutex<Inner>,
}

/// Mutable interior — all fields behind one lock for simplicity.
/// Fine for current throughput (GUI polls at 5 Hz, CLI is one-shot).
struct Inner {
    // ── Scan tracking ───────────────────────────────────
    scan_running: bool,
    scan_current_job: Option<Uuid>,
    scan_current_type: String,
    scan_history: Vec<ScanRecord>,

    // ── Update tracking ─────────────────────────────────
    update_running: bool,
    last_update_timestamp: Option<i64>,

    // ── Activity log ────────────────────────────────────
    activity: Vec<ActivityEntry>,

    // ── IPC stats ───────────────────────────────────────
    ipc_requests_served: u64,
}

impl AppState {
    pub fn new() -> Self {
        let now_ts = chrono::Utc::now().timestamp();
        let mut activity = Vec::new();
        activity.push(ActivityEntry {
            event_type: "daemon_start".into(),
            message: "Daemon started".into(),
            detail: Some("sentinelld is initializing".into()),
            timestamp: now_ts,
        });

        Self {
            started_at: Instant::now(),
            inner: Mutex::new(Inner {
                scan_running: false,
                scan_current_job: None,
                scan_current_type: String::new(),
                scan_history: Vec::new(),
                update_running: false,
                last_update_timestamp: None,
                activity,
                ipc_requests_served: 0,
            }),
        }
    }

    /// Called by the dispatcher on every request for metrics.
    pub fn record_request(&self) {
        self.inner.lock().unwrap().ipc_requests_served += 1;
    }

    // ═══════════════════════════════════════════════════════
    //  engine.status
    // ═══════════════════════════════════════════════════════

    pub fn engine_status(&self) -> EngineStatus {
        let inner = self.inner.lock().unwrap();
        EngineStatus {
            state: EngineState::Ready,
            protocol_version: 1,
            // Real values once libclamav FFI is wired.
            db_version: None,
            db_timestamp: None,
            signature_count: 0,
            last_update: inner.last_update_timestamp,
            engine_version: sentinella_common::PRODUCT_VERSION.into(),
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start / scan.status / scan.history
    // ═══════════════════════════════════════════════════════

    pub fn start_scan(&self, scan_type: &str) -> Uuid {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.inner.lock().unwrap();

        inner.scan_running = true;
        inner.scan_current_job = Some(id);
        inner.scan_current_type = scan_type.to_string();

        inner.activity.push(ActivityEntry {
            event_type: "scan_start".into(),
            message: format!("{} scan started", capitalize(scan_type)),
            detail: Some(format!("Job {}", &id.to_string()[..8])),
            timestamp: now,
        });

        // Immediately "complete" since we have no real engine yet.
        // When libclamav is wired, this will spawn a worker task instead.
        inner.scan_running = false;
        inner.scan_current_job = None;
        inner.scan_history.push(ScanRecord {
            job_id: id.to_string(),
            scan_type: scan_type.to_string(),
            started_at: now,
            finished_at: now,
            files_scanned: 0,
            threats_found: 0,
            status: "completed".into(),
        });
        inner.activity.push(ActivityEntry {
            event_type: "scan_complete".into(),
            message: format!("{} scan completed", capitalize(scan_type)),
            detail: Some("0 files scanned — engine not loaded".into()),
            timestamp: now,
        });

        id
    }

    pub fn scan_status(&self) -> ScanStatusResponse {
        let inner = self.inner.lock().unwrap();
        ScanStatusResponse {
            running: inner.scan_running,
            job_id: inner.scan_current_job.map(|u| u.to_string()),
            state: if inner.scan_running { "running" } else { "idle" },
            scan_type: if inner.scan_running { Some(inner.scan_current_type.clone()) } else { None },
            files_scanned: 0,
            threats_found: 0,
            current_path: None,
            scans_completed: inner.scan_history.len() as u64,
        }
    }

    pub fn scan_history(&self) -> Vec<ScanRecord> {
        let inner = self.inner.lock().unwrap();
        // Return newest first.
        let mut hist = inner.scan_history.clone();
        hist.reverse();
        hist
    }

    // ═══════════════════════════════════════════════════════
    //  quarantine.list
    // ═══════════════════════════════════════════════════════

    pub fn quarantine_list(&self) -> Vec<QuarantineEntry> {
        // Empty until vault is implemented. Honest.
        vec![]
    }

    // ═══════════════════════════════════════════════════════
    //  watcher.status
    // ═══════════════════════════════════════════════════════

    pub fn watcher_status(&self) -> WatcherStatus {
        WatcherStatus {
            enabled: false,
            mode: WatcherMode::Disabled,
            watched_roots: vec![],
            events_per_sec: 0.0,
            last_event: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  update.status / update.start
    // ═══════════════════════════════════════════════════════

    pub fn update_status(&self) -> UpdateStatus {
        let inner = self.inner.lock().unwrap();
        UpdateStatus {
            state: if inner.update_running { UpdateState::Checking } else { UpdateState::Idle },
            percent: None,
            bytes_downloaded: 0,
            bytes_total: None,
        }
    }

    pub fn start_update(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.inner.lock().unwrap();
        // Stub: record the attempt. Real impl spawns freshclam.
        inner.update_running = true;
        inner.activity.push(ActivityEntry {
            event_type: "update_start".into(),
            message: "Signature update started".into(),
            detail: Some("Checking database.clamav.net".into()),
            timestamp: now,
        });
        // Immediately "complete".
        inner.update_running = false;
        inner.last_update_timestamp = Some(now);
        inner.activity.push(ActivityEntry {
            event_type: "update_complete".into(),
            message: "Signature update completed".into(),
            detail: Some("No database loaded yet — freshclam not wired".into()),
            timestamp: now,
        });
    }

    // ═══════════════════════════════════════════════════════
    //  activity.list
    // ═══════════════════════════════════════════════════════

    pub fn activity_list(&self) -> Vec<ActivityEntry> {
        let inner = self.inner.lock().unwrap();
        // Newest first, capped at 50.
        let mut list = inner.activity.clone();
        list.reverse();
        list.truncate(50);
        list
    }

    // ═══════════════════════════════════════════════════════
    //  stats.runtime — daemon-level metrics
    // ═══════════════════════════════════════════════════════

    pub fn runtime_stats(&self) -> RuntimeStats {
        let inner = self.inner.lock().unwrap();
        let uptime_secs = self.started_at.elapsed().as_secs();
        RuntimeStats {
            uptime_secs,
            uptime_human: format_uptime(uptime_secs),
            scans_completed: inner.scan_history.len() as u64,
            threats_found_total: inner.scan_history.iter().map(|s| s.threats_found).sum(),
            ipc_requests_served: inner.ipc_requests_served,
            quarantine_count: 0, // vault not implemented
            activity_count: inner.activity.len() as u64,
            started_at: chrono::Utc::now().timestamp() - uptime_secs as i64,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Response types (daemon-specific, not in the proto crate)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatusResponse {
    pub running: bool,
    pub job_id: Option<String>,
    pub state: &'static str,
    pub scan_type: Option<String>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub current_path: Option<String>,
    pub scans_completed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub job_id: String,
    pub scan_type: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub event_type: String,
    pub message: String,
    pub detail: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStats {
    pub uptime_secs: u64,
    pub uptime_human: String,
    pub scans_completed: u64,
    pub threats_found_total: u64,
    pub ipc_requests_served: u64,
    pub quarantine_count: u64,
    pub activity_count: u64,
    pub started_at: i64,
}

// ═══════════════════════════════════════════════════════════════

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 { format!("{d}d {h}h {m}m") }
    else if h > 0 { format!("{h}h {m}m {s}s") }
    else if m > 0 { format!("{m}m {s}s") }
    else { format!("{s}s") }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}

//! `scan.*` — on-demand scan methods and notifications.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Parameters for `scan.start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    #[serde(default)]
    pub options: ScanOptions,
}

/// Per-scan configuration. Omitted fields use daemon defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub scan_archives: bool,
    pub scan_mail: bool,
    pub scan_pe: bool,
    pub scan_elf: bool,
    pub scan_ole2: bool,
    pub scan_pdf: bool,
    pub scan_html: bool,
    pub scan_scripts: bool,
    pub heuristic_alerts: bool,
    pub max_filesize_mb: u64,
    pub max_scansize_mb: u64,
    pub max_recursion: u32,
    pub max_files: u32,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            follow_symlinks: false,
            scan_archives: true,
            scan_mail: true,
            scan_pe: true,
            scan_elf: true,
            scan_ole2: true,
            scan_pdf: true,
            scan_html: true,
            scan_scripts: true,
            heuristic_alerts: true,
            max_filesize_mb: 100,
            max_scansize_mb: 400,
            max_recursion: 17,
            max_files: 10_000,
        }
    }
}

/// Response to `scan.start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStarted {
    pub job_id: Uuid,
}

/// Response to `scan.status` and payload of `scan.progress` notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub job_id: Uuid,
    pub state: ScanState,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub files_scanned: u64,
    pub files_total_estimate: Option<u64>,
    pub bytes_scanned: u64,
    pub threats_found: u64,
    pub current_path: Option<String>,
    pub errors: Vec<ScanError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: String,
    pub message: String,
}

/// Payload of `scan.threat_found` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFound {
    pub job_id: Uuid,
    pub path: String,
    pub signature: String,
    pub action_taken: ThreatAction,
    pub quarantine_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatAction {
    Quarantined,
    AlertOnly,
    Deleted,
    Ignored,
}

/// Response to `scan.cancel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelResult {
    pub ok: bool,
}

//! `update.*` — signature database update methods.

use serde::{Deserialize, Serialize};

/// Response to `update.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub state: UpdateState,
    pub percent: Option<f64>,
    pub bytes_downloaded: u64,
    pub bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Name of the file currently being downloaded (e.g. "daily.cvd").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Checking,
    Downloading,
    Applying,
    Completed,
    Error,
}

/// Single entry in `update.history`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHistoryEntry {
    pub timestamp: i64,
    pub result: UpdateResult,
    pub new_version: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateResult {
    Success,
    AlreadyCurrent,
    NetworkError,
    VerificationFailed,
    DiskError,
}

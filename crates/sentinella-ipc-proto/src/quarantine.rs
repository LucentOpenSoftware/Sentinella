//! `quarantine.*` — quarantine vault methods.

use serde::{Deserialize, Serialize};

/// A single quarantine entry as returned by `quarantine.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub original_size: u64,
    pub signature: String,
    pub sha256: String,
    pub quarantined_at: i64,
    pub restorable: bool,
}

/// Response to `quarantine.restore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub ok: bool,
    pub restored_to: Option<String>,
}

/// Response to `quarantine.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    pub ok: bool,
}

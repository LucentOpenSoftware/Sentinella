//! `engine.*` — engine lifecycle methods.

use serde::{Deserialize, Serialize};

/// Response to `engine.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub state: EngineState,
    pub protocol_version: u32,
    pub db_version: Option<u32>,
    pub db_timestamp: Option<i64>,
    pub signature_count: u64,
    pub last_update: Option<i64>,
    pub engine_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    Starting,
    Loading,
    Ready,
    Updating,
    Error,
    ShuttingDown,
}

/// Response to `engine.reload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResult {
    pub ok: bool,
}

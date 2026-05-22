//! `watcher.*` — real-time protection methods and events.

use serde::{Deserialize, Serialize};

/// Response to `watcher.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherStatus {
    pub enabled: bool,
    pub mode: WatcherMode,
    pub watched_roots: Vec<String>,
    pub events_per_sec: f64,
    pub last_event: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherMode {
    /// Post-facto detection. Cannot block access. v1 default.
    UserMode,
    /// Pre-access blocking via kernel minifilter. v2+.
    KernelMode,
    /// Watcher is disabled.
    Disabled,
}

/// Parameters for `watcher.enable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherEnableRequest {
    pub roots: Vec<String>,
}

/// Payload of `watcher.file_event` notification (rate-limited).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub kind: FileEventKind,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEventKind {
    Created,
    Modified,
    Renamed,
    OpenedForExec,
}

//! `engine.*` — engine lifecycle methods.

use serde::{Deserialize, Serialize};

/// Response to `engine.status`.
///
/// v0.1.7 Phase 2 — engine.status decoupling. Adds an explicit
/// `reload_phase` so the GUI can render an "Updating signatures…" badge
/// without flipping the main `state` away from `Ready`. The numeric
/// fields are now sourced from a **committed mirror** maintained by
/// `reload_engine_inner` on a successful commit — never from the in-flight
/// engine — so a freshclam-then-reload sequence cannot produce a transient
/// (old signature_count, new db_timestamp) tuple that GUI logic interprets
/// as "outdated definitions".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub state: EngineState,
    pub protocol_version: u32,
    pub db_version: Option<u32>,
    pub db_timestamp: Option<i64>,
    pub signature_count: u64,
    pub last_update: Option<i64>,
    pub engine_version: String,
    /// Where the current `reload_engine` (if any) is in its lifecycle.
    /// Always `Idle` outside an active reload. Set to `Failed` after a
    /// reload error; cleared back to `Idle` on the next successful reload.
    #[serde(default)]
    pub reload_phase: ReloadPhase,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReloadPhase {
    /// No reload in flight. `state` reflects the committed engine.
    #[default]
    Idle,
    /// `cl_engine_compile` is running. The committed engine is still
    /// serving scans — `state` stays `Ready`. UI may show a badge.
    Compiling,
    /// Compile finished; the swap is happening. Microseconds long.
    Activating,
    /// The most recent reload failed. The previous engine is still in
    /// place and serving. UI may surface a toast; do not flip `state`.
    Failed,
}

/// Response to `engine.reload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResult {
    pub ok: bool,
}

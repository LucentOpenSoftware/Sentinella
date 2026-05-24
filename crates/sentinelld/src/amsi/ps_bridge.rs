//! PowerShell Script Block Logging bridge.
//!
//! Reads PowerShell ScriptBlock events from Windows Event Log:
//!   Log: Microsoft-Windows-PowerShell/Operational
//!   Event ID: 4104 (ScriptBlockText)
//!
//! Requires: Script Block Logging enabled via Group Policy or registry.
//! Gracefully degrades if SBL is disabled (no events = no crash).
//!
//! This is observe-only — no blocking, no quarantine.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{RuntimeBuffer, ScriptLanguage};

/// Max recent events to keep for diagnostics UI.
const MAX_RECENT_EVENTS: usize = 10;

/// A recent runtime event summary (no raw content — privacy-safe).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeEventSummary {
    pub timestamp: i64,
    pub language: String,
    pub source_app: String,
    pub content_name: String,
    pub score: u32,
    pub findings_count: usize,
    pub lineage_summary: Option<String>,
    pub timed_out: bool,
    pub observe_only: bool,
}

/// PowerShell bridge diagnostics.
pub struct PsBridgeDiagnostics {
    pub events_seen: AtomicU64,
    pub events_scanned: AtomicU64,
    pub duplicates_skipped: AtomicU64,
    pub last_record_id: AtomicU64,
    pub last_score: AtomicU64,
    pub sbl_available: AtomicBool,
    pub errors: AtomicU64,
    /// Bounded ring buffer of recent event summaries.
    pub recent_events: std::sync::Mutex<Vec<RuntimeEventSummary>>,
}

impl PsBridgeDiagnostics {
    pub fn new() -> Self {
        Self {
            events_seen: AtomicU64::new(0),
            events_scanned: AtomicU64::new(0),
            duplicates_skipped: AtomicU64::new(0),
            last_record_id: AtomicU64::new(0),
            last_score: AtomicU64::new(0),
            sbl_available: AtomicBool::new(false),
            errors: AtomicU64::new(0),
            recent_events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Record a recent event summary (bounded ring buffer).
    pub fn record_event(&self, summary: RuntimeEventSummary) {
        if let Ok(mut events) = self.recent_events.lock() {
            events.push(summary);
            let len = events.len();
            if len > MAX_RECENT_EVENTS {
                events.drain(..len - MAX_RECENT_EVENTS);
            }
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let recent = self.recent_events.lock()
            .map(|e| serde_json::to_value(&*e).unwrap_or_default())
            .unwrap_or(serde_json::json!([]));
        serde_json::json!({
            "enabled": true,
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_scanned": self.events_scanned.load(Ordering::Relaxed),
            "duplicates_skipped": self.duplicates_skipped.load(Ordering::Relaxed),
            "last_record_id": self.last_record_id.load(Ordering::Relaxed),
            "last_score": self.last_score.load(Ordering::Relaxed),
            "sbl_available": self.sbl_available.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "recent_events": recent,
        })
    }
}

/// PowerShell Script Block Logging bridge.
pub struct PsBridge {
    pub diagnostics: Arc<PsBridgeDiagnostics>,
    running: Arc<AtomicBool>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl PsBridge {
    /// Start the PowerShell bridge on a background thread.
    /// `poll_secs`: how often to check for new events.
    /// `engine`: ARGUS engine for runtime scanning.
    /// `plm`: optional PLM for lineage correlation.
    pub fn start(
        poll_secs: u64,
        engine: Arc<argus::ArgusEngine>,
        plm: Option<Arc<crate::plm::LineageGraph>>,
    ) -> Self {
        let diagnostics = Arc::new(PsBridgeDiagnostics::new());
        let running = Arc::new(AtomicBool::new(true));

        let d = Arc::clone(&diagnostics);
        let r = Arc::clone(&running);

        let thread = std::thread::Builder::new()
            .name("ps-bridge".into())
            .spawn(move || {
                ps_bridge_loop(d, r, poll_secs, engine, plm);
            })
            .ok();

        Self {
            diagnostics,
            running,
            _thread: thread,
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for PsBridge {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Background polling loop.
fn ps_bridge_loop(
    diag: Arc<PsBridgeDiagnostics>,
    running: Arc<AtomicBool>,
    poll_secs: u64,
    engine: Arc<argus::ArgusEngine>,
    plm: Option<Arc<crate::plm::LineageGraph>>,
) {
    tracing::info!("PowerShell bridge started (poll={}s)", poll_secs);

    // Initial delay — let other components start first.
    std::thread::sleep(Duration::from_secs(3));

    let mut last_record_id: u64 = 0;

    while running.load(Ordering::Relaxed) {
        match read_new_script_blocks(last_record_id) {
            Ok(events) => {
                if !events.is_empty() {
                    diag.sbl_available.store(true, Ordering::Relaxed);
                }
                for evt in events {
                    if evt.record_id <= last_record_id {
                        diag.duplicates_skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    last_record_id = evt.record_id;
                    diag.last_record_id.store(last_record_id, Ordering::Relaxed);
                    diag.events_seen.fetch_add(1, Ordering::Relaxed);

                    // Skip very small blocks (noise from prompt, single commands).
                    if evt.script_text.len() < 50 {
                        continue;
                    }

                    // Build runtime buffer.
                    let buffer = RuntimeBuffer {
                        source_app: "powershell.exe".into(),
                        source_pid: evt.pid,
                        content_name: evt.script_name.unwrap_or_else(|| format!("block-{}", evt.record_id)),
                        language: ScriptLanguage::PowerShell,
                        content: evt.script_text.into_bytes(),
                        original_size: evt.script_text_len,
                        timestamp: evt.timestamp,
                    };

                    // Scan through ASTRA runtime pipeline.
                    let result = super::scan_runtime_buffer(&buffer, &engine);
                    diag.events_scanned.fetch_add(1, Ordering::Relaxed);
                    diag.last_score.store(result.score as u64, Ordering::Relaxed);

                    // PLM correlation.
                    let plm_boost = if let Some(ref graph) = plm {
                        if buffer.source_pid > 0 {
                            let chain = graph.get_chain(buffer.source_pid);
                            chain.chain_suspicion
                        } else { 0 }
                    } else { 0 };

                    let total = result.score.saturating_add(plm_boost).min(100);

                    // Record event summary for diagnostics UI.
                    let lineage_desc = if let Some(ref graph) = plm {
                        if buffer.source_pid > 0 {
                            let chain = graph.get_chain(buffer.source_pid);
                            if chain.depth > 1 { Some(chain.description.clone()) } else { None }
                        } else { None }
                    } else { None };

                    diag.record_event(RuntimeEventSummary {
                        timestamp: buffer.timestamp,
                        language: buffer.language.label().to_string(),
                        source_app: buffer.source_app.clone(),
                        content_name: buffer.content_name.clone(),
                        score: total,
                        findings_count: result.findings.len(),
                        lineage_summary: lineage_desc,
                        timed_out: false,
                        observe_only: true,
                    });

                    if total > 0 || !result.findings.is_empty() {
                        tracing::debug!(
                            pid = buffer.source_pid,
                            score = total,
                            runtime_score = result.score,
                            plm_boost,
                            findings = result.findings.len(),
                            "PS bridge: script block analyzed"
                        );
                    }

                    if total >= 50 {
                        tracing::info!(
                            pid = buffer.source_pid,
                            score = total,
                            findings = result.findings.len(),
                            name = %buffer.content_name,
                            "PS bridge: suspicious runtime content detected (observe-only)"
                        );
                    }
                }
            }
            Err(e) => {
                // SBL may not be enabled — not an error, just log once.
                static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !LOGGED.swap(true, Ordering::Relaxed) {
                    tracing::debug!(error = %e, "PowerShell SBL not available (Script Block Logging may be disabled)");
                }
                diag.errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        std::thread::sleep(Duration::from_secs(poll_secs));
    }

    tracing::info!("PowerShell bridge stopped");
}

/// A parsed ScriptBlock event from Event Log.
struct ScriptBlockEvent {
    record_id: u64,
    pid: u32,
    script_text: String,
    script_text_len: usize,
    script_name: Option<String>,
    timestamp: i64,
}

/// Read new ScriptBlock (4104) events from PowerShell Operational log.
/// Returns events with RecordId > `after_record_id`.
#[cfg(target_os = "windows")]
fn read_new_script_blocks(after_record_id: u64) -> Result<Vec<ScriptBlockEvent>, String> {
    use std::process::Command;

    // Use wevtutil to read events — no COM/WinAPI complexity.
    // Filter: Event ID 4104, most recent 20 events.
    let output = Command::new("wevtutil")
        .args([
            "qe",
            "Microsoft-Windows-PowerShell/Operational",
            "/q:*[System[EventID=4104]]",
            "/c:20",
            "/rd:true", // Reverse direction (newest first).
            "/f:text",
        ])
        .output()
        .map_err(|e| format!("wevtutil failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("wevtutil error: {stderr}"));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_wevtutil_output(&text, after_record_id)
}

#[cfg(not(target_os = "windows"))]
fn read_new_script_blocks(_after_record_id: u64) -> Result<Vec<ScriptBlockEvent>, String> {
    Ok(vec![]) // No PowerShell on non-Windows.
}

/// Parse wevtutil text output into ScriptBlockEvents.
#[cfg(target_os = "windows")]
fn parse_wevtutil_output(text: &str, after_record_id: u64) -> Result<Vec<ScriptBlockEvent>, String> {
    let mut events = Vec::new();
    let mut current_record_id: u64 = 0;
    let mut current_pid: u32 = 0;
    let mut current_script = String::new();
    let mut current_name: Option<String> = None;
    let mut current_timestamp: i64 = 0;
    let mut in_script_block = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // Record ID.
        if let Some(rest) = trimmed.strip_prefix("RecordId:") {
            // Save previous event if any.
            if current_record_id > after_record_id && !current_script.is_empty() {
                events.push(ScriptBlockEvent {
                    record_id: current_record_id,
                    pid: current_pid,
                    script_text: std::mem::take(&mut current_script),
                    script_text_len: current_script.len(),
                    script_name: current_name.take(),
                    timestamp: current_timestamp,
                });
            }
            current_record_id = rest.trim().parse().unwrap_or(0);
            current_pid = 0;
            current_script.clear();
            current_name = None;
            in_script_block = false;
        }

        // Process ID.
        if let Some(rest) = trimmed.strip_prefix("ProcessId:") {
            current_pid = rest.trim().parse().unwrap_or(0);
        }

        // Date/time.
        if let Some(rest) = trimmed.strip_prefix("Date:") {
            // Parse ISO-ish date from wevtutil.
            let ts_str = rest.trim();
            current_timestamp = chrono::DateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f%z")
                .or_else(|_| chrono::DateTime::parse_from_rfc3339(ts_str))
                .map(|dt| dt.timestamp())
                .unwrap_or(0);
        }

        // ScriptBlock text content — appears after "ScriptBlockText=" or as event data.
        if trimmed.starts_with("ScriptBlockText=") || trimmed.starts_with("ScriptBlockText:") {
            let content = trimmed.splitn(2, |c| c == '=' || c == ':').nth(1).unwrap_or("").trim();
            current_script.push_str(content);
            in_script_block = true;
        } else if in_script_block && !trimmed.is_empty()
            && !trimmed.starts_with("ScriptBlockId")
            && !trimmed.starts_with("Path")
            && !trimmed.starts_with("RecordId")
        {
            current_script.push('\n');
            current_script.push_str(trimmed);
        } else {
            in_script_block = false;
        }

        // Script path/name.
        if let Some(rest) = trimmed.strip_prefix("Path:") {
            let p = rest.trim();
            if !p.is_empty() {
                current_name = Some(p.to_string());
            }
        }
    }

    // Save last event.
    if current_record_id > after_record_id && !current_script.is_empty() {
        let len = current_script.len();
        events.push(ScriptBlockEvent {
            record_id: current_record_id,
            pid: current_pid,
            script_text: current_script,
            script_text_len: len,
            script_name: current_name,
            timestamp: current_timestamp,
        });
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_json() {
        let d = PsBridgeDiagnostics::new();
        d.events_seen.store(5, Ordering::Relaxed);
        d.sbl_available.store(true, Ordering::Relaxed);
        let j = d.to_json();
        assert_eq!(j["events_seen"], 5);
        assert_eq!(j["sbl_available"], true);
    }

    #[test]
    fn language_is_powershell() {
        let buf = RuntimeBuffer {
            source_app: "powershell.exe".into(),
            source_pid: 0,
            content_name: "test".into(),
            language: ScriptLanguage::PowerShell,
            content: vec![],
            original_size: 0,
            timestamp: 0,
        };
        assert_eq!(buf.language, ScriptLanguage::PowerShell);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_empty_output() {
        let result = parse_wevtutil_output("", 0).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn duplicate_suppression() {
        // Events with record_id <= after_record_id should be skipped.
        let result = parse_wevtutil_output("RecordId: 5\nScriptBlockText=test\n", 10).unwrap();
        assert!(result.is_empty(), "record_id 5 should be skipped when after=10");
    }
}

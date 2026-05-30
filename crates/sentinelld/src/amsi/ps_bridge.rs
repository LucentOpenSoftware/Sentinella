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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
        let recent = self
            .recent_events
            .lock()
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

/// Filter a freshly-read batch to events strictly newer than `baseline`,
/// returned in ASCENDING record-id order, plus the new high-water mark.
///
/// Bug fix: `wevtutil /rd:true` returns events newest-first (descending id).
/// The old loop bumped `last_record_id` to the FIRST event's id (the highest)
/// and then treated every later (lower-id) event as a duplicate — so only the
/// single newest script block per poll was ever scanned, and a burst of
/// scripts between polls was silently dropped. De-dup against the immutable
/// poll baseline and advance the high-water mark to the batch max instead.
fn unprocessed_ascending(
    mut batch: Vec<ScriptBlockEvent>,
    baseline: u64,
) -> (Vec<ScriptBlockEvent>, u64) {
    batch.retain(|e| e.record_id > baseline);
    let new_last = batch.iter().map(|e| e.record_id).max().unwrap_or(baseline);
    batch.sort_by_key(|e| e.record_id);
    (batch, new_last)
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
                // De-dup against the poll baseline (NOT a running max) and
                // process oldest-first so every genuinely-new event in the
                // batch is scanned, regardless of wevtutil's newest-first order.
                let total = events.len();
                let baseline = last_record_id;
                let (batch, new_last) = unprocessed_ascending(events, baseline);
                let dups = total - batch.len();
                if dups > 0 {
                    diag.duplicates_skipped
                        .fetch_add(dups as u64, Ordering::Relaxed);
                }
                last_record_id = new_last;
                diag.last_record_id.store(last_record_id, Ordering::Relaxed);

                for evt in batch {
                    diag.events_seen.fetch_add(1, Ordering::Relaxed);

                    // Skip very small blocks (noise from prompt, single commands).
                    if evt.script_text.len() < 50 {
                        continue;
                    }

                    // Build runtime buffer.
                    let buffer = RuntimeBuffer {
                        source_app: "powershell.exe".into(),
                        source_pid: evt.pid,
                        content_name: evt
                            .script_name
                            .unwrap_or_else(|| format!("block-{}", evt.record_id)),
                        language: ScriptLanguage::PowerShell,
                        content: evt.script_text.into_bytes(),
                        original_size: evt.script_text_len,
                        timestamp: evt.timestamp,
                    };

                    // Scan through ASTRA runtime pipeline.
                    let result = super::scan_runtime_buffer(&buffer, &engine);
                    diag.events_scanned.fetch_add(1, Ordering::Relaxed);
                    diag.last_score
                        .store(result.score as u64, Ordering::Relaxed);

                    // PLM correlation.
                    let plm_boost = if let Some(ref graph) = plm {
                        if buffer.source_pid > 0 {
                            let chain = graph.get_chain(buffer.source_pid);
                            chain.chain_suspicion
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    let total = result.score.saturating_add(plm_boost).min(100);

                    // Record event summary for diagnostics UI.
                    let lineage_desc = if let Some(ref graph) = plm {
                        if buffer.source_pid > 0 {
                            let chain = graph.get_chain(buffer.source_pid);
                            if chain.depth > 1 {
                                Some(chain.description.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

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
                static LOGGED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
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
    let output = {
        use crate::win_process::QuietCommand;
        Command::new("wevtutil")
            .args([
                "qe",
                "Microsoft-Windows-PowerShell/Operational",
                "/q:*[System[EventID=4104]]",
                "/c:20",
                "/rd:true", // Reverse direction (newest first).
                "/f:text",
            ])
            .quiet_windows()
            .output()
            .map_err(|e| format!("wevtutil failed: {e}"))?
    };

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
fn parse_wevtutil_output(
    text: &str,
    after_record_id: u64,
) -> Result<Vec<ScriptBlockEvent>, String> {
    // R3-fix: cap per-script text growth so a multi-MB attacker-controlled
    // ScriptBlock 4104 event cannot force MB-sized allocations per poll
    // cycle. 256 KiB is well above any legitimate script we want to scan.
    const MAX_SCRIPT_BYTES: usize = 256 * 1024;
    // R3-fix: defensive cap on emitted events per parse pass.
    const MAX_EVENTS: usize = 64;

    let mut events: Vec<ScriptBlockEvent> = Vec::new();
    let mut current_record_id: u64 = 0;
    let mut current_pid: u32 = 0;
    let mut current_script = String::new();
    let mut current_name: Option<String> = None;
    let mut current_timestamp: i64 = 0;
    let mut in_script_block = false;

    // Helper: append `s` to `current_script` without exceeding the byte cap,
    // truncating at a UTF-8 char boundary if necessary.
    fn capped_push(buf: &mut String, s: &str, cap: usize) {
        if buf.len() >= cap {
            return;
        }
        let remain = cap - buf.len();
        if s.len() <= remain {
            buf.push_str(s);
        } else {
            let mut cut = remain;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            buf.push_str(&s[..cut]);
        }
    }

    for line in text.lines() {
        let trimmed = line.trim();

        // Record ID.
        if let Some(rest) = trimmed.strip_prefix("RecordId:") {
            // Save previous event if any.
            if current_record_id > after_record_id
                && !current_script.is_empty()
                && events.len() < MAX_EVENTS
            {
                // Audit fix: capture length BEFORE `mem::take` empties the
                // string — struct fields evaluate top-to-bottom, so reading
                // `current_script.len()` after the take always yielded 0.
                let script_text_len = current_script.len();
                events.push(ScriptBlockEvent {
                    record_id: current_record_id,
                    pid: current_pid,
                    script_text: std::mem::take(&mut current_script),
                    script_text_len,
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
            let content = trimmed
                .splitn(2, |c| c == '=' || c == ':')
                .nth(1)
                .unwrap_or("")
                .trim();
            capped_push(&mut current_script, content, MAX_SCRIPT_BYTES);
            in_script_block = true;
        } else if in_script_block
            && !trimmed.is_empty()
            && !trimmed.starts_with("ScriptBlockId")
            && !trimmed.starts_with("Path")
            && !trimmed.starts_with("RecordId")
        {
            capped_push(&mut current_script, "\n", MAX_SCRIPT_BYTES);
            capped_push(&mut current_script, trimmed, MAX_SCRIPT_BYTES);
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
    if current_record_id > after_record_id
        && !current_script.is_empty()
        && events.len() < MAX_EVENTS
    {
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

    fn mk_evt(record_id: u64) -> ScriptBlockEvent {
        ScriptBlockEvent {
            record_id,
            pid: 0,
            script_text: "x".repeat(60),
            script_text_len: 60,
            script_name: None,
            timestamp: 0,
        }
    }

    #[test]
    fn descending_batch_processes_all_new_events() {
        // wevtutil returns newest-first; last seen = 10. All of 11..=15 are new.
        let batch = vec![mk_evt(15), mk_evt(14), mk_evt(13), mk_evt(12), mk_evt(11)];
        let (proc, new_last) = unprocessed_ascending(batch, 10);
        let ids: Vec<u64> = proc.iter().map(|e| e.record_id).collect();
        assert_eq!(
            ids,
            vec![11, 12, 13, 14, 15],
            "all 5 new events must be processed in ascending order, not just the newest"
        );
        assert_eq!(new_last, 15);
    }

    #[test]
    fn already_seen_events_are_dropped() {
        // last seen = 14 → only 15 is new; 13/14 already processed.
        let batch = vec![mk_evt(15), mk_evt(14), mk_evt(13)];
        let (proc, new_last) = unprocessed_ascending(batch, 14);
        assert_eq!(proc.len(), 1);
        assert_eq!(proc[0].record_id, 15);
        assert_eq!(new_last, 15);
    }

    #[test]
    fn empty_batch_keeps_baseline() {
        let (proc, new_last) = unprocessed_ascending(Vec::new(), 42);
        assert!(proc.is_empty());
        assert_eq!(new_last, 42, "high-water mark must not regress on an empty poll");
    }

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
        assert!(
            result.is_empty(),
            "record_id 5 should be skipped when after=10"
        );
    }
}

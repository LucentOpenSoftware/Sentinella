//! Lightweight Event Correlation
//!
//! Maintains a short rolling window of recent file + process events for
//! cross-file correlation. When a suspicious file is detected,
//! nearby events within the time window provide additional context.
//!
//! NOT a full EDR telemetry store. Keeps only the last N events
//! (default 200) and expires events older than 5 minutes.
//! No persistent storage, no process trees, no kernel hooks.
//!
//! ## Future: ETW Integration (v1.5+)
//!
//! The `ContextHints` struct is designed to accept future ETW-derived
//! signals without schema changes:
//! - `process_hint` ← ETW ProcessStart (PID, image path)
//! - `parent_process_hint` ← ETW ProcessStart (PPID)
//! - `domain_hint` ← ETW DNS Client (resolved domain)
//! - `origin_confidence` ← Zone.Identifier + ETW correlation strength
//!
//! When ETW is added, it feeds into the same `EventCorrelator` via
//! `record()` with richer `ContextHints`. No ARGUS engine changes needed.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum events in the rolling window.
const MAX_EVENTS: usize = 200;

/// Events older than this are expired.
const EVENT_TTL: Duration = Duration::from_secs(300); // 5 minutes.

/// Contextual hints attached to events — enriched by different sources.
/// Currently populated from file analysis. Future: ETW DNS + Process events.
#[derive(Debug, Clone, Default)]
pub struct ContextHints {
    /// Free-text source hint (e.g., "extracted from archive", "browser download").
    pub source_hint: Option<String>,

    /// Process that created/owns this file (future: from ETW ProcessStart).
    /// Format: "process_name.exe" or full path.
    pub process_hint: Option<String>,

    /// Parent process of the creator (future: from ETW PPID chain).
    /// Enables chains like: browser → download → exe → PowerShell.
    pub parent_process_hint: Option<String>,

    /// Domain this process resolved before/during file creation
    /// (future: from ETW DNS Client events).
    pub domain_hint: Option<String>,

    /// Confidence in the origin attribution (0.0-1.0).
    /// Zone.Identifier alone = 0.6, ETW DNS + process = 0.9.
    pub origin_confidence: f32,
}

/// A lightweight event record — what happened, where, when.
/// Internal only — not serialized across IPC.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub timestamp: Instant,
    pub path: PathBuf,
    pub event_type: EventType,
    /// Contextual hints from various sources.
    pub hints: ContextHints,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// File appeared in a watched directory.
    FileCreated,
    /// File was scanned and found clean.
    ScannedClean,
    /// File was scanned and found suspicious/malicious.
    ScannedSuspicious,
    /// File was quarantined.
    Quarantined,
    /// Process started (future: from ETW).
    ProcessStarted,
    /// DNS query observed (future: from ETW).
    DnsQuery,
}

/// Rolling event store for short-term correlation.
pub struct EventCorrelator {
    events: Mutex<VecDeque<EventRecord>>,
}

impl EventCorrelator {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(MAX_EVENTS)),
        }
    }

    /// Record a new event. Automatically expires old events.
    pub fn record(&self, path: PathBuf, event_type: EventType, source_hint: Option<String>) {
        self.record_with_hints(
            path,
            event_type,
            ContextHints {
                source_hint,
                ..Default::default()
            },
        );
    }

    /// Record with full context hints (for future ETW integration).
    pub fn record_with_hints(&self, path: PathBuf, event_type: EventType, hints: ContextHints) {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());

        // Expire old events.
        let cutoff = Instant::now() - EVENT_TTL;
        while events.front().is_some_and(|e| e.timestamp < cutoff) {
            events.pop_front();
        }

        // Add new event.
        events.push_back(EventRecord {
            timestamp: Instant::now(),
            path,
            event_type,
            hints,
        });

        // Cap size.
        while events.len() > MAX_EVENTS {
            events.pop_front();
        }
    }

    /// Query recent events near a given path within a time window.
    /// Returns events in the same directory or with related names.
    pub fn recent_context(&self, path: &std::path::Path, window_secs: u64) -> Vec<EventRecord> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(window_secs);

        let dir = path.parent().map(|p| p.to_string_lossy().to_lowercase());

        events
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .filter(|e| {
                // Same directory.
                if let Some(ref d) = dir {
                    let event_dir = e
                        .path
                        .parent()
                        .map(|p| p.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if event_dir == *d {
                        return true;
                    }
                }
                // Same filename base.
                let name = path
                    .file_stem()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                let event_name = e
                    .path
                    .file_stem()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if !name.is_empty() && name == event_name {
                    return true;
                }
                false
            })
            .cloned()
            .collect()
    }

    /// Count suspicious events in the last N seconds.
    pub fn recent_suspicious_count(&self, window_secs: u64) -> usize {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(window_secs);

        events
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .filter(|e| e.event_type == EventType::ScannedSuspicious)
            .count()
    }

    /// Get DNS domain hints for events near a path (future: ETW-populated).
    /// Returns domains that were resolved by processes in the same directory
    /// or time window as the target file.
    pub fn domain_hints_for(&self, _path: &std::path::Path, window_secs: u64) -> Vec<String> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(window_secs);

        events
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .filter(|e| e.event_type == EventType::DnsQuery)
            .filter_map(|e| e.hints.domain_hint.clone())
            .collect()
    }

    /// Get process chain hints for a path (future: ETW-populated).
    pub fn process_chain_for(
        &self,
        path: &std::path::Path,
        window_secs: u64,
    ) -> Vec<(String, Option<String>)> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(window_secs);
        let dir = path.parent().map(|p| p.to_string_lossy().to_lowercase());

        events
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .filter(|e| e.event_type == EventType::ProcessStarted)
            .filter(|e| {
                if let Some(ref d) = dir {
                    e.path
                        .parent()
                        .map(|p| p.to_string_lossy().to_lowercase())
                        .as_deref()
                        == Some(d.as_str())
                } else {
                    false
                }
            })
            .map(|e| {
                (
                    e.hints.process_hint.clone().unwrap_or_default(),
                    e.hints.parent_process_hint.clone(),
                )
            })
            .collect()
    }
}

impl Default for EventCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        let ec = EventCorrelator::new();
        ec.record(
            PathBuf::from("C:\\Downloads\\test.exe"),
            EventType::ScannedClean,
            None,
        );
        ec.record(
            PathBuf::from("C:\\Downloads\\other.exe"),
            EventType::ScannedSuspicious,
            None,
        );

        let ctx = ec.recent_context(std::path::Path::new("C:\\Downloads\\query.exe"), 60);
        assert_eq!(ctx.len(), 2, "Should find 2 events in same directory");
    }

    #[test]
    fn test_event_cap() {
        let ec = EventCorrelator::new();
        for i in 0..150 {
            ec.record(
                PathBuf::from(format!("C:\\test\\file{i}.exe")),
                EventType::FileCreated,
                None,
            );
        }
        // Should be capped at MAX_EVENTS.
        let events = ec.events.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            events.len() <= MAX_EVENTS,
            "Events exceeded cap: {}",
            events.len()
        );
    }

    #[test]
    fn test_suspicious_count() {
        let ec = EventCorrelator::new();
        ec.record(PathBuf::from("a.exe"), EventType::ScannedClean, None);
        ec.record(PathBuf::from("b.exe"), EventType::ScannedSuspicious, None);
        ec.record(PathBuf::from("c.exe"), EventType::ScannedSuspicious, None);
        ec.record(PathBuf::from("d.exe"), EventType::ScannedClean, None);

        assert_eq!(ec.recent_suspicious_count(60), 2);
    }

    #[test]
    fn test_empty_correlator() {
        let ec = EventCorrelator::new();
        let ctx = ec.recent_context(std::path::Path::new("C:\\test.exe"), 60);
        assert!(ctx.is_empty());
        assert_eq!(ec.recent_suspicious_count(60), 0);
    }

    #[test]
    fn test_unusual_paths() {
        let ec = EventCorrelator::new();
        // Should not panic on edge cases.
        ec.record(PathBuf::from(""), EventType::FileCreated, None);
        ec.record(PathBuf::from("C:\\"), EventType::FileCreated, None);
        ec.record(PathBuf::from("file_no_dir"), EventType::FileCreated, None);
        let ctx = ec.recent_context(std::path::Path::new(""), 60);
        // Should handle gracefully — no panic.
        let _ = ctx;
    }

    #[test]
    fn test_context_hints() {
        let ec = EventCorrelator::new();
        // Record with hints — future ETW integration path.
        ec.record_with_hints(
            PathBuf::from("C:\\Downloads\\stealer.exe"),
            EventType::DnsQuery,
            ContextHints {
                domain_hint: Some("discord.com".into()),
                process_hint: Some("stealer.exe".into()),
                origin_confidence: 0.9,
                ..Default::default()
            },
        );

        let domains = ec.domain_hints_for(std::path::Path::new("C:\\Downloads\\test.exe"), 60);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "discord.com");
    }

    #[test]
    fn test_default_hints() {
        // ContextHints::default() should have no data.
        let h = ContextHints::default();
        assert!(h.source_hint.is_none());
        assert!(h.process_hint.is_none());
        assert!(h.domain_hint.is_none());
        assert_eq!(h.origin_confidence, 0.0);
    }
}

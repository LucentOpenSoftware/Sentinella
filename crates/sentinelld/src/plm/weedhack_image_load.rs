//! WeedHack ImageLoad ETW source — orchestration layer.
//!
//! ## What this module does
//!
//! Sits between the Windows ETW `Microsoft-Windows-Kernel-Process` ImageLoad
//! provider and the canonical `weedhack_browser_injection::evaluate()`
//! detector. It is the FIRST real ETW source wired up for WeedHack
//! runtime correlation; FileIO (wallet harvest) and WinHTTP (EtherHiding)
//! intentionally remain unimplemented for now.
//!
//! Pipeline:
//!
//! ```text
//! ETW ImageLoad event (Windows-only)
//!     ↓  parse to ImageLoadRawEvent
//! BrowserImageLoadFilter::process_event
//!     ├─ cheap reject: not a browser target           → drop
//!     ├─ cheap reject: module not under user-writable → drop
//!     ├─ rate limit (max events/sec)                  → drop
//!     ├─ dedup (pid, module-path) within window       → drop
//!     ├─ ModuleSignerVerifier::verify                 → Trusted → drop
//!     ├─ JavaLineageChecker::has_java_ancestor        → false   → drop
//!     └─ delegate to weedhack_browser_injection::evaluate (CANONICAL gate)
//!         → Some(WeedHackSignal::BrowserInjectionFromJava)
//!             ↓
//!         PlmMonitor::ingest_weedhack_signal (Wave 1/2 path)
//!             ↓
//!         WeedHackCampaignTracker (tier dedup, advancement-only emit)
//!             ↓
//!         CampaignFinding recorded in diagnostics
//!             ↓
//!         Next scan-site hook surfaces it through ConvergenceLedger
//! ```
//!
//! ## Design choices
//!
//! - **No second verdict path.** The ETW thread does NOT push findings
//!   directly to any ledger. It records signals in the campaign tracker
//!   and lets the existing scan-site hooks surface them on the next pass.
//!   This honors the integration constraint and keeps a single source of
//!   truth for verdicts.
//!
//! - **Filter is the orchestration, detector is the policy.** All
//!   semantic decisions (what counts as a browser, what counts as a
//!   user-writable path, what counts as a Java ancestor) live in
//!   `weedhack_browser_injection`. This module only handles ETW-shaped
//!   concerns: high-volume event flow, dedup, rate limit, counters,
//!   pluggable verifier/lineage trait boundaries.
//!
//! - **Cheap-reject before expensive lookups.** The two free filters
//!   (browser image, user-writable path) run first; only events that
//!   survive both reach the signer + lineage queries which can hit the
//!   filesystem and walk the lineage graph.
//!
//! - **Bounded memory.** The dedup table is capped at
//!   `MAX_DEDUP_ENTRIES`; oldest entries evicted on overflow. Rate-limit
//!   state is a single Mutex-protected counter.

#![allow(dead_code)]

use super::weedhack_browser_injection;
use super::weedhack_runtime::WeedHackSignal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
//  Tunables
// ─────────────────────────────────────────────────────────────────────

/// Maximum ImageLoad events processed per second. Excess events are
/// rejected with `events_rate_limited++`. 256/s is far above the real
/// rate the browser-load filter sees post-filter (legitimate
/// browser startup loads ~150 modules total over a few seconds).
pub const MAX_EVENTS_PER_SEC: u32 = 256;

/// `(pid, module_path)` reads within this window are deduped.
/// Browsers re-load the same module on Worker spawn and tab navigation.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(60);

/// Hard memory cap on the dedup table.
pub const MAX_DEDUP_ENTRIES: usize = 1024;

// ─────────────────────────────────────────────────────────────────────
//  Public types
// ─────────────────────────────────────────────────────────────────────

/// Authenticode signer verdict for a loaded module. See `ModuleSignerVerifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerVerdict {
    /// Authenticode chain validates against a trusted root.
    Trusted,
    /// Module is unsigned or the signature is broken.
    Untrusted,
    /// Could not determine (file gone, IO error, verifier disabled).
    /// Per policy this does NOT auto-incriminate — only the
    /// browser+path+lineage triple does.
    Unknown,
}

/// Pluggable Authenticode verifier boundary. Wave 3 ships
/// `NullSignerVerifier` (always returns `Unknown`); a future wave can
/// implement a real WinTrust-backed checker without touching detectors.
pub trait ModuleSignerVerifier: Send + Sync {
    fn verify(&self, module_path: &str) -> SignerVerdict;
}

/// Default verifier: returns `Unknown` for every path.
///
/// Per the design policy: `Unknown` is treated identically to `Untrusted`
/// for signal eligibility but the campaign tracker's downstream tier
/// rules — pathognomonic vs corroborator — keep this from auto-escalating
/// without other evidence in the campaign.
pub struct NullSignerVerifier;

impl ModuleSignerVerifier for NullSignerVerifier {
    fn verify(&self, _module_path: &str) -> SignerVerdict {
        SignerVerdict::Unknown
    }
}

/// Pluggable lineage-probe boundary. Real implementation walks
/// `LineageGraph::get_chain(pid)` and checks for any `javaw.exe` /
/// `java.exe` ancestor. Tests use an in-memory mock.
pub trait JavaLineageChecker: Send + Sync {
    fn has_java_ancestor(&self, pid: u32) -> bool;
}

/// Production lineage probe backed by the PLM `LineageGraph`.
pub struct LineageGraphJavaChecker {
    graph: std::sync::Arc<super::LineageGraph>,
}

impl LineageGraphJavaChecker {
    pub fn new(graph: std::sync::Arc<super::LineageGraph>) -> Self {
        Self { graph }
    }
}

impl JavaLineageChecker for LineageGraphJavaChecker {
    fn has_java_ancestor(&self, pid: u32) -> bool {
        let chain = self.graph.get_chain(pid);
        chain.nodes.iter().any(|n| {
            let lower = n.image_name.to_ascii_lowercase();
            lower == "javaw.exe" || lower == "java.exe"
        })
    }
}

/// Raw ImageLoad event as captured by the ETW callback.
///
/// Field naming intentionally matches the existing
/// `weedhack_browser_injection::ImageLoadEvent` shape so the filter can
/// hand it to the canonical detector with a trivial conversion.
#[derive(Debug, Clone)]
pub struct ImageLoadRawEvent {
    pub target_pid: u32,
    pub target_image_name: String,
    pub loaded_module_path: String,
    pub timestamp_unix: i64,
}

// ─────────────────────────────────────────────────────────────────────
//  Filter — orchestration core
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct RateState {
    window_start: Instant,
    count: u32,
}

/// Stateful filter sitting between the ETW callback and the detector.
/// Thread-safe via internal Mutexes + atomics — multiple ETW threads or
/// test threads can drive it concurrently.
pub struct BrowserImageLoadFilter {
    seen: Mutex<HashMap<(u32, String), Instant>>,
    rate: Mutex<RateState>,
    /// Total raw events handed in.
    pub events_seen: AtomicU64,
    /// Cheaply-rejected (wrong target image or non-user-writable path).
    pub events_filtered: AtomicU64,
    /// Dropped due to (pid, module) dedup within the window.
    pub events_deduped: AtomicU64,
    /// Dropped due to per-second rate limit.
    pub events_rate_limited: AtomicU64,
    /// Trusted-signer rejections (legit signed module under foothold path).
    pub events_signed_trusted: AtomicU64,
    /// Signer check returned Unknown — eligibility kept, counter advanced.
    pub events_signer_unknown: AtomicU64,
    /// Survived all filters and the detector emitted a signal.
    pub events_emitted: AtomicU64,
    /// Rejected: no Java ancestor in lineage.
    pub events_no_java_ancestor: AtomicU64,
}

impl Default for BrowserImageLoadFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserImageLoadFilter {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            rate: Mutex::new(RateState {
                window_start: Instant::now(),
                count: 0,
            }),
            events_seen: AtomicU64::new(0),
            events_filtered: AtomicU64::new(0),
            events_deduped: AtomicU64::new(0),
            events_rate_limited: AtomicU64::new(0),
            events_signed_trusted: AtomicU64::new(0),
            events_signer_unknown: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            events_no_java_ancestor: AtomicU64::new(0),
        }
    }

    /// Process a single ImageLoad event. Returns `Some(signal)` when the
    /// canonical detector confirms a WeedHack browser-injection pattern,
    /// else `None`.
    ///
    /// The caller is responsible for ingesting the returned signal into
    /// the campaign tracker (`PlmMonitor::ingest_weedhack_signal`).
    pub fn process_event(
        &self,
        event: ImageLoadRawEvent,
        verifier: &dyn ModuleSignerVerifier,
        lineage: &dyn JavaLineageChecker,
    ) -> Option<WeedHackSignal> {
        self.process_event_at(event, verifier, lineage, Instant::now())
    }

    /// Test-friendly variant: caller supplies a synthetic `now`.
    pub fn process_event_at(
        &self,
        event: ImageLoadRawEvent,
        verifier: &dyn ModuleSignerVerifier,
        lineage: &dyn JavaLineageChecker,
        now: Instant,
    ) -> Option<WeedHackSignal> {
        self.events_seen.fetch_add(1, Ordering::Relaxed);

        // ── Cheap rejection #1: target image must be a known browser.
        if !weedhack_browser_injection::is_browser_image(&event.target_image_name) {
            self.events_filtered.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Cheap rejection #2: module path must be a user-writable
        //    foothold. Loads from System32 / Program Files etc. are out
        //    of scope for this signal (different vectors handle them).
        if !weedhack_browser_injection::is_user_writable_path(&event.loaded_module_path) {
            self.events_filtered.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Rate limit. Burst protection: ETW sometimes emits batches
        //    on browser startup that aren't WeedHack but still flood us.
        if !self.allow_rate_at(now) {
            self.events_rate_limited.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Dedup (pid, module-path) within window. Browsers re-import
        //    the same DLL on worker spawn; we only want to score it once
        //    per campaign window.
        if !self.allow_pid_module(event.target_pid, &event.loaded_module_path, now) {
            self.events_deduped.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Signer check. Trusted → drop early; Unknown → continue.
        let verdict = verifier.verify(&event.loaded_module_path);
        match verdict {
            SignerVerdict::Trusted => {
                self.events_signed_trusted.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            SignerVerdict::Unknown => {
                self.events_signer_unknown.fetch_add(1, Ordering::Relaxed);
            }
            SignerVerdict::Untrusted => {}
        }

        // ── Lineage check. Java ancestor is mandatory.
        let has_java = lineage.has_java_ancestor(event.target_pid);
        if !has_java {
            self.events_no_java_ancestor.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Canonical gate. Delegate the final yes/no to the existing
        //    detector so its semantics remain the single source of truth.
        let detector_event = weedhack_browser_injection::ImageLoadEvent {
            target_pid: event.target_pid,
            target_image_name: event.target_image_name.clone(),
            loaded_module_path: event.loaded_module_path.clone(),
            loaded_module_signed: match verdict {
                SignerVerdict::Trusted => Some(true),
                SignerVerdict::Untrusted => Some(false),
                SignerVerdict::Unknown => None,
            },
        };
        let sig = weedhack_browser_injection::evaluate(&detector_event, has_java);
        if sig.is_some() {
            self.events_emitted.fetch_add(1, Ordering::Relaxed);
        }
        sig
    }

    /// Diagnostics snapshot for the campaign panel / status endpoint.
    pub fn diagnostics_json(&self) -> serde_json::Value {
        serde_json::json!({
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_filtered": self.events_filtered.load(Ordering::Relaxed),
            "events_deduped": self.events_deduped.load(Ordering::Relaxed),
            "events_rate_limited": self.events_rate_limited.load(Ordering::Relaxed),
            "events_signed_trusted": self.events_signed_trusted.load(Ordering::Relaxed),
            "events_signer_unknown": self.events_signer_unknown.load(Ordering::Relaxed),
            "events_emitted": self.events_emitted.load(Ordering::Relaxed),
            "events_no_java_ancestor": self.events_no_java_ancestor.load(Ordering::Relaxed),
            "max_events_per_sec": MAX_EVENTS_PER_SEC,
            "dedup_window_secs": DEDUP_WINDOW.as_secs(),
            "max_dedup_entries": MAX_DEDUP_ENTRIES,
        })
    }

    // ── Internal: rate limit + dedup primitives ────────────────────

    fn allow_rate_at(&self, now: Instant) -> bool {
        let mut rs = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(rs.window_start) >= Duration::from_secs(1) {
            rs.window_start = now;
            rs.count = 0;
        }
        if rs.count >= MAX_EVENTS_PER_SEC {
            return false;
        }
        rs.count += 1;
        true
    }

    fn allow_pid_module(&self, pid: u32, module_path: &str, now: Instant) -> bool {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        // Light incremental eviction: drop entries older than window.
        map.retain(|_, ts| now.duration_since(*ts) < DEDUP_WINDOW);

        // Hard cap: if at limit and this entry is new, drop the oldest.
        let key = (pid, module_path.to_string());
        if map.len() >= MAX_DEDUP_ENTRIES && !map.contains_key(&key) {
            if let Some(oldest_k) = map
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_k);
            }
        }

        if let Some(ts) = map.get(&key) {
            if now.duration_since(*ts) < DEDUP_WINDOW {
                return false;
            }
        }
        map.insert(key, now);
        true
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Tests — exhaustive over the Phase 5 matrix
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock verifier — caller specifies the verdict per construction.
    struct MockVerifier(SignerVerdict);
    impl ModuleSignerVerifier for MockVerifier {
        fn verify(&self, _: &str) -> SignerVerdict {
            self.0
        }
    }

    /// Mock lineage — caller specifies yes/no.
    struct MockLineage(bool);
    impl JavaLineageChecker for MockLineage {
        fn has_java_ancestor(&self, _: u32) -> bool {
            self.0
        }
    }

    fn raw(pid: u32, target: &str, module: &str) -> ImageLoadRawEvent {
        ImageLoadRawEvent {
            target_pid: pid,
            target_image_name: target.into(),
            loaded_module_path: module.into(),
            timestamp_unix: 1_700_000_000,
        }
    }

    // ── Phase 5 required cases ────────────────────────────────────

    #[test]
    fn unsigned_temp_dll_in_chrome_under_java_emits_signal() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        assert_eq!(
            f.process_event(e, &v, &l),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
        assert_eq!(f.events_emitted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn signed_dll_in_chrome_under_java_does_not_emit() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Trusted);
        let l = MockLineage(true);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\legit.dll",
        );
        assert!(f.process_event(e, &v, &l).is_none());
        assert_eq!(f.events_signed_trusted.load(Ordering::Relaxed), 1);
        assert_eq!(f.events_emitted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unsigned_temp_dll_in_non_browser_under_java_does_not_emit() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        let e = raw(
            123,
            "notepad.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        assert!(f.process_event(e, &v, &l).is_none());
        assert_eq!(f.events_filtered.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unsigned_dll_in_browser_without_java_ancestor_does_not_emit() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(false);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll",
        );
        assert!(f.process_event(e, &v, &l).is_none());
        assert_eq!(f.events_no_java_ancestor.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn repeated_same_module_load_deduped() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        let path = "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll";
        let first = f.process_event(raw(123, "chrome.exe", path), &v, &l);
        assert!(first.is_some(), "first emit must succeed");
        let second = f.process_event(raw(123, "chrome.exe", path), &v, &l);
        assert!(second.is_none(), "second emit must be deduped");
        let third = f.process_event(raw(123, "chrome.exe", path), &v, &l);
        assert!(third.is_none(), "ongoing dedup");
        assert_eq!(f.events_deduped.load(Ordering::Relaxed), 2);
        assert_eq!(f.events_emitted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unknown_signer_still_eligible_when_path_and_lineage_match() {
        // Policy: Unknown is not auto-malicious, BUT when paired with
        // browser target + user-writable path + Java ancestor, the
        // canonical detector still emits. The Unknown counter advances.
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Unknown);
        let l = MockLineage(true);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\mystery.dll",
        );
        assert_eq!(
            f.process_event(e, &v, &l),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
        assert_eq!(f.events_signer_unknown.load(Ordering::Relaxed), 1);
        assert_eq!(f.events_emitted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unknown_signer_does_not_emit_without_java_ancestor() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Unknown);
        let l = MockLineage(false);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\mystery.dll",
        );
        assert!(f.process_event(e, &v, &l).is_none());
    }

    #[test]
    fn module_path_outside_foothold_drops_before_signer_check() {
        // System32 module — caller shouldn't bear signer-check cost.
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        let e = raw(123, "chrome.exe", "C:\\Windows\\System32\\anyDLL.dll");
        assert!(f.process_event(e, &v, &l).is_none());
        // events_signed_trusted / events_signer_unknown stayed at 0 ⇒
        // verifier wasn't called.
        assert_eq!(f.events_signer_unknown.load(Ordering::Relaxed), 0);
        assert_eq!(f.events_signed_trusted.load(Ordering::Relaxed), 0);
        assert_eq!(f.events_filtered.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rate_limit_blocks_burst() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        // Fire MAX_EVENTS_PER_SEC + 50 distinct loads in the same instant.
        let t0 = Instant::now();
        let mut emitted = 0u32;
        let mut rate_limited = 0u32;
        for i in 0..(MAX_EVENTS_PER_SEC + 50) {
            let e = raw(
                123,
                "chrome.exe",
                &format!("C:\\Users\\t\\AppData\\Local\\Temp\\m{i}.dll"),
            );
            let s = f.process_event_at(e, &v, &l, t0);
            if s.is_some() {
                emitted += 1;
            }
        }
        rate_limited = f.events_rate_limited.load(Ordering::Relaxed) as u32;
        assert_eq!(emitted, MAX_EVENTS_PER_SEC, "must emit exactly the budget");
        assert_eq!(rate_limited, 50, "excess must count as rate-limited");
    }

    #[test]
    fn rate_limit_window_resets_after_one_second() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        let t0 = Instant::now();
        // Burn through the budget at t0.
        for i in 0..MAX_EVENTS_PER_SEC {
            let e = raw(
                123,
                "chrome.exe",
                &format!("C:\\Users\\t\\AppData\\Local\\Temp\\m{i}.dll"),
            );
            let _ = f.process_event_at(e, &v, &l, t0);
        }
        // One second later, a fresh event must NOT be rate-limited.
        let t1 = t0 + Duration::from_secs(1);
        let e = raw(
            123,
            "chrome.exe",
            "C:\\Users\\t\\AppData\\Local\\Temp\\newer.dll",
        );
        assert_eq!(
            f.process_event_at(e, &v, &l, t1),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
    }

    #[test]
    fn dedup_table_is_bounded() {
        let f = BrowserImageLoadFilter::new();
        let v = MockVerifier(SignerVerdict::Untrusted);
        let l = MockLineage(true);
        // Force MAX_DEDUP_ENTRIES + 100 unique entries. Rate limit will
        // truncate the actual processed count, so we drive across many
        // rate-windows by advancing `now` per insert.
        let mut t = Instant::now();
        for i in 0..(MAX_DEDUP_ENTRIES + 100) {
            let e = raw(
                i as u32,
                "chrome.exe",
                &format!("C:\\Users\\t\\AppData\\Local\\Temp\\m{i}.dll"),
            );
            // Advance one millisecond per iteration so dedup stays in window
            // but rate-limit window rolls reasonably.
            t += Duration::from_millis(10);
            let _ = f.process_event_at(e, &v, &l, t);
        }
        // Table must have evicted oldest entries — exact size bounded.
        let len = f.seen.lock().unwrap().len();
        assert!(
            len <= MAX_DEDUP_ENTRIES,
            "dedup table size {len} exceeded cap {MAX_DEDUP_ENTRIES}"
        );
    }

    #[test]
    fn null_signer_verifier_returns_unknown() {
        let v = NullSignerVerifier;
        assert_eq!(v.verify("C:\\anything.dll"), SignerVerdict::Unknown);
    }

    #[test]
    fn lineage_graph_java_checker_detects_javaw() {
        use super::super::{LineageGraph, ProcessNode};
        let graph = std::sync::Arc::new(LineageGraph::new());
        graph.record_process(ProcessNode {
            pid: 1,
            parent_pid: 0,
            image_path: "C:\\Windows\\explorer.exe".into(),
            image_name: "explorer.exe".into(),
            command_line: None,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1000,
        });
        graph.record_process(ProcessNode {
            pid: 2,
            parent_pid: 1,
            image_path: "C:\\Program Files\\Java\\bin\\javaw.exe".into(),
            image_name: "javaw.exe".into(),
            command_line: None,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1100,
        });
        graph.record_process(ProcessNode {
            pid: 3,
            parent_pid: 2,
            image_path: "C:\\Program Files\\Google\\Chrome\\chrome.exe".into(),
            image_name: "chrome.exe".into(),
            command_line: None,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: 1200,
        });
        let checker = LineageGraphJavaChecker::new(graph);
        assert!(checker.has_java_ancestor(3), "chrome under javaw lineage");
        assert!(!checker.has_java_ancestor(999), "missing PID = no ancestor");
    }

    #[test]
    fn diagnostics_json_shape_is_stable() {
        let f = BrowserImageLoadFilter::new();
        let j = f.diagnostics_json();
        for k in [
            "events_seen",
            "events_filtered",
            "events_deduped",
            "events_rate_limited",
            "events_signed_trusted",
            "events_signer_unknown",
            "events_emitted",
            "events_no_java_ancestor",
            "max_events_per_sec",
            "dedup_window_secs",
            "max_dedup_entries",
        ] {
            assert!(j.get(k).is_some(), "missing key: {k}");
        }
    }
}

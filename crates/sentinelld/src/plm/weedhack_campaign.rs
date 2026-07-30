//! WeedHack campaign correlator.
//!
//! This module sits **on top of** the four runtime detectors
//! (`weedhack_runtime`, `weedhack_etherhiding`, `weedhack_browser_injection`,
//! `weedhack_wallet_harvest`) and turns their individual signals into a
//! single, time-correlated campaign view.
//!
//! ## Why a correlator?
//!
//! A live WeedHack infection emits several distinct signals as it walks
//! through its stages — Stage 1 spawns Stage 2 via `schtasks`, Stage 2
//! does an EtherHiding lookup and then a wallet-harvest burst, Stage 3
//! disables Defender and writes Run-key persistence. Each detector sees
//! one slice of that. Without correlation, the operator gets N
//! independent "suspicious" alerts on different PIDs that they have to
//! mentally reassemble. With correlation, ARGUS emits ONE
//! `CampaignFinding` whose tier grows as evidence accumulates, named
//! against a single campaign root.
//!
//! ## Architecture
//!
//! - **Campaign key**: a `CampaignKey` identifies a campaign. The key is
//!   normally derived from a process-tree root — the topmost
//!   `javaw.exe` (or `java.exe`) ancestor of the PID that emitted the
//!   signal. If no Java ancestor exists (e.g. an orphan `Pjibf.exe`),
//!   the PID itself is used as the root. The key includes
//!   `created_at_unix` to defeat PID reuse: a recycled PID gets a fresh
//!   timestamp and therefore a different `CampaignKey`, opening a new
//!   campaign instead of polluting the old one.
//!
//! - **Lineage resolution**: the tracker doesn't depend on PLM directly.
//!   It takes a `LineageResolver` (a trait), which production code
//!   implements as an adapter around `LineageGraph` and test code
//!   implements as an in-memory map.
//!
//! - **Signal accumulation**: each campaign owns a `HashSet<
//!   WeedHackSignal>`. Re-emitting the SAME signal type for an existing
//!   campaign is a no-op — only the FIRST occurrence of each distinct
//!   signal contributes weight. This matches the user-visible reality:
//!   the stealer reading 200 wallet files emits one
//!   `WalletHarvestBurst` signal (the detector dedupes); reading three
//!   more reverberates as the same signal.
//!
//! - **Tier model**: see [`CampaignTier`] below.
//!
//! - **Emission**: `ingest_signal()` returns `Some(CampaignFinding)`
//!   ONLY when the campaign's tier *advances*. Stable tiers (same
//!   signal re-fires, or a new signal but the tier formula still
//!   yields the same level) return `None`. This is the "single finding
//!   per campaign per tier transition" rule.
//!
//! - **Eviction**: campaigns expire after `WINDOW` of no new signals,
//!   and the active set is hard-capped at `MAX_CAMPAIGNS`. Eviction is
//!   driven by `evict_expired()`, normally called from a background
//!   tick alongside `LineageGraph::evict_expired()`.
//!
//! ## Tier model
//!
//! A **pathognomonic** signal (see
//! `WeedHackSignal::is_pathognomonic`) is one whose firing condition is
//! unique to WeedHack — there is no legitimate analog. Currently:
//! `Pjibf`, `JavaSecurityUpdaterTask`, `EtherHidingFromJava`.
//!
//! Given the set of distinct signals collected so far:
//!
//! ```text
//! count        = number of distinct signal types
//! total_weight = sum of weights for those distinct types
//! pathognomic  = at least one pathognomonic signal in the set
//!
//! Confirmed     ← count ≥ 3
//!              OR (pathognomonic AND count ≥ 2)
//!              OR total_weight ≥ 120
//!
//! HighConfidence ← count ≥ 2
//!              OR pathognomonic                ← one pathognomonic alone is enough
//!              OR total_weight ≥ 70
//!
//! Suspicious    ← total_weight ≥ 30
//!
//! None          (below 30 — single very-weak signal, shouldn't happen
//!                with current detectors since min weight is 32)
//! ```
//!
//! Worked examples:
//!
//! ```text
//! { UnnaturalJavaChild (32) }                  → Suspicious
//! { RunKeyFromJava (35) }                       → Suspicious
//! { Pjibf (60, path) }                          → HighConfidence
//! { UnnaturalJavaChild, DefenderDisableUnderJava }    → HighConfidence (2 types, 72 weight)
//! { UnnaturalJavaChild, DefenderDisableUnderJava, RunKeyFromJava } → Confirmed (3 types)
//! { Pjibf, UnnaturalJavaChild }                 → Confirmed (path + 1 corroborator)
//! { EtherHidingFromJava, WalletHarvestBurst }   → Confirmed (path + 1 corroborator)
//! ```

#![allow(dead_code)]

use super::weedhack_runtime::WeedHackSignal;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Time window during which signals correlate into the same campaign.
/// 20 minutes — middle of the 15–30 range the design called for.
pub const WINDOW: Duration = Duration::from_secs(20 * 60);

/// Hard cap on concurrent campaigns. Far above realistic concurrent
/// infection count; serves only as a memory backstop.
pub const MAX_CAMPAIGNS: usize = 64;

// ─────────────────────────────────────────────────────────────────────
//  Public types
// ─────────────────────────────────────────────────────────────────────

/// Identifier of a campaign's process-tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CampaignRoot {
    /// PID of the root process (topmost `javaw.exe` ancestor, or the
    /// signal-emitting PID itself if no Java ancestor exists).
    pub pid: u32,
    /// Unix timestamp of root process creation. Disambiguates PID reuse.
    pub created_at_unix: i64,
}

/// Map a leaf PID to its campaign root. Implementations:
///
///   * production: an adapter over `super::LineageGraph` that walks
///     parent_pid links and returns the topmost `javaw.exe` ancestor;
///   * tests: an in-memory `HashMap<u32, CampaignRoot>`.
///
/// Returning `None` is fine — the tracker falls back to using the
/// signal-emitting PID as its own root.
pub trait LineageResolver: Send + Sync {
    fn resolve_campaign_root(&self, pid: u32) -> Option<CampaignRoot>;
}

/// The three confidence tiers a campaign can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignTier {
    /// Single weak signal or low cumulative evidence. Watch-list only —
    /// no automatic action recommended.
    Suspicious,
    /// Either two distinct signals OR a single pathognomonic signal.
    /// Action recommended: surface to operator, optionally quarantine.
    HighConfidence,
    /// Three+ distinct signals, or pathognomonic + corroborator.
    /// Equivalent to a confirmed IOC hash hit: kill-on-sight.
    Confirmed,
}

impl CampaignTier {
    /// Numeric ladder for tier comparison (Suspicious=1, HighConfidence=2,
    /// Confirmed=3). Used internally for tier-advancement checks.
    pub const fn ladder(self) -> u8 {
        match self {
            CampaignTier::Suspicious => 1,
            CampaignTier::HighConfidence => 2,
            CampaignTier::Confirmed => 3,
        }
    }
}

/// A campaign finding emitted on tier advancement.
#[derive(Debug, Clone)]
pub struct CampaignFinding {
    /// Stable identifier for the campaign across its lifetime.
    pub root: CampaignRoot,
    /// Tier reached by this advancement.
    pub tier: CampaignTier,
    /// Total cumulative weight at emission time.
    pub score: u32,
    /// Distinct signals accumulated so far, in a stable order.
    pub signals: Vec<WeedHackSignal>,
    /// Time elapsed since the first signal.
    pub elapsed: Duration,
}

impl CampaignFinding {
    /// Human-readable summary suitable for an ARGUS finding description.
    pub fn describe(&self) -> String {
        let labels: Vec<&str> = self.signals.iter().map(|s| s.label()).collect();
        format!(
            "WeedHack campaign [{:?}] root=pid:{} score={} signals=[{}] elapsed={}s",
            self.tier,
            self.root.pid,
            self.score,
            labels.join(" | "),
            self.elapsed.as_secs(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Tracker internals
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Campaign {
    root: CampaignRoot,
    signals: HashSet<WeedHackSignal>,
    /// Insertion order of signals — used to render `CampaignFinding.signals`
    /// deterministically.
    signal_order: Vec<WeedHackSignal>,
    started_at: Instant,
    last_signal_at: Instant,
    last_tier_emitted: Option<CampaignTier>,
}

impl Campaign {
    fn new(root: CampaignRoot, now: Instant) -> Self {
        Self {
            root,
            signals: HashSet::new(),
            signal_order: Vec::new(),
            started_at: now,
            last_signal_at: now,
            last_tier_emitted: None,
        }
    }

    fn score(&self) -> u32 {
        self.signals.iter().map(|s| s.weight()).sum()
    }

    fn tier(&self) -> Option<CampaignTier> {
        classify(&self.signals)
    }
}

/// The tracker. Thread-safe via internal Mutex.
pub struct WeedHackCampaignTracker {
    resolver: std::sync::Arc<dyn LineageResolver>,
    inner: Mutex<HashMap<CampaignRoot, Campaign>>,
}

impl WeedHackCampaignTracker {
    pub fn new(resolver: std::sync::Arc<dyn LineageResolver>) -> Self {
        Self {
            resolver,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Ingest one detected signal for a process. Returns
    /// `Some(CampaignFinding)` when the campaign's tier **advances** as
    /// a result; returns `None` if the signal was already known, the
    /// tier didn't change, or the cumulative evidence didn't yet reach
    /// the lowest tier.
    pub fn ingest_signal(
        &self,
        emitting_pid: u32,
        signal: WeedHackSignal,
    ) -> Option<CampaignFinding> {
        self.ingest_signal_at(emitting_pid, signal, Instant::now())
    }

    /// Test-friendly variant: callers can supply a synthetic `now` so
    /// time-window tests don't depend on real elapsed time.
    pub fn ingest_signal_at(
        &self,
        emitting_pid: u32,
        signal: WeedHackSignal,
        now: Instant,
    ) -> Option<CampaignFinding> {
        let root = self
            .resolver
            .resolve_campaign_root(emitting_pid)
            .unwrap_or(CampaignRoot {
                // Fallback: orphan signal becomes its own campaign root.
                // created_at_unix=0 is fine — it serves only as a PID-reuse
                // disambiguator, and an orphan campaign will be evicted
                // long before a PID is realistically recycled.
                pid: emitting_pid,
                created_at_unix: 0,
            });

        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Light incremental eviction: campaigns that haven't advanced in
        // `WINDOW` are dropped on every ingest. This keeps the map bounded
        // without a background thread.
        map.retain(|_, c| now.duration_since(c.last_signal_at) < WINDOW);

        // Hard memory cap with flush-by-flood resistance: if at limit and
        // this campaign is new, evict a victim. Plain "oldest-by-last-signal"
        // let an attacker spawn MAX_CAMPAIGNS+ short-lived roots to flush an
        // in-progress HighConfidence/Confirmed campaign mid-accumulation
        // (a genuine multi-stage infection pauses between stages and is thus
        // the stalest entry). So we prefer evicting low-value campaigns —
        // those with no tier emitted yet or only Suspicious — and fall back
        // to oldest-overall only when every campaign is already high-tier.
        if map.len() >= MAX_CAMPAIGNS && !map.contains_key(&root) {
            let victim = map
                .iter()
                .filter(|(_, c)| {
                    c.last_tier_emitted
                        .map_or(true, |t| t.ladder() <= CampaignTier::Suspicious.ladder())
                })
                .min_by_key(|(_, c)| c.last_signal_at)
                .map(|(k, _)| *k)
                .or_else(|| {
                    map.iter()
                        .min_by_key(|(_, c)| c.last_signal_at)
                        .map(|(k, _)| *k)
                });
            if let Some(victim) = victim {
                map.remove(&victim);
            }
        }

        let campaign = map
            .entry(root)
            .or_insert_with(|| Campaign::new(root, now));

        campaign.last_signal_at = now;

        // De-dup: ignore repeats of an already-recorded signal type.
        let signal_was_new = campaign.signals.insert(signal);
        if signal_was_new {
            campaign.signal_order.push(signal);
        } else if campaign.last_tier_emitted.is_some() {
            // Same signal again on an already-emitted campaign — no advance.
            return None;
        }

        // Recompute tier and check for advancement.
        let new_tier = campaign.tier();
        let old_ladder = campaign
            .last_tier_emitted
            .map(|t| t.ladder())
            .unwrap_or(0);
        let new_ladder = new_tier.map(|t| t.ladder()).unwrap_or(0);

        if new_ladder > old_ladder {
            campaign.last_tier_emitted = new_tier;
            Some(CampaignFinding {
                root: campaign.root,
                tier: new_tier.expect("ladder>0 implies Some"),
                score: campaign.score(),
                signals: campaign.signal_order.clone(),
                elapsed: now.duration_since(campaign.started_at),
            })
        } else {
            None
        }
    }

    /// Drop campaigns whose `last_signal_at` is older than `WINDOW`.
    /// Returns the number of campaigns evicted.
    pub fn evict_expired(&self) -> usize {
        self.evict_expired_at(Instant::now())
    }

    /// Test-friendly variant.
    pub fn evict_expired_at(&self, now: Instant) -> usize {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, c| now.duration_since(c.last_signal_at) < WINDOW);
        before - map.len()
    }

    /// Current active campaign count. Diagnostics / tests.
    pub fn active_campaign_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Estimated memory footprint of the tracker right now.
    ///
    /// Each `Campaign` holds:
    ///   * a `HashSet<WeedHackSignal>` (≤10 enum variants, ≤80 bytes inline
    ///     + allocator overhead),
    ///   * a `Vec<WeedHackSignal>` with the same upper bound,
    ///   * 2 `Instant`s, 1 `CampaignRoot`, 1 `Option<CampaignTier>`.
    ///
    /// Plus the `CampaignRoot → Campaign` HashMap entry (~64 bytes of
    /// bucket overhead). Worst-case ~256 bytes per campaign. With
    /// `MAX_CAMPAIGNS=64` the upper bound is ~16 KiB — bounded.
    pub fn approx_bytes(&self) -> usize {
        const PER_CAMPAIGN_BYTES: usize = 256;
        self.active_campaign_count() * PER_CAMPAIGN_BYTES
    }
}

// ─────────────────────────────────────────────────────────────────────
//  LineageGraph-backed resolver (Phase 1 wiring)
// ─────────────────────────────────────────────────────────────────────

/// Production `LineageResolver` backed by the PLM `LineageGraph`.
///
/// Resolution rule: walk the lineage chain ancestor-first and return
/// the *topmost* `javaw.exe` / `java.exe` node as the campaign root.
/// This keeps Stage1/Stage2/Stage3 child processes converging on the
/// same campaign even as the WeedHack process tree grows.
///
/// `created_at_unix` is taken from the captured ProcessNode timestamp.
/// PID reuse → new timestamp → distinct `CampaignRoot` → fresh
/// campaign, as required by the PID-reuse safety design.
///
/// If no Java ancestor exists (orphan native stage like `Pjibf.exe`),
/// returns `None`; the tracker falls back to keying on the emitting
/// PID itself.
pub struct LineageGraphResolver {
    graph: std::sync::Arc<super::LineageGraph>,
}

impl LineageGraphResolver {
    pub fn new(graph: std::sync::Arc<super::LineageGraph>) -> Self {
        Self { graph }
    }
}

impl LineageResolver for LineageGraphResolver {
    fn resolve_campaign_root(&self, pid: u32) -> Option<CampaignRoot> {
        let chain = self.graph.get_chain(pid);
        // chain.nodes is ancestor-first; first javaw we see is the topmost.
        for node in &chain.nodes {
            let lower = node.image_name.to_ascii_lowercase();
            if lower == "javaw.exe" || lower == "java.exe" {
                return Some(CampaignRoot {
                    pid: node.pid,
                    created_at_unix: node.timestamp,
                });
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────
//  ARGUS finding mapping (Phase 4)
// ─────────────────────────────────────────────────────────────────────

impl CampaignFinding {
    /// Map this campaign finding to an `argus::Finding`. Layer + severity
    /// + weight chosen so the verdict pipeline takes the right action:
    ///
    /// | Tier             | Layer            | Severity | Weight       | Net effect                                    |
    /// |------------------|------------------|----------|--------------|-----------------------------------------------|
    /// | Suspicious       | Context (cap 15) | Medium   | 10           | LowSuspicion verdict — observe / surface only |
    /// | HighConfidence   | Context (cap 15) | High     | 20           | capped to 15 — needs corroboration to escalate|
    /// | Confirmed        | IocCorrelation   | Critical | campaign sum | Malicious verdict — eligible for quarantine via existing convergence policy |
    ///
    /// `root_image` is woven into the description when known so the
    /// operator sees which process tree the campaign sits on without
    /// going back to the diagnostics endpoint.
    pub fn to_argus_finding(&self, root_image: Option<String>) -> argus::Finding {
        let (layer, severity, weight) = match self.tier {
            CampaignTier::Suspicious => (
                argus::verdict::Layer::Context,
                argus::verdict::Severity::Medium,
                10,
            ),
            CampaignTier::HighConfidence => (
                argus::verdict::Layer::Context,
                argus::verdict::Severity::High,
                20,
            ),
            CampaignTier::Confirmed => (
                argus::verdict::Layer::IocCorrelation,
                argus::verdict::Severity::Critical,
                self.score,
            ),
        };

        let root_label = root_image
            .as_deref()
            .map(|s| format!(" image={s}"))
            .unwrap_or_default();

        argus::Finding {
            layer,
            severity,
            weight,
            description: format!(
                "WeedHack campaign [{:?}] root=pid:{}{} score={} signals={} elapsed={}s",
                self.tier,
                self.root.pid,
                root_label,
                self.score,
                self.signals.len(),
                self.elapsed.as_secs(),
            ),
            technical_detail: Some(self.describe()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Diagnostics (Phase 5)
// ─────────────────────────────────────────────────────────────────────

/// Ring-buffer cap for the recent-findings list exposed by diagnostics.
const RECENT_FINDINGS_CAP: usize = 16;

/// One serializable entry in the diagnostics `recent_findings` array.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignFindingRecord {
    pub tier: CampaignTier,
    pub root_pid: u32,
    pub root_image: Option<String>,
    pub signal_count: usize,
    /// Human-readable signal labels (not the enum variants — the labels
    /// are stable and operator-friendly).
    pub signals: Vec<&'static str>,
    pub narrative: String,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
}

/// Aggregate diagnostics for the campaign subsystem. Atomics for
/// counters + Mutex-protected ring buffer for the recent findings.
pub struct WeedHackCampaignDiagnostics {
    active: std::sync::atomic::AtomicU64,
    expired: std::sync::atomic::AtomicU64,
    last_confirmed_unix: std::sync::atomic::AtomicI64,
    confirmed_total: std::sync::atomic::AtomicU64,
    high_confidence_total: std::sync::atomic::AtomicU64,
    suspicious_total: std::sync::atomic::AtomicU64,
    recent: Mutex<std::collections::VecDeque<CampaignFindingRecord>>,
}

impl WeedHackCampaignDiagnostics {
    pub fn new() -> Self {
        Self {
            active: std::sync::atomic::AtomicU64::new(0),
            expired: std::sync::atomic::AtomicU64::new(0),
            last_confirmed_unix: std::sync::atomic::AtomicI64::new(0),
            confirmed_total: std::sync::atomic::AtomicU64::new(0),
            high_confidence_total: std::sync::atomic::AtomicU64::new(0),
            suspicious_total: std::sync::atomic::AtomicU64::new(0),
            recent: Mutex::new(std::collections::VecDeque::with_capacity(RECENT_FINDINGS_CAP)),
        }
    }

    /// Record one campaign finding as it's emitted. `root_image` is the
    /// resolved image name of the root PID (best-effort — may be None
    /// for orphan campaigns or when the LineageGraph has aged the node
    /// out). `now_unix` is the wall-clock Unix timestamp at record time.
    pub fn record(
        &self,
        finding: &CampaignFinding,
        root_image: Option<String>,
        now_unix: i64,
    ) {
        use std::sync::atomic::Ordering;
        match finding.tier {
            CampaignTier::Confirmed => {
                self.confirmed_total.fetch_add(1, Ordering::Relaxed);
                self.last_confirmed_unix.store(now_unix, Ordering::Relaxed);
            }
            CampaignTier::HighConfidence => {
                self.high_confidence_total.fetch_add(1, Ordering::Relaxed);
            }
            CampaignTier::Suspicious => {
                self.suspicious_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        let record = CampaignFindingRecord {
            tier: finding.tier,
            root_pid: finding.root.pid,
            root_image,
            signal_count: finding.signals.len(),
            signals: finding.signals.iter().map(|s| s.label()).collect(),
            narrative: finding.describe(),
            first_seen_unix: now_unix - finding.elapsed.as_secs() as i64,
            last_seen_unix: now_unix,
        };

        let mut buf = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= RECENT_FINDINGS_CAP {
            buf.pop_front();
        }
        buf.push_back(record);
    }

    /// Mark `n` campaigns as evicted during a maintenance pass.
    pub fn note_evicted(&self, n: usize) {
        if n > 0 {
            self.expired
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Snapshot the current active-campaign count (called by the
    /// integration layer with the tracker's live count).
    pub fn note_active(&self, n: usize) {
        self.active
            .store(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Serialize diagnostics as JSON in the shape required by the
    /// integration spec.
    pub fn to_json(&self, current_active: usize) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        self.note_active(current_active);
        let recent: Vec<CampaignFindingRecord> = self
            .recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect();
        serde_json::json!({
            "active": current_active,
            "max_campaigns": MAX_CAMPAIGNS,
            "expired": self.expired.load(Ordering::Relaxed),
            "last_confirmed_unix": self.last_confirmed_unix.load(Ordering::Relaxed),
            "confirmed_total": self.confirmed_total.load(Ordering::Relaxed),
            "high_confidence_total": self.high_confidence_total.load(Ordering::Relaxed),
            "suspicious_total": self.suspicious_total.load(Ordering::Relaxed),
            "recent_findings": recent,
        })
    }
}

impl Default for WeedHackCampaignDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
//  Tier classification — pure function for testability
// ─────────────────────────────────────────────────────────────────────

fn classify(signals: &HashSet<WeedHackSignal>) -> Option<CampaignTier> {
    if signals.is_empty() {
        return None;
    }
    let count = signals.len();
    let total: u32 = signals.iter().map(|s| s.weight()).sum();
    let pathognomonic = signals.iter().any(|s| s.is_pathognomonic());

    if count >= 3 || (pathognomonic && count >= 2) || total >= 120 {
        return Some(CampaignTier::Confirmed);
    }
    if count >= 2 || pathognomonic || total >= 70 {
        return Some(CampaignTier::HighConfidence);
    }
    if total >= 30 {
        return Some(CampaignTier::Suspicious);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory resolver used by tests. Maps PIDs to fixed roots; any
    /// PID not in the map has no Java ancestor (returns None, so the
    /// tracker falls back to the PID itself as its own root).
    #[derive(Default)]
    struct MockResolver {
        map: std::sync::Mutex<HashMap<u32, CampaignRoot>>,
    }
    impl MockResolver {
        fn add(&self, child_pid: u32, root_pid: u32, root_ts: i64) {
            self.map
                .lock()
                .unwrap()
                .insert(child_pid, CampaignRoot { pid: root_pid, created_at_unix: root_ts });
        }
    }
    impl LineageResolver for MockResolver {
        fn resolve_campaign_root(&self, pid: u32) -> Option<CampaignRoot> {
            self.map.lock().unwrap().get(&pid).copied()
        }
    }

    fn empty_tracker() -> WeedHackCampaignTracker {
        WeedHackCampaignTracker::new(std::sync::Arc::new(MockResolver::default()))
    }

    // ── Tier classification ────────────────────────────────────────

    #[test]
    fn tier_empty_signals_is_none() {
        assert_eq!(classify(&HashSet::new()), None);
    }

    #[test]
    fn tier_single_unnatural_java_child_is_suspicious() {
        let mut s = HashSet::new();
        s.insert(WeedHackSignal::UnnaturalJavaChild);
        assert_eq!(classify(&s), Some(CampaignTier::Suspicious));
    }

    #[test]
    fn tier_single_pjibf_is_high_confidence_not_confirmed() {
        let mut s = HashSet::new();
        s.insert(WeedHackSignal::Pjibf);
        assert_eq!(
            classify(&s),
            Some(CampaignTier::HighConfidence),
            "single pathognomonic signal lands at HighConfidence, not Confirmed — needs corroboration"
        );
    }

    #[test]
    fn tier_two_distinct_non_pathognomonic_is_high_confidence() {
        let mut s = HashSet::new();
        s.insert(WeedHackSignal::UnnaturalJavaChild);
        s.insert(WeedHackSignal::DefenderDisableUnderJava);
        assert_eq!(classify(&s), Some(CampaignTier::HighConfidence));
    }

    #[test]
    fn tier_pathognomonic_plus_corroborator_is_confirmed() {
        let mut s = HashSet::new();
        s.insert(WeedHackSignal::Pjibf);
        s.insert(WeedHackSignal::UnnaturalJavaChild);
        assert_eq!(classify(&s), Some(CampaignTier::Confirmed));
    }

    #[test]
    fn tier_three_distinct_signals_is_confirmed() {
        let mut s = HashSet::new();
        s.insert(WeedHackSignal::UnnaturalJavaChild);
        s.insert(WeedHackSignal::DefenderDisableUnderJava);
        s.insert(WeedHackSignal::RunKeyFromJava);
        assert_eq!(classify(&s), Some(CampaignTier::Confirmed));
    }

    // ── Tracker behaviour ──────────────────────────────────────────

    #[test]
    fn single_signal_does_not_form_high_confidence_campaign() {
        let t = empty_tracker();
        let finding = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        // A finding IS emitted (Suspicious tier crossed), but it must
        // not be HighConfidence or Confirmed.
        let f = finding.expect("Suspicious tier crossed");
        assert_eq!(f.tier, CampaignTier::Suspicious);
        assert!(f.tier < CampaignTier::HighConfidence);
    }

    #[test]
    fn multiple_signals_form_campaign() {
        let resolver = std::sync::Arc::new(MockResolver::default());
        resolver.add(101, 100, 1700_000_000);
        resolver.add(102, 100, 1700_000_000);
        let t = WeedHackCampaignTracker::new(resolver);

        // First signal — Suspicious tier crossed.
        let f1 = t.ingest_signal(101, WeedHackSignal::UnnaturalJavaChild).unwrap();
        assert_eq!(f1.tier, CampaignTier::Suspicious);

        // Second distinct signal under the same root — HighConfidence advance.
        let f2 = t.ingest_signal(102, WeedHackSignal::DefenderDisableUnderJava).unwrap();
        assert_eq!(f2.tier, CampaignTier::HighConfidence);
        assert_eq!(f2.root.pid, 100, "both PIDs share the same root");

        // Third distinct signal → Confirmed advance.
        let f3 = t.ingest_signal(102, WeedHackSignal::WalletHarvestBurst).unwrap();
        assert_eq!(f3.tier, CampaignTier::Confirmed);
        assert_eq!(t.active_campaign_count(), 1);
    }

    #[test]
    fn repeated_same_signal_is_deduplicated() {
        let t = empty_tracker();
        // First emission of UnnaturalJavaChild crosses Suspicious.
        let f1 = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        assert!(f1.is_some());
        // Re-firing the SAME signal must NOT emit a fresh finding
        // — the campaign hasn't gained new evidence.
        let f2 = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        assert!(f2.is_none(), "same-signal re-emission must dedup");
        let f3 = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        assert!(f3.is_none());
    }

    #[test]
    fn tier_does_not_emit_when_tier_unchanged() {
        let t = empty_tracker();
        // Pjibf alone → HighConfidence.
        let f1 = t.ingest_signal(100, WeedHackSignal::Pjibf).unwrap();
        assert_eq!(f1.tier, CampaignTier::HighConfidence);
        // A different signal lands at HighConfidence still (path + 1 → Confirmed,
        // so this should advance — pick UnnaturalJavaChild).
        let f2 = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild).unwrap();
        assert_eq!(f2.tier, CampaignTier::Confirmed);
        // Another corroborator after Confirmed: no advance, no emit.
        let f3 = t.ingest_signal(100, WeedHackSignal::RunKeyFromJava);
        assert!(f3.is_none(), "no advancement past Confirmed should silence emits");
    }

    #[test]
    fn timeout_expiry_removes_campaign() {
        let t = empty_tracker();
        let t0 = Instant::now();

        // Establish a campaign at t0.
        let _ = t.ingest_signal_at(100, WeedHackSignal::UnnaturalJavaChild, t0);
        assert_eq!(t.active_campaign_count(), 1);

        // 21 minutes later — past the WINDOW — eviction drops it.
        let t1 = t0 + Duration::from_secs(21 * 60);
        let evicted = t.evict_expired_at(t1);
        assert_eq!(evicted, 1);
        assert_eq!(t.active_campaign_count(), 0);

        // Inside-window eviction is a no-op.
        let _ = t.ingest_signal_at(100, WeedHackSignal::UnnaturalJavaChild, t0);
        let t_mid = t0 + Duration::from_secs(10 * 60);
        assert_eq!(t.evict_expired_at(t_mid), 0);
        assert_eq!(t.active_campaign_count(), 1);
    }

    #[test]
    fn pid_reuse_starts_a_new_campaign() {
        // The same emitting PID with a DIFFERENT root.created_at_unix
        // (because the OS recycled it) must map to a fresh campaign.
        let resolver = std::sync::Arc::new(MockResolver::default());
        // Initial: child PID 200 traces back to root PID 100 created at ts=1.
        resolver.add(200, 100, 1);
        let t = WeedHackCampaignTracker::new(resolver.clone());
        let f1 = t.ingest_signal(200, WeedHackSignal::UnnaturalJavaChild).unwrap();
        let f2 = t.ingest_signal(200, WeedHackSignal::DefenderDisableUnderJava).unwrap();
        assert_eq!(f1.tier, CampaignTier::Suspicious);
        assert_eq!(f2.tier, CampaignTier::HighConfidence);
        assert_eq!(t.active_campaign_count(), 1);

        // Now PID 200 is recycled by a new process whose root is PID 100
        // created at ts=2 (different timestamp = different campaign root).
        resolver.add(200, 100, 2);
        let f3 = t.ingest_signal(200, WeedHackSignal::UnnaturalJavaChild).unwrap();
        // New campaign, single signal again → tier resets to Suspicious.
        assert_eq!(f3.tier, CampaignTier::Suspicious);
        assert_eq!(t.active_campaign_count(), 2, "PID-reused chain must start fresh, not pollute the old campaign");
    }

    #[test]
    fn orphan_signal_with_no_resolver_match_becomes_own_campaign() {
        let t = empty_tracker(); // resolver returns None for everything
        // Pjibf observed without ETW lineage data — orphan. Still must emit.
        let f = t.ingest_signal(999, WeedHackSignal::Pjibf).unwrap();
        assert_eq!(f.root.pid, 999, "orphan signal keys on its own PID");
        assert_eq!(f.tier, CampaignTier::HighConfidence);
    }

    #[test]
    fn two_unrelated_pids_form_two_campaigns() {
        // Distinct root PIDs → distinct campaigns. Signals do NOT pool.
        let resolver = std::sync::Arc::new(MockResolver::default());
        resolver.add(200, 100, 1);
        resolver.add(300, 150, 1);
        let t = WeedHackCampaignTracker::new(resolver);

        let f_a1 = t.ingest_signal(200, WeedHackSignal::UnnaturalJavaChild).unwrap();
        let f_b1 = t.ingest_signal(300, WeedHackSignal::DefenderDisableUnderJava).unwrap();
        // Each campaign is at Suspicious independently — no cross-pollination.
        assert_eq!(f_a1.tier, CampaignTier::Suspicious);
        assert_eq!(f_b1.tier, CampaignTier::Suspicious);
        assert_eq!(t.active_campaign_count(), 2);
    }

    #[test]
    fn campaign_finding_describes_clearly() {
        let t = empty_tracker();
        let _ = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        let f = t.ingest_signal(100, WeedHackSignal::Pjibf).unwrap();
        let desc = f.describe();
        assert!(desc.contains("WeedHack campaign"));
        assert!(desc.contains("Confirmed"));
        assert!(desc.contains("100"));
    }

    #[test]
    fn memory_bound_under_campaign_storm() {
        let resolver = std::sync::Arc::new(MockResolver::default());
        // Each emitting PID has a unique root (so each forms a unique campaign).
        for i in 0..(MAX_CAMPAIGNS as u32 + 30) {
            resolver.add(1000 + i, i, 1);
        }
        let t = WeedHackCampaignTracker::new(resolver);
        for i in 0..(MAX_CAMPAIGNS as u32 + 30) {
            let _ = t.ingest_signal(1000 + i, WeedHackSignal::UnnaturalJavaChild);
        }
        assert!(
            t.active_campaign_count() <= MAX_CAMPAIGNS,
            "tracker exceeded MAX_CAMPAIGNS: {}",
            t.active_campaign_count()
        );
        // Memory accounting is sane.
        assert!(t.approx_bytes() <= MAX_CAMPAIGNS * 256);
    }

    #[test]
    fn confirmed_campaign_survives_flush_by_flood() {
        // A real multi-stage infection reaches Confirmed, then pauses
        // (Stage 2 → Stage 3 can be seconds-to-minutes apart) — making it
        // the stalest campaign. Pre-fix, an attacker spawning MAX_CAMPAIGNS+
        // short-lived roots would evict it (oldest-by-last-signal). The
        // flush-by-flood fix must keep the Confirmed campaign alive by
        // preferring low-tier eviction victims.
        let resolver = std::sync::Arc::new(MockResolver::default());
        // Victim campaign: root pid 1, reaches Confirmed via pathognomonic
        // + corroborator.
        resolver.add(10, 1, 1);
        // Flood roots: pids 100.. each its own root.
        for i in 0..(MAX_CAMPAIGNS as u32 + 50) {
            resolver.add(1000 + i, 100 + i, 1);
        }
        let t = WeedHackCampaignTracker::new(resolver);

        // Drive the victim to Confirmed (Pjibf pathognomonic + corroborator).
        let _ = t.ingest_signal(10, WeedHackSignal::Pjibf);
        let conf = t
            .ingest_signal(10, WeedHackSignal::UnnaturalJavaChild)
            .expect("victim should advance");
        assert_eq!(conf.tier, CampaignTier::Confirmed);
        let victim_root = conf.root;

        // Now flood far beyond the cap with fresh low-tier campaigns.
        for i in 0..(MAX_CAMPAIGNS as u32 + 50) {
            let _ = t.ingest_signal(1000 + i, WeedHackSignal::UnnaturalJavaChild);
        }

        assert!(t.active_campaign_count() <= MAX_CAMPAIGNS);
        // The Confirmed campaign must still be present: re-ingesting its
        // already-seen signal returns None (dedup on a LIVE campaign) rather
        // than re-emitting Suspicious (which would mean it was evicted and
        // recreated fresh).
        let re = t.ingest_signal(10, WeedHackSignal::Pjibf);
        assert!(
            re.is_none(),
            "Confirmed campaign was flushed by the flood (got a fresh emit: {re:?}) — root {victim_root:?}"
        );
    }

    #[test]
    fn tier_advancement_emits_at_each_step_no_skips() {
        let t = empty_tracker();
        // Suspicious
        let f1 = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild).unwrap();
        assert_eq!(f1.tier, CampaignTier::Suspicious);
        // HighConfidence
        let f2 = t.ingest_signal(100, WeedHackSignal::DefenderDisableUnderJava).unwrap();
        assert_eq!(f2.tier, CampaignTier::HighConfidence);
        // Confirmed
        let f3 = t.ingest_signal(100, WeedHackSignal::WalletHarvestBurst).unwrap();
        assert_eq!(f3.tier, CampaignTier::Confirmed);
        // No further emits.
        assert!(t
            .ingest_signal(100, WeedHackSignal::RunKeyFromJava)
            .is_none());
    }

    #[test]
    fn signals_are_listed_in_insertion_order_in_finding() {
        let t = empty_tracker();
        let _ = t.ingest_signal(100, WeedHackSignal::UnnaturalJavaChild);
        let f = t.ingest_signal(100, WeedHackSignal::Pjibf).unwrap();
        assert_eq!(
            f.signals,
            vec![
                WeedHackSignal::UnnaturalJavaChild,
                WeedHackSignal::Pjibf,
            ]
        );
    }

    // ── LineageGraphResolver (Phase 1) ─────────────────────────────

    use super::super::{LineageGraph, ProcessNode};
    use super::super::cmdline::CommandLineState;

    fn make_node(pid: u32, ppid: u32, name: &str, ts: i64) -> ProcessNode {
        ProcessNode {
            pid,
            parent_pid: ppid,
            image_path: format!("C:\\Program Files\\Java\\{name}"),
            image_name: name.to_string(),
            command_line: CommandLineState::NotCollected,
            is_signed: None,
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: ts,
        }
    }

    #[test]
    fn resolver_javaw_to_powershell_resolves_to_javaw_root() {
        let g = std::sync::Arc::new(LineageGraph::new());
        g.record_process(make_node(1, 0, "explorer.exe", 1000));
        g.record_process(make_node(2, 1, "javaw.exe", 1100));
        g.record_process(make_node(3, 2, "powershell.exe", 1200));
        let r = LineageGraphResolver::new(g);
        let root = r.resolve_campaign_root(3).expect("javaw ancestor present");
        assert_eq!(root.pid, 2);
        assert_eq!(root.created_at_unix, 1100);
    }

    #[test]
    fn resolver_orphan_pid_returns_none() {
        let g = std::sync::Arc::new(LineageGraph::new());
        g.record_process(make_node(1, 0, "explorer.exe", 1000));
        g.record_process(make_node(2, 1, "cmd.exe", 1100));
        let r = LineageGraphResolver::new(g);
        // No javaw in lineage — resolver returns None, tracker falls back.
        assert!(r.resolve_campaign_root(2).is_none());
    }

    #[test]
    fn resolver_pid_reuse_produces_different_campaign_root() {
        let g = std::sync::Arc::new(LineageGraph::new());
        g.record_process(make_node(1, 0, "explorer.exe", 1000));
        g.record_process(make_node(100, 1, "javaw.exe", 1100));
        g.record_process(make_node(200, 100, "cmd.exe", 1150));
        let r = LineageGraphResolver::new(std::sync::Arc::clone(&g));
        let root_a = r.resolve_campaign_root(200).unwrap();
        assert_eq!(root_a.pid, 100);
        assert_eq!(root_a.created_at_unix, 1100);

        // Sleep so the new node's `created_at` is strictly after node 200's
        // — otherwise PLM's PID-reuse guard rejects the recycled parent and
        // the chain stops at the child, masking the timestamp swap.
        std::thread::sleep(Duration::from_millis(5));

        // PID 100 recycled by a NEW javaw at a later timestamp.
        g.record_process(make_node(100, 1, "javaw.exe", 1300));
        let root_b = r.resolve_campaign_root(100).unwrap();
        assert_eq!(root_b.pid, 100);
        assert_eq!(root_b.created_at_unix, 1300, "timestamp swap → fresh root");
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn resolver_missing_parent_handled_safely() {
        let g = std::sync::Arc::new(LineageGraph::new());
        // PID 50 references parent 999 which is not in the graph.
        g.record_process(make_node(50, 999, "javaw.exe", 1100));
        let r = LineageGraphResolver::new(g);
        // get_chain stops walking at the missing parent; javaw IS found.
        let root = r.resolve_campaign_root(50).unwrap();
        assert_eq!(root.pid, 50);
    }

    #[test]
    fn resolver_pid_not_in_graph_returns_none() {
        let g = std::sync::Arc::new(LineageGraph::new());
        let r = LineageGraphResolver::new(g);
        // Empty graph + unknown PID → empty chain → None (no javaw).
        assert!(r.resolve_campaign_root(42).is_none());
    }

    // ── ARGUS finding mapping (Phase 4) ───────────────────────────

    fn finding(tier: CampaignTier, score: u32) -> CampaignFinding {
        CampaignFinding {
            root: CampaignRoot { pid: 100, created_at_unix: 1 },
            tier,
            score,
            signals: vec![WeedHackSignal::UnnaturalJavaChild],
            elapsed: Duration::from_secs(5),
        }
    }

    #[test]
    fn mapping_suspicious_is_medium_context_low_weight() {
        let f = finding(CampaignTier::Suspicious, 32).to_argus_finding(Some("javaw.exe".into()));
        assert!(matches!(f.layer, argus::verdict::Layer::Context));
        assert!(matches!(f.severity, argus::verdict::Severity::Medium));
        assert_eq!(f.weight, 10);
        assert!(f.description.contains("Suspicious"));
        assert!(f.description.contains("javaw.exe"));
    }

    #[test]
    fn mapping_high_confidence_is_high_context_capped_weight() {
        let f = finding(CampaignTier::HighConfidence, 60).to_argus_finding(None);
        assert!(matches!(f.layer, argus::verdict::Layer::Context));
        assert!(matches!(f.severity, argus::verdict::Severity::High));
        assert_eq!(f.weight, 20, "Context layer will cap to 15 at aggregation");
    }

    #[test]
    fn mapping_confirmed_is_critical_ioc_with_full_score() {
        let f = finding(CampaignTier::Confirmed, 120).to_argus_finding(Some("javaw.exe".into()));
        assert!(matches!(f.layer, argus::verdict::Layer::IocCorrelation));
        assert!(matches!(f.severity, argus::verdict::Severity::Critical));
        assert_eq!(f.weight, 120, "uncapped IoC layer — full campaign score");
    }

    // ── Diagnostics (Phase 5) ─────────────────────────────────────

    #[test]
    fn diagnostics_records_findings_and_counts_by_tier() {
        let d = WeedHackCampaignDiagnostics::new();
        let f_susp = finding(CampaignTier::Suspicious, 32);
        let f_conf = finding(CampaignTier::Confirmed, 120);
        d.record(&f_susp, Some("javaw.exe".into()), 1_700_000_010);
        d.record(&f_conf, Some("javaw.exe".into()), 1_700_000_020);

        let j = d.to_json(2);
        assert_eq!(j["active"], 2);
        assert_eq!(j["max_campaigns"], MAX_CAMPAIGNS);
        assert_eq!(j["confirmed_total"], 1);
        assert_eq!(j["suspicious_total"], 1);
        assert_eq!(j["last_confirmed_unix"], 1_700_000_020);
        let recent = j["recent_findings"].as_array().unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0]["root_image"], "javaw.exe");
        assert_eq!(recent[1]["tier"], "confirmed");
        // first_seen = last_seen - elapsed_secs (5s in the fixture).
        assert_eq!(recent[1]["first_seen_unix"], 1_700_000_020 - 5);
    }

    #[test]
    fn diagnostics_ring_buffer_is_bounded() {
        let d = WeedHackCampaignDiagnostics::new();
        for i in 0..(RECENT_FINDINGS_CAP + 10) {
            d.record(
                &finding(CampaignTier::Suspicious, 32),
                None,
                1_700_000_000 + i as i64,
            );
        }
        let j = d.to_json(1);
        let recent = j["recent_findings"].as_array().unwrap();
        assert_eq!(recent.len(), RECENT_FINDINGS_CAP, "must cap at ring size");
        // Oldest entries dropped — last entry should be the highest timestamp.
        assert_eq!(
            recent.last().unwrap()["last_seen_unix"],
            1_700_000_000 + (RECENT_FINDINGS_CAP + 10 - 1) as i64
        );
    }

    #[test]
    fn diagnostics_expired_counter_advances() {
        let d = WeedHackCampaignDiagnostics::new();
        d.note_evicted(3);
        d.note_evicted(2);
        let j = d.to_json(0);
        assert_eq!(j["expired"], 5);
    }
}

//! Behavioral Ecosystem Convergence — ASTRA coherent behavioral analysis.
//!
//! Evaluates behavioral ECOSYSTEMS, not isolated events.
//! Combines evidence from all ASTRA subsystems within time windows:
//!   ARGUS findings + PLM lineage + persistence + ADS + trust + drift + runtime
//!
//! Produces human-readable narratives that explain WHY a behavior pattern
//! is suspicious — not just THAT it scored N/100.
//!
//! Lifecycle: Active → Cooling → Expired → Pruned
//!   Active:  receiving evidence within COOLING_THRESHOLD
//!   Cooling: no new evidence, still visible, decaying
//!   Expired: past ECOSYSTEM_TTL, pruned on next cleanup
//!
//! Recurrence: when the same behavioral pattern (fingerprint) reappears
//! after a previous ecosystem expired, the recurrence count increases.
//! Bounded escalation, never overrides signatures.
//!
//! Safety: ecosystems shape convergence, never replace evidence.
//! Signatures remain authoritative. Trust never suppresses known malware.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum active ecosystems tracked simultaneously.
const MAX_ECOSYSTEMS: usize = 100;
/// Ecosystem expires after this duration without new evidence.
const ECOSYSTEM_TTL: Duration = Duration::from_secs(3600); // 1 hour
/// Ecosystem transitions to Cooling after this idle period.
const COOLING_THRESHOLD: Duration = Duration::from_secs(600); // 10 min
/// Max ecosystem escalation points (bounded).
const MAX_ECOSYSTEM_ESCALATION: u32 = 25;
/// Max evidence items per ecosystem (stability control).
const MAX_EVIDENCE_PER_ECOSYSTEM: usize = 50;
/// Max narrative length in characters.
const MAX_NARRATIVE_LEN: usize = 500;
/// Dedup window — same source+description within this period = skip.
const DEDUP_WINDOW: Duration = Duration::from_secs(60);
/// Max recurrence bonus points.
const MAX_RECURRENCE_BONUS: u32 = 8;
/// Points per recurrence.
const RECURRENCE_BONUS_PER: u32 = 2;
/// Max remembered fingerprints for recurrence detection.
const MAX_FINGERPRINTS: usize = 200;

/// Ecosystem lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcosystemState {
    /// Actively receiving evidence.
    Active,
    /// No recent evidence, still visible but decaying.
    Cooling,
    /// Past TTL, will be pruned.
    Expired,
}

/// A behavioral ecosystem — correlated evidence cluster.
#[derive(Debug, Clone, Serialize)]
pub struct BehavioralEcosystem {
    /// Unique ecosystem ID.
    pub id: String,
    /// When the ecosystem was first observed (unix ts).
    pub first_seen: i64,
    /// When the last evidence was added (unix ts).
    pub last_updated: i64,
    /// All evidence contributing to this ecosystem.
    pub evidence: Vec<EcosystemEvidence>,
    /// Computed severity.
    pub severity: EcosystemSeverity,
    /// Escalation points from ecosystem correlation.
    pub escalation: u32,
    /// Human-readable narrative.
    pub narrative: String,
    /// Root entity (file path, process chain, etc.)
    pub root_entity: String,
    /// Lifecycle state.
    pub state: EcosystemState,
    /// How many times severity increased during this ecosystem's life.
    pub escalation_count: u32,
    /// How many times this behavioral pattern recurred after expiration.
    pub recurrence_count: u32,
    /// Ordered timeline of behavioral events.
    pub timeline: Vec<TimelineEvent>,
    /// Convergence score attribution breakdown.
    pub attribution: Option<ConvergenceAttribution>,
    /// When the ecosystem was first observed (monotonic).
    #[serde(skip)]
    pub created_at: Instant,
    /// When the last evidence was added (monotonic).
    #[serde(skip)]
    pub last_activity: Instant,
}

/// A piece of evidence in an ecosystem.
#[derive(Debug, Clone, Serialize)]
pub struct EcosystemEvidence {
    /// Evidence source system.
    pub source: EvidenceSource,
    /// Timestamp (unix).
    pub timestamp: i64,
    /// Human-readable description.
    pub description: String,
    /// Suspicion contribution.
    pub weight: u32,
}

/// Timeline event — ordered chronological record.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    /// Unix timestamp.
    pub timestamp: i64,
    /// Short description.
    pub description: String,
    /// Source system.
    pub source: EvidenceSource,
    /// Weight contribution.
    pub weight: u32,
}

/// Convergence score attribution — explains how final score was shaped.
#[derive(Debug, Clone, Serialize)]
pub struct ConvergenceAttribution {
    /// Base score from ARGUS analysis.
    pub base_argus: u32,
    /// Trust graph adjustment (negative = discount, positive = rare entity penalty).
    pub trust_adjustment: i32,
    /// Drift escalation points.
    pub drift_escalation: u32,
    /// Ecosystem correlation escalation.
    pub ecosystem_escalation: u32,
    /// Recurrence bonus.
    pub recurrence_bonus: u32,
    /// Final convergence score.
    pub final_convergence: u32,
}

/// Where the evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Argus,
    Runtime,
    Plm,
    Persistence,
    Ads,
    TrustGraph,
    Drift,
    Signer,
}

impl EvidenceSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Argus => "ARGUS analysis",
            Self::Runtime => "Runtime script",
            Self::Plm => "Process lineage",
            Self::Persistence => "Persistence",
            Self::Ads => "Alternate data stream",
            Self::TrustGraph => "Trust graph",
            Self::Drift => "Behavioral drift",
            Self::Signer => "Code signing",
        }
    }
}

/// Ecosystem severity — computed from evidence convergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcosystemSeverity {
    /// Few correlated signals, mostly informational.
    Low,
    /// Multiple signals from different sources.
    Medium,
    /// Strong convergence across sources.
    High,
    /// Overwhelming evidence from many sources.
    Critical,
}

impl EcosystemSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Compute ecosystem severity from evidence.
fn compute_severity(evidence: &[EcosystemEvidence]) -> EcosystemSeverity {
    let total_weight: u32 = evidence.iter().map(|e| e.weight).sum();
    let source_diversity = source_count(evidence);

    // Severity based on weight + source diversity.
    if total_weight >= 30 && source_diversity >= 4 {
        EcosystemSeverity::Critical
    } else if total_weight >= 20 && source_diversity >= 3 {
        EcosystemSeverity::High
    } else if total_weight >= 10 && source_diversity >= 2 {
        EcosystemSeverity::Medium
    } else {
        EcosystemSeverity::Low
    }
}

/// Compute ecosystem escalation points (bounded).
fn compute_escalation(evidence: &[EcosystemEvidence], recurrence_count: u32) -> u32 {
    let diversity = source_count(evidence) as u32;

    // Base escalation from source diversity.
    let base: u32 = if diversity >= 5 {
        15
    } else if diversity >= 4 {
        10
    } else if diversity >= 3 {
        6
    } else if diversity >= 2 {
        3
    } else {
        0
    };

    // Recurrence bonus: repeated patterns escalate slightly.
    // saturating_mul: recurrence_count is u32 and could (in pathological
    // long-running scenarios) be large enough that `* 2` overflows in debug.
    let recurrence_bonus = recurrence_count
        .saturating_mul(RECURRENCE_BONUS_PER)
        .min(MAX_RECURRENCE_BONUS);

    base.saturating_add(recurrence_bonus)
        .min(MAX_ECOSYSTEM_ESCALATION)
}

/// Count unique evidence sources.
fn source_count(evidence: &[EcosystemEvidence]) -> usize {
    let mut sources = HashSet::new();
    for e in evidence {
        sources.insert(e.source);
    }
    sources.len()
}

// ── Narrative Compression ──────────────────────────────────────

/// Generate a compressed, readable narrative from ecosystem evidence.
///
/// Rules:
/// - Compact: merge related actions into single sentences
/// - No repeated actor names
/// - Preserve evidence clarity
/// - Max MAX_NARRATIVE_LEN characters
fn generate_narrative(root: &str, evidence: &[EcosystemEvidence]) -> String {
    if evidence.is_empty() {
        return format!("No behavioral evidence for {root}.");
    }

    // Extract actor (filename) from root entity for readability.
    let actor = root
        .rsplit('\\')
        .next()
        .or_else(|| root.rsplit('/').next())
        .unwrap_or(root);

    let has = |src: EvidenceSource| evidence.iter().any(|e| e.source == src);
    let desc_for = |src: EvidenceSource| -> Option<&str> {
        evidence
            .iter()
            .find(|e| e.source == src)
            .map(|e| e.description.as_str())
    };

    let mut sentences: Vec<String> = Vec::new();

    // 1) Runtime + PLM combined: "PowerShell-launched unsigned process"
    let has_runtime = has(EvidenceSource::Runtime);
    let has_plm = has(EvidenceSource::Plm);

    if has_runtime && has_plm {
        let rt_desc = desc_for(EvidenceSource::Runtime).unwrap_or("Script activity detected");
        let plm_desc = desc_for(EvidenceSource::Plm).unwrap_or("suspicious process chain");
        sentences.push(format!("{rt_desc} via {plm_desc}"));
    } else if has_runtime {
        if let Some(d) = desc_for(EvidenceSource::Runtime) {
            sentences.push(d.to_string());
        }
    } else if has_plm {
        if let Some(d) = desc_for(EvidenceSource::Plm) {
            sentences.push(d.to_string());
        }
    }

    // 2) Persistence + ADS combined: "created persistence and alternate data streams"
    let has_persist = has(EvidenceSource::Persistence);
    let has_ads = has(EvidenceSource::Ads);

    if has_persist && has_ads {
        sentences.push("Created startup persistence and alternate data streams".into());
    } else if has_persist {
        sentences.push("Added startup persistence".into());
    } else if has_ads {
        sentences.push("Created alternate data streams".into());
    }

    // 3) Drift + Signer combined: "Behavioral drift with unsigned/signer mismatch"
    let has_drift = has(EvidenceSource::Drift);
    let has_signer = has(EvidenceSource::Signer);

    if has_drift && has_signer {
        sentences.push("Behavioral drift detected with unsigned or signer mismatch".into());
    } else if has_drift {
        sentences.push("Behavioral drift from established pattern".into());
    } else if has_signer {
        sentences.push("Unsigned or signer mismatch".into());
    }

    // 4) Trust graph (standalone, always specific).
    if has(EvidenceSource::TrustGraph) {
        if let Some(d) = desc_for(EvidenceSource::TrustGraph) {
            sentences.push(d.to_string());
        }
    }

    // 5) ARGUS (only if nothing else generated a sentence — avoid redundancy).
    if sentences.is_empty() {
        if let Some(d) = desc_for(EvidenceSource::Argus) {
            sentences.push(d.to_string());
        }
    }

    // Fallback.
    if sentences.is_empty() {
        if let Some(e) = evidence.first() {
            sentences.push(e.description.clone());
        }
    }

    // Prepend actor on first sentence for context.
    if let Some(first) = sentences.first_mut() {
        // Only prepend if the sentence doesn't already contain the actor.
        if !first.to_lowercase().contains(&actor.to_lowercase()) {
            *first = format!("{actor}: {first}");
        }
    }

    let mut joined = sentences.join(". ");
    if !joined.ends_with('.') {
        joined.push('.');
    }

    // Enforce max length.
    // Audit fix: `String::truncate` panics if the index isn't a UTF-8 char
    // boundary — a multi-byte char (non-ASCII file path / description) at
    // offset MAX_NARRATIVE_LEN-3 would crash. Step back to a boundary.
    if joined.len() > MAX_NARRATIVE_LEN {
        let mut cut = MAX_NARRATIVE_LEN - 3;
        while cut > 0 && !joined.is_char_boundary(cut) {
            cut -= 1;
        }
        joined.truncate(cut);
        joined.push_str("...");
    }

    joined
}

// ── Fingerprinting for Recurrence ──────────────────────────────

/// Behavioral fingerprint — identifies a pattern for recurrence detection.
///
/// ARCH-5 fix: uses filename + sorted evidence sources to prevent unrelated
/// files with the same name (e.g. different "setup.exe" files) from merging.
/// The source set captures the behavioral shape (what subsystems triggered).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EcosystemFingerprint {
    /// Normalized root entity (lowercase filename only).
    root_name: String,
    /// Sorted evidence sources — behavioral shape.
    sources: Vec<EvidenceSource>,
}

impl EcosystemFingerprint {
    fn from_ecosystem(eco: &BehavioralEcosystem) -> Self {
        let root_name = normalize_root(&eco.root_entity);
        let mut sources: Vec<EvidenceSource> = eco
            .evidence
            .iter()
            .map(|e| e.source)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        sources.sort_by_key(|s| *s as u8);
        Self { root_name, sources }
    }

    /// Partial match: same filename, any source overlap = potential recurrence.
    /// Returns true if fingerprints share the same root AND at least 2 sources in common.
    fn matches_partial(&self, other: &Self) -> bool {
        if self.root_name != other.root_name {
            return false;
        }
        let overlap = self
            .sources
            .iter()
            .filter(|s| other.sources.contains(s))
            .count();
        overlap >= 2
    }
}

fn normalize_root(root_entity: &str) -> String {
    root_entity
        .rsplit('\\')
        .next()
        .or_else(|| root_entity.rsplit('/').next())
        .unwrap_or(root_entity)
        .to_lowercase()
}

// ── Ecosystem Tracker ──────────────────────────────────────────

/// The ecosystem tracker — holds active ecosystems and recurrence state.
pub struct EcosystemTracker {
    ecosystems: Mutex<HashMap<String, BehavioralEcosystem>>,
    /// Fingerprints of expired ecosystems for recurrence detection.
    expired_fingerprints: Mutex<HashMap<EcosystemFingerprint, u32>>,
    /// Pruned ecosystem count (diagnostics).
    pruned_count: std::sync::atomic::AtomicU64,
}

impl EcosystemTracker {
    pub fn new() -> Self {
        Self {
            ecosystems: Mutex::new(HashMap::new()),
            expired_fingerprints: Mutex::new(HashMap::new()),
            pruned_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add evidence to an ecosystem (creates if new).
    pub fn add_evidence(&self, root_entity: &str, evidence: EcosystemEvidence) {
        let mut map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        let now_ts = chrono::Utc::now().timestamp();
        let now = Instant::now();

        // Check recurrence for new ecosystems.
        let _is_new = !map.contains_key(root_entity);

        let eco = map.entry(root_entity.to_string()).or_insert_with(|| {
            // Look up recurrence from expired fingerprints.
            let recurrence = 0u32; // Will be updated after first evidence.

            BehavioralEcosystem {
                id: uuid::Uuid::new_v4().to_string(),
                first_seen: now_ts,
                last_updated: now_ts,
                evidence: Vec::new(),
                severity: EcosystemSeverity::Low,
                escalation: 0,
                narrative: String::new(),
                root_entity: root_entity.to_string(),
                state: EcosystemState::Active,
                escalation_count: 0,
                recurrence_count: recurrence,
                timeline: Vec::new(),
                attribution: None,
                created_at: now,
                last_activity: now,
            }
        });

        // Dedup: skip if same source+description within DEDUP_WINDOW.
        // Audit fix: `now_ts - e.timestamp` is i64 subtraction and panics
        // on overflow in debug builds if a stored timestamp is extreme
        // (caller-supplied). Use saturating_sub.
        let dominated = eco.evidence.iter().any(|e| {
            e.source == evidence.source
                && e.description == evidence.description
                && now_ts.saturating_sub(e.timestamp).unsigned_abs() < DEDUP_WINDOW.as_secs()
        });
        if dominated {
            return;
        }

        // Stability: cap evidence items.
        if eco.evidence.len() >= MAX_EVIDENCE_PER_ECOSYSTEM {
            // Remove oldest low-weight evidence to make room.
            if let Some(idx) = eco
                .evidence
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.weight)
                .map(|(i, _)| i)
            {
                eco.evidence.remove(idx);
            }
        }

        let prev_severity = eco.severity;
        eco.last_updated = now_ts;
        eco.last_activity = now;
        eco.state = EcosystemState::Active;

        // Add timeline event.
        eco.timeline.push(TimelineEvent {
            timestamp: now_ts,
            description: evidence.description.clone(),
            source: evidence.source,
            weight: evidence.weight,
        });
        // Cap timeline at 30 events.
        if eco.timeline.len() > 30 {
            eco.timeline.drain(..eco.timeline.len() - 30);
        }

        eco.evidence.push(evidence);
        eco.severity = compute_severity(&eco.evidence);
        eco.escalation = compute_escalation(&eco.evidence, eco.recurrence_count);
        eco.narrative = generate_narrative(root_entity, &eco.evidence);

        // Track escalation count.
        if eco.severity > prev_severity {
            eco.escalation_count += 1;
        }

        // Check recurrence: runs when ecosystem has ≥2 sources and recurrence not yet set.
        // ARCH-5: uses partial fingerprint matching (same name + ≥2 common sources)
        // to prevent unrelated files with the same name from merging recurrence.
        if eco.recurrence_count == 0 && source_count(&eco.evidence) >= 2 {
            let fp = EcosystemFingerprint::from_ecosystem(eco);
            let fp_map = self
                .expired_fingerprints
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let best_match = fp_map
                .iter()
                .filter(|(k, _)| fp.matches_partial(k))
                .max_by_key(|(_, v)| *v)
                .map(|(_, &v)| v);
            if let Some(prev_count) = best_match {
                eco.recurrence_count = prev_count + 1;
                eco.escalation = compute_escalation(&eco.evidence, eco.recurrence_count);
            }
        }

        // Prune if too many ecosystems.
        if map.len() > MAX_ECOSYSTEMS {
            // Remove oldest expired/cooling ecosystem first, then oldest active.
            let remove_key = map
                .values()
                .filter(|e| e.state != EcosystemState::Active)
                .min_by_key(|e| e.last_updated)
                .or_else(|| map.values().min_by_key(|e| e.last_updated))
                .map(|e| e.root_entity.clone());

            if let Some(key) = remove_key {
                if let Some(removed) = map.remove(&key) {
                    self.record_fingerprint(&removed);
                }
            }
        }
    }

    /// Set convergence attribution for an ecosystem.
    pub fn set_attribution(&self, root_entity: &str, attr: ConvergenceAttribution) {
        let mut map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(eco) = map.get_mut(root_entity) {
            eco.attribution = Some(attr);
        }
    }

    /// Get ecosystem for a root entity.
    pub fn get(&self, root_entity: &str) -> Option<BehavioralEcosystem> {
        let map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        map.get(root_entity).cloned()
    }

    /// Get all active suspicious ecosystems (severity >= Medium).
    pub fn suspicious_ecosystems(&self) -> Vec<BehavioralEcosystem> {
        let map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        let mut result: Vec<_> = map
            .values()
            .filter(|e| e.severity >= EcosystemSeverity::Medium)
            .cloned()
            .collect();
        result.sort_by(|a, b| b.escalation.cmp(&a.escalation));
        result.truncate(10);
        result
    }

    /// Update lifecycle states and expire old ecosystems.
    pub fn expire(&self) {
        self.expire_at(Instant::now());
    }

    /// Testable core of [`expire`]: `now` is the reference instant used to
    /// compute idle time. Production always passes `Instant::now()`.
    ///
    /// Tests pass a *future* instant (`Instant::now() + idle`) instead of
    /// pushing `last_activity` into the past with `Instant::checked_sub`.
    /// Adding a `Duration` to an `Instant` can never underflow the monotonic
    /// clock, so aging is deterministic regardless of machine uptime — the
    /// subtraction approach silently no-ops on a freshly-booted box (the
    /// monotonic epoch is < the subtracted duration), which is exactly what
    /// made the aging tests flaky.
    fn expire_at(&self, now: Instant) {
        let mut map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());

        // Phase 1: update states.
        for eco in map.values_mut() {
            // saturating: if `now` precedes `last_activity` (shouldn't happen
            // for real callers), treat idle as zero rather than panicking.
            let idle = now.saturating_duration_since(eco.last_activity);
            if idle >= ECOSYSTEM_TTL {
                eco.state = EcosystemState::Expired;
            } else if idle >= COOLING_THRESHOLD && eco.state == EcosystemState::Active {
                eco.state = EcosystemState::Cooling;
            }
        }

        // Phase 2: remove expired, record fingerprints.
        let expired_keys: Vec<String> = map
            .iter()
            .filter(|(_, e)| e.state == EcosystemState::Expired)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired_keys {
            if let Some(removed) = map.remove(key) {
                self.record_fingerprint_inner(&removed);
                self.pruned_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Record fingerprint of an expired ecosystem for recurrence detection.
    fn record_fingerprint(&self, eco: &BehavioralEcosystem) {
        // Only track fingerprints for suspicious+ ecosystems.
        if eco.severity < EcosystemSeverity::Medium {
            return;
        }

        let mut fp_map = self
            .expired_fingerprints
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fp = EcosystemFingerprint::from_ecosystem(eco);
        let count = fp_map.entry(fp).or_insert(0);
        *count = count.saturating_add(1);

        // Cap fingerprints.
        if fp_map.len() > MAX_FINGERPRINTS {
            // Remove least-recurring.
            if let Some(key) = fp_map
                .iter()
                .min_by_key(|(_, v)| *v)
                .map(|(k, _)| k.clone())
            {
                fp_map.remove(&key);
            }
        }
    }

    /// Inner version that doesn't re-lock expired_fingerprints.
    fn record_fingerprint_inner(&self, eco: &BehavioralEcosystem) {
        if eco.severity < EcosystemSeverity::Medium {
            return;
        }

        // R3-16: blocking lock so fingerprints are not silently dropped under
        // contention. Recurrence detection only works if every expiry is
        // recorded; lock hold time is microseconds (HashMap ops only).
        let mut fp_map = self
            .expired_fingerprints
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let fp = EcosystemFingerprint::from_ecosystem(eco);
        let count = fp_map.entry(fp).or_insert(0);
        *count = count.saturating_add(1);

        if fp_map.len() > MAX_FINGERPRINTS {
            if let Some(key) = fp_map
                .iter()
                .min_by_key(|(_, v)| *v)
                .map(|(k, _)| k.clone())
            {
                fp_map.remove(&key);
            }
        }
    }

    /// Extended diagnostics summary.
    pub fn diagnostics(&self) -> serde_json::Value {
        let map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        let total = map.len();
        let active = map
            .values()
            .filter(|e| e.state == EcosystemState::Active)
            .count();
        let cooling = map
            .values()
            .filter(|e| e.state == EcosystemState::Cooling)
            .count();
        let suspicious = map
            .values()
            .filter(|e| e.severity >= EcosystemSeverity::Medium)
            .count();
        let high = map
            .values()
            .filter(|e| e.severity >= EcosystemSeverity::High)
            .count();
        let critical = map
            .values()
            .filter(|e| e.severity >= EcosystemSeverity::Critical)
            .count();
        let recurring = map.values().filter(|e| e.recurrence_count > 0).count();
        let pruned = self.pruned_count.load(std::sync::atomic::Ordering::Relaxed);

        // Average lifetime of active ecosystems.
        let avg_lifetime_min = if total > 0 {
            let total_secs: u64 = map.values().map(|e| e.created_at.elapsed().as_secs()).sum();
            total_secs / total as u64 / 60
        } else {
            0
        };

        // Recurrence escalations total.
        let recurrence_total: u32 = map.values().map(|e| e.recurrence_count).sum();

        let recent: Vec<serde_json::Value> = map
            .values()
            .filter(|e| e.severity >= EcosystemSeverity::Medium)
            .take(5)
            .map(|e| {
                let timeline_recent: Vec<serde_json::Value> = e
                    .timeline
                    .iter()
                    .rev()
                    .take(5)
                    .map(|t| {
                        serde_json::json!({
                            "timestamp": t.timestamp,
                            "description": t.description,
                            "source": t.source.label(),
                            "weight": t.weight,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "root": e.root_entity,
                    "severity": e.severity.label(),
                    "state": format!("{:?}", e.state),
                    "escalation": e.escalation,
                    "escalation_count": e.escalation_count,
                    "recurrence_count": e.recurrence_count,
                    "evidence_count": e.evidence.len(),
                    "narrative": e.narrative,
                    "attribution": e.attribution,
                    "timeline": timeline_recent,
                })
            })
            .collect();

        serde_json::json!({
            "active_ecosystems": total,
            "active": active,
            "cooling": cooling,
            "suspicious": suspicious,
            "high_severity": high,
            "critical": critical,
            "recurring": recurring,
            "pruned": pruned,
            "average_lifetime_minutes": avg_lifetime_min,
            "recurrence_escalations": recurrence_total,
            "recent_suspicious": recent,
        })
    }
}

/// Create an ARGUS finding from ecosystem analysis.
pub fn ecosystem_finding(eco: &BehavioralEcosystem) -> Option<argus::Finding> {
    if eco.escalation == 0 {
        return None;
    }

    let severity = match eco.severity {
        EcosystemSeverity::Critical => argus::verdict::Severity::Critical,
        EcosystemSeverity::High => argus::verdict::Severity::High,
        EcosystemSeverity::Medium => argus::verdict::Severity::Medium,
        EcosystemSeverity::Low => return None,
    };

    let mut desc = format!("Behavioral ecosystem: {}", eco.narrative);
    if eco.recurrence_count > 0 {
        desc.push_str(&format!(" (recurring: {}x)", eco.recurrence_count));
    }

    Some(argus::Finding {
        layer: argus::verdict::Layer::Context,
        severity,
        weight: eco.escalation,
        description: desc,
        technical_detail: Some(format!(
            "sources={} evidence={} severity={:?} state={:?} escalation={} recurrence={} escalation_events={}",
            source_count(&eco.evidence),
            eco.evidence.len(),
            eco.severity,
            eco.state,
            eco.escalation,
            eco.recurrence_count,
            eco.escalation_count,
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(src: EvidenceSource, desc: &str, weight: u32) -> EcosystemEvidence {
        EcosystemEvidence {
            source: src,
            timestamp: chrono::Utc::now().timestamp(),
            description: desc.into(),
            weight,
        }
    }

    // ── Basic lifecycle ────────────────────────────

    #[test]
    fn single_source_is_low() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence(
            "test.exe",
            ev(EvidenceSource::Argus, "Suspicious imports", 5),
        );
        let eco = tracker.get("test.exe").unwrap();
        assert_eq!(eco.severity, EcosystemSeverity::Low);
        assert_eq!(eco.escalation, 0);
        assert_eq!(eco.state, EcosystemState::Active);
    }

    #[test]
    fn multi_source_escalates() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("evil.exe", ev(EvidenceSource::Argus, "Suspicious PE", 10));
        tracker.add_evidence("evil.exe", ev(EvidenceSource::Plm, "Word macro chain", 8));
        tracker.add_evidence("evil.exe", ev(EvidenceSource::Persistence, "Run key", 8));
        let eco = tracker.get("evil.exe").unwrap();
        assert!(eco.severity >= EcosystemSeverity::High);
        assert!(eco.escalation >= 6);
        assert_eq!(eco.escalation_count, 2); // Low→Medium→High
    }

    #[test]
    fn five_source_critical() {
        let tracker = EcosystemTracker::new();
        for (src, desc, w) in [
            (EvidenceSource::Argus, "Suspicious imports", 10),
            (EvidenceSource::Plm, "Suspicious chain", 8),
            (EvidenceSource::Persistence, "Run key added", 8),
            (EvidenceSource::Ads, "Hidden stream", 5),
            (EvidenceSource::Drift, "Chain mutated", 6),
        ] {
            tracker.add_evidence("payload.exe", ev(src, desc, w));
        }
        let eco = tracker.get("payload.exe").unwrap();
        assert_eq!(eco.severity, EcosystemSeverity::Critical);
        assert!(eco.escalation >= 15);
    }

    #[test]
    fn escalation_bounded() {
        let tracker = EcosystemTracker::new();
        for i in 0..10 {
            let src = match i % 6 {
                0 => EvidenceSource::Argus,
                1 => EvidenceSource::Plm,
                2 => EvidenceSource::Persistence,
                3 => EvidenceSource::Ads,
                4 => EvidenceSource::Drift,
                _ => EvidenceSource::Signer,
            };
            tracker.add_evidence("flood.exe", ev(src, &format!("Evidence {i}"), 10));
        }
        let eco = tracker.get("flood.exe").unwrap();
        assert!(eco.escalation <= MAX_ECOSYSTEM_ESCALATION);
    }

    // ── Ecosystem aging ────────────────────────────

    #[test]
    fn ecosystem_starts_active() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("x.exe", ev(EvidenceSource::Argus, "test", 5));
        let eco = tracker.get("x.exe").unwrap();
        assert_eq!(eco.state, EcosystemState::Active);
    }

    #[test]
    fn expire_removes_old() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("old.exe", ev(EvidenceSource::Argus, "old", 5));
        // Evaluate aging as if 2 hr have passed (past ECOSYSTEM_TTL of 1 hr)
        // via a future reference instant — robust regardless of uptime.
        let later = Instant::now() + Duration::from_secs(7200);
        tracker.expire_at(later);
        assert!(tracker.get("old.exe").is_none());
    }

    #[test]
    fn cooling_transition() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("cool.exe", ev(EvidenceSource::Argus, "test", 5));
        // Evaluate aging as if 15 min have passed: past COOLING_THRESHOLD
        // (10 min) but under ECOSYSTEM_TTL (1 hr). Use a future reference
        // instant instead of back-dating last_activity, so this is robust on
        // any machine uptime (Instant + Duration never underflows).
        let later = Instant::now() + Duration::from_secs(900);
        tracker.expire_at(later);
        let eco = tracker.get("cool.exe").unwrap();
        assert_eq!(eco.state, EcosystemState::Cooling);
    }

    // ── Deduplication ──────────────────────────────

    #[test]
    fn dedup_same_source_and_description() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("dup.exe", ev(EvidenceSource::Argus, "Same finding", 5));
        tracker.add_evidence("dup.exe", ev(EvidenceSource::Argus, "Same finding", 5));
        tracker.add_evidence("dup.exe", ev(EvidenceSource::Argus, "Same finding", 5));
        let eco = tracker.get("dup.exe").unwrap();
        assert_eq!(eco.evidence.len(), 1); // Deduped.
    }

    #[test]
    fn dedup_allows_different_source() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("x.exe", ev(EvidenceSource::Argus, "Finding", 5));
        tracker.add_evidence("x.exe", ev(EvidenceSource::Plm, "Finding", 5));
        let eco = tracker.get("x.exe").unwrap();
        assert_eq!(eco.evidence.len(), 2);
    }

    // ── Evidence cap ───────────────────────────────

    #[test]
    fn evidence_capped_at_max() {
        let tracker = EcosystemTracker::new();
        for i in 0..60 {
            tracker.add_evidence(
                "big.exe",
                EcosystemEvidence {
                    source: EvidenceSource::Argus,
                    timestamp: i, // Different timestamps bypass dedup.
                    description: format!("Finding {i}"),
                    weight: 5,
                },
            );
        }
        let eco = tracker.get("big.exe").unwrap();
        assert!(eco.evidence.len() <= MAX_EVIDENCE_PER_ECOSYSTEM);
    }

    // ── Narrative compression ──────────────────────

    #[test]
    fn narrative_compressed_persistence_and_ads() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("temp.exe", ev(EvidenceSource::Persistence, "Run key", 8));
        tracker.add_evidence("temp.exe", ev(EvidenceSource::Ads, "Zone.Identifier", 5));
        let eco = tracker.get("temp.exe").unwrap();
        assert!(eco.narrative.contains("persistence and alternate data"));
    }

    #[test]
    fn narrative_compressed_drift_and_signer() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("x.exe", ev(EvidenceSource::Drift, "Changed signer", 6));
        tracker.add_evidence("x.exe", ev(EvidenceSource::Signer, "Unsigned", 5));
        let eco = tracker.get("x.exe").unwrap();
        assert!(eco.narrative.contains("drift") && eco.narrative.contains("signer"));
        // Should be one sentence, not two.
        assert!(
            !eco.narrative
                .contains("Behavioral drift")
                .then(|| eco.narrative.matches('.').count())
                .unwrap_or(0)
                > 2
        );
    }

    #[test]
    fn narrative_includes_actor() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence(
            r"C:\Users\test\Downloads\payload.exe",
            ev(EvidenceSource::Argus, "Suspicious imports", 10),
        );
        let eco = tracker.get(r"C:\Users\test\Downloads\payload.exe").unwrap();
        assert!(eco.narrative.contains("payload.exe"));
    }

    #[test]
    fn narrative_max_length_enforced() {
        let tracker = EcosystemTracker::new();
        let long_desc = "x".repeat(600);
        tracker.add_evidence("long.exe", ev(EvidenceSource::Argus, &long_desc, 5));
        let eco = tracker.get("long.exe").unwrap();
        assert!(eco.narrative.len() <= MAX_NARRATIVE_LEN + 3); // +3 for "..."
    }

    // ── Timeline ───────────────────────────────────

    #[test]
    fn timeline_ordered() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("tl.exe", ev(EvidenceSource::Runtime, "Script detected", 8));
        tracker.add_evidence("tl.exe", ev(EvidenceSource::Persistence, "Run key", 8));
        tracker.add_evidence("tl.exe", ev(EvidenceSource::Ads, "Hidden stream", 5));
        let eco = tracker.get("tl.exe").unwrap();
        assert_eq!(eco.timeline.len(), 3);
        // Chronological order.
        for w in eco.timeline.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp);
        }
    }

    #[test]
    fn timeline_capped() {
        let tracker = EcosystemTracker::new();
        for i in 0..40 {
            tracker.add_evidence(
                "tl2.exe",
                EcosystemEvidence {
                    source: EvidenceSource::Argus,
                    timestamp: i,
                    description: format!("Event {i}"),
                    weight: 1,
                },
            );
        }
        let eco = tracker.get("tl2.exe").unwrap();
        assert!(eco.timeline.len() <= 30);
    }

    // ── Attribution ────────────────────────────────

    #[test]
    fn attribution_stored() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("attr.exe", ev(EvidenceSource::Argus, "Test", 10));
        tracker.set_attribution(
            "attr.exe",
            ConvergenceAttribution {
                base_argus: 58,
                trust_adjustment: -5,
                drift_escalation: 8,
                ecosystem_escalation: 15,
                recurrence_bonus: 0,
                final_convergence: 76,
            },
        );
        let eco = tracker.get("attr.exe").unwrap();
        let attr = eco.attribution.unwrap();
        assert_eq!(attr.base_argus, 58);
        assert_eq!(attr.final_convergence, 76);
    }

    // ── Recurrence ─────────────────────────────────

    #[test]
    fn recurrence_detected_after_expiration() {
        let tracker = EcosystemTracker::new();
        // Create initial ecosystem with enough severity for fingerprint.
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Argus, "Suspicious", 10));
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Plm, "Chain", 8));
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Persistence, "Run key", 8));

        // Expire it by evaluating aging 2 hr in the future (past TTL) via a
        // future reference instant — robust regardless of uptime.
        let later = Instant::now() + Duration::from_secs(7200);
        tracker.expire_at(later);
        assert!(tracker.get("recur.exe").is_none());

        // Same pattern recurs.
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Argus, "Suspicious", 10));
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Plm, "Chain", 8));
        tracker.add_evidence("recur.exe", ev(EvidenceSource::Persistence, "Run key", 8));

        let eco = tracker.get("recur.exe").unwrap();
        assert!(eco.recurrence_count >= 1);
        // Recurrence adds escalation bonus.
        assert!(eco.escalation > 6); // Base 6 + recurrence bonus.
    }

    #[test]
    fn recurrence_bonus_bounded() {
        let tracker = EcosystemTracker::new();
        // Simulate many recurrences via fingerprint map.
        {
            let mut fp_map = tracker.expired_fingerprints.lock().unwrap();
            let fp = EcosystemFingerprint {
                root_name: "bounded.exe".into(),
                sources: vec![EvidenceSource::Argus, EvidenceSource::Plm],
            };
            fp_map.insert(fp, 100); // Many prior recurrences.
        }
        tracker.add_evidence("bounded.exe", ev(EvidenceSource::Argus, "Test", 10));
        tracker.add_evidence("bounded.exe", ev(EvidenceSource::Plm, "Chain", 8));
        let eco = tracker.get("bounded.exe").unwrap();
        // Escalation should not exceed MAX.
        assert!(eco.escalation <= MAX_ECOSYSTEM_ESCALATION);
    }

    // ── Finding generation ─────────────────────────

    #[test]
    fn finding_only_for_medium_plus() {
        let low = BehavioralEcosystem {
            id: "1".into(),
            first_seen: 0,
            last_updated: 0,
            evidence: vec![],
            severity: EcosystemSeverity::Low,
            escalation: 0,
            narrative: String::new(),
            root_entity: "x".into(),
            state: EcosystemState::Active,
            escalation_count: 0,
            recurrence_count: 0,
            timeline: vec![],
            attribution: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert!(ecosystem_finding(&low).is_none());

        let high = BehavioralEcosystem {
            id: "2".into(),
            first_seen: 0,
            last_updated: 0,
            evidence: vec![],
            severity: EcosystemSeverity::High,
            escalation: 10,
            narrative: "test".into(),
            root_entity: "y".into(),
            state: EcosystemState::Active,
            escalation_count: 1,
            recurrence_count: 0,
            timeline: vec![],
            attribution: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let f = ecosystem_finding(&high);
        assert!(f.is_some());
        assert_eq!(f.unwrap().weight, 10);
    }

    #[test]
    fn finding_mentions_recurrence() {
        let eco = BehavioralEcosystem {
            id: "3".into(),
            first_seen: 0,
            last_updated: 0,
            evidence: vec![],
            severity: EcosystemSeverity::High,
            escalation: 10,
            narrative: "test".into(),
            root_entity: "y".into(),
            state: EcosystemState::Active,
            escalation_count: 1,
            recurrence_count: 3,
            timeline: vec![],
            attribution: None,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let f = ecosystem_finding(&eco).unwrap();
        assert!(f.description.contains("recurring: 3x"));
    }

    // ── Diagnostics ────────────────────────────────

    #[test]
    fn diagnostics_includes_new_fields() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("diag.exe", ev(EvidenceSource::Argus, "test", 5));
        let d = tracker.diagnostics();
        assert_eq!(d["active_ecosystems"], 1);
        assert_eq!(d["active"], 1);
        assert_eq!(d["cooling"], 0);
        assert!(d.get("pruned").is_some());
        assert!(d.get("recurring").is_some());
        assert!(d.get("average_lifetime_minutes").is_some());
    }

    // ── Pruning ────────────────────────────────────

    #[test]
    fn pruning_prefers_cooling_over_active() {
        let tracker = EcosystemTracker::new();
        // Fill to MAX + 1.
        for i in 0..MAX_ECOSYSTEMS {
            tracker.add_evidence(
                &format!("fill_{i}.exe"),
                ev(EvidenceSource::Argus, "fill", 1),
            );
        }
        // Mark one as cooling (pruning prefers non-Active victims). State is
        // set directly; no last_activity back-dating needed.
        {
            let mut map = tracker.ecosystems.lock().unwrap();
            if let Some(eco) = map.get_mut("fill_0.exe") {
                eco.state = EcosystemState::Cooling;
            }
        }
        // Add one more — should prune the cooling one.
        tracker.add_evidence("new.exe", ev(EvidenceSource::Argus, "new", 5));

        let map = tracker.ecosystems.lock().unwrap();
        assert!(map.len() <= MAX_ECOSYSTEMS);
    }
}

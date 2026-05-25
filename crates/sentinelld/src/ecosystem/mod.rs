//! Behavioral Ecosystem Convergence — ASTRA coherent behavioral analysis.
//!
//! Evaluates behavioral ECOSYSTEMS, not isolated events.
//! Combines evidence from all ASTRA subsystems within time windows:
//!   ARGUS findings + PLM lineage + persistence + ADS + trust + drift + runtime
//!
//! Produces human-readable narratives that explain WHY a behavior pattern
//! is suspicious — not just THAT it scored N/100.
//!
//! Safety: ecosystems shape convergence, never replace evidence.
//! Signatures remain authoritative. Trust never suppresses known malware.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum active ecosystems tracked simultaneously.
const MAX_ECOSYSTEMS: usize = 100;
/// Ecosystem expires after this duration without new evidence.
const ECOSYSTEM_TTL: Duration = Duration::from_secs(3600); // 1 hour
/// Short correlation window for tightly-coupled events (future use).
#[allow(dead_code)]
const SHORT_WINDOW: Duration = Duration::from_secs(30);
/// Medium correlation window (future use).
#[allow(dead_code)]
const MEDIUM_WINDOW: Duration = Duration::from_secs(300); // 5 min
/// Max ecosystem escalation points (bounded).
const MAX_ECOSYSTEM_ESCALATION: u32 = 25;

/// A behavioral ecosystem — correlated evidence cluster.
#[derive(Debug, Clone, Serialize)]
pub struct BehavioralEcosystem {
    /// Unique ecosystem ID.
    pub id: String,
    /// When the ecosystem was first observed.
    pub first_seen: i64,
    /// When the last evidence was added.
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
    /// Whether this ecosystem is still active (receiving evidence).
    #[serde(skip)]
    pub last_activity: Instant,
}

/// A piece of evidence in an ecosystem.
#[derive(Debug, Clone, Serialize)]
pub struct EcosystemEvidence {
    /// Evidence source system.
    pub source: EvidenceSource,
    /// Timestamp.
    pub timestamp: i64,
    /// Human-readable description.
    pub description: String,
    /// Suspicion contribution.
    pub weight: u32,
}

/// Where the evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    let source_diversity = {
        let mut sources = std::collections::HashSet::new();
        for e in evidence { sources.insert(std::mem::discriminant(&e.source)); }
        sources.len()
    };

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
fn compute_escalation(evidence: &[EcosystemEvidence]) -> u32 {
    let source_diversity = {
        let mut sources = std::collections::HashSet::new();
        for e in evidence { sources.insert(std::mem::discriminant(&e.source)); }
        sources.len() as u32
    };

    // Escalation = diversity bonus (evidence from N different systems).
    // Max 25 points. Bounded. Additive to ARGUS, not replacing.
    let base = if source_diversity >= 5 { 15 }
        else if source_diversity >= 4 { 10 }
        else if source_diversity >= 3 { 6 }
        else if source_diversity >= 2 { 3 }
        else { 0 };

    base.min(MAX_ECOSYSTEM_ESCALATION)
}

/// Generate a human-readable narrative from ecosystem evidence.
fn generate_narrative(root: &str, evidence: &[EcosystemEvidence]) -> String {
    if evidence.is_empty() {
        return format!("No behavioral evidence for {root}.");
    }

    let mut parts: Vec<String> = Vec::new();

    // Group by source for readable flow.
    let has = |src: EvidenceSource| evidence.iter().any(|e| e.source == src);

    if has(EvidenceSource::Runtime) {
        if let Some(e) = evidence.iter().find(|e| e.source == EvidenceSource::Runtime) {
            parts.push(e.description.clone());
        }
    }
    if has(EvidenceSource::Plm) {
        if let Some(e) = evidence.iter().find(|e| e.source == EvidenceSource::Plm) {
            parts.push(e.description.clone());
        }
    }
    if has(EvidenceSource::Persistence) {
        parts.push("Added startup persistence".into());
    }
    if has(EvidenceSource::Ads) {
        parts.push("Created alternate data streams".into());
    }
    if has(EvidenceSource::Drift) {
        parts.push("Behavioral drift detected from established pattern".into());
    }
    if has(EvidenceSource::Signer) {
        parts.push("Unsigned or signer mismatch".into());
    }
    if has(EvidenceSource::TrustGraph) {
        if let Some(e) = evidence.iter().find(|e| e.source == EvidenceSource::TrustGraph) {
            parts.push(e.description.clone());
        }
    }

    if parts.is_empty() {
        if let Some(e) = evidence.first() {
            parts.push(e.description.clone());
        }
    }

    let joined = parts.join(". ");
    if joined.ends_with('.') { joined } else { format!("{joined}.") }
}

/// The ecosystem tracker — holds active ecosystems.
pub struct EcosystemTracker {
    ecosystems: Mutex<HashMap<String, BehavioralEcosystem>>,
}

impl EcosystemTracker {
    pub fn new() -> Self {
        Self {
            ecosystems: Mutex::new(HashMap::new()),
        }
    }

    /// Add evidence to an ecosystem (creates if new).
    pub fn add_evidence(&self, root_entity: &str, evidence: EcosystemEvidence) {
        let mut map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        let now_ts = chrono::Utc::now().timestamp();

        let eco = map.entry(root_entity.to_string()).or_insert_with(|| {
            BehavioralEcosystem {
                id: uuid::Uuid::new_v4().to_string(),
                first_seen: now_ts,
                last_updated: now_ts,
                evidence: Vec::new(),
                severity: EcosystemSeverity::Low,
                escalation: 0,
                narrative: String::new(),
                root_entity: root_entity.to_string(),
                last_activity: Instant::now(),
            }
        });

        eco.last_updated = now_ts;
        eco.last_activity = Instant::now();
        eco.evidence.push(evidence);
        eco.severity = compute_severity(&eco.evidence);
        eco.escalation = compute_escalation(&eco.evidence);
        eco.narrative = generate_narrative(root_entity, &eco.evidence);

        // Prune if too many ecosystems.
        if map.len() > MAX_ECOSYSTEMS {
            let oldest = map.values()
                .min_by_key(|e| e.last_updated)
                .map(|e| e.root_entity.clone());
            if let Some(key) = oldest {
                map.remove(&key);
            }
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
        let mut result: Vec<_> = map.values()
            .filter(|e| e.severity >= EcosystemSeverity::Medium)
            .cloned()
            .collect();
        result.sort_by(|a, b| b.escalation.cmp(&a.escalation));
        result.truncate(10);
        result
    }

    /// Expire old ecosystems.
    pub fn expire(&self) {
        let mut map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, e| e.last_activity.elapsed() < ECOSYSTEM_TTL);
    }

    /// Diagnostics summary.
    pub fn diagnostics(&self) -> serde_json::Value {
        let map = self.ecosystems.lock().unwrap_or_else(|e| e.into_inner());
        let total = map.len();
        let suspicious = map.values().filter(|e| e.severity >= EcosystemSeverity::Medium).count();
        let high = map.values().filter(|e| e.severity >= EcosystemSeverity::High).count();

        let recent: Vec<serde_json::Value> = map.values()
            .filter(|e| e.severity >= EcosystemSeverity::Medium)
            .take(5)
            .map(|e| serde_json::json!({
                "root": e.root_entity,
                "severity": e.severity.label(),
                "escalation": e.escalation,
                "evidence_count": e.evidence.len(),
                "narrative": e.narrative,
            }))
            .collect();

        serde_json::json!({
            "active_ecosystems": total,
            "suspicious": suspicious,
            "high_severity": high,
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

    Some(argus::Finding {
        layer: argus::verdict::Layer::Context,
        severity,
        weight: eco.escalation,
        description: format!("Behavioral ecosystem: {}", eco.narrative),
        technical_detail: Some(format!(
            "sources={} evidence={} severity={:?} escalation={}",
            eco.evidence.iter().map(|e| e.source.label()).collect::<std::collections::HashSet<_>>().len(),
            eco.evidence.len(),
            eco.severity,
            eco.escalation,
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ecosystem_is_low() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("test.exe", EcosystemEvidence {
            source: EvidenceSource::Argus,
            timestamp: 0,
            description: "Suspicious imports".into(),
            weight: 5,
        });
        let eco = tracker.get("test.exe").unwrap();
        assert_eq!(eco.severity, EcosystemSeverity::Low);
        assert_eq!(eco.escalation, 0); // Only 1 source.
    }

    #[test]
    fn multi_source_escalates() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("evil.exe", EcosystemEvidence {
            source: EvidenceSource::Argus, timestamp: 0,
            description: "Suspicious PE structure".into(), weight: 10,
        });
        tracker.add_evidence("evil.exe", EcosystemEvidence {
            source: EvidenceSource::Plm, timestamp: 0,
            description: "Spawned by Word macro chain".into(), weight: 8,
        });
        tracker.add_evidence("evil.exe", EcosystemEvidence {
            source: EvidenceSource::Persistence, timestamp: 0,
            description: "Added Run key".into(), weight: 8,
        });
        let eco = tracker.get("evil.exe").unwrap();
        assert!(eco.severity >= EcosystemSeverity::High);
        assert!(eco.escalation >= 6);
    }

    #[test]
    fn four_source_critical() {
        let tracker = EcosystemTracker::new();
        for (src, desc, w) in [
            (EvidenceSource::Argus, "Suspicious imports", 10),
            (EvidenceSource::Plm, "Suspicious chain", 8),
            (EvidenceSource::Persistence, "Run key added", 8),
            (EvidenceSource::Ads, "Hidden stream", 5),
            (EvidenceSource::Drift, "Chain mutated", 6),
        ] {
            tracker.add_evidence("payload.exe", EcosystemEvidence {
                source: src, timestamp: 0, description: desc.into(), weight: w,
            });
        }
        let eco = tracker.get("payload.exe").unwrap();
        assert_eq!(eco.severity, EcosystemSeverity::Critical);
        assert!(eco.escalation >= 15);
    }

    #[test]
    fn narrative_is_readable() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("temp.exe", EcosystemEvidence {
            source: EvidenceSource::Runtime, timestamp: 0,
            description: "Encoded PowerShell command detected".into(), weight: 8,
        });
        tracker.add_evidence("temp.exe", EcosystemEvidence {
            source: EvidenceSource::Persistence, timestamp: 0,
            description: "Startup entry created".into(), weight: 8,
        });
        let eco = tracker.get("temp.exe").unwrap();
        assert!(eco.narrative.contains("Encoded PowerShell"));
        assert!(eco.narrative.contains("persistence"));
    }

    #[test]
    fn escalation_bounded() {
        let tracker = EcosystemTracker::new();
        for i in 0..10 {
            tracker.add_evidence("flood.exe", EcosystemEvidence {
                source: match i % 6 {
                    0 => EvidenceSource::Argus,
                    1 => EvidenceSource::Plm,
                    2 => EvidenceSource::Persistence,
                    3 => EvidenceSource::Ads,
                    4 => EvidenceSource::Drift,
                    _ => EvidenceSource::Signer,
                },
                timestamp: 0,
                description: format!("Evidence {i}"),
                weight: 10,
            });
        }
        let eco = tracker.get("flood.exe").unwrap();
        assert!(eco.escalation <= MAX_ECOSYSTEM_ESCALATION);
    }

    #[test]
    fn ecosystem_finding_only_for_medium_plus() {
        let low = BehavioralEcosystem {
            id: "1".into(), first_seen: 0, last_updated: 0,
            evidence: vec![], severity: EcosystemSeverity::Low,
            escalation: 0, narrative: String::new(),
            root_entity: "x".into(), last_activity: Instant::now(),
        };
        assert!(ecosystem_finding(&low).is_none());

        let high = BehavioralEcosystem {
            id: "2".into(), first_seen: 0, last_updated: 0,
            evidence: vec![], severity: EcosystemSeverity::High,
            escalation: 10, narrative: "test".into(),
            root_entity: "y".into(), last_activity: Instant::now(),
        };
        let f = ecosystem_finding(&high);
        assert!(f.is_some());
        assert_eq!(f.unwrap().weight, 10);
    }

    #[test]
    fn diagnostics_json() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("a.exe", EcosystemEvidence {
            source: EvidenceSource::Argus, timestamp: 0,
            description: "test".into(), weight: 5,
        });
        let d = tracker.diagnostics();
        assert_eq!(d["active_ecosystems"], 1);
    }

    #[test]
    fn expire_removes_old() {
        let tracker = EcosystemTracker::new();
        tracker.add_evidence("old.exe", EcosystemEvidence {
            source: EvidenceSource::Argus, timestamp: 0,
            description: "old".into(), weight: 5,
        });
        // Manually age the ecosystem.
        {
            let mut map = tracker.ecosystems.lock().unwrap();
            if let Some(eco) = map.get_mut("old.exe") {
                eco.last_activity = Instant::now() - Duration::from_secs(7200); // 2 hours ago.
            }
        }
        tracker.expire();
        assert!(tracker.get("old.exe").is_none());
    }
}

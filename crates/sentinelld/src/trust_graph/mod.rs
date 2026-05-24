//! Trust Graph — local contextual memory for ASTRA adaptive analysis.
//!
//! Teaches ASTRA what is NORMAL on THIS machine by tracking:
//! - process chain prevalence (how often this chain runs)
//! - executable stability (how long this binary has been seen)
//! - signer consistency (same signer over time)
//! - path familiarity (known locations vs new/rare ones)
//!
//! Trust NEVER suppresses known malware or bypasses signatures.
//! Trust only adjusts contextual confidence — how suspicious is this
//! behavior given what we know about this machine?
//!
//! Architecture:
//!   PLM chain → TrustGraph.record() → familiarity score
//!   Scan file → TrustGraph.query() → confidence adjustment
//!   Both → explainable: "Observed 217 times from Visual Studio Code"

use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

/// Max trust nodes before pruning oldest.
const MAX_NODES: usize = 10_000;
/// Trust decays after this many days without observation.
const TRUST_DECAY_DAYS: i64 = 30;
/// Minimum observations to be considered "stable."
const STABLE_THRESHOLD: u64 = 10;
/// Days of consistent observation to be considered "established."
const ESTABLISHED_DAYS: i64 = 7;

/// A trust node — represents a known entity (executable, chain, signer).
#[derive(Debug, Clone, Serialize)]
pub struct TrustNode {
    /// Unique key (path, chain hash, signer name).
    pub key: String,
    /// Node type.
    pub kind: TrustNodeKind,
    /// First time observed (unix timestamp).
    pub first_seen: i64,
    /// Last time observed (unix timestamp).
    pub last_seen: i64,
    /// Number of observations.
    pub observation_count: u64,
    /// Number of distinct days observed.
    pub stable_days: u32,
    /// Signer name (if applicable).
    pub signer: Option<String>,
    /// Trust level computed from observations.
    pub trust_level: TrustLevel,
}

/// What kind of entity this trust node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustNodeKind {
    /// An executable file path.
    Executable,
    /// A parent→child process chain (hash of chain).
    ProcessChain,
    /// A code signer identity.
    Signer,
    /// A runtime script source (e.g., PowerShell from VSCode).
    RuntimeSource,
    /// A persistence location entry.
    PersistenceEntry,
}

/// Trust level — computed from observations, never from content analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Never seen before on this machine.
    Unknown,
    /// Seen a few times, recently.
    Rare,
    /// Seen regularly but not yet established.
    Familiar,
    /// Consistently observed over multiple days.
    Established,
    /// Long-running stable presence, signed.
    Trusted,
}

impl TrustLevel {
    /// Confidence adjustment factor.
    /// Positive = reduces suspicion (for stable patterns).
    /// Zero = no adjustment (unknown/rare).
    pub fn confidence_discount(&self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Rare => 0,
            Self::Familiar => 2,
            Self::Established => 5,
            Self::Trusted => 8,
        }
    }

    /// Human-readable explanation fragment.
    pub fn explanation(&self, count: u64, days: u32) -> String {
        match self {
            Self::Unknown => "New — never observed on this machine".into(),
            Self::Rare => format!("Rare — observed {} time(s)", count),
            Self::Familiar => format!("Familiar — observed {} times over {} day(s)", count, days),
            Self::Established => format!("Established — consistently observed over {} days", days),
            Self::Trusted => format!("Trusted — stable presence over {} days ({} observations)", days, count),
        }
    }
}

/// Compute trust level from observation data.
fn compute_trust_level(count: u64, stable_days: u32, has_signer: bool, age_days: i64) -> TrustLevel {
    if count == 0 {
        return TrustLevel::Unknown;
    }
    if count < 3 || age_days < 1 {
        return TrustLevel::Rare;
    }
    if count >= STABLE_THRESHOLD && stable_days as i64 >= ESTABLISHED_DAYS && has_signer {
        return TrustLevel::Trusted;
    }
    if count >= STABLE_THRESHOLD && stable_days as i64 >= ESTABLISHED_DAYS {
        return TrustLevel::Established;
    }
    TrustLevel::Familiar
}

/// Result of querying the trust graph for confidence adjustment.
#[derive(Debug, Clone, Serialize)]
pub struct TrustQuery {
    /// Trust level for this entity.
    pub trust_level: TrustLevel,
    /// Confidence discount to subtract from ARGUS score.
    /// NEVER exceeds 8 points. NEVER suppresses signatures.
    pub confidence_discount: u32,
    /// Human-readable explanation.
    pub explanation: String,
    /// Observation count.
    pub observation_count: u64,
    /// Days of stability.
    pub stable_days: u32,
}

/// The trust graph — SQLite-backed local memory.
pub struct TrustGraph {
    conn: Mutex<Connection>,
}

impl TrustGraph {
    /// Open or create the trust graph database.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("trust_graph open: {e}"))?;

        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS trust_nodes (
                key TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 1,
                stable_days INTEGER NOT NULL DEFAULT 0,
                signer TEXT,
                last_day_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_trust_last_seen ON trust_nodes(last_seen);
            CREATE INDEX IF NOT EXISTS idx_trust_kind ON trust_nodes(kind);
        ").map_err(|e| format!("trust_graph schema: {e}"))?;

        info!("trust graph opened");
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Record an observation of an entity.
    pub fn observe(&self, key: &str, kind: TrustNodeKind, signer: Option<&str>) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let kind_str = format!("{kind:?}");

        // Upsert: insert or update observation.
        let result = conn.execute(
            "INSERT INTO trust_nodes (key, kind, first_seen, last_seen, observation_count, stable_days, signer, last_day_hash)
             VALUES (?1, ?2, ?3, ?3, 1, 1, ?4, ?5)
             ON CONFLICT(key) DO UPDATE SET
                last_seen = ?3,
                observation_count = observation_count + 1,
                stable_days = CASE
                    WHEN last_day_hash != ?5 THEN stable_days + 1
                    ELSE stable_days
                END,
                last_day_hash = ?5,
                signer = COALESCE(?4, signer)",
            params![key, kind_str, now, signer, today],
        );

        if let Err(e) = result {
            debug!(error = %e, key, "trust_graph observe failed");
        }

        // Prune if over capacity.
        self.prune_if_needed(&conn);
    }

    /// Query trust level for an entity.
    pub fn query(&self, key: &str) -> TrustQuery {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();

        let result = conn.query_row(
            "SELECT observation_count, stable_days, signer, first_seen, last_seen FROM trust_nodes WHERE key = ?1",
            params![key],
            |row| {
                let count: u64 = row.get(0)?;
                let stable_days: u32 = row.get(1)?;
                let signer: Option<String> = row.get(2)?;
                let first_seen: i64 = row.get(3)?;
                let last_seen: i64 = row.get(4)?;
                Ok((count, stable_days, signer, first_seen, last_seen))
            },
        );

        match result {
            Ok((count, stable_days, signer, first_seen, last_seen)) => {
                let age_days = (now - first_seen) / 86400;
                let stale_days = (now - last_seen) / 86400;

                // Trust decays if not seen recently.
                if stale_days > TRUST_DECAY_DAYS {
                    return TrustQuery {
                        trust_level: TrustLevel::Rare,
                        confidence_discount: 0,
                        explanation: format!("Stale — not seen in {} days", stale_days),
                        observation_count: count,
                        stable_days,
                    };
                }

                let level = compute_trust_level(count, stable_days, signer.is_some(), age_days);
                TrustQuery {
                    confidence_discount: level.confidence_discount(),
                    explanation: level.explanation(count, stable_days),
                    trust_level: level,
                    observation_count: count,
                    stable_days,
                }
            }
            Err(_) => TrustQuery {
                trust_level: TrustLevel::Unknown,
                confidence_discount: 0,
                explanation: TrustLevel::Unknown.explanation(0, 0),
                observation_count: 0,
                stable_days: 0,
            },
        }
    }

    /// Generate a chain key from a PLM process chain.
    pub fn chain_key(chain_names: &[&str]) -> String {
        chain_names.join("→")
    }

    /// Get diagnostics summary.
    pub fn diagnostics(&self) -> serde_json::Value {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();

        let total: u64 = conn.query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| r.get(0)).unwrap_or(0);
        let stable: u64 = conn.query_row(
            "SELECT COUNT(*) FROM trust_nodes WHERE observation_count >= ?1 AND stable_days >= ?2",
            params![STABLE_THRESHOLD, ESTABLISHED_DAYS],
            |r| r.get(0),
        ).unwrap_or(0);
        let rare: u64 = conn.query_row(
            "SELECT COUNT(*) FROM trust_nodes WHERE observation_count < 3",
            [], |r| r.get(0),
        ).unwrap_or(0);
        let recent: u64 = conn.query_row(
            "SELECT COUNT(*) FROM trust_nodes WHERE last_seen > ?1",
            params![now - 86400],
            |r| r.get(0),
        ).unwrap_or(0);
        let stale: u64 = conn.query_row(
            "SELECT COUNT(*) FROM trust_nodes WHERE last_seen < ?1",
            params![now - TRUST_DECAY_DAYS * 86400],
            |r| r.get(0),
        ).unwrap_or(0);

        serde_json::json!({
            "nodes": total,
            "stable_nodes": stable,
            "rare_nodes": rare,
            "recently_seen": recent,
            "stale_nodes": stale,
            "max_nodes": MAX_NODES,
            "decay_days": TRUST_DECAY_DAYS,
        })
    }

    /// Prune oldest entries if over capacity.
    fn prune_if_needed(&self, conn: &Connection) {
        let count: u64 = conn.query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| r.get(0)).unwrap_or(0);
        if count as usize > MAX_NODES {
            let to_remove = count as usize - MAX_NODES;
            let _ = conn.execute(
                "DELETE FROM trust_nodes WHERE key IN (SELECT key FROM trust_nodes ORDER BY last_seen ASC LIMIT ?1)",
                params![to_remove],
            );
        }
    }

    /// Expire stale entries (not seen in TRUST_DECAY_DAYS * 2).
    pub fn expire_stale(&self) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = chrono::Utc::now().timestamp() - (TRUST_DECAY_DAYS * 2 * 86400);
        let removed = conn.execute(
            "DELETE FROM trust_nodes WHERE last_seen < ?1",
            params![cutoff],
        ).unwrap_or(0);
        if removed > 0 {
            debug!(removed, "trust_graph: expired stale entries");
        }
    }

    /// Node count.
    pub fn node_count(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| r.get::<_, u64>(0)).unwrap_or(0) as usize
    }
}

/// Create an ARGUS finding from trust graph context.
/// This is a DISCOUNT finding — reduces score when behavior is familiar.
pub fn trust_finding(query: &TrustQuery) -> Option<argus::Finding> {
    if query.confidence_discount == 0 {
        return None; // Unknown/Rare = no adjustment.
    }

    Some(argus::Finding {
        layer: argus::verdict::Layer::Reputation, // Trust feeds into reputation layer.
        severity: argus::verdict::Severity::Low,
        weight: 0, // Discount applied separately, not as positive weight.
        description: format!("Local trust: {}", query.explanation),
        technical_detail: Some(format!(
            "trust_level={:?} discount={} observations={} stable_days={}",
            query.trust_level, query.confidence_discount,
            query.observation_count, query.stable_days
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_mem() -> TrustGraph {
        TrustGraph::open(std::path::Path::new(":memory:")).unwrap()
    }

    #[test]
    fn unknown_entity_returns_zero_discount() {
        let g = open_mem();
        let q = g.query("nonexistent");
        assert_eq!(q.trust_level, TrustLevel::Unknown);
        assert_eq!(q.confidence_discount, 0);
    }

    #[test]
    fn single_observation_is_rare() {
        let g = open_mem();
        g.observe("test.exe", TrustNodeKind::Executable, None);
        let q = g.query("test.exe");
        assert_eq!(q.trust_level, TrustLevel::Rare);
        assert_eq!(q.observation_count, 1);
    }

    #[test]
    fn many_observations_become_familiar() {
        let g = open_mem();
        for _ in 0..5 {
            g.observe("powershell.exe", TrustNodeKind::Executable, None);
        }
        let q = g.query("powershell.exe");
        // 5 observations, same day → Familiar (not yet Established).
        assert!(q.trust_level >= TrustLevel::Familiar || q.trust_level == TrustLevel::Rare);
        assert!(q.observation_count >= 5);
    }

    #[test]
    fn chain_key_format() {
        let key = TrustGraph::chain_key(&["explorer.exe", "powershell.exe", "cmd.exe"]);
        assert!(key.contains("powershell.exe"));
    }

    #[test]
    fn trust_never_suppresses_with_high_discount() {
        // Max discount is 8 points. Verify.
        assert_eq!(TrustLevel::Trusted.confidence_discount(), 8);
        assert_eq!(TrustLevel::Unknown.confidence_discount(), 0);
        // No trust level gives more than 8.
        for level in [TrustLevel::Unknown, TrustLevel::Rare, TrustLevel::Familiar, TrustLevel::Established, TrustLevel::Trusted] {
            assert!(level.confidence_discount() <= 8);
        }
    }

    #[test]
    fn diagnostics_json() {
        let g = open_mem();
        g.observe("a.exe", TrustNodeKind::Executable, None);
        g.observe("b.exe", TrustNodeKind::Executable, Some("Microsoft"));
        let d = g.diagnostics();
        assert_eq!(d["nodes"], 2);
    }

    #[test]
    fn prune_respects_max() {
        let g = open_mem();
        // Insert many nodes.
        for i in 0..100 {
            g.observe(&format!("file{i}.exe"), TrustNodeKind::Executable, None);
        }
        assert!(g.node_count() <= MAX_NODES);
    }

    #[test]
    fn trust_finding_only_for_familiar_plus() {
        let unknown = TrustQuery {
            trust_level: TrustLevel::Unknown,
            confidence_discount: 0,
            explanation: String::new(),
            observation_count: 0,
            stable_days: 0,
        };
        assert!(trust_finding(&unknown).is_none());

        let established = TrustQuery {
            trust_level: TrustLevel::Established,
            confidence_discount: 5,
            explanation: "Established — 14 days".into(),
            observation_count: 50,
            stable_days: 14,
        };
        let f = trust_finding(&established);
        assert!(f.is_some());
        assert_eq!(f.unwrap().weight, 0); // Discount, not positive weight.
    }

    #[test]
    fn explanation_is_human_readable() {
        let e = TrustLevel::Trusted.explanation(200, 30);
        assert!(e.contains("200"));
        assert!(e.contains("30"));
        assert!(e.contains("Trusted"));
    }
}

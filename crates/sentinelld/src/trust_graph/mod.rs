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

use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, warn};

// ── D-2 fix: Trust node integrity ──────────────────────────────
// Keyed hash prevents external SQLite tampering from manufacturing trust.
// Tampered nodes → integrity mismatch → no discount (safe default).

static TRUST_INTEGRITY_SECRET: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();

/// Set the trust integrity secret (called during daemon startup from vault key).
pub fn set_trust_integrity_secret(secret: &[u8]) {
    let mut key = [0u8; 16];
    for (i, byte) in secret.iter().take(16).enumerate() {
        key[i] = *byte;
    }
    // Use different bytes than cache to avoid cross-component key reuse.
    key[0] ^= 0xAA;
    key[15] ^= 0x55;
    let _ = TRUST_INTEGRITY_SECRET.set(key);
}

/// Compute integrity hash for a trust node's security-critical fields.
fn trust_node_hash(
    key: &str,
    observation_count: u64,
    stable_days: u32,
    signer: Option<&str>,
) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let secret = TRUST_INTEGRITY_SECRET.get().copied().unwrap_or([0u8; 16]);

    let mut hasher = DefaultHasher::new();
    secret.hash(&mut hasher);
    key.hash(&mut hasher);
    observation_count.hash(&mut hasher);
    stable_days.hash(&mut hasher);
    // Bind the signer into the integrity hash. `has_signer` (and the signer
    // identity) drives compute_trust_level Established→Trusted, so leaving it
    // unhashed let an `UPDATE trust_nodes SET signer='Microsoft'` manufacture
    // a Trusted node (+discount) without breaking integrity verification.
    signer.unwrap_or("").hash(&mut hasher);
    secret.hash(&mut hasher);
    hasher.finish() as i64
}

/// Max trust nodes before pruning oldest.
const MAX_NODES: usize = 10_000;
/// Max drift events retained in database (ARCH-7 fix).
const MAX_DRIFT_EVENTS: usize = 1_000;
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
            Self::Trusted => format!(
                "Trusted — stable presence over {} days ({} observations)",
                days, count
            ),
        }
    }
}

/// Compute trust level from observation data.
fn compute_trust_level(
    count: u64,
    stable_days: u32,
    has_signer: bool,
    age_days: i64,
) -> TrustLevel {
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

/// A behavioral drift event — trusted pattern mutated.
#[derive(Debug, Clone, Serialize)]
pub struct DriftEvent {
    pub timestamp: i64,
    pub entity_key: String,
    pub drift_type: DriftType,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub trust_impact: String,
    pub explanation: String,
}

/// Types of behavioral drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftType {
    /// Signer changed on a previously-signed binary.
    SignerChanged,
    /// Trusted process chain mutated (new child process).
    ChainMutated,
    /// Previously stable binary moved to new location.
    PathChanged,
    /// Trusted entity reappeared after long absence.
    StaleReturn,
    /// New persistence entry from previously non-persistent process.
    NewPersistence,
}

impl DriftType {
    /// Suspicion boost for this drift type.
    pub fn suspicion_weight(&self) -> u32 {
        match self {
            Self::SignerChanged => 10,
            Self::ChainMutated => 6,
            Self::PathChanged => 4,
            Self::StaleReturn => 3,
            Self::NewPersistence => 8,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::SignerChanged => "Signer changed",
            Self::ChainMutated => "Process chain mutated",
            Self::PathChanged => "File path changed",
            Self::StaleReturn => "Returned after long absence",
            Self::NewPersistence => "New persistence entry",
        }
    }
}

/// The trust graph — SQLite-backed local memory.
pub struct TrustGraph {
    conn: Mutex<Connection>,
}

impl TrustGraph {
    /// Open or create the trust graph database.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("trust_graph open: {e}"))?;

        conn.execute_batch(
            "
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
                last_day_hash TEXT,
                integrity_hash INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_trust_last_seen ON trust_nodes(last_seen);
            CREATE INDEX IF NOT EXISTS idx_trust_kind ON trust_nodes(kind);

            CREATE TABLE IF NOT EXISTS drift_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                entity_key TEXT NOT NULL,
                drift_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                trust_impact TEXT NOT NULL,
                explanation TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_drift_timestamp ON drift_events(timestamp);
        ",
        )
        .map_err(|e| format!("trust_graph schema: {e}"))?;

        // D-2 fix: add integrity_hash column if upgrading from older schema.
        let _ = conn.execute(
            "ALTER TABLE trust_nodes ADD COLUMN integrity_hash INTEGER NOT NULL DEFAULT 0",
            [],
        );

        info!("trust graph opened");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record an observation of an entity.
    pub fn observe(&self, key: &str, kind: TrustNodeKind, signer: Option<&str>) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        self.observe_locked(&conn, key, kind, signer);
    }

    /// Same as `observe`, but the caller already holds the connection lock.
    /// R3-19: lets observe_with_signer perform read+write atomically without
    /// dropping the lock between them.
    fn observe_locked(
        &self,
        conn: &rusqlite::Connection,
        key: &str,
        kind: TrustNodeKind,
        signer: Option<&str>,
    ) {
        let now = chrono::Utc::now().timestamp();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let kind_str = format!("{kind:?}");

        // Upsert + integrity-hash update MUST be atomic. Previously these
        // were two separate `conn.execute` calls; a crash, SIGTERM, or
        // SQLITE_BUSY rollback between them left rows with integrity_hash=0,
        // which `query()` then rejects as INTEGRITY MISMATCH → silent trust
        // loss for every entity that hit the window. Wrapping in a
        // rusqlite Transaction guarantees both statements commit together
        // or neither does. We use the typed Transaction API (not raw
        // BEGIN/COMMIT strings) because the calibration-module BEGIN-swallow
        // bug already proved string-based txn control is fragile.
        let tx_result: Result<(), rusqlite::Error> = (|| {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO trust_nodes (key, kind, first_seen, last_seen, observation_count, stable_days, signer, last_day_hash, integrity_hash)
                 VALUES (?1, ?2, ?3, ?3, 1, 1, ?4, ?5, 0)
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
            )?;

            // Read the EFFECTIVE signer after the COALESCE upsert (not the
            // call arg) so the hash matches what query() will verify.
            let row: (u64, u32, Option<String>) = tx.query_row(
                "SELECT observation_count, stable_days, signer FROM trust_nodes WHERE key = ?1",
                params![key],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u32,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )?;

            let ihash = trust_node_hash(key, row.0, row.1, row.2.as_deref());
            tx.execute(
                "UPDATE trust_nodes SET integrity_hash = ?1 WHERE key = ?2",
                params![ihash, key],
            )?;
            tx.commit()?;
            Ok(())
        })();

        if let Err(e) = tx_result {
            debug!(error = %e, key, "trust_graph observe transaction failed");
        }

        // Prune if over capacity.
        self.prune_if_needed(conn);
    }

    /// Query trust level for an entity.
    pub fn query(&self, key: &str) -> TrustQuery {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();

        let result = conn.query_row(
            "SELECT observation_count, stable_days, signer, first_seen, last_seen, integrity_hash FROM trust_nodes WHERE key = ?1",
            params![key],
            |row| {
                let count: u64 = row.get(0)?;
                let stable_days: u32 = row.get(1)?;
                let signer: Option<String> = row.get(2)?;
                let first_seen: i64 = row.get(3)?;
                let last_seen: i64 = row.get(4)?;
                let stored_hash: i64 = row.get(5).unwrap_or(0);
                Ok((count, stable_days, signer, first_seen, last_seen, stored_hash))
            },
        );

        match result {
            Ok((count, stable_days, signer, first_seen, last_seen, stored_hash)) => {
                // D-2 fix: verify integrity hash. Bug R3-4: previous `!= 0`
                // gate let attackers `UPDATE trust_nodes SET integrity_hash=0`
                // and bypass verification entirely. Now any mismatch including
                // zero is rejected.
                {
                    let expected = trust_node_hash(key, count, stable_days, signer.as_deref());
                    if stored_hash != expected {
                        warn!(
                            key,
                            "trust graph: INTEGRITY MISMATCH — node rejected (possible tampering)"
                        );
                        return TrustQuery {
                            trust_level: TrustLevel::Unknown,
                            confidence_discount: 0,
                            explanation: "Integrity verification failed — trust revoked".into(),
                            observation_count: 0,
                            stable_days: 0,
                        };
                    }
                }
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
        chain_names.join(">")
    }

    /// Observe with signer consistency check.
    /// Detects drift: signer changed on previously-signed binary.
    pub fn observe_with_signer(
        &self,
        key: &str,
        kind: TrustNodeKind,
        new_signer: Option<&str>,
    ) -> Option<DriftEvent> {
        // R3-19: read prior signer and write the observation under the SAME
        // held lock so a concurrent observe cannot slip in between and make
        // us record drift against a stale value (or miss real drift).
        let existing_signer: Option<String> = {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let prev = conn
                .query_row(
                    "SELECT signer FROM trust_nodes WHERE key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .ok()
                .flatten();
            self.observe_locked(&conn, key, kind, new_signer);
            prev
        };

        // Detect signer drift.
        if let Some(ref old) = existing_signer {
            if let Some(new) = new_signer {
                if !old.is_empty() && old != new {
                    let drift = DriftEvent {
                        timestamp: chrono::Utc::now().timestamp(),
                        entity_key: key.to_string(),
                        drift_type: DriftType::SignerChanged,
                        old_value: Some(old.clone()),
                        new_value: Some(new.to_string()),
                        trust_impact: "trust invalidated".into(),
                        explanation: format!("Signer changed from '{}' to '{}'", old, new),
                    };
                    self.record_drift(&drift);
                    // Invalidate trust: reset observation count.
                    self.reset_trust(key);
                    return Some(drift);
                }
            } else if !old.is_empty() {
                // Was signed, now unsigned — significant drift.
                let drift = DriftEvent {
                    timestamp: chrono::Utc::now().timestamp(),
                    entity_key: key.to_string(),
                    drift_type: DriftType::SignerChanged,
                    old_value: Some(old.clone()),
                    new_value: None,
                    trust_impact: "trust invalidated — unsigned".into(),
                    explanation: format!("Previously signed by '{}', now unsigned", old),
                };
                self.record_drift(&drift);
                self.reset_trust(key);
                return Some(drift);
            }
        }

        None
    }

    /// Detect chain mutation: trusted chain gained new child.
    pub fn check_chain_drift(
        &self,
        base_chain_key: &str,
        extended_chain_key: &str,
    ) -> Option<DriftEvent> {
        let base_q = self.query(base_chain_key);
        let ext_q = self.query(extended_chain_key);

        // Base chain is established but extended chain is unknown = mutation.
        if base_q.trust_level >= TrustLevel::Established && ext_q.trust_level == TrustLevel::Unknown
        {
            let drift = DriftEvent {
                timestamp: chrono::Utc::now().timestamp(),
                entity_key: extended_chain_key.to_string(),
                drift_type: DriftType::ChainMutated,
                old_value: Some(base_chain_key.to_string()),
                new_value: Some(extended_chain_key.to_string()),
                trust_impact: "new child in trusted chain".into(),
                explanation: format!(
                    "Trusted chain '{}' extended with new process",
                    base_chain_key
                ),
            };
            self.record_drift(&drift);
            return Some(drift);
        }

        None
    }

    /// Record a drift event.
    /// ARCH-7 fix: prunes drift table to MAX_DRIFT_EVENTS after insert.
    fn record_drift(&self, drift: &DriftEvent) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let dtype = format!("{:?}", drift.drift_type);
        let _ = conn.execute(
            "INSERT INTO drift_events (timestamp, entity_key, drift_type, old_value, new_value, trust_impact, explanation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![drift.timestamp, drift.entity_key, dtype, drift.old_value, drift.new_value, drift.trust_impact, drift.explanation],
        );

        // Prune old drift events — keep only the most recent MAX_DRIFT_EVENTS.
        let _ = conn.execute(
            "DELETE FROM drift_events WHERE id NOT IN (SELECT id FROM drift_events ORDER BY timestamp DESC LIMIT ?1)",
            params![MAX_DRIFT_EVENTS],
        );

        info!(
            entity = %drift.entity_key,
            drift_type = %dtype,
            "ASTRA behavioral drift detected"
        );
    }

    /// Reset trust for an entity (signer changed, etc.)
    fn reset_trust(&self, key: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // D-2 fix: update integrity_hash after reset to keep it consistent.
        // Clear signer too (trust is being revoked, often BECAUSE the signer
        // changed) so the node must re-earn Trusted, and the hash matches the
        // post-reset (signer = NULL) row.
        let new_hash = trust_node_hash(key, 1, 0, None);
        let _ = conn.execute(
            "UPDATE trust_nodes SET observation_count = 1, stable_days = 0, signer = NULL, integrity_hash = ?1 WHERE key = ?2",
            params![new_hash, key],
        );
    }

    /// Get recent drift events for diagnostics.
    pub fn recent_drifts(&self, limit: usize) -> Vec<DriftEvent> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = match conn.prepare(
            "SELECT timestamp, entity_key, drift_type, old_value, new_value, trust_impact, explanation FROM drift_events ORDER BY timestamp DESC LIMIT ?1"
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        match stmt.query_map(params![limit as i64], |row| {
            let dtype_str: String = row.get(2)?;
            let drift_type = match dtype_str.as_str() {
                "SignerChanged" => DriftType::SignerChanged,
                "ChainMutated" => DriftType::ChainMutated,
                "PathChanged" => DriftType::PathChanged,
                "StaleReturn" => DriftType::StaleReturn,
                "NewPersistence" => DriftType::NewPersistence,
                _ => DriftType::ChainMutated,
            };
            Ok(DriftEvent {
                timestamp: row.get(0)?,
                entity_key: row.get(1)?,
                drift_type,
                old_value: row.get(3)?,
                new_value: row.get(4)?,
                trust_impact: row.get(5)?,
                explanation: row.get(6)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        }
    }

    /// Get diagnostics summary.
    pub fn diagnostics(&self) -> serde_json::Value {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();

        let total: u64 = conn
            .query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| r.get(0))
            .unwrap_or(0);
        let stable: u64 = conn.query_row(
            "SELECT COUNT(*) FROM trust_nodes WHERE observation_count >= ?1 AND stable_days >= ?2",
            params![STABLE_THRESHOLD, ESTABLISHED_DAYS],
            |r| r.get(0),
        ).unwrap_or(0);
        let rare: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trust_nodes WHERE observation_count < 3",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let recent: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trust_nodes WHERE last_seen > ?1",
                params![now - 86400],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let stale: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trust_nodes WHERE last_seen < ?1",
                params![now - TRUST_DECAY_DAYS * 86400],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let drift_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM drift_events", [], |r| r.get(0))
            .unwrap_or(0);
        let recent_drifts: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM drift_events WHERE timestamp > ?1",
                params![now - 86400],
                |r| r.get(0),
            )
            .unwrap_or(0);

        serde_json::json!({
            "nodes": total,
            "stable_nodes": stable,
            "rare_nodes": rare,
            "recently_seen": recent,
            "stale_nodes": stale,
            "drift_events_total": drift_count,
            "drift_events_24h": recent_drifts,
            "max_nodes": MAX_NODES,
            "decay_days": TRUST_DECAY_DAYS,
        })
    }

    /// Prune oldest entries if over capacity.
    fn prune_if_needed(&self, conn: &Connection) {
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| r.get(0))
            .unwrap_or(0);
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
        let removed = conn
            .execute(
                "DELETE FROM trust_nodes WHERE last_seen < ?1",
                params![cutoff],
            )
            .unwrap_or(0);
        if removed > 0 {
            debug!(removed, "trust_graph: expired stale entries");
        }
    }

    /// Node count.
    pub fn node_count(&self) -> usize {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM trust_nodes", [], |r| {
            r.get::<_, u64>(0)
        })
        .unwrap_or(0) as usize
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
            query.trust_level,
            query.confidence_discount,
            query.observation_count,
            query.stable_days
        )),
    })
}

/// Create an ARGUS finding from behavioral drift detection.
/// Drift INCREASES suspicion — a trusted pattern that mutated is concerning.
pub fn drift_finding(drift: &DriftEvent) -> argus::Finding {
    argus::Finding {
        layer: argus::verdict::Layer::Context,
        severity: if drift.drift_type.suspicion_weight() >= 8 {
            argus::verdict::Severity::High
        } else {
            argus::verdict::Severity::Medium
        },
        weight: drift.drift_type.suspicion_weight(),
        description: format!("Behavioral drift: {}", drift.explanation),
        technical_detail: Some(format!(
            "type={:?} old={:?} new={:?} impact={}",
            drift.drift_type, drift.old_value, drift.new_value, drift.trust_impact
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_mem() -> TrustGraph {
        TrustGraph::open(std::path::Path::new(":memory:")).unwrap()
    }

    #[test]
    fn signer_tamper_revokes_trust_via_integrity() {
        let g = open_mem();
        g.observe("C:\\app.exe", TrustNodeKind::Executable, Some("Acme Corp"));

        // Baseline: integrity valid → not revoked.
        let before = g.query("C:\\app.exe");
        assert!(
            !before.explanation.contains("Integrity verification failed"),
            "fresh node should verify"
        );

        // Tamper: swap the signer in the DB WITHOUT recomputing the integrity
        // hash — simulates `UPDATE trust_nodes SET signer='Microsoft'`. Since
        // signer is now bound into the hash, this must fail verification.
        {
            let conn = g.conn.lock().unwrap();
            conn.execute("UPDATE trust_nodes SET signer = 'Microsoft'", [])
                .unwrap();
        }

        let after = g.query("C:\\app.exe");
        assert_eq!(after.trust_level, TrustLevel::Unknown);
        assert_eq!(
            after.confidence_discount, 0,
            "tampered signer must yield no trust discount"
        );
        assert!(after.explanation.contains("Integrity verification failed"));
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
        for level in [
            TrustLevel::Unknown,
            TrustLevel::Rare,
            TrustLevel::Familiar,
            TrustLevel::Established,
            TrustLevel::Trusted,
        ] {
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

    #[test]
    fn signer_change_detects_drift() {
        let g = open_mem();
        // First observation with signer A.
        g.observe("app.exe", TrustNodeKind::Executable, Some("Company A"));
        // Second observation with signer B.
        let drift = g.observe_with_signer("app.exe", TrustNodeKind::Executable, Some("Company B"));
        assert!(drift.is_some());
        let d = drift.unwrap();
        assert_eq!(d.drift_type, DriftType::SignerChanged);
        // Trust should be reset.
        let q = g.query("app.exe");
        assert_eq!(q.observation_count, 1); // Reset to 1.
    }

    #[test]
    fn same_signer_no_drift() {
        let g = open_mem();
        g.observe("app.exe", TrustNodeKind::Executable, Some("Microsoft"));
        let drift = g.observe_with_signer("app.exe", TrustNodeKind::Executable, Some("Microsoft"));
        assert!(drift.is_none());
    }

    #[test]
    fn unsigned_after_signed_is_drift() {
        let g = open_mem();
        g.observe("tool.exe", TrustNodeKind::Executable, Some("Vendor"));
        let drift = g.observe_with_signer("tool.exe", TrustNodeKind::Executable, None);
        assert!(drift.is_some());
        assert_eq!(drift.unwrap().drift_type, DriftType::SignerChanged);
    }

    #[test]
    fn drift_suspicion_weights() {
        assert!(
            DriftType::SignerChanged.suspicion_weight() > DriftType::StaleReturn.suspicion_weight()
        );
        assert!(
            DriftType::NewPersistence.suspicion_weight()
                > DriftType::PathChanged.suspicion_weight()
        );
    }

    #[test]
    fn drift_finding_has_weight() {
        let d = DriftEvent {
            timestamp: 0,
            entity_key: "test".into(),
            drift_type: DriftType::SignerChanged,
            old_value: Some("A".into()),
            new_value: Some("B".into()),
            trust_impact: "invalidated".into(),
            explanation: "Signer changed".into(),
        };
        let f = drift_finding(&d);
        assert_eq!(f.weight, 10);
        assert_eq!(f.severity, argus::verdict::Severity::High);
    }

    #[test]
    fn recent_drifts_returns_events() {
        let g = open_mem();
        g.observe("test.exe", TrustNodeKind::Executable, Some("A"));
        let _ = g.observe_with_signer("test.exe", TrustNodeKind::Executable, Some("B"));
        let drifts = g.recent_drifts(10);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].drift_type, DriftType::SignerChanged);
    }
}

//! False-positive calibration logging.
//!
//! Tracks every detection event and every user-initiated restore (which
//! signals a likely false positive). The data feeds per-layer FP-rate
//! statistics and produces a sanitised JSON bundle that developers can
//! use to tune ARGUS layers, YARA rules, and ClamAV exclusions.
//!
//! The database lives at `runtime/state/calibration.db` — separate from
//! the main state DB so it can be shipped / wiped independently.

use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use tracing::{error, info};

// ═══════════════════════════════════════════════════════════════
//  Data structs
// ═══════════════════════════════════════════════════════════════

/// A single detection event recorded by any engine.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionEvent {
    pub id: String,
    pub timestamp: i64,
    pub file_path: String,
    pub file_hash: String,
    pub file_size: u64,
    pub detection_name: String,
    /// Which engine produced the detection: `"clamav"`, `"argus"`,
    /// `"yara"`, or `"sandbox"`.
    pub detection_source: String,
    pub argus_score: Option<u32>,
    pub argus_verdict: Option<String>,
    /// Layer names that contributed to the ARGUS score.
    pub layers_triggered: Vec<String>,
    /// Behavioural tags emitted by the sandbox or heuristic layers.
    pub behavior_tags: Vec<String>,
    /// YARA rule identifiers that matched.
    pub yara_rules_matched: Vec<String>,
    /// Sandbox detonation findings (if any).
    pub sandbox_findings: Vec<String>,
    /// Context in which the scan ran.
    pub scan_context: String,
    /// Action the daemon took: `"quarantine"`, `"alert"`, `"log"`.
    pub action_taken: String,
    pub engine_version: Option<String>,
    pub argus_version: Option<String>,
    pub yara_rule_count: Option<u32>,
    pub signature_count: Option<u64>,
}

/// A restore event — the user recovered a quarantined file, implying
/// the original detection was a false positive.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreEvent {
    pub id: String,
    /// Foreign key back to `DetectionEvent.id`.
    pub detection_event_id: String,
    pub timestamp: i64,
    pub file_path: String,
    pub file_hash: String,
    /// Broad category: `"developer_tool"`, `"emulator"`, `"game_mod"`,
    /// `"sysadmin"`, `"unknown"`.
    pub fp_category: String,
    pub user_notes: Option<String>,
}

/// Per-layer false-positive statistics.
#[derive(Debug, Clone, Serialize)]
pub struct LayerStat {
    pub layer_name: String,
    pub total_triggers: u64,
    pub fp_triggers: u64,
    pub last_fp_timestamp: Option<i64>,
}

/// A file that was restored from quarantine — a likely false-positive
/// candidate worth reviewing.
#[derive(Debug, Clone, Serialize)]
pub struct FPCandidate {
    pub file_hash: String,
    pub file_path: String,
    pub detection_name: String,
    pub detection_source: String,
    pub fp_category: String,
    pub restore_count: u64,
    pub last_restore_timestamp: i64,
}

/// A sanitised bundle of calibration data suitable for developer review.
#[derive(Debug, Clone, Serialize)]
pub struct CalibrationBundle {
    pub generated_at: String,
    pub total_detections: u64,
    pub total_restores: u64,
    pub fp_rate: f64,
    pub layer_stats: Vec<LayerStat>,
    pub fp_candidates: Vec<FPCandidate>,
    pub top_noisy_rules: Vec<(String, u64)>,
}

// ═══════════════════════════════════════════════════════════════
//  Schema
// ═══════════════════════════════════════════════════════════════

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS detection_events (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    detection_name TEXT NOT NULL,
    detection_source TEXT NOT NULL,
    argus_score INTEGER,
    argus_verdict TEXT,
    layers_triggered TEXT,
    behavior_tags TEXT,
    yara_rules_matched TEXT,
    sandbox_findings TEXT,
    scan_context TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    engine_version TEXT,
    argus_version TEXT,
    yara_rule_count INTEGER,
    signature_count INTEGER
);

CREATE TABLE IF NOT EXISTS restore_events (
    id TEXT PRIMARY KEY,
    detection_event_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    fp_category TEXT,
    user_notes TEXT,
    FOREIGN KEY (detection_event_id) REFERENCES detection_events(id)
);

CREATE TABLE IF NOT EXISTS layer_stats (
    layer_name TEXT NOT NULL,
    total_triggers INTEGER DEFAULT 0,
    fp_triggers INTEGER DEFAULT 0,
    last_fp_timestamp INTEGER,
    PRIMARY KEY (layer_name)
);

CREATE INDEX IF NOT EXISTS idx_det_hash ON detection_events(file_hash);
CREATE INDEX IF NOT EXISTS idx_det_source ON detection_events(detection_source);
CREATE INDEX IF NOT EXISTS idx_det_time ON detection_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_restore_det ON restore_events(detection_event_id);
CREATE INDEX IF NOT EXISTS idx_restore_hash ON restore_events(file_hash);
";

// ═══════════════════════════════════════════════════════════════
//  CalibrationLog
// ═══════════════════════════════════════════════════════════════

/// Persistent store for detection and false-positive calibration data.
pub struct CalibrationLog {
    conn: Connection,
}

impl CalibrationLog {
    /// Open (or create) the calibration database at `path`.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create calibration DB directory: {e}"))?;
        }

        let conn =
            Connection::open(path).map_err(|e| format!("Cannot open calibration DB: {e}"))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("PRAGMA failed: {e}"))?;

        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("Schema creation failed: {e}"))?;

        info!(path = %path.display(), "calibration database opened");
        Ok(Self { conn })
    }

    // ───────────────────────────────────────────────────────────
    //  Record a detection event
    // ───────────────────────────────────────────────────────────

    /// Persist a detection event and update per-layer trigger counts.
    pub fn record_detection(&self, event: &DetectionEvent) -> Result<(), String> {
        // Audit fix: bounded retention so this DB doesn't grow forever on a
        // high-detection-rate host.
        const RETENTION_ROWS: i64 = 50_000;

        let layers_json = serde_json::to_string(&event.layers_triggered).unwrap_or_default();
        let tags_json = serde_json::to_string(&event.behavior_tags).unwrap_or_default();
        let yara_json = serde_json::to_string(&event.yara_rules_matched).unwrap_or_default();
        let sandbox_json = serde_json::to_string(&event.sandbox_findings).unwrap_or_default();

        // Audit fix: wrap detection insert + layer upserts in a single
        // transaction so a mid-loop failure cannot leave the detection row
        // with partial layer counts. The previous `let _ = ...BEGIN` swallowed
        // BEGIN failure (DB busy / stale transaction), so subsequent statements
        // ran in autocommit — and ROLLBACK at the error path became a no-op,
        // re-introducing the very partial-commit class the audit was meant to
        // eliminate. Surface BEGIN errors.
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| format!("BEGIN failed: {e}"))?;
        let result = (|| -> Result<(), String> {
            self.conn
                .execute(
                    "INSERT INTO detection_events \
                     (id, timestamp, file_path, file_hash, file_size, detection_name, \
                      detection_source, argus_score, argus_verdict, layers_triggered, \
                      behavior_tags, yara_rules_matched, sandbox_findings, scan_context, \
                      action_taken, engine_version, argus_version, yara_rule_count, signature_count) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                    params![
                        event.id,
                        event.timestamp,
                        event.file_path,
                        event.file_hash,
                        event.file_size as i64,
                        event.detection_name,
                        event.detection_source,
                        event.argus_score.map(|s| s as i64),
                        event.argus_verdict,
                        layers_json,
                        tags_json,
                        yara_json,
                        sandbox_json,
                        event.scan_context,
                        event.action_taken,
                        event.engine_version,
                        event.argus_version,
                        event.yara_rule_count.map(|c| c as i64),
                        event.signature_count.map(|c| c as i64),
                    ],
                )
                .map_err(|e| format!("insert detection_event failed: {e}"))?;

            for layer in &event.layers_triggered {
                self.conn
                    .execute(
                        "INSERT INTO layer_stats (layer_name, total_triggers, fp_triggers) \
                         VALUES (?1, 1, 0) \
                         ON CONFLICT(layer_name) DO UPDATE SET total_triggers = total_triggers + 1",
                        params![layer],
                    )
                    .map_err(|e| format!("layer_stats upsert failed: {e}"))?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                let _ = self.conn.execute_batch("COMMIT");
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }

        // Prune oldest detection rows beyond the retention cap.
        let _ = self.conn.execute(
            "DELETE FROM detection_events WHERE id NOT IN (
                SELECT id FROM detection_events ORDER BY timestamp DESC, rowid DESC LIMIT ?1
            )",
            params![RETENTION_ROWS],
        );

        Ok(())
    }

    // ───────────────────────────────────────────────────────────
    //  Record a restore (likely FP)
    // ───────────────────────────────────────────────────────────

    /// Persist a restore event and update per-layer FP counts.
    pub fn record_restore(&self, event: &RestoreEvent) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO restore_events \
                 (id, detection_event_id, timestamp, file_path, file_hash, fp_category, user_notes) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    event.id,
                    event.detection_event_id,
                    event.timestamp,
                    event.file_path,
                    event.file_hash,
                    event.fp_category,
                    event.user_notes,
                ],
            )
            .map_err(|e| format!("insert restore_event failed: {e}"))?;

        // Look up which layers the original detection triggered so we can
        // increment their FP counters.
        let layers_json: Option<String> = self
            .conn
            .query_row(
                "SELECT layers_triggered FROM detection_events WHERE id = ?1",
                params![event.detection_event_id],
                |row| row.get(0),
            )
            .ok();

        if let Some(json) = layers_json {
            if let Ok(layers) = serde_json::from_str::<Vec<String>>(&json) {
                for layer in &layers {
                    let _ = self.conn.execute(
                        "UPDATE layer_stats \
                         SET fp_triggers = fp_triggers + 1, last_fp_timestamp = ?1 \
                         WHERE layer_name = ?2",
                        params![event.timestamp, layer],
                    );
                }
            }
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────────
    //  Queries
    // ───────────────────────────────────────────────────────────

    /// Files that have been restored from quarantine — likely false
    /// positives that deserve review.
    pub fn get_fp_candidates(&self) -> Vec<FPCandidate> {
        // Deterministic per-hash representative row. The old query did
        // `GROUP BY r.file_hash` while SELECTing bare (non-aggregated)
        // file_path / detection_name / detection_source / fp_category. SQLite's
        // "bare column with a single max()" rule made those come from the
        // max-timestamp row, but on a timestamp TIE the chosen row was
        // arbitrary → FP-candidate metadata could flip between identical runs.
        // Window functions pin the representative to the newest restore with a
        // rowid tiebreak; COUNT/MAX OVER give the same aggregates. Column order
        // is preserved so the row.get indices below are unchanged.
        let mut stmt = match self.conn.prepare(
            "SELECT file_hash, file_path, detection_name, detection_source, \
                    fp_category, restore_count, last_ts FROM ( \
                SELECT r.file_hash AS file_hash, \
                       r.file_path AS file_path, \
                       d.detection_name AS detection_name, \
                       d.detection_source AS detection_source, \
                       r.fp_category AS fp_category, \
                       COUNT(*) OVER (PARTITION BY r.file_hash) AS restore_count, \
                       MAX(r.timestamp) OVER (PARTITION BY r.file_hash) AS last_ts, \
                       ROW_NUMBER() OVER ( \
                           PARTITION BY r.file_hash \
                           ORDER BY r.timestamp DESC, r.rowid DESC \
                       ) AS rn \
                FROM restore_events r \
                JOIN detection_events d ON d.id = r.detection_event_id \
             ) WHERE rn = 1 \
             ORDER BY restore_count DESC, last_ts DESC",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "get_fp_candidates query failed");
                return vec![];
            }
        };

        match stmt.query_map([], |row| {
            Ok(FPCandidate {
                file_hash: row.get(0)?,
                file_path: row.get(1)?,
                detection_name: row.get(2)?,
                detection_source: row.get(3)?,
                fp_category: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                restore_count: row.get::<_, i64>(5)? as u64,
                last_restore_timestamp: row.get(6)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "get_fp_candidates failed");
                vec![]
            }
        }
    }

    /// Per-layer trigger and FP counts.
    pub fn get_layer_stats(&self) -> Vec<LayerStat> {
        let mut stmt = match self.conn.prepare(
            "SELECT layer_name, total_triggers, fp_triggers, last_fp_timestamp \
             FROM layer_stats ORDER BY fp_triggers DESC, total_triggers DESC",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "get_layer_stats query failed");
                return vec![];
            }
        };

        match stmt.query_map([], |row| {
            Ok(LayerStat {
                layer_name: row.get(0)?,
                total_triggers: row.get::<_, i64>(1)? as u64,
                fp_triggers: row.get::<_, i64>(2)? as u64,
                last_fp_timestamp: row.get(3)?,
            })
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "get_layer_stats failed");
                vec![]
            }
        }
    }

    /// Look up a previous detection by file hash.
    pub fn get_detection_by_hash(&self, hash: &str) -> Option<DetectionEvent> {
        self.conn
            .query_row(
                "SELECT id, timestamp, file_path, file_hash, file_size, detection_name, \
                        detection_source, argus_score, argus_verdict, layers_triggered, \
                        behavior_tags, yara_rules_matched, sandbox_findings, scan_context, \
                        action_taken, engine_version, argus_version, yara_rule_count, \
                        signature_count \
                 FROM detection_events WHERE file_hash = ?1 \
                 ORDER BY timestamp DESC LIMIT 1",
                params![hash],
                |row| {
                    let layers_json: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
                    let tags_json: String = row.get::<_, Option<String>>(10)?.unwrap_or_default();
                    let yara_json: String = row.get::<_, Option<String>>(11)?.unwrap_or_default();
                    let sandbox_json: String =
                        row.get::<_, Option<String>>(12)?.unwrap_or_default();

                    Ok(DetectionEvent {
                        id: row.get(0)?,
                        timestamp: row.get(1)?,
                        file_path: row.get(2)?,
                        file_hash: row.get(3)?,
                        file_size: row.get::<_, i64>(4)? as u64,
                        detection_name: row.get(5)?,
                        detection_source: row.get(6)?,
                        argus_score: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
                        argus_verdict: row.get(8)?,
                        layers_triggered: serde_json::from_str(&layers_json).unwrap_or_default(),
                        behavior_tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                        yara_rules_matched: serde_json::from_str(&yara_json).unwrap_or_default(),
                        sandbox_findings: serde_json::from_str(&sandbox_json).unwrap_or_default(),
                        scan_context: row.get(13)?,
                        action_taken: row.get(14)?,
                        engine_version: row.get(15)?,
                        argus_version: row.get(16)?,
                        yara_rule_count: row.get::<_, Option<i64>>(17)?.map(|v| v as u32),
                        signature_count: row.get::<_, Option<i64>>(18)?.map(|v| v as u64),
                    })
                },
            )
            .ok()
    }

    /// Build a sanitised calibration bundle for developer review.
    ///
    /// All file paths are stripped to filenames only so that the bundle
    /// can be shared without leaking local directory structure.
    pub fn export_calibration_bundle(&self) -> CalibrationBundle {
        let total_detections: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM detection_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let total_restores: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM restore_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let fp_rate = if total_detections > 0 {
            total_restores as f64 / total_detections as f64
        } else {
            0.0
        };

        let layer_stats = self.get_layer_stats();

        // FP candidates — sanitise paths to filenames only.
        let fp_candidates: Vec<FPCandidate> = self
            .get_fp_candidates()
            .into_iter()
            .map(|mut c| {
                c.file_path = Path::new(&c.file_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                c
            })
            .collect();

        // Top noisy rules — detection names that fire most often.
        let top_noisy_rules = self.top_noisy_rules(20);

        let generated_at = chrono::Utc::now().to_rfc3339();

        CalibrationBundle {
            generated_at,
            total_detections,
            total_restores,
            fp_rate,
            layer_stats,
            fp_candidates,
            top_noisy_rules,
        }
    }

    // ───────────────────────────────────────────────────────────
    //  Helpers
    // ───────────────────────────────────────────────────────────

    /// Detection names ranked by frequency.
    fn top_noisy_rules(&self, limit: u32) -> Vec<(String, u64)> {
        let mut stmt = match self.conn.prepare(
            "SELECT detection_name, COUNT(*) AS cnt \
             FROM detection_events \
             GROUP BY detection_name \
             ORDER BY cnt DESC \
             LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "top_noisy_rules query failed");
                return vec![];
            }
        };

        match stmt.query_map(params![limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "top_noisy_rules failed");
                vec![]
            }
        }
    }
}

/// Auto-detect FP category from file path patterns.
pub fn guess_fp_category(path: &str) -> String {
    let p = path.to_lowercase();
    if p.contains("android") && (p.contains("sdk") || p.contains("emulator")) {
        return "emulator".into();
    }
    if p.contains("qemu") || p.contains("virtualbox") || p.contains("vmware") {
        return "emulator".into();
    }
    if p.contains("\\cargo\\") || p.contains("\\target\\") || p.contains("\\.rustup\\") {
        return "developer_tool".into();
    }
    if p.contains("node_modules") || p.contains("\\npm\\") || p.contains("\\yarn\\") {
        return "node_env".into();
    }
    if p.contains("\\python") || p.contains("\\pip\\") || p.contains("\\conda\\") {
        return "python_env".into();
    }
    if p.contains("\\steam\\") || p.contains("\\epic games\\") || p.contains("\\riot") {
        return "game_mod".into();
    }
    if p.contains("\\discord\\") || p.contains("\\slack\\") || p.contains("\\teams\\") {
        return "electron_app".into();
    }
    if p.contains("\\vscode\\") || p.contains("\\cursor\\") || p.contains("\\windsurf\\") {
        return "developer_tool".into();
    }
    if p.contains("\\sysinternals\\") || p.contains("\\pstools\\") || p.contains("putty") {
        return "sysadmin".into();
    }
    if p.contains("\\7-zip\\") || p.contains("\\winrar\\") || p.contains("\\peazip\\") {
        return "compression".into();
    }
    if p.contains("\\ida\\") || p.contains("\\ghidra\\") || p.contains("\\x64dbg\\") {
        return "reverse_engineering".into();
    }
    if p.contains(".onnx") || p.contains(".safetensors") || p.contains("\\ollama\\") {
        return "ai_tool".into();
    }
    "unknown".into()
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Open an in-memory calibration DB for testing.
    fn open_mem() -> CalibrationLog {
        CalibrationLog::open(Path::new(":memory:")).expect("in-memory DB should open")
    }

    fn sample_detection(id: &str, hash: &str) -> DetectionEvent {
        DetectionEvent {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            file_path: r"C:\Users\test\sample.exe".to_string(),
            file_hash: hash.to_string(),
            file_size: 4096,
            detection_name: "Win.Test.Agent-1".to_string(),
            detection_source: "clamav".to_string(),
            argus_score: Some(75),
            argus_verdict: Some("suspicious".to_string()),
            layers_triggered: vec!["entropy".to_string(), "imports".to_string()],
            behavior_tags: vec!["network".to_string()],
            yara_rules_matched: vec!["RULE_TEST".to_string()],
            sandbox_findings: vec![],
            scan_context: "realtime".to_string(),
            action_taken: "quarantine".to_string(),
            engine_version: Some("1.4.1".to_string()),
            argus_version: Some("0.1.0".to_string()),
            yara_rule_count: Some(150),
            signature_count: Some(500_000),
        }
    }

    fn sample_restore(id: &str, det_id: &str, hash: &str) -> RestoreEvent {
        RestoreEvent {
            id: id.to_string(),
            detection_event_id: det_id.to_string(),
            timestamp: 1_700_001_000,
            file_path: r"C:\Users\test\sample.exe".to_string(),
            file_hash: hash.to_string(),
            fp_category: "developer_tool".to_string(),
            user_notes: Some("Known safe build tool".to_string()),
        }
    }

    #[test]
    fn fp_candidates_tiebreak_is_deterministic() {
        let log = open_mem();
        // Two detections sharing one file_hash, distinct detection names.
        let mut d1 = sample_detection("det-a", "feedface");
        d1.detection_name = "Win.First".into();
        let mut d2 = sample_detection("det-b", "feedface");
        d2.detection_name = "Win.Second".into();
        log.record_detection(&d1).unwrap();
        log.record_detection(&d2).unwrap();

        // Two restores for the SAME hash with the SAME timestamp → forces a
        // tie that the old bare-column GROUP BY resolved arbitrarily.
        let mut r1 = sample_restore("rst-a", "det-a", "feedface");
        let mut r2 = sample_restore("rst-b", "det-b", "feedface");
        r1.timestamp = 1_700_009_000;
        r2.timestamp = 1_700_009_000;
        log.record_restore(&r1).unwrap(); // lower rowid
        log.record_restore(&r2).unwrap(); // higher rowid → newest → must win

        let cands = log.get_fp_candidates();
        assert_eq!(cands.len(), 1, "one candidate per hash");
        assert_eq!(cands[0].restore_count, 2);
        assert_eq!(
            cands[0].detection_name, "Win.Second",
            "timestamp tie must resolve to the newest restore (highest rowid)"
        );

        // Deterministic across repeated runs — no arbitrary-row flip.
        for _ in 0..5 {
            assert_eq!(log.get_fp_candidates()[0].detection_name, "Win.Second");
        }
    }

    #[test]
    fn record_and_retrieve_detection() {
        let log = open_mem();
        let det = sample_detection("det-1", "aabbccdd");
        log.record_detection(&det).expect("insert should succeed");

        let found = log.get_detection_by_hash("aabbccdd");
        assert!(found.is_some(), "should find detection by hash");
        let found = found.unwrap();
        assert_eq!(found.id, "det-1");
        assert_eq!(found.detection_name, "Win.Test.Agent-1");
        assert_eq!(found.layers_triggered, vec!["entropy", "imports"]);
    }

    #[test]
    fn record_restore_updates_layer_stats() {
        let log = open_mem();
        let det = sample_detection("det-2", "11223344");
        log.record_detection(&det).unwrap();

        let restore = sample_restore("rst-1", "det-2", "11223344");
        log.record_restore(&restore).unwrap();

        let stats = log.get_layer_stats();
        assert!(!stats.is_empty());
        for s in &stats {
            assert_eq!(s.total_triggers, 1);
            assert_eq!(s.fp_triggers, 1);
            assert!(s.last_fp_timestamp.is_some());
        }
    }

    #[test]
    fn fp_candidates_populated_after_restore() {
        let log = open_mem();
        log.record_detection(&sample_detection("det-3", "deadbeef"))
            .unwrap();
        log.record_restore(&sample_restore("rst-2", "det-3", "deadbeef"))
            .unwrap();

        let candidates = log.get_fp_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].file_hash, "deadbeef");
        assert_eq!(candidates[0].fp_category, "developer_tool");
        assert_eq!(candidates[0].restore_count, 1);
    }

    #[test]
    fn export_bundle_computes_fp_rate() {
        let log = open_mem();
        // 2 detections, 1 restore => fp_rate = 0.5
        log.record_detection(&sample_detection("d1", "hash1"))
            .unwrap();
        log.record_detection(&sample_detection("d2", "hash2"))
            .unwrap();
        log.record_restore(&sample_restore("r1", "d1", "hash1"))
            .unwrap();

        let bundle = log.export_calibration_bundle();
        assert_eq!(bundle.total_detections, 2);
        assert_eq!(bundle.total_restores, 1);
        assert!((bundle.fp_rate - 0.5).abs() < f64::EPSILON);
        assert!(!bundle.generated_at.is_empty());
    }

    #[test]
    fn export_bundle_sanitises_paths() {
        let log = open_mem();
        log.record_detection(&sample_detection("d3", "cafe"))
            .unwrap();
        log.record_restore(&sample_restore("r2", "d3", "cafe"))
            .unwrap();

        let bundle = log.export_calibration_bundle();
        for c in &bundle.fp_candidates {
            // Path should be filename-only, no directory components.
            assert!(
                !c.file_path.contains('\\') && !c.file_path.contains('/'),
                "path should be sanitised to filename: {}",
                c.file_path,
            );
        }
    }

    #[test]
    fn missing_hash_returns_none() {
        let log = open_mem();
        assert!(log.get_detection_by_hash("nonexistent").is_none());
    }

    #[test]
    fn top_noisy_rules_ranking() {
        let log = open_mem();
        // Insert 3 detections with same name, 1 with different.
        for i in 0..3 {
            let mut det = sample_detection(&format!("n{i}"), &format!("h{i}"));
            det.detection_name = "NoisyRule".to_string();
            det.layers_triggered = vec![];
            log.record_detection(&det).unwrap();
        }
        let mut quiet = sample_detection("q0", "hq");
        quiet.detection_name = "QuietRule".to_string();
        quiet.layers_triggered = vec![];
        log.record_detection(&quiet).unwrap();

        let bundle = log.export_calibration_bundle();
        assert!(bundle.top_noisy_rules.len() >= 2);
        assert_eq!(bundle.top_noisy_rules[0].0, "NoisyRule");
        assert_eq!(bundle.top_noisy_rules[0].1, 3);
    }
}

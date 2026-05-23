//! Persistent local database for scan history, detections, and activity events.
//!
//! Uses SQLite via rusqlite. The database file lives at:
//!   runtime/state/sentinella.db
//!
//! This module is the only code that touches SQLite. All reads and writes
//! go through the `Database` struct.

use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use tracing::{error, info};

/// The persistent database handle.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) the database at the given path.
    pub fn open(path: &Path) -> Result<Self, String> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create DB directory: {e}"))?;
        }

        let conn = Connection::open(path).map_err(|e| format!("Cannot open database: {e}"))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("PRAGMA failed: {e}"))?;

        // Schema version tracking.
        conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            .map_err(|e| format!("version table: {e}"))?;
        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Create tables if they don't exist.
        // Apply schema (idempotent — uses IF NOT EXISTS).
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("Schema creation failed: {e}"))?;

        // Record current schema version.
        const CURRENT_VERSION: i64 = 3; // v3: added argus_verdicts table.
        if version < CURRENT_VERSION {
            let _ = conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![CURRENT_VERSION],
            );
            info!(
                from = version,
                to = CURRENT_VERSION,
                "database schema updated"
            );
        }

        info!(path = %path.display(), "database opened");
        Ok(Self { conn })
    }

    // ═══════════════════════════════════════════════════════
    //  Scan history
    // ═══════════════════════════════════════════════════════

    pub fn insert_scan(&self, scan: &ScanRow) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO scans (scan_id, scan_type, status, started_at, finished_at, files_scanned, threats_found, errors_count, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan.scan_id, scan.scan_type, scan.status,
                scan.started_at, scan.finished_at,
                scan.files_scanned, scan.threats_found, scan.errors_count,
                scan.duration_ms,
            ],
        ) {
            error!(%e, "failed to insert scan record");
        }
    }

    pub fn recent_scans(&self, limit: u32) -> Vec<ScanRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT scan_id, scan_type, status, started_at, finished_at, files_scanned, threats_found, errors_count, duration_ms
             FROM scans ORDER BY started_at DESC LIMIT ?1"
        ) {
            Ok(s) => s,
            Err(e) => { error!(%e, "query scans failed"); return vec![]; }
        };

        let rows = stmt.query_map(params![limit], |row| {
            Ok(ScanRow {
                scan_id: row.get(0)?,
                scan_type: row.get(1)?,
                status: row.get(2)?,
                started_at: row.get(3)?,
                finished_at: row.get(4)?,
                files_scanned: row.get(5)?,
                threats_found: row.get(6)?,
                errors_count: row.get(7)?,
                duration_ms: row.get(8)?,
            })
        });

        match rows {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "scan query failed");
                vec![]
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Detections
    // ═══════════════════════════════════════════════════════

    pub fn insert_detection(&self, det: &DetectionRow) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO detections (detection_id, scan_id, path, virus_name, detected_at, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                det.detection_id, det.scan_id, det.path,
                det.virus_name, det.detected_at, det.action_taken,
            ],
        ) {
            error!(%e, "failed to insert detection");
        }
    }

    pub fn detections_for_scan(&self, scan_id: &str) -> Vec<DetectionRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT detection_id, scan_id, path, virus_name, detected_at, action_taken FROM detections WHERE scan_id = ?1 ORDER BY detected_at DESC"
        ) { Ok(s) => s, Err(e) => { error!(%e, "query detections failed"); return vec![]; } };
        match stmt.query_map(params![scan_id], |row| {
            Ok(DetectionRow {
                detection_id: row.get(0)?,
                scan_id: row.get(1)?,
                path: row.get(2)?,
                virus_name: row.get(3)?,
                detected_at: row.get(4)?,
                action_taken: row.get(5)?,
            })
        }) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "detections query failed");
                vec![]
            }
        }
    }

    pub fn recent_detections(&self, limit: u32) -> Vec<DetectionRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT detection_id, scan_id, path, virus_name, detected_at, action_taken
             FROM detections ORDER BY detected_at DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "query detections failed");
                return vec![];
            }
        };

        match stmt.query_map(params![limit], |row| {
            Ok(DetectionRow {
                detection_id: row.get(0)?,
                scan_id: row.get(1)?,
                path: row.get(2)?,
                virus_name: row.get(3)?,
                detected_at: row.get(4)?,
                action_taken: row.get(5)?,
            })
        }) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "detection query failed");
                vec![]
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Activity events
    // ═══════════════════════════════════════════════════════

    pub fn insert_activity(&self, evt: &ActivityRow) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO activity (event_id, timestamp, severity, category, title, message, related_scan_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                evt.event_id, evt.timestamp, evt.severity, evt.category,
                evt.title, evt.message, evt.related_scan_id,
            ],
        ) {
            error!(%e, "failed to insert activity");
        }
    }

    pub fn recent_activity(&self, limit: u32) -> Vec<ActivityRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT event_id, timestamp, severity, category, title, message, related_scan_id
             FROM activity ORDER BY timestamp DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "query activity failed");
                return vec![];
            }
        };

        match stmt.query_map(params![limit], |row| {
            Ok(ActivityRow {
                event_id: row.get(0)?,
                timestamp: row.get(1)?,
                severity: row.get(2)?,
                category: row.get(3)?,
                title: row.get(4)?,
                message: row.get(5)?,
                related_scan_id: row.get(6)?,
            })
        }) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "activity query failed");
                vec![]
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Stats
    // ═══════════════════════════════════════════════════════

    pub fn total_scans(&self) -> u64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap_or(0)
    }

    pub fn total_threats(&self) -> u64 {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(threats_found), 0) FROM scans",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0)
    }

    pub fn total_detections(&self) -> u64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM detections", [], |row| row.get(0))
            .unwrap_or(0)
    }

    // ═══════════════════════════════════════════════════════
    //  Quarantine
    // ═══════════════════════════════════════════════════════

    pub fn insert_quarantine_item(&self, item: &QuarantineRow) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO quarantine (quarantine_id, original_path, vault_path, virus_name, sha256, original_size, quarantined_at, scan_id, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![item.quarantine_id, item.original_path, item.vault_path, item.virus_name, item.sha256, item.original_size, item.quarantined_at, item.scan_id, item.status],
        ) { error!(%e, "failed to insert quarantine item"); }
    }

    pub fn get_quarantine_item(&self, id: &str) -> Option<QuarantineRow> {
        self.conn.query_row(
            "SELECT quarantine_id, original_path, vault_path, virus_name, sha256, original_size, quarantined_at, scan_id, status FROM quarantine WHERE quarantine_id = ?1",
            params![id],
            |row| Ok(QuarantineRow {
                quarantine_id: row.get(0)?, original_path: row.get(1)?, vault_path: row.get(2)?,
                virus_name: row.get(3)?, sha256: row.get(4)?, original_size: row.get(5)?,
                quarantined_at: row.get(6)?, scan_id: row.get(7)?, status: row.get(8)?,
            }),
        ).ok()
    }

    pub fn list_quarantine(&self) -> Vec<QuarantineRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT quarantine_id, original_path, vault_path, virus_name, sha256, original_size, quarantined_at, scan_id, status FROM quarantine WHERE status = 'quarantined' ORDER BY quarantined_at DESC"
        ) { Ok(s) => s, Err(e) => { error!(%e, "quarantine query failed"); return vec![]; } };
        match stmt.query_map([], |row| {
            Ok(QuarantineRow {
                quarantine_id: row.get(0)?,
                original_path: row.get(1)?,
                vault_path: row.get(2)?,
                virus_name: row.get(3)?,
                sha256: row.get(4)?,
                original_size: row.get(5)?,
                quarantined_at: row.get(6)?,
                scan_id: row.get(7)?,
                status: row.get(8)?,
            })
        }) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                error!(%e, "quarantine query failed");
                vec![]
            }
        }
    }

    pub fn update_quarantine_status(&self, id: &str, status: &str) {
        if let Err(e) = self.conn.execute(
            "UPDATE quarantine SET status = ?1 WHERE quarantine_id = ?2",
            params![status, id],
        ) {
            error!(%e, "quarantine status update failed");
        }
    }

    pub fn quarantine_count(&self) -> u64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM quarantine WHERE status = 'quarantined'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0)
    }

    // ═══════════════════════════════════════════════════════
    //  ARGUS verdicts
    // ═══════════════════════════════════════════════════════

    /// Persist an ARGUS verdict as a forensic record.
    pub fn insert_argus_verdict(&self, v: &ArgusVerdictRow) {
        if let Err(e) = self.conn.execute(
            "INSERT INTO argus_verdicts (scan_id, path, score, verdict, findings_json, sha256, mime_type, file_size, analysis_time_us, engine_version, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                v.scan_id, v.path, v.score, v.verdict, v.findings_json,
                v.sha256, v.mime_type, v.file_size, v.analysis_time_us,
                v.engine_version, v.timestamp,
            ],
        ) {
            error!(%e, "failed to insert ARGUS verdict");
        }
    }

    /// Get recent ARGUS verdicts (across all scans).
    pub fn recent_argus_verdicts(&self, limit: u32) -> Vec<ArgusVerdictRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT scan_id, path, score, verdict, findings_json, sha256, mime_type, file_size, analysis_time_us, engine_version, timestamp
             FROM argus_verdicts ORDER BY timestamp DESC LIMIT ?1"
        ) {
            Ok(s) => s,
            Err(e) => { error!(%e, "argus verdict query failed"); return vec![]; }
        };
        stmt.query_map(params![limit], |row| {
            Ok(ArgusVerdictRow {
                scan_id: row.get(0)?,
                path: row.get(1)?,
                score: row.get(2)?,
                verdict: row.get(3)?,
                findings_json: row.get(4)?,
                sha256: row.get(5)?,
                mime_type: row.get(6)?,
                file_size: row.get(7)?,
                analysis_time_us: row.get(8)?,
                engine_version: row.get(9)?,
                timestamp: row.get(10)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Get ARGUS verdicts for a specific scan.
    pub fn argus_verdicts_for_scan(&self, scan_id: &str) -> Vec<ArgusVerdictRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT scan_id, path, score, verdict, findings_json, sha256, mime_type, file_size, analysis_time_us, engine_version, timestamp
             FROM argus_verdicts WHERE scan_id = ?1 ORDER BY score DESC"
        ) {
            Ok(s) => s,
            Err(e) => { error!(%e, "argus verdict query failed"); return vec![]; }
        };
        stmt.query_map(params![scan_id], |row| {
            Ok(ArgusVerdictRow {
                scan_id: row.get(0)?,
                path: row.get(1)?,
                score: row.get(2)?,
                verdict: row.get(3)?,
                findings_json: row.get(4)?,
                sha256: row.get(5)?,
                mime_type: row.get(6)?,
                file_size: row.get(7)?,
                analysis_time_us: row.get(8)?,
                engine_version: row.get(9)?,
                timestamp: row.get(10)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Get ARGUS verdict for a specific file path (most recent).
    pub fn argus_verdict_for_path(&self, path: &str) -> Option<ArgusVerdictRow> {
        self.conn.query_row(
            "SELECT scan_id, path, score, verdict, findings_json, sha256, mime_type, file_size, analysis_time_us, engine_version, timestamp
             FROM argus_verdicts WHERE path = ?1 ORDER BY timestamp DESC LIMIT 1",
            params![path],
            |row| Ok(ArgusVerdictRow {
                scan_id: row.get(0)?,
                path: row.get(1)?,
                score: row.get(2)?,
                verdict: row.get(3)?,
                findings_json: row.get(4)?,
                sha256: row.get(5)?,
                mime_type: row.get(6)?,
                file_size: row.get(7)?,
                analysis_time_us: row.get(8)?,
                engine_version: row.get(9)?,
                timestamp: row.get(10)?,
            }),
        ).ok()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Schema
// ═══════════════════════════════════════════════════════════════

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    scan_type      TEXT NOT NULL,
    status         TEXT NOT NULL,
    started_at     INTEGER NOT NULL,
    finished_at    INTEGER,
    files_scanned  INTEGER NOT NULL DEFAULT 0,
    threats_found  INTEGER NOT NULL DEFAULT 0,
    errors_count   INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id   TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    path           TEXT NOT NULL,
    virus_name     TEXT NOT NULL,
    detected_at    INTEGER NOT NULL,
    action_taken   TEXT NOT NULL DEFAULT 'none',
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS activity (
    event_id         TEXT PRIMARY KEY,
    timestamp        INTEGER NOT NULL,
    severity         TEXT NOT NULL,
    category         TEXT NOT NULL,
    title            TEXT NOT NULL,
    message          TEXT NOT NULL,
    related_scan_id  TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id  TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    vault_path     TEXT NOT NULL,
    virus_name     TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    original_size  INTEGER NOT NULL,
    quarantined_at INTEGER NOT NULL,
    scan_id        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'quarantined'
);

CREATE TABLE IF NOT EXISTS argus_verdicts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL,
    path            TEXT NOT NULL,
    score           INTEGER NOT NULL,
    verdict         TEXT NOT NULL,
    findings_json   TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    mime_type       TEXT,
    file_size       INTEGER NOT NULL DEFAULT 0,
    analysis_time_us INTEGER NOT NULL DEFAULT 0,
    engine_version  TEXT NOT NULL,
    timestamp       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_scan ON detections(scan_id);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_argus_scan ON argus_verdicts(scan_id);
CREATE INDEX IF NOT EXISTS idx_argus_path ON argus_verdicts(path);
CREATE INDEX IF NOT EXISTS idx_argus_score ON argus_verdicts(score DESC);
CREATE INDEX IF NOT EXISTS idx_argus_time ON argus_verdicts(timestamp DESC);
";

// ═══════════════════════════════════════════════════════════════
//  Row types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanRow {
    pub scan_id: String,
    pub scan_type: String,
    pub status: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub errors_count: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionRow {
    pub detection_id: String,
    pub scan_id: String,
    pub path: String,
    pub virus_name: String,
    pub detected_at: i64,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityRow {
    pub event_id: String,
    pub timestamp: i64,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub message: String,
    pub related_scan_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineRow {
    pub quarantine_id: String,
    pub original_path: String,
    pub vault_path: String,
    pub virus_name: String,
    pub sha256: String,
    pub original_size: u64,
    pub quarantined_at: i64,
    pub scan_id: String,
    pub status: String,
}

/// ARGUS verdict record — a forensic intelligence record.
#[derive(Debug, Clone, Serialize)]
pub struct ArgusVerdictRow {
    pub scan_id: String,
    pub path: String,
    pub score: u32,
    pub verdict: String,
    pub findings_json: String,
    pub sha256: String,
    pub mime_type: Option<String>,
    pub file_size: u64,
    pub analysis_time_us: u64,
    pub engine_version: String,
    pub timestamp: i64,
}

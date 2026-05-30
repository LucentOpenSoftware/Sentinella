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
        // synchronous=FULL: fsync on every commit so security-sensitive writes
        // (quarantine status flips, scan history) survive power loss. Default
        // WAL+NORMAL returns Ok after page-cache write, NOT after fsync — a
        // crash between vault-purge and the next WAL checkpoint would revert
        // a "released" row to "quarantined" with no vault file, leaving the
        // user unable to restore and the realtime watcher re-quarantining
        // the restored file in a loop. ~10-30ms per commit is the right
        // tradeoff for a security DB.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )
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

        // Always run CREATE TABLE IF NOT EXISTS for new tables and base schema.
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("Schema creation failed: {e}"))?;

        // Migration framework: per-version DDL applied incrementally.
        // Each entry is (target_version, DDL). When upgrading from N to M,
        // every migration with version > N and <= M is applied in order.
        // Use ALTER TABLE / CREATE INDEX IF NOT EXISTS — NOT CREATE TABLE
        // (base schema handles that).
        const MIGRATIONS: &[(i64, &str)] = &[
            // v4: per-job perf telemetry — bytes scanned and the ClamAV/ARGUS
            // phase split. Older rows back-fill to 0 via the column default.
            (
                4,
                "ALTER TABLE scans ADD COLUMN bytes_scanned INTEGER NOT NULL DEFAULT 0; \
                 ALTER TABLE scans ADD COLUMN clamav_phase_us INTEGER NOT NULL DEFAULT 0; \
                 ALTER TABLE scans ADD COLUMN argus_phase_us INTEGER NOT NULL DEFAULT 0;",
            ),
        ];

        const CURRENT_VERSION: i64 = 4; // v4: per-job perf fields on scans.
        let target = MIGRATIONS.iter().map(|(v, _)| *v).max().unwrap_or(CURRENT_VERSION).max(CURRENT_VERSION);

        if version < target {
            // R3-21: wrap each migration in BEGIN/COMMIT so partial DDL
            // failure rolls back cleanly.
            //
            // Audit fix: only advance the recorded schema version to the
            // highest CONTIGUOUSLY-applied migration. Previously the version
            // was bumped to `target` unconditionally even when a migration
            // failed + rolled back — marking the DB as fully migrated so it
            // never retried, a permanent silent schema inconsistency.
            // Migrations apply in ascending order; a failure stops the chain
            // (later migrations may depend on the failed one).
            let mut applied = version;
            for (mig_v, ddl) in MIGRATIONS {
                if *mig_v > version && *mig_v <= target {
                    info!(version = *mig_v, "applying schema migration");
                    let wrapped = format!("BEGIN; {ddl} COMMIT;");
                    if let Err(e) = conn.execute_batch(&wrapped) {
                        let _ = conn.execute_batch("ROLLBACK;");
                        tracing::error!(version = *mig_v, %e, "schema migration FAILED (rolled back) — halting migration chain");
                        break;
                    }
                    applied = *mig_v;
                }
            }
            // If MIGRATIONS is empty (only base-schema bump), `applied` stays
            // at `version`; still record `target` so the base CURRENT_VERSION
            // is captured. Otherwise record the highest applied migration.
            let record = applied.max(if MIGRATIONS.is_empty() { target } else { applied });
            let _ = conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![record],
            );
            info!(from = version, to = record, requested = target, "database schema updated");
        }

        info!(path = %path.display(), "database opened");
        Ok(Self { conn })
    }

    // ═══════════════════════════════════════════════════════
    //  Scan history
    // ═══════════════════════════════════════════════════════

    pub fn insert_scan(&self, scan: &ScanRow) {
        // R9: mirror R8-LETHAL #2 retention pattern. Daemon uptime in years
        // would otherwise grow `scans` unbounded.
        const RETENTION_ROWS: i64 = 5_000;
        if let Err(e) = self.conn.execute(
            "INSERT INTO scans (scan_id, scan_type, status, started_at, finished_at, files_scanned, threats_found, errors_count, duration_ms, bytes_scanned, clamav_phase_us, argus_phase_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                scan.scan_id, scan.scan_type, scan.status,
                scan.started_at, scan.finished_at,
                scan.files_scanned, scan.threats_found, scan.errors_count,
                scan.duration_ms,
                scan.bytes_scanned, scan.clamav_phase_us, scan.argus_phase_us,
            ],
        ) {
            error!(%e, "failed to insert scan record");
        }
        let _ = self.conn.execute(
            // Audit fix: tie-break on rowid so same-second timestamps never
            // evict a newer row (rowid is monotonic insert order).
            "DELETE FROM scans WHERE rowid NOT IN (
                SELECT rowid FROM scans ORDER BY started_at DESC, rowid DESC LIMIT ?1
            )",
            params![RETENTION_ROWS],
        );
    }

    pub fn recent_scans(&self, limit: u32) -> Vec<ScanRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT scan_id, scan_type, status, started_at, finished_at, files_scanned, threats_found, errors_count, duration_ms, bytes_scanned, clamav_phase_us, argus_phase_us
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
                bytes_scanned: row.get(9)?,
                clamav_phase_us: row.get(10)?,
                argus_phase_us: row.get(11)?,
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
        // R9: cap path/virus_name + bounded retention.
        const MAX_PATH: usize = 4096;
        const MAX_VIRUS: usize = 256;
        const MAX_ACTION: usize = 64;
        const RETENTION_ROWS: i64 = 20_000;

        let truncate = |s: &str, max: usize| {
            if s.len() <= max {
                s.to_string()
            } else {
                let mut end = max;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                s[..end].to_string()
            }
        };
        let path = truncate(&det.path, MAX_PATH);
        let virus_name = truncate(&det.virus_name, MAX_VIRUS);
        let action_taken = truncate(&det.action_taken, MAX_ACTION);

        if let Err(e) = self.conn.execute(
            "INSERT INTO detections (detection_id, scan_id, path, virus_name, detected_at, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                det.detection_id, det.scan_id, path,
                virus_name, det.detected_at, action_taken,
            ],
        ) {
            error!(%e, "failed to insert detection");
        }
        let _ = self.conn.execute(
            "DELETE FROM detections WHERE rowid NOT IN (
                SELECT rowid FROM detections ORDER BY detected_at DESC, rowid DESC LIMIT ?1
            )",
            params![RETENTION_ROWS],
        );
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
        // R8-LETHAL #2: cap field lengths + bounded retention.
        //
        // Internal callers feed long strings (file paths up to MAX_PATH,
        // chained error messages, virus descriptions). Without these
        // caps the activity table can grow multi-GB over months of
        // uptime → daemon startup balloons → OOM on disk-pressured boxes.
        const MAX_TITLE: usize = 256;
        const MAX_MESSAGE: usize = 2048;
        const MAX_CATEGORY: usize = 48;
        const MAX_SEVERITY: usize = 24;
        const MAX_EVENT_ID: usize = 64;
        const RETENTION_ROWS: i64 = 10_000;

        let truncate = |s: &str, max: usize| {
            if s.len() <= max {
                s.to_string()
            } else {
                // Be UTF-8 safe — `s[..max]` would panic on a multi-byte
                // boundary. Step back to the nearest char boundary.
                let mut end = max;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                s[..end].to_string()
            }
        };

        let severity = truncate(&evt.severity, MAX_SEVERITY);
        let category = truncate(&evt.category, MAX_CATEGORY);
        let title = truncate(&evt.title, MAX_TITLE);
        let message = truncate(&evt.message, MAX_MESSAGE);
        let event_id = truncate(&evt.event_id, MAX_EVENT_ID);

        if let Err(e) = self.conn.execute(
            "INSERT INTO activity (event_id, timestamp, severity, category, title, message, related_scan_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![event_id, evt.timestamp, severity, category, title, message, evt.related_scan_id],
        ) {
            error!(%e, "failed to insert activity");
        }

        // Bounded retention: delete all but the most recent N rows. Cheap
        // (id + timestamp index assumed). Runs on every insert; SQLite
        // turns this into a no-op once the table is at steady state.
        let _ = self.conn.execute(
            "DELETE FROM activity WHERE rowid NOT IN (
                SELECT rowid FROM activity ORDER BY timestamp DESC, rowid DESC LIMIT ?1
            )",
            params![RETENTION_ROWS],
        );
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

    pub fn update_quarantine_status(&self, id: &str, status: &str) -> Result<(), String> {
        // Returns Result so callers in security-sensitive paths (restore)
        // can commit-then-cleanup: only purge the vault after the DB write
        // succeeds. Previously this swallowed errors → a crash between vault
        // delete and DB write left the row "quarantined" with no vault →
        // unrecoverable + the realtime watcher could re-quarantine the
        // restored file in a loop. Cleanup-only callers may still use `let _`.
        self.conn
            .execute(
                "UPDATE quarantine SET status = ?1 WHERE quarantine_id = ?2",
                params![status, id],
            )
            .map_err(|e| {
                error!(%e, "quarantine status update failed");
                format!("DB update failed: {e}")
            })
            .map(|_| ())
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
        // R9: bounded retention + cap findings_json (could be MBs from
        // adversarial flood of weight-1 findings — R4-CV4 priority-cap
        // limits scoring impact but raw JSON storage was uncapped).
        const MAX_PATH: usize = 4096;
        const MAX_FINDINGS_JSON: usize = 64 * 1024;
        const RETENTION_ROWS: i64 = 20_000;

        let truncate = |s: &str, max: usize| {
            if s.len() <= max {
                s.to_string()
            } else {
                let mut end = max;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                s[..end].to_string()
            }
        };
        let path = truncate(&v.path, MAX_PATH);
        let findings_json = if v.findings_json.len() <= MAX_FINDINGS_JSON {
            v.findings_json.clone()
        } else {
            "[]".to_string() // Drop oversized JSON entirely; keep a valid sentinel.
        };

        if let Err(e) = self.conn.execute(
            "INSERT INTO argus_verdicts (scan_id, path, score, verdict, findings_json, sha256, mime_type, file_size, analysis_time_us, engine_version, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                v.scan_id, path, v.score, v.verdict, findings_json,
                v.sha256, v.mime_type, v.file_size, v.analysis_time_us,
                v.engine_version, v.timestamp,
            ],
        ) {
            error!(%e, "failed to insert ARGUS verdict");
        }
        let _ = self.conn.execute(
            "DELETE FROM argus_verdicts WHERE rowid NOT IN (
                SELECT rowid FROM argus_verdicts ORDER BY timestamp DESC, rowid DESC LIMIT ?1
            )",
            params![RETENTION_ROWS],
        );
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
    scan_id          TEXT PRIMARY KEY,
    scan_type        TEXT NOT NULL,
    status           TEXT NOT NULL,
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    files_scanned    INTEGER NOT NULL DEFAULT 0,
    threats_found    INTEGER NOT NULL DEFAULT 0,
    errors_count     INTEGER NOT NULL DEFAULT 0,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    bytes_scanned    INTEGER NOT NULL DEFAULT 0,
    clamav_phase_us  INTEGER NOT NULL DEFAULT 0,
    argus_phase_us   INTEGER NOT NULL DEFAULT 0
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

#[derive(Debug, Clone, Default, Serialize)]
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
    /// Total bytes ClamAV actually scanned (v0.1.6+; older rows = 0).
    #[serde(default)]
    pub bytes_scanned: u64,
    /// Aggregated ClamAV phase time across the job, µs (v0.1.6+; older rows = 0).
    #[serde(default)]
    pub clamav_phase_us: u64,
    /// Aggregated ARGUS phase time across the job, µs (v0.1.6+; older rows = 0).
    #[serde(default)]
    pub argus_phase_us: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "senti-db-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// v4 schema: scans rows round-trip the new perf fields and older rows
    /// surface as 0 (column default).
    #[test]
    fn scan_row_v4_perf_fields_roundtrip() {
        let path = tmp_db("scans-v4");
        let db = Database::open(&path).expect("open db");

        let row = ScanRow {
            scan_id: "test-1".into(),
            scan_type: "file".into(),
            status: "clean".into(),
            started_at: 1_700_000_000,
            finished_at: Some(1_700_000_001),
            files_scanned: 1,
            threats_found: 0,
            errors_count: 0,
            duration_ms: 1_000,
            bytes_scanned: 4_096,
            clamav_phase_us: 1_234,
            argus_phase_us: 5_678,
        };
        db.insert_scan(&row);

        // Also insert one with all-zero perf fields to model legacy/back-filled.
        let legacy = ScanRow {
            scan_id: "test-legacy".into(),
            scan_type: "full".into(),
            status: "clean".into(),
            started_at: 1_700_000_002,
            finished_at: Some(1_700_000_005),
            files_scanned: 42,
            threats_found: 0,
            errors_count: 0,
            duration_ms: 3_000,
            ..ScanRow::default()
        };
        db.insert_scan(&legacy);

        let rows = db.recent_scans(10);
        assert_eq!(rows.len(), 2);

        let got = rows.iter().find(|r| r.scan_id == "test-1").expect("row");
        assert_eq!(got.bytes_scanned, 4_096);
        assert_eq!(got.clamav_phase_us, 1_234);
        assert_eq!(got.argus_phase_us, 5_678);

        let legacy_back = rows
            .iter()
            .find(|r| r.scan_id == "test-legacy")
            .expect("legacy row");
        assert_eq!(legacy_back.bytes_scanned, 0);
        assert_eq!(legacy_back.clamav_phase_us, 0);
        assert_eq!(legacy_back.argus_phase_us, 0);

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

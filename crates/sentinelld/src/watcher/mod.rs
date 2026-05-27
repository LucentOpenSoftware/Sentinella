//! Real-time filesystem watcher — user-mode, post-write detection.
//!
//! Uses the `notify` crate (ReadDirectoryChangesW on Windows, inotify on Linux).
//! Debounces rapid events and feeds new/modified files into the scan queue.

pub mod file_identity;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};
use tracing::{debug, error, info, warn};

use crate::engine::ClamEngine;
use crate::fish::response::{
    ResponseType, find_suspect_processes, suspend_process, terminate_process,
};
use crate::fish::{FileMutationEvent, FishDecision, MutationKind};

/// Max file size the watcher will scan (256 MB).
const WATCHER_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Debounce delay — wait for writes to stabilize. Reduced from 800ms in v0.1.4:
/// small files (downloaded EICAR, scripts, droppers) often write in a single
/// chunk and don't need long coalescing. Long debounce loses races against
/// other AVs with kernel filters. Large files still benefit because writes
/// continue to extend the debounce window.
const DEBOUNCE_MS: u64 = 150;
/// Maximum size of file to fast-path scan (skip debounce) on Create events.
/// Files written atomically (rename-from-temp) and small files (≤2 MB) are
/// scanned immediately. Larger files fall through to the normal debounce
/// path so multi-chunk writes coalesce.
const FAST_PATH_MAX_SIZE: u64 = 2 * 1024 * 1024;
const DEBOUNCE_CAP: usize = 10_000;
const OVERFLOW_RESCAN_CAP: usize = 2_000;

/// Simple guard: don't sandbox the same file twice within 60 seconds.
const SANDBOX_DEDUP_SECS: u64 = 60;

/// Maximum score_delta a single sandbox detonation can contribute.
const SANDBOX_MAX_SCORE_DELTA: i32 = 50;

/// State of the real-time watcher.
#[allow(dead_code)]
pub struct RealtimeWatcher {
    running: Arc<AtomicBool>,
    events_count: Arc<AtomicU64>,
    detections_count: Arc<AtomicU64>,
    watched_roots: Vec<PathBuf>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl RealtimeWatcher {
    /// Start watching the given directories for file changes.
    pub fn start(
        roots: Vec<PathBuf>,
        engine: Arc<ClamEngine>,
        state: Arc<crate::ipc::AppState>,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let events_count = Arc::new(AtomicU64::new(0));
        let detections_count = Arc::new(AtomicU64::new(0));
        let cache = Arc::new(crate::scan::cache::ScanCache::new());

        let r = Arc::clone(&running);
        let ec = Arc::clone(&events_count);
        let dc = Arc::clone(&detections_count);
        let watched = roots.clone();
        let cache_clone = Arc::clone(&cache);

        let thread = std::thread::spawn(move || {
            watcher_loop(watched, engine, state, r, ec, dc, cache_clone);
        });

        info!(dirs = roots.len(), "real-time watcher started");

        Ok(Self {
            running,
            events_count,
            detections_count,
            watched_roots: roots,
            _thread: Some(thread),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn events_count(&self) -> u64 {
        self.events_count.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn detections_count(&self) -> u64 {
        self.detections_count.load(Ordering::Relaxed)
    }

    pub fn watched_roots(&self) -> &[PathBuf] {
        &self.watched_roots
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("real-time watcher stop requested");
    }
}

impl Drop for RealtimeWatcher {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Main watcher loop — runs in a dedicated thread.
fn watcher_loop(
    roots: Vec<PathBuf>,
    engine: Arc<ClamEngine>,
    state: Arc<crate::ipc::AppState>,
    running: Arc<AtomicBool>,
    events_count: Arc<AtomicU64>,
    detections_count: Arc<AtomicU64>,
    cache: Arc<crate::scan::cache::ScanCache>,
) {
    // Channel for debounced events.
    let (tx, rx) = std::sync::mpsc::channel();

    // Create the filesystem watcher.
    let mut watcher =
        match notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                let _ = tx.send(event);
            }
            Err(e) => warn!(%e, "watcher error"),
        }) {
            Ok(w) => w,
            Err(e) => {
                error!(%e, "failed to create filesystem watcher");
                return;
            }
        };

    // Register watched directories.
    for root in &roots {
        if root.exists() {
            match watcher.watch(root, RecursiveMode::Recursive) {
                Ok(()) => info!(path = %root.display(), "watching directory"),
                Err(e) => warn!(path = %root.display(), %e, "failed to watch"),
            }
        } else {
            debug!(path = %root.display(), "skipping non-existent directory");
        }
    }

    // Debounce set — paths seen recently.
    let mut recent: HashSet<PathBuf> = HashSet::new();
    let mut overflow_dirs: HashSet<PathBuf> = HashSet::new();
    let mut last_flush = Instant::now();

    // Sandbox dedup guard — tracks recently detonated files to prevent
    // double score_delta application when the watcher fires twice for
    // the same path in rapid succession.
    let mut sandbox_dedup: HashMap<PathBuf, Instant> = HashMap::new();

    // TOCTOU race prevention diagnostics.
    let race_diag = file_identity::RaceDiagnostics::new();
    // Snapshot of watched roots for identity revalidation (TOCTOU).
    let watched_roots_vec: Vec<PathBuf> = roots.clone();

    // FISH — observe-only ransomware detection via AppState's shared MutationWindow.

    while running.load(Ordering::Relaxed) {
        // Wait for events with timeout.
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                // ── FISH: feed all relevant events (observe-only) ──
                fish_feed_event(&event, &state);

                // Only care about file creation and modification for scanning.
                let dominated = matches!(
                    event.kind,
                    EventKind::Create(CreateKind::File)
                        | EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Modify(ModifyKind::Any)
                        | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
                        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
                );
                if !dominated {
                    continue;
                }

                // Fast-path: Create events for small files are scanned
                // immediately without waiting for debounce. EICAR, scripts,
                // and atomically-renamed downloads land here.
                let is_create = matches!(event.kind, EventKind::Create(CreateKind::File));

                for path in event.paths {
                    if !path.is_file() {
                        continue;
                    }
                    if is_create {
                        // Check file size — if small enough, scan now and skip debounce.
                        if let Ok(meta) = std::fs::metadata(&path) {
                            if meta.len() <= FAST_PATH_MAX_SIZE {
                                // Force immediate flush by setting last_flush far in the past.
                                recent.insert(path);
                                last_flush = Instant::now()
                                    .checked_sub(Duration::from_millis(DEBOUNCE_MS + 100))
                                    .unwrap_or(last_flush);
                                continue;
                            }
                        }
                    }
                    if recent.len() < DEBOUNCE_CAP {
                        recent.insert(path);
                    } else if let Some(parent) = path.parent() {
                        overflow_dirs.insert(parent.to_path_buf());
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Flush debounce buffer after delay.
        if (!recent.is_empty() || !overflow_dirs.is_empty())
            && last_flush.elapsed() >= Duration::from_millis(DEBOUNCE_MS)
        {
            let mut batch: Vec<PathBuf> = recent.drain().collect();
            if !overflow_dirs.is_empty() {
                let dirs: Vec<PathBuf> = overflow_dirs.drain().collect();
                let before = batch.len();
                for dir in &dirs {
                    collect_overflow_rescan_files(dir, &mut batch, OVERFLOW_RESCAN_CAP);
                }
                warn!(
                    dirs = dirs.len(),
                    queued = batch.len().saturating_sub(before),
                    cap = DEBOUNCE_CAP,
                    "watcher debounce overflow; queued targeted directory rescan"
                );
            }
            last_flush = Instant::now();
            state.touch_watcher_heartbeat();
            let config = crate::config::Config::load(None).unwrap_or_default();

            for path in batch {
                events_count.fetch_add(1, Ordering::Relaxed);

                // Skip excluded / system files / own files / build dirs / transient artifacts.
                if crate::scan::should_skip_file(&path) {
                    continue;
                }
                if crate::scan::is_sentinella_path(&path) {
                    continue;
                }
                if crate::scan::is_build_or_dev_path(&path) {
                    continue;
                }
                if crate::scan::is_transient_build_artifact(&path) {
                    continue;
                }
                if crate::scan::is_excluded(
                    &path,
                    &config.excluded_paths,
                    &config.excluded_extensions,
                ) {
                    continue;
                }

                // Smart extension filtering — real-time watcher focuses on
                // file types that can contain executable content. Pure data
                // files (images, fonts, logs) are skipped for performance.
                if let Some(ext) = path.extension() {
                    let ext_lower = ext.to_string_lossy().to_lowercase();
                    // Skip known-safe data file types.
                    if matches!(
                        ext_lower.as_str(),
                        // Logs/temp/IDE artifacts.
                        "log" | "tmp" | "bak" | "swp" | "swo"
                        | "db-journal" | "db-wal" | "db-shm"
                        // Images (never executable).
                        | "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp"
                        | "svg" | "ico" | "tiff" | "tif"
                        // Fonts.
                        | "woff" | "woff2" | "ttf" | "otf" | "eot"
                        // Audio/video (scanned on-demand, not realtime).
                        | "mp3" | "mp4" | "mkv" | "avi" | "wav" | "flac"
                        | "ogg" | "m4a" | "webm"
                        // Build artifacts (Rust, C/C++, .NET, Node).
                        | "rlib" | "rmeta" | "fingerprint" | "incremental"
                        | "pdb" | "ilk" | "lib" | "exp" | "map"
                        | "d" | "o" | "obj" | "cache" | "lock"
                        // Pure text data.
                        | "csv" | "tsv" | "yaml" | "yml" | "toml"
                        | "json" | "xml" | "ini" | "cfg" | "conf"
                        | "md" | "txt" | "rst" | "tex"
                        // Quarantine vault files.
                        | "vault"
                    ) {
                        continue;
                    }
                }

                // Skip large files.
                let path_meta = match std::fs::metadata(&path) {
                    Ok(meta) if meta.len() > WATCHER_MAX_FILE_SIZE => continue,
                    Ok(meta) if meta.len() == 0 => continue, // Empty files.
                    Err(_) => continue,
                    Ok(meta) => meta,
                };

                // Cooldown: skip files created less than 500ms ago — but ONLY
                // for paths that look like build artifact zones. Originally
                // this applied to all files to dodge `cargo build` contention,
                // but it also added 500ms latency to every legit download
                // (EICAR landed in Downloads → 500ms cooldown → Defender wins).
                //
                // User-visible folders (Downloads, Desktop, Documents, OneDrive)
                // and download partials never need this cooldown — those are
                // exactly the paths where we MUST scan as fast as possible.
                let path_str_lower = path.to_string_lossy().to_ascii_lowercase();
                let is_user_visible_target = path_str_lower.contains("\\downloads\\")
                    || path_str_lower.contains("\\desktop\\")
                    || path_str_lower.contains("\\documents\\")
                    || path_str_lower.contains("\\onedrive\\");
                if !is_user_visible_target {
                    if let Ok(created) = path_meta.created() {
                        if let Ok(age) = created.elapsed() {
                            if age < std::time::Duration::from_millis(500) {
                                continue;
                            }
                        }
                    }
                }

                // TOCTOU fix: capture file identity snapshot BEFORE scan.
                // Replaces old is_symlink() check — now detects ALL reparse
                // points (junctions, mount points) and captures canonical path +
                // metadata for revalidation before scan and quarantine.
                let file_id = match file_identity::FileIdentity::capture(&path) {
                    Some(id) => id,
                    None => {
                        // Reparse point or unresolvable → reject.
                        race_diag.reparse_rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                // Check scan cache — skip if recently scanned and clean.
                if let Some(true) = cache.check_with_metadata(&path, &path_meta) {
                    debug!(file = %path.display(), "cache hit: clean");
                    continue;
                }

                // TOCTOU Phase 2: revalidate identity before scan.
                // Between debounce buffer flush and now, the file may have been
                // replaced by a symlink/junction. Reject if identity changed.
                if let Err(mismatch) = file_id.revalidate(&watched_roots_vec) {
                    debug!(
                        file = %path.display(),
                        reason = %mismatch,
                        "TOCTOU: identity changed before scan, skipping"
                    );
                    race_diag.race_skipped.fetch_add(1, Ordering::Relaxed);
                    race_diag.identity_changed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Verify file is readable (not locked by another process).
                match std::fs::File::open(&path) {
                    Ok(_) => {} // File is accessible.
                    Err(_) => {
                        continue;
                    } // Skip locked/inaccessible files.
                }

                // ── Budget-bounded realtime scan ──────────────
                let rt_profile = argus::profile::ScanProfile::realtime();
                let rt_budget = rt_profile.budget.clone();
                let rt_cancel = std::sync::atomic::AtomicBool::new(false);
                let rt_tracker = argus::budget::BudgetTracker::new(
                    rt_budget,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );

                // Record realtime scan activity for residency management.
                state.activity_tracker.record_realtime_scan();

                // Layer 0: ClamAV signature scan (with budget check).
                let clamav_start = std::time::Instant::now();
                let result = state.scan_file_clamav(&engine, &path, &rt_cancel);
                if rt_tracker.phase_expired(clamav_start, rt_tracker.budget().max_clamav_duration) {
                    rt_tracker.record_timeout(argus::budget::TimeoutReason::ClamAvTimeout);
                }

                if !path.exists() {
                    continue;
                }

                // Check total budget before ARGUS — realtime MUST NOT stall.
                let mut argus_verdict = if rt_tracker.is_expired() {
                    rt_tracker.record_timeout(argus::budget::TimeoutReason::TotalTimeout);
                    debug!(file = %path.display(), "realtime budget exhausted, skipping ARGUS");
                    // H4 fix: partial analysis (ARGUS skipped) → NEVER cache as clean.
                    // Budget exhaustion means incomplete analysis. Only cache ClamAV positives.
                    // Clean-looking files remain uncached → will be re-scanned next encounter.
                    if result.infected {
                        cache.record_with_metadata(&path, &path_meta, false);
                    }
                    // else: deliberately NOT cached — next scan attempt will retry.
                    if result.infected {
                        // ClamAV positive — still report threat even without ARGUS.
                        let threat_name = result.virus_name.clone().unwrap_or("Unknown".into());
                        warn!(file = %path.display(), threat = %threat_name, "REALTIME THREAT (budget-partial)");
                        detections_count.fetch_add(1, Ordering::Relaxed);
                        let path_str = path.to_string_lossy().to_string();
                        match state.quarantine_file(&path_str, &threat_name, "realtime") {
                            Ok(q) => {
                                info!(id = %q.quarantine_id, "auto-quarantined (budget-partial)")
                            }
                            Err(e) => warn!(%e, "auto-quarantine failed"),
                        }
                    }
                    continue;
                } else if config.heuristic_alerts {
                    let argus_start = std::time::Instant::now();
                    let v = state.argus().analyze_file(&path);
                    if rt_tracker.phase_expired(argus_start, rt_tracker.budget().max_yara_duration)
                    {
                        rt_tracker.record_timeout(argus::budget::TimeoutReason::YaraTimeout);
                    }
                    v
                } else {
                    argus::ArgusVerdict {
                        path: path.to_string_lossy().to_string(),
                        file_size: 0,
                        sha256: String::new(),
                        mime_type: None,
                        score: 0,
                        verdict: argus::verdict::Verdict::Clean,
                        findings: vec![],
                        analysis_time_us: 0,
                        engine_version: argus::ENGINE_VERSION,
                        timestamp: 0,
                        explanation: argus::verdict::VerdictExplanation::default(),
                        timing: None,
                    }
                };

                // ── ConvergenceLedger (ARCH-H1 fix: realtime uses same path as manual) ──
                let mut ledger =
                    crate::convergence::ConvergenceLedger::new(&argus_verdict, result.infected);

                // ── ADS content scan (ASTRA, realtime: exe streams only) ──
                if !rt_tracker.is_expired() {
                    let ads_policy = crate::scan::ads::ads_policy_for_profile(&rt_profile);
                    let streams = crate::scan::ads::enumerate_ads(&path);
                    let filtered = crate::scan::ads::filter_streams(streams, ads_policy);
                    for stream in &filtered {
                        if rt_tracker.is_expired() {
                            break;
                        }
                        let ads_result = crate::scan::ads::scan_ads_content(stream, state.argus());
                        for finding in ads_result.content_findings {
                            ledger.add_evidence("ADS", finding);
                        }
                    }
                }

                // ── Trust graph (realtime: query discount, defer observation) ──
                // H7 fix: observe() moved AFTER finalize — only clean files build trust.
                // Previously, malicious files observed BEFORE scoring → slowly earned trust.
                if let Some(tg) = state.trust_graph() {
                    let file_key = path.to_string_lossy().to_lowercase();
                    // Query existing trust level for discount (read-only).
                    let trust_q = tg.query(&file_key);
                    if trust_q.confidence_discount > 0 {
                        let trust_finding = crate::trust_graph::trust_finding(&trust_q);
                        ledger.apply_trust_discount(trust_q.confidence_discount, trust_finding);
                    }
                }

                // ── Persistence intelligence ──
                if let Some(ptype) = crate::persistence::check_persistence_context(&path) {
                    let finding = crate::persistence::persistence_finding(ptype, &path, false);
                    ledger.add_evidence("Persistence", finding);
                }

                // ── PLM lineage correlation ──
                if let Some(plm) = state.plm() {
                    if let Some(chain) = plm.query_by_image_path(&path) {
                        if let Some(finding) = crate::plm::lineage_finding(&chain) {
                            ledger.add_evidence("PLM", finding);
                        }
                    }
                }

                // ── Ecosystem convergence ──
                if ledger.base_score > 0 {
                    let file_key = path.to_string_lossy().to_string();
                    if !ledger.findings.is_empty() {
                        state.ecosystem.add_evidence(
                            &file_key,
                            crate::ecosystem::EcosystemEvidence {
                                source: crate::ecosystem::EvidenceSource::Argus,
                                timestamp: chrono::Utc::now().timestamp(),
                                description: format!(
                                    "{} findings, score {}",
                                    ledger.findings.len(),
                                    ledger.base_score
                                ),
                                weight: (ledger.base_score / 10).min(10),
                            },
                        );
                    }
                    if let Some(eco) = state.ecosystem.get(&file_key) {
                        if let Some(finding) = crate::ecosystem::ecosystem_finding(&eco) {
                            ledger.add_evidence("Ecosystem", finding);
                        }
                    }
                }

                // ── Finalize convergence ──
                let (final_score, final_verdict, _) = ledger.finalize();
                argus_verdict.score = final_score;
                argus_verdict.verdict = final_verdict;
                argus_verdict.findings = ledger.findings.clone();
                ledger.patch_explanation(&mut argus_verdict.explanation, final_score);

                // H7 fix: deferred trust observation — only clean files build familiarity.
                // Prevents malware from slowly earning trust through repeated execution.
                if final_score == 0 && !result.infected {
                    if let Some(tg) = state.trust_graph() {
                        let file_key = path.to_string_lossy().to_lowercase();
                        tg.observe(
                            &file_key,
                            crate::trust_graph::TrustNodeKind::Executable,
                            None,
                        );
                    }
                }

                // ── Behavioral sandbox routing (async) ────────────
                // ARGUS 26-75 + sandbox enabled → detonate on background thread.
                // Watcher thread NEVER blocks on sandbox (up to 35s).
                // If sandbox raises score into threat range, background thread
                // handles quarantine + notification autonomously.
                let sandbox_config = config.sandbox.clone();
                if crate::sandbox_worker::should_sandbox(argus_verdict.score, &sandbox_config)
                    && !result.infected
                    && path
                        .extension()
                        .map(|e| {
                            let e = e.to_string_lossy().to_lowercase();
                            matches!(
                                e.as_str(),
                                "exe" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "msi"
                            )
                        })
                        .unwrap_or(false)
                // Only detonate executable types.
                {
                    // Guard: don't sandbox the same file twice within SANDBOX_DEDUP_SECS.
                    let now = Instant::now();
                    // Evict stale entries.
                    sandbox_dedup
                        .retain(|_, ts| now.duration_since(*ts).as_secs() < SANDBOX_DEDUP_SECS);

                    if sandbox_dedup.contains_key(&path) {
                        debug!(
                            file = %path.display(),
                            "sandbox skipped: same file detonated recently"
                        );
                    } else {
                        sandbox_dedup.insert(path.clone(), now);

                        // Fire-and-forget: sandbox runs on background thread.
                        // Watcher continues scanning the next file immediately.
                        let sb_path = path.clone();
                        let sb_state = Arc::clone(&state);
                        let sb_score = argus_verdict.score;
                        let sb_sha256 = argus_verdict.sha256.clone();
                        let sb_dc = Arc::clone(&detections_count);
                        let sb_config = sandbox_config.clone();
                        if let Err(e) = std::thread::Builder::new()
                            .name("watcher-sandbox".into())
                            .spawn(move || {
                                sandbox_detonation_background(
                                    sb_path, sb_state, sb_score, sb_sha256, sb_dc, sb_config,
                                );
                            })
                        {
                            warn!(error = %e, "failed to spawn sandbox background thread");
                            // Not fatal — file already got pre-sandbox verdict.
                        }
                    }
                }

                // Trusted hash whitelist — skip quarantine for manually trusted files.
                if state.is_hash_trusted(&argus_verdict.sha256) {
                    debug!(file = %path.display(), sha256 = argus_verdict.sha256.as_str(), "hash trusted — skipping");
                    cache.record_with_metadata(&path, &path_meta, true);
                    continue;
                }

                // Unified verdict — one file, one detection.
                let (is_threat, threat_name_opt) = crate::ipc::unify_detection_filtered(
                    result.infected,
                    result.virus_name.as_deref(),
                    &argus_verdict,
                    &state.detection_exclusions(),
                );
                let threat_name = threat_name_opt.unwrap_or_default();

                // Update cache.
                if result.error.is_none() {
                    cache.record_with_metadata(&path, &path_meta, !is_threat);
                }

                if is_threat {
                    warn!(
                        file = %path.display(),
                        threat = %threat_name,
                        argus_score = argus_verdict.score,
                        "REAL-TIME THREAT DETECTED",
                    );
                    detections_count.fetch_add(1, Ordering::Relaxed);

                    // Auto memory scan if the detected file is a running process.
                    let path_str_for_mem = path.to_string_lossy().to_string();
                    state.auto_memory_scan_if_running(&path_str_for_mem, argus_verdict.score);

                    // TOCTOU Phase 3: revalidate identity BEFORE quarantine.
                    // Scanning wrong file is bad. Quarantining wrong file is CRITICAL.
                    if let Err(mismatch) = file_id.revalidate(&watched_roots_vec) {
                        warn!(
                            file = %path.display(),
                            reason = %mismatch,
                            "TOCTOU: identity changed before quarantine — PREVENTED"
                        );
                        race_diag
                            .quarantine_race_prevented
                            .fetch_add(1, Ordering::Relaxed);
                        // Still log the detection, but do NOT quarantine the wrong file.
                        let path_str = path.to_string_lossy().to_string();
                        state.log_activity(
                            "critical",
                            "watcher",
                            &format!(
                                "Threat detected but quarantine blocked (TOCTOU): {threat_name}"
                            ),
                            &path_str,
                            None,
                        );
                        continue; // Skip quarantine, move to next file.
                    }

                    // Auto-quarantine (identity verified).
                    let path_str = path.to_string_lossy().to_string();
                    match state.quarantine_file(&path_str, &threat_name, "realtime") {
                        Ok(q) => {
                            info!(id = %q.quarantine_id, "auto-quarantined by watcher");
                        }
                        Err(e) => {
                            warn!(%e, "auto-quarantine failed");
                            state.log_activity(
                                "critical",
                                "watcher",
                                &format!("Threat detected: {threat_name}"),
                                &path_str,
                                None,
                            );
                        }
                    }
                } else if !argus_verdict.findings.is_empty() {
                    debug!(
                        file = %path.display(),
                        score = argus_verdict.score,
                        findings = argus_verdict.findings.len(),
                        "watcher: {} (ARGUS {}/100)",
                        argus_verdict.verdict.label(),
                        argus_verdict.score,
                    );
                } else {
                    debug!(file = %path.display(), "watcher scan: clean");
                }
            }
        }
    }

    info!("real-time watcher loop exited");
}

/// Background sandbox detonation for watcher.
///
/// Runs on a dedicated thread so the watcher loop is never blocked (up to 35s)
/// by sandbox detonation. If behavioral signals push the score into threat
/// range, this function handles quarantine + logging autonomously.
fn sandbox_detonation_background(
    path: PathBuf,
    state: Arc<crate::ipc::AppState>,
    pre_sandbox_score: u32,
    sha256: String,
    detections_count: Arc<AtomicU64>,
    sandbox_config: crate::config::SandboxConfig,
) {
    use tracing::{debug, info, warn};

    let no_cancel = std::sync::atomic::AtomicBool::new(false);
    match crate::sandbox_worker::detonate(&path, &sandbox_config, &no_cancel) {
        Ok(sb_result) => {
            let backend = sb_result.backend_used.as_deref().unwrap_or("unknown");
            info!(
                file = %path.display(),
                detonation_ms = sb_result.detonation_time_ms,
                monitor_ms = sb_result.monitor_duration_ms,
                backend,
                "sandbox detonation completed (async)"
            );

            if sb_result.score_delta > 0 {
                let capped_delta = sb_result.score_delta.min(SANDBOX_MAX_SCORE_DELTA);
                let final_score = pre_sandbox_score
                    .saturating_add(capped_delta as u32)
                    .min(100);
                let final_verdict = argus::verdict::Verdict::from_score(final_score);

                info!(
                    file = %path.display(),
                    pre_score = pre_sandbox_score,
                    raw_delta = sb_result.score_delta,
                    capped_delta,
                    final_score,
                    findings = sb_result.findings.len(),
                    "sandbox behavioral signals (async)"
                );

                state.log_activity(
                    "info",
                    "sandbox",
                    &format!(
                        "[BehavioralRuntime] Sandbox: {} — {} findings, score_delta={} (capped from {}), final_score={}",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        sb_result.findings.len(),
                        capped_delta,
                        sb_result.score_delta,
                        final_score,
                    ),
                    &sb_result.status,
                    None,
                );

                // If sandbox pushes score into threat range, quarantine now.
                // Threshold: same as unify_detection — ARGUS score >= 76 = auto-quarantine.
                if final_score >= 76 && path.exists() {
                    // Re-check trusted hash in case user whitelisted during detonation.
                    if state.is_hash_trusted(&sha256) {
                        debug!(file = %path.display(), "sandbox escalation skipped: hash trusted");
                        return;
                    }

                    let threat_name =
                        format!("ARGUS.Behavioral.{}.{}", final_verdict.label(), final_score);
                    warn!(
                        file = %path.display(),
                        threat = %threat_name,
                        "SANDBOX ESCALATION: quarantining post-detonation"
                    );
                    detections_count.fetch_add(1, Ordering::Relaxed);

                    let path_str = path.to_string_lossy().to_string();
                    state.auto_memory_scan_if_running(&path_str, final_score);

                    match state.quarantine_file(&path_str, &threat_name, "realtime-sandbox") {
                        Ok(q) => {
                            info!(id = %q.quarantine_id, "auto-quarantined by sandbox escalation");
                        }
                        Err(e) => {
                            warn!(%e, "sandbox escalation quarantine failed");
                            state.log_activity(
                                "critical",
                                "watcher",
                                &format!("Sandbox threat: {threat_name}"),
                                &path_str,
                                None,
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            debug!(file = %path.display(), error = %e, "sandbox detonation skipped (async)");
        }
    }
}

/// Directories where high rewrite rates are normal (browser temp, build tools).
/// FISH should NOT count these as potential ransomware activity.
fn is_fish_excluded_path(path: &std::path::Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    // Temp directories — browsers, apps, ClamAV constantly rewrite here.
    p.contains("\\temp\\") || p.contains("/temp/")
    || p.contains("\\tmp\\") || p.contains("/tmp/")
    // ClamAV extraction temp files.
    || p.contains("html-tmp.") || p.contains("ole2-tmp.") || p.contains("clamav-")
    // Browser caches.
    || p.contains("\\cache\\") || p.contains("\\code cache\\")
    || p.contains("\\gpucache\\") || p.contains("\\shadercache\\")
    // Build artifacts.
    || p.contains("\\target\\") || p.contains("\\node_modules\\")
    || p.contains("\\.git\\") || p.contains("\\dist\\")
    // Log rotation.
    || p.contains("\\logs\\") || p.ends_with(".log")
    // AppData noise — browser profiles, extensions, etc.
    || p.contains("\\appdata\\local\\") && (
        p.contains("\\user data\\") || p.contains("\\extensions\\")
        || p.contains("\\indexeddb\\") || p.contains("\\local storage\\")
    )
}

/// Feed a notify event into the FISH MutationWindow (observe-only telemetry).
fn fish_feed_event(event: &Event, state: &Arc<crate::ipc::AppState>) {
    let now = Instant::now();

    let kind = match &event.kind {
        EventKind::Create(CreateKind::File) => Some(MutationKind::Create),
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
            Some(MutationKind::Rewrite)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            // notify sends both old + new paths in event.paths[0..2].
            if event.paths.len() >= 2 {
                let old = event.paths[0]
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let new = event.paths[1]
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                // Check extension mutation.
                let old_ext = event.paths[0]
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let new_ext = event.paths[1]
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if old_ext != new_ext && !old_ext.is_empty() {
                    Some(MutationKind::ExtensionMutation { old_ext, new_ext })
                } else {
                    Some(MutationKind::Rename {
                        old_name: old,
                        new_name: new,
                    })
                }
            } else {
                None
            }
        }
        EventKind::Remove(_) => Some(MutationKind::Delete),
        _ => None,
    };

    if let Some(mutation_kind) = kind {
        for path in &event.paths {
            if fish_should_skip_path(path) {
                continue;
            }
            let decision = state.fish_record(FileMutationEvent {
                path: path.clone(),
                kind: mutation_kind.clone(),
                timestamp: now,
            });
            match &decision {
                FishDecision::Normal => {}
                FishDecision::RenameBurst { count, window_secs } => {
                    warn!(count, window_secs, "FISH: rename burst detected");
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Rename burst: {count} files in {window_secs}s"),
                    );
                }
                FishDecision::RewriteBurst { count, window_secs } => {
                    warn!(count, window_secs, "FISH: rewrite burst detected");
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Rewrite burst: {count} files in {window_secs}s"),
                    );
                }
                FishDecision::ExtensionMutation { count, pattern } => {
                    warn!(
                        count,
                        pattern = pattern.as_str(),
                        "FISH: extension mutation burst"
                    );
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Extension mutation: {count} files → .{pattern}"),
                    );
                }
                FishDecision::Cooldown {
                    original,
                    suppressed_count,
                } => {
                    debug!(
                        original = original.as_str(),
                        suppressed = suppressed_count,
                        "FISH: cooldown"
                    );
                }
            }
            // Only record once per event batch (use first path).
            break;
        }
    }
}

fn fish_should_skip_path(path: &std::path::Path) -> bool {
    if crate::scan::is_sentinella_path(path) || crate::scan::is_build_or_dev_path(path) {
        return true;
    }
    // Exclude noisy directories from FISH — normal high-rewrite locations.
    if is_fish_excluded_path(path) {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|v| v.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "tmp"
                | "temp"
                | "log"
                | "bak"
                | "swp"
                | "swo"
                | "lock"
                | "cache"
                | "db-journal"
                | "db-wal"
                | "db-shm"
        ) {
            return true;
        }
    }

    false
}

/// Handle a FISH burst — observe or take active response.
fn fish_handle_burst(
    state: &Arc<crate::ipc::AppState>,
    affected_path: &std::path::Path,
    description: &str,
) {
    let fish_diag = state.fish_diagnostics();
    let response_mode = ResponseType::from_config(&fish_diag.active_response);

    match response_mode {
        ResponseType::Observe => {
            state.log_activity(
                "warning",
                "fish",
                description,
                "Observe-only — no action taken",
                None,
            );
        }
        ResponseType::Suspend | ResponseType::Terminate => {
            // Find suspect processes in the affected directory.
            let affected_dir = affected_path.parent().unwrap_or(affected_path);
            let suspects = find_suspect_processes(affected_dir);

            if suspects.is_empty() {
                warn!("FISH: no suspect process found — logging only");
                state.log_activity(
                    "warning",
                    "fish",
                    description,
                    "Active response: no suspect process identified",
                    None,
                );
                return;
            }

            for suspect in &suspects {
                let action_name = if response_mode == ResponseType::Suspend {
                    "suspend"
                } else {
                    "terminate"
                };

                warn!(
                    pid = suspect.pid,
                    process = suspect.name.as_str(),
                    reason = suspect.suspicion_reason.as_str(),
                    action = action_name,
                    "FISH: active response on suspect process"
                );

                let result = if response_mode == ResponseType::Suspend {
                    suspend_process(suspect.pid)
                } else {
                    terminate_process(suspect.pid)
                };

                match result {
                    Ok(()) => {
                        state.log_activity(
                            "critical",
                            "fish",
                            &format!("FISH {action_name}: {} (PID {})", suspect.name, suspect.pid),
                            &format!("{description} — {}", suspect.suspicion_reason),
                            None,
                        );
                        // Record in FISH counters.
                        if response_mode == ResponseType::Suspend {
                            state.fish_record_suspension();
                        } else {
                            state.fish_record_termination();
                        }
                    }
                    Err(e) => {
                        error!(
                            pid = suspect.pid,
                            error = e.as_str(),
                            "FISH: active response failed"
                        );
                        state.log_activity(
                            "warning",
                            "fish",
                            &format!(
                                "FISH {action_name} failed: {} (PID {})",
                                suspect.name, suspect.pid
                            ),
                            &e,
                            None,
                        );
                    }
                }
                // Only act on first suspect per burst.
                break;
            }
        }
    }
}

fn collect_overflow_rescan_files(dir: &std::path::Path, out: &mut Vec<PathBuf>, cap: usize) {
    let max_len = DEBOUNCE_CAP.saturating_add(cap);
    if out.len() >= max_len {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= max_len {
            break;
        }
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        }
    }
}

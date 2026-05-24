//! ARGUS Engine — the core orchestrator.
//!
//! Coordinates all analysis layers, aggregates findings, and produces
//! the final scored verdict for every scanned target.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::layers;
use crate::verdict::*;

/// Engine version — embedded in every verdict for traceability.
pub const ENGINE_VERSION: &str = "0.1.0-alpha";

/// Configuration for the ARGUS engine.
#[derive(Debug, Clone)]
pub struct ArgusConfig {
    /// Maximum file size to analyze (bytes). Files larger than this are skipped.
    pub max_file_size: u64,

    /// Enable PE/ELF structural analysis.
    pub pe_heuristics: bool,

    /// Enable packer/protector detection.
    pub packer_detection: bool,

    /// Enable script content analysis.
    pub script_analysis: bool,

    /// Enable specialty malware pattern detection.
    pub pattern_detection: bool,

    /// Enable MIME/magic byte validation.
    pub mime_validation: bool,

    /// Enable file deception detection (extension tricks, RTLO, etc.).
    pub file_deception: bool,
}

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MB — larger files use ClamAV only
            pe_heuristics: true,
            packer_detection: true,
            script_analysis: true,
            pattern_detection: true,
            mime_validation: true,
            file_deception: true,
        }
    }
}

/// Runtime statistics for the ARGUS engine.
#[derive(Debug, Clone, Serialize)]
pub struct ArgusStats {
    /// Total files analyzed since engine start.
    pub files_analyzed: u64,
    /// Total findings generated across all analyses.
    pub total_findings: u64,
    /// Files classified as Malicious (score 76+, matches `Verdict::Malicious`).
    pub threats_detected: u64,
    /// Files classified as clean (score == 0).
    pub clean_files: u64,
    /// Total analysis time in microseconds (cumulative).
    pub total_analysis_time_us: u64,
    /// Average analysis time per file in microseconds.
    pub avg_analysis_time_us: u64,
    /// Number of active analysis layers.
    pub active_layers: u32,
    /// Number of IOC hashes loaded.
    pub ioc_hashes_loaded: u64,
    /// Number of YARA rules loaded.
    pub yara_rules_loaded: u64,
    /// Engine version.
    pub engine_version: &'static str,
}

/// The ARGUS heuristics engine.
///
/// Thread-safe — create one instance and share it via `Arc`.
pub struct ArgusEngine {
    config: ArgusConfig,
    /// IOC hash matching database.
    pub ioc: layers::ioc::IocDatabase,
    /// YARA-X rule engine.
    pub yara: layers::yara::YaraEngine,
    /// Event correlator for short-term cross-file context.
    pub correlator: crate::correlation::EventCorrelator,
    /// Trusted hash cache — verified-clean files with trust signals.
    pub trusted_cache: layers::trusted_cache::TrustedCache,
    // Atomic counters for runtime stats.
    files_analyzed: AtomicU64,
    total_findings: AtomicU64,
    threats_detected: AtomicU64,
    clean_files: AtomicU64,
    total_analysis_time_us: AtomicU64,
}

impl ArgusEngine {
    /// Create a new ARGUS engine with the given configuration.
    pub fn new(config: ArgusConfig) -> Self {
        tracing::info!(
            version = ENGINE_VERSION,
            "ARGUS Heuristics Engine initialized",
        );
        Self {
            config,
            ioc: layers::ioc::IocDatabase::new(),
            yara: layers::yara::YaraEngine::new(),
            correlator: crate::correlation::EventCorrelator::new(),
            trusted_cache: layers::trusted_cache::TrustedCache::new(),
            files_analyzed: AtomicU64::new(0),
            total_findings: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            clean_files: AtomicU64::new(0),
            total_analysis_time_us: AtomicU64::new(0),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ArgusConfig::default())
    }

    /// Get current engine statistics.
    pub fn stats(&self) -> ArgusStats {
        let analyzed = self.files_analyzed.load(Ordering::Relaxed);
        let total_time = self.total_analysis_time_us.load(Ordering::Relaxed);
        let yara_count = self.yara.rule_count();
        let active_layers = [
            self.config.mime_validation,
            self.config.pe_heuristics,
            self.config.packer_detection,
            self.config.script_analysis,
            self.config.pattern_detection,
            self.config.file_deception,
            true,           // IOC (always active)
            yara_count > 0, // YARA (active if rules loaded)
        ]
        .iter()
        .filter(|&&v| v)
        .count() as u32;

        ArgusStats {
            files_analyzed: analyzed,
            total_findings: self.total_findings.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            clean_files: self.clean_files.load(Ordering::Relaxed),
            total_analysis_time_us: total_time,
            avg_analysis_time_us: if analyzed > 0 {
                total_time / analyzed
            } else {
                0
            },
            active_layers,
            ioc_hashes_loaded: self.ioc.len(),
            yara_rules_loaded: yara_count,
            engine_version: ENGINE_VERSION,
        }
    }

    /// Analyze a file at the given path. Returns a fully scored verdict.
    ///
    /// This is the primary entry point for file analysis. It:
    /// 1. Reads the file into memory (via mmap for large files)
    /// 2. Computes SHA-256 hash
    /// 3. Runs all enabled analysis layers
    /// 4. Aggregates findings into a scored verdict
    pub fn analyze_file(&self, path: &Path) -> ArgusVerdict {
        let start = Instant::now();
        let path_str = path.to_string_lossy().to_string();

        // ── Read the file ──────────────────────────────────────
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return self.error_verdict(&path_str, start, format!("Cannot read file: {e}"));
            }
        };

        let file_size = metadata.len();

        if file_size == 0 {
            return self.empty_verdict(&path_str, start);
        }

        // ── Strategy classification ─────────────────────────
        let strategy = ScanStrategy::classify(&path_str, file_size);
        if strategy == ScanStrategy::TooLarge {
            debug!(path = %path_str, size = file_size, "Skipped: too large for ARGUS");
            return self.empty_verdict(&path_str, start);
        }
        if strategy == ScanStrategy::SkipSafe {
            debug!(path = %path_str, "Skipped: safe file type");
            return self.empty_verdict(&path_str, start);
        }

        if file_size > self.config.max_file_size {
            debug!(path = %path_str, size = file_size, "Skipped: exceeds max file size");
            return self.empty_verdict(&path_str, start);
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return self.error_verdict(&path_str, start, format!("Read error: {e}"));
            }
        };

        // ── Timing: SHA-256 ───────────────────────────────────
        let hash_start = Instant::now();
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        };
        let hash_us = hash_start.elapsed().as_micros() as u64;

        // ── Trusted cache fast path ────────────────────────────
        // If this hash was previously verified clean with trust signals,
        // return cached verdict immediately. Saves full analysis time.
        if let Some(cached_score) = self.trusted_cache.check(&sha256) {
            let elapsed = start.elapsed().as_micros() as u64;
            self.files_analyzed.fetch_add(1, Ordering::Relaxed);
            self.clean_files.fetch_add(1, Ordering::Relaxed);
            self.total_analysis_time_us
                .fetch_add(elapsed, Ordering::Relaxed);

            let mime_type = infer::get(&data).map(|t| t.mime_type().to_string());
            return ArgusVerdict {
                path: path_str,
                file_size,
                sha256,
                mime_type,
                score: cached_score,
                verdict: Verdict::from_score(cached_score),
                findings: vec![],
                analysis_time_us: elapsed,
                engine_version: ENGINE_VERSION,
                timestamp: chrono::Utc::now().timestamp(),
                explanation: VerdictExplanation {
                    confidence_label: ConfidenceLabel::Trusted,
                    framework: None,
                    ..default_explanation()
                },
                timing: None, // Cached — no analysis performed.
            };
        }

        // ── Detect MIME type ───────────────────────────────────
        let mime_type = infer::get(&data).map(|t| t.mime_type().to_string());

        // ── Run analysis layers ────────────────────────────────
        let mut findings = Vec::new();

        // Layer: IOC hash matching (O(1) lookup — fastest check).
        findings.extend(self.ioc.check(&sha256));

        // Layer: File deception (path-only analysis — runs first, very fast).
        if self.config.file_deception {
            findings.extend(layers::file_deception::analyze_path(&path_str));
        }

        // Layer: MIME/magic validation.
        if self.config.mime_validation {
            findings.extend(layers::mime::analyze(&path_str, &data));
        }

        // Layer: PE/ELF structural analysis.
        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        if is_pe {
            if let Ok(pe) = goblin::pe::PE::parse(&data) {
                if self.config.pe_heuristics {
                    findings.extend(layers::pe_heuristics::analyze(&pe, &data));
                }
                if self.config.packer_detection {
                    findings.extend(layers::packer::analyze(&pe, &data));
                }
            } else {
                debug!(path = %path_str, "PE parse failed — skipping structural analysis");
            }
        } else if self.config.packer_detection {
            // Non-PE packer checks (PyInstaller, Node SEA can be checked without PE parse).
            // Create a minimal PE stub to reuse packer::analyze structure.
            // For now, check raw data patterns directly.
            check_non_pe_packers(&data, &mut findings);
        }

        // Layer: Script analysis.
        if self.config.script_analysis {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let is_script = matches!(
                ext.as_str(),
                "ps1" | "psm1" | "psd1" | "js" | "jse" | "vbs" | "vbe" | "bat" | "cmd" | "reg"
            );
            if is_script {
                findings.extend(layers::script::analyze(&path_str, &data));
            }
        }

        // Layer: Pattern detection (works on raw bytes).
        if self.config.pattern_detection {
            findings.extend(layers::patterns::analyze(&path_str, &data));
        }

        // Layer: YARA rule engine (runs compiled rules against buffer).
        // Skip YARA for SignatureOnly strategy (media, firmware, large blobs).
        let yara_start = Instant::now();
        if strategy == ScanStrategy::FullAnalysis || strategy == ScanStrategy::LightAnalysis {
            findings.extend(self.yara.scan(&data));
        }
        let yara_us = yara_start.elapsed().as_micros() as u64;

        // Layer: Authenticode signature verification (Windows PE only).
        let mut authenticode_discount: u32 = 0;
        if is_pe {
            findings.extend(layers::authenticode::analyze(path));
            authenticode_discount = layers::authenticode::signature_discount(path);
        }

        // Layer: Software reputation — recognizes known publishers.
        findings.extend(layers::reputation::analyze(&path_str, &data));
        let reputation_discount = layers::reputation::reputation_discount(&path_str, &data);

        // ── Installer framework detection ──────────────────────
        // NSIS, InnoSetup, WiX, Electron installers are expected to have
        // compressed data, few imports, large overlays, temp extraction,
        // and download capabilities. These are NOT suspicious in an installer.
        let installer_detected_early = is_pe && is_known_installer(&data, &path_str);
        if installer_detected_early {
            for f in &mut findings {
                match f.layer {
                    // Structural/packer: aggressive reduction (/3).
                    Layer::StructuralAnalysis | Layer::PackerDetection => {
                        f.weight = f.weight / 3;
                    }
                    // YARA: moderate reduction (/2) for installer-expected patterns.
                    // Dropper, updater, and persistence rules fire on normal installers.
                    Layer::YaraRules => {
                        if let Some(ref detail) = f.technical_detail {
                            let dl = detail.to_lowercase();
                            if dl.contains("dropper")
                                || dl.contains("updater")
                                || dl.contains("installer")
                                || dl.contains("persistence")
                                || dl.contains("temp_extraction")
                                || dl.contains("fake_updater")
                            {
                                f.weight = f.weight / 2;
                            }
                        }
                    }
                    _ => {}
                }
                if f.weight == 0 && f.severity > Severity::Info {
                    f.severity = Severity::Info;
                }
            }
        }

        // ── Trusted binary noise suppression ───────────────────
        // If both Authenticode + reputation agree this is trusted,
        // suppress low-weight structural findings entirely to produce
        // cleaner verdicts for known-good software.
        if authenticode_discount >= 15 && reputation_discount >= 15 {
            findings.retain(|f| {
                // Keep behavioral/pattern findings (always important).
                // Suppress trivial structural noise.
                if f.weight <= 3
                    && matches!(f.layer, Layer::StructuralAnalysis | Layer::PackerDetection)
                {
                    false // Drop trivial structural findings for trusted binaries.
                } else {
                    true
                }
            });
        }

        // ── Contextual amplification ──────────────────────────
        // Runs after all content layers. Uses the pre-discount raw score
        // to decide whether to amplify — context alone never creates a threat.
        // SUPPRESSED for trusted signed binaries — they don't need context amplification.
        let pre_context_score: u32 = findings.iter().map(|f| f.weight).sum();
        let trust_suppresses_context = reputation_discount >= 15 || authenticode_discount >= 15;
        if pre_context_score > 0 && !trust_suppresses_context {
            findings.extend(layers::context::analyze(path, pre_context_score));
        }

        // ── Aggregate score + build explanation ────────────────
        let installer_detected = is_pe && is_known_installer(&data, &path_str);
        let (score, verdict, explanation) = aggregate_score(
            &mut findings,
            reputation_discount,
            authenticode_discount,
            installer_detected,
        );
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;

        // ── Record event for correlation ──────────────────────
        let event_type = if score >= 76 {
            crate::correlation::EventType::ScannedSuspicious
        } else if score > 0 {
            crate::correlation::EventType::ScannedClean // Suspicious but not threat-level.
        } else {
            crate::correlation::EventType::ScannedClean
        };
        self.correlator.record(path.to_path_buf(), event_type, None);

        // ── Update stats ──────────────────────────────────────
        self.files_analyzed.fetch_add(1, Ordering::Relaxed);
        self.total_findings
            .fetch_add(findings.len() as u64, Ordering::Relaxed);
        self.total_analysis_time_us
            .fetch_add(elapsed_us, Ordering::Relaxed);
        if matches!(verdict, Verdict::Malicious) {
            self.threats_detected.fetch_add(1, Ordering::Relaxed);
        } else if score == 0 {
            self.clean_files.fetch_add(1, Ordering::Relaxed);
        }

        // Only log files with findings to avoid flooding logs during large scans.
        if !findings.is_empty() {
            debug!(
                path = %path_str,
                score,
                findings = findings.len(),
                time_us = elapsed_us,
                verdict = verdict.label(),
                "ARGUS analysis: findings detected",
            );
        }

        // ── Record in trusted cache if clean ─────────
        if score == 0 {
            self.trusted_cache.record(
                &sha256,
                score,
                explanation.signer.as_deref(),
                explanation.recognized_software.as_deref(),
            );
        }

        ArgusVerdict {
            path: path_str,
            file_size,
            sha256,
            mime_type,
            score,
            verdict,
            findings,
            analysis_time_us: elapsed_us,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation,
            timing: Some(ScanTiming {
                hash_us,
                clamav_us: 0, // ClamAV is called separately by daemon
                argus_total_us: elapsed_us,
                yara_us,
                structural_us: 0, // TODO: instrument per-layer
                strategy: Some(strategy),
                timeout_reasons: Vec::new(),
                completed_within_budget: true,
            }),
        }
    }

    /// Analyze raw bytes (for in-memory scanning, e.g., ASAR contents).
    pub fn analyze_buffer(&self, name: &str, data: &[u8]) -> ArgusVerdict {
        let start = Instant::now();
        let mut findings = Vec::new();

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        };

        let mime_type = infer::get(data).map(|t| t.mime_type().to_string());

        // Run applicable layers on the buffer.
        if self.config.mime_validation {
            findings.extend(layers::mime::analyze(name, data));
        }

        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        if is_pe {
            if let Ok(pe) = goblin::pe::PE::parse(data) {
                if self.config.pe_heuristics {
                    findings.extend(layers::pe_heuristics::analyze(&pe, data));
                }
                if self.config.packer_detection {
                    findings.extend(layers::packer::analyze(&pe, data));
                }
            }
        }

        if self.config.script_analysis {
            findings.extend(layers::script::analyze(name, data));
        }

        if self.config.pattern_detection {
            findings.extend(layers::patterns::analyze(name, data));
        }

        let raw_score: u32 = findings.iter().map(|f| f.weight).sum();
        let score = raw_score.min(MAX_SCORE);
        findings.sort_by(|a, b| b.weight.cmp(&a.weight));
        let verdict = Verdict::from_score(score);

        ArgusVerdict {
            path: name.to_string(),
            file_size: data.len() as u64,
            sha256,
            mime_type,
            score,
            verdict,
            findings,
            analysis_time_us: start.elapsed().as_micros() as u64,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation: default_explanation(),
            timing: None,
        }
    }

    fn empty_verdict(&self, path: &str, start: Instant) -> ArgusVerdict {
        ArgusVerdict {
            path: path.to_string(),
            file_size: 0,
            sha256: String::new(),
            mime_type: None,
            score: 0,
            verdict: Verdict::Clean,
            findings: vec![],
            analysis_time_us: start.elapsed().as_micros() as u64,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation: default_explanation(),
            timing: None,
        }
    }

    fn error_verdict(&self, path: &str, start: Instant, error: String) -> ArgusVerdict {
        // File-not-found is a normal race condition (temp files deleted between
        // watcher event and scan). Log at debug, not warn.
        if error.contains("os error 2") || error.contains("os error 3") {
            debug!(path, %error, "ARGUS: file vanished before scan");
        } else {
            warn!(path, %error, "ARGUS analysis error");
        }
        ArgusVerdict {
            path: path.to_string(),
            file_size: 0,
            sha256: String::new(),
            mime_type: None,
            score: 0,
            verdict: Verdict::Clean,
            findings: vec![Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 0,
                description: format!("Analysis incomplete: {error}"),
                technical_detail: None,
            }],
            analysis_time_us: start.elapsed().as_micros() as u64,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation: default_explanation(),
            timing: None,
        }
    }
}

fn default_explanation() -> VerdictExplanation {
    VerdictExplanation {
        raw_score: 0,
        reputation_discount: 0,
        authenticode_discount: 0,
        installer_discount_applied: false,
        final_score: 0,
        signer: None,
        recognized_software: None,
        suspicion_reasons: vec![],
        trust_reasons: vec![],
        confidence_label: ConfidenceLabel::Normal,
        framework: None,
        threat_maturity: ThreatMaturity::Benign,
        progression_depth: 0,
    }
}

/// Compute convergence assessment from weighted findings.
///
/// Identifies coherent attack chains from BehaviorTag combinations.
/// Chain strength reflects how dangerous the combination is, not just tag count.
fn compute_convergence(findings: &[Finding]) -> crate::verdict::ConvergenceInfo {
    use crate::verdict::{ChainStrength, ConvergenceInfo};
    use std::collections::HashSet;

    let active: Vec<_> = findings.iter().filter(|f| f.weight > 0).collect();

    let tags: HashSet<BehaviorTag> = active
        .iter()
        .filter_map(|f| f.behavior_tag())
        .filter(|t| *t != BehaviorTag::DownloadOriginContext)
        .collect();

    let layers: HashSet<Layer> = active.iter().map(|f| f.layer).collect();

    let has = |tag: BehaviorTag| tags.contains(&tag);

    // ── Detect chains ────────────────────────────────────
    let mut chains: Vec<(&'static str, ChainStrength)> = Vec::new();

    // STRONG chains — high-confidence malicious combinations.
    if has(BehaviorTag::KnownMalware) {
        chains.push(("known_malware_ioc", ChainStrength::Strong));
    }
    if has(BehaviorTag::CredentialTheft) && has(BehaviorTag::Exfiltration) {
        chains.push(("stealer", ChainStrength::Strong));
    }
    if has(BehaviorTag::Ransomware)
        && (has(BehaviorTag::Injection) || has(BehaviorTag::Persistence))
    {
        chains.push(("ransomware", ChainStrength::Strong));
    }
    if has(BehaviorTag::Persistence) && has(BehaviorTag::C2Communication) {
        chains.push(("backdoor", ChainStrength::Strong));
    }
    if has(BehaviorTag::WalletTheft)
        && (has(BehaviorTag::Exfiltration) || has(BehaviorTag::CredentialTheft))
    {
        chains.push(("crypto_stealer", ChainStrength::Strong));
    }

    // MODERATE chains — suspicious combinations that need more context.
    if has(BehaviorTag::FakeInstaller)
        && (has(BehaviorTag::Persistence) || has(BehaviorTag::DownloaderCapability))
    {
        chains.push(("fake_installer", ChainStrength::Moderate));
    }
    if has(BehaviorTag::ScriptAbuse)
        && (has(BehaviorTag::DownloaderCapability) || has(BehaviorTag::C2Communication))
    {
        chains.push(("script_malware", ChainStrength::Moderate));
    }
    if has(BehaviorTag::DownloaderCapability)
        && has(BehaviorTag::ArchiveStaging)
        && has(BehaviorTag::Evasion)
    {
        chains.push(("loader", ChainStrength::Moderate));
    }
    if has(BehaviorTag::Persistence) && has(BehaviorTag::DownloaderCapability) {
        chains.push(("persistent_downloader", ChainStrength::Moderate));
    }

    // WEAK chains — common combinations that are often benign.
    if has(BehaviorTag::DownloaderCapability) && tags.len() == 1 {
        chains.push(("downloader_only", ChainStrength::Weak));
    }
    if has(BehaviorTag::Packing) && has(BehaviorTag::Entropy) && tags.len() <= 2 {
        chains.push(("packed_only", ChainStrength::Weak));
    }

    // Strongest chain wins.
    let chain_strength = chains
        .iter()
        .map(|(_, s)| *s)
        .max()
        .unwrap_or(ChainStrength::None);

    let chain_names: Vec<&'static str> = chains
        .iter()
        .filter(|(_, s)| *s >= ChainStrength::Moderate)
        .map(|(name, _)| *name)
        .collect();

    // Compute attack progression score.
    let tag_vec: Vec<BehaviorTag> = tags.iter().copied().collect();
    let progression = crate::verdict::attack_progression_score(&tag_vec);

    ConvergenceInfo {
        distinct_behaviors: tags.len(),
        distinct_layers: layers.len(),
        chain_strength,
        chain_names,
        progression_score: progression,
    }
}

/// Deduplicate findings using structured BehaviorTags.
///
/// DEDUP RULE: Same behavior tag + same layer → redundant (keep only max weight).
/// Same behavior tag + different layers → convergence (both count — independent confirmation).
///
/// This preserves multi-layer agreement (YARA + Pattern both say "stealer" = stronger)
/// while preventing intra-layer redundancy (two structural entropy findings = one).
///
/// Context-layer findings are never deduplicated.
fn deduplicate_findings(findings: &mut Vec<Finding>) {
    use crate::verdict::BehaviorTag;

    // Sort by weight descending — highest-weight findings kept.
    findings.sort_by(|a, b| b.weight.cmp(&a.weight));

    // Track (tag, layer) pairs already counted.
    let mut seen: std::collections::HashSet<(BehaviorTag, Layer)> =
        std::collections::HashSet::new();

    for f in findings.iter_mut() {
        if let Some(tag) = f.behavior_tag() {
            // Context is never deduplicated.
            if tag == BehaviorTag::DownloadOriginContext {
                continue;
            }

            let key = (tag, f.layer);
            if seen.contains(&key) {
                // Same tag + same layer → redundant → zero weight.
                f.weight = 0;
                if f.severity > Severity::Info {
                    f.severity = Severity::Info;
                }
            } else {
                seen.insert(key);
            }
        }
    }
}

/// Pure scoring function — computes final score, verdict, and explanation
/// from raw findings + discount values. Sorts findings by weight.
///
/// This is the single source of truth for score aggregation.
fn aggregate_score(
    findings: &mut Vec<Finding>,
    reputation_discount: u32,
    authenticode_discount: u32,
    installer_detected: bool,
) -> (u32, Verdict, VerdictExplanation) {
    // ── Evidence deduplication — prevent counting same behavior twice ──
    // When multiple layers detect the same semantic behavior (e.g., "downloader"
    // from YARA + "downloader" from patterns + "URL download" from imports),
    // keep only the highest-weight finding per behavior group.
    deduplicate_findings(findings);

    // ── Category caps — prevent single-category score inflation ──
    const CAP_STRUCTURAL: u32 = 30;
    const CAP_YARA: u32 = 40;
    const CAP_CONTEXT: u32 = 15;
    const CAP_PACKER: u32 = 20;
    const CAP_PATTERN: u32 = 25;
    const CAP_SCRIPT: u32 = 40;
    const CAP_DECEPTION: u32 = 50;

    // Apply per-category caps by proportionally reducing weights.
    let apply_cap = |findings: &mut Vec<Finding>, layer: Layer, cap: u32| {
        let total: u32 = findings
            .iter()
            .filter(|f| f.layer == layer)
            .map(|f| f.weight)
            .sum();
        if total > cap && total > 0 {
            let ratio = cap as f64 / total as f64;
            for f in findings.iter_mut() {
                if f.layer == layer {
                    f.weight = (f.weight as f64 * ratio).round() as u32;
                }
            }
        }
    };

    apply_cap(findings, Layer::StructuralAnalysis, CAP_STRUCTURAL);
    apply_cap(findings, Layer::YaraRules, CAP_YARA);
    apply_cap(findings, Layer::Context, CAP_CONTEXT);
    apply_cap(findings, Layer::PackerDetection, CAP_PACKER);
    apply_cap(findings, Layer::PatternDetection, CAP_PATTERN);
    apply_cap(findings, Layer::ScriptAnalysis, CAP_SCRIPT);
    apply_cap(findings, Layer::FileDeception, CAP_DECEPTION);

    let raw_score: u32 = findings.iter().map(|f| f.weight).sum();
    // Discounts don't stack fully — use the larger.
    let total_discount = reputation_discount.max(authenticode_discount);
    let adjusted = raw_score.saturating_sub(total_discount);
    let score = adjusted.min(MAX_SCORE);

    // Sort findings by weight (highest first).
    findings.sort_by(|a, b| b.weight.cmp(&a.weight));

    let mut verdict = Verdict::from_score(score);

    // PUA reclassification: if dominant behavior is PUA-tagged and score
    // is in suspicious range, reclassify as PotentiallyUnwanted.
    if matches!(verdict, Verdict::Suspicious | Verdict::HighSuspicion) {
        let pua_weight: u32 = findings
            .iter()
            .filter(|f| f.behavior_tag() == Some(BehaviorTag::PotentiallyUnwanted))
            .map(|f| f.weight)
            .sum();
        if pua_weight > 0 && pua_weight >= raw_score / 2 {
            verdict = Verdict::PotentiallyUnwanted;
        }
    }

    // Build structured explanation — group by evidence type for readability.
    let mut seen = std::collections::HashSet::new();
    let suspicion_reasons: Vec<String> = findings
        .iter()
        .filter(|f| f.weight > 0 && f.layer != Layer::Reputation)
        .filter(|f| {
            let short = f.description.chars().take(60).collect::<String>();
            seen.insert(short)
        })
        .take(8)
        .map(|f| {
            // Prefix with weight for clarity in explanations.
            if f.weight >= 20 {
                format!("[+{}] {}", f.weight, f.description)
            } else {
                f.description.clone()
            }
        })
        .collect();

    let mut trust_reasons = Vec::new();
    if reputation_discount > 0 {
        let sw_name = findings
            .iter()
            .find(|f| f.layer == Layer::Reputation)
            .and_then(|f| f.technical_detail.as_ref())
            .and_then(|d| d.split("Publisher: ").nth(1))
            .map(|s| s.split(" |").next().unwrap_or(s).to_string());
        trust_reasons.push(format!(
            "Recognized software (−{reputation_discount} points)"
        ));
        if let Some(ref name) = sw_name {
            trust_reasons.push(format!("Publisher: {name}"));
        }
    }
    if authenticode_discount > 0 {
        trust_reasons.push(format!(
            "Valid digital signature (−{authenticode_discount} points)"
        ));
    }
    if installer_detected {
        trust_reasons.push("Installer framework detected — structural weights reduced".into());
    }

    let signer = findings
        .iter()
        .find(|f| f.layer == Layer::Reputation && f.description.contains("Digitally signed"))
        .and_then(|f| f.technical_detail.as_ref())
        .map(|d| d.replace("Signer: ", ""));

    let recognized_software = findings
        .iter()
        .find(|f| f.layer == Layer::Reputation && f.description.contains("Recognized as"))
        .and_then(|f| f.technical_detail.as_ref())
        .and_then(|d| d.split("Publisher: ").nth(1))
        .map(|s| s.split(" |").next().unwrap_or(s).to_string());

    // Compute convergence — how many independent behavior categories + layers agree.
    let convergence = compute_convergence(findings);

    // Confidence label — convergence-aware assessment for UI.
    let confidence_label = ConfidenceLabel::from_convergence(
        score,
        authenticode_discount > 0,
        reputation_discount > 0,
        installer_detected,
        &convergence,
    );

    // Detect framework from findings.
    let framework = detect_framework_from_findings(findings);

    let threat_maturity = ThreatMaturity::from_convergence(&convergence, score);

    let explanation = VerdictExplanation {
        raw_score,
        reputation_discount,
        authenticode_discount,
        installer_discount_applied: installer_detected,
        final_score: score,
        signer,
        recognized_software,
        suspicion_reasons,
        trust_reasons,
        confidence_label,
        framework,
        threat_maturity,
        progression_depth: convergence.progression_score,
    };

    (score, verdict, explanation)
}

/// Extract framework name from findings (if detected).
fn detect_framework_from_findings(findings: &[Finding]) -> Option<String> {
    for f in findings {
        let desc = f.description.to_lowercase();
        let detail = f.technical_detail.as_deref().unwrap_or("").to_lowercase();
        let combined = format!("{desc} {detail}");

        if combined.contains("pyinstaller") {
            return Some("PyInstaller".into());
        }
        if combined.contains("electron") || combined.contains("asar") {
            return Some("Electron".into());
        }
        if combined.contains("node.js sea") || combined.contains("node_sea") {
            return Some("Node.js SEA".into());
        }
        if combined.contains("nuitka") {
            return Some("Nuitka".into());
        }
        if combined.contains("tauri") {
            return Some("Tauri".into());
        }
        if combined.contains("nw.js") || combined.contains("nwjs") {
            return Some("NW.js".into());
        }
    }
    None
}

/// Detect if a PE file is a known installer framework.
/// These legitimately have high entropy, few imports, and large overlays.
fn is_known_installer(data: &[u8], path: &str) -> bool {
    // Binary content checks for known installer frameworks.
    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let has_nsis = contains(b"Nullsoft Inst") || contains(b"NullsoftInst");
    let has_inno = contains(b"Inno Setup S") || contains(b"InnoSetupLdr");
    let has_wix = contains(b"Windows Installer");
    let has_msi = data.len() >= 8 && data[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    let has_installshield = contains(b"InstallShiel");
    let has_ai = contains(b"Advanced Installer");

    // Framework detection — Electron, Tauri, Qt, Squirrel, and similar bundle frameworks.
    // These have unusual PE characteristics (large overlay, few imports)
    // that trigger structural false positives.
    let has_electron = contains(b"ASAR")
        || contains(b"electron.asar")
        || contains(b"Electron Framework")
        || contains(b"electron.exe");
    let has_nwjs = contains(b"nw.exe") || contains(b"nwjs");
    let has_tauri = contains(b"tauri") && contains(b"webview");
    let has_squirrel = contains(b"Squirrel") && contains(b"Update.exe");
    let has_qt_installer = contains(b"Qt Installer Framework") || contains(b"QtInstallerFramework");
    let has_flutter = contains(b"flutter_engine") || contains(b"FlutterDesktop");
    let has_unity = contains(b"UnityPlayer") || contains(b"Unity Technologies");
    let has_unreal = contains(b"UnrealEngine") || contains(b"EpicGames");

    // Filename heuristic — only applies if binary also has framework markers.
    // Prevents "setup.exe" random files from getting discount.
    let path_lower = path.to_lowercase();
    let name_indicators = [
        "setup",
        "install",
        "installer",
        "update",
        "updater",
        "_setup",
        "-setup",
    ];
    let has_installer_name = name_indicators.iter().any(|p| path_lower.contains(p));

    // Framework detected → always installer.
    if has_nsis || has_inno || has_wix || has_msi || has_installshield || has_ai {
        return true;
    }
    // Framework → installer treatment (structural noise reduction).
    if has_electron
        || has_nwjs
        || has_tauri
        || has_squirrel
        || has_qt_installer
        || has_flutter
        || has_unity
        || has_unreal
    {
        return true;
    }
    // Go binaries — large static binaries with unusual sections but NOT packed/malicious.
    // They have "Go build ID:" marker and are typically >5MB.
    let has_go = contains(b"Go build ID:") || contains(b"runtime.main");
    if has_go && data.len() > 3_000_000 {
        return true; // Go binary → framework treatment.
    }

    // Rust binaries — large static binaries via musl or similar.
    // Contain Rust panic messages and are typically >2MB.
    let has_rust_static = contains(b"rust_begin_unwind") || contains(b"rust_panic");
    if has_rust_static && data.len() > 2_000_000 {
        return true;
    }

    // Name-only heuristic requires PE header + large size.
    let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    if has_installer_name && data.len() > 2_000_000 && is_pe {
        return true;
    }
    false
}

/// Check for packer signatures in non-PE files.
fn check_non_pe_packers(data: &[u8], findings: &mut Vec<Finding>) {
    // PyInstaller magic.
    let magic = b"MEI\x0C\x0B\x0A\x0B\x0E";
    if data.len() > 64 {
        let search_start = data.len().saturating_sub(4096);
        let tail = &data[search_start..];
        if tail.windows(magic.len()).any(|w| w == magic) {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 5,
                description: "File contains PyInstaller archive markers — legitimate Python packaging tool, also commonly used by Python-based malware.".into(),
                technical_detail: Some("PyInstaller CArchive magic found".into()),
            });
        }
    }

    // Node.js SEA.
    let fuse = b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
    if data.windows(fuse.len()).any(|w| w == fuse) {
        findings.push(Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Low,
            weight: 5,
            description: "File is a Node.js Single Executable Application — legitimate packaging format, also used to conceal Node.js malware.".into(),
            technical_detail: Some("NODE_SEA_FUSE sentinel found".into()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_clean_text_file() {
        let engine = ArgusEngine::with_defaults();
        let dir = std::env::temp_dir().join("argus_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clean.txt");
        std::fs::write(&path, b"Hello, world!").unwrap();

        let verdict = engine.analyze_file(&path);
        assert_eq!(verdict.score, 0);
        assert_eq!(verdict.verdict, Verdict::Clean);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_fake_pdf_exe() {
        let engine = ArgusEngine::with_defaults();
        let dir = std::env::temp_dir().join("argus_test_pdf");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invoice.pdf");

        // Write MZ header.
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0x4D, 0x5A]).unwrap(); // MZ
        f.write_all(&[0; 200]).unwrap();
        drop(f);

        let verdict = engine.analyze_file(&path);
        assert!(
            verdict.score >= 40,
            "Expected high score for fake PDF, got {}",
            verdict.score
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.layer == Layer::MimeValidation)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_buffer_analysis() {
        let engine = ArgusEngine::with_defaults();
        let data = b"eval(eval(eval(atob('malicious code'))))";
        let verdict = engine.analyze_buffer("suspicious.js", data);
        assert!(verdict.score > 0, "Expected suspicion from eval chains");
    }

    #[test]
    fn test_stats_threat_count_matches_verdict() {
        // Verify stats threat counting uses the same threshold as Verdict::is_threat().
        let engine = ArgusEngine::with_defaults();

        // Clean file → stats should NOT increment threats.
        let dir = std::env::temp_dir().join("argus_test_stats");
        std::fs::create_dir_all(&dir).unwrap();
        let clean = dir.join("clean.txt");
        std::fs::write(&clean, b"perfectly safe content").unwrap();
        let _ = engine.analyze_file(&clean);
        assert_eq!(
            engine.stats().threats_detected,
            0,
            "Clean file should not count as threat"
        );

        // Score 40-75 file → should NOT be a threat (only 76+ = Malicious).
        let v = engine.analyze_buffer("test.txt", b"safe content");
        assert!(!v.is_threat(), "Low-score file should not be a threat");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_aggregate_score_pure() {
        // Test the scoring aggregation helper directly.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Test finding 1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Test finding 2".into(),
                technical_detail: None,
            },
        ];

        // No discounts → raw score.
        let (score, verdict, explanation) = aggregate_score(&mut findings, 0, 0, false);
        assert_eq!(score, 40);
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(explanation.raw_score, 40);
        assert_eq!(explanation.final_score, 40);
        assert!(explanation.suspicion_reasons.len() == 2);

        // With reputation discount → reduced.
        let (score2, verdict2, _) = aggregate_score(&mut findings, 20, 0, false);
        assert_eq!(score2, 20);
        assert_eq!(verdict2, Verdict::LowSuspicion);

        // With both discounts → uses max, not sum.
        let (score3, _, expl3) = aggregate_score(&mut findings, 20, 25, false);
        assert_eq!(score3, 15); // 40 - max(20,25) = 15
        assert_eq!(expl3.reputation_discount, 20);
        assert_eq!(expl3.authenticode_discount, 25);
    }

    // ═══════════════════════════════════════════════════════════════════
    // A) Trusted cache tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_trusted_cache_hit() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        cache.record("abc123hash", 0, Some("Microsoft Corporation"), None);
        let result = cache.check("abc123hash");
        assert_eq!(result, Some(0), "Cache should return the recorded score");
    }

    #[test]
    fn test_trusted_cache_rejects_unsigned() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        // No signer, no reputation → should NOT be cached.
        cache.record("unsigned_hash", 0, None, None);
        let result = cache.check("unsigned_hash");
        assert_eq!(
            result, None,
            "Unsigned file without reputation should not be cached"
        );
    }

    #[test]
    fn test_trusted_cache_invalidation() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        cache.record("valid_hash", 5, Some("Trusted Signer"), None);
        assert_eq!(cache.check("valid_hash"), Some(5));
        // Invalidate (simulates signature DB update).
        cache.invalidate();
        assert_eq!(
            cache.check("valid_hash"),
            None,
            "After invalidation, cache should return None"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // B) Category cap tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_structural_cap() {
        // 3 structural findings totaling weight 50; cap is 30.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "Structural A".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Structural B".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 15,
                description: "Structural C".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // After cap, structural contribution should be ≤30.
        let structural_total: u32 = findings
            .iter()
            .filter(|f| f.layer == Layer::StructuralAnalysis)
            .map(|f| f.weight)
            .sum();
        assert!(
            structural_total <= 30,
            "Structural cap should limit to 30, got {structural_total}"
        );
        assert!(score <= 30, "Total score should be ≤30, got {score}");
    }

    #[test]
    fn test_yara_cap() {
        // 3 YARA findings totaling weight 60; cap is 40.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "YARA match A".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 20,
                description: "YARA match B".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 15,
                description: "YARA match C".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        let yara_total: u32 = findings
            .iter()
            .filter(|f| f.layer == Layer::YaraRules)
            .map(|f| f.weight)
            .sum();
        assert!(
            yara_total <= 40,
            "YARA cap should limit to 40, got {yara_total}"
        );
        assert!(score <= 40, "Total score should be ≤40, got {score}");
    }

    // ═══════════════════════════════════════════════════════════════════
    // C) Confidence label tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_confidence_trusted_signed() {
        let label = ConfidenceLabel::from_context(0, true, true, false);
        assert_eq!(label, ConfidenceLabel::Trusted);
    }

    #[test]
    fn test_confidence_unusual_unsigned() {
        let label = ConfidenceLabel::from_context(20, false, false, false);
        assert_eq!(label, ConfidenceLabel::Unusual);
    }

    #[test]
    fn test_confidence_suspicious() {
        let label = ConfidenceLabel::from_context(50, false, false, false);
        assert_eq!(label, ConfidenceLabel::Suspicious);
    }

    // ═══════════════════════════════════════════════════════════════════
    // D) Context amplification tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_context_gate_blocks_low_score() {
        use std::path::PathBuf;
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\something.exe");
        let findings = crate::layers::context::analyze(&path, 3);
        assert!(
            findings.is_empty(),
            "Context gate should block score < 5, got {} findings",
            findings.len()
        );
    }

    #[test]
    fn test_context_gate_allows_above() {
        use std::path::PathBuf;
        // Use a path that triggers context (Downloads + exe).
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\suspicious.exe");
        let findings = crate::layers::context::analyze(&path, 10);
        // Downloads path with existing_score=10 should produce findings.
        assert!(
            !findings.is_empty(),
            "Context should amplify score >= 5 in Downloads"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // E) Framework detection test
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_framework_detection() {
        let findings = vec![Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: "PyInstaller bundled executable detected".into(),
            technical_detail: None,
        }];
        let framework = detect_framework_from_findings(&findings);
        assert_eq!(framework, Some("PyInstaller".to_string()));
    }

    #[test]
    fn test_aggregate_score_with_installer() {
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 10,
            description: "Structural finding".into(),
            technical_detail: None,
        }];

        let (_, _, expl) = aggregate_score(&mut findings, 0, 0, true);
        assert!(expl.installer_discount_applied);
        assert!(expl.trust_reasons.iter().any(|r| r.contains("Installer")));
    }

    #[test]
    fn test_installer_detection() {
        // NSIS installer.
        let mut nsis_data = vec![0x4D, 0x5A]; // MZ header.
        nsis_data.extend_from_slice(&[0; 500]);
        nsis_data.extend_from_slice(b"Nullsoft Inst");
        assert!(is_known_installer(&nsis_data, "test.exe"));

        // InnoSetup.
        let mut inno_data = vec![0x4D, 0x5A];
        inno_data.extend_from_slice(&[0; 500]);
        inno_data.extend_from_slice(b"Inno Setup S");
        assert!(is_known_installer(&inno_data, "test.exe"));

        // Filename-based detection requires large PE file (>2MB with MZ header).
        let mut large_data = vec![0u8; 3_000_000];
        large_data[0] = 0x4D; // M
        large_data[1] = 0x5A; // Z
        assert!(is_known_installer(&large_data, "Notion Setup 7.6.1.exe"));
        assert!(is_known_installer(&large_data, "git-2.53.0-installer.exe"));

        // Large non-PE with installer name → NOT detected (prevents FP on archives).
        let large_non_pe = vec![0u8; 3_000_000];
        assert!(!is_known_installer(&large_non_pe, "setup-files.zip"));

        // Small file with installer name → NOT detected (prevents FP on tiny scripts).
        assert!(!is_known_installer(&[0x4D, 0x5A], "setup.exe"));

        // NOT an installer.
        assert!(!is_known_installer(&[0x4D, 0x5A], "malware.exe"));

        // Electron framework → detected.
        let mut electron_data = vec![0u8; 500];
        electron_data.extend_from_slice(b"electron.asar");
        assert!(is_known_installer(&electron_data, "app.exe"));
    }

    #[test]
    fn test_explanation_has_weights() {
        // High-weight findings should show [+N] prefix in explanations.
        // Uses IOC layer which has no category cap in aggregate_score.
        let mut findings = vec![Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 35,
            description: "Critical IOC match detected".into(),
            technical_detail: None,
        }];
        let (_, _, expl) = aggregate_score(&mut findings, 0, 0, false);
        assert!(
            expl.suspicion_reasons[0].starts_with("[+35]"),
            "High-weight reason should have weight prefix, got: {}",
            expl.suspicion_reasons[0]
        );
    }

    #[test]
    fn test_ioc_match_is_malicious_strength() {
        let mut findings = vec![Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 90,
            description: "File hash matches a known-malicious indicator of compromise (IOC)."
                .into(),
            technical_detail: None,
        }];
        let (score, verdict, expl) = aggregate_score(&mut findings, 0, 0, false);
        assert_eq!(score, 90);
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(expl.confidence_label, ConfidenceLabel::HighRisk);
        assert_eq!(expl.threat_maturity, ThreatMaturity::ActiveMalware);
    }

    #[test]
    fn test_yara_rules_compile_cleanly() {
        // Verify all YARA rules in the runtime directory compile.
        let dirs = vec![std::path::PathBuf::from("../../runtime/argus/rules/yara")];
        let existing_dirs: Vec<_> = dirs.iter().filter(|d| d.exists()).cloned().collect();
        if existing_dirs.is_empty() {
            // Skip in CI where runtime dir may not exist.
            return;
        }
        let yara = crate::layers::yara::YaraEngine::new();
        let result = yara.load_rules(&existing_dirs);
        match result {
            Ok(count) => {
                assert!(count >= 100, "Expected at least 100 rules, got {count}");
                println!("YARA: {count} rules compiled successfully");
            }
            Err(e) => panic!("YARA compilation failed: {e}"),
        }
    }

    #[test]
    fn test_context_suppressed_for_trusted() {
        // Verify that trust_suppresses_context logic works:
        // When reputation or authenticode discount >= 15, context should not amplify.
        // Test via aggregate_score — if context was added, score would be higher.
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 5,
            description: "Minor structural finding".into(),
            technical_detail: None,
        }];

        // Without trust discount — score = 5.
        let (score_no_trust, _, _) = aggregate_score(&mut findings, 0, 0, false);
        assert_eq!(score_no_trust, 5);

        // With trust discount >= 15 — score should be 0 (5 - 15 = 0, clamped).
        let (score_trusted, _, _) = aggregate_score(&mut findings, 20, 0, false);
        assert_eq!(
            score_trusted, 0,
            "Trusted binary should have score 0 after discount"
        );
    }

    // ── Invariant tests ────────────────────────────────────

    #[test]
    fn test_invariant_context_alone_never_threat() {
        // Context findings with weight 15 (max) + no other findings.
        // Even at max context, score < 76 (Malicious threshold).
        let mut findings = vec![Finding {
            layer: Layer::Context,
            severity: Severity::Medium,
            weight: 15,
            description: "Internet download context".into(),
            technical_detail: None,
        }];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, false);
        assert!(
            score < 76,
            "Context alone should never reach Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_invariant_structural_alone_never_quarantine() {
        // Max structural cap (30) + max packer cap (20) = 50.
        // Even with every structural finding, still below 76.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "S1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "S2".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 10,
                description: "S3".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "P1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 10,
                description: "P2".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, false);
        assert!(
            score <= 50,
            "Structural+packer alone capped at 50. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_invariant_signed_installer_never_malicious() {
        // Signed installer with structural noise — trust should suppress.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "S1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "S2".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 5,
                description: "P1".into(),
                technical_detail: None,
            },
        ];
        // Signed (25 discount) + reputation (20 discount) → max(25,20)=25 off.
        let (score, verdict, _) = aggregate_score(&mut findings, 20, 25, true);
        assert!(
            score < 76,
            "Signed installer should never be Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_multi_layer_stealer_crosses_threshold() {
        // Real stealer: YARA match + pattern match + structural.
        // Must cross Malicious threshold despite category caps.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 30,
                description: "Discord token stealer".into(),
                technical_detail: Some("Pack: stealers".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft pattern".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 10,
                description: "Discord CDN download".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // YARA capped 30→30, Pattern capped 25→25, Structural capped 15→15, Context capped 10→10 = 80
        assert!(
            score >= 76,
            "Multi-layer stealer must cross Malicious threshold. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_deduplication_same_layer() {
        // Two findings from SAME layer with SAME behavior tag → deduplicated.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Downloads remote content via URLDownloadToFileA".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "InternetOpenUrlA download import".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Same layer + same tag → only max (12) counts.
        assert!(
            score <= 12,
            "Same-layer same-tag findings should be deduplicated. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_cross_layer_convergence() {
        // Two findings from DIFFERENT layers with same behavior tag → both count.
        // This is convergence: independent detections agreeing = higher confidence.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft pattern (YARA)".into(),
                technical_detail: Some("Pack: stealers".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Credential theft indicators detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Different layers → convergence → both count: 25 + 20 = 45.
        assert!(
            score >= 40,
            "Cross-layer convergence must count. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_unique_findings_preserved() {
        // Two findings describing DIFFERENT behaviors → both counted.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "Discord token stealer pattern".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Different behaviors → both counted.
        assert_eq!(
            score, 40,
            "Unique behaviors should both count. Score: {score}"
        );
    }

    #[test]
    fn test_go_binary_installer_detection() {
        // Go binary (>3MB with Go build ID marker) → installer/framework treatment.
        let mut data = vec![0u8; 4_000_000];
        data[1000..1012].copy_from_slice(b"Go build ID:");
        assert!(
            is_known_installer(&data, "mytool.exe"),
            "Go binary should be detected as installer/framework"
        );
    }

    #[test]
    fn test_confidence_label_framework_unsigned() {
        // Unsigned framework binary at score 45 → should be Unusual (not Suspicious)
        // if installer detected.
        let label = ConfidenceLabel::from_context(45, false, false, true);
        assert_eq!(
            label,
            ConfidenceLabel::Unusual,
            "Unsigned installer at score 45 should be Unusual"
        );
    }

    #[test]
    fn test_confidence_label_signed_installer_trusted() {
        // Signed installer at residual score 10 → Trusted.
        let label = ConfidenceLabel::from_context(10, true, true, true);
        assert_eq!(
            label,
            ConfidenceLabel::Trusted,
            "Signed installer should be Trusted"
        );
    }

    // ── Malware chain regression tests ─────────────────────

    #[test]
    fn test_stealer_chain_credential_plus_exfil() {
        // Credential theft + exfiltration are DIFFERENT behaviors → both counted.
        let mut findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft: Login Data and browser cookies accessed".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 22,
                description: "Data exfiltration via Discord webhook".into(),
                technical_detail: Some("Pack: stealer_exfil".into()),
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 10,
                description: "Downloaded from Discord CDN".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // All three are different groups → all counted.
        // Pattern 25 (capped 25), YARA 22 (capped 22), Context 10 (capped 10) = 57
        assert!(
            score >= 50,
            "Stealer chain must maintain high score. Score: {score}"
        );
    }

    #[test]
    fn test_ransomware_chain_encrypt_plus_delete() {
        // Ransomware: file enumeration + encryption + shadow copy deletion.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Critical,
                weight: 35,
                description: "Ransomware behavior: file encryption and ransom note creation".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Process kill list targeting security software".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Different behaviors → all counted. 35+20+15 = 70 (under caps).
        assert!(
            score >= 65,
            "Ransomware chain must remain high risk. Score: {score}"
        );
    }

    #[test]
    fn test_downloader_only_not_malicious() {
        // Just downloader capability — suspicious but not malicious.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "URLDownloadToFileA import detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 15,
                description: "File downloads remote content via HTTP".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, false);
        // Deduplicated: both are "downloader_capability" → only max (15) counts.
        assert!(
            score < 76,
            "Downloader-only should not be Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_packer_only_not_malicious() {
        // Just packing indicators — unusual but not malicious.
        // Cross-layer convergence: PackerDetection + Structural both detect packing → both count.
        let mut findings = vec![
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "UPX packed executable".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "Section has packed characteristics".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, false);
        // Cross-layer convergence: 15 + 6 = 21. Still well below Malicious (76).
        assert!(score <= 25, "Packer-only should be low. Score: {score}");
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_context_not_deduplicated_with_downloader() {
        // "Downloaded from internet" (context) + "has download APIs" (structural)
        // must NOT be deduplicated — they're different signals.
        let mut findings = vec![
            Finding {
                layer: Layer::Context,
                severity: Severity::Low,
                weight: 5,
                description: "Downloaded from the internet (Zone.Identifier)".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "URLDownloadToFileA import — downloads remote content".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Context is never deduplicated. Both count: 5 + 8 = 13.
        assert_eq!(
            score, 13,
            "Context + downloader must both count. Score: {score}"
        );
    }

    #[test]
    fn test_credential_theft_and_exfil_both_count() {
        // Credential theft + exfiltration are different attack stages → both count.
        let mut findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Credential theft indicators detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 18,
                description: "Data exfiltration via Telegram Bot API".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        assert_eq!(
            score, 38,
            "Credential theft + exfil must both count. Score: {score}"
        );
    }

    #[test]
    fn test_fake_updater_unsigned_crosses_threshold() {
        // Fake updater: downloader + persistence + evasion + unsigned + context.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Fake updater with download and execution".into(),
                technical_detail: Some("Pack: suspicious_updater".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Persistence via registry Run key".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Anti-debugging checks detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 12,
                description: "Downloaded from link monetizer".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Different groups: downloader(20) + persistence(20) + evasion(12) + context(12) = 64
        // No trust discounts → 64. Not auto-quarantine (ARGUS-only needs 85) but high suspicion.
        assert!(
            score >= 50,
            "Fake updater chain must be high risk. Score: {score}"
        );
    }

    #[test]
    fn test_entropy_dedup_within_structural() {
        // Two entropy findings from structural layer → deduplicated.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "Section has near-random entropy (7.8/8.0)".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Resource section contains high-entropy encrypted payload".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, false);
        // Both are "entropy" group, same layer → only max (12) counts.
        assert!(
            score <= 12,
            "Entropy findings should be deduplicated. Score: {score}"
        );
    }

    // ── BehaviorTag tests ──────────────────────────────────

    #[test]
    fn test_behavior_tag_context_is_origin() {
        let f = Finding {
            layer: Layer::Context,
            severity: Severity::Low,
            weight: 5,
            description: "Downloaded from internet".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::DownloadOriginContext));
    }

    #[test]
    fn test_behavior_tag_packer_detection() {
        let f = Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: "UPX packed binary".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Packing));
    }

    #[test]
    fn test_behavior_tag_yara_stealer() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 25,
            description: "Discord stealer".into(),
            technical_detail: Some("Pack: stealers".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::CredentialTheft));
    }

    #[test]
    fn test_behavior_tag_yara_exfil() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "Webhook exfil".into(),
            technical_detail: Some("Pack: stealer_exfil".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Exfiltration));
    }

    #[test]
    fn test_behavior_tag_yara_c2() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "C2 beacon".into(),
            technical_detail: Some("Pack: c2_indicators".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::C2Communication));
    }

    #[test]
    fn test_behavior_tag_yara_ransomware() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::Critical,
            weight: 35,
            description: "Ransom note".into(),
            technical_detail: Some("Pack: ransomware".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Ransomware));
    }

    #[test]
    fn test_behavior_tag_structural_entropy() {
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 6,
            description: "Near-random entropy section".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Entropy));
    }

    #[test]
    fn test_behavior_tag_structural_injection() {
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 30,
            description: "Process injection triad imports".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Injection));
    }

    #[test]
    fn test_behavior_tag_unique_finding() {
        // Generic structural finding with no specific behavior → None (always counted).
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Info,
            weight: 3,
            description: "Small import table".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), None);
    }

    #[test]
    fn test_behavior_tag_script_abuse() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 25,
            description: "PowerShell download cradle".into(),
            technical_detail: Some("Pack: powershell_advanced".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::ScriptAbuse));
    }

    // ── Convergence + confidence tests ─────────────────────

    #[test]
    fn test_convergence_stealer_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft indicators".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Exfiltration webhook".into(),
                technical_detail: Some("Pack: stealer_exfil".into()),
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "CredentialTheft + Exfiltration = Strong chain"
        );
        assert!(conv.chain_names.contains(&"stealer"));
        assert!(conv.distinct_behaviors >= 2);
    }

    #[test]
    fn test_convergence_backdoor_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Persistence via registry".into(),
                technical_detail: Some("Pack: persistence".into()),
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 18,
                description: "C2 beacon communication".into(),
                technical_detail: Some("Pack: c2_indicators".into()),
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "Persistence + C2 = Strong chain"
        );
        assert!(conv.chain_names.contains(&"backdoor"));
    }

    #[test]
    fn test_convergence_fake_installer_moderate() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Fake updater detected".into(),
                technical_detail: Some("Pack: suspicious_updater".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "Persistence via registry Run key".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength >= ChainStrength::Moderate,
            "FakeInstaller + Persistence = Moderate+"
        );
    }

    #[test]
    fn test_convergence_script_malware_moderate() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "PowerShell download cradle".into(),
                technical_detail: Some("Pack: powershell_advanced".into()),
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "Downloads remote content via InternetOpenUrlA".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength >= ChainStrength::Moderate,
            "ScriptAbuse + Downloader = Moderate+"
        );
    }

    #[test]
    fn test_convergence_weak_downloader_only() {
        use crate::verdict::ChainStrength;
        let findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 8,
            description: "URLDownloadToFileA import — downloads remote content".into(),
            technical_detail: None,
        }];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength <= ChainStrength::Weak,
            "Downloader-only = Weak or None"
        );
    }

    #[test]
    fn test_confidence_single_category_not_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(80, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Suspicious,
            "Single-category score 80 should be Suspicious, not HighRisk"
        );
    }

    #[test]
    fn test_confidence_strong_chain_promotes_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 2,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(55, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 55 + Strong chain + 3 behaviors → HighRisk"
        );
    }

    #[test]
    fn test_confidence_high_score_strong_convergence_malicious() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 4,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(95, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Malicious,
            "Score 95 + Strong chain + 4 behaviors → Malicious"
        );
    }

    #[test]
    fn test_confidence_high_score_weak_convergence_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(95, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 95 + weak convergence → HighRisk, not Malicious label"
        );
    }

    #[test]
    fn test_convergence_wallet_theft_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Crypto wallet theft".into(),
                technical_detail: Some("Pack: crypto_threats".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 18,
                description: "Credential theft: browser cookies".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "WalletTheft + CredentialTheft = Strong"
        );
    }

    #[test]
    fn test_weak_diverse_tags_not_auto_highrisk() {
        // Many weak unrelated tags should NOT auto-promote to HighRisk.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 5,
            distinct_layers: 2,
            chain_strength: ChainStrength::Weak,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(50, false, false, false, &conv);
        // 5 behaviors but only Weak chain → Suspicious, not HighRisk.
        assert_eq!(
            label,
            ConfidenceLabel::Suspicious,
            "Many weak tags at score 50 should be Suspicious, not HighRisk"
        );
    }

    #[test]
    fn test_score_70_with_strong_chain_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(70, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 70 + Strong chain → HighRisk"
        );
    }

    #[test]
    fn test_yara_category_backdoor_maps_to_c2() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 30,
            description: "RAT behavior".into(),
            technical_detail: Some("Pack: backdoor".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::C2Communication));
    }

    #[test]
    fn test_yara_category_miner_maps_to_pua() {
        // Crypto miners are PUA (potentially unwanted), not wallet theft.
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::Medium,
            weight: 15,
            description: "Crypto mining".into(),
            technical_detail: Some("Pack: miner".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::PotentiallyUnwanted));
    }

    #[test]
    fn test_yara_category_spyware_maps_to_credential() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "Keylogger".into(),
            technical_detail: Some("Pack: spyware".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::CredentialTheft));
    }

    // ── Attack progression tests ───────────────────────────

    #[test]
    fn test_progression_score_coherent_chain() {
        // InitialAccess → Execution → CredentialAccess → Exfiltration = 3 transitions.
        let tags = vec![
            BehaviorTag::DownloaderCapability, // InitialAccess (0)
            BehaviorTag::ScriptAbuse,          // Execution (1)
            BehaviorTag::CredentialTheft,      // CredentialAccess (4)
            BehaviorTag::Exfiltration,         // Exfiltration (6)
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert!(
            score >= 2,
            "Coherent 4-stage chain should have progression ≥2. Got: {score}"
        );
    }

    #[test]
    fn test_progression_score_single_stage() {
        // All DefenseEvasion → no transitions.
        let tags = vec![
            BehaviorTag::Packing,
            BehaviorTag::Entropy,
            BehaviorTag::Evasion,
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert_eq!(score, 0, "Same-stage tags should have 0 progression");
    }

    #[test]
    fn test_progression_score_two_stages() {
        // InitialAccess → Exfiltration = 1 transition (big gap but still 1).
        let tags = vec![BehaviorTag::DownloaderCapability, BehaviorTag::Exfiltration];
        let score = crate::verdict::attack_progression_score(&tags);
        // Gap of 6 stages — too large for "meaningful transition" (gap > 4).
        assert_eq!(score, 0, "Huge gap should not count as transition");
    }

    #[test]
    fn test_progression_close_stages() {
        // InitialAccess(0) → Execution(1) → Persistence(2) = 2 transitions.
        let tags = vec![
            BehaviorTag::FakeInstaller, // InitialAccess (0)
            BehaviorTag::ScriptAbuse,   // Execution (1)
            BehaviorTag::Persistence,   // Persistence (2)
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert_eq!(score, 2, "Three consecutive stages = 2 transitions");
    }

    // ── Process lineage tests ──────────────────────────────

    #[test]
    fn test_lineage_office_to_powershell() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("winword.exe".into()),
            process: Some("powershell.exe".into()),
        };
        assert_eq!(
            hint.suspicion_score(),
            15,
            "Office → PowerShell = max suspicion"
        );
    }

    #[test]
    fn test_lineage_explorer_to_installer() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("explorer.exe".into()),
            process: Some("setup.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "Explorer → installer = normal");
    }

    #[test]
    fn test_lineage_browser_to_temp() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("chrome.exe".into()),
            process: Some("C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe".into()),
        };
        assert_eq!(
            hint.suspicion_score(),
            10,
            "Browser → temp exe = suspicious"
        );
    }

    #[test]
    fn test_lineage_steam_to_game() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("steam.exe".into()),
            process: Some("game.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "Steam → game = normal");
    }

    #[test]
    fn test_lineage_no_parent() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: None,
            process: Some("something.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "No parent = no suspicion");
    }

    // ── ThreatMaturity tests ───────────────────────────────

    #[test]
    fn test_maturity_benign() {
        use crate::verdict::{ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo::default();
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 0),
            ThreatMaturity::Benign
        );
    }

    #[test]
    fn test_maturity_suspicious_utility() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Weak,
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 25),
            ThreatMaturity::SuspiciousUtility
        );
    }

    #[test]
    fn test_maturity_loader() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Moderate,
            chain_names: vec!["fake_installer"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 50),
            ThreatMaturity::Loader
        );
    }

    #[test]
    fn test_maturity_active_malware() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 80),
            ThreatMaturity::ActiveMalware
        );
    }

    #[test]
    fn test_maturity_destructive() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["ransomware"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 90),
            ThreatMaturity::DestructiveMalware
        );
    }

    // ── Signed abuse test ──────────────────────────────────

    #[test]
    fn test_signed_malicious_convergence_stays_highrisk() {
        // Signed binary with strong malicious chain → still HighRisk, not Trusted.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["backdoor"],
            progression_score: 2,
        };
        // Score 60 + signed → trust would normally make this Unusual.
        // But strong chain overrides trust.
        let label = ConfidenceLabel::from_convergence(60, true, true, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Signed binary with strong malicious chain must be HighRisk"
        );
    }

    #[test]
    fn test_signed_no_chain_stays_trusted() {
        // Signed binary with NO chain → stays trusted.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(15, true, true, true, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Trusted,
            "Signed installer with no chain should remain Trusted"
        );
    }

    // ── Scan strategy tests ────────────────────────────────

    #[test]
    fn test_strategy_exe_full() {
        assert_eq!(
            ScanStrategy::classify("malware.exe", 5_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_dll_full() {
        assert_eq!(
            ScanStrategy::classify("library.dll", 2_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_script_full() {
        assert_eq!(
            ScanStrategy::classify("payload.ps1", 50_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_archive_full() {
        assert_eq!(
            ScanStrategy::classify("archive.zip", 10_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_pdf_full() {
        assert_eq!(
            ScanStrategy::classify("document.pdf", 1_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_log_skip() {
        assert_eq!(
            ScanStrategy::classify("app.log", 100_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_rlib_skip() {
        assert_eq!(
            ScanStrategy::classify("libargus.rlib", 5_000_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_json_skip() {
        assert_eq!(
            ScanStrategy::classify("config.json", 10_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_image_signature_only() {
        assert_eq!(
            ScanStrategy::classify("photo.jpg", 3_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_video_signature_only() {
        assert_eq!(
            ScanStrategy::classify("movie.mp4", 50_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_firmware_signature_only() {
        assert_eq!(
            ScanStrategy::classify("firmware.bin", 60_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_too_large() {
        assert_eq!(
            ScanStrategy::classify("huge.exe", 200_000_000),
            ScanStrategy::TooLarge
        );
    }

    #[test]
    fn test_strategy_unknown_ext_light() {
        assert_eq!(
            ScanStrategy::classify("something.xyz", 500_000),
            ScanStrategy::LightAnalysis
        );
    }

    #[test]
    fn test_strategy_large_non_exe_signature_only() {
        // 60MB DLL → still full (DLLs are executable)
        assert_eq!(
            ScanStrategy::classify("driver.dll", 60_000_000),
            ScanStrategy::FullAnalysis
        );
        // 60MB DAT → signature only
        assert_eq!(
            ScanStrategy::classify("data.dat", 60_000_000),
            ScanStrategy::SignatureOnly
        );
    }
}

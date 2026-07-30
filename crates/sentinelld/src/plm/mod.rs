//! PLM — Process Lineage Monitor.
//!
//! Tracks parent-child process relationships via ETW process creation
//! events. When ASTRA scans a file, PLM provides lineage context:
//! "who spawned the process that created/modified this file?"
//!
//! This transforms ASTRA from a file scanner into a contextual
//! behavioral intelligence engine.
//!
//! Architecture:
//!   ETW → ProcessEvent → LineageGraph → ASTRA context query
//!
//! Example chain detection:
//!   winword.exe → powershell.exe → cmd.exe → temp.exe
//!   Each step alone: medium suspicion. Chain together: high confidence.

#![allow(dead_code)]

#[cfg(target_os = "windows")]
pub mod etw_intake;
pub mod etw_file_io;
pub mod etw_image_load;
pub mod weedhack_browser_injection;
pub mod weedhack_campaign;
pub mod weedhack_etherhiding;
pub mod weedhack_etw_adapters;
pub mod weedhack_http_intake;
pub mod weedhack_image_load;
pub mod weedhack_runtime;
pub mod weedhack_wallet_harvest;
pub mod wintrust_verifier;

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum process nodes to track (bounded graph).
const MAX_NODES: usize = 4096;
/// Process nodes older than this are evicted.
const NODE_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// A process node in the lineage graph.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub parent_pid: u32,
    /// Image path (executable).
    pub image_path: String,
    /// Image file name only.
    pub image_name: String,
    /// Command line (if available).
    pub command_line: Option<String>,
    /// Whether the binary is signed.
    pub is_signed: Option<bool>,
    /// Integrity level (if known).
    pub integrity_level: Option<String>,
    /// When this node was created.
    #[serde(skip)]
    pub created_at: Instant,
    /// Unix timestamp.
    pub timestamp: i64,
}

/// A process lineage chain — ordered from root to leaf.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessChain {
    /// Ordered process nodes (ancestor first, target last).
    pub nodes: Vec<ProcessNode>,
    /// Depth of the chain.
    pub depth: usize,
    /// Suspicion score contribution from the chain.
    pub chain_suspicion: u32,
    /// Human-readable chain description.
    pub description: String,
}

/// The lineage graph — bounded, TTL-evicted.
pub struct LineageGraph {
    nodes: Mutex<HashMap<u32, ProcessNode>>,
}

impl LineageGraph {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
        }
    }

    /// Record a process creation event.
    pub fn record_process(&self, node: ProcessNode) {
        let mut map = self.nodes.lock().unwrap_or_else(|e| e.into_inner());

        // ARCH-6 fix: strict cap. Evict expired first, then oldest if still full.
        if map.len() >= MAX_NODES {
            let now = Instant::now();
            map.retain(|_, n| now.duration_since(n.created_at) < NODE_TTL);

            // If still at capacity after TTL eviction (all nodes fresh), drop the
            // oldest in ONE batch down to 90% capacity. The previous code did a
            // fresh O(n) `min_by_key` scan + single removal on EVERY insert once
            // full → O(n) per insert under an ETW process storm. Batching to a
            // low-water mark amortizes the O(n log n) sort over ~10% of MAX_NODES
            // inserts, so the steady-state cost per insert is negligible.
            if map.len() >= MAX_NODES {
                let low_water = MAX_NODES * 9 / 10;
                // Sort by `created_at` (monotonic Instant), the same clock
                // the TTL eviction above uses — sorting by the wall-clock
                // `timestamp` would mix two clocks and make eviction order
                // sensitive to wall-clock adjustments.
                let mut by_age: Vec<(Instant, u32)> =
                    map.values().map(|n| (n.created_at, n.pid)).collect();
                // Oldest first (ascending age); pid as deterministic tiebreak.
                by_age.sort_unstable();
                let drop_count = map.len().saturating_sub(low_water);
                for (_, pid) in by_age.into_iter().take(drop_count) {
                    map.remove(&pid);
                }
            }
        }

        map.insert(node.pid, node);
    }

    /// Query the lineage chain for a process.
    /// Walks parent_pid links up to 8 levels.
    pub fn get_chain(&self, pid: u32) -> ProcessChain {
        let map = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let mut chain = Vec::new();
        let mut current = pid;
        let max_depth = 8;
        // PID-reuse guard: the map is keyed on PID alone, but the OS recycles
        // PIDs. If a child recorded parent_pid=N and PID N was later reused by
        // a NEWER process, walking parent_pid would attribute the child to the
        // wrong ancestor (false lineage → bogus convergence escalation). A real
        // parent must have been recorded no later than its child, so we reject
        // any hop where the candidate parent's `created_at` is AFTER the child's.
        let mut child_created_at: Option<Instant> = None;

        for _ in 0..max_depth {
            if let Some(node) = map.get(&current) {
                if let Some(child_ts) = child_created_at {
                    if node.created_at > child_ts {
                        // Candidate parent is younger than its child → the PID
                        // was recycled. Stop before recording false lineage.
                        break;
                    }
                }
                chain.push(node.clone());
                if node.parent_pid == 0 || node.parent_pid == node.pid {
                    break; // Root or self-parent.
                }
                child_created_at = Some(node.created_at);
                current = node.parent_pid;
            } else {
                break;
            }
        }

        chain.reverse(); // Ancestor first.
        let depth = chain.len();
        let suspicion = compute_chain_suspicion(&chain);
        let description = describe_chain(&chain);

        ProcessChain {
            nodes: chain,
            depth,
            chain_suspicion: suspicion,
            description,
        }
    }

    /// Get number of tracked processes.
    pub fn node_count(&self) -> usize {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Look up a single process node by PID. Returns a clone so the
    /// caller never holds the internal lock. Used by the WeedHack
    /// campaign integration to resolve a campaign-root PID back to its
    /// image name for diagnostics.
    pub fn get_node(&self, pid: u32) -> Option<ProcessNode> {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pid)
            .cloned()
    }

    /// Evict expired nodes.
    pub fn evict_expired(&self) {
        let mut map = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        map.retain(|_, n| now.duration_since(n.created_at) < NODE_TTL);
    }
}

/// Compute suspicion score for a process chain.
/// LOLBin chains and Office macro chains get high scores.
///
/// Generic-chain weight is capped at 30 (convergence contribution, not a
/// standalone verdict). Family-specific runtime signals (WeedHack) are
/// ADDED on top of that base — they represent confirmed family attribution
/// at runtime, equivalent to an IOC hit, and are NOT subject to the 30 cap.
/// The combined score is hard-capped at 100 to align with the verdict scale.
fn compute_chain_suspicion(chain: &[ProcessNode]) -> u32 {
    // WeedHack signals can fire on a single node (e.g. Pjibf.exe running by
    // itself) so evaluate them first, independent of chain depth.
    let weedhack = weedhack_runtime::chain_score(chain);

    if chain.len() <= 1 {
        return weedhack.min(100);
    }

    let mut suspicion: u32 = 0;

    // Check for suspicious parent-child transitions.
    for window in chain.windows(2) {
        let parent = &window[0].image_name;
        let child = &window[1].image_name;
        suspicion += transition_weight(parent, child);
    }

    // Depth bonus: deeper chains are more suspicious.
    if chain.len() >= 4 {
        suspicion += 5;
    }

    let base = suspicion.min(30);
    base.saturating_add(weedhack).min(100)
}

/// Weight for a specific parent→child transition.
fn transition_weight(parent: &str, child: &str) -> u32 {
    let p = parent.to_lowercase();
    let c = child.to_lowercase();

    // Office → script engine = macro attack.
    if is_office_app(&p) && is_script_engine(&c) {
        return 15;
    }

    // Script engine → command shell = download cradle.
    if is_script_engine(&p) && is_shell(&c) {
        return 8;
    }

    // Shell → LOLBin = proxy execution.
    if is_shell(&p) && is_lolbin(&c) {
        return 10;
    }

    // LOLBin → unknown executable = payload delivery.
    if is_lolbin(&p) && !is_system_binary(&c) {
        return 8;
    }

    // Script engine → unknown executable.
    if is_script_engine(&p) && !is_system_binary(&c) {
        return 6;
    }

    0
}

fn is_office_app(name: &str) -> bool {
    matches!(
        name,
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "msaccess.exe"
    )
}

fn is_script_engine(name: &str) -> bool {
    matches!(
        name,
        "powershell.exe" | "pwsh.exe" | "cscript.exe" | "wscript.exe" | "mshta.exe" | "cmd.exe"
    )
}

fn is_shell(name: &str) -> bool {
    matches!(name, "cmd.exe" | "powershell.exe" | "pwsh.exe")
}

fn is_lolbin(name: &str) -> bool {
    matches!(
        name,
        "rundll32.exe"
            | "regsvr32.exe"
            | "mshta.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "msiexec.exe"
            | "wmic.exe"
            | "cmstp.exe"
            | "installutil.exe"
            | "msbuild.exe"
            | "forfiles.exe"
    )
}

fn is_system_binary(name: &str) -> bool {
    matches!(
        name,
        "svchost.exe"
            | "csrss.exe"
            | "lsass.exe"
            | "services.exe"
            | "winlogon.exe"
            | "explorer.exe"
            | "dwm.exe"
            | "taskhost.exe"
            | "conhost.exe"
            | "sihost.exe"
            | "fontdrvhost.exe"
    )
}

/// Human-readable chain description for ASTRA explanations.
fn describe_chain(chain: &[ProcessNode]) -> String {
    if chain.is_empty() {
        return "No lineage data".into();
    }
    chain
        .iter()
        .map(|n| n.image_name.as_str())
        .collect::<Vec<_>>()
        .join(" → ")
}

/// Create an ARGUS finding from process lineage analysis.
///
/// When WeedHack runtime signals fire, the finding is routed to
/// `Layer::IocCorrelation` (uncapped) at `Critical` severity and the
/// description names the specific signals — sysadmins reading the
/// quarantine report see exactly which behaviour triggered the kill,
/// not just "chain looked weird".
///
/// Without WeedHack signals the existing generic-chain semantics are
/// preserved: routed to `Layer::Context` (cap 15) with tiered severity.
pub fn lineage_finding(chain: &ProcessChain) -> Option<argus::Finding> {
    if chain.chain_suspicion == 0 {
        return None;
    }

    let weedhack_hits = weedhack_runtime::evaluate_chain(&chain.nodes);

    if !weedhack_hits.is_empty() {
        return Some(argus::Finding {
            layer: argus::verdict::Layer::IocCorrelation,
            severity: argus::verdict::Severity::Critical,
            weight: chain.chain_suspicion,
            description: format!(
                "WeedHack runtime detection in process lineage (depth {}): {} — {}",
                chain.depth,
                chain.description,
                weedhack_runtime::describe_signals(&weedhack_hits),
            ),
            technical_detail: Some(serde_json::to_string(chain).unwrap_or_default()),
        });
    }

    let severity = if chain.chain_suspicion >= 15 {
        argus::verdict::Severity::High
    } else if chain.chain_suspicion >= 8 {
        argus::verdict::Severity::Medium
    } else {
        argus::verdict::Severity::Low
    };

    Some(argus::Finding {
        layer: argus::verdict::Layer::Context, // Lineage feeds into context layer.
        severity,
        weight: chain.chain_suspicion,
        description: format!(
            "Suspicious process lineage (depth {}): {}",
            chain.depth, chain.description
        ),
        technical_detail: Some(serde_json::to_string(chain).unwrap_or_default()),
    })
}

// ═══════════════════════════════════════════════════════════════
//  Live PLM Monitor — background process snapshot intake
// ═══════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// PLM diagnostics — atomic counters.
pub struct PlmDiagnostics {
    pub events_seen: AtomicU64,
    pub chains_scored: AtomicU64,
    pub dropped_events: AtomicU64,
    pub suspicious_chains: AtomicU64,
}

impl PlmDiagnostics {
    pub fn new() -> Self {
        Self {
            events_seen: AtomicU64::new(0),
            chains_scored: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            suspicious_chains: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self, node_count: usize) -> serde_json::Value {
        serde_json::json!({
            "enabled": true,
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "nodes": node_count,
            "chains_scored": self.chains_scored.load(Ordering::Relaxed),
            "dropped_events": self.dropped_events.load(Ordering::Relaxed),
            "suspicious_chains": self.suspicious_chains.load(Ordering::Relaxed),
        })
    }
}

/// PLM intake mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlmMode {
    /// Real-time ETW kernel process events.
    Etw,
    /// Periodic process snapshot polling.
    Snapshot,
}

/// Live PLM monitor — background process lineage tracking.
/// Tries ETW first for real-time events, falls back to snapshot polling.
pub struct PlmMonitor {
    pub graph: Arc<LineageGraph>,
    pub diagnostics: Arc<PlmDiagnostics>,
    pub mode: PlmMode,
    /// WeedHack campaign correlator. Stays bounded by `MAX_CAMPAIGNS`,
    /// evicted alongside the lineage graph by the maintenance loop.
    pub weedhack_tracker: Arc<weedhack_campaign::WeedHackCampaignTracker>,
    /// Diagnostics for the campaign subsystem (atomic counters + ring
    /// buffer of recent findings). Exposed in the daemon's status JSON.
    pub weedhack_diagnostics: Arc<weedhack_campaign::WeedHackCampaignDiagnostics>,
    /// Wave 3 — ImageLoad ETW filter. Orchestration layer between the
    /// Windows ETW callback (when implemented) and the canonical
    /// `weedhack_browser_injection` detector. Always present; the
    /// Windows-only ETW provider source feeds it when running.
    pub weedhack_image_load_filter: Arc<weedhack_image_load::BrowserImageLoadFilter>,
    /// Wave 4 — ImageLoad kernel ETW pump diagnostics. Counters track the
    /// kernel-side hot path (events seen, parse errors, forwards, drops).
    /// Surfaced under `image_load_etw` in the campaign diagnostics JSON.
    pub image_load_etw_diagnostics: Arc<etw_image_load::ImageLoadEtwDiagnostics>,
    /// Wave 5 — WinTrust-backed signer verifier. Replaces the Wave 3
    /// NullSignerVerifier with a real Authenticode chain check (via
    /// argus). Diagnostics counters surfaced under
    /// `image_load_etw.signer`.
    pub weedhack_signer_verifier: Arc<wintrust_verifier::WinTrustModuleSignerVerifier>,
    /// Wave 6 — WalletHarvestDetector that the FileIO ETW worker feeds.
    /// Shared via Arc; per-PID state and threshold/dedup live inside.
    pub weedhack_wallet_detector: Arc<weedhack_wallet_harvest::WalletHarvestDetector>,
    /// Wave 6 — FileIO ETW pump diagnostics. Counters surface under
    /// `fileio_etw` in the campaign diagnostics JSON.
    pub file_io_etw_diagnostics: Arc<etw_file_io::FileIoEtwDiagnostics>,
    /// Wave 7 — HTTP intake diagnostics. Counters surface under
    /// `http_intake` in the campaign diagnostics JSON. The actual
    /// WinHTTP / WinINet ETW listener is intentionally NOT shipped —
    /// see weedhack_http_intake module docs for the body-visibility
    /// reasoning. The pipeline is reachable via
    /// `PlmMonitor::ingest_http_post()`.
    pub http_intake_diagnostics: Arc<weedhack_http_intake::HttpIntakeDiagnostics>,
    running: Arc<AtomicBool>,
    _snapshot_thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os = "windows")]
    _etw_thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os = "windows")]
    pub etw_diagnostics: Option<Arc<etw_intake::EtwIntakeDiagnostics>>,
}

impl PlmMonitor {
    /// Start the PLM monitor. Tries ETW first, falls back to snapshot.
    pub fn start(interval_secs: u64) -> Self {
        let graph = Arc::new(LineageGraph::new());
        let diagnostics = Arc::new(PlmDiagnostics::new());
        let running = Arc::new(AtomicBool::new(true));

        // WeedHack campaign correlator — backed by a resolver wrapping
        // the lineage graph above.
        let resolver: Arc<dyn weedhack_campaign::LineageResolver> = Arc::new(
            weedhack_campaign::LineageGraphResolver::new(Arc::clone(&graph)),
        );
        let weedhack_tracker = Arc::new(
            weedhack_campaign::WeedHackCampaignTracker::new(resolver),
        );
        let weedhack_diagnostics =
            Arc::new(weedhack_campaign::WeedHackCampaignDiagnostics::new());
        let weedhack_image_load_filter =
            Arc::new(weedhack_image_load::BrowserImageLoadFilter::new());

        // Wave 5: WinTrust-backed signer verifier. The Arc<dyn> object
        // hands to the worker thread; the strongly-typed Arc on
        // PlmMonitor is kept so diagnostics can be surfaced.
        let weedhack_signer_verifier =
            Arc::new(wintrust_verifier::WinTrustModuleSignerVerifier::new());
        let signer_verifier_dyn: Arc<dyn weedhack_image_load::ModuleSignerVerifier> =
            Arc::clone(&weedhack_signer_verifier)
                as Arc<dyn weedhack_image_load::ModuleSignerVerifier>;

        // Wave 4: start the ImageLoad ETW worker thread. The worker is
        // OS-agnostic — on Windows it receives events from the kernel
        // pump; on other platforms it idles (no events ever arrive).
        let (image_load_etw_diagnostics, _image_load_thread) =
            etw_image_load::start_image_load_worker(
                Arc::clone(&weedhack_image_load_filter),
                Arc::clone(&weedhack_tracker),
                Arc::clone(&weedhack_diagnostics),
                Arc::clone(&graph),
                Arc::clone(&running),
                signer_verifier_dyn,
            );

        // Wave 6: WalletHarvestDetector + FileIO ETW worker. The detector
        // lives on PlmMonitor so it's reachable from non-ETW callers
        // (e.g. tests, future tools); the worker feeds it from the
        // bounded channel attached to the shared SentinellaPLM session.
        let weedhack_wallet_detector =
            Arc::new(weedhack_wallet_harvest::WalletHarvestDetector::new());
        let (file_io_etw_diagnostics, _file_io_thread) = etw_file_io::start_file_io_worker(
            Arc::clone(&weedhack_wallet_detector),
            Arc::clone(&weedhack_tracker),
            Arc::clone(&weedhack_diagnostics),
            Arc::clone(&graph),
            Arc::clone(&running),
        );

        // Wave 7: HTTP intake worker. Spawned ready-to-receive; the
        // public ingest entry point is PlmMonitor::ingest_http_post().
        let (http_intake_diagnostics, _http_dedup, _http_thread) =
            weedhack_http_intake::start_http_intake_worker(
                Arc::clone(&weedhack_tracker),
                Arc::clone(&weedhack_diagnostics),
                Arc::clone(&graph),
                Arc::clone(&running),
            );

        // Try ETW first (requires admin).
        #[cfg(target_os = "windows")]
        let (etw_thread, etw_diag, mode) = {
            let etw_d = Arc::new(etw_intake::EtwIntakeDiagnostics::new());
            match etw_intake::start_etw_intake(
                Arc::clone(&graph),
                Arc::clone(&etw_d),
                Arc::clone(&running),
            ) {
                Ok(thread) => {
                    tracing::info!("PLM: ETW real-time mode active");
                    (Some(thread), Some(etw_d), PlmMode::Etw)
                }
                Err(e) => {
                    tracing::info!(error = %e, "PLM: ETW unavailable, using snapshot mode");
                    (None, Some(etw_d), PlmMode::Snapshot)
                }
            }
        };

        #[cfg(not(target_os = "windows"))]
        let mode = PlmMode::Snapshot;

        // Snapshot interval: if ETW thread is alive, snapshot is supplemental (6x slower).
        // A background monitor checks if ETW gave up and boosts snapshot frequency.
        let snapshot_interval = Arc::new(AtomicU64::new(if mode == PlmMode::Etw {
            interval_secs * 6
        } else {
            interval_secs
        }));

        // Always run snapshot thread (as primary or supplemental cleanup).
        let g = Arc::clone(&graph);
        let d = Arc::clone(&diagnostics);
        let r = Arc::clone(&running);
        let si = Arc::clone(&snapshot_interval);
        let wh_tracker = Arc::clone(&weedhack_tracker);
        let wh_diag = Arc::clone(&weedhack_diagnostics);

        let snapshot_thread = std::thread::Builder::new()
            .name("plm-snapshot".into())
            .spawn(move || {
                plm_loop(g, d, r, si, wh_tracker, wh_diag);
            })
            .ok();

        // If ETW was attempted, spawn a tiny monitor that detects ETW giving up
        // and boosts snapshot interval to primary frequency.
        #[cfg(target_os = "windows")]
        if mode == PlmMode::Etw {
            let etw_d2 = etw_diag.clone();
            let si2 = Arc::clone(&snapshot_interval);
            let r2 = Arc::clone(&running);
            let primary_interval = interval_secs;
            std::thread::Builder::new()
                .name("plm-etw-watchdog".into())
                .spawn(move || {
                    // Check every 5s if ETW gave up.
                    while r2.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_secs(5));
                        if let Some(ref ed) = etw_d2 {
                            if ed.etw_gave_up.load(Ordering::Relaxed) {
                                tracing::info!(
                                    interval_secs = primary_interval,
                                    "PLM: ETW gave up, boosting snapshot to primary frequency"
                                );
                                si2.store(primary_interval, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                })
                .ok();
        }

        Self {
            graph,
            diagnostics,
            mode,
            weedhack_tracker,
            weedhack_diagnostics,
            weedhack_image_load_filter,
            image_load_etw_diagnostics,
            weedhack_signer_verifier,
            weedhack_wallet_detector,
            file_io_etw_diagnostics,
            http_intake_diagnostics,
            running,
            _snapshot_thread: snapshot_thread,
            #[cfg(target_os = "windows")]
            _etw_thread: etw_thread,
            #[cfg(target_os = "windows")]
            etw_diagnostics: etw_diag,
        }
    }

    // ── WeedHack campaign integration (Phase 3) ─────────────────────

    /// Ingest one WeedHack runtime signal for `emitting_pid`. Returns
    /// an `argus::Finding` ONLY when the campaign's confidence tier
    /// advances — never when a signal is a no-op duplicate or doesn't
    /// move the needle.
    ///
    /// Suspicious tier maps to Layer::Context / Medium / weight 10 →
    /// observe-only, will not push verdict to Malicious by itself.
    /// HighConfidence is Layer::Context / High / weight 20 → capped at
    /// 15 by the layer, still needs corroboration. Confirmed routes to
    /// the uncapped Layer::IocCorrelation / Critical with the cumulative
    /// campaign score, eligible for the existing quarantine pipeline via
    /// the ConvergenceLedger.
    pub fn ingest_weedhack_signal(
        &self,
        emitting_pid: u32,
        signal: weedhack_runtime::WeedHackSignal,
    ) -> Option<argus::Finding> {
        let finding = self.weedhack_tracker.ingest_signal(emitting_pid, signal)?;
        let root_image = self
            .graph
            .get_node(finding.root.pid)
            .map(|n| n.image_name);
        let now_unix = chrono::Utc::now().timestamp();
        self.weedhack_diagnostics
            .record(&finding, root_image.clone(), now_unix);
        self.weedhack_diagnostics
            .note_active(self.weedhack_tracker.active_campaign_count());
        Some(finding.to_argus_finding(root_image))
    }

    /// Evaluate the lineage chain ending at `leaf_pid` for WeedHack
    /// runtime signals and feed each one through the campaign tracker.
    /// Returns the campaign-tier ARGUS findings emitted (if any) — one
    /// per tier advancement during this call.
    ///
    /// This is OPT-IN: callers explicitly ask for campaign observation
    /// when they think a scanned file lives under a process tree worth
    /// correlating. Existing `lineage_finding()` behaviour is unchanged.
    pub fn observe_chain_for_weedhack(&self, leaf_pid: u32) -> Vec<argus::Finding> {
        let chain = self.graph.get_chain(leaf_pid);
        let signals = weedhack_runtime::evaluate_chain(&chain.nodes);
        let mut out = Vec::new();
        for sig in signals {
            if let Some(f) = self.ingest_weedhack_signal(leaf_pid, sig) {
                out.push(f);
            }
        }
        out
    }

    /// Serialize the WeedHack campaign subsystem's diagnostics view.
    /// Includes the ImageLoad filter counters under `image_load_filter`
    /// and the kernel ETW pump counters under `image_load_etw`. PLM
    /// session lifecycle (running/access_denied/gave_up/reconnects) is
    /// mirrored from `etw_diagnostics` into the ETW block — these
    /// describe the SHARED session that drives both PLM and ImageLoad.
    pub fn weedhack_diagnostics_json(&self) -> serde_json::Value {
        let mut base = self
            .weedhack_diagnostics
            .to_json(self.weedhack_tracker.active_campaign_count());

        // Reflect shared-session state into BOTH ImageLoad and FileIO ETW
        // diagnostics — they share the SentinellaPLM session, so a single
        // PLM ETW health value drives both views.
        #[cfg(target_os = "windows")]
        {
            if let Some(ref etw) = self.etw_diagnostics {
                use std::sync::atomic::Ordering;
                let running = etw.etw_running.load(Ordering::Relaxed);
                let gave_up = etw.etw_gave_up.load(Ordering::Relaxed);
                let reconnects = etw.reconnects.load(Ordering::Relaxed);

                self.image_load_etw_diagnostics
                    .running
                    .store(running, Ordering::Relaxed);
                self.image_load_etw_diagnostics
                    .access_denied
                    .store(gave_up, Ordering::Relaxed);
                self.image_load_etw_diagnostics
                    .gave_up
                    .store(gave_up, Ordering::Relaxed);
                self.image_load_etw_diagnostics
                    .reconnects
                    .store(reconnects, Ordering::Relaxed);

                self.file_io_etw_diagnostics
                    .running
                    .store(running, Ordering::Relaxed);
                self.file_io_etw_diagnostics
                    .access_denied
                    .store(gave_up, Ordering::Relaxed);
                self.file_io_etw_diagnostics
                    .gave_up
                    .store(gave_up, Ordering::Relaxed);
                self.file_io_etw_diagnostics
                    .reconnects
                    .store(reconnects, Ordering::Relaxed);
            }
        }

        if let Some(obj) = base.as_object_mut() {
            obj.insert(
                "image_load_filter".into(),
                self.weedhack_image_load_filter.diagnostics_json(),
            );
            // image_load_etw now carries the signer sub-block per Wave 5 spec.
            let mut etw_json = self.image_load_etw_diagnostics.to_json();
            if let Some(etw_obj) = etw_json.as_object_mut() {
                etw_obj.insert(
                    "signer".into(),
                    self.weedhack_signer_verifier.diagnostics_json(),
                );
            }
            obj.insert("image_load_etw".into(), etw_json);

            // Wave 6: FileIO pump diagnostics, sibling block to image_load_etw.
            obj.insert(
                "fileio_etw".into(),
                self.file_io_etw_diagnostics.to_json(),
            );

            // Wave 7: HTTP intake diagnostics. Body capture is dormant
            // by design (see weedhack_http_intake docs) — the counters
            // show exactly what the pipeline could see.
            obj.insert(
                "http_intake".into(),
                self.http_intake_diagnostics.to_json(),
            );
        }
        base
    }

    /// Wave 7 public ingestion entry point. Any source that can supply
    /// HTTP request data — current and future — calls this to feed the
    /// EtherHiding detection pipeline. The path is a no-op when the
    /// worker hasn't been started.
    pub fn ingest_http_post(
        &self,
        event: weedhack_http_intake::HttpPostRawEvent,
    ) -> Result<(), ()> {
        weedhack_http_intake::ingest(event)
    }

    /// Ingest a raw ImageLoad event from the Windows ETW provider.
    /// Returns `Some(argus::Finding)` ONLY when the canonical detector
    /// emits AND the campaign tracker's tier advances. Otherwise the
    /// caller (ETW thread) simply discards `None` and the next scan-site
    /// hook surfaces accumulated state when it runs.
    ///
    /// Production lineage / signer probes are built from the PLM
    /// LineageGraph + the Wave 5 WinTrust-backed signer verifier
    /// (`self.weedhack_signer_verifier`). Tests can call the underlying
    /// `weedhack_image_load_filter.process_event` directly with mocks.
    pub fn ingest_image_load(
        &self,
        event: weedhack_image_load::ImageLoadRawEvent,
    ) -> Option<argus::Finding> {
        // The lineage checker is built per-call to capture the graph's
        // current Arc — cheap; the inner graph lookup is the only work.
        let lineage = weedhack_image_load::LineageGraphJavaChecker::new(Arc::clone(&self.graph));
        let signal = self
            .weedhack_image_load_filter
            .process_event(event.clone(), &*self.weedhack_signer_verifier, &lineage)?;
        self.ingest_weedhack_signal(event.target_pid, signal)
    }

    /// Query lineage for a file path — find recent processes matching this image.
    pub fn query_by_image_path(&self, path: &std::path::Path) -> Option<ProcessChain> {
        let p = path.to_string_lossy().to_lowercase();
        let map = self.graph.nodes.lock().unwrap_or_else(|e| e.into_inner());

        // Find most recent process with matching image path.
        let target_pid = map
            .values()
            .filter(|n| n.image_path.to_lowercase() == p)
            .max_by_key(|n| n.timestamp)
            .map(|n| n.pid);
        drop(map);

        if let Some(pid) = target_pid {
            self.diagnostics
                .chains_scored
                .fetch_add(1, Ordering::Relaxed);
            let chain = self.graph.get_chain(pid);
            if chain.chain_suspicion > 0 {
                self.diagnostics
                    .suspicious_chains
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(chain)
        } else {
            None
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for PlmMonitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Background loop: snapshot processes and feed into graph.
fn plm_loop(
    graph: Arc<LineageGraph>,
    diagnostics: Arc<PlmDiagnostics>,
    running: Arc<AtomicBool>,
    interval: Arc<AtomicU64>,
    weedhack_tracker: Arc<weedhack_campaign::WeedHackCampaignTracker>,
    weedhack_diagnostics: Arc<weedhack_campaign::WeedHackCampaignDiagnostics>,
) {
    let initial = interval.load(Ordering::Relaxed);
    tracing::info!("PLM monitor started (interval={}s)", initial);

    // Initial snapshot.
    snapshot_processes(&graph, &diagnostics);

    while running.load(Ordering::Relaxed) {
        let secs = interval.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(secs));
        if !running.load(Ordering::Relaxed) {
            break;
        }

        snapshot_processes(&graph, &diagnostics);

        // Periodic eviction of stale lineage nodes and stale campaigns.
        graph.evict_expired();
        let evicted = weedhack_tracker.evict_expired();
        weedhack_diagnostics.note_evicted(evicted);
        weedhack_diagnostics.note_active(weedhack_tracker.active_campaign_count());
    }

    tracing::info!("PLM monitor stopped");
}

/// Snapshot all running processes and add to graph.
#[cfg(target_os = "windows")]
fn snapshot_processes(graph: &LineageGraph, diagnostics: &PlmDiagnostics) {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = match snapshot {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            diagnostics.dropped_events.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // RAII handle guard: previously CloseHandle was called manually on each
    // exit path. The daemon snapshots processes repeatedly; any panic between
    // acquisition and close leaked a kernel handle each pass — bounded by the
    // per-process handle table on long-running boxes. The guard closes on
    // every drop (normal, early-return, panic).
    struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
    impl Drop for SnapshotGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    let _snap_guard = SnapshotGuard(snapshot);

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if ok.is_err() {
        return; // guard closes the handle
    }

    let now = Instant::now();
    let ts = chrono::Utc::now().timestamp();
    let mut count = 0u64;

    loop {
        let exe_name = wide_to_string_plm(&entry.szExeFile);
        let pid = entry.th32ProcessID;
        let ppid = entry.th32ParentProcessID;

        if !exe_name.is_empty() && pid != 0 {
            let image_name = exe_name.rsplit('\\').next().unwrap_or(&exe_name);
            // Insert if not already tracked — but ALSO re-record when the
            // tracked node's identity differs from the live ToolHelp
            // entry: in snapshot-only mode (ETW unavailable) a recycled
            // PID would otherwise keep the previous owner's image name,
            // parents, and created_at for up to NODE_TTL, defeating the
            // PID-reuse guard in get_chain (which keys on created_at
            // freshness that snapshot mode would never update).
            let map = graph.nodes.lock().unwrap_or_else(|e| e.into_inner());
            let needs_record = match map.get(&pid) {
                None => true,
                Some(n) => {
                    n.parent_pid != ppid || !n.image_name.eq_ignore_ascii_case(image_name)
                }
            };
            drop(map);

            if needs_record {
                graph.record_process(ProcessNode {
                    pid,
                    parent_pid: ppid,
                    image_path: exe_name.clone(),
                    image_name: image_name.to_string(),
                    command_line: None, // ToolHelp32 doesn't provide cmdline.
                    is_signed: None,
                    integrity_level: None,
                    created_at: now,
                    timestamp: ts,
                });
                count += 1;
            }
        }

        let ok = unsafe { Process32NextW(snapshot, &mut entry) };
        if ok.is_err() {
            break;
        }
    }
    // _snap_guard closes the handle on drop here.
    diagnostics.events_seen.fetch_add(count, Ordering::Relaxed);
}

#[cfg(not(target_os = "windows"))]
fn snapshot_processes(_graph: &LineageGraph, _diagnostics: &PlmDiagnostics) {
    // PLM not available on non-Windows platforms.
}

#[cfg(target_os = "windows")]
fn wide_to_string_plm(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(pid: u32, ppid: u32, name: &str) -> ProcessNode {
        ProcessNode {
            pid,
            parent_pid: ppid,
            image_path: format!("C:\\Windows\\System32\\{name}"),
            image_name: name.to_string(),
            command_line: None,
            is_signed: Some(true),
            integrity_level: None,
            created_at: Instant::now(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    #[test]
    fn record_and_query() {
        let graph = LineageGraph::new();
        graph.record_process(make_node(100, 0, "explorer.exe"));
        graph.record_process(make_node(200, 100, "powershell.exe"));
        graph.record_process(make_node(300, 200, "cmd.exe"));

        let chain = graph.get_chain(300);
        assert_eq!(chain.depth, 3);
        assert_eq!(chain.nodes[0].image_name, "explorer.exe");
        assert_eq!(chain.nodes[2].image_name, "cmd.exe");
    }

    #[test]
    fn office_macro_chain_high_suspicion() {
        let graph = LineageGraph::new();
        graph.record_process(make_node(1, 0, "explorer.exe"));
        graph.record_process(make_node(2, 1, "winword.exe"));
        graph.record_process(make_node(3, 2, "powershell.exe"));
        graph.record_process(make_node(4, 3, "cmd.exe"));

        let chain = graph.get_chain(4);
        // winword→powershell = 15, powershell→cmd = 8, depth bonus = 5
        assert!(chain.chain_suspicion >= 20);
    }

    #[test]
    fn normal_chain_no_suspicion() {
        let graph = LineageGraph::new();
        graph.record_process(make_node(1, 0, "explorer.exe"));
        graph.record_process(make_node(2, 1, "notepad.exe"));

        let chain = graph.get_chain(2);
        assert_eq!(chain.chain_suspicion, 0);
    }

    #[test]
    fn chain_description_readable() {
        let graph = LineageGraph::new();
        graph.record_process(make_node(1, 0, "winword.exe"));
        graph.record_process(make_node(2, 1, "powershell.exe"));
        graph.record_process(make_node(3, 2, "rundll32.exe"));

        let chain = graph.get_chain(3);
        assert_eq!(
            chain.description,
            "winword.exe → powershell.exe → rundll32.exe"
        );
    }

    #[test]
    fn lineage_finding_generated() {
        let graph = LineageGraph::new();
        graph.record_process(make_node(1, 0, "winword.exe"));
        graph.record_process(make_node(2, 1, "powershell.exe"));

        let chain = graph.get_chain(2);
        let finding = lineage_finding(&chain);
        assert!(finding.is_some());
        assert!(finding.unwrap().weight >= 10);
    }

    #[test]
    fn pid_reuse_does_not_produce_false_lineage() {
        // Legit chain: 100 (explorer) → 200 (powershell) → 300 (cmd).
        let graph = LineageGraph::new();
        graph.record_process(make_node(100, 0, "explorer.exe"));
        graph.record_process(make_node(200, 100, "powershell.exe"));
        graph.record_process(make_node(300, 200, "cmd.exe"));

        // PID 200 is recycled by a NEWER, unrelated process recorded later.
        // (sleep so its created_at is strictly after node 300's.)
        std::thread::sleep(Duration::from_millis(5));
        graph.record_process(make_node(200, 999, "malware.exe"));

        // Walking from 300 must NOT attach 300 to the recycled 200/999 lineage.
        // The younger parent is rejected, so the chain stops at 300.
        let chain = graph.get_chain(300);
        assert_eq!(chain.depth, 1, "recycled parent must not extend the chain");
        assert_eq!(chain.nodes[0].image_name, "cmd.exe");
        assert!(
            !chain.nodes.iter().any(|n| n.image_name == "malware.exe"),
            "recycled-PID process leaked into a victim's lineage"
        );

        // A genuinely older parent still links correctly.
        let chain2 = graph.get_chain(200);
        assert_eq!(chain2.nodes.last().unwrap().image_name, "malware.exe");
    }

    #[test]
    fn bounded_graph_caps_at_max() {
        let graph = LineageGraph::new();
        // Fill to MAX_NODES — eviction runs but fresh nodes won't expire.
        // The graph caps inserts to prevent unbounded growth: once full,
        // eviction runs each insert. With same-age nodes, oldest PIDs
        // remain but new ones still insert (HashMap replaces or grows).
        // Just verify it doesn't panic or grow to millions.
        for i in 0..MAX_NODES + 100 {
            graph.record_process(make_node(i as u32, 0, "test.exe"));
        }
        // Graph should be roughly MAX_NODES (eviction may not remove fresh nodes).
        assert!(graph.node_count() <= MAX_NODES + 200);
    }

    // ──────────────────────────────────────────────────────────────
    //  Phase 6 — Integration tests
    //
    //  Build a PlmMonitor-shaped subsystem without starting threads
    //  (we test the ingestion + diagnostics + finding-mapping path,
    //  not the snapshot loop). The thread loop is exercised by the
    //  existing PLM tests; here we focus on the campaign wiring.
    // ──────────────────────────────────────────────────────────────

    use crate::plm::weedhack_campaign::{
        LineageGraphResolver, LineageResolver, WeedHackCampaignDiagnostics,
        WeedHackCampaignTracker,
    };
    use crate::plm::weedhack_runtime::WeedHackSignal;

    /// Mini test harness mirroring PlmMonitor's WeedHack wiring without
    /// spawning the snapshot thread.
    struct TestHarness {
        graph: Arc<LineageGraph>,
        tracker: Arc<WeedHackCampaignTracker>,
        diagnostics: Arc<WeedHackCampaignDiagnostics>,
    }

    impl TestHarness {
        fn new() -> Self {
            let graph = Arc::new(LineageGraph::new());
            let resolver: Arc<dyn LineageResolver> =
                Arc::new(LineageGraphResolver::new(Arc::clone(&graph)));
            Self {
                tracker: Arc::new(WeedHackCampaignTracker::new(resolver)),
                diagnostics: Arc::new(WeedHackCampaignDiagnostics::new()),
                graph,
            }
        }

        /// Mirror of PlmMonitor::ingest_weedhack_signal — same logic.
        fn ingest(
            &self,
            pid: u32,
            sig: WeedHackSignal,
        ) -> Option<argus::Finding> {
            let cf = self.tracker.ingest_signal(pid, sig)?;
            let root_image = self.graph.get_node(cf.root.pid).map(|n| n.image_name);
            self.diagnostics.record(&cf, root_image.clone(), 1_700_000_000);
            self.diagnostics
                .note_active(self.tracker.active_campaign_count());
            Some(cf.to_argus_finding(root_image))
        }
    }

    #[test]
    fn integration_runtime_signal_flows_into_tracker() {
        let h = TestHarness::new();
        h.graph
            .record_process(make_node(100, 0, "javaw.exe"));
        h.graph
            .record_process(make_node(200, 100, "powershell.exe"));
        // First signal under javaw root: tracker emits Suspicious.
        let f = h.ingest(200, WeedHackSignal::UnnaturalJavaChild)
            .expect("Suspicious must emit");
        assert!(matches!(f.severity, argus::verdict::Severity::Medium));
        assert!(f.description.contains("Suspicious"));
        assert!(f.description.contains("image=javaw.exe"));
    }

    #[test]
    fn integration_weak_signal_remains_observe_only() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        let f = h
            .ingest(100, WeedHackSignal::UnnaturalJavaChild)
            .unwrap();
        // weight=10 in Context (cap 15) — verdict will be LowSuspicion.
        assert_eq!(f.weight, 10);
        assert!(matches!(f.layer, argus::verdict::Layer::Context));
        // No re-emission on same-signal repeat.
        assert!(h.ingest(100, WeedHackSignal::UnnaturalJavaChild).is_none());
    }

    #[test]
    fn integration_pathognomonic_plus_corroborator_emits_confirmed() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        // Pjibf alone → HighConfidence.
        let f1 = h.ingest(100, WeedHackSignal::Pjibf).unwrap();
        assert!(matches!(f1.severity, argus::verdict::Severity::High));
        // Corroborator advances campaign to Confirmed.
        let f2 = h.ingest(100, WeedHackSignal::UnnaturalJavaChild).unwrap();
        assert!(matches!(f2.severity, argus::verdict::Severity::Critical));
        assert!(matches!(f2.layer, argus::verdict::Layer::IocCorrelation));
        // Weight = cumulative campaign score (uncapped IOC layer).
        assert!(f2.weight >= 60, "confirmed weight must carry campaign score");
    }

    #[test]
    fn integration_repeated_same_signal_dedupes() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        let _ = h.ingest(100, WeedHackSignal::Pjibf).unwrap();
        assert!(
            h.ingest(100, WeedHackSignal::Pjibf).is_none(),
            "same-signal repeat must not emit"
        );
        assert!(
            h.ingest(100, WeedHackSignal::Pjibf).is_none(),
            "stays silent on further repeats"
        );
    }

    #[test]
    fn integration_tracker_eviction_works_from_maintenance() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        // Establish campaign at t0.
        let t0 = Instant::now();
        let _ = h
            .tracker
            .ingest_signal_at(100, WeedHackSignal::UnnaturalJavaChild, t0);
        assert_eq!(h.tracker.active_campaign_count(), 1);

        // Simulate maintenance pass 21 minutes later.
        let t1 = t0 + Duration::from_secs(21 * 60);
        let evicted = h.tracker.evict_expired_at(t1);
        h.diagnostics.note_evicted(evicted);
        h.diagnostics
            .note_active(h.tracker.active_campaign_count());

        assert_eq!(evicted, 1);
        assert_eq!(h.tracker.active_campaign_count(), 0);
        let j = h.diagnostics.to_json(0);
        assert_eq!(j["expired"], 1);
        assert_eq!(j["active"], 0);
    }

    #[test]
    fn integration_confirmed_finding_maps_to_critical_ioc() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        // Three distinct signals → Confirmed at the third.
        let _ = h.ingest(100, WeedHackSignal::UnnaturalJavaChild).unwrap();
        let _ = h.ingest(100, WeedHackSignal::DefenderDisableUnderJava).unwrap();
        let f = h
            .ingest(100, WeedHackSignal::WalletHarvestBurst)
            .unwrap();
        assert!(matches!(f.layer, argus::verdict::Layer::IocCorrelation));
        assert!(matches!(f.severity, argus::verdict::Severity::Critical));
    }

    #[test]
    fn integration_diagnostics_payload_shape_matches_spec() {
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        h.graph.record_process(make_node(200, 100, "powershell.exe"));
        let _ = h.ingest(200, WeedHackSignal::UnnaturalJavaChild).unwrap();
        let _ = h
            .ingest(200, WeedHackSignal::DefenderDisableUnderJava)
            .unwrap();

        let j = h
            .diagnostics
            .to_json(h.tracker.active_campaign_count());
        // All required keys present.
        for key in [
            "active",
            "max_campaigns",
            "expired",
            "last_confirmed_unix",
            "recent_findings",
        ] {
            assert!(j.get(key).is_some(), "missing diagnostics key: {key}");
        }
        let recent = j["recent_findings"].as_array().unwrap();
        // Two findings recorded (Suspicious → HighConfidence advance).
        assert_eq!(recent.len(), 2);
        let last = &recent[1];
        for key in [
            "tier",
            "root_pid",
            "root_image",
            "signal_count",
            "signals",
            "narrative",
            "first_seen_unix",
            "last_seen_unix",
        ] {
            assert!(last.get(key).is_some(), "missing record key: {key}");
        }
        assert_eq!(last["root_pid"], 100, "campaign root is the javaw ancestor");
        assert_eq!(last["root_image"], "javaw.exe");
    }

    #[test]
    fn integration_scan_site_hook_dedupes_on_repeat() {
        // Simulate the scan-site pattern from watcher/idle_scanner/scan_buffer:
        // build a process chain and call `observe_chain_for_weedhack` twice.
        // The second pass must return no NEW findings — tracker dedupes by
        // (campaign-root, signal-type) so a re-scan of the same chain doesn't
        // spam ConvergenceLedger with stale evidence.
        let harness = TestHarness::new();
        harness.graph.record_process(make_node(1, 0, "explorer.exe"));
        harness.graph.record_process(make_node(2, 1, "javaw.exe"));
        harness.graph.record_process(make_node(3, 2, "schtasks.exe"));

        // Mimic PlmMonitor::observe_chain_for_weedhack inline (we can't
        // build a PlmMonitor without thread spawn here, but the path is
        // identical: chain → evaluate → ingest per signal).
        let scan_pass = |h: &TestHarness, leaf_pid: u32| -> Vec<argus::Finding> {
            let chain = h.graph.get_chain(leaf_pid);
            let sigs = crate::plm::weedhack_runtime::evaluate_chain(&chain.nodes);
            sigs.into_iter()
                .filter_map(|s| h.ingest(leaf_pid, s))
                .collect()
        };

        let first = scan_pass(&harness, 3);
        assert!(!first.is_empty(), "first scan must emit at least one finding");
        let second = scan_pass(&harness, 3);
        assert!(
            second.is_empty(),
            "repeat scan of same chain must yield zero new findings"
        );
        let third = scan_pass(&harness, 3);
        assert!(third.is_empty(), "no drift on Nth re-scan");
    }

    #[test]
    fn integration_diagnostics_json_empty_when_no_signals() {
        // Fresh tracker → all counters zero, recent_findings empty.
        // The UI keys on this shape to hide the panel entirely.
        let harness = TestHarness::new();
        let j = harness
            .diagnostics
            .to_json(harness.tracker.active_campaign_count());
        assert_eq!(j["active"], 0);
        assert_eq!(j["expired"], 0);
        assert_eq!(j["confirmed_total"], 0);
        assert_eq!(j["high_confidence_total"], 0);
        assert_eq!(j["suspicious_total"], 0);
        assert_eq!(j["last_confirmed_unix"], 0);
        assert_eq!(j["recent_findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn integration_diagnostics_json_has_required_keys_after_confirmed() {
        let harness = TestHarness::new();
        harness.graph.record_process(make_node(100, 0, "javaw.exe"));
        // Escalate through the full ladder.
        let _ = harness.ingest(100, WeedHackSignal::UnnaturalJavaChild);
        let _ = harness.ingest(100, WeedHackSignal::DefenderDisableUnderJava);
        let _ = harness.ingest(100, WeedHackSignal::WalletHarvestBurst);
        let j = harness
            .diagnostics
            .to_json(harness.tracker.active_campaign_count());
        // Top-level shape contract.
        for k in [
            "active",
            "max_campaigns",
            "expired",
            "confirmed_total",
            "high_confidence_total",
            "suspicious_total",
            "last_confirmed_unix",
            "recent_findings",
        ] {
            assert!(j.get(k).is_some(), "missing diagnostics field: {k}");
        }
        assert_eq!(j["confirmed_total"], 1);
        // last_confirmed_unix stamped by record() — non-zero now.
        assert!(j["last_confirmed_unix"].as_i64().unwrap() > 0);
        // recent_findings contains entries with the spec-required keys.
        let arr = j["recent_findings"].as_array().unwrap();
        assert!(!arr.is_empty());
        for k in [
            "tier",
            "root_pid",
            "root_image",
            "signal_count",
            "signals",
            "narrative",
            "first_seen_unix",
            "last_seen_unix",
        ] {
            assert!(
                arr[0].get(k).is_some(),
                "recent_findings[0] missing key: {k}"
            );
        }
    }

    #[test]
    fn integration_image_load_pipeline_emits_into_campaign_tracker() {
        // Full Wave 3 pipeline:
        //   raw ImageLoad event
        //   → BrowserImageLoadFilter::process_event (cheap filters + dedup)
        //   → weedhack_browser_injection::evaluate (canonical gate)
        //   → WeedHackCampaignTracker.ingest_signal
        //   → Suspicious finding emitted (observe-only)
        let harness = TestHarness::new();
        // Populate lineage so Java ancestor check passes.
        harness.graph.record_process(make_node(1, 0, "explorer.exe"));
        harness.graph.record_process(make_node(2, 1, "javaw.exe"));
        harness.graph.record_process(make_node(3, 2, "chrome.exe"));

        let filter = crate::plm::weedhack_image_load::BrowserImageLoadFilter::new();
        let verifier = crate::plm::weedhack_image_load::NullSignerVerifier;
        let lineage = crate::plm::weedhack_image_load::LineageGraphJavaChecker::new(
            Arc::clone(&harness.graph),
        );

        let event = crate::plm::weedhack_image_load::ImageLoadRawEvent {
            target_pid: 3,
            target_image_name: "chrome.exe".into(),
            loaded_module_path:
                "C:\\Users\\t\\AppData\\Local\\Temp\\krxz.dll".into(),
            timestamp_unix: 1_700_000_000,
        };
        let sig = filter
            .process_event(event, &verifier, &lineage)
            .expect("pipeline must emit signal");
        // Now feed through campaign tracker (same path as PlmMonitor would).
        let finding = harness.ingest(3, sig).expect("campaign tracker emits");
        // Suspicious tier — observe only.
        assert!(matches!(finding.severity, argus::verdict::Severity::Medium));
        assert!(matches!(finding.layer, argus::verdict::Layer::Context));
        assert_eq!(finding.weight, 10, "weight 10 = LowSuspicion floor");
    }

    #[test]
    fn integration_image_load_suspicious_stays_observe_only_without_corroboration() {
        // ImageLoad alone (BrowserInjectionFromJava) is a non-pathognomonic
        // signal of weight 50. Per Wave 1 tier rules, a single non-path
        // signal lands at Suspicious — NOT Confirmed. Wave 3 must respect
        // this: ETW path produces the same tier as a hand-fed signal.
        let harness = TestHarness::new();
        harness.graph.record_process(make_node(1, 0, "javaw.exe"));
        harness.graph.record_process(make_node(2, 1, "chrome.exe"));

        let f = harness
            .ingest(2, WeedHackSignal::BrowserInjectionFromJava)
            .expect("first signal emits");
        assert!(matches!(f.layer, argus::verdict::Layer::Context));
        assert!(matches!(f.severity, argus::verdict::Severity::Medium));
        // Re-feeding the same signal: deduped, no emit.
        assert!(harness
            .ingest(2, WeedHackSignal::BrowserInjectionFromJava)
            .is_none());
        // Only a SECOND distinct signal can advance the tier.
        let f2 = harness
            .ingest(2, WeedHackSignal::UnnaturalJavaChild)
            .expect("second distinct signal emits");
        assert!(matches!(f2.severity, argus::verdict::Severity::High));
    }

    #[test]
    fn integration_no_detector_behavior_regression() {
        // Confirm the existing chain analysis still produces identical
        // output: the tracker is a SEPARATE pathway, not a rewrite of
        // weedhack_runtime::evaluate_chain. Tracker is not consulted by
        // the detector — calling it does not influence subsequent
        // detector output.
        let h = TestHarness::new();
        h.graph.record_process(make_node(100, 0, "javaw.exe"));
        h.graph.record_process(make_node(200, 100, "schtasks.exe"));
        let chain_before = h.graph.get_chain(200);
        let sigs_before = crate::plm::weedhack_runtime::evaluate_chain(&chain_before.nodes);

        // Drive the tracker.
        let _ = h.ingest(200, WeedHackSignal::UnnaturalJavaChild);
        let _ = h.ingest(200, WeedHackSignal::DefenderDisableUnderJava);

        // Detector re-evaluated post-ingest must yield the same signals.
        let chain_after = h.graph.get_chain(200);
        let sigs_after = crate::plm::weedhack_runtime::evaluate_chain(&chain_after.nodes);
        assert_eq!(sigs_before, sigs_after, "detector output must be untouched");
    }

    // ──────────────────────────────────────────────────────────────
    //  Wave 8 — Live-pattern regression tests
    //
    //  These tests simulate realistic non-WeedHack workloads and
    //  assert ZERO campaign findings. They're the synthetic stand-in
    //  for Phase 1/2 live validation runs; every false positive the
    //  user observes during real runs should be memorialized here
    //  via the same pattern (Phase 6 — "no untested tuning").
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn live_pattern_minecraft_launcher_produces_no_signal() {
        // Pattern: explorer → MinecraftLauncher → javaw -jar minecraft.jar.
        // The Wave 1 detector specifically excludes "vanilla Minecraft" chains
        // via the `clean_minecraft_no_signals` test but we re-assert here
        // through the FULL Wave 1+2 integration layer.
        let h = TestHarness::new();
        h.graph.record_process(make_node(1, 0, "explorer.exe"));
        h.graph.record_process(make_node(2, 1, "MinecraftLauncher.exe"));
        h.graph.record_process(make_node(3, 2, "javaw.exe"));
        let findings = {
            let chain = h.graph.get_chain(3);
            let sigs = crate::plm::weedhack_runtime::evaluate_chain(&chain.nodes);
            sigs.into_iter().filter_map(|s| h.ingest(3, s)).collect::<Vec<_>>()
        };
        assert!(
            findings.is_empty(),
            "vanilla Minecraft chain must produce zero campaign findings; got {findings:?}"
        );
        assert_eq!(h.tracker.active_campaign_count(), 0);
    }

    #[test]
    fn live_pattern_intellij_running_java_test_does_not_confirm() {
        // Pattern: IntelliJ runs a Gradle build then javaw to execute a
        // JUnit test that happens to spawn cmd.exe to chmod/run a helper.
        // This trips the `UnnaturalJavaChild` signal (powershell from
        // javaw) but ALONE should stay at Suspicious — never escalate
        // to HighConfidence or Confirmed.
        let h = TestHarness::new();
        h.graph.record_process(make_node(1, 0, "explorer.exe"));
        h.graph.record_process(make_node(2, 1, "idea64.exe"));
        h.graph.record_process(make_node(3, 2, "javaw.exe"));
        h.graph.record_process(make_node(4, 3, "powershell.exe"));
        let chain = h.graph.get_chain(4);
        let sigs = crate::plm::weedhack_runtime::evaluate_chain(&chain.nodes);
        let mut last_tier = None;
        for s in sigs {
            if let Some(f) = h.ingest(4, s) {
                last_tier = Some(f.severity);
            }
        }
        // Maximum allowed tier here is Suspicious → severity Medium.
        // Anything stronger would auto-quarantine on a benign chain.
        if let Some(sev) = last_tier {
            assert!(
                matches!(sev, argus::verdict::Severity::Medium),
                "IntelliJ-like java→powershell must stay at Medium severity; got {sev:?}"
            );
        }
    }

    #[test]
    fn live_pattern_jenkins_agent_does_not_fire() {
        // Pattern: services.exe → java.exe (Jenkins agent) → cmd.exe → mvn.
        // cmd.exe is NOT in the unnatural-java-child list (build tools
        // legitimately spawn cmd), so the chain produces zero signals.
        let h = TestHarness::new();
        h.graph.record_process(make_node(1, 0, "services.exe"));
        h.graph.record_process(make_node(2, 1, "java.exe"));
        h.graph.record_process(make_node(3, 2, "cmd.exe"));
        h.graph.record_process(make_node(4, 3, "mvn.cmd"));
        let chain = h.graph.get_chain(4);
        let sigs = crate::plm::weedhack_runtime::evaluate_chain(&chain.nodes);
        let findings: Vec<_> = sigs
            .into_iter()
            .filter_map(|s| h.ingest(4, s))
            .collect();
        assert!(
            findings.is_empty(),
            "Jenkins-like java→cmd→mvn must produce zero campaign findings; got {findings:?}"
        );
    }

    #[test]
    fn live_pattern_synthetic_image_load_alone_stays_suspicious() {
        // Wave 4 path: ImageLoad of an unsigned DLL into Chrome under a
        // javaw ancestor → Suspicious tier. ALONE (no other signal)
        // this must not advance past Suspicious.
        let h = TestHarness::new();
        h.graph.record_process(make_node(1, 0, "explorer.exe"));
        h.graph.record_process(make_node(2, 1, "javaw.exe"));
        h.graph.record_process(make_node(3, 2, "chrome.exe"));
        let f = h.ingest(3, WeedHackSignal::BrowserInjectionFromJava).unwrap();
        assert!(matches!(f.severity, argus::verdict::Severity::Medium));
        assert_eq!(h.tracker.active_campaign_count(), 1);
    }

    #[test]
    fn live_pattern_synthetic_full_chain_reaches_confirmed() {
        // Synthetic positive (Phase 3): three distinct WeedHack signals
        // → Confirmed tier through the same code path live ETW would
        // exercise. This is the test we'd run after a synthetic
        // injection in production to confirm "the path is alive".
        let h = TestHarness::new();
        h.graph.record_process(make_node(1, 0, "explorer.exe"));
        h.graph.record_process(make_node(2, 1, "javaw.exe"));
        // Suspicious → emitted
        let f1 = h.ingest(2, WeedHackSignal::BrowserInjectionFromJava).unwrap();
        assert!(matches!(f1.severity, argus::verdict::Severity::Medium));
        // HighConfidence → emitted
        let f2 = h.ingest(2, WeedHackSignal::WalletHarvestBurst).unwrap();
        assert!(matches!(f2.severity, argus::verdict::Severity::High));
        // Confirmed → emitted, Critical severity, IocCorrelation layer.
        let f3 = h.ingest(2, WeedHackSignal::EtherHidingFromJava).unwrap();
        assert!(matches!(f3.severity, argus::verdict::Severity::Critical));
        assert!(matches!(f3.layer, argus::verdict::Layer::IocCorrelation));
    }
}

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
                let mut by_age: Vec<(i64, u32)> =
                    map.values().map(|n| (n.timestamp, n.pid)).collect();
                // Oldest first (ascending timestamp); pid as deterministic tiebreak.
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

    /// Evict expired nodes.
    pub fn evict_expired(&self) {
        let mut map = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        map.retain(|_, n| now.duration_since(n.created_at) < NODE_TTL);
    }
}

/// Compute suspicion score for a process chain.
/// LOLBin chains and Office macro chains get high scores.
fn compute_chain_suspicion(chain: &[ProcessNode]) -> u32 {
    if chain.len() <= 1 {
        return 0;
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

    // Cap at 30 (convergence contribution, not standalone verdict).
    suspicion.min(30)
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
pub fn lineage_finding(chain: &ProcessChain) -> Option<argus::Finding> {
    if chain.chain_suspicion == 0 {
        return None;
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

        let snapshot_thread = std::thread::Builder::new()
            .name("plm-snapshot".into())
            .spawn(move || {
                plm_loop(g, d, r, si);
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
            running,
            _snapshot_thread: snapshot_thread,
            #[cfg(target_os = "windows")]
            _etw_thread: etw_thread,
            #[cfg(target_os = "windows")]
            etw_diagnostics: etw_diag,
        }
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

        // Periodic eviction.
        graph.evict_expired();
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
            // Only insert if not already tracked (avoid overwriting timestamps).
            let map = graph.nodes.lock().unwrap_or_else(|e| e.into_inner());
            let already_tracked = map.contains_key(&pid);
            drop(map);

            if !already_tracked {
                graph.record_process(ProcessNode {
                    pid,
                    parent_pid: ppid,
                    image_path: exe_name.clone(),
                    image_name: exe_name
                        .rsplit('\\')
                        .next()
                        .unwrap_or(&exe_name)
                        .to_string(),
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
}

// Centralized API layer. Every daemon call goes through here.
// No component should call invoke() directly.

import { invoke } from "@tauri-apps/api/core";
import type {
  EngineStatus,
  ScanStatusResponse,
  ScanRecord,
  ScanStarted,
  FileScanResponse,
  QuarantineEntry,
  WatcherStatus,
  UpdateStatus,
  ActivityEntry,
  RuntimeStats,
  ArgusVerdict,
  ArgusVersion,
  ArgusVerdictRecord,
  ArgusPacksResponse,
  IdleScannerStatus,
} from "../types/sentinella";

// ── Engine ──────────────────────────────────────────────────

export const getEngineStatus = () =>
  invoke<EngineStatus>("get_engine_status");

// ── Scan ────────────────────────────────────────────────────

export const getScanStatus = () =>
  invoke<ScanStatusResponse>("get_scan_status");

/** Scan a single file through the daemon's ClamAV engine. */
export const scanFile = (path: string) =>
  invoke<FileScanResponse>("scan_file", { path });

export const startQuickScan = () =>
  invoke<ScanStarted>("start_quick_scan");

export const cancelScan = () =>
  invoke<{ ok: boolean }>("cancel_scan");

export const startFullScan = () =>
  invoke<ScanStarted>("start_full_scan");

export const startStartupScan = () =>
  invoke<ScanStarted>("start_startup_scan");

export const scanFolder = (path: string) =>
  invoke<FileScanResponse>("scan_folder", { path });

export const getScanHistory = () =>
  invoke<ScanRecord[]>("get_scan_history");

// ── Quarantine ──────────────────────────────────────────────

export const getQuarantineItems = () =>
  invoke<QuarantineEntry[]>("get_quarantine_items");

export const quarantineFile = (path: string, virusName: string, scanId: string) =>
  invoke<{ quarantine_id?: string; error?: string }>("quarantine_file", { path, virusName, scanId });

export const restoreQuarantine = (id: string) =>
  invoke<{ ok: boolean; restored_to?: string; error?: string }>("quarantine_restore", { id });

export const deleteQuarantine = (id: string) =>
  invoke<{ ok: boolean; error?: string }>("quarantine_delete", { id });

// ── Detections ──────────────────────────────────────────

export interface DetectionEntry {
  detection_id: string;
  scan_id: string;
  path: string;
  virus_name: string;
  detected_at: number;
  action_taken: string;
}

export const getDetections = (scanId?: string) =>
  invoke<DetectionEntry[]>("get_detections", { scanId });

// ── Settings ────────────────────────────────────────────

export const getSettings = () =>
  invoke<Record<string, unknown>>("get_settings");

export const saveSettings = (config: Record<string, unknown>) =>
  invoke<{ ok: boolean; error?: string }>("save_settings", { config });

// ── Watcher ─────────────────────────────────────────────────

export const getWatcherStatus = () =>
  invoke<WatcherStatus>("get_watcher_status");

// ── Idle Scanner ───────────────────────────────────────────────

export const getIdleScannerStatus = () =>
  invoke<IdleScannerStatus>("get_idle_scanner_status");

// ── Updates ─────────────────────────────────────────────────

export const getUpdateStatus = () =>
  invoke<UpdateStatus>("get_update_status");

export const startSignatureUpdate = () =>
  invoke<{ ok: boolean }>("start_signature_update");

// ── Activity ────────────────────────────────────────────────

export const getActivity = () =>
  invoke<ActivityEntry[]>("get_activity");

// ── Security ───────────────────────────────────────────────

/** Request a single-use challenge token for dangerous operations. */
export const requestChallengeToken = () =>
  invoke<{ token: string }>("request_challenge_token");

// ── Protection critical settings ────────────────────────────

/** Change security-critical settings (requires challenge token internally). */
export const setCriticalProtection = (opts: {
  realtimeEnabled?: boolean;
  autoQuarantine?: boolean;
}) =>
  invoke<{ ok: boolean; changes?: string[]; error?: string; requires_elevation?: boolean }>("set_critical_protection", {
    realtimeEnabled: opts.realtimeEnabled,
    autoQuarantine: opts.autoQuarantine,
  });

/** Pause all protection temporarily. */
export const pauseProtection = () =>
  invoke<{ ok: boolean; state?: string }>("pause_protection");

/** Resume protection after pause. */
export const resumeProtection = () =>
  invoke<{ ok: boolean; state?: string }>("resume_protection");

// ── Reports ────────────────────────────────────────────────

export const exportScanReport = () =>
  invoke<Record<string, unknown>>("export_scan_report");

/** Export diagnostics snapshot — no secrets, no file contents. */
export const exportDiagnostics = () =>
  invoke<Record<string, unknown>>("export_diagnostics");

// ── ARGUS Heuristics Engine ─────────────────────────────────

export const argusAnalyze = (path: string) =>
  invoke<ArgusVerdict>("argus_analyze", { path });

export const argusVersion = () =>
  invoke<ArgusVersion>("argus_version");

export const getArgusVerdicts = (scanId?: string) =>
  invoke<ArgusVerdictRecord[]>("get_argus_verdicts", { scanId });

export const getArgusPacks = () =>
  invoke<ArgusPacksResponse>("get_argus_packs");

export const reloadArgus = () =>
  invoke<{ ok: boolean; yara_rules: number; ioc_hashes: number; message: string }>("reload_argus");

// ── Runtime stats ───────────────────────────────────────────

export const getRuntimeStats = () =>
  invoke<RuntimeStats>("get_runtime_stats");

// ── Memory Scanner ──────────────────────────────────────────

export interface ProcessInfo {
  pid: number;
  name: string;
  path: string | null;
  memory_mb: number;
}

export interface MemoryScanResult {
  pid: number;
  process_name: string;
  process_path: string | null;
  regions_scanned: number;
  bytes_scanned: number;
  findings: MemoryFinding[];
  errors: string[];
  scan_time_ms: number;
}

export interface MemoryFinding {
  region_address: number;
  region_size: number;
  description: string;
  severity: "info" | "suspicious" | "malicious";
  yara_rule: string | null;
}

export const listProcesses = () =>
  invoke<ProcessInfo[]>("list_processes");

export const scanProcessMemory = (pid: number) =>
  invoke<MemoryScanResult>("scan_process_memory", { pid });

// ── Supervisor / Recovery ────────────────────────────────────

export type ConnectionState = "connecting" | "connected" | "recovering" | "degraded" | "disconnected" | "user_disabled";

export interface RecoveryInfo {
  state: ConnectionState;
  restart_attempts: number;
  successful_recoveries: number;
  failed_recoveries: number;
  last_restart_reason: string | null;
  last_restart_at: string | null;
  daemon_spawned: boolean;
  crash_loop_detected: boolean;
  audit_mode: boolean;
  current_backoff_sec: number;
  stable_since: string | null;
}

export const getRecoveryState = () =>
  invoke<RecoveryInfo>("get_recovery_state");

export const getConnectionState = () =>
  invoke<ConnectionState>("get_connection_state");

// ── Aggregate fetcher for dashboard polling ─────────────────

export interface DashboardData {
  engine: EngineStatus;
  scan: ScanStatusResponse;
  watcher: WatcherStatus;
  update: UpdateStatus;
  quarantine: QuarantineEntry[];
  activity: ActivityEntry[];
  stats: RuntimeStats;
  scanHistory: ScanRecord[];
  idleScanner: IdleScannerStatus;
}

export async function fetchDashboard(): Promise<DashboardData> {
  // Each call is individually caught so one failure doesn't break the dashboard.
  const [engine, scan, watcher, update, quarantine, activity, stats, scanHistory, idleScanner] =
    await Promise.all([
      getEngineStatus().catch(() => ({ state: "error" as const, protocol_version: 0, db_version: null, db_timestamp: null, signature_count: 0, last_update: null, engine_version: "?" })),
      getScanStatus().catch(() => ({ running: false, job_id: null, state: "idle" as const, scan_type: null, files_scanned: 0, files_total: 0, progress_percent: 0, threats_found: 0, current_path: null, scans_completed: 0, detections: [], started_at: null, finished_at: null, errors_count: 0 })),
      getWatcherStatus().catch(() => ({ enabled: false, mode: "disabled" as const, watched_roots: [], events_per_sec: 0, last_event: null })),
      getUpdateStatus().catch(() => ({ state: "idle" as const, percent: null, bytes_downloaded: 0, bytes_total: null, last_error: null, current_file: null })),
      getQuarantineItems().catch(() => []),
      getActivity().catch(() => []),
      getRuntimeStats().catch(() => ({ uptime_secs: 0, uptime_human: "?", scans_completed: 0, threats_found_total: 0, ipc_requests_served: 0, quarantine_count: 0, activity_count: 0, started_at: 0, engine_loaded: false, signature_count: 0, db_stale: true, db_stale_hours: 0, watcher_active: false, last_update_timestamp: null, total_files_scanned: 0, total_detections: 0, argus_version: "?", argus_files_analyzed: 0, argus_threats_detected: 0, argus_active_layers: 0, argus_avg_analysis_us: 0, argus_yara_rules: 0, protection_state: "unprotected" as const, protection_detail: "Daemon unreachable", cache_hits: 0, cache_misses: 0, cache_entries: 0, idle_scanner_state: "disabled", idle_scanner_files: 0, ipc_reconnect_count: 0, ipc_last_error_ts: 0 })),
      getScanHistory().catch(() => []),
      getIdleScannerStatus().catch(() => ({ state: "disabled" as const, files_scanned_session: 0, current_target: "", last_pause_reason: "", last_completed: null })),
    ]);
  return { engine, scan, watcher, update, quarantine, activity, stats, scanHistory, idleScanner };
}

// ── Notifications ───────────────────────────────────────────
// Centralized in src/notifications/. Re-export for backward compat.

export { notifyThreatDetected as notifyThreat } from "../notifications";
export { notifyQuarantined as notifyQuarantine } from "../notifications";

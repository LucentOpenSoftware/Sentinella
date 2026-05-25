// Types matching daemon IPC responses EXACTLY.
// No cosmetic additions — every field here comes from sentinelld.

/** Result of scanning a single file via scan.start with target. */
export interface FileScanResponse {
  job_id: string;
  status: "clean" | "infected" | "error" | "completed" | "queued";
  result: {
    path: string;
    infected: boolean;
    virus_name: string | null;
    scanned_bytes: number;
    error: string | null;
  } | null;
  error: string | null;
}

export interface EngineStatus {
  state: "starting" | "loading" | "ready" | "updating" | "error" | "shutting_down";
  protocol_version: number;
  db_version: number | null;
  db_timestamp: number | null;
  signature_count: number;
  last_update: number | null;
  engine_version: string;
}

export interface ScanStatusResponse {
  running: boolean;
  job_id: string | null;
  state: "idle" | "pending" | "queued" | "running" | "completed" | "cancelled" | "cancelling" | "failed";
  scan_type: string | null;
  files_scanned: number;
  files_total: number;
  progress_percent: number;
  threats_found: number;
  current_path: string | null;
  scans_completed: number;
  detections: { path: string; virus_name: string }[];
  started_at: number | null;
  finished_at: number | null;
  errors_count: number;
}

/** Scan record from SQLite (scan.history response). */
export interface ScanRecord {
  scan_id: string;
  scan_type: string;
  status: string;
  started_at: number;
  finished_at: number | null;
  files_scanned: number;
  threats_found: number;
  errors_count: number;
  duration_ms: number;
}

export interface ScanStarted {
  job_id: string;
}

export interface QuarantineEntry {
  id: string;
  original_path: string;
  original_size: number;
  signature: string;
  sha256: string;
  quarantined_at: number;
  restorable: boolean;
}

export interface WatcherStatus {
  enabled: boolean;
  mode: "user_mode" | "kernel_mode" | "disabled";
  watched_roots: string[];
  events_per_sec: number;
  last_event: number | null;
}

export interface UpdateStatus {
  state: "idle" | "checking" | "downloading" | "applying" | "completed" | "error";
  percent: number | null;
  bytes_downloaded: number;
  bytes_total: number | null;
  last_error: string | null;
  current_file: string | null;
}

/** Activity event from SQLite (activity.list response). */
export interface ActivityEntry {
  event_id: string;
  timestamp: number;
  severity: string;
  category: string;
  title: string;
  message: string;
  related_scan_id: string | null;
}

// ── ARGUS Heuristics Engine ─────────────────────────────────────

export interface ArgusVerdict {
  path: string;
  file_size: number;
  sha256: string;
  mime_type: string | null;
  score: number;
  verdict: "clean" | "low_suspicion" | "suspicious" | "high_suspicion" | "malicious";
  findings: ArgusFinding[];
  analysis_time_us: number;
  engine_version: string;
  timestamp: number;
  explanation: VerdictExplanation;
}

export type ConfidenceLabel = "trusted" | "normal" | "unusual" | "suspicious" | "high_risk" | "malicious";

export interface VerdictExplanation {
  raw_score: number;
  reputation_discount: number;
  authenticode_discount: number;
  installer_discount_applied: boolean;
  final_score: number;
  signer: string | null;
  recognized_software: string | null;
  suspicion_reasons: string[];
  trust_reasons: string[];
  confidence_label: ConfidenceLabel;
  framework: string | null;
}

export interface ArgusFinding {
  layer: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  weight: number;
  description: string;
  technical_detail: string | null;
}

export interface ArgusVersion {
  engine: string;
  version: string;
  layers: string[];
}

/** Persisted ARGUS verdict from SQLite. */
export interface ArgusVerdictRecord {
  scan_id: string;
  path: string;
  score: number;
  verdict: string;
  findings_json: string;
  sha256: string;
  mime_type: string | null;
  file_size: number;
  analysis_time_us: number;
  engine_version: string;
  timestamp: number;
}

/** Intelligence pack info from daemon. */
export interface ArgusPackInfo {
  name: string;
  display_name: string;
  version: string;
  category: string;
  description: string;
  file: string;
  rule_count: number;
  author: string;
}

export interface ArgusPacksResponse {
  packs: ArgusPackInfo[];
  total_yara_rules: number;
  total_ioc_hashes: number;
  reputation_entries: number;
  engine_version: string;
}

// ── Runtime ────────────────────────────────────────────────────

export interface RuntimeStats {
  uptime_secs: number;
  uptime_human: string;
  scans_completed: number;
  threats_found_total: number;
  ipc_requests_served: number;
  quarantine_count: number;
  activity_count: number;
  started_at: number;
  engine_loaded: boolean;
  signature_count: number;
  db_stale: boolean;
  db_stale_hours: number;
  watcher_active: boolean;
  last_update_timestamp: number | null;
  total_files_scanned: number;
  total_detections: number;
  // ARGUS heuristics engine stats
  argus_version: string;
  argus_files_analyzed: number;
  argus_threats_detected: number;
  argus_active_layers: number;
  argus_avg_analysis_us: number;
  argus_yara_rules: number;
  protection_state: "fully_protected" | "degraded" | "minimal" | "unprotected" | "user_disabled";
  protection_detail: string | null;
  // Scan cache stats
  cache_hits: number;
  cache_misses: number;
  cache_entries: number;
  // Idle scanner
  idle_scanner_state: string;
  idle_scanner_files: number;
  // IPC health
  ipc_reconnect_count: number;
  ipc_last_error_ts: number;
  // Memory footprint
  footprint?: {
    working_set_mb: number;
    private_bytes_mb: number;
    peak_working_set_mb: number;
    warning_level: string;
    delta_since_start_mb: number;
    delta_since_last_scan_mb: number;
    notes: string[];
  };
}

// ── Idle Scanner ──────────────────────────────────────────────

export type IdleScannerState =
  | "disabled"
  | "waiting_for_capacity"
  | "scanning_slow"
  | "scanning_normal"
  | "scanning_fast"
  | "paused_cpu"
  | "paused_disk"
  | "paused_fullscreen"
  | "paused_battery"
  | "paused_scan_running"
  | "completed";

export interface IdleScannerStatus {
  state: IdleScannerState;
  files_scanned_session: number;
  current_target: string;
  last_pause_reason: string;
  last_completed: number | null;
}

// ── Runtime Intelligence ────────────────────────────────────

export interface RuntimeIntelligenceStatus {
  plm: {
    enabled: boolean;
    events_seen: number;
    nodes: number;
    chains_scored: number;
    suspicious_chains: number;
    mode?: string;
    etw_events?: number;
    etw_running?: boolean;
    etw_reconnects?: number;
  };
  powershell: {
    enabled: boolean;
    events_seen: number;
    events_scanned: number;
    duplicates_skipped: number;
    last_score: number;
    sbl_available: boolean;
    errors: number;
    recent_events: RuntimeRecentEvent[];
  };
  amsi: {
    enabled: boolean;
    note?: string;
  };
}

export interface RuntimeRecentEvent {
  timestamp: number;
  language: string;
  source_app: string;
  content_name: string;
  score: number;
  findings_count: number;
  lineage_summary: string | null;
  timed_out: boolean;
  observe_only: boolean;
}

// ── Trust Graph ─────────────────────────────────────────────

export interface TrustGraphStatus {
  nodes: number;
  stable_nodes: number;
  rare_nodes: number;
  recently_seen: number;
  stale_nodes: number;
  drift_events_total: number;
  drift_events_24h: number;
  max_nodes: number;
  decay_days: number;
  recent_drift_events: TrustDriftEvent[];
}

export interface TrustDriftEvent {
  timestamp: number;
  entity: string;
  type: string;
  old: string | null;
  new: string | null;
  impact: string;
  explanation: string;
  weight: number;
}

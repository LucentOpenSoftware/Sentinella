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
  /**
   * v0.1.7 Phase 2 — where any currently-running engine reload is in its
   * lifecycle. `state` reflects the COMMITTED engine (a reload-in-flight
   * keeps the previous engine serving scans, so `state` stays "ready"),
   * `reload_phase` tells the UI whether to render an "Updating
   * signatures…" badge alongside without flipping the protection shield
   * to degraded. Optional for backward compatibility with v0.1.6 daemons.
   */
  reload_phase?: "idle" | "compiling" | "activating" | "failed";
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

// ── Ecosystem ─────────────────────────────────────────────

export interface EcosystemDiagnostics {
  active_ecosystems: number;
  active: number;
  cooling: number;
  suspicious: number;
  high_severity: number;
  critical: number;
  recurring: number;
  pruned: number;
  average_lifetime_minutes: number;
  recurrence_escalations: number;
  recent_suspicious: EcosystemSummary[];
}

export interface EcosystemSummary {
  root: string;
  severity: string;
  state: string;
  escalation: number;
  escalation_count: number;
  recurrence_count: number;
  evidence_count: number;
  narrative: string;
  attribution: ConvergenceAttribution | null;
  timeline: EcosystemTimelineEvent[];
}

export interface ConvergenceAttribution {
  base_argus: number;
  trust_adjustment: number;
  drift_escalation: number;
  ecosystem_escalation: number;
  recurrence_bonus: number;
  final_convergence: number;
}

// ── Signature Sources ─────────────────────────────────────

export interface SignatureSourcesStatus {
  core: {
    name: string;
    status: string;
    always_enabled: boolean;
  };
  enhanced: {
    active_provider: string | null;
    active_name: string | null;
    active_focus: string | null;
    active_signatures: number;
    active_footprint_mb: number;
    active_fp_risk: string | null;
  };
  available_providers: SignatureProviderInfo[];
  provider_fingerprint: string;
}

export interface SignatureProviderInfo {
  id: string;
  name: string;
  description: string;
  focus: string;
  estimated_signatures: number;
  estimated_footprint_mb: number;
  fp_risk: string;
  fp_explanation: string;
  stability: string;
  recommendation: string;
  use_case: string;
  update_frequency: string;
  license: string;
  homepage: string;
  attribution: string;
  active: boolean;
  files_present: boolean;
}

export interface EcosystemTimelineEvent {
  timestamp: number;
  description: string;
  source: string;
  weight: number;
}

// ─── v0.1.8 FullConfig (Settings page expansion) ────────────────
//
// Mirrors `sentinella_ipc_proto::full_config::FullConfig`. All fields
// optional on the TS side so the GUI can render against an older
// daemon that doesn't ship a field yet. Server-side strict types are
// the source of truth.

export type RestartRequirement = "none" | "engine_reload" | "daemon_restart";

export interface RestartRequirementMap {
  fields: Record<string, RestartRequirement>;
}

export interface FullScanConfig {
  argus_worker_enabled: boolean;
  argus_worker_path: string;
  argus_worker_timeout_sec: number;
  orchestrator_file_scan_enabled: boolean;
  orchestrator_folder_scan_enabled: boolean;
  orchestrator_quick_scan_enabled: boolean;
  orchestrator_full_scan_enabled: boolean;
}

export interface FullPerformanceConfig {
  /** "low" | "normal" | "aggressive" */
  memory_profile: string;
  memory_warning_mb: number;
  memory_critical_mb: number;
  external_argus_under_pressure: boolean;
  max_resident_workers_on_pressure: number;
}

export interface FullFishConfig {
  enabled: boolean;
  observe_only: boolean;
  window_seconds: number;
  rename_threshold: number;
  rewrite_threshold: number;
  ext_mutation_threshold: number;
  slow_burn_window_secs: number;
  slow_burn_threshold: number;
  entropy_delta_threshold: number;
  alert_cooldown_seconds: number;
  /** "observe" | "suspend" | "terminate" */
  active_response: string;
}

export interface FullSandboxConfig {
  enabled: boolean;
  /** "experimental" | "production" */
  mode: string;
  timeout_sec: number;
  min_score: number;
  max_score: number;
}

export interface DeveloperConfigPublic {
  enabled: boolean;
  telemetry_enabled: boolean;
  telemetry_max_kb: number;
  // password_sha256 is NEVER carried on the wire — see proto::full_config.
}

export interface FullConfig {
  // Real-time protection
  realtime_enabled: boolean;
  realtime_roots: string[];

  // Scan limits
  max_file_size_mb: number;
  scan_archives: boolean;
  heuristic_alerts: boolean;

  // Updates
  auto_update: boolean;
  update_interval_hours: number;
  signature_stale_days: number;
  update_mirror: string;

  // Quarantine
  quarantine_retention_days: number;
  auto_quarantine: boolean;

  // Exclusions
  excluded_paths: string[];
  excluded_extensions: string[];
  excluded_detections: string[];
  trusted_hashes: string[];

  // Enhanced signature provider
  enhanced_signature_provider: string;

  // Logging
  log_level: string;

  // Scheduler
  scheduled_scan_enabled: boolean;
  scheduled_scan_hour: number;
  scheduled_scan_type: string;

  // Startup
  startup_critical_scan: boolean;

  // PowerShell bridge
  powershell_bridge_enabled: boolean;
  powershell_poll_seconds: number;

  // Idle scanner
  idle_scan_enabled: boolean;
  idle_scan_start_delay_secs: number;
  idle_scan_on_battery: boolean;
  idle_scan_cpu_pause_threshold: number;
  idle_scan_max_file_size_mb: number;
  idle_scan_fullscreen_pause: boolean;
  idle_scan_disk_latency_pause_ms: number;
  idle_scan_max_files_per_session: number;
  idle_scan_slow_delay_min_ms: number;
  idle_scan_slow_delay_max_ms: number;
  idle_scan_normal_delay_min_ms: number;
  idle_scan_normal_delay_max_ms: number;
  idle_scan_fast_delay_min_ms: number;
  idle_scan_fast_delay_max_ms: number;

  // ARGUS worker (top-level)
  argus_worker_enabled: boolean;
  argus_worker_path: string;
  argus_worker_timeout_sec: number;

  // ClamAV isolation
  clamav_isolation: string;
  clamav_worker_timeout_sec: number;

  // Nested sub-configs
  scan: FullScanConfig;
  performance: FullPerformanceConfig;
  fish: FullFishConfig;
  sandbox: FullSandboxConfig;
  developer: DeveloperConfigPublic;
}

/** Sentinel for "kill-vector" fields — must travel via set_critical_settings, not save_full_settings. */
export const CRITICAL_FIELDS: ReadonlySet<string> = new Set([
  "realtime_enabled",
  "auto_quarantine",
  "argus_worker_enabled",
  "argus_worker_path",
  "scan.argus_worker_enabled",
  "scan.argus_worker_path",
  "excluded_paths",
  "excluded_extensions",
  "excluded_detections",
  "trusted_hashes",
  "realtime_roots",
  "heuristic_alerts",
  "idle_scan_enabled",
  "scheduled_scan_enabled",
  "enhanced_signature_provider",
  // v0.1.9 audit additions (HIGH-2 / LOW-19) — keep in lockstep with
  // sentinella-ipc-proto::full_config::CRITICAL_FIELDS.
  "fish.enabled",
  "fish.observe_only",
  "fish.active_response",
  "sandbox.enabled",
  "clamav_isolation",
]);

/** Response shape for save_full_settings / set_critical_settings. */
export interface SettingsWriteResult {
  ok: boolean;
  error?: string;
  requires_elevation?: boolean;
  changes?: string[];
}

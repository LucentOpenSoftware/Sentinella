// Types matching daemon IPC responses EXACTLY.
// No cosmetic additions — every field here comes from sentinelld.

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
  state: "idle" | "running" | "completed";
  scan_type: string | null;
  files_scanned: number;
  threats_found: number;
  current_path: string | null;
  scans_completed: number;
}

export interface ScanRecord {
  job_id: string;
  scan_type: string;
  started_at: number;
  finished_at: number;
  files_scanned: number;
  threats_found: number;
  status: string;
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
}

export interface ActivityEntry {
  event_type: string;
  message: string;
  detail: string | null;
  timestamp: number;
}

export interface RuntimeStats {
  uptime_secs: number;
  uptime_human: string;
  scans_completed: number;
  threats_found_total: number;
  ipc_requests_served: number;
  quarantine_count: number;
  activity_count: number;
  started_at: number;
}

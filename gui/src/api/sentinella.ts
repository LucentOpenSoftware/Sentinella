// Centralized API layer. Every daemon call goes through here.
// No component should call invoke() directly.

import { invoke } from "@tauri-apps/api/core";
import type {
  EngineStatus,
  ScanStatusResponse,
  ScanRecord,
  ScanStarted,
  QuarantineEntry,
  WatcherStatus,
  UpdateStatus,
  ActivityEntry,
  RuntimeStats,
} from "../types/sentinella";

// ── Engine ──────────────────────────────────────────────────

export const getEngineStatus = () =>
  invoke<EngineStatus>("get_engine_status");

// ── Scan ────────────────────────────────────────────────────

export const getScanStatus = () =>
  invoke<ScanStatusResponse>("get_scan_status");

export const startQuickScan = () =>
  invoke<ScanStarted>("start_quick_scan");

export const startFullScan = () =>
  invoke<ScanStarted>("start_full_scan");

export const getScanHistory = () =>
  invoke<ScanRecord[]>("get_scan_history");

// ── Quarantine ──────────────────────────────────────────────

export const getQuarantineItems = () =>
  invoke<QuarantineEntry[]>("get_quarantine_items");

// ── Watcher ─────────────────────────────────────────────────

export const getWatcherStatus = () =>
  invoke<WatcherStatus>("get_watcher_status");

// ── Updates ─────────────────────────────────────────────────

export const getUpdateStatus = () =>
  invoke<UpdateStatus>("get_update_status");

export const startSignatureUpdate = () =>
  invoke<{ ok: boolean }>("start_signature_update");

// ── Activity ────────────────────────────────────────────────

export const getActivity = () =>
  invoke<ActivityEntry[]>("get_activity");

// ── Runtime stats ───────────────────────────────────────────

export const getRuntimeStats = () =>
  invoke<RuntimeStats>("get_runtime_stats");

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
}

export async function fetchDashboard(): Promise<DashboardData> {
  const [engine, scan, watcher, update, quarantine, activity, stats, scanHistory] =
    await Promise.all([
      getEngineStatus(),
      getScanStatus(),
      getWatcherStatus(),
      getUpdateStatus(),
      getQuarantineItems(),
      getActivity(),
      getRuntimeStats(),
      getScanHistory(),
    ]);
  return { engine, scan, watcher, update, quarantine, activity, stats, scanHistory };
}

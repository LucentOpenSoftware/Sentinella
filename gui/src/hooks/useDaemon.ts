import { useState, useEffect, useCallback, useRef } from "react";
import type { DashboardData, ConnectionState } from "../api/sentinella";
import { fetchDashboard, getConnectionState } from "../api/sentinella";
import {
  notifyScanComplete,
  notifyUpdateFailed,
  notifyProtectionDegraded,
  notifyRealtimeUnavailable,
  notifyQuarantined,
} from "../notifications";

const POLL_INTERVAL = 5000; // 5 seconds
const DISCONNECT_THRESHOLD = 3; // Require 3 consecutive failures before showing disconnected

export interface DaemonState {
  data: DashboardData | null;
  connected: boolean;
  /** Richer connection state from supervisor. */
  connectionState: ConnectionState;
  loading: boolean;
  error: string | null;
  lastRefresh: Date | null;
  refresh: () => void;
}

export function useDaemon(): DaemonState {
  const [data, setData] = useState<DashboardData | null>(null);
  const [connected, setConnected] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const failCountRef = useRef(0);

  // ── State transition tracking for notifications ─────────
  const prevRef = useRef<{
    scanRunning: boolean;
    scanThreats: number;
    scanFiles: number;
    scanType: string;
    updateState: string;
    updateError: string | null;
    protectionState: string;
    watcherActive: boolean;
    quarantineCount: number;
    quarantineIds: Set<string>;
  } | null>(null);

  const refresh = useCallback(async () => {
    // Check supervisor connection state (fast, always available).
    const supervisorState = await getConnectionState().catch(() => "disconnected" as ConnectionState);
    setConnectionState(supervisorState);

    try {
      const result = await fetchDashboard();
      const isConnected = result.engine.state !== "error" || result.engine.signature_count > 0;
      setData(result);
      setConnected(isConnected);
      setError(null);
      setLastRefresh(new Date());
      failCountRef.current = 0; // Reset on success.

      // ── Detect transitions → fire notifications ───────
      const prev = prevRef.current;
      if (prev && isConnected) {
        // Scan completed with threats.
        if (prev.scanRunning && !result.scan.running && result.scan.state === "completed") {
          notifyScanComplete(
            result.scan.threats_found,
            result.scan.files_scanned,
            result.scan.scan_type || "scan",
          );
        }

        // Update failed.
        if (prev.updateState !== "error" && result.update.state === "error" && result.update.last_error) {
          notifyUpdateFailed(result.update.last_error);
        }

        // Protection degraded — only notify if we're actually connected.
        // Transient IPC failures produce fallback stats with "unprotected" which
        // is a false positive. Only fire if the daemon is genuinely reachable
        // and reports degraded state.
        const ps = result.stats.protection_state;
        const statsAreReal = result.stats.uptime_secs > 0; // fallback has uptime=0
        if (statsAreReal && prev.protectionState === "fully_protected" && ps !== "fully_protected") {
          notifyProtectionDegraded(result.stats.protection_detail || "");
        }

        // Watcher went down — same guard.
        if (statsAreReal && prev.watcherActive && !result.stats.watcher_active) {
          notifyRealtimeUnavailable();
        }

        // New quarantine items (watcher auto-quarantine).
        for (const q of result.quarantine) {
          if (!prev.quarantineIds.has(q.id)) {
            notifyQuarantined(q.signature, q.original_path);
          }
        }
      }

      // Update prev state.
      prevRef.current = {
        scanRunning: result.scan.running,
        scanThreats: result.scan.threats_found,
        scanFiles: result.scan.files_scanned,
        scanType: result.scan.scan_type || "",
        updateState: result.update.state,
        updateError: result.update.last_error ?? null,
        protectionState: result.stats.protection_state,
        watcherActive: result.stats.watcher_active,
        quarantineCount: result.quarantine.length,
        quarantineIds: new Set(result.quarantine.map(q => q.id)),
      };
    } catch (e) {
      failCountRef.current += 1;
      // Only show disconnected after multiple consecutive failures.
      // Prevents flicker during heavy scans when pipe is temporarily busy.
      if (failCountRef.current >= DISCONNECT_THRESHOLD) {
        console.error("[useDaemon] fetchDashboard failed:", e);
        setConnected(false);
        setError(String(e));
      }
      // Keep showing last known data during transient failures.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch.
    refresh();

    // Polling — pauses when window is hidden/minimized.
    const startPolling = () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = setInterval(refresh, POLL_INTERVAL);
    };
    const stopPolling = () => {
      if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null; }
    };
    const onVisibility = () => {
      if (document.hidden) { stopPolling(); } else { refresh(); startPolling(); }
    };

    startPolling();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopPolling();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [refresh]);

  return { data, connected, connectionState, loading, error, lastRefresh, refresh };
}

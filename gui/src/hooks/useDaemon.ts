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
// v0.1.9 audit HIGH-3 fix: invalidate the Settings page's module-scope
// defaults + restart_requirements caches whenever the daemon goes from
// disconnected back to connected — the daemon binary may have changed
// across the gap (tray restart, service auto-restart, scheduled
// update reload), and the cached schema metadata could be stale.
import { invalidateSettingsCache } from "../pages/Settings/hooks/useFullConfig";

const POLL_INTERVAL = 5000; // 5 seconds
// v0.1.8: bumped 3 -> 6 to absorb heavier daemon work bursts
// (trust_graph integrity checks + FISH detector + idle scanner all
// firing concurrently on busy systems can briefly starve the IPC
// thread). 6 × 5s ≈ 30 s of failure before flipping the badge.
const DISCONNECT_THRESHOLD = 6;
// Debounce isConnected (the engine-status-based check) the same way.
// Without this, ONE engine.status timeout flipped connected=false
// instantly because each call has its own .catch fallback that returns
// engine.state="error"+signature_count=0 — the negative case bypassed
// failCountRef entirely. Now isConnected only flips false after
// CONNECTED_DEBOUNCE consecutive engine-status failures.
const CONNECTED_DEBOUNCE = 3;

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
  // v0.1.8: separate counter for engine-status-based "connected" flag.
  // Bumped on each poll where engine.state==="error" + signature_count===0;
  // reset on any healthy poll. UI flips false only when ≥ CONNECTED_DEBOUNCE.
  const disconnectCountRef = useRef(0);
  // Monotonic refresh id. Each refresh() call bumps it and captures the value;
  // state writes only commit if the captured id is still the latest. Closes a
  // race where two overlapping refreshes (e.g. quick visibility toggle, or a
  // manual `refresh()` racing the 5s poll) could let an older response land
  // AFTER a newer one — pinning the UI to stale "scanning" / connection state.
  const refreshIdRef = useRef(0);

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
    const myId = ++refreshIdRef.current;
    const isLatest = () => refreshIdRef.current === myId;

    // Check supervisor connection state (fast, always available).
    const supervisorState = await getConnectionState().catch(() => "disconnected" as ConnectionState);
    if (!isLatest()) return;
    setConnectionState(supervisorState);

    try {
      const result = await fetchDashboard();
      if (!isLatest()) return; // A newer refresh already landed — drop ours.
      // v0.1.9 audit MED-7: half-dead detection.
      //
      // fetchDashboard wraps each of 9 IPC calls in its own .catch()
      // returning a synthetic fallback, so Promise.all never throws.
      // Previously healthyThisPoll was just the engine signal, which
      // meant: if getEngineStatus succeeded (cached/fast) but every
      // OTHER endpoint silently fell back (uptime=0, watcher=false,
      // quarantine=[]), connected stayed TRUE and the UI rendered a
      // green badge over a zeroed dashboard. The author's own
      // `statsAreReal = stats.uptime_secs > 0` guard later in this
      // file is the smoking gun that this fallback shape is known to
      // happen in practice. Now we require BOTH signals — engine OK
      // AND stats are real — before calling the connection healthy.
      const engineHealthy =
        result.engine.state !== "error" || result.engine.signature_count > 0;
      const statsAreReal = (result.stats?.uptime_secs ?? 0) > 0;
      const healthyThisPoll = engineHealthy && statsAreReal;
      // Debounce the disconnect flip — see CONNECTED_DEBOUNCE comment.
      if (healthyThisPoll) {
        // v0.1.9 audit HIGH-3: if we just transitioned from
        // disconnected→connected, the daemon may have hot-restarted with
        // a new binary — invalidate the Settings cache so the next mount
        // re-fetches defaults + restart_requirements against the new
        // schema. Cheap no-op if the cache was already empty.
        setConnected((prev) => {
          if (!prev) {
            invalidateSettingsCache();
          }
          return true;
        });
        disconnectCountRef.current = 0;
      } else {
        disconnectCountRef.current += 1;
        if (disconnectCountRef.current >= CONNECTED_DEBOUNCE) {
          setConnected(false);
        }
      }
      setData(result);
      setError(null);
      setLastRefresh(new Date());
      failCountRef.current = 0; // Reset hard-failure counter on any successful fetchDashboard.

      // ── Detect transitions → fire notifications ───────
      const prev = prevRef.current;
      if (prev && healthyThisPoll) {
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
        // `getQuarantineItems()` falls back to [] on a transient failure
        // (quarantine.list is auth-gated + IPC can be busy mid-reload). A
        // sudden N>0 → empty drop is almost certainly that blip, not a real
        // clear — treat the list as UNRELIABLE and don't re-notify (which would
        // flash an old item as freshly caught once the list comes back).
        const qReliable = result.quarantine.length > 0 || prev.quarantineCount === 0;
        if (qReliable) {
          for (const q of result.quarantine) {
            if (!prev.quarantineIds.has(q.id)) {
              notifyQuarantined(q.signature, q.original_path);
            }
          }
        }
      }

      // Update prev state — ONLY from a genuinely-connected poll. During an
      // engine reload the dashboard briefly reports disconnected/fallback data
      // (engine=error, signature_count=0, empty quarantine list). Overwriting
      // prev with that wiped `quarantineIds`, so on the next reconnect poll the
      // existing (old) quarantine items were all "not in prev" → re-fired a
      // tray toast as if freshly caught. Preserving the last-good snapshot
      // across the reload blip stops the phantom flash (and likewise keeps
      // scan/update/protection transitions measured against real state).
      if (healthyThisPoll) {
        // Preserve the last-good quarantine set when the list looks like a
        // transient empty-blip (see qReliable above), so the dedup survives the
        // reload churn instead of re-flagging old items as new on recovery.
        const prevSnap = prevRef.current;
        const qReliable =
          result.quarantine.length > 0 || (prevSnap?.quarantineCount ?? 0) === 0;
        prevRef.current = {
          scanRunning: result.scan.running,
          scanThreats: result.scan.threats_found,
          scanFiles: result.scan.files_scanned,
          scanType: result.scan.scan_type || "",
          updateState: result.update.state,
          updateError: result.update.last_error ?? null,
          protectionState: result.stats.protection_state,
          watcherActive: result.stats.watcher_active,
          quarantineCount: qReliable
            ? result.quarantine.length
            : (prevSnap?.quarantineCount ?? 0),
          quarantineIds: qReliable
            ? new Set(result.quarantine.map(q => q.id))
            : (prevSnap?.quarantineIds ?? new Set()),
        };
      }
    } catch (e) {
      if (!isLatest()) return;
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
      if (isLatest()) setLoading(false);
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

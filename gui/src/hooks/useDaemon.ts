import { useState, useEffect, useCallback, useRef } from "react";
import type { DashboardData } from "../api/sentinella";
import { fetchDashboard } from "../api/sentinella";

const POLL_INTERVAL = 5000; // 5 seconds

export interface DaemonState {
  data: DashboardData | null;
  connected: boolean;
  loading: boolean;
  error: string | null;
  lastRefresh: Date | null;
  refresh: () => void;
}

export function useDaemon(): DaemonState {
  const [data, setData] = useState<DashboardData | null>(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const result = await fetchDashboard();
      setData(result);
      setConnected(true);
      setError(null);
      setLastRefresh(new Date());
    } catch (e) {
      setConnected(false);
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch.
    refresh();

    // Polling.
    intervalRef.current = setInterval(refresh, POLL_INTERVAL);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [refresh]);

  return { data, connected, loading, error, lastRefresh, refresh };
}

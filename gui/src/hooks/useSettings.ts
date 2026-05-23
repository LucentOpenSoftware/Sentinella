import { useState, useEffect, useCallback, useRef } from "react";
import { getSettings, saveSettings } from "../api/sentinella";

export interface DaemonConfig {
  realtime_enabled: boolean;
  realtime_roots: string[];
  max_file_size_mb: number;
  scan_archives: boolean;
  heuristic_alerts: boolean;
  auto_update: boolean;
  update_interval_hours: number;
  update_mirror: string;
  quarantine_retention_days: number;
  auto_quarantine: boolean;
  excluded_paths: string[];
  excluded_extensions: string[];
  excluded_detections: string[];
  trusted_hashes: string[];
  log_level: string;
  scheduled_scan_enabled: boolean;
  scheduled_scan_hour: number;
  scheduled_scan_type: string;
}

const DEFAULTS: DaemonConfig = {
  realtime_enabled: true,
  realtime_roots: [],
  max_file_size_mb: 512,
  scan_archives: true,
  heuristic_alerts: true,
  auto_update: true,
  update_interval_hours: 4,
  update_mirror: "database.clamav.net",
  quarantine_retention_days: 90,
  auto_quarantine: true,
  excluded_paths: [],
  excluded_extensions: [],
  excluded_detections: [],
  trusted_hashes: [],
  log_level: "info",
  scheduled_scan_enabled: true,
  scheduled_scan_hour: 3,
  scheduled_scan_type: "quick",
};

export function useSettings() {
  const [config, setConfig] = useState<DaemonConfig>(DEFAULTS);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveOk, setSaveOk] = useState(false);
  const saveOkTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Use ref to avoid stale closure when rapid toggles happen.
  const configRef = useRef(config);
  configRef.current = config;

  useEffect(() => {
    getSettings()
      .then((raw) => {
        const loaded = { ...DEFAULTS, ...(raw as Partial<DaemonConfig>) };
        setConfig(loaded);
        configRef.current = loaded;
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, []);

  // Cleanup timer on unmount.
  useEffect(() => {
    return () => {
      if (saveOkTimer.current) clearTimeout(saveOkTimer.current);
    };
  }, []);

  const update = useCallback(async (patch: Partial<DaemonConfig>) => {
    // Use ref to get latest config, not stale closure value.
    const newConfig = { ...configRef.current, ...patch };
    setConfig(newConfig);
    configRef.current = newConfig;
    setSaving(true);
    setSaveError(null);
    setSaveOk(false);
    if (saveOkTimer.current) clearTimeout(saveOkTimer.current);
    try {
      const result = await saveSettings(newConfig as unknown as Record<string, unknown>);
      if (result && typeof result === "object" && "error" in result && result.error) {
        setSaveError(String(result.error));
      } else {
        const saved = await getSettings().catch(() => newConfig);
        const confirmed = { ...DEFAULTS, ...(saved as Partial<DaemonConfig>) };
        setConfig(confirmed);
        configRef.current = confirmed;
        setSaveOk(true);
        saveOkTimer.current = setTimeout(() => setSaveOk(false), 2000);
      }
    } catch (e) {
      setSaveError(String(e));
    } finally {
      setSaving(false);
    }
  }, []); // No deps — uses configRef to avoid stale closure.

  return { config, loaded, saving, saveError, saveOk, update };
}

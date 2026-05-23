// Centralized notification dispatch — calm, meaningful Windows toasts.
//
// Philosophy: notify only when the user needs to know.
// No fearware. No spam. No exclamation marks.
//
// Hardened with:
// - Deduplication (5-min cooldown per unique event)
// - Storm control (aggregate rapid-fire events)
// - Severity threshold
// - Local history recording

import { sendNotification, isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { loadNotificationSettings, meetsMinSeverity, type NotificationSeverity } from "./settings";
import { dedupeCheck, stormControlled } from "./dedupe";
import { recordNotification } from "./history";

// ── Permission ────────────────────────────────────────────────

let permissionGranted: boolean | null = null;

async function ensurePermission(): Promise<boolean> {
  if (permissionGranted !== null) return permissionGranted;
  try {
    permissionGranted = await isPermissionGranted();
    if (!permissionGranted) {
      const result = await requestPermission();
      permissionGranted = result === "granted";
    }
  } catch {
    permissionGranted = false;
  }
  return permissionGranted;
}

// ── Core dispatch ─────────────────────────────────────────────

async function send(title: string, body: string): Promise<void> {
  const ok = await ensurePermission();
  if (!ok) return;
  try {
    sendNotification({ title, body });
  } catch {
    // Notification failure must never crash the app.
  }
}

type Gate = "onThreat" | "onQuarantine" | "onUpdateFailure" | "onDegraded" | "onScanComplete";

function shouldNotify(gate: Gate, severity: NotificationSeverity): boolean {
  const s = loadNotificationSettings();
  if (!s.enabled || s.quietMode) return false;
  if (!s[gate]) return false;
  if (!meetsMinSeverity(severity, s.minSeverity)) return false;
  return true;
}

// ── Public API ────────────────────────────────────────────────

/** A threat was detected (ClamAV or ARGUS). */
export function notifyThreatDetected(virusName: string, filePath: string): void {
  if (!shouldNotify("onThreat", "threat")) return;

  const dedupeKey = `threat:${virusName}:${filePath}`;
  const fileName = filePath.split(/[/\\]/).pop() || filePath;

  stormControlled(
    "threat",
    () => {
      if (!dedupeCheck(dedupeKey)) return;
      send("Threat detected", `Sentinella detected ${virusName} in ${fileName}.`);
      recordNotification("threat", "Threat detected", filePath);
    },
    (count) => {
      send("Multiple threats detected", `Sentinella detected ${count} threats during monitoring.`);
      recordNotification("threat_storm", `${count} threats detected`);
    },
  );
}

/** A file was successfully quarantined. */
export function notifyQuarantined(virusName: string, filePath: string): void {
  if (!shouldNotify("onQuarantine", "threat")) return;

  const dedupeKey = `quarantine:${filePath}`;
  const fileName = filePath.split(/[/\\]/).pop() || filePath;

  stormControlled(
    "quarantine",
    () => {
      if (!dedupeCheck(dedupeKey)) return;
      send("File quarantined", `${fileName} (${virusName}) has been moved to quarantine.`);
      recordNotification("quarantine", "File quarantined", filePath);
    },
    (count) => {
      send("Files quarantined", `Sentinella quarantined ${count} files.`);
      recordNotification("quarantine_storm", `${count} files quarantined`);
    },
  );
}

/** Quarantine failed — user needs to know. */
export function notifyQuarantineFailed(filePath: string, reason: string): void {
  if (!shouldNotify("onQuarantine", "critical")) return;
  const dedupeKey = `quarantine_fail:${filePath}`;
  if (!dedupeCheck(dedupeKey)) return;

  const fileName = filePath.split(/[/\\]/).pop() || filePath;
  send("Quarantine failed", `Could not quarantine ${fileName}: ${reason}`);
  recordNotification("quarantine_failed", "Quarantine failed", filePath);
}

/** Scan completed with threats. Clean scans are silent. */
export function notifyScanComplete(threats: number, filesScanned: number, scanType: string): void {
  if (threats === 0) return;
  if (!shouldNotify("onScanComplete", "warning")) return;

  const dedupeKey = `scan_complete:${scanType}:${threats}`;
  if (!dedupeCheck(dedupeKey, 60_000)) return; // 1-min cooldown for scan completion

  const label = scanType === "quick" ? "Quick scan" : scanType === "full" ? "Full scan" : "Scan";
  send(`${label} complete`, `${threats} threat${threats > 1 ? "s" : ""} found in ${filesScanned.toLocaleString()} files.`);
  recordNotification("scan_complete", `${label} complete — ${threats} threats`);
}

/** Signature update failed. */
export function notifyUpdateFailed(reason: string): void {
  if (!shouldNotify("onUpdateFailure", "warning")) return;
  if (!dedupeCheck("update_failed")) return;

  send("Signature update failed", `Sentinella could not update virus signatures: ${reason}`);
  recordNotification("update_failed", "Signature update failed");
}

/** Protection state degraded or unavailable. */
export function notifyProtectionDegraded(detail: string): void {
  if (!shouldNotify("onDegraded", "critical")) return;
  if (!dedupeCheck("protection_degraded")) return;

  send("Protection degraded", detail || "Some protection subsystems are unavailable.");
  recordNotification("protection_degraded", "Protection degraded");
}

/** Realtime protection unavailable. */
export function notifyRealtimeUnavailable(): void {
  if (!shouldNotify("onDegraded", "critical")) return;
  if (!dedupeCheck("realtime_unavailable")) return;

  send("Real-time protection unavailable", "The filesystem watcher could not start. New files are not being monitored.");
  recordNotification("realtime_unavailable", "Real-time protection unavailable");
}

/** First-run signature update completed. */
export function notifyFirstRunUpdateComplete(sigCount: number): void {
  if (!loadNotificationSettings().enabled) return;
  if (!dedupeCheck("first_run_complete")) return;

  send("Sentinella is ready", `Virus signatures loaded (${sigCount.toLocaleString()} signatures). Your system is now protected.`);
  recordNotification("first_run_complete", "Sentinella is ready");
}

/** First-run signature update failed. */
export function notifyFirstRunUpdateFailed(): void {
  if (!loadNotificationSettings().enabled) return;
  if (!dedupeCheck("first_run_failed")) return;

  send("Signature download failed", "Sentinella could not download virus signatures. You can retry from the Update page.");
  recordNotification("first_run_failed", "Signature download failed");
}

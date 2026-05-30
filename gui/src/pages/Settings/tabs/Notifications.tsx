// Notifications tab — Windows notification cadence + severity gate.
//
// State is stored in localStorage via the notifications/settings.ts
// helpers, NOT in the daemon's TOML. This is GUI-local UX preference,
// not protection policy.

import { useState } from "react";
import { Bell, ListFilter, Moon, Tags } from "lucide-react";
import * as i18n from "../../../i18n";
import {
  loadNotificationSettings,
  saveNotificationSettings,
  type NotificationSettings,
  type NotificationSeverity,
} from "../../../notifications";
import { Section, SettingRow, Toggle } from "../components/widgets";

export function NotificationsTab() {
  const [ns, setNs] = useState<NotificationSettings>(loadNotificationSettings);

  const toggle = (key: keyof NotificationSettings) => {
    const updated = { ...ns, [key]: !ns[key] };
    setNs(updated);
    saveNotificationSettings(updated);
  };

  const setSeverity = (level: NotificationSeverity) => {
    const updated = { ...ns, minSeverity: level };
    setNs(updated);
    saveNotificationSettings(updated);
  };

  return (
    <div>
      {/* ── Master toggle ──────────────────────────── */}
      <Section
        icon={<Bell />}
        title={i18n.t("settings.win_notifications")}
        subtitle={i18n.t("settings.win_notifications_desc")}
      >
        <SettingRow
          label={i18n.t("settings.enable_notifications")}
          description={i18n.t("settings.enable_notifications_desc")}
          control={
            <Toggle
              checked={ns.enabled}
              onChange={() => toggle("enabled")}
            />
          }
        />
      </Section>

      {/* ── Per-event toggles ──────────────────────── */}
      <Section
        icon={<Tags />}
        title={i18n.t("settings.notification_events")}
        subtitle={i18n.t("settings.notification_events_desc")}
      >
        <SettingRow
          label={i18n.t("settings.threat_detected")}
          description={i18n.t("settings.threat_detected_desc")}
          control={
            <Toggle
              checked={ns.onThreat}
              onChange={() => toggle("onThreat")}
              disabled={!ns.enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.file_quarantined")}
          description={i18n.t("settings.file_quarantined_desc")}
          control={
            <Toggle
              checked={ns.onQuarantine}
              onChange={() => toggle("onQuarantine")}
              disabled={!ns.enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.scan_completed_threats")}
          description={i18n.t("settings.scan_completed_threats_desc")}
          control={
            <Toggle
              checked={ns.onScanComplete}
              onChange={() => toggle("onScanComplete")}
              disabled={!ns.enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.sig_update_failed")}
          description={i18n.t("settings.sig_update_failed_desc")}
          control={
            <Toggle
              checked={ns.onUpdateFailure}
              onChange={() => toggle("onUpdateFailure")}
              disabled={!ns.enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.protection_degraded")}
          description={i18n.t("settings.protection_degraded_desc")}
          control={
            <Toggle
              checked={ns.onDegraded}
              onChange={() => toggle("onDegraded")}
              disabled={!ns.enabled}
            />
          }
        />
      </Section>

      {/* ── Severity floor ─────────────────────────── */}
      <Section
        icon={<ListFilter />}
        title={i18n.t("settings.severity_threshold")}
        subtitle={i18n.t("settings.severity_threshold_desc")}
      >
        <div
          className={`grid grid-cols-4 gap-1 rounded-md bg-[rgb(var(--surface))]/40 p-1 ${
            !ns.enabled ? "opacity-40 pointer-events-none" : ""
          }`}
        >
          {(["info", "warning", "threat", "critical"] as NotificationSeverity[]).map(
            (level) => (
              <button
                key={level}
                onClick={() => setSeverity(level)}
                className={`py-1.5 rounded text-xs font-medium capitalize transition-colors ${
                  ns.minSeverity === level
                    ? "bg-[rgb(var(--accent))] text-white"
                    : "text-[rgb(var(--muted))] hover:bg-[rgb(var(--surface))]/60"
                }`}
              >
                {level === "info"
                  ? i18n.t("settings.severity_all")
                  : level}
              </button>
            ),
          )}
        </div>
        <p className="text-[11px] text-[rgb(var(--muted))] mt-1.5">
          {ns.minSeverity === "info" && i18n.t("settings.severity_info_desc")}
          {ns.minSeverity === "warning" &&
            i18n.t("settings.severity_warning_desc")}
          {ns.minSeverity === "threat" &&
            i18n.t("settings.severity_threat_desc")}
          {ns.minSeverity === "critical" &&
            i18n.t("settings.severity_critical_desc")}
        </p>
      </Section>

      {/* ── Quiet mode ─────────────────────────────── */}
      <Section
        icon={<Moon />}
        title={i18n.t("settings.quiet_mode")}
        subtitle={i18n.t("settings.quiet_mode_desc")}
      >
        <SettingRow
          label={i18n.t("settings.quiet_toggle")}
          description={i18n.t("settings.quiet_toggle_desc")}
          control={
            <Toggle
              checked={ns.quietMode}
              onChange={() => toggle("quietMode")}
              disabled={!ns.enabled}
            />
          }
        />
      </Section>
    </div>
  );
}

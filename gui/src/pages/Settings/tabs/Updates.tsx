// Updates tab — signature update cadence, mirror, staleness threshold.

import { Database, Globe, RefreshCw } from "lucide-react";
import * as i18n from "../../../i18n";
import {
  SelectInput,
  Section,
  SettingRow,
  TextInput,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function UpdatesTab({ ctx }: { ctx: UseFullConfigResult }) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];

  const intervalOpts: Array<{ value: string; label: string }> = [
    { value: "1", label: i18n.t("settings.every_hour") },
    { value: "2", label: i18n.t("settings.every_2h") },
    { value: "4", label: i18n.t("settings.every_4h") },
    { value: "12", label: i18n.t("settings.every_12h") },
    { value: "24", label: i18n.t("settings.daily") },
  ];

  const staleOpts = [1, 3, 7, 14, 30].map((d) => ({
    value: String(d),
    label: `${d} ${i18n.t("settings.days_unit")}`,
  }));

  // Notification threshold. Starts at 7 because anything shorter would
  // interrupt the user about failures that the updater's own retry plus the
  // next scheduled cycle routinely fix on their own.
  const notifyOpts = [7, 14, 30, 60, 90].map((d) => ({
    value: String(d),
    label: `${d} ${i18n.t("settings.days_unit")}`,
  }));

  return (
    <div>
      {/* ── Auto-update cadence ────────────────────── */}
      <Section
        icon={<RefreshCw className="w-5 h-5" />}
        title={i18n.t("settings.section_auto_update")}
        subtitle={i18n.t("settings.section_auto_update_desc")}
      >
        <SettingRow
          label={i18n.t("settings.auto_update")}
          description={i18n.t("settings.auto_update_desc")}
          restartRequirement={rr("auto_update")}
          isDefault={isDefault("auto_update")}
          onReset={() => resetField("auto_update")}
          control={
            <Toggle
              checked={draft.auto_update}
              onChange={(v) => updatePath("auto_update", v)}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.update_interval")}
          description={i18n.t("settings.update_interval_desc")}
          isDefault={isDefault("update_interval_hours")}
          onReset={() => resetField("update_interval_hours")}
          control={
            <SelectInput<string>
              value={String(draft.update_interval_hours)}
              onChange={(v) =>
                updatePath("update_interval_hours", parseInt(v, 10))
              }
              options={intervalOpts}
              disabled={!draft.auto_update}
            />
          }
        />
      </Section>

      {/* ── Mirror + staleness ─────────────────────── */}
      <Section
        icon={<Globe className="w-5 h-5" />}
        title={i18n.t("settings.section_update_source")}
        subtitle={i18n.t("settings.section_update_source_desc")}
      >
        <SettingRow
          label={i18n.t("settings.update_mirror")}
          description={i18n.t("settings.update_mirror_desc")}
          isDefault={isDefault("update_mirror")}
          onReset={() => resetField("update_mirror")}
          control={
            <TextInput
              value={draft.update_mirror}
              onChange={(v) => updatePath("update_mirror", v)}
              placeholder="database.clamav.net"
              width="w-72"
            />
          }
        />
      </Section>

      {/* ── Staleness threshold ────────────────────── */}
      <Section
        icon={<Database className="w-5 h-5" />}
        title={i18n.t("settings.section_freshness")}
        subtitle={i18n.t("settings.section_freshness_desc")}
      >
        <SettingRow
          label={i18n.t("settings.signature_stale_days")}
          description={i18n.t("settings.signature_stale_days_desc")}
          isDefault={isDefault("signature_stale_days")}
          onReset={() => resetField("signature_stale_days")}
          control={
            <SelectInput<string>
              value={String(draft.signature_stale_days)}
              onChange={(v) =>
                updatePath("signature_stale_days", parseInt(v, 10))
              }
              options={staleOpts}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.signature_stale_notify_days")}
          description={i18n.t("settings.signature_stale_notify_days_desc")}
          isDefault={isDefault("signature_stale_notify_days")}
          onReset={() => resetField("signature_stale_notify_days")}
          control={
            <SelectInput<string>
              value={String(draft.signature_stale_notify_days)}
              onChange={(v) =>
                updatePath("signature_stale_notify_days", parseInt(v, 10))
              }
              options={notifyOpts}
            />
          }
        />
      </Section>
    </div>
  );
}

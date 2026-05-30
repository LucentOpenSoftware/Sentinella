// Schedule tab — scheduled scan + idle background scanner (~12 fields).

import { useState } from "react";
import {
  Clock,
  Coffee,
  ChevronDown,
  ChevronRight,
  ScanLine,
} from "lucide-react";
import * as i18n from "../../../i18n";
import {
  ElevationBanner,
  NumberInput,
  SelectInput,
  Section,
  SettingRow,
  Slider,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function ScheduleTab({
  ctx,
  isElevated,
  onRestartAsAdmin,
}: {
  ctx: UseFullConfigResult;
  isElevated: boolean;
  onRestartAsAdmin?: () => void;
}) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  const [advancedOpen, setAdvancedOpen] = useState(false);
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];

  const hourOpts = Array.from({ length: 24 }, (_, i) => ({
    value: String(i),
    label: `${String(i).padStart(2, "0")}:00`,
  }));

  const scanTypeOpts: Array<{ value: string; label: string }> = [
    { value: "quick", label: i18n.t("settings.scan_type_quick") },
    { value: "full", label: i18n.t("settings.scan_type_full") },
  ];

  return (
    <div>
      {!isElevated && <ElevationBanner onRestartAsAdmin={onRestartAsAdmin} />}

      {/* ── Scheduled scan ─────────────────────────── */}
      <Section
        icon={<Clock className="w-5 h-5" />}
        title={i18n.t("settings.section_scheduled")}
        subtitle={i18n.t("settings.section_scheduled_desc")}
      >
        <SettingRow
          label={i18n.t("settings.scheduled_scan_enabled")}
          description={i18n.t("settings.scheduled_scan_enabled_desc")}
          locked
          restartRequirement={rr("scheduled_scan_enabled")}
          isDefault={isDefault("scheduled_scan_enabled")}
          onReset={() => resetField("scheduled_scan_enabled")}
          control={
            <Toggle
              checked={draft.scheduled_scan_enabled}
              onChange={(v) => updatePath("scheduled_scan_enabled", v)}
              disabled={!isElevated}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.scheduled_scan_hour")}
          description={i18n.t("settings.scheduled_scan_hour_desc")}
          isDefault={isDefault("scheduled_scan_hour")}
          onReset={() => resetField("scheduled_scan_hour")}
          control={
            <SelectInput<string>
              value={String(draft.scheduled_scan_hour)}
              onChange={(v) =>
                updatePath("scheduled_scan_hour", parseInt(v, 10))
              }
              options={hourOpts}
              disabled={!draft.scheduled_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.scheduled_scan_type")}
          description={i18n.t("settings.scheduled_scan_type_desc")}
          isDefault={isDefault("scheduled_scan_type")}
          onReset={() => resetField("scheduled_scan_type")}
          control={
            <SelectInput<string>
              value={draft.scheduled_scan_type}
              onChange={(v) => updatePath("scheduled_scan_type", v)}
              options={scanTypeOpts}
              disabled={!draft.scheduled_scan_enabled}
            />
          }
        />
      </Section>

      {/* ── Idle background scanner ────────────────── */}
      <Section
        icon={<ScanLine className="w-5 h-5" />}
        title={i18n.t("settings.section_idle")}
        subtitle={i18n.t("settings.section_idle_desc")}
      >
        <SettingRow
          label={i18n.t("settings.idle_scan_enabled")}
          description={i18n.t("settings.idle_scan_enabled_desc")}
          locked
          isDefault={isDefault("idle_scan_enabled")}
          onReset={() => resetField("idle_scan_enabled")}
          control={
            <Toggle
              checked={draft.idle_scan_enabled}
              onChange={(v) => updatePath("idle_scan_enabled", v)}
              disabled={!isElevated}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_on_battery")}
          description={i18n.t("settings.idle_scan_on_battery_desc")}
          isDefault={isDefault("idle_scan_on_battery")}
          onReset={() => resetField("idle_scan_on_battery")}
          control={
            <Toggle
              checked={draft.idle_scan_on_battery}
              onChange={(v) => updatePath("idle_scan_on_battery", v)}
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_fullscreen_pause")}
          description={i18n.t("settings.idle_scan_fullscreen_pause_desc")}
          isDefault={isDefault("idle_scan_fullscreen_pause")}
          onReset={() => resetField("idle_scan_fullscreen_pause")}
          control={
            <Toggle
              checked={draft.idle_scan_fullscreen_pause}
              onChange={(v) => updatePath("idle_scan_fullscreen_pause", v)}
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_cpu_pause_threshold")}
          description={i18n.t("settings.idle_scan_cpu_pause_threshold_desc")}
          isDefault={isDefault("idle_scan_cpu_pause_threshold")}
          onReset={() => resetField("idle_scan_cpu_pause_threshold")}
          control={
            <Slider
              value={draft.idle_scan_cpu_pause_threshold}
              onChange={(v) =>
                updatePath("idle_scan_cpu_pause_threshold", v)
              }
              min={10}
              max={90}
              step={5}
              suffix="%"
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_max_file_size_mb")}
          description={i18n.t("settings.idle_scan_max_file_size_mb_desc")}
          isDefault={isDefault("idle_scan_max_file_size_mb")}
          onReset={() => resetField("idle_scan_max_file_size_mb")}
          control={
            <Slider
              value={draft.idle_scan_max_file_size_mb}
              onChange={(v) => updatePath("idle_scan_max_file_size_mb", v)}
              min={16}
              max={4096}
              step={16}
              suffix="MB"
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_max_files_per_session")}
          description={i18n.t("settings.idle_scan_max_files_per_session_desc")}
          isDefault={isDefault("idle_scan_max_files_per_session")}
          onReset={() => resetField("idle_scan_max_files_per_session")}
          control={
            <NumberInput
              value={draft.idle_scan_max_files_per_session}
              onChange={(v) =>
                updatePath("idle_scan_max_files_per_session", v)
              }
              min={100}
              max={1_000_000}
              step={100}
              disabled={!draft.idle_scan_enabled}
              width="w-28"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_start_delay_secs")}
          description={i18n.t("settings.idle_scan_start_delay_secs_desc")}
          isDefault={isDefault("idle_scan_start_delay_secs")}
          onReset={() => resetField("idle_scan_start_delay_secs")}
          control={
            <NumberInput
              value={draft.idle_scan_start_delay_secs}
              onChange={(v) => updatePath("idle_scan_start_delay_secs", v)}
              min={0}
              max={3600}
              step={30}
              suffix="s"
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.idle_scan_disk_latency_pause_ms")}
          description={i18n.t("settings.idle_scan_disk_latency_pause_ms_desc")}
          isDefault={isDefault("idle_scan_disk_latency_pause_ms")}
          onReset={() => resetField("idle_scan_disk_latency_pause_ms")}
          control={
            <NumberInput
              value={draft.idle_scan_disk_latency_pause_ms}
              onChange={(v) =>
                updatePath("idle_scan_disk_latency_pause_ms", v)
              }
              min={10}
              max={5000}
              step={10}
              suffix="ms"
              disabled={!draft.idle_scan_enabled}
            />
          }
        />
      </Section>

      {/* ── Pacing (advanced, collapsible) ─────────── */}
      <section className="bg-[rgb(var(--surface))]/40 border border-[rgb(var(--border))]/30 rounded-xl p-5 mb-5">
        <button
          onClick={() => setAdvancedOpen((o) => !o)}
          className="w-full flex items-center justify-between gap-3 text-left"
        >
          <div className="flex items-center gap-3">
            <Coffee className="w-5 h-5 text-[rgb(var(--accent))]" />
            <div>
              <h3 className="text-base font-semibold">
                {i18n.t("settings.section_pacing")}
              </h3>
              <p className="text-xs text-[rgb(var(--muted))] mt-0.5">
                {i18n.t("settings.section_pacing_desc")}
              </p>
            </div>
          </div>
          {advancedOpen ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>
        {advancedOpen && (
          <div className="space-y-3 mt-4">
            <PacingTier
              ctx={ctx}
              tier="slow"
              label={i18n.t("settings.pacing_slow")}
              minKey="idle_scan_slow_delay_min_ms"
              maxKey="idle_scan_slow_delay_max_ms"
            />
            <PacingTier
              ctx={ctx}
              tier="normal"
              label={i18n.t("settings.pacing_normal")}
              minKey="idle_scan_normal_delay_min_ms"
              maxKey="idle_scan_normal_delay_max_ms"
            />
            <PacingTier
              ctx={ctx}
              tier="fast"
              label={i18n.t("settings.pacing_fast")}
              minKey="idle_scan_fast_delay_min_ms"
              maxKey="idle_scan_fast_delay_max_ms"
            />
          </div>
        )}
      </section>
    </div>
  );
}

function PacingTier({
  ctx,
  tier,
  label,
  minKey,
  maxKey,
}: {
  ctx: UseFullConfigResult;
  tier: string;
  label: string;
  minKey: keyof import("../../../types/sentinella").FullConfig;
  maxKey: keyof import("../../../types/sentinella").FullConfig;
}) {
  const { draft, updatePath, isDefault, resetField } = ctx;
  if (!draft) return null;
  const minVal = draft[minKey] as number;
  const maxVal = draft[maxKey] as number;
  const invalid = minVal > maxVal;
  return (
    <div className="border-b border-[rgb(var(--border))]/15 last:border-b-0 py-2">
      <div className="flex items-center justify-between gap-3 mb-1">
        <span className="text-sm font-medium capitalize">{label}</span>
        {invalid && (
          <span className="text-xs text-red-400">
            {i18n.t("settings.min_must_le_max")}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2">
        <SettingRow
          label={i18n.t("settings.min_ms")}
          isDefault={isDefault(minKey as string)}
          onReset={() => resetField(minKey as string)}
          control={
            <NumberInput
              value={minVal}
              onChange={(v) => updatePath(minKey as string, v)}
              min={0}
              max={60_000}
              step={10}
              suffix="ms"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.max_ms")}
          isDefault={isDefault(maxKey as string)}
          onReset={() => resetField(maxKey as string)}
          control={
            <NumberInput
              value={maxVal}
              onChange={(v) => updatePath(maxKey as string, v)}
              min={0}
              max={60_000}
              step={10}
              suffix="ms"
            />
          }
        />
      </div>
      <p className="text-[10px] text-[rgb(var(--muted))] mt-1">
        {i18n.t("settings.pacing_tier_hint").replace("{tier}", tier)}
      </p>
    </div>
  );
}

// Engine tab — ClamAV isolation, ARGUS worker, memory profile.

import { Cpu, Gauge, MemoryStick, Workflow } from "lucide-react";
import * as i18n from "../../../i18n";
import {
  ElevationBanner,
  NumberInput,
  SelectInput,
  Section,
  SettingRow,
  Slider,
  TextInput,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function EngineTab({
  ctx,
  isElevated,
  onRestartAsAdmin,
}: {
  ctx: UseFullConfigResult;
  isElevated: boolean;
  onRestartAsAdmin?: () => void;
}) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];

  const isolationOpts: Array<{ value: string; label: string }> = [
    { value: "in_process", label: i18n.t("settings.isolation_in_process") },
    { value: "subprocess", label: i18n.t("settings.isolation_subprocess") },
  ];

  const memProfileOpts: Array<{ value: string; label: string }> = [
    { value: "low", label: i18n.t("settings.mem_profile_low") },
    { value: "normal", label: i18n.t("settings.mem_profile_normal") },
    { value: "aggressive", label: i18n.t("settings.mem_profile_aggressive") },
  ];

  return (
    <div>
      {!isElevated && <ElevationBanner onRestartAsAdmin={onRestartAsAdmin} />}

      {/* ── ClamAV isolation ───────────────────────── */}
      <Section
        icon={<Cpu className="w-5 h-5" />}
        title={i18n.t("settings.section_clamav")}
        subtitle={i18n.t("settings.section_clamav_desc")}
      >
        <SettingRow
          label={i18n.t("settings.clamav_isolation")}
          description={i18n.t("settings.clamav_isolation_desc")}
          locked
          restartRequirement={rr("clamav_isolation")}
          isDefault={isDefault("clamav_isolation")}
          onReset={() => resetField("clamav_isolation")}
          warning={
            draft.clamav_isolation === "subprocess"
              ? i18n.t("settings.subprocess_warning")
              : undefined
          }
          control={
            <SelectInput<string>
              value={draft.clamav_isolation}
              onChange={(v) => updatePath("clamav_isolation", v)}
              options={isolationOpts}
              disabled={!isElevated}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.clamav_worker_timeout")}
          description={i18n.t("settings.clamav_worker_timeout_desc")}
          isDefault={isDefault("clamav_worker_timeout_sec")}
          onReset={() => resetField("clamav_worker_timeout_sec")}
          control={
            <Slider
              value={draft.clamav_worker_timeout_sec}
              onChange={(v) =>
                updatePath("clamav_worker_timeout_sec", v)
              }
              min={5}
              max={300}
              step={5}
              suffix="s"
              disabled={draft.clamav_isolation !== "subprocess"}
            />
          }
        />
      </Section>

      {/* ── ARGUS worker ───────────────────────────── */}
      <Section
        icon={<Workflow className="w-5 h-5" />}
        title={i18n.t("settings.section_argus")}
        subtitle={i18n.t("settings.section_argus_desc")}
      >
        <SettingRow
          label={i18n.t("settings.argus_worker_enabled")}
          description={i18n.t("settings.argus_worker_enabled_desc")}
          locked
          restartRequirement={rr("argus_worker_enabled")}
          isDefault={isDefault("argus_worker_enabled")}
          onReset={() => resetField("argus_worker_enabled")}
          control={
            <Toggle
              checked={draft.argus_worker_enabled}
              onChange={(v) => updatePath("argus_worker_enabled", v)}
              disabled={!isElevated}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.argus_worker_path")}
          description={i18n.t("settings.argus_worker_path_desc")}
          locked
          isDefault={isDefault("argus_worker_path")}
          onReset={() => resetField("argus_worker_path")}
          control={
            <TextInput
              value={draft.argus_worker_path}
              onChange={(v) => updatePath("argus_worker_path", v)}
              placeholder="argusd.exe"
              disabled={!isElevated}
              width="w-72"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.argus_worker_timeout")}
          description={i18n.t("settings.argus_worker_timeout_desc")}
          isDefault={isDefault("argus_worker_timeout_sec")}
          onReset={() => resetField("argus_worker_timeout_sec")}
          control={
            <Slider
              value={draft.argus_worker_timeout_sec}
              onChange={(v) => updatePath("argus_worker_timeout_sec", v)}
              min={5}
              max={120}
              step={1}
              suffix="s"
              disabled={!draft.argus_worker_enabled}
            />
          }
        />
      </Section>

      {/* ── Memory & pressure ──────────────────────── */}
      <Section
        icon={<MemoryStick className="w-5 h-5" />}
        title={i18n.t("settings.section_memory")}
        subtitle={i18n.t("settings.section_memory_desc")}
      >
        <SettingRow
          label={i18n.t("settings.memory_profile")}
          description={i18n.t("settings.memory_profile_desc")}
          isDefault={isDefault("performance.memory_profile")}
          onReset={() => resetField("performance.memory_profile")}
          control={
            <SelectInput<string>
              value={draft.performance.memory_profile}
              onChange={(v) =>
                updatePath("performance.memory_profile", v)
              }
              options={memProfileOpts}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.memory_warning_mb")}
          description={i18n.t("settings.memory_warning_mb_desc")}
          isDefault={isDefault("performance.memory_warning_mb")}
          onReset={() => resetField("performance.memory_warning_mb")}
          control={
            <NumberInput
              value={draft.performance.memory_warning_mb}
              onChange={(v) =>
                updatePath("performance.memory_warning_mb", v)
              }
              min={256}
              max={16384}
              step={64}
              suffix="MB"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.memory_critical_mb")}
          description={i18n.t("settings.memory_critical_mb_desc")}
          isDefault={isDefault("performance.memory_critical_mb")}
          onReset={() => resetField("performance.memory_critical_mb")}
          warning={
            draft.performance.memory_critical_mb <=
            draft.performance.memory_warning_mb
              ? i18n.t("settings.critical_must_exceed_warning")
              : undefined
          }
          control={
            <NumberInput
              value={draft.performance.memory_critical_mb}
              onChange={(v) =>
                updatePath("performance.memory_critical_mb", v)
              }
              min={512}
              max={32768}
              step={64}
              suffix="MB"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.external_argus_under_pressure")}
          description={i18n.t("settings.external_argus_under_pressure_desc")}
          isDefault={isDefault("performance.external_argus_under_pressure")}
          onReset={() =>
            resetField("performance.external_argus_under_pressure")
          }
          control={
            <Toggle
              checked={draft.performance.external_argus_under_pressure}
              onChange={(v) =>
                updatePath("performance.external_argus_under_pressure", v)
              }
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.max_resident_workers_on_pressure")}
          description={i18n.t("settings.max_resident_workers_on_pressure_desc")}
          isDefault={isDefault("performance.max_resident_workers_on_pressure")}
          onReset={() =>
            resetField("performance.max_resident_workers_on_pressure")
          }
          control={
            <NumberInput
              value={draft.performance.max_resident_workers_on_pressure}
              onChange={(v) =>
                updatePath("performance.max_resident_workers_on_pressure", v)
              }
              min={1}
              max={16}
              step={1}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.startup_critical_scan")}
          description={i18n.t("settings.startup_critical_scan_desc")}
          restartRequirement={rr("startup_critical_scan")}
          isDefault={isDefault("startup_critical_scan")}
          onReset={() => resetField("startup_critical_scan")}
          control={
            <Toggle
              checked={draft.startup_critical_scan}
              onChange={(v) => updatePath("startup_critical_scan", v)}
            />
          }
        />
      </Section>

      {/* ── Gauges info (read-only) ────────────────── */}
      <Section
        icon={<Gauge className="w-5 h-5" />}
        title={i18n.t("settings.section_orchestrator")}
        subtitle={i18n.t("settings.section_orchestrator_desc")}
      >
        <SettingRow
          label={i18n.t("settings.orchestrator_file_scan_enabled")}
          description={i18n.t("settings.orchestrator_file_scan_enabled_desc")}
          isDefault={isDefault("scan.orchestrator_file_scan_enabled")}
          onReset={() => resetField("scan.orchestrator_file_scan_enabled")}
          control={
            <Toggle
              checked={draft.scan.orchestrator_file_scan_enabled}
              onChange={(v) =>
                updatePath("scan.orchestrator_file_scan_enabled", v)
              }
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.orchestrator_folder_scan_enabled")}
          description={i18n.t("settings.orchestrator_folder_scan_enabled_desc")}
          isDefault={isDefault("scan.orchestrator_folder_scan_enabled")}
          onReset={() => resetField("scan.orchestrator_folder_scan_enabled")}
          control={
            <Toggle
              checked={draft.scan.orchestrator_folder_scan_enabled}
              onChange={(v) =>
                updatePath("scan.orchestrator_folder_scan_enabled", v)
              }
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.orchestrator_quick_scan_enabled")}
          description={i18n.t("settings.orchestrator_quick_scan_enabled_desc")}
          isDefault={isDefault("scan.orchestrator_quick_scan_enabled")}
          onReset={() => resetField("scan.orchestrator_quick_scan_enabled")}
          control={
            <Toggle
              checked={draft.scan.orchestrator_quick_scan_enabled}
              onChange={(v) =>
                updatePath("scan.orchestrator_quick_scan_enabled", v)
              }
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.orchestrator_full_scan_enabled")}
          description={i18n.t("settings.orchestrator_full_scan_enabled_desc")}
          isDefault={isDefault("scan.orchestrator_full_scan_enabled")}
          onReset={() => resetField("scan.orchestrator_full_scan_enabled")}
          control={
            <Toggle
              checked={draft.scan.orchestrator_full_scan_enabled}
              onChange={(v) =>
                updatePath("scan.orchestrator_full_scan_enabled", v)
              }
            />
          }
        />
      </Section>
    </div>
  );
}

// Ransomware tab — FISH detector configuration.

import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Sliders,
} from "lucide-react";
import * as i18n from "../../../i18n";
import {
  ElevationBanner,
  NumberInput,
  SelectInput,
  Section,
  SettingRow,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function RansomwareTab({
  ctx,
  isElevated,
  onRestartAsAdmin,
}: {
  ctx: UseFullConfigResult;
  isElevated: boolean;
  onRestartAsAdmin?: () => void;
}) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  const [thresholdsOpen, setThresholdsOpen] = useState(false);
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];
  // v0.1.9: fish.enabled, fish.observe_only, fish.active_response moved
  // into CRITICAL_FIELDS — daemon refuses them from unelevated callers.
  const critDisabled = !isElevated;

  const responseOpts: Array<{ value: string; label: string }> = [
    { value: "observe", label: i18n.t("settings.fish_response_observe") },
    { value: "suspend", label: i18n.t("settings.fish_response_suspend") },
    { value: "terminate", label: i18n.t("settings.fish_response_terminate") },
  ];

  return (
    <div>
      {!isElevated && <ElevationBanner onRestartAsAdmin={onRestartAsAdmin} />}

      {/* ── Master toggle + response ───────────────── */}
      <Section
        icon={<ShieldAlert className="w-5 h-5" />}
        title={i18n.t("settings.section_fish")}
        subtitle={i18n.t("settings.section_fish_desc")}
      >
        <SettingRow
          label={i18n.t("settings.fish_enabled")}
          description={i18n.t("settings.fish_enabled_desc")}
          locked
          restartRequirement={rr("fish.enabled")}
          isDefault={isDefault("fish.enabled")}
          onReset={() => resetField("fish.enabled")}
          control={
            <Toggle
              checked={draft.fish.enabled}
              onChange={(v) => updatePath("fish.enabled", v)}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.fish_observe_only")}
          description={i18n.t("settings.fish_observe_only_desc")}
          locked
          isDefault={isDefault("fish.observe_only")}
          onReset={() => resetField("fish.observe_only")}
          warning={
            !draft.fish.observe_only
              ? i18n.t("settings.fish_active_warning")
              : undefined
          }
          control={
            <Toggle
              checked={draft.fish.observe_only}
              onChange={(v) => updatePath("fish.observe_only", v)}
              disabled={!draft.fish.enabled || critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.fish_active_response")}
          description={i18n.t("settings.fish_active_response_desc")}
          locked
          isDefault={isDefault("fish.active_response")}
          onReset={() => resetField("fish.active_response")}
          control={
            <SelectInput<string>
              value={draft.fish.active_response}
              onChange={(v) => updatePath("fish.active_response", v)}
              options={responseOpts}
              disabled={!draft.fish.enabled || draft.fish.observe_only || critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.fish_alert_cooldown_seconds")}
          description={i18n.t("settings.fish_alert_cooldown_seconds_desc")}
          isDefault={isDefault("fish.alert_cooldown_seconds")}
          onReset={() => resetField("fish.alert_cooldown_seconds")}
          control={
            <NumberInput
              value={draft.fish.alert_cooldown_seconds}
              onChange={(v) =>
                updatePath("fish.alert_cooldown_seconds", v)
              }
              min={0}
              max={86400}
              step={10}
              suffix="s"
              disabled={!draft.fish.enabled}
            />
          }
        />
      </Section>

      {/* ── Thresholds (collapsible) ───────────────── */}
      <section className="bg-[rgb(var(--surface))]/40 border border-[rgb(var(--border))]/30 rounded-xl p-5 mb-5">
        <button
          onClick={() => setThresholdsOpen((o) => !o)}
          className="w-full flex items-center justify-between gap-3 text-left"
          disabled={!draft.fish.enabled}
        >
          <div className="flex items-center gap-3">
            <Sliders className="w-5 h-5 text-[rgb(var(--accent))]" />
            <div>
              <h3 className="text-base font-semibold">
                {i18n.t("settings.section_fish_thresholds")}
              </h3>
              <p className="text-xs text-[rgb(var(--muted))] mt-0.5">
                {i18n.t("settings.section_fish_thresholds_desc")}
              </p>
            </div>
          </div>
          {thresholdsOpen ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>
        {thresholdsOpen && draft.fish.enabled && (
          <div className="space-y-3 mt-4">
            <SettingRow
              label={i18n.t("settings.fish_window_seconds")}
              description={i18n.t("settings.fish_window_seconds_desc")}
              isDefault={isDefault("fish.window_seconds")}
              onReset={() => resetField("fish.window_seconds")}
              control={
                <NumberInput
                  value={draft.fish.window_seconds}
                  onChange={(v) => updatePath("fish.window_seconds", v)}
                  min={5}
                  max={3600}
                  step={5}
                  suffix="s"
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_rename_threshold")}
              description={i18n.t("settings.fish_rename_threshold_desc")}
              isDefault={isDefault("fish.rename_threshold")}
              onReset={() => resetField("fish.rename_threshold")}
              control={
                <NumberInput
                  value={draft.fish.rename_threshold}
                  onChange={(v) => updatePath("fish.rename_threshold", v)}
                  min={1}
                  max={10000}
                  step={1}
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_rewrite_threshold")}
              description={i18n.t("settings.fish_rewrite_threshold_desc")}
              isDefault={isDefault("fish.rewrite_threshold")}
              onReset={() => resetField("fish.rewrite_threshold")}
              control={
                <NumberInput
                  value={draft.fish.rewrite_threshold}
                  onChange={(v) => updatePath("fish.rewrite_threshold", v)}
                  min={1}
                  max={10000}
                  step={1}
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_ext_mutation_threshold")}
              description={i18n.t("settings.fish_ext_mutation_threshold_desc")}
              isDefault={isDefault("fish.ext_mutation_threshold")}
              onReset={() => resetField("fish.ext_mutation_threshold")}
              control={
                <NumberInput
                  value={draft.fish.ext_mutation_threshold}
                  onChange={(v) =>
                    updatePath("fish.ext_mutation_threshold", v)
                  }
                  min={1}
                  max={1000}
                  step={1}
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_entropy_delta_threshold")}
              description={i18n.t("settings.fish_entropy_delta_threshold_desc")}
              isDefault={isDefault("fish.entropy_delta_threshold")}
              onReset={() => resetField("fish.entropy_delta_threshold")}
              control={
                <NumberInput
                  value={Math.round(
                    draft.fish.entropy_delta_threshold * 100,
                  )}
                  onChange={(v) =>
                    updatePath("fish.entropy_delta_threshold", v / 100)
                  }
                  min={0}
                  max={100}
                  step={1}
                  suffix="%"
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_slow_burn_window_secs")}
              description={i18n.t("settings.fish_slow_burn_window_secs_desc")}
              isDefault={isDefault("fish.slow_burn_window_secs")}
              onReset={() => resetField("fish.slow_burn_window_secs")}
              control={
                <NumberInput
                  value={draft.fish.slow_burn_window_secs}
                  onChange={(v) =>
                    updatePath("fish.slow_burn_window_secs", v)
                  }
                  min={60}
                  max={86400}
                  step={60}
                  suffix="s"
                  width="w-28"
                />
              }
            />
            <SettingRow
              label={i18n.t("settings.fish_slow_burn_threshold")}
              description={i18n.t("settings.fish_slow_burn_threshold_desc")}
              isDefault={isDefault("fish.slow_burn_threshold")}
              onReset={() => resetField("fish.slow_burn_threshold")}
              control={
                <NumberInput
                  value={draft.fish.slow_burn_threshold}
                  onChange={(v) =>
                    updatePath("fish.slow_burn_threshold", v)
                  }
                  min={1}
                  max={10000}
                  step={10}
                />
              }
            />
          </div>
        )}
      </section>
    </div>
  );
}

// Sandbox tab — behavioural detonation (experimental).
//
// Guarded with an experimental banner and a checkbox the user must
// tick before any of the fields are editable. The toggle gate flips
// it back to disabled if the box is unticked again.

import { useState } from "react";
import { AlertTriangle, FlaskConical, Gauge } from "lucide-react";
import * as i18n from "../../../i18n";
import {
  NumberInput,
  SelectInput,
  Section,
  SettingRow,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function SandboxTab({ ctx }: { ctx: UseFullConfigResult }) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  const [acknowledged, setAcknowledged] = useState(false);
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];

  // Once sandbox is already enabled in the saved config, no need to
  // re-acknowledge — the user clearly understood the implications
  // when they enabled it.
  const gateLocked = !acknowledged && !draft.sandbox.enabled;

  const modeOpts: Array<{ value: string; label: string }> = [
    { value: "experimental", label: "experimental" },
    { value: "production", label: "production" },
  ];

  return (
    <div>
      {/* ── Experimental banner ────────────────────── */}
      <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-sm">
        <div className="flex items-center gap-2 mb-2 text-amber-300">
          <AlertTriangle className="w-4 h-4" />
          <strong>{i18n.t("settings.sandbox_experimental_title")}</strong>
        </div>
        <p className="text-xs text-[rgb(var(--muted))] leading-relaxed mb-2">
          {i18n.t("settings.sandbox_experimental_desc")}
        </p>
        {!draft.sandbox.enabled && (
          <label className="flex items-center gap-2 text-xs cursor-pointer mt-2">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="accent-amber-500"
            />
            {i18n.t("settings.sandbox_ack")}
          </label>
        )}
      </div>

      <Section
        icon={<FlaskConical className="w-5 h-5" />}
        title={i18n.t("settings.section_sandbox")}
        subtitle={i18n.t("settings.section_sandbox_desc")}
        experimental
      >
        <SettingRow
          label={i18n.t("settings.sandbox_enabled")}
          description={i18n.t("settings.sandbox_enabled_desc")}
          restartRequirement={rr("sandbox.enabled")}
          isDefault={isDefault("sandbox.enabled")}
          onReset={() => resetField("sandbox.enabled")}
          control={
            <Toggle
              checked={draft.sandbox.enabled}
              onChange={(v) => updatePath("sandbox.enabled", v)}
              disabled={gateLocked}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.sandbox_mode")}
          description={i18n.t("settings.sandbox_mode_desc")}
          isDefault={isDefault("sandbox.mode")}
          onReset={() => resetField("sandbox.mode")}
          control={
            <SelectInput<string>
              value={draft.sandbox.mode}
              onChange={(v) => updatePath("sandbox.mode", v)}
              options={modeOpts}
              disabled={!draft.sandbox.enabled || gateLocked}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.sandbox_timeout_sec")}
          description={i18n.t("settings.sandbox_timeout_sec_desc")}
          isDefault={isDefault("sandbox.timeout_sec")}
          onReset={() => resetField("sandbox.timeout_sec")}
          control={
            <NumberInput
              value={draft.sandbox.timeout_sec}
              onChange={(v) => updatePath("sandbox.timeout_sec", v)}
              min={1}
              max={600}
              step={1}
              suffix="s"
              disabled={!draft.sandbox.enabled || gateLocked}
            />
          }
        />
      </Section>

      <Section
        icon={<Gauge className="w-5 h-5" />}
        title={i18n.t("settings.section_sandbox_scoring")}
        subtitle={i18n.t("settings.section_sandbox_scoring_desc")}
      >
        <SettingRow
          label={i18n.t("settings.sandbox_min_score")}
          description={i18n.t("settings.sandbox_min_score_desc")}
          isDefault={isDefault("sandbox.min_score")}
          onReset={() => resetField("sandbox.min_score")}
          control={
            <NumberInput
              value={draft.sandbox.min_score}
              onChange={(v) => updatePath("sandbox.min_score", v)}
              min={0}
              max={100}
              step={1}
              disabled={!draft.sandbox.enabled || gateLocked}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.sandbox_max_score")}
          description={i18n.t("settings.sandbox_max_score_desc")}
          isDefault={isDefault("sandbox.max_score")}
          onReset={() => resetField("sandbox.max_score")}
          warning={
            draft.sandbox.max_score <= draft.sandbox.min_score
              ? i18n.t("settings.sandbox_max_must_exceed_min")
              : undefined
          }
          control={
            <NumberInput
              value={draft.sandbox.max_score}
              onChange={(v) => updatePath("sandbox.max_score", v)}
              min={1}
              max={100}
              step={1}
              disabled={!draft.sandbox.enabled || gateLocked}
            />
          }
        />
      </Section>
    </div>
  );
}

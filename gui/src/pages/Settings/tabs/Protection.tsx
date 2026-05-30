// Protection tab — first tab of the v0.1.8 Settings page.
//
// Fields shown here (CRITICAL = lock icon + UAC required):
//   - realtime_enabled            🔒  Real-time protection master toggle
//   - realtime_roots              🔒  Watched directories (chip list + picker)
//   - max_file_size_mb                Largest file the scanner inspects
//   - scan_archives                   Recurse into ZIP/7z/RAR/etc
//   - heuristic_alerts            🔒  Surface ARGUS/heuristic verdicts
//   - auto_quarantine             🔒  Move detected files to quarantine
//   - excluded_paths              🔒  Skip these paths entirely
//   - excluded_extensions         🔒  Skip files with these extensions
//   - excluded_detections         🔒  Detection-name whitelist
//   - trusted_hashes              🔒  SHA-256 manual whitelist
//
// All critical fields are gated client-side too: the controls are
// disabled when the GUI is not elevated, and the elevation banner at
// the top of the tab explains why with a one-click "Restart as Admin".

import { FileSearch, Shield, ShieldOff } from "lucide-react";
import * as i18n from "../../../i18n";
import {
  ElevationBanner,
  ListEditor,
  Section,
  SettingRow,
  Slider,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function ProtectionTab({
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

  const rr = (path: string) => restartReqs.fields[path];
  const critDisabled = !isElevated; // kill-vector fields require admin

  return (
    <div>
      {!isElevated && <ElevationBanner onRestartAsAdmin={onRestartAsAdmin} />}

      {/* ── Real-time protection ───────────────────── */}
      <Section
        icon={<Shield className="w-5 h-5" />}
        title={i18n.t("settings.section_realtime")}
        subtitle={i18n.t("settings.section_realtime_desc")}
      >
        <SettingRow
          label={i18n.t("settings.realtime_enabled")}
          description={i18n.t("settings.realtime_enabled_desc")}
          locked
          restartRequirement={rr("realtime_enabled")}
          isDefault={isDefault("realtime_enabled")}
          onReset={() => resetField("realtime_enabled")}
          control={
            <Toggle
              checked={draft.realtime_enabled}
              onChange={(v) => updatePath("realtime_enabled", v)}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.realtime_roots")}
          description={i18n.t("settings.realtime_roots_desc")}
          locked
          restartRequirement={rr("realtime_roots")}
          isDefault={isDefault("realtime_roots")}
          onReset={() => resetField("realtime_roots")}
          control={
            <ListEditor
              items={draft.realtime_roots}
              onChange={(v) => updatePath("realtime_roots", v)}
              placeholder={i18n.t("settings.add_watched_root")}
              withPathPicker
              pathPickerOptions={{ directory: true, multiple: true }}
              validator={(v) => {
                if (v.length > 4096) return i18n.t("settings.path_too_long");
                const lower = v.trim().toLowerCase().replace(/\\$/, "");
                if (
                  lower === "" ||
                  lower === "c:" ||
                  lower === "c:/" ||
                  lower === "/" ||
                  lower === "\\" ||
                  lower === "c:\\windows" ||
                  lower === "c:\\windows\\system32" ||
                  lower === "c:\\program files" ||
                  lower === "c:\\program files (x86)" ||
                  lower.includes("..")
                ) {
                  return i18n.t("settings.path_too_broad");
                }
                return null;
              }}
              disabled={critDisabled}
            />
          }
        />
      </Section>

      {/* ── Scanning behavior ─────────────────────── */}
      <Section
        icon={<FileSearch className="w-5 h-5" />}
        title={i18n.t("settings.section_scanning")}
        subtitle={i18n.t("settings.section_scanning_desc")}
      >
        <SettingRow
          label={i18n.t("settings.max_file_size_mb")}
          description={i18n.t("settings.max_file_size_mb_desc")}
          restartRequirement={rr("max_file_size_mb")}
          isDefault={isDefault("max_file_size_mb")}
          onReset={() => resetField("max_file_size_mb")}
          control={
            <Slider
              value={draft.max_file_size_mb}
              onChange={(v) => updatePath("max_file_size_mb", v)}
              min={16}
              max={4096}
              step={16}
              suffix="MB"
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.scan_archives")}
          description={i18n.t("settings.scan_archives_desc")}
          restartRequirement={rr("scan_archives")}
          isDefault={isDefault("scan_archives")}
          onReset={() => resetField("scan_archives")}
          control={
            <Toggle
              checked={draft.scan_archives}
              onChange={(v) => updatePath("scan_archives", v)}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.heuristic_alerts")}
          description={i18n.t("settings.heuristic_alerts_desc")}
          locked
          restartRequirement={rr("heuristic_alerts")}
          isDefault={isDefault("heuristic_alerts")}
          onReset={() => resetField("heuristic_alerts")}
          control={
            <Toggle
              checked={draft.heuristic_alerts}
              onChange={(v) => updatePath("heuristic_alerts", v)}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.auto_quarantine")}
          description={i18n.t("settings.auto_quarantine_desc")}
          locked
          isDefault={isDefault("auto_quarantine")}
          onReset={() => resetField("auto_quarantine")}
          control={
            <Toggle
              checked={draft.auto_quarantine}
              onChange={(v) => updatePath("auto_quarantine", v)}
              disabled={critDisabled}
            />
          }
        />
      </Section>

      {/* ── Exclusions ─────────────────────────────── */}
      <Section
        icon={<ShieldOff className="w-5 h-5" />}
        title={i18n.t("settings.section_exclusions")}
        subtitle={i18n.t("settings.section_exclusions_desc")}
      >
        <SettingRow
          label={i18n.t("settings.excluded_paths")}
          description={i18n.t("settings.excluded_paths_desc")}
          locked
          restartRequirement={rr("excluded_paths")}
          isDefault={isDefault("excluded_paths")}
          onReset={() => resetField("excluded_paths")}
          warning={
            draft.excluded_paths.length > 0
              ? i18n.t("settings.exclusion_warning")
              : undefined
          }
          control={
            <ListEditor
              items={draft.excluded_paths}
              onChange={(v) => updatePath("excluded_paths", v)}
              placeholder={i18n.t("settings.add_excluded_path")}
              withPathPicker
              pathPickerOptions={{ directory: false, multiple: false }}
              validator={(v) => {
                const lower = v.trim().toLowerCase().replace(/\\$/, "");
                if (
                  lower === "" ||
                  lower === "c:" ||
                  lower === "c:\\windows" ||
                  lower === "c:\\program files" ||
                  lower.includes("..")
                ) {
                  return i18n.t("settings.exclusion_too_broad");
                }
                return null;
              }}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.excluded_extensions")}
          description={i18n.t("settings.excluded_extensions_desc")}
          locked
          isDefault={isDefault("excluded_extensions")}
          onReset={() => resetField("excluded_extensions")}
          control={
            <ListEditor
              items={draft.excluded_extensions}
              onChange={(v) => updatePath("excluded_extensions", v)}
              placeholder={i18n.t("settings.add_excluded_ext")}
              validator={(v) => {
                const t = v.trim().replace(/^\./, "");
                if (!t) return i18n.t("settings.empty_entry");
                if (t.length > 16) return i18n.t("settings.ext_too_long");
                if (!/^[A-Za-z0-9]+$/.test(t))
                  return i18n.t("settings.ext_must_be_alnum");
                return null;
              }}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.excluded_detections")}
          description={i18n.t("settings.excluded_detections_desc")}
          locked
          isDefault={isDefault("excluded_detections")}
          onReset={() => resetField("excluded_detections")}
          warning={i18n.t("settings.detection_exclusion_warning")}
          control={
            <ListEditor
              items={draft.excluded_detections}
              onChange={(v) => updatePath("excluded_detections", v)}
              placeholder={i18n.t("settings.add_excluded_detection")}
              validator={(v) => {
                if (!v.trim()) return i18n.t("settings.empty_entry");
                if (v.length > 256) return i18n.t("settings.entry_too_long");
                return null;
              }}
              disabled={critDisabled}
            />
          }
        />
        <SettingRow
          label={i18n.t("settings.trusted_hashes")}
          description={i18n.t("settings.trusted_hashes_desc")}
          locked
          isDefault={isDefault("trusted_hashes")}
          onReset={() => resetField("trusted_hashes")}
          warning={
            draft.trusted_hashes.length > 0
              ? i18n.t("settings.trusted_hash_warning")
              : undefined
          }
          control={
            <ListEditor
              items={draft.trusted_hashes}
              onChange={(v) => updatePath("trusted_hashes", v)}
              placeholder={i18n.t("settings.add_trusted_hash")}
              validator={(v) => {
                const t = v.trim().toLowerCase();
                if (!/^[0-9a-f]{64}$/.test(t))
                  return i18n.t("settings.hash_invalid");
                return null;
              }}
              disabled={critDisabled}
            />
          }
        />
      </Section>
    </div>
  );
}

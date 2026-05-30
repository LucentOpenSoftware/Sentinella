// Advanced tab — logging, quarantine retention, protection shutdown,
// developer mode (password-gated, local-only perf telemetry).
//
// `Developer mode` section is hidden entirely until the daemon
// reports that a password hash has been provisioned out-of-band.
// Same gate as the legacy DeveloperSection.

import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  AlertTriangle,
  Archive,
  Bug,
  FileText,
  Loader2,
  Terminal,
  Wrench,
} from "lucide-react";
import * as i18n from "../../../i18n";
import {
  getDeveloperStatus,
  runBenchmark,
  setDeveloperMode,
  type BenchmarkReport,
  type DeveloperStatus,
} from "../../../api/sentinella";
import {
  SelectInput,
  Section,
  SettingRow,
  Toggle,
} from "../components/widgets";
import type { UseFullConfigResult } from "../hooks/useFullConfig";

export function AdvancedTab({ ctx }: { ctx: UseFullConfigResult }) {
  const { draft, restartReqs, updatePath, resetField, isDefault } = ctx;
  if (!draft || !restartReqs) return null;
  const rr = (p: string) => restartReqs.fields[p];

  const logLevelOpts = [
    { value: "error", label: i18n.t("settings.log_error") },
    { value: "warn", label: i18n.t("settings.log_warn") },
    { value: "info", label: i18n.t("settings.log_info") },
    { value: "debug", label: i18n.t("settings.log_debug") },
    { value: "trace", label: i18n.t("settings.log_trace") },
  ];

  const retentionOpts = [30, 60, 90, 180, 365].map((d) => ({
    value: String(d),
    label: `${d} ${i18n.t("settings.days_unit")}`,
  }));

  return (
    <div>
      {/* ── Logging ────────────────────────────────── */}
      <Section
        icon={<FileText />}
        title={i18n.t("settings.logging")}
        subtitle={i18n.t("settings.logging_desc")}
      >
        <SettingRow
          label={i18n.t("settings.log_level")}
          description={i18n.t("settings.log_level_desc")}
          restartRequirement={rr("log_level")}
          isDefault={isDefault("log_level")}
          onReset={() => resetField("log_level")}
          control={
            <SelectInput<string>
              value={draft.log_level}
              onChange={(v) => updatePath("log_level", v)}
              options={logLevelOpts}
            />
          }
        />
      </Section>

      {/* ── Quarantine retention ───────────────────── */}
      <Section
        icon={<Archive />}
        title={i18n.t("settings.quarantine_retention")}
        subtitle={i18n.t("settings.quarantine_retention_desc")}
      >
        <SettingRow
          label={i18n.t("settings.retention_period")}
          description={i18n.t("settings.retention_period_desc")}
          isDefault={isDefault("quarantine_retention_days")}
          onReset={() => resetField("quarantine_retention_days")}
          control={
            <SelectInput<string>
              value={String(draft.quarantine_retention_days)}
              onChange={(v) =>
                updatePath("quarantine_retention_days", parseInt(v, 10))
              }
              options={retentionOpts}
            />
          }
        />
      </Section>

      {/* ── Protection shutdown (guarded) ──────────── */}
      <Section
        icon={<AlertTriangle />}
        title={i18n.t("settings.protection_control")}
        subtitle={i18n.t("settings.protection_control_desc")}
      >
        <ProtectionShutdownBlock />
      </Section>

      {/* ── Developer mode (provisioned only) ──────── */}
      <DeveloperSection />
    </div>
  );
}

// ─── Protection shutdown — type-to-confirm ──────────────────────

function ProtectionShutdownBlock() {
  const [showShutdown, setShowShutdown] = useState(false);
  const [shutdownPhrase, setShutdownPhrase] = useState("");
  const [shutdownError, setShutdownError] = useState("");

  if (!showShutdown) {
    return (
      <button
        onClick={() => setShowShutdown(true)}
        className="flex items-center gap-2 text-xs text-red-400/70 hover:text-red-400 transition-colors"
      >
        <AlertTriangle className="w-3.5 h-3.5" />
        {i18n.t("settings.disable_protection")}
      </button>
    );
  }

  return (
    <div className="rounded-md border border-red-500/20 bg-red-500/5 p-3">
      <div className="flex items-start gap-2 mb-3">
        <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-red-400">
            {i18n.t("settings.disable_all_protection")}
          </p>
          <p className="text-xs text-[rgb(var(--muted))] mt-1 leading-snug">
            {i18n.t("settings.shutdown_warning")}
          </p>
        </div>
      </div>
      <p className="text-[11px] text-[rgb(var(--muted))] mb-2">
        {i18n.t("settings.type_to_confirm").replace("{phrase}", "")}
        <strong className="text-red-400 font-mono">DISABLE PROTECTION</strong>
      </p>
      <input
        type="text"
        value={shutdownPhrase}
        onChange={(e) => {
          setShutdownPhrase(e.target.value);
          setShutdownError("");
        }}
        placeholder={i18n.t("settings.confirmation_placeholder")}
        className="w-full rounded border border-red-500/30 bg-[rgb(var(--surface))]/80 px-2 py-1.5 text-xs font-mono outline-none focus:border-red-400 mb-2"
        autoComplete="off"
        spellCheck={false}
      />
      {shutdownError && (
        <p className="text-[11px] text-red-400 mb-2">{shutdownError}</p>
      )}
      <div className="flex gap-2">
        <button
          onClick={async () => {
            if (shutdownPhrase !== "DISABLE PROTECTION") {
              setShutdownError(i18n.t("settings.incorrect_phrase"));
              return;
            }
            try {
              const result = await invoke<{
                requires_elevation?: boolean;
                error?: string;
              }>("confirmed_shutdown", {
                confirmation: shutdownPhrase,
              });
              if (result?.requires_elevation) {
                setShutdownError(
                  result.error ?? i18n.t("settings.requires_admin"),
                );
              }
            } catch (e) {
              setShutdownError(String(e));
            }
          }}
          disabled={shutdownPhrase.length < 5}
          className="px-3 py-1.5 rounded bg-red-500 text-white text-xs font-semibold hover:opacity-90 disabled:opacity-30"
        >
          {i18n.t("settings.confirm_shutdown")}
        </button>
        <button
          onClick={() => {
            setShowShutdown(false);
            setShutdownPhrase("");
            setShutdownError("");
          }}
          className="px-3 py-1.5 rounded bg-[rgb(var(--surface))]/60 text-xs text-[rgb(var(--muted))]"
        >
          {i18n.t("common.cancel")}
        </button>
      </div>
    </div>
  );
}

// ─── Developer section (hidden unless provisioned) ──────────────

function DeveloperSection() {
  const [status, setStatus] = useState<DeveloperStatus | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [benchBusy, setBenchBusy] = useState(false);
  const [bench, setBench] = useState<BenchmarkReport | null>(null);
  const [benchError, setBenchError] = useState("");

  const refresh = async () => {
    try {
      setStatus(await getDeveloperStatus());
    } catch {
      // daemon may be offline
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const toggle = async (enabled: boolean, telemetry?: boolean) => {
    if (password.length === 0) {
      setError(i18n.t("settings.dev_password_required"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await setDeveloperMode(password, enabled, telemetry);
      if (res?.error) {
        setError(res.error);
      } else {
        setPassword("");
        await refresh();
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const doBenchmark = async () => {
    setBenchBusy(true);
    setBenchError("");
    setBench(null);
    try {
      const r = await runBenchmark(3);
      if (r?.error) {
        setBenchError(r.error);
      } else {
        setBench(r);
        await refresh();
      }
    } catch (e) {
      setBenchError(String(e));
    } finally {
      setBenchBusy(false);
    }
  };

  // Hidden until provisioned out-of-band.
  if (!status || !status.provisioned) return null;

  return (
    <Section
      icon={<Wrench />}
      title={i18n.t("settings.developer_mode")}
      subtitle={i18n.t("settings.developer_mode_desc")}
    >
      <div className="flex items-center gap-2 mb-2">
        <Terminal className="w-3.5 h-3.5 text-[rgb(var(--muted))]" />
        <span
          className={`text-[11px] font-semibold px-2 py-0.5 rounded ${
            status.enabled
              ? "bg-emerald-500/15 text-emerald-400"
              : "bg-[rgb(var(--surface))]/60 text-[rgb(var(--muted))]"
          }`}
        >
          {status.enabled ? i18n.t("settings.dev_on") : i18n.t("settings.dev_off")}
        </span>
      </div>

      <input
        type="password"
        value={password}
        onChange={(e) => {
          setPassword(e.target.value);
          setError("");
        }}
        placeholder={i18n.t("settings.dev_password_placeholder")}
        className="w-full rounded border border-[rgb(var(--border))]/40 bg-[rgb(var(--surface))]/80 px-2 py-1.5 text-xs outline-none focus:border-[rgb(var(--accent))] mb-2"
        autoComplete="off"
        spellCheck={false}
      />
      {error && <p className="text-[11px] text-red-400 mb-2">{error}</p>}

      <div className="flex gap-2 mb-2">
        {!status.enabled ? (
          <button
            onClick={() => toggle(true)}
            disabled={busy || password.length === 0}
            className="px-3 py-1.5 rounded bg-[rgb(var(--accent))] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-30"
          >
            {i18n.t("settings.dev_enable")}
          </button>
        ) : (
          <button
            onClick={() => toggle(false)}
            disabled={busy || password.length === 0}
            className="px-3 py-1.5 rounded bg-[rgb(var(--surface))]/60 text-xs text-[rgb(var(--muted))] disabled:opacity-30"
          >
            {i18n.t("settings.dev_disable")}
          </button>
        )}
      </div>

      {status.enabled && (
        <div className="border-t border-[rgb(var(--border))]/15 pt-2 mt-2">
          <SettingRow
            label={i18n.t("settings.dev_telemetry")}
            description={i18n.t("settings.dev_telemetry_desc")}
            control={
              <Toggle
                checked={status.telemetry_enabled}
                onChange={(v) => toggle(true, v)}
              />
            }
          />
          <div className="text-[11px] text-[rgb(var(--muted))] mt-2 space-y-1">
            <div className="flex justify-between gap-2">
              <span>{i18n.t("settings.dev_dump_path")}</span>
              <span className="font-mono truncate max-w-[60%]" title={status.dump_path}>
                {status.dump_path}
              </span>
            </div>
            <div className="flex justify-between gap-2">
              <span>{i18n.t("settings.dev_dump_size")}</span>
              <span className="font-mono">
                {status.dump_size_kb} / {status.telemetry_max_kb} KB
              </span>
            </div>
          </div>

          {/* Benchmark trigger */}
          <div className="mt-3 border-t border-[rgb(var(--border))]/15 pt-2">
            <div className="flex items-center justify-between gap-3 mb-2">
              <div>
                <p className="text-sm font-medium">
                  {i18n.t("settings.dev_benchmark")}
                </p>
                <p className="text-[11px] text-[rgb(var(--muted))] mt-0.5">
                  {i18n.t("settings.dev_benchmark_desc")}
                </p>
              </div>
              <button
                onClick={doBenchmark}
                disabled={benchBusy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[rgb(var(--accent))] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40"
              >
                {benchBusy && <Loader2 className="w-3 h-3 animate-spin" />}
                <Bug className="w-3 h-3" />
                {benchBusy
                  ? i18n.t("settings.dev_benchmark_running")
                  : i18n.t("settings.dev_benchmark_run")}
              </button>
            </div>
            {benchError && (
              <p className="text-[11px] text-red-400">{benchError}</p>
            )}
            {bench && (
              <div className="rounded bg-[rgb(var(--surface))]/40 p-2 text-[11px] space-y-1">
                <div className="flex justify-between gap-2">
                  <span>{i18n.t("settings.dev_bench_index")}</span>
                  <span className="font-mono">
                    {bench.performance_index ?? "—"}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span>{i18n.t("settings.dev_bench_throughput")}</span>
                  <span className="font-mono">
                    {(bench.files_per_sec ?? 0).toFixed(1)} files/s ·{" "}
                    {(bench.mb_per_sec ?? 0).toFixed(1)} MB/s
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span>{i18n.t("settings.dev_bench_latency")}</span>
                  <span className="font-mono">
                    p50 {bench.per_file_us?.p50 ?? 0}µs · p95{" "}
                    {bench.per_file_us?.p95 ?? 0}µs
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span>{i18n.t("settings.dev_bench_system")}</span>
                  <span className="font-mono">
                    {bench.system?.logical_cores ?? 0} cores ·{" "}
                    {(bench.system?.simd ?? []).join(",") || "—"}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </Section>
  );
}

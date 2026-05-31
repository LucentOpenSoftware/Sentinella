import { useState, useEffect, useCallback, useRef } from "react";
import {
  CheckCircle,
  Clock,
  Database,
  Download,
  Globe,
  Loader2,
  RefreshCw,
  Shield,
  XCircle,
} from "lucide-react";
import { Card } from "../components/Card";
import { AppUpdater } from "../components/AppUpdater";
import { useDaemonContext } from "../hooks/DaemonContext";
import { startSignatureUpdate, getUpdateStatus, getArgusPacks, reloadArgus } from "../api/sentinella";
import type { ArgusPackInfo } from "../types/sentinella";
import type { UpdateStatus } from "../types/sentinella";
import { t } from "../i18n";

export function UpdatePage() {
  const { data, connected } = useDaemonContext();
  const [updating, setUpdating] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [lastResult, setLastResult] = useState<{ ok: boolean; message: string } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Poll update status while an update is running.
  const pollStatus = useCallback(async () => {
    try {
      const status = await getUpdateStatus();
      setUpdateStatus(status);

      // Update finished (state returned to idle or error).
      if (status.state === "idle" || status.state === "error") {
        setUpdating(false);
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
        if (status.state === "error" && status.last_error) {
          setLastResult({ ok: false, message: status.last_error });
        } else if (status.state === "idle" && updating) {
          // Went from running -> idle = success.
          setLastResult({ ok: true, message: t("update.success") });
        }
      }
    } catch {
      // Ignore polling failures.
    }
  }, [updating]);

  // Start polling when update begins.
  useEffect(() => {
    if (updating && !pollRef.current) {
      pollRef.current = setInterval(pollStatus, 1500);
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [updating, pollStatus]);

  // Check initial update status on mount.
  useEffect(() => {
    getUpdateStatus()
      .then((s) => {
        setUpdateStatus(s);
        if (s.state === "downloading" || s.state === "checking" || s.state === "applying") {
          setUpdating(true);
        }
      })
      .catch(() => {});
  }, []);

  const handleUpdate = async () => {
    setLastResult(null);
    setUpdating(true);
    try {
      await startSignatureUpdate();
    } catch (e) {
      setUpdating(false);
      setLastResult({ ok: false, message: String(e) });
    }
  };

  const engine = data?.engine;
  const stats = data?.stats;
  const sigCount = engine?.signature_count ?? 0;
  const dbVersion = engine?.db_version ? `v${engine.db_version}` : t("update.na");
  const engineVersion = engine?.engine_version ?? t("common.unknown");
  const lastUpdate = stats?.last_update_timestamp
    ? new Date(stats.last_update_timestamp * 1000).toLocaleString()
    : engine?.last_update
      ? new Date(engine.last_update * 1000).toLocaleString()
      : t("common.never");
  const dbTimestamp = engine?.db_timestamp
    ? new Date(engine.db_timestamp * 1000).toLocaleString()
    : null;
  const isStale = stats?.db_stale ?? false;
  const staleHours = stats?.db_stale_hours ?? 0;

  const statusLabel =
    updateStatus?.state === "downloading" || updateStatus?.state === "checking"
      ? t("update.updating")
      : updateStatus?.state === "applying"
        ? t("update.applying")
        : updating
          ? t("update.updating")
          : isStale
            ? t("update.available")
            : t("update.status_up_to_date");

  const statusColor = updating
    ? "accent"
    : isStale
      ? "amber"
      : "green";

  return (
    <div className="page-stack">
      {/* Hero status card */}
      <Card className={`border-[rgb(var(--${statusColor}))]/12`}>
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.7fr)_280px] xl:items-start">
          <div className="flex items-start gap-5">
            <div
              className={`flex h-16 w-16 flex-shrink-0 items-center justify-center rounded ${
                updating
                  ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]"
                  : isStale
                    ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]"
                    : "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
              }`}
            >
              {updating ? (
                <Loader2 size={28} className="animate-spin" />
              ) : isStale ? (
                <Download size={28} />
              ) : (
                <CheckCircle size={28} />
              )}
            </div>
            <div className="flex min-w-0 flex-col gap-3">
              <h3 className="text-[24px] font-bold leading-tight">
                {updating ? t("update.hero_updating") : isStale ? t("update.hero_available") : t("update.hero_up_to_date")}
              </h3>
              <p className="max-w-2xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                {updating
                  ? t("update.desc_updating")
                  : isStale && staleHours > 0
                    ? t("update.desc_stale").replace("{hours}", String(staleHours))
                    : sigCount > 0
                      ? t("update.desc_active").replace("{count}", sigCount.toLocaleString())
                      : t("update.desc_empty")}
              </p>

              {/* Progress bar + current file */}
              {updating && updateStatus && (
                <div className="space-y-2">
                  {/* Progress bar */}
                  <div className="w-full h-2 bg-[rgb(var(--raised))]/40 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[rgb(var(--accent))] rounded-full transition-all duration-500 ease-out"
                      style={{ width: `${updateStatus.percent ?? 0}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="text-[11px] text-[rgb(var(--t3))]">
                      {updateStatus.current_file
                        ? t("update.downloading").replace("{file}", updateStatus.current_file)
                        : updateStatus.state === "checking"
                          ? t("update.checking")
                          : updateStatus.state === "applying"
                            ? t("update.applying_updates")
                            : t("update.processing")}
                    </p>
                    <p className="text-[11px] font-semibold text-[rgb(var(--accent))]">
                      {Math.round(updateStatus.percent ?? 0)}%
                    </p>
                  </div>
                </div>
              )}

              {/* Result banner */}
              {lastResult && !updating && (
                <div
                  className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-[12px] ${
                    lastResult.ok
                      ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
                      : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                  }`}
                >
                  {lastResult.ok ? <CheckCircle size={14} /> : <XCircle size={14} />}
                  <span>{lastResult.message}</span>
                </div>
              )}
            </div>
          </div>

          {/* Update button */}
          <div className="flex flex-col gap-4">
            <button
              onClick={handleUpdate}
              disabled={updating || !connected}
              className={`flex items-center justify-center gap-2.5 rounded-xl px-6 py-3.5 text-[13px] font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
                updating
                  ? "bg-[rgb(var(--raised))]/40 text-[rgb(var(--t2))]"
                  : "bg-[rgb(var(--accent))] text-white shadow-[rgb(var(--accent))]/15 hover:opacity-90"
              }`}
            >
              {updating ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <RefreshCw size={16} />
              )}
              {updating ? t("update.updating") : t("update.check")}
            </button>
            {!connected && (
              <p className="text-center text-[11px] text-[rgb(var(--amber))]">
                {t("update.daemon_not_connected")}
              </p>
            )}
          </div>
        </div>
      </Card>

      {/* Database info tiles */}
      <div className="card-grid-4">
        <InfoTile
          icon={<Database size={18} />}
          label={t("update.db_version")}
          value={dbVersion}
          sub={dbTimestamp ? t("update.build_date").replace("{date}", dbTimestamp) : t("update.build_date_unknown")}
          color="accent"
        />
        <InfoTile
          icon={<Shield size={18} />}
          label={t("update.signatures_label")}
          value={sigCount > 0 ? sigCount.toLocaleString() : "0"}
          sub={t("update.signatures_sub")}
          color={sigCount > 0 ? "green" : "amber"}
        />
        <InfoTile
          icon={<Clock size={18} />}
          label={t("update.last_updated")}
          value={lastUpdate === t("common.never") ? t("common.never") : new Date(
            stats?.last_update_timestamp
              ? stats.last_update_timestamp * 1000
              : engine?.last_update
                ? engine.last_update * 1000
                : 0
          ).toLocaleDateString()}
          sub={lastUpdate === t("common.never") ? t("update.no_updates_performed") : lastUpdate}
          color={isStale ? "amber" : "accent"}
        />
        <InfoTile
          icon={<Globe size={18} />}
          label={t("update.engine")}
          value={engineVersion}
          sub={t("update.engine_version_sub")}
          color="accent"
        />
      </div>

      {/* Update details + ARGUS packs — side by side */}
      <div className="card-grid-2">
        <Card>
          <h4 className="text-[14px] font-semibold">{t("update.details_title")}</h4>
          <p className="mb-4 mt-1 text-[11px] text-[rgb(var(--t3))]">
            {t("update.details_desc")}
          </p>
          <div className="space-y-0">
            <DetailRow label={t("update.update_source")} value={t("update.source_full")} />
            <DetailRow label={t("update.database_format")} value={t("update.format_value")} />
            <DetailRow label={t("update.engine_version_label")} value={engineVersion} />
            <DetailRow label={t("update.signatures_loaded")} value={sigCount > 0 ? sigCount.toLocaleString() : t("update.none")} />
            <DetailRow label={t("update.last_successful_update")} value={lastUpdate} />
            <DetailRow
              label={t("update.db_status")}
              value={statusLabel}
              valueColor={updating ? "accent" : isStale ? "amber" : "green"}
            />
            <DetailRow label={t("update.tool")} value={t("update.tool_value")} />
          </div>
        </Card>

        <ArgusPacksSection />
      </div>

      {/* v0.1.9: Sentinella app updates (Tauri updater for the GUI +
          shipped daemon binaries). Distinct from the signature updates
          above. Moved here from About so all "anything that updates"
          lives in one page. */}
      <div className="px-1">
        <h4 className="text-[13px] font-medium text-[rgb(var(--t3))] mb-2">
          {t("update.section_app_updates")}
        </h4>
        <AppUpdater />
      </div>

      {/* How updates work */}
      <Card>
        <h4 className="text-[15px] font-semibold">{t("update.how_updates_work")}</h4>
        <p className="mb-5 mt-1 text-[12px] text-[rgb(var(--t3))]">
          {t("update.how_updates_desc")}
        </p>

        <div className="grid gap-4 sm:grid-cols-3">
          <StepCard
            step="1"
            icon={<Download size={16} />}
            title={t("update.step_download")}
            desc={t("update.step_download_desc_full")}
          />
          <StepCard
            step="2"
            icon={<Database size={16} />}
            title={t("update.step_verify")}
            desc={t("update.step_verify_desc_full")}
          />
          <StepCard
            step="3"
            icon={<RefreshCw size={16} />}
            title={t("update.step_reload")}
            desc={t("update.step_reload_desc_full")}
          />
        </div>
      </Card>
    </div>
  );
}

const PACK_CATEGORY_COLORS: Record<string, string> = {
  credential_theft: "var(--red)",
  script_abuse: "var(--amber)",
  deception: "var(--amber)",
  github_stealer: "var(--red)",
  lolbin: "var(--amber)",
  document: "var(--amber)",
  persistence: "var(--red)",
};

function ArgusPacksSection() {
  // v0.1.9 audit MED-10 fix: this section was the root cause of the
  // long-standing "0 reglas conductuales en 0 paquetes" cosmetic bug.
  //
  // Daemon-side is fine — argus.packs returns a populated manifest list
  // (verified by raw named-pipe round-trip). GUI-side, the v0.1.7
  // version of this component did `useEffect(..., [])` with `.catch(() => {})`
  // — one-shot fetch on mount, errors swallowed, no refetch on
  // connectivity change. So when the section mounted during one of
  // the brief windows where the named-pipe call failed (daemon not
  // yet started, supervisor mid-respawn, transient PIPE_BUSY,
  // disconnect-debounce gap), packs stayed at [] forever and the
  // UI rendered the alarming-looking 0/0 indefinitely. The peer
  // tiles on the same page recovered because they come from the
  // continuously-polled DaemonContext.
  //
  // Fix: re-fetch on every disconnect→reconnect transition by keying
  // the effect on daemon.connected. The component now self-heals
  // without requiring the user to click "Reload rules" or navigate
  // away and back.
  const { connected } = useDaemonContext();
  const [packs, setPacks] = useState<ArgusPackInfo[]>([]);
  const [totalRules, setTotalRules] = useState(0);
  const [reloading, setReloading] = useState(false);
  const [reloadResult, setReloadResult] = useState<string | null>(null);

  useEffect(() => {
    if (!connected) return;
    let cancelled = false;
    getArgusPacks()
      .then((r) => {
        if (cancelled) return;
        setPacks(r.packs);
        setTotalRules(r.total_yara_rules);
      })
      .catch((e) => {
        // Keep the catch — transient failures during reconnect are
        // expected — but log so the same class of "silent 0/0" bug
        // stops hiding in future regressions.
        if (!cancelled) {
          console.warn("[ArgusPacksSection] getArgusPacks failed:", e);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [connected]);

  const handleReload = async () => {
    setReloading(true);
    setReloadResult(null);
    try {
      const r = await reloadArgus();
      setReloadResult(r.message);
      setTotalRules(r.yara_rules);
      // Refresh pack list.
      getArgusPacks().then((p) => setPacks(p.packs)).catch(() => {});
    } catch (e) {
      setReloadResult(String(e));
    } finally {
      setReloading(false);
    }
  };

  return (
    <Card>
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
            <Shield size={16} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h4 className="text-[15px] font-semibold">{t("update.argus_packs")}</h4>
            <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">
              {t("update.rules_across_packs").replace("{rules}", String(totalRules)).replace("{packs}", String(packs.length))}
            </p>
          </div>
        </div>
        <button onClick={handleReload} disabled={reloading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold text-[rgb(var(--accent))] border border-[rgb(var(--accent))]/15 hover:bg-[rgb(var(--accent))]/5 cursor-pointer disabled:opacity-40">
          {reloading ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
          {t("update.reload_rules")}
        </button>
      </div>

      {reloadResult && (
        <div className="flex items-center gap-2 mb-4 px-3 py-2 rounded-lg bg-[rgb(var(--green))]/8 text-[11px] text-[rgb(var(--green))]">
          <CheckCircle size={13} /> {reloadResult}
        </div>
      )}

      <div className="space-y-2">
        {packs.map((pack) => {
          const catColor = PACK_CATEGORY_COLORS[pack.category] ?? "var(--accent)";
          return (
            <div key={pack.name} className="flex items-center gap-3 rounded-xl bg-[rgb(var(--raised))]/12 px-4 py-3">
              <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg"
                style={{ background: `rgba(${catColor}, 0.08)`, color: `rgb(${catColor})` }}>
                <Shield size={14} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-semibold">{pack.display_name}</p>
                <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5 truncate">{pack.description}</p>
              </div>
              <div className="text-right flex-shrink-0">
                <p className="text-[12px] font-semibold">{pack.rule_count}</p>
                <p className="text-[9px] text-[rgb(var(--t3))]">{t("update.rules_label")}</p>
              </div>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))] flex-shrink-0">
                v{pack.version}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function InfoTile({
  icon,
  label,
  value,
  sub,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  color: "accent" | "green" | "amber" | "red";
}) {
  const palette = {
    accent: "var(--accent)",
    green: "var(--green)",
    amber: "var(--amber)",
    red: "var(--red)",
  }[color];

  return (
    <div className="glass-card flex flex-col gap-1.5 px-5 py-4 h-full">
      <div className="flex items-center gap-2.5">
        <div
          className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md"
          style={{ background: `rgba(${palette}, 0.08)`, color: `rgb(${palette})` }}
        >
          {icon}
        </div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: `rgba(${palette}, 0.65)` }}>
          {label}
        </p>
      </div>
      <p className="text-[20px] font-bold leading-tight text-[rgb(var(--t1))]">{value}</p>
      <p className="text-[11px] leading-snug text-[rgb(var(--t3))]">{sub}</p>
    </div>
  );
}

function DetailRow({
  label,
  value,
  valueColor,
}: {
  label: string;
  value: string;
  valueColor?: "accent" | "green" | "amber" | "red";
}) {
  const colorClass = valueColor
    ? `text-[rgb(var(--${valueColor}))]`
    : "text-[rgb(var(--t1))]";

  return (
    <div className="flex items-center justify-between border-b border-[rgb(var(--border))]/8 py-3 last:border-0">
      <span className="text-[13px] text-[rgb(var(--t3))]">{label}</span>
      <span className={`text-[13px] font-medium ${colorClass}`}>{value}</span>
    </div>
  );
}

function StepCard({
  step,
  icon,
  title,
  desc,
}: {
  step: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="rounded border border-[rgb(var(--border))]/10 bg-[rgb(var(--raised))]/15 p-5">
      <div className="mb-3 flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))] text-[12px] font-bold">
          {step}
        </div>
        <div className="flex items-center gap-2 text-[rgb(var(--t1))]">
          {icon}
          <span className="text-[13px] font-semibold">{title}</span>
        </div>
      </div>
      <p className="text-[11px] leading-relaxed text-[rgb(var(--t3))]">{desc}</p>
    </div>
  );
}

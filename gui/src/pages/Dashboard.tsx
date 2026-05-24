import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Archive,
  CheckCircle,
  Clock,
  Database,
  Eye,
  Loader2,
  RefreshCw,
  Search,
  ShieldOff,
  WifiOff,
  Zap,
} from "lucide-react";
import { useState, useEffect } from "react";
import { Card } from "../components/Card";
import { ShieldIcon } from "../components/ShieldIcon";
import { useDaemonContext } from "../hooks/DaemonContext";
import { startQuickScan, getRuntimeIntelligence } from "../api/sentinella";
import { t } from "../i18n";
import type { Page } from "../components/Sidebar";
import type { RuntimeIntelligenceStatus } from "../types/sentinella";

export function Dashboard({ onNavigate }: { onNavigate: (p: Page) => void }) {
  const { data, connected, loading, error, lastRefresh, refresh } = useDaemonContext();

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center py-32">
        <Loader2 size={24} className="mb-4 animate-spin text-[rgb(var(--accent))]" />
        <p className="text-[13px] text-[rgb(var(--t3))]">{t("dash.connecting")}</p>
      </div>
    );
  }

  if (!connected && !data) {
    return (
      <div className="page-stack">
        <Card className="border-[rgb(var(--amber))]/12">
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_320px] xl:items-start">
            <div className="flex items-start gap-5">
              <div className="flex h-16 w-16 flex-shrink-0 items-center justify-center rounded bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]">
                <WifiOff size={28} />
              </div>
              <div className="flex min-w-0 flex-col gap-3">
                <h3 className="text-[24px] font-bold leading-tight">{t("dash.not_connected")}</h3>
                <p className="max-w-xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                  {t("dash.not_connected_desc")}
                </p>
                {error && (
                  <div className="flex items-center gap-2 text-[12px] text-[rgb(var(--red))]">
                    <AlertCircle size={14} />
                    <span>{error}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex flex-col gap-4">
              <div className="rounded border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/25 p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">{t("dash.endpoint")}</p>
                <p className="mt-2 break-all font-mono text-[12px] text-[rgb(var(--t2))]">\\.\pipe\sentinelld</p>
              </div>
              <button
                onClick={refresh}
                className="rounded-xl bg-[rgb(var(--accent))] px-5 py-3 text-[13px] font-semibold text-white shadow-sm shadow-[rgb(var(--accent))]/15 hover:opacity-90 cursor-pointer"
              >
                {t("dash.retry")}
              </button>
            </div>
          </div>
        </Card>

        <div className="card-grid-4">
          <StatusTile
            label={t("tile.realtime")}
            value={t("dash.unavailable")}
            sub={t("dash.watcher_offline")}
            color="amber"
            icon={<Eye size={18} />}
          />
          <StatusTile
            label={t("tile.engine")}
            value={t("tile.disconnected")}
            sub={t("dash.daemon_unreachable")}
            color="red"
            icon={<ShieldOff size={18} />}
          />
          <StatusTile
            label={t("tile.signatures")}
            value={t("common.unknown")}
            sub={t("dash.db_state_unavailable")}
            color="amber"
            icon={<Database size={18} />}
          />
          <StatusTile
            label={t("dash.last_update")}
            value={t("common.never")}
            sub={t("dash.no_sync")}
            color="amber"
            icon={<Clock size={18} />}
          />
        </div>

        <section className="section-stack">
          <div className="flex flex-col gap-2">
            <h4 className="text-[15px] font-semibold">{t("dash.quick_actions")}</h4>
            <p className="text-[12px] text-[rgb(var(--t3))]">{t("dash.quick_actions_offline")}</p>
          </div>
          <div className="card-grid-4">
            <ActionTile
              icon={<Search size={20} />}
              label={t("scan.file")}
              description={t("dash.scan_file_desc")}
              onClick={() => onNavigate("scan")}
            />
            <ActionTile icon={<Zap size={20} />} label={t("scan.quick")} description={t("dash.requires_daemon")} />
            <ActionTile icon={<RefreshCw size={20} />} label={t("nav.update")} description={t("dash.retry_sigs_desc")} />
            <ActionTile
              icon={<Archive size={20} />}
              label={t("scan.quarantine_action")}
              description={t("dash.review_isolated")}
              onClick={() => onNavigate("quarantine")}
            />
          </div>
        </section>
      </div>
    );
  }

  const engine = data!.engine;
  const watcher = data!.watcher;
  const stats = data!.stats;
  const activity = data!.activity;
  const idle = data!.idleScanner;
  const isReady = engine.state === "ready";
  const lastDbUpdate = engine.last_update ? new Date(engine.last_update * 1000).toLocaleString() : t("common.never");
  const lastSeen = lastRefresh ? lastRefresh.toLocaleTimeString() : t("tile.waiting");
  const dbVersion = engine.db_version ? `v${engine.db_version}` : t("dash.unavailable");

  return (
    <div className="page-stack">
      {/* Notifications now live in TopBar — dashboard content starts clean */}

      <Card className={isReady ? "border-[rgb(var(--green))]/12" : "border-[rgb(var(--red))]/12"}>
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.7fr)_300px] xl:items-start">
          <div className="flex items-start gap-5">
            <div
              className={`flex h-16 w-16 flex-shrink-0 items-center justify-center rounded ${
                isReady ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]" : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
              }`}
            >
              <ShieldIcon icon={isReady ? "protected" : "threat"} size={38} className={`brightness-0 invert ${isReady ? "opacity-80" : "opacity-60"}`} />
            </div>
            <div className="flex min-w-0 flex-col gap-3">
              <h3 className="text-[24px] font-bold leading-tight">
                {isReady ? t("dash.protected") : t("dash.attention")}
              </h3>
              <p className="max-w-2xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                {engine.signature_count > 0
                  ? `${engine.signature_count.toLocaleString()} ${t("dash.sigs_loaded_db")} ${dbVersion}.`
                  : t("dash.no_sigs_loaded")}
              </p>
              <div className="flex flex-wrap items-center gap-3 text-[12px] text-[rgb(var(--t3))]">
                <span className="rounded-full bg-[rgb(var(--raised))]/25 px-3 py-1.5">
                  {t("dash.engine_prefix")} {engine.engine_version}
                </span>
                <span className="rounded-full bg-[rgb(var(--raised))]/25 px-3 py-1.5">
                  {t("dash.watcher_prefix")} {watcher.mode.replace("_", " ")}
                </span>
              </div>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
            <HeroDetail label={t("dash.last_refresh")} value={lastSeen} sub={t("dash.ui_heartbeat")} />
            <HeroDetail label={t("dash.db_updated")} value={lastDbUpdate} sub={t("dash.last_sync")} />
          </div>
        </div>
      </Card>

      <div className="card-grid-4">
        <StatusTile
          label={t("tile.realtime")}
          value={watcher.enabled ? t("tile.active") : t("tile.disabled")}
          sub={watcher.enabled ? `${watcher.events_per_sec} ${t("dash.events_per_sec_suffix")}` : t("tile.watcher_inactive")}
          color={watcher.enabled ? "green" : "amber"}
          icon={<Eye size={18} />}
        />
        <StatusTile
          label={t("tile.background")}
          value={idle.state === "disabled" ? t("tile.off")
            : idle.state.startsWith("scanning") ? t("tile.scanning")
            : idle.state.startsWith("paused") ? t("tile.paused")
            : idle.state === "completed" ? t("tile.done")
            : t("tile.waiting")}
          sub={idle.state === "disabled" ? t("dash.idle_disabled")
            : idle.state.startsWith("scanning") ? `${idle.files_scanned_session} ${t("dash.files_suffix")} · ${idle.current_target || "..."}`
            : idle.state.startsWith("paused") ? idle.last_pause_reason.replace("_", " ")
            : idle.state === "completed" ? `${idle.files_scanned_session} ${t("dash.files_checked")}`
            : t("dash.waiting_capacity")}
          color={idle.state === "disabled" ? "amber"
            : idle.state.startsWith("scanning") ? "green"
            : idle.state === "completed" ? "green"
            : "accent"}
          icon={<Search size={18} />}
        />
        <StatusTile
          label={t("tile.argus")}
          value={stats.argus_active_layers > 0 ? `${stats.argus_active_layers} ${t("argus.layers_suffix")}` : t("tile.active")}
          sub={stats.argus_yara_rules > 0
            ? `${stats.argus_yara_rules} ${t("argus.rules_suffix")} · ${stats.argus_files_analyzed} ${t("argus.analyzed_suffix")}`
            : stats.argus_files_analyzed > 0
              ? `${stats.argus_files_analyzed} ${t("argus.files_analyzed_suffix")}`
              : t("argus.heuristic_ready")}
          color="accent"
          icon={<Zap size={18} />}
        />
        <StatusTile
          label={t("tile.signatures")}
          value={engine.signature_count > 0 ? engine.signature_count.toLocaleString() : "0"}
          sub={`${t("dash.database_prefix")} ${dbVersion}`}
          color={engine.signature_count > 0 ? "green" : "amber"}
          icon={<Database size={18} />}
        />
      </div>

      {/* Secondary row: Uptime + ARGUS Intelligence pill */}
      <div className="dash-secondary-row">
        <StatusTile
          label={t("tile.uptime")}
          value={stats.uptime_human}
          sub={t("tile.daemon_runtime")}
          color="accent"
          icon={<Clock size={16} />}
        />
        {stats.argus_yara_rules > 0 ? (
          <div className="glass-card flex items-center gap-6 px-7 py-5">
            {/* Left: icon + title */}
            <div className="flex items-center gap-3 flex-shrink-0">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
                <Zap size={16} className="text-[rgb(var(--accent))]" />
              </div>
              <div>
                <h4 className="text-[13px] font-semibold">{t("argus.intelligence")} · ASTRA</h4>
                <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">
                  v{stats.argus_version} · {stats.argus_active_layers} {t("argus.layers_suffix")} · {stats.argus_yara_rules} {t("argus.rules_suffix")}
                </p>
              </div>
            </div>
            {/* Middle: tags */}
            <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
              {[
                t("argus.pack_stealer"),
                t("argus.pack_script"),
                t("argus.pack_deception"),
                t("argus.pack_github"),
                t("argus.pack_lolbin"),
                t("argus.pack_documents"),
                t("argus.pack_persistence"),
              ].map((pack) => (
                <span key={pack} className="text-[10px] px-2.5 py-1 rounded-full bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))] whitespace-nowrap">
                  {pack}
                </span>
              ))}
            </div>
            {/* Right: stat */}
            {stats.argus_files_analyzed > 0 && (
              <div className="text-right flex-shrink-0 min-w-[80px]">
                <p className="text-[18px] font-bold text-[rgb(var(--t1))]">{stats.argus_files_analyzed.toLocaleString()}</p>
                <p className="text-[10px] text-[rgb(var(--t3))]">{t("argus.files_analyzed")}</p>
              </div>
            )}
          </div>
        ) : (
          <div className="glass-card flex items-center gap-4 px-7 py-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
              <Zap size={16} className="text-[rgb(var(--accent))]" />
            </div>
            <div>
              <h4 className="text-[13px] font-semibold">{t("argus.intelligence")} · ASTRA</h4>
              <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{t("argus.no_yara")}</p>
            </div>
          </div>
        )}
      </div>

      {/* Runtime Intelligence — compact ASTRA card */}
      <RuntimeIntelligenceCard />

      <section className="section-stack">
        <div className="flex flex-col gap-2">
          <h4 className="text-[15px] font-semibold">{t("dash.quick_actions")}</h4>
          <p className="text-[12px] text-[rgb(var(--t3))]">{t("dash.quick_actions_desc")}</p>
        </div>
        <div className="card-grid-4">
          <ActionTile
            icon={<Search size={20} />}
            label={t("scan.file")}
            description={t("dash.select_scan_one")}
            onClick={() => onNavigate("scan")}
          />
          <ActionTile
            icon={<Zap size={20} />}
            label={t("scan.quick")}
            description={t("dash.scan_common_folders")}
            accent
            onClick={() => {
              startQuickScan().catch((e) => console.error("Quick scan failed:", e));
              onNavigate("scan");
            }}
          />
          <ActionTile
            icon={<RefreshCw size={20} />}
            label={t("nav.update")}
            description={t("dash.refresh_sig_db")}
            onClick={() => onNavigate("update")}
          />
          <ActionTile
            icon={<Archive size={20} />}
            label={t("scan.quarantine_action")}
            description={t("dash.inspect_isolated")}
            onClick={() => onNavigate("quarantine")}
          />
        </div>
      </section>

      <Card>
        <div className="mb-5 flex items-center justify-between gap-4">
          <div>
            <h4 className="text-[15px] font-semibold">{t("dash.recent_activity")}</h4>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">{t("dash.recent_activity_desc")}</p>
          </div>
          <button
            onClick={() => onNavigate("history")}
            className="rounded-xl border border-[rgb(var(--accent))]/15 px-3 py-2 text-[11px] font-semibold text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/6 cursor-pointer"
          >
            {t("dash.view_history")}
          </button>
        </div>
        {activity.length > 0 ? (
          <div className="space-y-2">
            {activity.slice(0, 5).map((entry) => {
              const state = entry.category.includes("scan")
                ? "scan"
                : entry.category.includes("threat")
                  ? "threat"
                  : "neutral";
              return (
                <div key={entry.event_id} className="flex items-start gap-4 rounded-xl px-4 py-3 hover:bg-[rgb(var(--raised))]/20 transition-colors">
                  <div
                    className={`mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl ${
                      state === "scan"
                        ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
                        : state === "threat"
                          ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                          : "bg-[rgb(var(--raised))]/40 text-[rgb(var(--t3))]"
                    }`}
                  >
                    {state === "scan" ? <CheckCircle size={15} /> : state === "threat" ? <AlertTriangle size={15} /> : <Activity size={15} />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-medium">{entry.title}</p>
                    {entry.message && <p className="mt-1 text-[11px] text-[rgb(var(--t3))]">{entry.message}</p>}
                  </div>
                  <span className="mt-1 flex-shrink-0 text-[10px] text-[rgb(var(--t3))]">
                    {new Date(entry.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex flex-col items-center py-10 text-center">
            <Clock size={32} className="mb-3 text-[rgb(var(--t3))]/20" />
            <p className="text-[14px] font-medium text-[rgb(var(--t2))]">{t("dash.no_activity")}</p>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">{t("dash.no_activity_desc")}</p>
          </div>
        )}
      </Card>
    </div>
  );
}

function HeroDetail({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/20 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">{label}</p>
      <p className="mt-2 text-[15px] font-semibold text-[rgb(var(--t1))]">{value}</p>
      <p className="mt-1 text-[11px] text-[rgb(var(--t3))]">{sub}</p>
    </div>
  );
}

function StatusTile({
  label,
  value,
  sub,
  color,
  icon,
}: {
  label: string;
  value: string;
  sub: string;
  color: "accent" | "green" | "amber" | "red";
  icon: React.ReactNode;
}) {
  const palette = {
    accent: "var(--accent)",
    green: "var(--green)",
    amber: "var(--amber)",
    red: "var(--red)",
  }[color];

  return (
    <div className="glass-card flex flex-col gap-2 px-5 py-4 h-full">
      {/* Header: icon + label */}
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
      {/* Value */}
      <p className="text-[22px] font-bold leading-tight text-[rgb(var(--t1))]">{value}</p>
      {/* Subtitle */}
      <p className="text-[11px] leading-snug text-[rgb(var(--t3))]">{sub}</p>
    </div>
  );
}

function ActionTile({
  icon,
  label,
  description,
  accent,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  description: string;
  accent?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex h-full min-h-[130px] w-full flex-col items-start gap-4 rounded border p-6 text-left transition-colors cursor-pointer ${
        accent
          ? "border-[rgb(var(--accent))]/16 bg-[rgb(var(--accent))]/6 text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/10"
          : "border-[rgb(var(--border))]/15 bg-[rgb(var(--surface))] text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t1))]"
      }`}
    >
      <div
        className={`flex h-10 w-10 items-center justify-center rounded-xl ${
          accent ? "bg-[rgb(var(--accent))]/10" : "bg-[rgb(var(--raised))]/40"
        }`}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-[13px] font-semibold text-current">{label}</p>
        <p className="mt-1 text-[11px] leading-relaxed text-[rgb(var(--t3))]">{description}</p>
      </div>
    </button>
  );
}

// ── Runtime Intelligence compact card ─────────────────────────

function RuntimeIntelligenceCard() {
  const [ri, setRi] = useState<RuntimeIntelligenceStatus | null>(null);
  const { connected } = useDaemonContext();

  useEffect(() => {
    if (!connected) return;
    getRuntimeIntelligence().then(setRi).catch(() => {});
    const interval = setInterval(() => {
      getRuntimeIntelligence().then(setRi).catch(() => {});
    }, 10000); // Refresh every 10s.
    return () => clearInterval(interval);
  }, [connected]);

  if (!ri) return null;

  const plmActive = ri.plm?.enabled;
  const psEnabled = ri.powershell?.enabled;
  const psEvents = ri.powershell?.events_scanned ?? 0;
  const plmNodes = ri.plm?.nodes ?? 0;
  const plmChains = ri.plm?.suspicious_chains ?? 0;
  const recentEvents = ri.powershell?.recent_events ?? [];

  // Don't show if everything is disabled and no data.
  if (!plmActive && !psEnabled && recentEvents.length === 0) return null;

  return (
    <div className="glass-card px-7 py-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
            <Activity size={15} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">Runtime Intelligence</h4>
            <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">ASTRA adaptive analysis · observe-only</p>
          </div>
        </div>
        <span className="text-[10px] px-2.5 py-1 rounded-full bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]">
          {plmActive ? "Active" : "Standby"}
        </span>
      </div>

      {/* Compact stats row */}
      <div className="grid grid-cols-4 gap-4 mb-4">
        <MiniStat label="PLM nodes" value={plmNodes} />
        <MiniStat label="PS buffers" value={psEvents} />
        <MiniStat label="Suspicious chains" value={plmChains} color={plmChains > 0 ? "amber" : undefined} />
        <MiniStat label="SBL" value={ri.powershell?.sbl_available ? "Available" : "Unavailable"} />
      </div>

      {/* Recent events (if any) */}
      {recentEvents.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-2">
            Recent runtime events
          </p>
          <div className="space-y-1.5">
            {recentEvents.slice(-5).reverse().map((evt, i) => (
              <div key={i} className="flex items-center gap-3 text-[11px] py-1.5 px-2 rounded-lg hover:bg-[rgb(var(--raised))]/10">
                <span className={`w-6 text-right font-mono font-bold ${evt.score >= 50 ? "text-[rgb(var(--amber))]" : evt.score > 0 ? "text-[rgb(var(--t2))]" : "text-[rgb(var(--t3))]/40"}`}>
                  {evt.score}
                </span>
                <span className="text-[rgb(var(--t3))]/60 w-16 flex-shrink-0">{evt.language}</span>
                <span className="text-[rgb(var(--t2))] truncate flex-1 min-w-0">{evt.content_name}</span>
                {evt.findings_count > 0 && (
                  <span className="text-[10px] text-[rgb(var(--amber))] flex-shrink-0">{evt.findings_count} findings</span>
                )}
                {evt.lineage_summary && (
                  <span className="text-[10px] text-[rgb(var(--accent))]/60 truncate max-w-[150px] flex-shrink-0" title={evt.lineage_summary}>
                    {evt.lineage_summary}
                  </span>
                )}
                <span className="text-[9px] text-[rgb(var(--green))]/50 flex-shrink-0">observe</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Disabled states */}
      {!psEnabled && (
        <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-2">
          PowerShell bridge disabled · enable in sentinelld.toml
        </p>
      )}
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  const c = color === "amber" ? "var(--amber)" : "var(--t1)";
  return (
    <div>
      <p className="text-[18px] font-bold" style={{ color: `rgb(${c})` }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{label}</p>
    </div>
  );
}

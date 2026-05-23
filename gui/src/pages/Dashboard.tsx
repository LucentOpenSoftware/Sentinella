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
import { Card } from "../components/Card";
import { ShieldIcon } from "../components/ShieldIcon";
import { useDaemonContext } from "../hooks/DaemonContext";
import { startQuickScan } from "../api/sentinella";
import type { Page } from "../components/Sidebar";

export function Dashboard({ onNavigate }: { onNavigate: (p: Page) => void }) {
  const { data, connected, loading, error, lastRefresh, refresh } = useDaemonContext();

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center py-32">
        <Loader2 size={24} className="mb-4 animate-spin text-[rgb(var(--accent))]" />
        <p className="text-[13px] text-[rgb(var(--t3))]">Connecting to daemon...</p>
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
                <h3 className="text-[24px] font-bold leading-tight">Daemon Not Connected</h3>
                <p className="max-w-xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                  Cannot reach the Sentinella daemon. Make sure sentinelld is running.
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
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">Endpoint</p>
                <p className="mt-2 break-all font-mono text-[12px] text-[rgb(var(--t2))]">\\.\pipe\sentinelld</p>
              </div>
              <button
                onClick={refresh}
                className="rounded-xl bg-[rgb(var(--accent))] px-5 py-3 text-[13px] font-semibold text-white shadow-sm shadow-[rgb(var(--accent))]/15 hover:opacity-90 cursor-pointer"
              >
                Retry Connection
              </button>
            </div>
          </div>
        </Card>

        <div className="card-grid-4">
          <StatusTile
            label="Real-time"
            value="Unavailable"
            sub="Watcher offline"
            color="amber"
            icon={<Eye size={18} />}
          />
          <StatusTile
            label="Engine"
            value="Disconnected"
            sub="Daemon unreachable"
            color="red"
            icon={<ShieldOff size={18} />}
          />
          <StatusTile
            label="Signatures"
            value="Unknown"
            sub="Database state unavailable"
            color="amber"
            icon={<Database size={18} />}
          />
          <StatusTile
            label="Last Update"
            value="Never"
            sub="No sync detected"
            color="amber"
            icon={<Clock size={18} />}
          />
        </div>

        <section className="section-stack">
          <div className="flex flex-col gap-2">
            <h4 className="text-[15px] font-semibold">Quick Actions</h4>
            <p className="text-[12px] text-[rgb(var(--t3))]">Common tasks remain available once the daemon reconnects.</p>
          </div>
          <div className="card-grid-4">
            <ActionTile
              icon={<Search size={20} />}
              label="Scan File"
              description="Open single-file scan"
              onClick={() => onNavigate("scan")}
            />
            <ActionTile icon={<Zap size={20} />} label="Quick Scan" description="Requires daemon connection" />
            <ActionTile icon={<RefreshCw size={20} />} label="Update" description="Retry signatures after reconnect" />
            <ActionTile
              icon={<Archive size={20} />}
              label="Quarantine"
              description="Review isolated items"
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
  const lastDbUpdate = engine.last_update ? new Date(engine.last_update * 1000).toLocaleString() : "Never";
  const lastSeen = lastRefresh ? lastRefresh.toLocaleTimeString() : "Waiting";
  const dbVersion = engine.db_version ? `v${engine.db_version}` : "Unavailable";

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
              <ShieldIcon icon={isReady ? "protected" : "threat"} size={38} className={isReady ? "" : "opacity-70"} />
            </div>
            <div className="flex min-w-0 flex-col gap-3">
              <h3 className="text-[24px] font-bold leading-tight">
                {isReady ? "Your System is Protected" : "Protection Attention Needed"}
              </h3>
              <p className="max-w-2xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                {engine.signature_count > 0
                  ? `${engine.signature_count.toLocaleString()} signatures loaded. ARGUS heuristics active. Database ${dbVersion}.`
                  : "No signature database loaded yet. ARGUS heuristics active."}
              </p>
              <div className="flex flex-wrap items-center gap-3 text-[12px] text-[rgb(var(--t3))]">
                <span className="rounded-full bg-[rgb(var(--raised))]/25 px-3 py-1.5">
                  Engine {engine.engine_version}
                </span>
                <span className="rounded-full bg-[rgb(var(--raised))]/25 px-3 py-1.5">
                  Watcher {watcher.mode.replace("_", " ")}
                </span>
              </div>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
            <HeroDetail label="Last Refresh" value={lastSeen} sub="UI heartbeat" />
            <HeroDetail label="Database Updated" value={lastDbUpdate} sub="Last signatures sync" />
          </div>
        </div>
      </Card>

      <div className="card-grid-4">
        <StatusTile
          label="Real-time"
          value={watcher.enabled ? "Active" : "Disabled"}
          sub={watcher.enabled ? `${watcher.events_per_sec} events/sec` : "Watcher inactive"}
          color={watcher.enabled ? "green" : "amber"}
          icon={<Eye size={18} />}
        />
        <StatusTile
          label="Background"
          value={idle.state === "disabled" ? "Off"
            : idle.state.startsWith("scanning") ? "Scanning"
            : idle.state.startsWith("paused") ? "Paused"
            : idle.state === "completed" ? "Done"
            : "Waiting"}
          sub={idle.state === "disabled" ? "Idle scanner disabled"
            : idle.state.startsWith("scanning") ? `${idle.files_scanned_session} files · ${idle.current_target || "..."}`
            : idle.state.startsWith("paused") ? idle.last_pause_reason.replace("_", " ")
            : idle.state === "completed" ? `${idle.files_scanned_session} files checked`
            : "Waiting for capacity"}
          color={idle.state === "disabled" ? "amber"
            : idle.state.startsWith("scanning") ? "green"
            : idle.state === "completed" ? "green"
            : "accent"}
          icon={<Search size={18} />}
        />
        <StatusTile
          label="ARGUS"
          value={stats.argus_active_layers > 0 ? `${stats.argus_active_layers} Layers` : "Active"}
          sub={stats.argus_yara_rules > 0
            ? `${stats.argus_yara_rules} rules · ${stats.argus_files_analyzed} analyzed`
            : stats.argus_files_analyzed > 0
              ? `${stats.argus_files_analyzed} files analyzed`
              : "Heuristic engine ready"}
          color="accent"
          icon={<Zap size={18} />}
        />
        <StatusTile
          label="Signatures"
          value={engine.signature_count > 0 ? engine.signature_count.toLocaleString() : "0"}
          sub={`Database ${dbVersion}`}
          color={engine.signature_count > 0 ? "green" : "amber"}
          icon={<Database size={18} />}
        />
      </div>

      {/* Secondary row: Uptime + ARGUS Intelligence pill */}
      <div className="dash-secondary-row">
        <StatusTile
          label="Uptime"
          value={stats.uptime_human}
          sub="Daemon runtime"
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
                <h4 className="text-[13px] font-semibold">ARGUS Intelligence</h4>
                <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">
                  v{stats.argus_version} · {stats.argus_active_layers} layers · {stats.argus_yara_rules} rules
                </p>
              </div>
            </div>
            {/* Middle: tags */}
            <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
              {["Stealer Detection", "Script Abuse", "Deception & Evasion", "GitHub Stealers", "LOLBin Abuse", "Documents", "Persistence"].map((pack) => (
                <span key={pack} className="text-[10px] px-2.5 py-1 rounded-full bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))] whitespace-nowrap">
                  {pack}
                </span>
              ))}
            </div>
            {/* Right: stat */}
            {stats.argus_files_analyzed > 0 && (
              <div className="text-right flex-shrink-0 min-w-[80px]">
                <p className="text-[18px] font-bold text-[rgb(var(--t1))]">{stats.argus_files_analyzed.toLocaleString()}</p>
                <p className="text-[10px] text-[rgb(var(--t3))]">files analyzed</p>
              </div>
            )}
          </div>
        ) : (
          <div className="glass-card flex items-center gap-4 px-7 py-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
              <Zap size={16} className="text-[rgb(var(--accent))]" />
            </div>
            <div>
              <h4 className="text-[13px] font-semibold">ARGUS Intelligence</h4>
              <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">Heuristic engine active · no YARA rules loaded</p>
            </div>
          </div>
        )}
      </div>

      <section className="section-stack">
        <div className="flex flex-col gap-2">
          <h4 className="text-[15px] font-semibold">Quick Actions</h4>
          <p className="text-[12px] text-[rgb(var(--t3))]">Run the most common security tasks.</p>
        </div>
        <div className="card-grid-4">
          <ActionTile
            icon={<Search size={20} />}
            label="Scan File"
            description="Select and scan one file"
            onClick={() => onNavigate("scan")}
          />
          <ActionTile
            icon={<Zap size={20} />}
            label="Quick Scan"
            description="Scan common folders"
            accent
            onClick={() => {
              startQuickScan().catch((e) => console.error("Quick scan failed:", e));
              onNavigate("scan");
            }}
          />
          <ActionTile
            icon={<RefreshCw size={20} />}
            label="Update"
            description="Refresh signature database"
            onClick={() => onNavigate("update")}
          />
          <ActionTile
            icon={<Archive size={20} />}
            label="Quarantine"
            description="Inspect isolated items"
            onClick={() => onNavigate("quarantine")}
          />
        </div>
      </section>

      <Card>
        <div className="mb-5 flex items-center justify-between gap-4">
          <div>
            <h4 className="text-[15px] font-semibold">Recent Activity</h4>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">Latest daemon events and scan history.</p>
          </div>
          <button
            onClick={() => onNavigate("history")}
            className="rounded-xl border border-[rgb(var(--accent))]/15 px-3 py-2 text-[11px] font-semibold text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/6 cursor-pointer"
          >
            View History
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
            <p className="text-[14px] font-medium text-[rgb(var(--t2))]">No recent activity</p>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">Activity appears here after scans and updates.</p>
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

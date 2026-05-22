import {
  Zap,
  HardDrive,
  RefreshCw,
  Archive,
  Database,
  ShieldCheck,
  ShieldOff,
  Eye,
  EyeOff,
  Clock,
  Activity,
  Loader2,
  WifiOff,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  ServerCrash,
} from "lucide-react";
import { QuickActionCard } from "../components/QuickActionCard";
import { StatCard } from "../components/StatCard";
import { Card } from "../components/Card";
import { useDaemon } from "../hooks/useDaemon";
import { startQuickScan, startFullScan, startSignatureUpdate } from "../api/sentinella";

export function Dashboard() {
  const { data, connected, loading, error, lastRefresh, refresh } = useDaemon();

  // ── Loading ─────────────────────────────────────────────
  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center py-32">
        <Loader2 size={28} className="text-[rgb(var(--accent))] animate-spin mb-4" />
        <p className="text-sm text-[rgb(var(--text-muted))]">Connecting to daemon...</p>
      </div>
    );
  }

  // ── Disconnected (never connected) ──────────────────────
  if (!connected && !data) {
    return (
      <Card className="text-center py-20 max-w-lg mx-auto">
        <WifiOff size={32} className="mx-auto text-[rgb(var(--warning))] mb-4" />
        <h3 className="text-lg font-semibold mb-2">Daemon not connected</h3>
        <p className="text-sm text-[rgb(var(--text-muted))] mb-1">
          Cannot reach sentinelld on the named pipe.
        </p>
        <p className="text-xs text-[rgb(var(--text-muted))] font-mono mb-6">
          \\.\pipe\sentinelld
        </p>
        {error && (
          <p className="text-xs text-[rgb(var(--danger))] mb-4 flex items-center justify-center gap-1">
            <AlertCircle size={12} /> {error}
          </p>
        )}
        <button
          onClick={refresh}
          className="px-5 py-2.5 bg-[rgb(var(--accent))] text-white rounded-xl text-sm font-medium hover:opacity-90 transition-opacity cursor-pointer"
        >
          Retry Connection
        </button>
      </Card>
    );
  }

  // ── Destructure daemon data ─────────────────────────────
  const engine = data!.engine;
  const scan = data!.scan;
  const watcher = data!.watcher;
  const stats = data!.stats;
  const quarantineCount = data!.quarantine.length;
  const activity = data!.activity;
  const scanHistory = data!.scanHistory;

  const isReady = engine.state === "ready";
  const isError = engine.state === "error";

  return (
    <div className="space-y-5">
      {/* ── Stale-data banner ──────────────────────────── */}
      {!connected && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-[rgb(var(--warning))]/8 border border-[rgb(var(--warning))]/20 text-sm">
          <WifiOff size={15} className="text-[rgb(var(--warning))] flex-shrink-0" />
          <span className="text-[rgb(var(--warning))]">Daemon disconnected — showing last known state</span>
          <button onClick={refresh} className="ml-auto text-xs text-[rgb(var(--accent))] hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {/* ── Protection hero ────────────────────────────── */}
      <div className={`rounded-2xl p-5 border flex items-center gap-5 ${
        isError ? "bg-[rgb(var(--danger))]/5 border-[rgb(var(--danger))]/20"
        : isReady ? "bg-[rgb(var(--success))]/5 border-[rgb(var(--success))]/20"
        : "bg-[rgb(var(--accent))]/5 border-[rgb(var(--accent))]/20"
      }`}>
        <div className={`w-13 h-13 rounded-2xl flex items-center justify-center flex-shrink-0 ${
          isError ? "bg-[rgb(var(--danger))]/15" : isReady ? "bg-[rgb(var(--success))]/15" : "bg-[rgb(var(--accent))]/15"
        }`}>
          {isError ? <ShieldOff size={26} className="text-[rgb(var(--danger))]" />
            : isReady ? <ShieldCheck size={26} className="text-[rgb(var(--success))]" />
            : <Loader2 size={26} className="text-[rgb(var(--accent))] animate-spin" />}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-semibold">
            {isError ? "Protection Issue" : isReady ? "Your System is Protected" : "Engine Loading..."}
          </h3>
          <p className="text-sm text-[rgb(var(--text-muted))] mt-0.5">
            {engine.signature_count > 0
              ? `${engine.signature_count.toLocaleString()} signatures loaded`
              : "No signature database loaded"}
            {engine.db_version ? ` · DB v${engine.db_version}` : ""}
          </p>
        </div>
        <div className="text-right flex-shrink-0 space-y-0.5">
          <p className="text-xs text-[rgb(var(--text-muted))]">Engine {engine.engine_version}</p>
          {lastRefresh && (
            <p className="text-[11px] text-[rgb(var(--text-muted))]">
              Refreshed {lastRefresh.toLocaleTimeString()}
            </p>
          )}
        </div>
      </div>

      {/* ── Stats grid ─────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard
          icon={<Database size={18} />}
          label="Signatures"
          value={engine.signature_count > 0 ? engine.signature_count.toLocaleString() : "—"}
          sub={engine.db_version ? `DB v${engine.db_version}` : "No database"}
          color="accent"
        />
        <StatCard
          icon={watcher.enabled ? <Eye size={18} /> : <EyeOff size={18} />}
          label="Real-time"
          value={watcher.enabled ? "Active" : "Not active"}
          sub={watcher.enabled ? `${watcher.watched_roots.length} folders` : "Watcher not implemented"}
          color={watcher.enabled ? "success" : "warning"}
        />
        <StatCard
          icon={<Activity size={18} />}
          label="Scans"
          value={String(stats.scans_completed)}
          sub={scan.running ? `${scan.scan_type} scan running` : "Idle"}
          color={scan.running ? "accent" : "muted"}
        />
        <StatCard
          icon={<Clock size={18} />}
          label="Uptime"
          value={stats.uptime_human}
          sub={`${stats.ipc_requests_served} IPC requests`}
          color="muted"
        />
      </div>

      {/* ── Quick actions ──────────────────────────────── */}
      <div>
        <p className="text-xs font-medium text-[rgb(var(--text-muted))] mb-3 uppercase tracking-wider">Quick Actions</p>
        <div className="grid grid-cols-4 gap-3">
          <QuickActionCard icon={<Zap size={20} />} label="Quick Scan" description="Scan critical areas" accent
            onClick={() => startQuickScan().catch(() => {})} />
          <QuickActionCard icon={<HardDrive size={20} />} label="Full Scan" description="Scan entire system"
            onClick={() => startFullScan().catch(() => {})} />
          <QuickActionCard icon={<RefreshCw size={20} />} label="Update Sigs" description="Check for new definitions"
            onClick={() => startSignatureUpdate().catch(() => {})} />
          <QuickActionCard icon={<Archive size={20} />} label="Quarantine"
            description={`${quarantineCount} item${quarantineCount !== 1 ? "s" : ""}`} />
        </div>
      </div>

      {/* ── Engine details + activity ──────────────────── */}
      <div className="grid grid-cols-5 gap-4">
        {/* Engine panel */}
        <Card className="col-span-2">
          <div className="flex items-center gap-2 mb-3">
            <ServerCrash size={14} className="text-[rgb(var(--accent))]" />
            <h4 className="text-sm font-semibold">Engine</h4>
          </div>
          <div className="space-y-2 text-[13px]">
            <DRow label="State" value={engine.state} color={isReady ? "success" : isError ? "danger" : undefined} />
            <DRow label="Version" value={engine.engine_version} />
            <DRow label="Protocol" value={`v${engine.protocol_version}`} />
            <DRow label="Database" value={engine.db_version ? `v${engine.db_version}` : "None"} />
            <DRow label="Signatures" value={engine.signature_count.toLocaleString()} />
            <DRow label="Last update" value={engine.last_update ? new Date(engine.last_update * 1000).toLocaleString() : "Never"} />
            <DRow label="Watcher" value={watcher.mode} />
            <DRow label="Quarantine" value={`${quarantineCount} items`} />
          </div>
        </Card>

        {/* Activity + scan history */}
        <Card className="col-span-3">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Clock size={14} className="text-[rgb(var(--text-muted))]" />
              <h4 className="text-sm font-semibold">Activity</h4>
            </div>
            <span className="text-[11px] text-[rgb(var(--text-muted))] bg-[rgb(var(--bg-elevated))] px-2 py-1 rounded-lg">
              {activity.length} events · {scanHistory.length} scans
            </span>
          </div>

          {activity.length > 0 ? (
            <div className="space-y-1">
              {activity.slice(0, 8).map((e, i) => (
                <div key={i} className="flex items-start gap-3 px-2 py-2 rounded-lg hover:bg-[rgb(var(--bg-elevated))]/40 transition-colors">
                  <div className={`w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0 mt-0.5 ${
                    e.event_type.includes("threat") || e.event_type.includes("error")
                      ? "bg-[rgb(var(--danger))]/10 text-[rgb(var(--danger))]"
                      : e.event_type.includes("scan") ? "bg-[rgb(var(--success))]/10 text-[rgb(var(--success))]"
                      : e.event_type.includes("update") ? "bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))]"
                      : "bg-[rgb(var(--bg-elevated))] text-[rgb(var(--text-muted))]"
                  }`}>
                    {e.event_type.includes("scan") ? <CheckCircle size={13} />
                      : e.event_type.includes("threat") ? <AlertTriangle size={13} />
                      : e.event_type.includes("update") ? <RefreshCw size={13} />
                      : <Activity size={13} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium leading-tight">{e.message}</p>
                    {e.detail && <p className="text-[11px] text-[rgb(var(--text-muted))] truncate mt-0.5">{e.detail}</p>}
                  </div>
                  <span className="text-[11px] text-[rgb(var(--text-muted))] flex-shrink-0 mt-0.5">
                    {new Date(e.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[rgb(var(--text-muted))] text-center py-6">No activity yet</p>
          )}
        </Card>
      </div>
    </div>
  );
}

function DRow({ label, value, color }: { label: string; value: string; color?: "success" | "danger" | "warning" }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-[rgb(var(--text-muted))]">{label}</span>
      <span className={color ? `font-medium text-[rgb(var(--${color}))]` : "font-medium"}>{value}</span>
    </div>
  );
}

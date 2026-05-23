import { useState, useEffect } from "react";
import {
  Activity, Cpu, Database, HardDrive, Heart, Loader2, RefreshCw,
  Shield, Zap, Eye, AlertTriangle, Clock,
} from "lucide-react";
import { Card } from "../components/Card";
import { exportDiagnostics } from "../api/sentinella";

interface DiagData {
  [key: string]: unknown;
}

export function DiagnosticsPage() {
  const [data, setData] = useState<DiagData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [raw, setRaw] = useState(false);

  const refresh = async () => {
    setLoading(true);
    try {
      const d = await exportDiagnostics();
      setData(d as DiagData);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center py-32">
        <Loader2 size={24} className="mb-4 animate-spin text-[rgb(var(--accent))]" />
        <p className="text-[13px] text-[rgb(var(--t3))]">Loading diagnostics...</p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="page-stack">
        <Card>
          <div className="flex items-center gap-4">
            <AlertTriangle size={20} className="text-[rgb(var(--red))]" />
            <div>
              <p className="text-[14px] font-semibold text-[rgb(var(--red))]">Failed to load diagnostics</p>
              <p className="text-[12px] text-[rgb(var(--t3))] mt-1">{error}</p>
            </div>
            <button onClick={refresh} className="ml-auto px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] cursor-pointer">Retry</button>
          </div>
        </Card>
      </div>
    );
  }

  const d = data!;
  const fp = d.footprint as any || {};
  const mp = d.memory_pressure as any || {};
  const fish = d.fish as any || {};
  const res = d.resilience as any || {};
  const orch = d.orchestrator as any || {};
  const mode = (d.daemon_mode as string) || "normal";
  const audit = d.audit_mode === true;

  return (
    <div className="page-stack">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[16px] font-semibold">System Diagnostics</h3>
          <p className="text-[11px] text-[rgb(var(--t3))] mt-1">
            Internal telemetry — no personal data collected
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => setRaw(!raw)}
            className="px-3 py-2 rounded-xl bg-[rgb(var(--raised))]/25 text-[11px] text-[rgb(var(--t3))] hover:text-[rgb(var(--t1))] cursor-pointer">
            {raw ? "Cards" : "Raw JSON"}
          </button>
          <button onClick={refresh}
            className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[rgb(var(--accent))]/8 text-[11px] text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/15 cursor-pointer">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {raw ? (
        <Card>
          <pre className="text-[11px] font-mono text-[rgb(var(--t2))] overflow-auto max-h-[600px] whitespace-pre-wrap">
            {JSON.stringify(d, null, 2)}
          </pre>
        </Card>
      ) : (
        <>
          {/* Mode + uptime row */}
          <div className="card-grid-4">
            <DiagTile icon={<Shield size={16} />} label="Mode" value={audit ? "Audit" : mode} color={audit ? "amber" : "green"} />
            <DiagTile icon={<Clock size={16} />} label="Uptime" value={`${d.uptime_secs ?? 0}s`} color="accent" />
            <DiagTile icon={<Database size={16} />} label="Signatures" value={String(d.signature_count ?? 0)} color="green" />
            <DiagTile icon={<Zap size={16} />} label="ARGUS" value={`${d.argus_layers ?? 0} layers`} color="accent" />
          </div>

          {/* Memory / Pressure */}
          <Card>
            <SectionHead icon={<Cpu size={15} />} title="Memory Footprint" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="Working Set" value={`${fp.working_set_mb ?? 0} MB`} />
              <Stat label="Private Bytes" value={`${fp.private_bytes_mb ?? 0} MB`} />
              <Stat label="Peak" value={`${fp.peak_working_set_mb ?? 0} MB`} />
              <Stat label="Warning Level" value={fp.warning_level ?? "?"} color={fp.warning_level === "normal" ? "green" : fp.warning_level === "critical" ? "red" : "amber"} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-3">
              <Stat label="Delta (start)" value={`${fp.delta_since_start_mb ?? 0} MB`} />
              <Stat label="Delta (scan)" value={`${fp.delta_since_last_scan_mb ?? 0} MB`} />
              <Stat label="Cache Entries" value={String(fp.scan_cache_entries ?? 0)} />
              <Stat label="Active Workers" value={String(fp.active_workers ?? 0)} />
            </div>
            {fp.notes?.length > 0 && (
              <div className="mt-4 space-y-1">
                {(fp.notes as string[]).map((n: string, i: number) => (
                  <p key={i} className="text-[10px] text-[rgb(var(--t3))] font-mono">• {n}</p>
                ))}
              </div>
            )}
          </Card>

          {/* Memory Pressure */}
          <Card>
            <SectionHead icon={<Activity size={15} />} title="Memory Pressure" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="State" value={mp.state ?? "?"} color={mp.state === "normal" ? "green" : mp.state === "critical" ? "red" : "amber"} />
              <Stat label="Working Set" value={`${mp.working_set_mb ?? 0} MB`} />
              <Stat label="External ARGUS" value={mp.prefer_external_argus ? "Yes" : "No"} />
              <Stat label="Idle Paused" value={mp.pause_idle_scanner ? "Yes" : "No"} />
            </div>
            {mp.actions?.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {(mp.actions as string[]).map((a: string) => (
                  <span key={a} className="text-[10px] px-2.5 py-1 rounded-full bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]">{a}</span>
                ))}
              </div>
            )}
          </Card>

          {/* FISH */}
          <Card>
            <SectionHead icon={<Eye size={15} />} title="FISH — Ransomware Shield" sub="observe-only" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="Enabled" value={fish.enabled ? "Yes" : "No"} color={fish.enabled ? "green" : "amber"} />
              <Stat label="Recent Events" value={String(fish.recent_events ?? 0)} />
              <Stat label="Rename Bursts" value={String(fish.rename_bursts ?? 0)} />
              <Stat label="Rewrite Bursts" value={String(fish.rewrite_bursts ?? 0)} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-3">
              <Stat label="Ext Mutations" value={String(fish.extension_mutations ?? 0)} />
              <Stat label="Alerts Suppressed" value={String(fish.alerts_suppressed ?? 0)} />
              <Stat label="Total Events" value={String(fish.total_events ?? 0)} />
              <Stat label="Observe Only" value={fish.observe_only ? "Yes" : "No"} />
            </div>
            {fish.top_mutated_extensions?.length > 0 && (
              <div className="mt-3">
                <p className="text-[10px] text-[rgb(var(--t3))] mb-1.5">Top extensions:</p>
                <div className="flex flex-wrap gap-1.5">
                  {(fish.top_mutated_extensions as string[]).map((e: string) => (
                    <span key={e} className="text-[10px] px-2 py-0.5 rounded-full bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))]">.{e}</span>
                  ))}
                </div>
              </div>
            )}
          </Card>

          {/* Resilience */}
          <Card>
            <SectionHead icon={<Heart size={15} />} title="Resilience" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="Worker Panics" value={String(res.worker_panics ?? 0)} color={(res.worker_panics ?? 0) > 0 ? "red" : "green"} />
              <Stat label="Worker Timeouts" value={String(res.worker_timeouts ?? 0)} />
              <Stat label="ARGUS Fallbacks" value={String(res.argus_fallbacks ?? 0)} />
              <Stat label="ARGUS Timeouts" value={String(res.argus_timeouts ?? 0)} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-3">
              <Stat label="Watcher HB" value={res.watcher_heartbeat_stale ? "Stale" : "OK"} color={res.watcher_heartbeat_stale ? "red" : "green"} />
              <Stat label="Orchestrator HB" value={res.orchestrator_heartbeat_stale ? "Stale" : "OK"} color={res.orchestrator_heartbeat_stale ? "red" : "green"} />
              <Stat label="Recovery Reason" value={res.last_recovery_reason ?? "None"} />
            </div>
          </Card>

          {/* Orchestrator */}
          {orch.queues && (
            <Card>
              <SectionHead icon={<HardDrive size={15} />} title="Orchestrator" />
              <div className="mt-4 space-y-3">
                {(orch.queues as any[]).map((q: any) => (
                  <div key={q.kind} className="flex items-center gap-4 px-4 py-3 rounded-xl bg-[rgb(var(--raised))]/12">
                    <span className="text-[11px] font-semibold w-20 capitalize">{q.kind}</span>
                    <Stat label="Depth" value={String(q.depth)} compact />
                    <Stat label="Submitted" value={String(q.submitted)} compact />
                    <Stat label="Completed" value={String(q.completed)} compact />
                    <Stat label="Avg ms" value={String(q.average_scan_duration_ms)} compact />
                    <span className={`text-[10px] px-2 py-0.5 rounded-full ${
                      q.pressure === "normal" ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
                        : q.pressure === "saturated" ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                        : "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]"
                    }`}>{q.pressure}</span>
                  </div>
                ))}
              </div>
              {orch.workers && (
                <div className="mt-4 space-y-2">
                  <p className="text-[10px] text-[rgb(var(--t3))] font-semibold uppercase tracking-wider">Workers</p>
                  {(orch.workers as any[]).map((w: any) => (
                    <div key={w.id} className="flex items-center gap-3 px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/8 text-[11px]">
                      <span className="font-mono w-24 text-[rgb(var(--t2))]">{w.id}</span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] ${
                        w.state === "ready" ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
                          : w.state === "busy" ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]"
                          : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                      }`}>{w.state}</span>
                      <span className="text-[rgb(var(--t3))]">jobs: {w.completed_jobs}</span>
                      <span className="text-[rgb(var(--t3))]">last: {w.last_duration_ms}ms</span>
                      <span className="text-[rgb(var(--t3))]">longest: {w.longest_duration_ms}ms</span>
                      {w.crash_count > 0 && <span className="text-[rgb(var(--red))]">crashes: {w.crash_count}</span>}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {/* Scan Cache */}
          <Card>
            <SectionHead icon={<Database size={15} />} title="Scan Cache" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="Cache Hits" value={String(d.cache_hits ?? 0)} color="green" />
              <Stat label="Cache Misses" value={String(d.cache_misses ?? 0)} />
              <Stat label="Entries" value={String(d.cache_entries ?? 0)} />
              <Stat label="Hit Rate" value={
                (d.cache_hits as number ?? 0) + (d.cache_misses as number ?? 0) > 0
                  ? `${Math.round(((d.cache_hits as number ?? 0) / ((d.cache_hits as number ?? 0) + (d.cache_misses as number ?? 0))) * 100)}%`
                  : "—"
              } color="green" />
            </div>
          </Card>

          {/* Watcher */}
          <Card>
            <SectionHead icon={<Eye size={15} />} title="Real-time Watcher" />
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 mt-4">
              <Stat label="Active" value={(d.watcher_active as boolean) ? "Yes" : "No"} color={(d.watcher_active as boolean) ? "green" : "amber"} />
              <Stat label="Mode" value={String(d.watcher_mode ?? "?")} />
            </div>
          </Card>

          {/* Generated at */}
          <p className="text-[10px] text-[rgb(var(--t3))]/30 text-right">
            Generated: {d.generated_at as string ?? "?"}
          </p>
        </>
      )}
    </div>
  );
}

function SectionHead({ icon, title, sub }: { icon: React.ReactNode; title: string; sub?: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]">
        {icon}
      </div>
      <div>
        <h4 className="text-[13px] font-semibold">{title}</h4>
        {sub && <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

function DiagTile({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  const palette = `var(--${color})`;
  return (
    <div className="glass-card flex flex-col gap-2 px-5 py-4 h-full">
      <div className="flex items-center gap-2.5">
        <div className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md"
          style={{ background: `rgba(${palette}, 0.08)`, color: `rgb(${palette})` }}>
          {icon}
        </div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: `rgba(${palette}, 0.65)` }}>{label}</p>
      </div>
      <p className="text-[22px] font-bold leading-tight text-[rgb(var(--t1))] capitalize">{value}</p>
    </div>
  );
}

function Stat({ label, value, color, compact }: { label: string; value: string; color?: string; compact?: boolean }) {
  if (compact) {
    return (
      <div className="text-center">
        <span className="text-[10px] text-[rgb(var(--t3))]">{label}: </span>
        <span className="text-[11px] font-semibold text-[rgb(var(--t1))]">{value}</span>
      </div>
    );
  }
  const c = color === "green" ? "var(--green)" : color === "red" ? "var(--red)" : color === "amber" ? "var(--amber)" : undefined;
  return (
    <div>
      <p className="text-[10px] text-[rgb(var(--t3))] mb-1">{label}</p>
      <p className="text-[14px] font-semibold" style={c ? { color: `rgb(${c})` } : undefined}>{value}</p>
    </div>
  );
}

import { useState, useEffect } from "react";
import { Activity, Eye, Shield, AlertTriangle, Zap, GitBranch, TrendingUp, Clock } from "lucide-react";
import { Card } from "../components/Card";
import { getRuntimeIntelligence, getTrustStatus } from "../api/sentinella";
import { useDaemonContext } from "../hooks/DaemonContext";
import type { RuntimeIntelligenceStatus, TrustGraphStatus, EcosystemSummary, ConvergenceAttribution, EcosystemTimelineEvent } from "../types/sentinella";

export function IntelligencePage() {
  const { connected } = useDaemonContext();
  const [ri, setRi] = useState<RuntimeIntelligenceStatus | null>(null);
  const [ts, setTs] = useState<TrustGraphStatus | null>(null);

  useEffect(() => {
    if (!connected) return;
    const load = () => {
      getRuntimeIntelligence().then(setRi).catch(() => {});
      getTrustStatus().then(setTs).catch(() => {});
    };
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [connected]);

  if (!connected) {
    return (
      <div className="page-stack">
        <Card className="text-center py-14">
          <p className="text-[14px] text-[rgb(var(--t2))]">Connect to daemon to view intelligence status.</p>
        </Card>
      </div>
    );
  }

  const plm = ri?.plm;
  const ps = ri?.powershell;
  const eco = (ri as any)?.ecosystem;
  const drifts = ts?.recent_drift_events ?? [];

  return (
    <div className="page-stack">
      {/* Header */}
      <Card>
        <div className="flex items-center gap-4 mb-1">
          <div className="w-10 h-10 rounded-xl bg-[rgb(var(--accent))]/8 flex items-center justify-center">
            <Activity size={18} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h3 className="text-[18px] font-bold">ASTRA Adaptive Analysis</h3>
            <p className="text-[12px] text-[rgb(var(--t3))] mt-0.5">
              Contextual behavioral intelligence · local-first · explainable
            </p>
          </div>
        </div>
      </Card>

      {/* Status grid */}
      <div className="card-grid-2">
        {/* PLM */}
        <Card>
          <SectionHead icon={<GitBranch size={14} />} title="Process Lineage Monitor" />
          <div className="grid grid-cols-2 gap-4 mt-3">
            <Stat label="Mode" value={plm?.mode === "Etw" ? "ETW Realtime" : "Snapshot"} color={plm?.etw_running ? "green" : "accent"} />
            <Stat label="Graph nodes" value={plm?.nodes ?? 0} />
            <Stat label="Events seen" value={plm?.events_seen ?? 0} />
            <Stat label="Suspicious chains" value={plm?.suspicious_chains ?? 0} color={(plm?.suspicious_chains ?? 0) > 0 ? "amber" : undefined} />
          </div>
          {plm?.etw_running && (
            <p className="text-[10px] text-[rgb(var(--green))]/60 mt-3">Real-time process creation monitoring via ETW kernel events</p>
          )}
          {!plm?.etw_running && plm?.enabled && (
            <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-3">Snapshot polling mode — run as admin for ETW realtime</p>
          )}
        </Card>

        {/* PowerShell Runtime */}
        <Card>
          <SectionHead icon={<Zap size={14} />} title="PowerShell Runtime" />
          <div className="grid grid-cols-2 gap-4 mt-3">
            <Stat label="Status" value={ps?.enabled ? "Active" : "Disabled"} color={ps?.enabled ? "green" : undefined} />
            <Stat label="SBL" value={ps?.sbl_available ? "Available" : "Unavailable"} />
            <Stat label="Buffers scanned" value={ps?.events_scanned ?? 0} />
            <Stat label="Last score" value={ps?.last_score ?? 0} color={(ps?.last_score ?? 0) >= 50 ? "amber" : undefined} />
          </div>
          {!ps?.enabled && (
            <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-3">Enable in sentinelld.toml: powershell_bridge_enabled = true</p>
          )}
        </Card>
      </div>

      {/* Trust Graph + Ecosystems */}
      <div className="card-grid-2">
        {/* Trust Graph */}
        <Card>
          <SectionHead icon={<Shield size={14} />} title="Behavioral Memory" />
          <div className="grid grid-cols-2 gap-4 mt-3">
            <Stat label="Known entities" value={ts?.nodes ?? 0} />
            <Stat label="Stable" value={ts?.stable_nodes ?? 0} color="green" />
            <Stat label="Rare" value={ts?.rare_nodes ?? 0} color={(ts?.rare_nodes ?? 0) > 10 ? "amber" : undefined} />
            <Stat label="Stale" value={ts?.stale_nodes ?? 0} />
          </div>
          <div className="grid grid-cols-2 gap-4 mt-3">
            <Stat label="Drift events" value={ts?.drift_events_total ?? 0} color={(ts?.drift_events_total ?? 0) > 0 ? "amber" : undefined} />
            <Stat label="Drifts today" value={ts?.drift_events_24h ?? 0} color={(ts?.drift_events_24h ?? 0) > 0 ? "amber" : undefined} />
          </div>
          {(ts?.nodes ?? 0) === 0 && (
            <EmptyState message="No entities observed yet. ASTRA learns as files are scanned." />
          )}
        </Card>

        {/* Ecosystems */}
        <Card>
          <SectionHead icon={<Eye size={14} />} title="Behavioral Ecosystems" />
          <div className="grid grid-cols-3 gap-4 mt-3">
            <Stat label="Active" value={eco?.active ?? eco?.active_ecosystems ?? 0} />
            <Stat label="Cooling" value={eco?.cooling ?? 0} />
            <Stat label="Recurring" value={eco?.recurring ?? 0} color={(eco?.recurring ?? 0) > 0 ? "accent" : undefined} />
          </div>
          <div className="grid grid-cols-3 gap-4 mt-3">
            <Stat label="Suspicious" value={eco?.suspicious ?? 0} color={(eco?.suspicious ?? 0) > 0 ? "amber" : undefined} />
            <Stat label="High severity" value={eco?.high_severity ?? 0} color={(eco?.high_severity ?? 0) > 0 ? "red" : undefined} />
            <Stat label="Pruned" value={eco?.pruned ?? 0} />
          </div>
          {(eco?.active_ecosystems ?? 0) === 0 && (
            <EmptyState message="No behavioral ecosystems formed yet. Correlated evidence creates ecosystems automatically." />
          )}
        </Card>
      </div>

      {/* Active suspicious ecosystems with timelines */}
      {eco?.recent_suspicious?.length > 0 && (
        <Card>
          <SectionHead icon={<AlertTriangle size={14} />} title="Active Suspicious Ecosystems" />
          <div className="space-y-4 mt-3">
            {eco.recent_suspicious.slice(0, 3).map((e: EcosystemSummary, i: number) => (
              <EcosystemCard key={i} eco={e} />
            ))}
          </div>
        </Card>
      )}

      {/* Drift events feed */}
      {drifts.length > 0 && (
        <Card>
          <SectionHead icon={<AlertTriangle size={14} />} title="Recent Behavioral Drift" />
          <div className="space-y-2 mt-3">
            {drifts.slice(0, 8).map((d, i) => (
              <div key={i} className="flex items-start gap-3 py-2 px-3 rounded-lg bg-[rgb(var(--amber))]/3">
                <span className="text-[rgb(var(--amber))] font-bold text-[12px] flex-shrink-0 w-6 text-right">+{d.weight}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] text-[rgb(var(--t1))]">{d.explanation}</p>
                  <p className="text-[9px] text-[rgb(var(--t3))]/50 mt-0.5 truncate">{d.entity}</p>
                </div>
                <div className="flex-shrink-0 text-right">
                  <span className="text-[9px] text-[rgb(var(--t3))]/40">{d.type}</span>
                  <p className="text-[9px] text-[rgb(var(--t3))]/30">
                    {new Date(d.timestamp * 1000).toLocaleTimeString()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Runtime events feed */}
      {(ps?.recent_events?.length ?? 0) > 0 && (
        <Card>
          <SectionHead icon={<Zap size={14} />} title="Recent Runtime Events" />
          <div className="space-y-1.5 mt-3">
            {ps!.recent_events.slice(-8).reverse().map((evt, i) => (
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
                  <span className="text-[10px] text-[rgb(var(--accent))]/60 truncate max-w-[150px]" title={evt.lineage_summary}>
                    {evt.lineage_summary}
                  </span>
                )}
                <span className="text-[9px] text-[rgb(var(--green))]/50 flex-shrink-0">observe</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Footer */}
      <p className="text-center text-[10px] text-[rgb(var(--t3))]/20">
        ARGUS powered by ASTRA adaptive analysis · local-first · no cloud · no telemetry
      </p>
    </div>
  );
}

// ── Ecosystem Card with Timeline + Attribution ──────────────

function EcosystemCard({ eco }: { eco: EcosystemSummary }) {
  const actor = eco.root?.split('\\').pop() || eco.root;
  const severityColor = eco.severity === "Critical" ? "red" : eco.severity === "High" ? "amber" : "accent";
  const stateLabel = eco.state?.replace("Active", "Active").replace("Cooling", "Cooling") || "Active";

  return (
    <div className="rounded-xl bg-[rgb(var(--raised))]/5 px-4 py-3">
      {/* Header: actor + severity badge + state */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[12px] font-semibold text-[rgb(var(--t1))] truncate">{actor}</span>
          <SeverityBadge severity={eco.severity} />
          <StateBadge state={stateLabel} />
          {eco.recurrence_count > 0 && (
            <span className="text-[9px] font-bold text-[rgb(var(--accent))] bg-[rgb(var(--accent))]/8 px-1.5 py-0.5 rounded-full">
              {eco.recurrence_count}x recurring
            </span>
          )}
        </div>
        <span className={`text-[11px] font-bold text-[rgb(var(--${severityColor}))]`}>
          +{eco.escalation}
        </span>
      </div>

      {/* Narrative */}
      <p className="text-[11px] text-[rgb(var(--t2))] leading-relaxed mb-2">{eco.narrative}</p>

      {/* Timeline */}
      {eco.timeline && eco.timeline.length > 0 && (
        <div className="mb-2">
          <div className="flex items-center gap-1.5 mb-1.5">
            <Clock size={10} className="text-[rgb(var(--t3))]/40" />
            <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-[rgb(var(--t3))]/40">
              Timeline
            </p>
          </div>
          <div className="space-y-1 pl-3 border-l border-[rgb(var(--t3))]/8">
            {eco.timeline.slice(-5).map((t: EcosystemTimelineEvent, i: number) => (
              <div key={i} className="flex items-start gap-2">
                <span className="text-[9px] text-[rgb(var(--t3))]/40 flex-shrink-0 w-12">
                  {new Date(t.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
                <span className="text-[10px] text-[rgb(var(--t2))] flex-1">{t.description}</span>
                <span className="text-[9px] text-[rgb(var(--t3))]/30 flex-shrink-0">+{t.weight}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attribution */}
      {eco.attribution && <AttributionBar attr={eco.attribution} />}

      {/* Meta */}
      <p className="text-[9px] text-[rgb(var(--t3))]/30 mt-1">
        {eco.evidence_count} evidence sources · {eco.escalation_count} escalation{eco.escalation_count !== 1 ? "s" : ""}
      </p>
    </div>
  );
}

// ── Convergence Attribution Bar ─────────────────────────────

function AttributionBar({ attr }: { attr: ConvergenceAttribution }) {
  return (
    <div className="rounded-lg bg-[rgb(var(--base))]/40 px-3 py-2 mb-1">
      <div className="flex items-center gap-1.5 mb-1.5">
        <TrendingUp size={10} className="text-[rgb(var(--accent))]/60" />
        <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-[rgb(var(--t3))]/40">
          Convergence Attribution
        </p>
      </div>
      <div className="flex items-center gap-3 text-[10px]">
        <AttrItem label="Base" value={attr.base_argus} />
        {attr.trust_adjustment !== 0 && (
          <AttrItem
            label="Trust"
            value={attr.trust_adjustment}
            color={attr.trust_adjustment < 0 ? "green" : "amber"}
            signed
          />
        )}
        {attr.drift_escalation > 0 && (
          <AttrItem label="Drift" value={attr.drift_escalation} color="amber" signed />
        )}
        {attr.ecosystem_escalation > 0 && (
          <AttrItem label="Ecosystem" value={attr.ecosystem_escalation} color="amber" signed />
        )}
        {attr.recurrence_bonus > 0 && (
          <AttrItem label="Recurrence" value={attr.recurrence_bonus} color="accent" signed />
        )}
        <span className="text-[rgb(var(--t3))]/30 mx-1">=</span>
        <span className="font-bold text-[rgb(var(--t1))]">{attr.final_convergence}</span>
      </div>
    </div>
  );
}

function AttrItem({ label, value, color, signed }: { label: string; value: number; color?: string; signed?: boolean }) {
  const c = color === "green" ? "var(--green)" : color === "amber" ? "var(--amber)" : color === "accent" ? "var(--accent)" : "var(--t2)";
  const prefix = signed && value > 0 ? "+" : "";
  return (
    <span style={{ color: `rgb(${c})` }}>
      <span className="text-[rgb(var(--t3))]/40 mr-0.5">{label}</span>
      <span className="font-semibold">{prefix}{value}</span>
    </span>
  );
}

// ── Badges ──────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    Critical: "var(--red)",
    High: "var(--amber)",
    Medium: "var(--accent)",
    Low: "var(--t3)",
  };
  const c = colors[severity] || "var(--t3)";
  return (
    <span
      className="text-[9px] font-bold px-1.5 py-0.5 rounded-full"
      style={{ color: `rgb(${c})`, background: `rgb(${c} / 0.1)` }}
    >
      {severity}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const isActive = state === "Active";
  return (
    <span className={`text-[8px] font-semibold px-1.5 py-0.5 rounded-full uppercase tracking-wider ${
      isActive
        ? "text-[rgb(var(--green))]/60 bg-[rgb(var(--green))]/5"
        : "text-[rgb(var(--t3))]/40 bg-[rgb(var(--t3))]/5"
    }`}>
      {state}
    </span>
  );
}

// ── Shared components ───────────────────────────────────────

function EmptyState({ message }: { message: string }) {
  return (
    <p className="text-[10px] text-[rgb(var(--t3))]/30 mt-3 italic">{message}</p>
  );
}

function SectionHead({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[rgb(var(--accent))]/8">
        <span className="text-[rgb(var(--accent))]">{icon}</span>
      </div>
      <h4 className="text-[13px] font-semibold">{title}</h4>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  const c = color === "green" ? "var(--green)" : color === "amber" ? "var(--amber)" : color === "red" ? "var(--red)" : color === "accent" ? "var(--accent)" : "var(--t1)";
  return (
    <div>
      <p className="text-[16px] font-bold" style={{ color: `rgb(${c})` }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{label}</p>
    </div>
  );
}

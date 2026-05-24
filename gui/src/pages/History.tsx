import { useState, useEffect } from "react";
import {
  AlertTriangle, ArrowLeft, CheckCircle, ChevronDown, ChevronUp,
  Clock, Download, Eye, Loader2, Search, Shield, WifiOff, XCircle,
} from "lucide-react";
import { Card } from "../components/Card";
import { getScanHistory, getDetections, getArgusVerdicts, exportScanReport, type DetectionEntry } from "../api/sentinella";
import type { ScanRecord, ArgusVerdictRecord, ArgusFinding } from "../types/sentinella";
import { t } from "../i18n";

type View = { k: "list" } | { k: "detail"; scan: ScanRecord };

export function HistoryPage() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "threats">("all");
  const [search, setSearch] = useState("");
  const [view, setView] = useState<View>({ k: "list" });
  const [pageSize, setPageSize] = useState(50);

  useEffect(() => {
    getScanHistory()
      .then((r) => { setRecords(r); setErr(null); })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin" /></div>;
  if (err) return <Card className="text-center py-10"><WifiOff size={20} className="mx-auto text-[rgb(var(--amber))] mb-3" /><p className="text-[13px] text-[rgb(var(--t3))]">{t("history.daemon_error")}</p></Card>;

  if (view.k === "detail") {
    return <ScanDetail scan={view.scan} onBack={() => setView({ k: "list" })} />;
  }

  const filtered = records.filter((r) => {
    if (filter === "threats" && r.threats_found === 0) return false;
    if (search && !r.scan_type.includes(search.toLowerCase()) && !r.scan_id.includes(search)) return false;
    return true;
  });

  return (
    <div className="page-stack">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[rgb(var(--surface))] border border-[rgb(var(--border))]/12 flex-1 max-w-[280px]">
          <Search size={14} className="text-[rgb(var(--t3))]/30" />
          <input type="text" placeholder={t("history.search")} value={search} onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent text-[13px] outline-none w-full text-[rgb(var(--t1))] placeholder:text-[rgb(var(--t3))]/25" />
        </div>
        {(["all", "threats"] as const).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`text-[12px] font-medium px-4 py-2.5 rounded-xl border cursor-pointer capitalize ${filter === f
              ? "border-[rgb(var(--accent))]/15 text-[rgb(var(--accent))] bg-[rgb(var(--accent))]/5"
              : "border-[rgb(var(--border))]/12 text-[rgb(var(--t3))] bg-[rgb(var(--surface))]"
            }`}>{f === "threats" ? t("history.with_threats") : t("history.all")}</button>
        ))}
        <span className="text-[11px] text-[rgb(var(--t3))]/25 md:ml-auto">{records.length} {t("history.total")}</span>
        <button onClick={async () => {
          try {
            const report = await exportScanReport();
            // Create downloadable blob.
            const json = JSON.stringify(report, null, 2);
            const blob = new Blob([json], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `sentinella-report-${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
          } catch {}
        }} className="flex items-center gap-1.5 text-[11px] text-[rgb(var(--accent))] hover:underline cursor-pointer">
          <Download size={12} /> {t("history.export")}
        </button>
      </div>

      {/* Results */}
      {filtered.length === 0 ? (
        <Card className="text-center py-12">
          <Clock size={28} className="mx-auto text-[rgb(var(--t3))]/15 mb-3" />
          <p className="text-[14px] font-medium text-[rgb(var(--t2))]">{records.length === 0 ? t("history.no_scans") : t("history.no_matching")}</p>
        </Card>
      ) : (
        <Card>
          <div className="space-y-2">
            {filtered.slice(0, pageSize).map((r) => (
              <button key={r.scan_id} onClick={() => setView({ k: "detail", scan: r })}
                className="flex items-center gap-4 px-4 py-3.5 rounded-xl bg-[rgb(var(--raised))]/12 hover:bg-[rgb(var(--raised))]/22 transition-colors w-full text-left cursor-pointer"
              >
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${r.threats_found > 0 ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]" : r.status === "cancelled" ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]" : "bg-[rgb(var(--green))]/6 text-[rgb(var(--green))]"}`}>
                  {r.threats_found > 0 ? <AlertTriangle size={15} /> : r.status === "cancelled" ? <XCircle size={15} /> : <CheckCircle size={15} />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-semibold capitalize">{r.scan_type} {t("history.scan_suffix")}</p>
                  <p className="text-[11px] text-[rgb(var(--t3))]/40 mt-0.5">{new Date(r.started_at * 1000).toLocaleString()}</p>
                </div>
                <p className="text-[13px] font-medium text-[rgb(var(--t2))]">{r.files_scanned} {t("history.files")}</p>
                <p className="text-[13px] font-medium w-[55px] text-right">{Math.floor(r.duration_ms / 1000)}s</p>
                <p className={`text-[13px] font-semibold w-[80px] text-right ${r.threats_found > 0 ? "text-[rgb(var(--red))]" : r.status === "cancelled" ? "text-[rgb(var(--amber))]" : "text-[rgb(var(--green))]"}`}>
                  {r.threats_found > 0 ? `${r.threats_found} ${r.threats_found > 1 ? t("history.threats") : t("history.threat")}` : r.status === "cancelled" ? t("history.cancelled") : t("history.clean")}
                </p>
              </button>
            ))}
          </div>
          {filtered.length > pageSize && (
            <button
              onClick={() => setPageSize((s) => s + 50)}
              className="mt-4 w-full py-3 text-[12px] text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/5 rounded cursor-pointer transition-colors"
            >
              {t("history.load_more")} ({filtered.length - pageSize} {t("history.remaining")})
            </button>
          )}
        </Card>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Scan Detail — drill-down view
   ═══════════════════════════════════════════════════════════════ */

const SEV_COLORS: Record<string, string> = {
  critical: "var(--red)", high: "var(--red)", medium: "var(--amber)",
  low: "var(--accent)", info: "var(--t3)",
};

const LAYER_KEYS: Record<string, string> = {
  signatures: "history.layer_signatures", yara_rules: "history.layer_yara",
  mime_validation: "history.layer_mime", structural_analysis: "history.layer_structural",
  packer_detection: "history.layer_packer", script_analysis: "history.layer_script",
  ioc_correlation: "history.layer_ioc", pattern_detection: "history.layer_pattern",
  file_deception: "history.layer_deception",
  reputation: "history.layer_reputation",
  context: "history.layer_context",
};

function ScanDetail({ scan, onBack }: { scan: ScanRecord; onBack: () => void }) {
  const [detections, setDetections] = useState<DetectionEntry[]>([]);
  const [verdicts, setVerdicts] = useState<ArgusVerdictRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getDetections(scan.scan_id).catch(() => []),
      getArgusVerdicts(scan.scan_id).catch(() => []),
    ]).then(([dets, vds]) => {
      setDetections(dets);
      setVerdicts(vds);
    }).finally(() => setLoading(false));
  }, [scan.scan_id]);

  const statusColor = scan.threats_found > 0 ? "red" : scan.status === "cancelled" ? "amber" : "green";
  const cv = `var(--${statusColor})`;
  const started = new Date(scan.started_at * 1000);
  const finished = scan.finished_at ? new Date(scan.finished_at * 1000) : null;

  return (
    <div className="page-stack">
      {/* Back button */}
      <button onClick={onBack}
        className="flex items-center gap-2 text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--t1))] cursor-pointer transition-colors self-start">
        <ArrowLeft size={14} /> {t("history.back")}
      </button>

      {/* Summary card */}
      <Card className={`border-[rgb(${cv})]/12`}>
        <div className="flex items-start gap-5">
          <div className="flex h-14 w-14 flex-shrink-0 items-center justify-center rounded"
            style={{ background: `rgba(${cv}, 0.08)`, color: `rgb(${cv})` }}>
            {scan.threats_found > 0 ? <AlertTriangle size={24} /> : scan.status === "cancelled" ? <XCircle size={24} /> : <Shield size={24} />}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-[20px] font-bold capitalize">{scan.scan_type} {t("history.scan_suffix")}</h3>
            <p className="text-[13px] text-[rgb(var(--t3))] mt-1">
              {started.toLocaleString()}
              {finished && ` — ${Math.floor(scan.duration_ms / 1000)}s ${t("history.duration_suffix")}`}
            </p>
          </div>
          <div className="text-right">
            <p className="text-[24px] font-bold" style={{ color: `rgb(${cv})` }}>
              {scan.threats_found > 0 ? scan.threats_found : scan.status === "cancelled" ? "—" : "0"}
            </p>
            <p className="text-[11px] text-[rgb(var(--t3))] mt-1">
              {scan.threats_found > 0 ? t("history.threats_found") : scan.status === "cancelled" ? t("history.status_cancelled") : t("history.threats_found")}
            </p>
          </div>
        </div>

        {/* Metadata grid */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mt-6">
          <MetaBox label={t("history.files_scanned")} value={scan.files_scanned.toLocaleString()} />
          <MetaBox label={t("history.duration")} value={`${(scan.duration_ms / 1000).toFixed(1)}s`} />
          <MetaBox label={t("history.errors")} value={String(scan.errors_count)} />
          <MetaBox label={t("history.scan_id")} value={scan.scan_id.slice(0, 8)} title={scan.scan_id} />
        </div>
      </Card>

      {loading && (
        <div className="flex items-center justify-center py-8">
          <Loader2 size={18} className="text-[rgb(var(--accent))] animate-spin" />
        </div>
      )}

      {/* Detections */}
      {!loading && detections.length > 0 && (
        <Card>
          <h4 className="text-[15px] font-semibold mb-4">{t("history.detections")}</h4>
          <div className="space-y-2">
            {detections.map((d) => (
              <div key={d.detection_id} className="flex items-center gap-3 rounded-xl bg-[rgb(var(--red))]/5 px-4 py-3">
                <AlertTriangle size={15} className="text-[rgb(var(--red))] flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-semibold text-[rgb(var(--red))]">{d.virus_name}</p>
                  <p className="text-[11px] text-[rgb(var(--t3))] truncate mt-0.5" title={d.path}>{shortenPath(d.path)}</p>
                </div>
                <span className="text-[10px] text-[rgb(var(--t3))]">{new Date(d.detected_at * 1000).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ARGUS Verdicts */}
      {!loading && verdicts.length > 0 && (
        <Card>
          <div className="flex items-center gap-3 mb-5">
            <Eye size={16} className="text-[rgb(var(--accent))]" />
            <div>
              <h4 className="text-[15px] font-semibold">{t("history.argus_results")}</h4>
              <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">{t("history.files_analyzed").replace("{count}", String(verdicts.length))}</p>
            </div>
          </div>
          <div className="space-y-3">
            {verdicts
              .sort((a, b) => b.score - a.score)
              .map((v, i) => <VerdictRow key={i} v={v} />)
            }
          </div>
        </Card>
      )}

      {/* Empty state */}
      {!loading && detections.length === 0 && verdicts.length === 0 && (
        <Card className="text-center py-10">
          <CheckCircle size={24} className="mx-auto text-[rgb(var(--green))]/40 mb-3" />
          <p className="text-[13px] text-[rgb(var(--t3))]">{t("history.no_analysis")}</p>
        </Card>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   ARGUS Verdict Row — expandable forensic detail
   ═══════════════════════════════════════════════════════════════ */

function VerdictRow({ v }: { v: ArgusVerdictRecord }) {
  const [expanded, setExpanded] = useState(false);
  const findings: ArgusFinding[] = (() => {
    try { return JSON.parse(v.findings_json); } catch { return []; }
  })();

  const vColor = v.score >= 76 ? "var(--red)" : v.score >= 51 ? "var(--amber)" : v.score >= 26 ? "var(--amber)" : v.score > 0 ? "var(--accent)" : "var(--green)";

  return (
    <div className="rounded-xl border border-[rgb(var(--border))]/8 overflow-hidden">
      <button onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-3 w-full px-4 py-3 text-left hover:bg-[rgb(var(--raised))]/15 transition-colors cursor-pointer"
      >
        {/* Score badge */}
        <div className="flex h-8 w-8 items-center justify-center rounded-lg text-[11px] font-bold flex-shrink-0"
          style={{ background: `rgba(${vColor}, 0.1)`, color: `rgb(${vColor})` }}>
          {v.score}
        </div>
        {/* File info */}
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-medium truncate" title={v.path}>{shortenPath(v.path)}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] text-[rgb(var(--t3))]">{v.verdict}</span>
            {v.mime_type && <span className="text-[10px] text-[rgb(var(--t3))]/40">{v.mime_type}</span>}
            <span className="text-[10px] text-[rgb(var(--t3))]/40">{formatBytes(v.file_size)}</span>
          </div>
        </div>
        {/* Finding count */}
        {findings.length > 0 && (
          <span className="text-[10px] text-[rgb(var(--t3))] px-2 py-0.5 rounded bg-[rgb(var(--raised))]/20">
            {findings.length} {findings.length > 1 ? t("history.findings") : t("history.finding")}
          </span>
        )}
        {findings.length > 0 && (expanded ? <ChevronUp size={14} className="text-[rgb(var(--t3))]" /> : <ChevronDown size={14} className="text-[rgb(var(--t3))]" />)}
      </button>

      {expanded && findings.length > 0 && (
        <div className="border-t border-[rgb(var(--border))]/8 px-4 py-3 space-y-2 bg-[rgb(var(--raised))]/5">
          {/* File metadata */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-2 mb-3">
            <MiniMeta label={t("history.sha256")} value={v.sha256.slice(0, 16) + "..."} title={v.sha256} />
            <MiniMeta label={t("history.analysis_time")} value={`${(v.analysis_time_us / 1000).toFixed(1)}ms`} />
            <MiniMeta label={t("history.engine")} value={`ARGUS ${v.engine_version}`} />
            <MiniMeta label={t("history.analyzed")} value={new Date(v.timestamp * 1000).toLocaleTimeString()} />
          </div>

          {/* Findings */}
          {findings.map((f, i) => {
            const sevColor = SEV_COLORS[f.severity] ?? "var(--t3)";
            return (
              <div key={i} className="flex items-start gap-3 rounded-lg px-3 py-2.5 bg-[rgb(var(--raised))]/15">
                <div className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded text-[9px] font-bold"
                  style={{ background: `rgba(${sevColor}, 0.1)`, color: `rgb(${sevColor})` }}>
                  +{f.weight}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] leading-relaxed">{f.description}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))]">
                      {LAYER_KEYS[f.layer] ? t(LAYER_KEYS[f.layer]) : f.layer}
                    </span>
                    <span className="text-[9px] font-semibold uppercase" style={{ color: `rgb(${sevColor})` }}>
                      {f.severity}
                    </span>
                  </div>
                  {f.technical_detail && (
                    <p className="text-[9px] text-[rgb(var(--t3))]/40 mt-1 font-mono break-all">{f.technical_detail}</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Utilities
   ═══════════════════════════════════════════════════════════════ */

function MetaBox({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="rounded-xl bg-[rgb(var(--raised))]/15 px-3.5 py-2.5">
      <p className="text-[10px] text-[rgb(var(--t3))] uppercase tracking-wider">{label}</p>
      <p className="text-[13px] font-semibold mt-1 truncate" title={title}>{value}</p>
    </div>
  );
}

function MiniMeta({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="rounded-lg bg-[rgb(var(--raised))]/10 px-2.5 py-1.5">
      <p className="text-[9px] text-[rgb(var(--t3))]/50 uppercase tracking-wider">{label}</p>
      <p className="text-[10px] font-medium mt-0.5 truncate" title={title}>{value}</p>
    </div>
  );
}

function shortenPath(path: string): string {
  const parts = path.split(/[/\\]/);
  if (parts.length <= 3) return path;
  return "..." + parts.slice(-3).join("\\");
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`;
}

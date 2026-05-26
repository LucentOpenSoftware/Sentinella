import { useState, useEffect, useRef } from "react";
import { FileSearch, Zap, CheckCircle, AlertTriangle, Loader2, ShieldCheck, ShieldAlert, XCircle, WifiOff, Square, Eye, ChevronDown, ChevronUp, Search } from "lucide-react";
import { ShieldIcon } from "../components/ShieldIcon";
import { open } from "@tauri-apps/plugin-dialog";
import { Card } from "../components/Card";
import { scanFile, scanFolder, startQuickScan, startFullScan, startStartupScan, getScanStatus, cancelScan, getScanHistory, notifyThreat, quarantineFile, notifyQuarantine } from "../api/sentinella";
import { FolderOpen, HardDrive, RotateCcw } from "lucide-react";
import type { FileScanResponse, ScanRecord, ScanStatusResponse, EngineStatus, ArgusVerdict, ArgusFinding } from "../types/sentinella";
import { t } from "../i18n";

type St = {k:"idle"}|{k:"picked";path:string}|{k:"scanning";path:string}|{k:"result";r:FileScanResponse;argus?:ArgusVerdict}|{k:"quick"}|{k:"error";msg:string};

export function ScanPage({ droppedFile, onConsumeDroppedFile, connected, engineStatus }: {
  droppedFile?: string | null;
  onConsumeDroppedFile?: () => string | null;
  connected?: boolean;
  engineStatus?: EngineStatus | null;
}) {
  const [st, setSt] = useState<St>({k:"idle"});
  const [ss, setSs] = useState<ScanStatusResponse|null>(null);
  const [hist, setHist] = useState<ScanRecord[]>([]);
  const poll = useRef<ReturnType<typeof setInterval>|null>(null);

  // Use shared connection state from parent (consistent with TopBar).
  // Falls back to own check if not provided (backward compat).
  const up = connected ?? true;
  const eng = engineStatus ?? null;

  useEffect(() => {
    getScanHistory().then(setHist).catch(() => {});
  }, [st.k]);

  // Handle dropped file from drag-and-drop.
  useEffect(() => {
    if (droppedFile && st.k === "idle" && onConsumeDroppedFile) {
      const file = onConsumeDroppedFile();
      if (file) {
        setSt({ k: "picked", path: file });
      }
    }
  }, [droppedFile, st.k, onConsumeDroppedFile]);

  useEffect(() => {
    if (st.k === "quick") {
      const fn = () => getScanStatus().then(s => {
        setSs(s);
        if (!s.running && s.state !== "idle" && s.state !== "pending") {
          if (poll.current) clearInterval(poll.current);
          getScanHistory().then(setHist).catch(() => {});
        }
      }).catch(() => {});
      fn();
      poll.current = setInterval(fn, 2000); // was 500ms — reduced IPC load during scans
      return () => { if (poll.current) clearInterval(poll.current); };
    }
  }, [st.k]);

  const ready = up && eng?.state === "ready" && (eng?.signature_count ?? 0) > 0;
  const qQueued = st.k === "quick" && ss && (ss.state === "queued" || ss.state === "pending");
  const qCancelling = st.k === "quick" && ss?.state === "cancelling";
  const qr = st.k === "quick" && ss?.running && !qQueued && !qCancelling;
  const qd = st.k === "quick" && ss && !ss.running && ss.state !== "idle" && ss.state !== "queued" && ss.state !== "pending";

  return (
    <div className="page-stack">
      {!up && (
        <div className="flex items-center gap-3 px-5 py-3 rounded-xl bg-[rgb(var(--amber))]/6 border border-[rgb(var(--amber))]/10 text-[12px] text-[rgb(var(--amber))]">
          <WifiOff size={14} /> {t("scan.not_connected")}
        </div>
      )}

      {/* ── SCAN TYPES ── */}
      {(st.k === "idle" || st.k === "picked") && (
        <>
          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            <ScanTypeCard icon={<FileSearch size={22}/>} title={t("scan.file")} desc={t("scan.file_desc")} accent disabled={!ready}
              onClick={async () => { const p = await open({multiple:false,directory:false,title:t("scan.file")}); if (p) setSt({k:"picked",path:p as string}); }} />
            <ScanTypeCard icon={<Zap size={22}/>} title={t("scan.quick")} desc={t("scan.quick_desc")} disabled={!ready}
              onClick={async () => { try { await startQuickScan(); setSt({k:"quick"}); } catch(e) { setSt({k:"error",msg:String(e)}); }}} />
            <ScanTypeCard icon={<FolderOpen size={22}/>} title={t("scan.folder")} desc={t("scan.folder_desc")} disabled={!ready}
              onClick={async () => {
                const p = await open({multiple:false, directory:true, title:t("scan.folder")});
                if (p) { try { await scanFolder(p as string); setSt({k:"quick"}); } catch(e) { setSt({k:"error",msg:String(e)}); } }
              }} />
          </div>
          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            <ScanTypeCard icon={<HardDrive size={22}/>} title={t("scan.full")} desc={t("scan.full_desc")} disabled={!ready}
              onClick={async () => { try { await startFullScan(); setSt({k:"quick"}); } catch(e) { setSt({k:"error",msg:String(e)}); }}} />
            <ScanTypeCard icon={<RotateCcw size={22}/>} title={t("scan.startup")} desc={t("scan.startup_desc")} disabled={!ready}
              onClick={async () => { try { await startStartupScan(); setSt({k:"quick"}); } catch(e) { setSt({k:"error",msg:String(e)}); }}} />
          </div>
        </>
      )}

      {/* ── FILE PICKED ── */}
      {st.k === "picked" && (
        <Card>
          <div className="flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-[rgb(var(--accent))]/8 flex items-center justify-center flex-shrink-0">
              <FileSearch size={18} className="text-[rgb(var(--accent))]" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold">{t("scan.selected_file")}</p>
              <p className="text-[12px] text-[rgb(var(--t3))] truncate mt-0.5">{st.path}</p>
            </div>
            <button disabled={!ready} onClick={async () => {
              setSt({k:"scanning",path:st.path});
              try {
                const r = await scanFile(st.path);
                // Orchestrator owns queued scans; use shared scan.status polling.
                if (r.status === "queued") {
                  setSt({k:"quick"});
                  return;
                } else {
                  setSt({k:"result",r});
                  getScanHistory().then(setHist).catch(()=>{});
                  if (r.result?.infected) notifyThreat(r.result.virus_name || "Unknown", r.result.path);
                }
              }
              catch(e) { setSt({k:"error",msg:String(e)}); }
            }} className="px-5 py-2.5 bg-[rgb(var(--accent))] text-white rounded-xl text-[13px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-40 shadow-sm shadow-[rgb(var(--accent))]/10">
              {t("scan.now")}
            </button>
          </div>
        </Card>
      )}

      {/* ── SCANNING ── */}
      {st.k === "scanning" && (
        <Card><div className="flex items-center gap-4 py-2">
          <Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin" />
          <div className="flex-1 min-w-0"><p className="text-[14px] font-semibold">{t("scan.scanning")}</p><p className="text-[12px] text-[rgb(var(--t3))] truncate">{st.path}</p></div>
        </div></Card>
      )}

      {/* ── FILE RESULT ── */}
      {st.k === "result" && st.r.result && <FileResult r={st.r.result} argus={st.argus} onDismiss={() => setSt({k:"idle"})} onQuarantine={async () => {
        const r = st.r.result!;
        await quarantineFile(r.path, r.virus_name || "Unknown", st.r.job_id);
        notifyQuarantine(r.virus_name || "Unknown", r.path);
        setSt({k:"idle"});
        getScanHistory().then(setHist).catch(()=>{});
      }} />}

      {/* ── QUEUED (waiting for worker) ── */}
      {qQueued && ss && (
        <Card>
          <div className="flex items-center gap-4 py-2">
            <Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin" />
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold">{t("scan.queued")}</p>
              <p className="text-[12px] text-[rgb(var(--t3))]">{t("scan.queued_desc")}</p>
            </div>
            <button onClick={() => cancelScan().catch(()=>{})} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] hover:text-[rgb(var(--red))] cursor-pointer"><Square size={11}/>{t("scan.cancel")}</button>
          </div>
        </Card>
      )}

      {/* ── CANCELLING ── */}
      {qCancelling && ss && (
        <Card>
          <div className="flex items-center gap-4 py-2">
            <Loader2 size={20} className="text-[rgb(var(--amber))] animate-spin" />
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold text-[rgb(var(--amber))]">{t("scan.cancelling")}</p>
              <p className="text-[12px] text-[rgb(var(--t3))]">{ss.files_scanned.toLocaleString()} {t("scan.files_scanned_before_cancel")}</p>
            </div>
          </div>
        </Card>
      )}

      {/* ── QUICK SCAN RUNNING ── */}
      {qr && ss && (
        <>
          <Card className="border-[rgb(var(--accent))]/12">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="relative flex-shrink-0">
                  <ShieldIcon icon="scan" size={28} className="brightness-0 invert opacity-70" />
                  <Loader2 size={12} className="text-[rgb(var(--accent))] animate-spin absolute -bottom-0.5 -right-0.5" />
                </div>
                <div>
                  <p className="text-[15px] font-semibold">{ss.scan_type === "folder" ? t("scan.folder") : t("scan.quick")} {t("scan.running_suffix")}</p>
                  <p className="text-[12px] text-[rgb(var(--t3))] truncate max-w-[400px]">{ss.current_path || t("scan.starting")}</p>
                </div>
              </div>
              <button onClick={() => cancelScan().catch(()=>{})} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] hover:text-[rgb(var(--red))] cursor-pointer"><Square size={11}/>{t("scan.cancel")}</button>
            </div>
            {/* Progress bar */}
            {ss.files_total > 0 && (
              <div className="mb-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] text-[rgb(var(--t3))]">{ss.files_scanned.toLocaleString()} / {ss.files_total.toLocaleString()} {t("scan.files")}</span>
                  <span className="text-[13px] font-bold text-[rgb(var(--accent))]">{ss.progress_percent < 1 && ss.progress_percent > 0 ? ss.progress_percent.toFixed(1) : Math.round(ss.progress_percent)}%</span>
                </div>
                <div className="w-full h-2 bg-[rgb(var(--raised))]/40 rounded-full overflow-hidden">
                  <div className="h-full bg-[rgb(var(--accent))] rounded-full transition-all duration-300" style={{ width: `${ss.progress_percent}%` }} />
                </div>
              </div>
            )}
            <div className="grid gap-5 text-center md:grid-cols-3">
              <div><p className="text-[24px] font-bold">{ss.files_scanned.toLocaleString()}</p><p className="text-[11px] text-[rgb(var(--t3))] mt-1">{t("scan.files_scanned")}</p></div>
              <div><p className={`text-[24px] font-bold ${ss.threats_found > 0 ? "text-[rgb(var(--red))]" : ""}`}>{ss.threats_found}</p><p className="text-[11px] text-[rgb(var(--t3))] mt-1">{t("scan.threats_found")}</p></div>
              <div><p className="text-[24px] font-bold">{ss.started_at ? `${Math.max(0, Math.floor(Date.now()/1000 - ss.started_at))}s` : "—"}</p><p className="text-[11px] text-[rgb(var(--t3))] mt-1">{t("scan.elapsed")}</p></div>
            </div>
          </Card>

          {/* Live threat feed — shows detections as they're found */}
          {ss.detections.length > 0 && (
            <Card className="border-[rgb(var(--red))]/10">
              <div className="flex items-center gap-3 mb-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[rgb(var(--red))]/8">
                  <AlertTriangle size={15} className="text-[rgb(var(--red))]" />
                </div>
                <div>
                  <h4 className="text-[14px] font-semibold">
                    {ss.detections.length} {t("scan.threats_detected")}
                  </h4>
                  <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">{t("scan.live_feed")}</p>
                </div>
              </div>
              <div className="space-y-2">
                {ss.detections.map((d, i) => {
                  const isArgus = d.virus_name.startsWith("ARGUS/");
                  const fileName = d.path.split(/[/\\]/).pop() || d.path;
                  const dirPath = d.path.split(/[/\\]/).slice(0, -1).join("\\");
                  return (
                    <div key={i} className="flex items-start gap-3 rounded-xl bg-[rgb(var(--raised))]/12 px-4 py-3 animate-in fade-in">
                      <div className={`mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg ${
                        isArgus ? "bg-[rgb(var(--amber))]/8" : "bg-[rgb(var(--red))]/8"
                      }`}>
                        {isArgus
                          ? <Eye size={14} className="text-[rgb(var(--amber))]" />
                          : <ShieldAlert size={14} className="text-[rgb(var(--red))]" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className={`text-[13px] font-semibold ${isArgus ? "text-[rgb(var(--amber))]" : "text-[rgb(var(--red))]"}`}>
                            {d.virus_name}
                          </p>
                          <span className={`text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                            isArgus
                              ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]"
                              : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                          }`}>
                            {isArgus ? t("scan.heuristic") : t("scan.signature")}
                          </span>
                        </div>
                        <p className="text-[12px] font-medium text-[rgb(var(--t1))] mt-1 truncate" title={d.path}>{fileName}</p>
                        <p className="text-[10px] text-[rgb(var(--t3))]/40 truncate" title={d.path}>{dirPath}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </>
      )}

      {/* ── SCAN COMPLETE — Full Report ── */}
      {qd && ss && <ScanReport ss={ss} onNewScan={() => { setSt({k:"idle"}); setSs(null); }} />}

      {/* ── ERROR ── */}
      {st.k === "error" && (
        <Card className="border-[rgb(var(--red))]/12"><div className="flex items-center gap-4"><XCircle size={18} className="text-[rgb(var(--red))]"/><div className="flex-1"><p className="text-[14px] font-semibold text-[rgb(var(--red))]">{t("scan.failed")}</p><p className="text-[12px] text-[rgb(var(--t3))]">{st.msg}</p></div><button onClick={() => setSt({k:"idle"})} className="px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] cursor-pointer">{t("scan.dismiss")}</button></div></Card>
      )}

      {/* ── RECENT SCANS ── */}
      <Card>
        <h4 className="text-[15px] font-semibold mb-5">{t("scan.recent")}</h4>
        {hist.length === 0 ? (
          <p className="text-[13px] text-[rgb(var(--t3))]/40 py-6 text-center">{t("scan.no_scans")}</p>
        ) : (
          <div className="space-y-2">
            {hist.slice(0,5).map(s => (
              <div key={s.scan_id} className="flex items-center gap-4 px-4 py-3 rounded-xl bg-[rgb(var(--raised))]/15 hover:bg-[rgb(var(--raised))]/25 transition-colors">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${s.threats_found > 0 ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]" : s.status === "cancelled" ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]" : "bg-[rgb(var(--green))]/6 text-[rgb(var(--green))]"}`}>
                  {s.threats_found > 0 ? <AlertTriangle size={14}/> : s.status === "cancelled" ? <XCircle size={14}/> : <CheckCircle size={14}/>}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-medium capitalize">{s.scan_type} {t("scan.scan_suffix")}</p>
                  <p className="text-[11px] text-[rgb(var(--t3))]/40">{new Date(s.started_at * 1000).toLocaleString()}</p>
                </div>
                <p className="text-[13px] font-medium">{s.files_scanned} {t("scan.files")}</p>
                <p className={`text-[13px] font-semibold min-w-[60px] text-right ${s.threats_found > 0 ? "text-[rgb(var(--red))]" : s.status === "cancelled" ? "text-[rgb(var(--amber))]" : "text-[rgb(var(--green))]"}`}>
                  {s.threats_found > 0 ? `${s.threats_found} ${s.threats_found > 1 ? t("scan.threats_word") : t("scan.threat_word")}` : s.status === "cancelled" ? t("common.cancelled") : t("common.clean")}
                </p>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Scan Report — shown after scan completes or is cancelled.
   Presents a full summary with stats, detections, and actions.
   ═══════════════════════════════════════════════════════════════ */

function ScanReport({ ss, onNewScan }: { ss: ScanStatusResponse; onNewScan: () => void }) {
  const cancelled = ss.state === "cancelled";
  const hasThreats = ss.threats_found > 0;
  const statusColor = cancelled ? "amber" : hasThreats ? "red" : "green";
  const cv = `var(--${statusColor})`;
  const elapsed = ss.started_at && ss.finished_at ? ss.finished_at - ss.started_at : 0;
  const scanType = ss.scan_type || "quick";

  return (
    <div className="page-stack">
      {/* Hero result card */}
      <Card className={`border-[rgb(${cv})]/12`}>
        <div className="flex items-start gap-5">
          <div className="flex h-16 w-16 flex-shrink-0 items-center justify-center rounded"
            style={{ background: `rgba(${cv}, 0.08)`, color: `rgb(${cv})` }}>
            {cancelled ? <XCircle size={28} /> : hasThreats ? <ShieldAlert size={28} /> : <ShieldCheck size={28} />}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-[22px] font-bold leading-tight">
              {cancelled
                ? t("scan.scan_cancelled")
                : hasThreats
                  ? t("scan.threats_result").replace("{count}", String(ss.threats_found))
                  : t("scan.complete_no_threats")}
            </h3>
            <p className="text-[13px] text-[rgb(var(--t2))] mt-2 leading-relaxed">
              {cancelled
                ? `${scanType} ${t("scan.scan_suffix")} — ${ss.files_scanned.toLocaleString()} ${t("scan.files_scanned_before_cancel")}.${hasThreats ? ` ${ss.threats_found} ${ss.threats_found > 1 ? t("scan.threats_word") : t("scan.threat_word")}.` : ""}`
                : hasThreats
                  ? `ARGUS + ClamAV — ${ss.files_scanned.toLocaleString()} ${t("scan.files")} — ${ss.threats_found} ${ss.threats_found > 1 ? t("scan.threats_word") : t("scan.threat_word")}.`
                  : `${ss.files_scanned.toLocaleString()} ${t("scan.files")} — ${t("scan.clean_desc")}`}
            </p>
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mt-6">
          <StatBox label={t("scan.files_scanned")} value={ss.files_scanned.toLocaleString()} />
          <StatBox label={t("scan.threats_found")} value={String(ss.threats_found)} color={hasThreats ? "red" : undefined} />
          <StatBox label={t("scan.duration")} value={elapsed > 0 ? formatDuration(elapsed) : "—"} />
          <StatBox label={t("scan.errors")} value={String(ss.errors_count)} color={ss.errors_count > 0 ? "amber" : undefined} />
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 mt-6 pt-5 border-t border-[rgb(var(--border))]/8">
          <button onClick={onNewScan}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[13px] font-semibold hover:opacity-90 cursor-pointer shadow-sm shadow-[rgb(var(--accent))]/10">
            <Search size={14} />
            {t("scan.new_scan")}
          </button>
          {hasThreats && !cancelled && (
            <p className="text-[11px] text-[rgb(var(--t3))] ml-2">
              {t("scan.threats_review_hint")}
            </p>
          )}
        </div>
      </Card>

      {/* Detection list */}
      {ss.detections.length > 0 && (
        <Card>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--red))]/8">
                <AlertTriangle size={16} className="text-[rgb(var(--red))]" />
              </div>
              <div>
                <h4 className="text-[15px] font-semibold">{t("scan.detected_threats")}</h4>
                <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">
                  {ss.detections.length} {t("scan.items_identified")}
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            {ss.detections.map((d, i) => {
              const isArgus = d.virus_name.startsWith("ARGUS/");
              const fileName = d.path.split(/[/\\]/).pop() || d.path;
              const dirPath = d.path.split(/[/\\]/).slice(0, -1).join("\\");
              // Extract ARGUS score if present in the name (e.g., "ARGUS/Stealer.Discord [85/100]")
              const scoreMatch = d.virus_name.match(/\[(\d+)\/100\]/);
              const score = scoreMatch ? parseInt(scoreMatch[1]) : null;

              return (
                <div key={i} className="flex items-start gap-3 rounded-xl border border-[rgb(var(--border))]/8 px-4 py-3.5">
                  <div className={`mt-0.5 flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl ${
                    isArgus ? "bg-[rgb(var(--amber))]/8" : "bg-[rgb(var(--red))]/8"
                  }`}>
                    {isArgus
                      ? <Eye size={18} className="text-[rgb(var(--amber))]" />
                      : <ShieldAlert size={18} className="text-[rgb(var(--red))]" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className={`text-[13px] font-semibold ${isArgus ? "text-[rgb(var(--amber))]" : "text-[rgb(var(--red))]"}`}>
                        {d.virus_name.replace(/\s*\[\d+\/100\]/, "")}
                      </p>
                      <span className={`text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                        isArgus ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]" : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                      }`}>
                        {isArgus ? t("scan.heuristic") : t("scan.signature")}
                      </span>
                      {score !== null && (
                        <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))]">
                          {t("scan.suspicion_score")}: {score}/100
                        </span>
                      )}
                    </div>
                    <p className="text-[12px] font-medium text-[rgb(var(--t1))] mt-1.5">{fileName}</p>
                    <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-0.5 truncate" title={d.path}>{dirPath}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Clean result — positive reinforcement */}
      {ss.detections.length === 0 && !cancelled && (
        <Card>
          <div className="flex flex-col items-center py-6 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded bg-[rgb(var(--green))]/8 mb-4">
              <CheckCircle size={28} className="text-[rgb(var(--green))]" />
            </div>
            <p className="text-[15px] font-semibold text-[rgb(var(--t1))]">{t("scan.all_clear")}</p>
            <p className="text-[12px] text-[rgb(var(--t3))] mt-2 max-w-md leading-relaxed">
              {ss.files_scanned.toLocaleString()} {t("scan.files")} — {t("scan.clean_desc")}
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: string; color?: "red" | "amber" }) {
  return (
    <div className="rounded-xl bg-[rgb(var(--raised))]/15 px-4 py-3 text-center">
      <p className="text-[10px] text-[rgb(var(--t3))] uppercase tracking-wider">{label}</p>
      <p className={`text-[18px] font-bold mt-1 ${color ? `text-[rgb(var(--${color}))]` : ""}`}>{value}</p>
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function ScanTypeCard({ icon, title, desc, accent, disabled, onClick }: { icon: React.ReactNode; title: string; desc: string; accent?: boolean; disabled?: boolean; onClick?: () => void }) {
  return (
    <Card className={`${disabled ? "opacity-35" : "cursor-pointer"} ${accent && !disabled ? "border-[rgb(var(--accent))]/12" : ""}`}>
      <button onClick={onClick} disabled={disabled} className="flex w-full flex-col gap-4 text-left cursor-pointer disabled:cursor-not-allowed">
        <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${accent && !disabled ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]" : "bg-[rgb(var(--raised))]/40 text-[rgb(var(--t3))]"}`}>{icon}</div>
        <div className="min-w-0">
          <h4 className="text-[14px] font-semibold">{title}</h4>
          <p className="mt-2 text-[12px] leading-relaxed text-[rgb(var(--t3))]">{desc}</p>
        </div>
      </button>
    </Card>
  );
}

/* ─── ARGUS-enriched file scan result ─── */

const VERDICT_STYLE: Record<string, { color: string; labelKey: string }> = {
  clean: { color: "var(--green)", labelKey: "scan.verdict_clean" },
  low_suspicion: { color: "var(--accent)", labelKey: "scan.verdict_low_suspicion" },
  suspicious: { color: "var(--amber)", labelKey: "scan.verdict_suspicious" },
  high_suspicion: { color: "var(--amber)", labelKey: "scan.verdict_high_suspicion" },
  malicious: { color: "var(--red)", labelKey: "scan.verdict_malicious" },
};

const SEV_COLORS: Record<string, string> = {
  critical: "var(--red)",
  high: "var(--red)",
  medium: "var(--amber)",
  low: "var(--accent)",
  info: "var(--t3)",
};

/** Behavioral Analysis panel — shows sandbox detonation results when present. */
function BehavioralPanel({ findings }: { findings: ArgusFinding[] }) {
  const behavioral = findings.filter(f => f.layer === "behavioral_runtime");
  if (behavioral.length === 0) return null;

  // Group by description content.
  const groups: Record<string, ArgusFinding[]> = {};
  for (const f of behavioral) {
    const desc = f.description.toLowerCase();
    const group = desc.includes("spawn") || desc.includes("process") ? "process"
      : desc.includes("registry") || desc.includes("run key") ? "registry"
      : desc.includes("network") || desc.includes("tcp") || desc.includes("connect") ? "network"
      : desc.includes("dll") || desc.includes("image") || desc.includes("loaded") ? "image_load"
      : desc.includes("containment") || desc.includes("job object") || desc.includes("token") ? "containment"
      : "other";
    (groups[group] ??= []).push(f);
  }

  const hasDegraded = behavioral.some(f => f.description.toLowerCase().includes("degraded") || f.description.toLowerCase().includes("containment failed"));
  const totalDelta = behavioral.reduce((sum, f) => sum + f.weight, 0);

  return (
    <div className="rounded border border-[rgb(var(--accent))]/12 bg-[rgb(var(--accent))]/3 px-5 py-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))]">
            <Eye size={14} />
          </div>
          <div>
            <p className="text-[13px] font-semibold">{t("scan.behavioral_analysis")}</p>
            <p className="text-[10px] text-[rgb(var(--t3))]">{t("scan.sandbox_experimental")}</p>
          </div>
        </div>
        {totalDelta > 0 && (
          <span className="text-[12px] font-bold text-[rgb(var(--amber))]">+{totalDelta} {t("scan.score_impact_suffix")}</span>
        )}
      </div>

      {hasDegraded && (
        <div className="flex items-center gap-2 px-3 py-2 rounded bg-[rgb(var(--amber))]/8 text-[11px] text-[rgb(var(--amber))]">
          <AlertTriangle size={13} />
          {t("scan.containment_degraded")}
        </div>
      )}

      {Object.entries(groups).filter(([k]) => k !== "containment").map(([group, items]) => (
        <div key={group}>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[rgb(var(--t3))]/50 mb-1">{t(`scan.group_${group}`)}</p>
          {items.map((f, i) => {
            const sevColor = f.severity === "critical" ? "var(--red)"
              : f.severity === "high" ? "var(--red)"
              : f.severity === "medium" ? "var(--amber)"
              : "var(--t3)";
            return (
              <div key={i} className="flex items-center gap-2 py-1">
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: `rgb(${sevColor})` }} />
                <span className="text-[12px] text-[rgb(var(--t1))] flex-1">{f.description}</span>
                <span className="text-[10px] font-semibold uppercase" style={{ color: `rgb(${sevColor})` }}>{f.severity}</span>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

const LAYER_KEYS: Record<string, string> = {
  signatures: "scan.layer_signatures",
  yara_rules: "scan.layer_yara_rules",
  mime_validation: "scan.layer_mime_validation",
  structural_analysis: "scan.layer_structural_analysis",
  packer_detection: "scan.layer_packer_detection",
  script_analysis: "scan.layer_script_analysis",
  ioc_correlation: "scan.layer_ioc_correlation",
  pattern_detection: "scan.layer_pattern_detection",
  file_deception: "scan.layer_file_deception",
  reputation: "scan.layer_reputation",
  context: "scan.layer_context",
  behavioral_runtime: "scan.layer_behavioral_runtime",
};

function FileResult({ r, argus, onDismiss, onQuarantine }: {
  r: NonNullable<FileScanResponse["result"]>;
  argus?: ArgusVerdict;
  onDismiss: () => void;
  onQuarantine: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const inf = r.infected;
  const vs = argus ? VERDICT_STYLE[argus.verdict] ?? VERDICT_STYLE.clean : null;
  const borderCls = inf ? "border-[rgb(var(--red))]/15" : vs && argus && argus.score > 25 ? "border-[rgb(var(--amber))]/15" : "border-[rgb(var(--green))]/15";

  return (
    <div className="page-stack">
      {/* Main result card */}
      <Card className={borderCls}>
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${inf ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]" : "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"}`}>
            {inf ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[15px] font-semibold">{inf ? `${t("common.threat")}: ${r.virus_name}` : t("scan.file_clean")}</p>
            <p className="text-[12px] text-[rgb(var(--t3))] truncate mt-0.5">{r.path}</p>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            {inf && (
              <button onClick={onQuarantine}
                className="px-4 py-2 rounded-xl bg-[rgb(var(--red))]/8 text-[12px] font-semibold text-[rgb(var(--red))] hover:bg-[rgb(var(--red))]/15 cursor-pointer">
                {t("scan.quarantine_action")}
              </button>
            )}
            <button onClick={onDismiss}
              className="px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] hover:text-[rgb(var(--t1))] cursor-pointer">
              {inf ? t("scan.ignore") : t("scan.scan_another")}
            </button>
          </div>
        </div>
      </Card>

      {/* ARGUS Analysis card */}
      {argus && (
        <Card>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
                <Eye size={16} className="text-[rgb(var(--accent))]" />
              </div>
              <div>
                <h4 className="text-[14px] font-semibold">{t("scan.argus_analysis")}</h4>
                <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">
                  {t("scan.heuristic_engine")} v{argus.engine_version} · {(argus.analysis_time_us / 1000).toFixed(1)}ms
                </p>
              </div>
            </div>

            {/* Score badge */}
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-[11px] text-[rgb(var(--t3))]">{t("scan.suspicion_score")}</p>
                <p className="text-[20px] font-bold leading-none mt-1" style={{ color: vs ? `rgb(${vs.color})` : undefined }}>
                  {argus.score}<span className="text-[12px] font-normal text-[rgb(var(--t3))]">/100</span>
                </p>
              </div>
              <div
                className="px-3 py-1.5 rounded-lg text-[11px] font-semibold"
                style={{
                  background: vs ? `color-mix(in srgb, rgb(${vs.color}) 8%, transparent)` : undefined,
                  color: vs ? `rgb(${vs.color})` : undefined,
                }}
              >
                {vs ? t(vs.labelKey) : t("scan.verdict_clean")}
              </div>
            </div>
          </div>

          {/* File metadata */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-5">
            <MetaItem label={t("scan.file_size")} value={formatBytes(argus.file_size)} />
            <MetaItem label={t("scan.mime_type")} value={argus.mime_type ?? t("common.unknown")} />
            <MetaItem label={t("scan.sha256")} value={argus.sha256.slice(0, 16) + "..."} title={argus.sha256} />
            <MetaItem label={t("scan.findings")} value={String(argus.findings.length)} />
          </div>

          {/* Why this verdict? — explainable scoring */}
          {argus.explanation && (argus.explanation.suspicion_reasons.length > 0 || argus.explanation.trust_reasons.length > 0) && (
            <div className="mb-5 rounded-xl border border-[rgb(var(--border))]/8 p-4">
              <p className="text-[12px] font-semibold text-[rgb(var(--t2))] mb-3">{t("scan.why_verdict")}</p>
              <div className="grid gap-4 md:grid-cols-2">
                {argus.explanation.suspicion_reasons.length > 0 && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-[rgb(var(--amber))] mb-2">
                      {t("scan.suspicion_increased")} (+{argus.explanation.raw_score})
                    </p>
                    <ul className="space-y-1.5">
                      {argus.explanation.suspicion_reasons.map((r, i) => (
                        <li key={i} className="text-[11px] text-[rgb(var(--t2))] leading-relaxed flex gap-2">
                          <span className="text-[rgb(var(--amber))] flex-shrink-0 mt-0.5">▲</span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {argus.explanation.trust_reasons.length > 0 && (
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-[rgb(var(--green))] mb-2">
                      {t("scan.trust_applied")}
                    </p>
                    <ul className="space-y-1.5">
                      {argus.explanation.trust_reasons.map((r, i) => (
                        <li key={i} className="text-[11px] text-[rgb(var(--t2))] leading-relaxed flex gap-2">
                          <span className="text-[rgb(var(--green))] flex-shrink-0 mt-0.5">▼</span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
              {(argus.explanation.signer || argus.explanation.recognized_software) && (
                <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-[rgb(var(--border))]/8">
                  {argus.explanation.signer && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]">
                      {t("scan.signed_prefix")}: {argus.explanation.signer}
                    </span>
                  )}
                  {argus.explanation.recognized_software && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]">
                      {t("scan.known_prefix")}: {argus.explanation.recognized_software}
                    </span>
                  )}
                  {argus.explanation.installer_discount_applied && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))]">
                      {t("scan.installer_framework")}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Behavioral Analysis summary — only shows when sandbox findings exist */}
          <BehavioralPanel findings={argus.findings} />

          {/* Findings list */}
          {argus.findings.length > 0 ? (
            <>
              <div className="space-y-2">
                {argus.findings.slice(0, expanded ? undefined : 4).map((f, i) => {
                  const sevColor = SEV_COLORS[f.severity] ?? "var(--t3)";
                  return (
                    <div key={i} className="flex items-start gap-3 rounded-xl px-4 py-3 bg-[rgb(var(--raised))]/15">
                      <div
                        className="mt-0.5 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-lg text-[10px] font-bold"
                        style={{ background: `color-mix(in srgb, rgb(${sevColor}) 10%, transparent)`, color: `rgb(${sevColor})` }}
                      >
                        +{f.weight}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-[12px] leading-relaxed">{f.description}</p>
                        <div className="flex items-center gap-2 mt-1.5">
                          <span className="text-[10px] px-2 py-0.5 rounded bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))]">
                            {LAYER_KEYS[f.layer] ? t(LAYER_KEYS[f.layer]) : f.layer}
                          </span>
                          <span className="text-[10px] font-semibold uppercase" style={{ color: `rgb(${sevColor})` }}>
                            {f.severity}
                          </span>
                        </div>
                        {expanded && f.technical_detail && (
                          <p className="text-[10px] text-[rgb(var(--t3))]/50 mt-1.5 font-mono break-all">
                            {f.technical_detail}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              {argus.findings.length > 4 && (
                <button onClick={() => setExpanded(!expanded)}
                  className="flex items-center gap-1.5 mt-3 text-[11px] font-semibold text-[rgb(var(--accent))] cursor-pointer hover:underline">
                  {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                  {expanded ? t("scan.show_less") : `${t("scan.show_all").replace("{count}", String(argus.findings.length))}`}
                </button>
              )}
            </>
          ) : (
            <div className="flex items-center gap-3 py-4 text-[12px] text-[rgb(var(--green))]">
              <CheckCircle size={15} />
              {t("scan.no_suspicious")}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function MetaItem({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="rounded-xl bg-[rgb(var(--raised))]/15 px-3.5 py-2.5">
      <p className="text-[10px] text-[rgb(var(--t3))] uppercase tracking-wider">{label}</p>
      <p className="text-[12px] font-medium mt-1 truncate" title={title}>{value}</p>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`;
}

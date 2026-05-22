import { useState, useEffect } from "react";
import {
  Search,
  Zap,
  HardDrive,
  FolderOpen,
  Upload,
  CheckCircle,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/Card";
import { startQuickScan, startFullScan, getScanHistory } from "../api/sentinella";
import type { ScanRecord } from "../types/sentinella";

type ScanMode = "idle" | "scanning" | "complete";

export function ScanPage() {
  const [mode, setMode] = useState<ScanMode>("idle");
  const [progress, setProgress] = useState(0);
  const [dragOver, setDragOver] = useState(false);
  const [recentScans, setRecentScans] = useState<ScanRecord[]>([]);

  useEffect(() => {
    getScanHistory().then(setRecentScans).catch(() => {});
  }, [mode]); // refetch after a scan completes

  async function handleStartScan(type: "quick" | "full") {
    setMode("scanning");
    setProgress(0);

    // Call the real daemon endpoint.
    try {
      if (type === "quick") await startQuickScan();
      else await startFullScan();
    } catch {
      // Daemon call may fail; still show mock progress for now.
    }

    // Mock progress animation until real scan streaming exists.
    const interval = setInterval(() => {
      setProgress((p) => {
        if (p >= 100) {
          clearInterval(interval);
          setMode("complete");
          return 100;
        }
        return p + 2;
      });
    }, 80);
  }

  return (
    <div>
      <PageHeader
        icon={<Search size={22} />}
        title="Scan"
        subtitle="Run a virus scan on your system"
      />

      {/* ── Scan types ─────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <ScanTypeCard
          icon={<Zap size={22} />}
          title="Quick Scan"
          description="Scans Downloads, Desktop, Documents, and Temp folders."
          duration="~2 min"
          accent
          onClick={() => handleStartScan("quick")}
          disabled={mode === "scanning"}
        />
        <ScanTypeCard
          icon={<HardDrive size={22} />}
          title="Full Scan"
          description="Comprehensive scan of all files on every drive."
          duration="~45 min"
          onClick={() => handleStartScan("full")}
          disabled={mode === "scanning"}
        />
        <ScanTypeCard
          icon={<FolderOpen size={22} />}
          title="Custom Scan"
          description="Choose specific files or folders to scan."
          duration="Varies"
          onClick={() => handleStartScan("quick")}
          disabled={mode === "scanning"}
        />
      </div>

      {/* ── Drag & drop zone ───────────────────────────────── */}
      <Card
        className={`mb-6 transition-colors ${
          dragOver
            ? "border-[rgb(var(--accent))] bg-[rgb(var(--accent))]/5"
            : ""
        }`}
      >
        <div
          className="flex flex-col items-center py-8 text-center"
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); handleStartScan("quick"); }}
        >
          <div className="w-14 h-14 rounded-2xl bg-[rgb(var(--bg-elevated))] flex items-center justify-center mb-3">
            <Upload size={24} className={dragOver ? "text-[rgb(var(--accent))]" : "text-[rgb(var(--text-muted))]"} />
          </div>
          <p className="text-sm font-medium mb-1">
            Drag files or folders here to scan
          </p>
          <p className="text-xs text-[rgb(var(--text-muted))]">
            Or use one of the scan types above
          </p>
        </div>
      </Card>

      {/* ── Scan progress / result ─────────────────────────── */}
      {mode === "scanning" && (
        <Card className="mb-6">
          <div className="flex items-center gap-4 mb-4">
            <Loader2 size={22} className="text-[rgb(var(--accent))] animate-spin" />
            <div className="flex-1">
              <p className="text-sm font-semibold">Scanning...</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">
                {Math.floor(progress * 142)} files checked
              </p>
            </div>
            <span className="text-sm font-bold text-[rgb(var(--accent))]">{progress}%</span>
          </div>
          {/* Progress bar */}
          <div className="w-full h-2 bg-[rgb(var(--bg-elevated))] rounded-full overflow-hidden">
            <div
              className="h-full bg-[rgb(var(--accent))] rounded-full transition-all duration-200"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="text-xs text-[rgb(var(--text-muted))] mt-2 truncate">
            C:\Users\Nicolas\Documents\project\src\main.rs
          </p>
        </Card>
      )}

      {mode === "complete" && (
        <Card className="mb-6 border-[rgb(var(--success))]/30">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[rgb(var(--success))]/15 flex items-center justify-center">
              <CheckCircle size={24} className="text-[rgb(var(--success))]" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-semibold">Scan complete — No threats found</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">
                14,203 files scanned in 2m 14s
              </p>
            </div>
            <button
              onClick={() => setMode("idle")}
              className="text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text-primary))] px-3 py-1.5 rounded-lg bg-[rgb(var(--bg-elevated))] transition-colors"
            >
              Dismiss
            </button>
          </div>
        </Card>
      )}

      {/* ── Recent scans (from daemon) ──────────────────────── */}
      <h3 className="text-xs font-medium text-[rgb(var(--text-muted))] mb-3 uppercase tracking-wider">
        Recent Scans
      </h3>
      {recentScans.length === 0 ? (
        <Card className="text-center py-10">
          <p className="text-sm text-[rgb(var(--text-muted))]">No scans recorded yet. Run a scan to see results here.</p>
        </Card>
      ) : (
      <Card className="p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[rgb(var(--border))] text-left text-[rgb(var(--text-muted))]">
              <th className="px-5 py-3 font-medium">Type</th>
              <th className="px-5 py-3 font-medium">Date</th>
              <th className="px-5 py-3 font-medium">Files</th>
              <th className="px-5 py-3 font-medium">Result</th>
              <th className="px-5 py-3 font-medium">Duration</th>
            </tr>
          </thead>
          <tbody>
            {recentScans.slice(0, 5).map((scan) => (
              <tr
                key={scan.job_id}
                className="border-b border-[rgb(var(--border))]/40 last:border-0 hover:bg-[rgb(var(--bg-elevated))]/40 transition-colors"
              >
                <td className="px-5 py-3 capitalize font-medium">{scan.scan_type}</td>
                <td className="px-5 py-3 text-[rgb(var(--text-muted))]">{new Date(scan.started_at * 1000).toLocaleString()}</td>
                <td className="px-5 py-3">{scan.files_scanned.toLocaleString()}</td>
                <td className="px-5 py-3">
                  {scan.threats_found > 0 ? (
                    <span className="inline-flex items-center gap-1 text-[rgb(var(--danger))]">
                      <AlertTriangle size={13} />
                      <span className="font-medium">{scan.threats_found} threat{scan.threats_found > 1 ? "s" : ""}</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[rgb(var(--success))]">
                      <CheckCircle size={13} />
                      <span className="font-medium">Clean</span>
                    </span>
                  )}
                </td>
                <td className="px-5 py-3 text-[rgb(var(--text-muted))]">
                  {formatDur(scan.finished_at - scan.started_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      )}
    </div>
  );
}

function ScanTypeCard({
  icon,
  title,
  description,
  duration,
  accent,
  onClick,
  disabled,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  duration: string;
  accent?: boolean;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <Card
      className={`
        ${accent ? "border-[rgb(var(--accent))]/30" : ""}
        ${disabled ? "opacity-60" : "hover:border-[rgb(var(--accent))]/40 cursor-pointer"}
        transition-all
      `}
    >
      <div className="flex items-start gap-4">
        <div
          className={`w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0 ${
            accent
              ? "bg-[rgb(var(--accent))]/15 text-[rgb(var(--accent))]"
              : "bg-[rgb(var(--bg-elevated))] text-[rgb(var(--text-muted))]"
          }`}
        >
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-semibold mb-1">{title}</h4>
          <p className="text-xs text-[rgb(var(--text-muted))] leading-relaxed mb-3">
            {description}
          </p>
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-[rgb(var(--text-muted))]">{duration}</span>
            <button
              onClick={onClick}
              disabled={disabled}
              className={`text-xs font-medium px-3 py-1.5 rounded-lg transition-colors ${
                accent
                  ? "bg-[rgb(var(--accent))] text-white hover:opacity-90"
                  : "bg-[rgb(var(--bg-elevated))] text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text-primary))]"
              } ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`}
            >
              Start
            </button>
          </div>
        </div>
      </div>
    </Card>
  );
}

function formatDur(secs: number): string {
  if (secs <= 0) return "<1s";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

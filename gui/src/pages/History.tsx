import { useState, useEffect } from "react";
import {
  Clock,
  CheckCircle,
  AlertTriangle,
  Search,
  Zap,
  HardDrive,
  FolderOpen,
  Loader2,
  WifiOff,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/Card";
import { getScanHistory } from "../api/sentinella";
import type { ScanRecord } from "../types/sentinella";

const typeIcons: Record<string, React.ReactNode> = {
  quick: <Zap size={16} />,
  full: <HardDrive size={16} />,
  custom: <FolderOpen size={16} />,
};

export function HistoryPage() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "threats">("all");
  const [searchText, setSearchText] = useState("");

  useEffect(() => {
    getScanHistory()
      .then((r) => { setRecords(r); setError(null); })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center py-24">
        <Loader2 size={24} className="text-[rgb(var(--accent))] animate-spin mb-3" />
        <p className="text-sm text-[rgb(var(--text-muted))]">Loading scan history...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader icon={<Clock size={22} />} title="History" subtitle="Review past scan results" />
        <Card className="text-center py-12">
          <WifiOff size={28} className="mx-auto text-[rgb(var(--warning))] mb-3" />
          <p className="text-sm text-[rgb(var(--text-muted))]">Could not reach daemon</p>
          <p className="text-xs text-[rgb(var(--danger))] mt-1">{error}</p>
        </Card>
      </div>
    );
  }

  const filtered = records.filter((r) => {
    if (filter === "threats" && r.threats_found === 0) return false;
    if (searchText && !r.scan_type.toLowerCase().includes(searchText.toLowerCase()) &&
        !r.job_id.toLowerCase().includes(searchText.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <PageHeader icon={<Clock size={22} />} title="History" subtitle="Review past scan results">
        <span className="text-xs text-[rgb(var(--text-muted))] bg-[rgb(var(--bg-elevated))] px-3 py-1.5 rounded-lg">
          {records.length} scan{records.length !== 1 ? "s" : ""} recorded
        </span>
      </PageHeader>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[rgb(var(--bg-surface))] border border-[rgb(var(--border))] flex-1 max-w-xs">
          <Search size={14} className="text-[rgb(var(--text-muted))]" />
          <input type="text" placeholder="Search scans..." value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            className="bg-transparent text-sm outline-none w-full text-[rgb(var(--text-primary))] placeholder:text-[rgb(var(--text-muted))]" />
        </div>
        <Pill active={filter === "all"} onClick={() => setFilter("all")} label="All" />
        <Pill active={filter === "threats"} onClick={() => setFilter("threats")} label="With threats" />
      </div>

      {filtered.length === 0 ? (
        <Card className="text-center py-16">
          <Clock size={28} className="mx-auto text-[rgb(var(--text-muted))] mb-3" />
          <p className="text-sm font-medium mb-1">
            {records.length === 0 ? "No scans recorded yet" : "No matching scans"}
          </p>
          <p className="text-xs text-[rgb(var(--text-muted))]">
            {records.length === 0
              ? "Run a scan from the Dashboard or Scan page."
              : "Try a different search term or filter."}
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((r) => (
            <Card key={r.job_id} className="hover:border-[rgb(var(--accent))]/30 transition-colors">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-[rgb(var(--bg-elevated))] flex items-center justify-center text-[rgb(var(--text-muted))] flex-shrink-0">
                  {typeIcons[r.scan_type] || <FolderOpen size={16} />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold capitalize">{r.scan_type} Scan</p>
                    {r.threats_found > 0 ? (
                      <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-md bg-[rgb(var(--danger))]/10 text-[rgb(var(--danger))]">
                        <AlertTriangle size={11} /> {r.threats_found} threat{r.threats_found > 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-md bg-[rgb(var(--success))]/10 text-[rgb(var(--success))]">
                        <CheckCircle size={11} /> {r.status}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[rgb(var(--text-muted))] mt-0.5">
                    {new Date(r.started_at * 1000).toLocaleString()} · Job {r.job_id.slice(0, 8)}
                  </p>
                </div>
                <div className="flex items-center gap-6 text-sm flex-shrink-0">
                  <div className="text-right">
                    <p className="text-[11px] text-[rgb(var(--text-muted))]">Files</p>
                    <p className="font-medium">{r.files_scanned.toLocaleString()}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-[11px] text-[rgb(var(--text-muted))]">Duration</p>
                    <p className="font-medium">{formatDuration(r.finished_at - r.started_at)}</p>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function Pill({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} className={`text-xs font-medium px-3 py-2 rounded-xl border transition-colors cursor-pointer ${
      active ? "border-[rgb(var(--accent))]/40 text-[rgb(var(--accent))] bg-[rgb(var(--accent))]/10"
        : "border-[rgb(var(--border))] text-[rgb(var(--text-muted))] bg-[rgb(var(--bg-surface))] hover:border-[rgb(var(--text-muted))]"
    }`}>{label}</button>
  );
}

function formatDuration(secs: number): string {
  if (secs <= 0) return "<1s";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

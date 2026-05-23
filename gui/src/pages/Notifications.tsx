import { useState } from "react";
import {
  Bell, Trash2, AlertTriangle, ShieldCheck, ShieldAlert,
  RefreshCw, Archive, Info, CheckCircle,
} from "lucide-react";
import { Card } from "../components/Card";
import { loadNotificationHistory, clearNotificationHistory, type NotificationRecord } from "../notifications";

const ICON_MAP: Record<string, React.ReactNode> = {
  threat: <ShieldAlert size={14} className="text-[rgb(var(--red))]" />,
  quarantine: <Archive size={14} className="text-[rgb(var(--amber))]" />,
  quarantine_failed: <AlertTriangle size={14} className="text-[rgb(var(--red))]" />,
  scan_complete: <CheckCircle size={14} className="text-[rgb(var(--green))]" />,
  update_failed: <RefreshCw size={14} className="text-[rgb(var(--red))]" />,
  protection_degraded: <ShieldAlert size={14} className="text-[rgb(var(--amber))]" />,
  realtime_unavailable: <AlertTriangle size={14} className="text-[rgb(var(--amber))]" />,
  first_run: <ShieldCheck size={14} className="text-[rgb(var(--green))]" />,
};

const COLOR_MAP: Record<string, string> = {
  threat: "red",
  quarantine: "amber",
  quarantine_failed: "red",
  scan_complete: "green",
  update_failed: "red",
  protection_degraded: "amber",
  realtime_unavailable: "amber",
  first_run: "green",
};

export function NotificationsPage() {
  const [history, setHistory] = useState<NotificationRecord[]>(() => loadNotificationHistory());

  const handleClear = () => {
    clearNotificationHistory();
    setHistory([]);
  };

  return (
    <div className="page-stack">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[16px] font-semibold">Notification History</h3>
          <p className="text-[11px] text-[rgb(var(--t3))] mt-1">
            {history.length} notification{history.length !== 1 ? "s" : ""} recorded this session
          </p>
        </div>
        {history.length > 0 && (
          <button onClick={handleClear}
            className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[rgb(var(--raised))]/25 text-[11px] text-[rgb(var(--t3))] hover:text-[rgb(var(--red))] cursor-pointer">
            <Trash2 size={12} /> Clear All
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center py-12 text-center">
            <Bell size={32} className="mb-3 text-[rgb(var(--t3))]/20" />
            <p className="text-[14px] font-medium text-[rgb(var(--t2))]">No notifications yet</p>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">
              Threat detections, quarantine actions, and scan results appear here.
            </p>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="space-y-1">
            {[...history].reverse().map((entry, i) => {
              const color = COLOR_MAP[entry.type] || "accent";
              const palette = `var(--${color})`;
              const icon = ICON_MAP[entry.type] || <Info size={14} className="text-[rgb(var(--t3))]" />;
              const time = new Date(entry.timestamp);
              const relative = formatRelative(entry.timestamp);

              return (
                <div key={i} className="flex items-start gap-3 rounded-xl px-4 py-3 hover:bg-[rgb(var(--raised))]/15 transition-colors">
                  <div className="mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg"
                    style={{ background: `rgba(${palette}, 0.08)` }}>
                    {icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium text-[rgb(var(--t1))]">{entry.title}</p>
                    {entry.relatedFile && (
                      <p className="text-[11px] text-[rgb(var(--t3))] truncate mt-0.5" title={entry.relatedFile}>
                        {entry.relatedFile}
                      </p>
                    )}
                  </div>
                  <div className="flex-shrink-0 text-right">
                    <p className="text-[10px] text-[rgb(var(--t3))]">{relative}</p>
                    <p className="text-[9px] text-[rgb(var(--t3))]/40 mt-0.5">{time.toLocaleTimeString()}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}

function formatRelative(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

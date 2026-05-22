import {
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Archive,
  Eye,
} from "lucide-react";
import type { ActivityEvent } from "../data/mock";

const iconMap: Record<ActivityEvent["type"], React.ReactNode> = {
  scan_complete: <CheckCircle size={16} />,
  threat_found: <AlertTriangle size={16} />,
  update: <RefreshCw size={16} />,
  quarantine: <Archive size={16} />,
  realtime: <Eye size={16} />,
};

const colorMap: Record<ActivityEvent["type"], string> = {
  scan_complete: "var(--success)",
  threat_found: "var(--danger)",
  update: "var(--accent)",
  quarantine: "var(--warning)",
  realtime: "var(--accent)",
};

interface ActivityListProps {
  events: ActivityEvent[];
  limit?: number;
}

export function ActivityList({ events, limit }: ActivityListProps) {
  const items = limit ? events.slice(0, limit) : events;

  return (
    <div className="space-y-1">
      {items.map((event) => {
        const c = colorMap[event.type];
        return (
          <div
            key={event.id}
            className="flex items-start gap-3 px-3 py-3 rounded-xl hover:bg-[rgb(var(--bg-elevated))]/50 transition-colors"
          >
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
              style={{
                backgroundColor: `rgba(${c}, 0.12)`,
                color: `rgb(${c})`,
              }}
            >
              {iconMap[event.type]}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium leading-tight">{event.message}</p>
              {event.detail && (
                <p className="text-xs text-[rgb(var(--text-muted))] mt-0.5 truncate">
                  {event.detail}
                </p>
              )}
            </div>
            <span className="text-[11px] text-[rgb(var(--text-muted))] flex-shrink-0 mt-0.5">
              {event.timestamp}
            </span>
          </div>
        );
      })}
    </div>
  );
}

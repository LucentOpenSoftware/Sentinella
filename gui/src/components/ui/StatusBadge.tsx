import { CheckCircle, AlertCircle, WifiOff, Shield, ShieldOff, Search, RefreshCw, XCircle, AlertTriangle, Loader2, Eye } from "lucide-react";

export type StatusType =
  | "connected" | "disconnected"
  | "protected" | "degraded" | "unprotected"
  | "scanning" | "cancelling" | "updating"
  | "clean" | "threat" | "warning"
  | "idle" | "paused";

const CONFIG: Record<StatusType, { color: string; icon: React.ComponentType<{ size?: number }>; label: string }> = {
  connected:    { color: "green",  icon: CheckCircle,   label: "Connected" },
  disconnected: { color: "amber",  icon: WifiOff,       label: "Disconnected" },
  protected:    { color: "green",  icon: Shield,        label: "Protected" },
  degraded:     { color: "amber",  icon: AlertCircle,   label: "Degraded" },
  unprotected:  { color: "red",    icon: ShieldOff,     label: "Unprotected" },
  scanning:     { color: "accent", icon: Search,        label: "Scanning" },
  cancelling:   { color: "amber",  icon: Loader2,       label: "Cancelling" },
  updating:     { color: "accent", icon: RefreshCw,     label: "Updating" },
  clean:        { color: "green",  icon: CheckCircle,   label: "Clean" },
  threat:       { color: "red",    icon: AlertTriangle,  label: "Threat" },
  warning:      { color: "amber",  icon: AlertCircle,   label: "Warning" },
  idle:         { color: "accent", icon: Eye,           label: "Monitoring" },
  paused:       { color: "amber",  icon: XCircle,       label: "Paused" },
};

interface Props {
  status: StatusType;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  className?: string;
}

export function StatusBadge({ status, size = "md", showLabel = true, className = "" }: Props) {
  const cfg = CONFIG[status];
  const colorVar = `var(--${cfg.color})`;

  const sizes = {
    sm: { icon: 10, text: "10px", px: "8px", py: "3px", dot: "5px" },
    md: { icon: 12, text: "11px", px: "12px", py: "5px", dot: "7px" },
    lg: { icon: 14, text: "12px", px: "14px", py: "6px", dot: "8px" },
  }[size];

  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-full badge-glass border ${className}`}
      style={{
        background: `rgba(${colorVar}, 0.08)`,
        borderColor: `rgba(${colorVar}, 0.12)`,
        padding: `${sizes.py} ${sizes.px}`,
      }}
      role="status"
      aria-label={cfg.label}
    >
      {status === "cancelling" || status === "scanning" || status === "updating" ? (
        <Loader2 size={sizes.icon} className="animate-spin" style={{ color: `rgb(${colorVar})` }} />
      ) : (
        <div
          className="rounded-full flex-shrink-0"
          style={{ width: sizes.dot, height: sizes.dot, background: `rgb(${colorVar})` }}
        />
      )}
      {showLabel && (
        <span className="font-semibold" style={{ fontSize: sizes.text, color: `rgb(${colorVar})` }}>
          {cfg.label}
        </span>
      )}
    </div>
  );
}

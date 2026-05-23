import { useState } from "react";
import { AlertCircle, CheckCircle, Info, AlertTriangle, X } from "lucide-react";

type Variant = "info" | "warning" | "error" | "success";

interface Props {
  variant?: Variant;
  message: string;
  actions?: React.ReactNode;
  dismissKey?: string;
  onDismiss?: () => void;
}

const COLORS: Record<Variant, string> = {
  info: "accent",
  warning: "amber",
  error: "red",
  success: "green",
};

const ICONS: Record<Variant, React.ComponentType<{ size?: number }>> = {
  info: Info,
  warning: AlertCircle,
  error: AlertTriangle,
  success: CheckCircle,
};

export function TopBarNotice({ variant = "warning", message, actions, dismissKey, onDismiss }: Props) {
  const storageKey = dismissKey ? `sentinella-dismissed-${dismissKey}` : null;
  const [dismissed, setDismissed] = useState(() => {
    if (storageKey) return sessionStorage.getItem(storageKey) === "true";
    return false;
  });

  if (dismissed) return null;

  const color = COLORS[variant];
  const colorVar = `var(--${color})`;
  const Icon = ICONS[variant];

  const handleDismiss = () => {
    setDismissed(true);
    if (storageKey) sessionStorage.setItem(storageKey, "true");
    onDismiss?.();
  };

  return (
    <div className="topbar-notice" style={{ background: `rgba(${colorVar}, 0.07)`, borderColor: `rgba(${colorVar}, 0.12)` }}>
      <div className="flex-shrink-0" style={{ color: `rgb(${colorVar})` }}>
        <Icon size={13} />
      </div>
      <span className="topbar-notice__message" style={{ color: `rgba(${colorVar}, 0.85)` }}>
        {message}
      </span>
      {actions && <div className="topbar-notice__actions">{actions}</div>}
      <button
        onClick={handleDismiss}
        className="p-0.5 rounded-md hover:bg-white/8 cursor-pointer flex-shrink-0 transition-colors"
        style={{ color: `rgba(${colorVar}, 0.4)` }}
        aria-label="Dismiss"
      >
        <X size={13} />
      </button>
    </div>
  );
}

import { useState } from "react";
import { AlertCircle, CheckCircle, Info, AlertTriangle, X } from "lucide-react";

type Variant = "info" | "warning" | "error" | "success";

interface Props {
  variant?: Variant;
  children: React.ReactNode;
  actions?: React.ReactNode;
  dismissible?: boolean;
  icon?: React.ReactNode;
  onDismiss?: () => void;
}

const VARIANT_CONFIG: Record<Variant, { color: string; Icon: React.ComponentType<{ size?: number }> }> = {
  info:    { color: "accent", Icon: Info },
  warning: { color: "amber",  Icon: AlertCircle },
  error:   { color: "red",    Icon: AlertTriangle },
  success: { color: "green",  Icon: CheckCircle },
};

export function InlineNotification({
  variant = "warning",
  children,
  actions,
  dismissible = true,
  icon,
  onDismiss,
}: Props) {
  const [visible, setVisible] = useState(true);

  if (!visible) return null;

  const cfg = VARIANT_CONFIG[variant];
  const colorVar = `var(--${cfg.color})`;
  const Icon = cfg.Icon;

  const handleDismiss = () => {
    setVisible(false);
    onDismiss?.();
  };

  return (
    <div
      className="inline-notification"
      style={{
        background: `rgba(${colorVar}, 0.06)`,
        borderColor: `rgba(${colorVar}, 0.12)`,
      }}
      role="alert"
    >
      <div className="flex items-center gap-3 min-w-0 flex-1">
        <div className="flex-shrink-0" style={{ color: `rgb(${colorVar})` }}>
          {icon || <Icon size={15} />}
        </div>
        <div className="text-[12px] leading-relaxed min-w-0 flex-1" style={{ color: `rgba(${colorVar}, 0.9)` }}>
          {children}
        </div>
      </div>
      <div className="flex items-center gap-3 flex-shrink-0">
        {actions}
        {dismissible && (
          <button
            onClick={handleDismiss}
            className="p-1 rounded-lg hover:bg-white/5 cursor-pointer transition-colors"
            style={{ color: `rgba(${colorVar}, 0.5)` }}
            aria-label="Dismiss"
          >
            <X size={14} />
          </button>
        )}
      </div>
    </div>
  );
}

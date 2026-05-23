import { WifiOff, AlertCircle } from "lucide-react";
import { GlassPanel } from "./GlassPanel";

interface Props {
  title?: string;
  message?: string;
  variant?: "disconnected" | "error";
  action?: React.ReactNode;
}

export function ErrorState({ title, message, variant = "disconnected", action }: Props) {
  const Icon = variant === "disconnected" ? WifiOff : AlertCircle;
  const color = variant === "disconnected" ? "amber" : "red";
  const defaultTitle = variant === "disconnected" ? "Cannot reach daemon" : "Something went wrong";
  const defaultMsg = variant === "disconnected"
    ? "Sentinella daemon is not responding. Make sure sentinelld is running."
    : "An unexpected error occurred.";

  return (
    <GlassPanel className="text-center py-10">
      <Icon size={24} className={`mx-auto text-[rgb(var(--${color}))] mb-3`} />
      <h3 className="text-[15px] font-semibold mb-1.5">{title || defaultTitle}</h3>
      <p className="text-[12px] text-[rgb(var(--t3))] max-w-xs mx-auto leading-relaxed">
        {message || defaultMsg}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </GlassPanel>
  );
}

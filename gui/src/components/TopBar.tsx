import { RefreshCw, Bell } from "lucide-react";
import { StatusBadge } from "./ui";
import { t } from "../i18n";

/** Max notices displayed simultaneously in the TopBar. */
const MAX_NOTICES = 3;

export function TopBar({ title, subtitle, connected, onRefresh, onNotifications, notices }: {
  title: string;
  subtitle?: string;
  connected: boolean;
  onRefresh?: () => void;
  onNotifications?: () => void;
  notices?: React.ReactNode[];
}) {
  const visible = (notices || []).filter(Boolean).slice(0, MAX_NOTICES);

  return (
    <header className="flex-shrink-0 glass-topbar px-14 py-3">
      <div className="app-shell-width grid items-center gap-5" style={{ gridTemplateColumns: "auto minmax(0, 1fr) auto" }}>
        {/* Left: page title */}
        <div className="min-w-0">
          <h2 className="text-[16px] font-semibold leading-none">{title}</h2>
          {subtitle && <p className="mt-1.5 text-[11px] text-[rgb(var(--t3))]">{subtitle}</p>}
        </div>

        {/* Center: notices (up to 3) */}
        <div className="flex justify-center items-center gap-2 min-w-0 overflow-hidden">
          {visible}
        </div>

        {/* Right: controls */}
        <div className="flex items-center gap-4">
          <button onClick={onRefresh} className="rounded-xl p-2.5 text-[rgb(var(--t3))]/35 hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t2))] cursor-pointer" title={t("topbar.refresh")} aria-label={t("topbar.refresh")}>
            <RefreshCw size={15} />
          </button>
          <button onClick={onNotifications} className="rounded-xl p-2.5 text-[rgb(var(--t3))]/35 hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t2))] cursor-pointer" title={t("topbar.notifications")} aria-label={t("topbar.notifications")}>
            <Bell size={15} />
          </button>
          <div className="h-5 w-px bg-[rgb(var(--border))]/15" />
          <StatusBadge status={connected ? "connected" : "disconnected"} />
        </div>
      </div>
    </header>
  );
}

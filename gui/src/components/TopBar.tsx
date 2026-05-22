import { Bell, RefreshCw, WifiOff } from "lucide-react";

interface TopBarProps {
  title: string;
  subtitle?: string;
  connected: boolean;
  onRefresh?: () => void;
}

export function TopBar({ title, subtitle, connected, onRefresh }: TopBarProps) {
  return (
    <header className="h-14 flex items-center justify-between px-6 border-b border-[rgb(var(--border))] bg-[rgb(var(--bg-surface))] flex-shrink-0">
      <div>
        <h2 className="text-[15px] font-semibold leading-tight">{title}</h2>
        {subtitle && (
          <p className="text-[11px] text-[rgb(var(--text-muted))]">{subtitle}</p>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={onRefresh}
          className="p-2 rounded-lg hover:bg-[rgb(var(--bg-elevated))] transition-colors text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text-primary))] cursor-pointer"
          title="Refresh"
        >
          <RefreshCw size={16} />
        </button>
        <button
          className="p-2 rounded-lg hover:bg-[rgb(var(--bg-elevated))] transition-colors text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text-primary))]"
          title="Notifications"
        >
          <Bell size={16} />
        </button>
        {/* Connection status */}
        {connected ? (
          <div className="ml-2 flex items-center gap-1.5 px-2.5 py-1.5 rounded-full bg-[rgb(var(--success))]/10 border border-[rgb(var(--success))]/20">
            <div className="w-1.5 h-1.5 rounded-full bg-[rgb(var(--success))]" />
            <span className="text-[11px] font-medium text-[rgb(var(--success))]">Connected</span>
          </div>
        ) : (
          <div className="ml-2 flex items-center gap-1.5 px-2.5 py-1.5 rounded-full bg-[rgb(var(--warning))]/10 border border-[rgb(var(--warning))]/20">
            <WifiOff size={11} className="text-[rgb(var(--warning))]" />
            <span className="text-[11px] font-medium text-[rgb(var(--warning))]">Disconnected</span>
          </div>
        )}
      </div>
    </header>
  );
}

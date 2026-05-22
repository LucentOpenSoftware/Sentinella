import {
  Shield,
  Search,
  Archive,
  Clock,
  Settings,
  Info,
} from "lucide-react";

export type Page =
  | "dashboard"
  | "scan"
  | "quarantine"
  | "history"
  | "settings"
  | "about";

interface SidebarProps {
  current: Page;
  onNavigate: (page: Page) => void;
}

const mainNav: { page: Page; label: string; icon: React.ReactNode }[] = [
  { page: "dashboard", label: "Dashboard", icon: <Shield size={20} /> },
  { page: "scan", label: "Scan", icon: <Search size={20} /> },
  { page: "quarantine", label: "Quarantine", icon: <Archive size={20} /> },
  { page: "history", label: "History", icon: <Clock size={20} /> },
];

const bottomNav: { page: Page; label: string; icon: React.ReactNode }[] = [
  { page: "settings", label: "Settings", icon: <Settings size={20} /> },
  { page: "about", label: "About", icon: <Info size={20} /> },
];

export function Sidebar({ current, onNavigate }: SidebarProps) {
  return (
    <aside className="w-60 h-screen flex flex-col border-r border-[rgb(var(--border))] bg-[rgb(var(--bg-surface))]">
      {/* Logo area */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-[rgb(var(--border))]">
        <div className="w-9 h-9 rounded-xl bg-[rgb(var(--accent))] flex items-center justify-center">
          <Shield size={20} className="text-white" />
        </div>
        <div>
          <h1 className="text-base font-semibold tracking-tight">Sentinella</h1>
          <p className="text-xs text-[rgb(var(--text-muted))]">Antivirus Suite</p>
        </div>
      </div>

      {/* Main navigation */}
      <nav className="flex-1 px-3 py-4">
        <p className="px-3 mb-2 text-[11px] font-medium uppercase tracking-wider text-[rgb(var(--text-muted))]">
          Protection
        </p>
        {mainNav.map((item) => (
          <NavItem
            key={item.page}
            active={current === item.page}
            icon={item.icon}
            label={item.label}
            onClick={() => onNavigate(item.page)}
          />
        ))}

        <p className="px-3 mt-6 mb-2 text-[11px] font-medium uppercase tracking-wider text-[rgb(var(--text-muted))]">
          System
        </p>
        {bottomNav.map((item) => (
          <NavItem
            key={item.page}
            active={current === item.page}
            icon={item.icon}
            label={item.label}
            onClick={() => onNavigate(item.page)}
          />
        ))}
      </nav>

      {/* Version footer */}
      <div className="px-5 py-3 border-t border-[rgb(var(--border))] text-xs text-[rgb(var(--text-muted))]">
        v0.1.0 &middot; GPLv2
      </div>
    </aside>
  );
}

function NavItem({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`
        w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium
        transition-colors duration-150 cursor-pointer mb-0.5
        ${
          active
            ? "bg-[rgb(var(--accent))]/15 text-[rgb(var(--accent))]"
            : "text-[rgb(var(--text-muted))] hover:bg-[rgb(var(--bg-elevated))] hover:text-[rgb(var(--text-primary))]"
        }
      `}
    >
      {icon}
      {label}
    </button>
  );
}

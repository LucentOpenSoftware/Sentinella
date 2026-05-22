import { Sidebar, type Page } from "./Sidebar";
import { TopBar } from "./TopBar";

interface AppShellProps {
  currentPage: Page;
  onNavigate: (page: Page) => void;
  connected: boolean;
  onRefresh?: () => void;
  children: React.ReactNode;
}

const pageMeta: Record<Page, { title: string; subtitle?: string }> = {
  dashboard: { title: "Dashboard", subtitle: "System overview" },
  scan: { title: "Scan", subtitle: "Run a virus scan" },
  quarantine: { title: "Quarantine", subtitle: "Isolated threats" },
  history: { title: "History", subtitle: "Scan records" },
  settings: { title: "Settings", subtitle: "Configure Sentinella" },
  about: { title: "About", subtitle: "Sentinella v0.1.0" },
};

export function AppShell({ currentPage, onNavigate, connected, onRefresh, children }: AppShellProps) {
  const meta = pageMeta[currentPage];
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar current={currentPage} onNavigate={onNavigate} />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar title={meta.title} subtitle={meta.subtitle} connected={connected} onRefresh={onRefresh} />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}

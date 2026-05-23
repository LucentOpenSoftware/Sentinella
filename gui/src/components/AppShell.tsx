import { Sidebar, type Page } from "./Sidebar";
import { TopBar } from "./TopBar";
import { t } from "../i18n";

/** [title i18n key, subtitle string] per page. */
const metaKeys: Record<Page, [string, string]> = {
  dashboard: ["nav.dashboard", "System overview"],
  scan: ["nav.scan", "Run a virus scan"],
  quarantine: ["nav.quarantine", "Isolated threats"],
  history: ["nav.history", "Scan records"],
  notifications: ["nav.notifications", "Alert history"],
  update: ["nav.update", "Signature database"],
  settings: ["nav.settings", "Configure Sentinella"],
  about: ["nav.about", "Sentinella v0.1.0"],
};

export function AppShell({ currentPage, onNavigate, connected, onRefresh, notices, children }: {
  currentPage: Page;
  onNavigate: (p: Page) => void;
  connected: boolean;
  onRefresh?: () => void;
  notices?: React.ReactNode[];
  children: React.ReactNode;
}) {
  const [titleKey, subtitle] = metaKeys[currentPage];
  const title = t(titleKey);
  return (
    <div className="flex h-screen overflow-hidden bg-[rgb(var(--base))]">
      <Sidebar current={currentPage} onNavigate={onNavigate} />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar title={title} subtitle={subtitle} connected={connected} onRefresh={onRefresh} onNotifications={() => onNavigate("notifications")} notices={notices} />
        <main className="flex-1 overflow-y-auto px-14 py-10 content-depth">
          <div className="app-shell-width">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

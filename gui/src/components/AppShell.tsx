import { Sidebar, type Page } from "./Sidebar";
import { TopBar } from "./TopBar";
import { t, tf } from "../i18n";
import { APP_VERSION_TAG } from "../app-version";

/** Page title i18n key per page. */
const titleKeys: Record<Page, string> = {
  dashboard: "nav.dashboard",
  scan: "nav.scan",
  quarantine: "nav.quarantine",
  history: "nav.history",
  notifications: "nav.notifications",
  intelligence: "nav.intelligence",
  update: "nav.update",
  settings: "nav.settings",
  about: "nav.about",
};

/**
 * Subtitle i18n key per page. These used to be English literals while the
 * matching `meta.*_sub` values sat translated and unread in all 9 locale files
 * — so e.g. a German user read German titles over English subtitles on every
 * page. `about` is absent on purpose; see subtitleFor().
 */
const subtitleKeys: Record<Exclude<Page, "about">, string> = {
  dashboard: "meta.dashboard_sub",
  scan: "meta.scan_sub",
  quarantine: "meta.quarantine_sub",
  history: "meta.history_sub",
  notifications: "meta.notifications_sub",
  intelligence: "meta.intelligence_sub",
  update: "meta.update_sub",
  settings: "meta.settings_sub",
};

/** English fallbacks for subtitle keys no locale file defines yet. */
const subtitleFallbacks: Partial<Record<Page, string>> = {
  // meta.intelligence_sub exists in none of the 9 locales.
  intelligence: "ASTRA adaptive analysis",
};

/** TopBar subtitle for `page`, in the active locale. */
function subtitleFor(page: Page): string {
  // Not a translatable sentence — a product name plus the version, which must
  // come from APP_VERSION so a release bump cannot miss it. (The locale files
  // used to carry a hardcoded "meta.about_sub" holding the version as text;
  // it was dead and is gone. See app-version.ts.)
  if (page === "about") return `Sentinella ${APP_VERSION_TAG}`;
  // tf, not t: a key missing everywhere must render as blank (TopBar hides an
  // empty subtitle), never as the literal string "meta.foo_sub".
  return tf(subtitleKeys[page], subtitleFallbacks[page] ?? "");
}

export function AppShell({ currentPage, onNavigate, connected, onRefresh, notices, children }: {
  currentPage: Page;
  onNavigate: (p: Page) => void;
  connected: boolean;
  onRefresh?: () => void;
  notices?: React.ReactNode[];
  children: React.ReactNode;
}) {
  const title = t(titleKeys[currentPage]);
  const subtitle = subtitleFor(currentPage);
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

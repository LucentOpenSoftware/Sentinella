import { Shield, Search, Archive, Clock, Settings, Info, RefreshCw, Bell, Activity } from "lucide-react";
import { ShieldIcon } from "./ShieldIcon";
import { t } from "../i18n";
import { APP_VERSION_TAG } from "../app-version";

export type Page = "dashboard" | "scan" | "quarantine" | "history" | "notifications" | "intelligence" | "update" | "settings" | "about";

const groups = [
  { labelKey: "nav.protection", items: [
    { page: "dashboard" as Page, labelKey: "nav.dashboard", Icon: Shield },
    { page: "scan" as Page, labelKey: "nav.scan", Icon: Search },
    { page: "quarantine" as Page, labelKey: "nav.quarantine", Icon: Archive },
    { page: "history" as Page, labelKey: "nav.history", Icon: Clock },
    { page: "notifications" as Page, labelKey: "nav.notifications", Icon: Bell },
    { page: "intelligence" as Page, labelKey: "nav.intelligence", Icon: Activity },
  ]},
  { labelKey: "nav.system", items: [
    { page: "update" as Page, labelKey: "nav.update", Icon: RefreshCw },
    { page: "settings" as Page, labelKey: "nav.settings", Icon: Settings },
    { page: "about" as Page, labelKey: "nav.about", Icon: Info },
  ]},
];

export function Sidebar({ current, onNavigate }: { current: Page; onNavigate: (p: Page) => void }) {
  return (
    <aside className="flex h-screen w-[248px] flex-shrink-0 flex-col glass-sidebar">
      {/* Brand area — generous, calm */}
      <div className="flex items-center gap-3.5 px-6 py-6">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[rgb(var(--accent))] to-[rgb(var(--accent))]/60 flex items-center justify-center shadow-lg shadow-[rgb(var(--accent))]/10 overflow-hidden">
          <ShieldIcon icon="sentinel" size={30} className="brightness-0 invert" />
        </div>
        <div>
          <p className="text-[15px] font-bold leading-none tracking-tight">{t("app.name")}</p>
          <p className="text-[11px] text-[rgb(var(--t3))] mt-1">{t("app.subtitle")}</p>
        </div>
      </div>

      {/* Navigation — spacious, desktop-native */}
      <nav className="flex-1 overflow-y-auto px-5 pb-4">
        {groups.map(g => (
          <div key={g.labelKey} className="mb-7">
            <p className="mb-3 px-4 text-[10px] font-semibold tracking-[0.15em] text-[rgb(var(--t3))]/35 uppercase">
              {t(g.labelKey)}
            </p>
            <div className="space-y-1">
              {g.items.map(item => {
                const active = current === item.page;
                return (
                  <button key={item.page} onClick={() => onNavigate(item.page)}
                    aria-current={active ? "page" : undefined}
                    className={`w-full flex items-center gap-3 rounded-xl px-4 py-3 text-[13px] font-medium cursor-pointer transition-colors
                      ${active
                        ? "bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))]"
                        : "text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/40 hover:text-[rgb(var(--t1))]"
                      }`}
                  >
                    <item.Icon size={18} strokeWidth={active ? 2 : 1.5} />
                    {t(item.labelKey)}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-6 py-6 text-[10px] text-[rgb(var(--t3))]/20">
        {APP_VERSION_TAG} · GPLv2
      </div>
    </aside>
  );
}

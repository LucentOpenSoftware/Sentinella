// Settings page — v0.1.8 tab shell.
//
// Top-pill nav (Windows 11 Settings vibe). Each tab is a leaf
// component that reads from useFullConfig() and calls update*()/
// resetField()/save() — no direct API calls inside tabs.
//
// The Legacy tab keeps the v0.1.7 Settings UI alive until every
// piece of it has been ported to a typed tab. It does NOT use the
// FullConfig hook — it's the original mostly-flat-list UI.

import { useEffect, useState } from "react";
import {
  Bell,
  CheckCircle,
  ChevronRight,
  Cpu,
  FlaskConical,
  Layers,
  Loader2,
  RefreshCw,
  Save,
  Server,
  Shield,
  ShieldAlert,
  Wrench,
  XCircle,
} from "lucide-react";
import * as i18n from "../../i18n";
import { invoke } from "@tauri-apps/api/core";
import { LegacySettingsPage } from "./legacy";
import { ProtectionTab } from "./tabs/Protection";
import { TabStub } from "./tabs/Stubs";
import { useFullConfig } from "./hooks/useFullConfig";

type TabKey =
  | "protection"
  | "updates"
  | "schedule"
  | "engine"
  | "ransomware"
  | "sandbox"
  | "notifications"
  | "advanced"
  | "legacy";

interface TabDef {
  key: TabKey;
  label: string;
  icon: React.ReactNode;
  phase: number;
}

function tabs(): TabDef[] {
  return [
    {
      key: "protection",
      label: i18n.t("settings.tab_protection"),
      icon: <Shield className="w-4 h-4" />,
      phase: 1,
    },
    {
      key: "updates",
      label: i18n.t("settings.tab_updates"),
      icon: <RefreshCw className="w-4 h-4" />,
      phase: 2,
    },
    {
      key: "engine",
      label: i18n.t("settings.tab_engine"),
      icon: <Cpu className="w-4 h-4" />,
      phase: 2,
    },
    {
      key: "schedule",
      label: i18n.t("settings.tab_schedule"),
      icon: <Layers className="w-4 h-4" />,
      phase: 3,
    },
    {
      key: "ransomware",
      label: i18n.t("settings.tab_ransomware"),
      icon: <ShieldAlert className="w-4 h-4" />,
      phase: 4,
    },
    {
      key: "sandbox",
      label: i18n.t("settings.tab_sandbox"),
      icon: <FlaskConical className="w-4 h-4" />,
      phase: 4,
    },
    {
      key: "notifications",
      label: i18n.t("settings.tab_notifications"),
      icon: <Bell className="w-4 h-4" />,
      phase: 5,
    },
    {
      key: "advanced",
      label: i18n.t("settings.tab_advanced"),
      icon: <Wrench className="w-4 h-4" />,
      phase: 5,
    },
    {
      key: "legacy",
      label: i18n.t("settings.tab_legacy"),
      icon: <Server className="w-4 h-4" />,
      phase: 0,
    },
  ];
}

export function SettingsPage() {
  const [active, setActive] = useState<TabKey>("protection");
  const ctx = useFullConfig();
  const [isElevated, setIsElevated] = useState(false);
  const [saveResult, setSaveResult] = useState<{
    ok: boolean;
    message: string;
  } | null>(null);

  useEffect(() => {
    invoke<boolean>("is_elevated_check")
      .then(setIsElevated)
      .catch(() => setIsElevated(false));
  }, []);

  const onRestartAsAdmin = () => {
    invoke<{ ok: boolean; error?: string }>("restart_as_admin").catch(() => {});
  };

  const onSave = async () => {
    setSaveResult(null);
    const r = await ctx.save();
    if (r.ok) {
      setSaveResult({ ok: true, message: i18n.t("settings.saved_ok") });
    } else if (r.requires_elevation) {
      setSaveResult({
        ok: false,
        message: i18n.t("settings.requires_elevation"),
      });
    } else {
      setSaveResult({ ok: false, message: r.error ?? "unknown error" });
    }
    // Auto-clear after 4s.
    setTimeout(() => setSaveResult(null), 4000);
  };

  const tabList = tabs();
  const activeTab = tabList.find((t) => t.key === active)!;

  return (
    <div className="h-full flex flex-col">
      <header className="px-6 pt-5 pb-3 border-b border-[rgb(var(--border))]/30">
        <h2 className="text-2xl font-semibold mb-1">
          {i18n.t("settings.title")}
        </h2>
        <p className="text-sm text-[rgb(var(--muted))]">
          {i18n.t("settings.subtitle")}
        </p>
      </header>

      {/* ── Windows 11 pill nav ──────────────────────────── */}
      <nav
        className="px-6 py-3 border-b border-[rgb(var(--border))]/30 flex flex-wrap gap-1.5 overflow-x-auto"
        role="tablist"
      >
        {tabList.map((t) => {
          const isActive = t.key === active;
          return (
            <button
              key={t.key}
              onClick={() => setActive(t.key)}
              role="tab"
              aria-selected={isActive}
              className={`px-3 py-1.5 rounded-full text-sm flex items-center gap-2 whitespace-nowrap transition-colors ${
                isActive
                  ? "bg-[rgb(var(--accent))]/15 text-[rgb(var(--accent))] border border-[rgb(var(--accent))]/40"
                  : "border border-transparent text-[rgb(var(--muted))] hover:bg-[rgb(var(--surface))]/60"
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          );
        })}
      </nav>

      {/* ── Tab body ────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {ctx.status.kind === "loading" && active !== "legacy" && (
          <div className="flex items-center gap-3 text-[rgb(var(--muted))] text-sm py-12 justify-center">
            <Loader2 className="w-4 h-4 animate-spin" />
            {i18n.t("settings.loading")}
          </div>
        )}
        {ctx.status.kind === "error" && active !== "legacy" && (
          <div className="text-sm text-red-400 py-12 text-center">
            <XCircle className="w-6 h-6 mx-auto mb-2" />
            {ctx.status.message}
          </div>
        )}
        {ctx.status.kind !== "loading" && ctx.status.kind !== "error" && (
          <>
            {active === "protection" && (
              <ProtectionTab
                ctx={ctx}
                isElevated={isElevated}
                onRestartAsAdmin={onRestartAsAdmin}
              />
            )}
            {active === "updates" && (
              <TabStub
                title={i18n.t("settings.tab_updates")}
                phase={activeTab.phase}
              />
            )}
            {active === "engine" && (
              <TabStub
                title={i18n.t("settings.tab_engine")}
                phase={activeTab.phase}
              />
            )}
            {active === "schedule" && (
              <TabStub
                title={i18n.t("settings.tab_schedule")}
                phase={activeTab.phase}
              />
            )}
            {active === "ransomware" && (
              <TabStub
                title={i18n.t("settings.tab_ransomware")}
                phase={activeTab.phase}
              />
            )}
            {active === "sandbox" && (
              <TabStub
                title={i18n.t("settings.tab_sandbox")}
                phase={activeTab.phase}
              />
            )}
            {active === "notifications" && (
              <TabStub
                title={i18n.t("settings.tab_notifications")}
                phase={activeTab.phase}
              />
            )}
            {active === "advanced" && (
              <TabStub
                title={i18n.t("settings.tab_advanced")}
                phase={activeTab.phase}
              />
            )}
            {active === "legacy" && <LegacySettingsPage />}
          </>
        )}
      </div>

      {/* ── Save footer ─────────────────────────────────── */}
      {active !== "legacy" && (
        <footer className="px-6 py-3 border-t border-[rgb(var(--border))]/30 flex items-center justify-between gap-3">
          <div className="text-xs text-[rgb(var(--muted))] flex items-center gap-2">
            {ctx.isDirty ? (
              <>
                <ChevronRight className="w-3 h-3" />
                {ctx.isCriticalDirty
                  ? i18n.t("settings.unsaved_changes_critical")
                  : i18n.t("settings.unsaved_changes")}
              </>
            ) : (
              <>{i18n.t("settings.all_saved")}</>
            )}
          </div>
          <div className="flex items-center gap-2">
            {saveResult && (
              <span
                className={`text-xs flex items-center gap-1 ${
                  saveResult.ok ? "text-emerald-400" : "text-red-400"
                }`}
              >
                {saveResult.ok ? (
                  <CheckCircle className="w-3 h-3" />
                ) : (
                  <XCircle className="w-3 h-3" />
                )}
                {saveResult.message}
              </span>
            )}
            <button
              onClick={() => ctx.reload()}
              disabled={!ctx.isDirty || ctx.status.kind === "saving"}
              className="px-3 py-1.5 text-xs rounded border border-[rgb(var(--border))]/40 hover:border-[rgb(var(--muted))] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {i18n.t("settings.discard")}
            </button>
            <button
              onClick={onSave}
              disabled={!ctx.isDirty || ctx.status.kind === "saving"}
              className="px-3 py-1.5 text-xs rounded bg-[rgb(var(--accent))] text-white disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
            >
              {ctx.status.kind === "saving" ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Save className="w-3 h-3" />
              )}
              {i18n.t("settings.save")}
            </button>
          </div>
        </footer>
      )}
    </div>
  );
}

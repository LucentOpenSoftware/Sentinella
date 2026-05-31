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
  Palette,
  RefreshCw,
  Save,
  Shield,
  ShieldAlert,
  Wrench,
  XCircle,
} from "lucide-react";
import * as i18n from "../../i18n";
import { invoke } from "@tauri-apps/api/core";
import { AdvancedTab } from "./tabs/Advanced";
import { AppearanceTab } from "./tabs/Appearance";
import { EngineTab } from "./tabs/Engine";
import { NotificationsTab } from "./tabs/Notifications";
import { ProtectionTab } from "./tabs/Protection";
import { RansomwareTab } from "./tabs/Ransomware";
import { SandboxTab } from "./tabs/Sandbox";
import { ScheduleTab } from "./tabs/Schedule";
import { UpdatesTab } from "./tabs/Updates";
import { useFullConfig } from "./hooks/useFullConfig";

type TabKey =
  | "protection"
  | "updates"
  | "engine"
  | "schedule"
  | "ransomware"
  | "sandbox"
  | "notifications"
  | "appearance"
  | "advanced";

interface TabDef {
  key: TabKey;
  label: string;
  icon: React.ReactNode;
}

function tabs(): TabDef[] {
  return [
    { key: "protection", label: i18n.t("settings.tab_protection"), icon: <Shield /> },
    { key: "updates", label: i18n.t("settings.tab_updates"), icon: <RefreshCw /> },
    { key: "engine", label: i18n.t("settings.tab_engine"), icon: <Cpu /> },
    { key: "schedule", label: i18n.t("settings.tab_schedule"), icon: <Layers /> },
    { key: "ransomware", label: i18n.t("settings.tab_ransomware"), icon: <ShieldAlert /> },
    { key: "sandbox", label: i18n.t("settings.tab_sandbox"), icon: <FlaskConical /> },
    { key: "notifications", label: i18n.t("settings.tab_notifications"), icon: <Bell /> },
    { key: "appearance", label: i18n.t("settings.tab_appearance"), icon: <Palette /> },
    { key: "advanced", label: i18n.t("settings.tab_advanced"), icon: <Wrench /> },
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

  return (
    <div className="h-full flex flex-col">
      <header className="px-5 pt-3 pb-2 border-b border-[rgb(var(--border))]/30">
        <h2 className="text-lg font-semibold">
          {i18n.t("settings.title")}
        </h2>
        <p className="text-xs text-[rgb(var(--muted))]">
          {i18n.t("settings.subtitle")}
        </p>
      </header>

      {/* ── Windows 11 pill nav ──────────────────────────── */}
      <nav
        className="px-5 py-2 border-b border-[rgb(var(--border))]/30 flex flex-wrap gap-1 overflow-x-auto"
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
              className={`px-2.5 py-1 rounded-full text-xs flex items-center gap-1.5 whitespace-nowrap transition-colors [&>svg]:w-3.5 [&>svg]:h-3.5 ${
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
      <div className="flex-1 overflow-y-auto px-5 py-3">
        {/* Appearance + Notifications tabs are GUI-local (no FullConfig
            needed), so they render even while ctx is still loading. */}
        {active === "appearance" && <AppearanceTab />}
        {active === "notifications" && <NotificationsTab />}

        {ctx.status.kind === "loading" &&
          active !== "appearance" &&
          active !== "notifications" && (
            <div className="flex items-center gap-3 text-[rgb(var(--muted))] text-sm py-12 justify-center">
              <Loader2 className="w-4 h-4 animate-spin" />
              {i18n.t("settings.loading")}
            </div>
          )}
        {ctx.status.kind === "error" &&
          active !== "appearance" &&
          active !== "notifications" && (
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
            {active === "updates" && <UpdatesTab ctx={ctx} />}
            {active === "engine" && (
              <EngineTab
                ctx={ctx}
                isElevated={isElevated}
                onRestartAsAdmin={onRestartAsAdmin}
              />
            )}
            {active === "schedule" && (
              <ScheduleTab
                ctx={ctx}
                isElevated={isElevated}
                onRestartAsAdmin={onRestartAsAdmin}
              />
            )}
            {active === "ransomware" && (
              <RansomwareTab
                ctx={ctx}
                isElevated={isElevated}
                onRestartAsAdmin={onRestartAsAdmin}
              />
            )}
            {active === "sandbox" && (
              <SandboxTab
                ctx={ctx}
                isElevated={isElevated}
                onRestartAsAdmin={onRestartAsAdmin}
              />
            )}
            {active === "advanced" && <AdvancedTab ctx={ctx} />}
          </>
        )}
      </div>

      {/* ── Save footer ─────────────────────────────────── */}
      {/* Hide footer on GUI-local tabs — they auto-save to localStorage. */}
      {active !== "appearance" && active !== "notifications" && (
        <footer className="px-5 py-2 border-t border-[rgb(var(--border))]/30 flex items-center justify-between gap-3">
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

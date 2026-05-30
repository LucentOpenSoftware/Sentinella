import { useState, useEffect } from "react";
import { Archive, Bell, Bug, CheckCircle, Clock, Eye, FileSearch, FolderOpen, Globe, Palette, RefreshCw, Shield, ShieldOff, Wrench, Loader2, Plus, X, AlertTriangle, Terminal } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { Card } from "../../components/Card";
import { getDeveloperStatus, setDeveloperMode, runBenchmark, type DeveloperStatus, type BenchmarkReport } from "../../api/sentinella";
import { useSettings, type DaemonConfig } from "../../hooks/useSettings";
import { loadNotificationSettings, saveNotificationSettings, type NotificationSettings, type NotificationSeverity } from "../../notifications";
import * as i18n from "../../i18n";

type Tab = "general" | "appearance" | "protection" | "notifications" | "updates" | "advanced";

const tabs: { id: Tab; labelKey: string; Icon: React.ComponentType<{ size?: number }> }[] = [
  { id: "general", labelKey: "settings.general", Icon: Globe },
  { id: "appearance", labelKey: "settings.appearance", Icon: Palette },
  { id: "protection", labelKey: "settings.protection", Icon: Shield },
  { id: "notifications", labelKey: "settings.notifications", Icon: Bell },
  { id: "updates", labelKey: "settings.updates", Icon: RefreshCw },
  { id: "advanced", labelKey: "settings.advanced", Icon: Wrench },
];

export function LegacySettingsPage() {
  const [tab, setTab] = useState<Tab>("general");
  const settings = useSettings();

  if (!settings.loaded) {
    return <div className="flex items-center justify-center py-20"><Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin" /></div>;
  }

  return (
    <div className="grid items-start gap-6 xl:grid-cols-[200px_minmax(0,1fr)]">
      <Card className="self-start">
        <div className="space-y-1">
          {tabs.map((item) => (
            <button key={item.id} onClick={() => setTab(item.id)}
              className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-[13px] font-medium transition-colors cursor-pointer ${
                tab === item.id ? "bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))]" : "text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/30 hover:text-[rgb(var(--t1))]"
              }`}>
              <item.Icon size={16} />{i18n.t(item.labelKey)}
            </button>
          ))}
        </div>
        {settings.saving && <p className="text-[9px] text-[rgb(var(--accent))] mt-3 px-4">{i18n.t("settings.saving")}</p>}
        {settings.saveOk && <p className="text-[9px] text-[rgb(var(--green))] mt-1 px-4">{i18n.t("settings.saved")}</p>}
        {settings.saveError && <p className="text-[9px] text-[rgb(var(--red))] mt-1 px-4 truncate" title={settings.saveError}>{i18n.t("settings.save_failed")}</p>}
      </Card>

      <div className="page-stack min-w-0">
        {tab === "general" && <GeneralTab />}
        {tab === "appearance" && <AppearanceTab />}
        {tab === "protection" && <ProtectionTab config={settings.config} update={settings.update} />}
        {tab === "notifications" && <NotificationsTab />}
        {tab === "updates" && <UpdatesTab config={settings.config} update={settings.update} />}
        {tab === "advanced" && <AdvancedTab config={settings.config} update={settings.update} />}
      </div>
    </div>
  );
}

function Section({ title, desc, children }: { title: string; desc?: string; children: React.ReactNode }) {
  return (
    <Card>
      <h4 className="text-[14px] font-semibold">{title}</h4>
      {desc ? <p className="mb-5 mt-1 text-[12px] text-[rgb(var(--t3))]">{desc}</p> : <div className="mt-5" />}
      {children}
    </Card>
  );
}

function Toggle({ icon, label, desc, checked, onChange, disabled }: {
  icon?: React.ReactNode; label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean;
}) {
  return (
    <div className={`flex items-center justify-between gap-4 border-b border-[rgb(var(--border))]/8 py-3.5 last:border-0 ${disabled ? "opacity-40 pointer-events-none" : ""}`}>
      <div className="flex items-center gap-3">
        {icon && <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[rgb(var(--raised))]/30 text-[rgb(var(--t3))]">{icon}</div>}
        <div>
          <p className="text-[13px] font-medium">{label}</p>
          {desc && <p className="mt-0.5 text-[11px] text-[rgb(var(--t3))]">{desc}</p>}
        </div>
      </div>
      <button onClick={() => onChange(!checked)} disabled={disabled}
        className={`flex h-6 w-11 flex-shrink-0 items-center rounded-full px-[3px] transition-colors cursor-pointer disabled:cursor-default ${
          checked ? "justify-end bg-[rgb(var(--accent))]" : "justify-start bg-[rgb(var(--border))]/40"
        }`}>
        <div className="h-4 w-4 rounded-full bg-white shadow-sm" />
      </button>
    </div>
  );
}

/* ─── Tabs ─── */

function GeneralTab() {
  const [locale, setLocaleState] = useState(() => i18n.getLocale());
  return (
    <>
      <Section title={i18n.t("settings.language")} desc={i18n.t("settings.language_desc")}>
        <select
          value={locale}
          onChange={e => { i18n.setLocale(e.target.value); setLocaleState(e.target.value); }}
          className="w-56 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none"
        >
          {i18n.availableLocales().map(l => (
            <option key={l.code} value={l.code}>{l.label}</option>
          ))}
        </select>
      </Section>
    </>
  );
}

function AppearanceTab() {
  const [theme, setTheme] = useState<"dark" | "light">(() => (localStorage.getItem("sentinella-theme") as "dark" | "light") || "dark");
  const [ai, setAi] = useState(() => {
    const saved = localStorage.getItem("sentinella-accent-idx");
    return saved ? parseInt(saved) : 0;
  });
  const colors = [
    { n: "Blue", v: "#3b82f6" }, { n: "Teal", v: "#14b8a6" }, { n: "Purple", v: "#a855f7" },
    { n: "Pink", v: "#ec4899" }, { n: "Orange", v: "#f97316" }, { n: "Cyan", v: "#06b6d4" },
  ];

  // Persist theme choice + apply immediately.
  const handleTheme = (t: "dark" | "light") => {
    setTheme(t);
    localStorage.setItem("sentinella-theme", t);
    document.documentElement.setAttribute("data-theme", t);
  };

  // Persist accent color.
  const handleAccent = (idx: number) => {
    setAi(idx);
    localStorage.setItem("sentinella-accent-idx", String(idx));
    // Apply accent color to CSS variable.
    const hex = colors[idx].v;
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    document.documentElement.style.setProperty("--accent", `${r} ${g} ${b}`);
  };
  return (
    <>
      <Section title={i18n.t("settings.theme")} desc={i18n.t("settings.theme_desc")}>
        <div className="flex flex-wrap gap-3">
          {(["dark", "light"] as const).map(t => (
            <button key={t} onClick={() => handleTheme(t)} className={`rounded-xl border px-5 py-2 text-[13px] font-medium capitalize cursor-pointer ${
              theme === t ? "border-[rgb(var(--accent))]/20 bg-[rgb(var(--accent))]/6 text-[rgb(var(--accent))]" : "border-[rgb(var(--border))]/15 text-[rgb(var(--t2))]"
            }`}>{i18n.t(`settings.theme_${t}`)}</button>
          ))}
        </div>
      </Section>
      <Section title={i18n.t("settings.accent")} desc={i18n.t("settings.accent_desc")}>
        <div className="flex flex-wrap gap-3">
          {colors.map((c, i) => (
            <button key={c.n} onClick={() => handleAccent(i)} title={c.n} className={`h-9 w-9 rounded-full cursor-pointer transition-transform ${
              ai === i ? "scale-110 ring-2 ring-white ring-offset-2 ring-offset-[rgb(var(--surface))]" : "hover:scale-105"
            }`} style={{ background: c.v }} />
          ))}
        </div>
      </Section>
    </>
  );
}

function ProtectionTab({ config, update }: { config: DaemonConfig; update: (p: Partial<DaemonConfig>) => void }) {
  return (
    <>
      <Section title={i18n.t("settings.realtime_protection")} desc={i18n.t("settings.realtime_desc")}>
        <Toggle icon={<Eye size={14} />} label={i18n.t("settings.enable_realtime")} desc={i18n.t("settings.enable_realtime_desc")}
          checked={config.realtime_enabled} onChange={async (v) => {
            const { setCriticalProtection } = await import("../../api/sentinella");
            const result = await setCriticalProtection({ realtimeEnabled: v });
            if (result?.requires_elevation) { alert(result.error || i18n.t("settings.requires_admin")); return; }
            if (result?.ok) {
              update({}); // Reload config from daemon.
            }
          }} />
        <Toggle icon={<Archive size={14} />} label={i18n.t("settings.auto_quarantine")} desc={i18n.t("settings.auto_quarantine_desc")}
          checked={config.auto_quarantine} onChange={async (v) => {
            const { setCriticalProtection } = await import("../../api/sentinella");
            const result = await setCriticalProtection({ autoQuarantine: v });
            if (result?.requires_elevation) { alert(result.error || i18n.t("settings.requires_admin")); return; }
            if (result?.ok) {
              update({});
            }
          }} />
      </Section>
      <Section title={i18n.t("settings.scan_options")} desc={i18n.t("settings.scan_options_desc")}>
        <Toggle icon={<FileSearch size={14} />} label={i18n.t("settings.scan_archives")} desc={i18n.t("settings.scan_archives_desc")}
          checked={config.scan_archives} onChange={(v) => update({ scan_archives: v })} />
        <Toggle icon={<Bug size={14} />} label={i18n.t("settings.heuristic_alerts")} desc={i18n.t("settings.heuristic_alerts_desc")}
          checked={config.heuristic_alerts} onChange={(v) => update({ heuristic_alerts: v })} />
      </Section>
      <Section title={i18n.t("settings.quarantine_retention")} desc={i18n.t("settings.quarantine_retention_desc")}>
        <select value={String(config.quarantine_retention_days)} onChange={e => update({ quarantine_retention_days: parseInt(e.target.value) })}
          className="w-56 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none">
          <option value="30">{i18n.t("settings.retention_30")}</option><option value="60">{i18n.t("settings.retention_60")}</option><option value="90">{i18n.t("settings.retention_90")}</option>
          <option value="180">{i18n.t("settings.retention_180")}</option><option value="365">{i18n.t("settings.retention_365")}</option>
        </select>
      </Section>
    </>
  );
}

function UpdatesTab({ config, update }: { config: DaemonConfig; update: (p: Partial<DaemonConfig>) => void }) {
  return (
    <>
      <Section title={i18n.t("settings.auto_updates")} desc={i18n.t("settings.auto_updates_desc")}>
        <Toggle icon={<RefreshCw size={14} />} label={i18n.t("settings.auto_update_sigs")} desc={i18n.t("settings.auto_update_sigs_desc")}
          checked={config.auto_update} onChange={(v) => update({ auto_update: v })} />
        <div className="pt-3">
          <p className="text-[13px] font-medium mb-2">{i18n.t("settings.interval")}</p>
          <select value={String(config.update_interval_hours)} onChange={e => update({ update_interval_hours: parseInt(e.target.value) })}
            disabled={!config.auto_update}
            className="w-48 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
            <option value="1">{i18n.t("settings.every_hour")}</option><option value="2">{i18n.t("settings.every_2h")}</option><option value="4">{i18n.t("settings.every_4h")}</option>
            <option value="12">{i18n.t("settings.every_12h")}</option><option value="24">{i18n.t("settings.daily")}</option>
          </select>
        </div>
        <div className="pt-3">
          <p className="text-[13px] font-medium mb-2">{i18n.t("settings.sig_stale")}</p>
          <select value={String(config.signature_stale_days)} onChange={e => update({ signature_stale_days: parseInt(e.target.value) })}
            className="w-48 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none">
            {[3, 5, 7, 14].map(d => (
              <option key={d} value={String(d)}>{d} {i18n.t("settings.days_unit")}</option>
            ))}
          </select>
          <p className="text-[12px] text-[rgb(var(--t3))] mt-1.5">{i18n.t("settings.sig_stale_desc")}</p>
        </div>
      </Section>
      <Section title={i18n.t("settings.scheduled_scans")} desc={i18n.t("settings.scheduled_scans_desc")}>
        <Toggle icon={<Clock size={14} />} label={i18n.t("settings.enable_scheduled_scan")} desc={i18n.t("settings.enable_scheduled_scan_desc")}
          checked={config.scheduled_scan_enabled} onChange={(v) => update({ scheduled_scan_enabled: v })} />
        <div className="flex flex-wrap gap-4 pt-3">
          <div>
            <p className="text-[13px] font-medium mb-2">{i18n.t("settings.time")}</p>
            <select value={String(config.scheduled_scan_hour)} onChange={e => update({ scheduled_scan_hour: parseInt(e.target.value) })}
              disabled={!config.scheduled_scan_enabled}
              className="w-36 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
              {Array.from({ length: 24 }, (_, i) => (
                <option key={i} value={String(i)}>{String(i).padStart(2, "0")}:00</option>
              ))}
            </select>
          </div>
          <div>
            <p className="text-[13px] font-medium mb-2">{i18n.t("settings.scan_type")}</p>
            <select value={config.scheduled_scan_type} onChange={e => update({ scheduled_scan_type: e.target.value })}
              disabled={!config.scheduled_scan_enabled}
              className="w-36 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
              <option value="quick">{i18n.t("settings.scan_type_quick")}</option>
              <option value="full">{i18n.t("settings.scan_type_full")}</option>
            </select>
          </div>
        </div>
      </Section>
    </>
  );
}

function AdvancedTab({ config, update }: { config: DaemonConfig; update: (p: Partial<DaemonConfig>) => void }) {
  const [showShutdown, setShowShutdown] = useState(false);
  const [shutdownPhrase, setShutdownPhrase] = useState("");
  const [shutdownError, setShutdownError] = useState("");

  return (
    <>
      <Section title={i18n.t("settings.exclusions")} desc={i18n.t("settings.exclusions_desc")}>
        {config.excluded_paths.length > 0 && (
          <div className="space-y-2 mb-4">
            {config.excluded_paths.map((p, i) => (
              <div key={i} className="flex items-center gap-3 rounded-xl bg-[rgb(var(--raised))]/15 px-4 py-2.5 group">
                <FolderOpen size={14} className="text-[rgb(var(--t3))] flex-shrink-0" />
                <span className="text-[12px] text-[rgb(var(--t2))] flex-1 min-w-0 truncate font-mono" title={p}>{p}</span>
                <button
                  onClick={() => update({ excluded_paths: config.excluded_paths.filter((_, j) => j !== i) })}
                  className="opacity-0 group-hover:opacity-100 flex-shrink-0 p-1 rounded-lg hover:bg-[rgb(var(--red))]/10 text-[rgb(var(--t3))] hover:text-[rgb(var(--red))] transition-all cursor-pointer"
                  title={i18n.t("settings.remove_exclusion")}
                >
                  <X size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
        <button
          onClick={async () => {
            const selected = await open({ multiple: false, directory: true, title: i18n.t("settings.select_folder_title") });
            if (selected && typeof selected === "string") {
              if (!config.excluded_paths.includes(selected)) {
                update({ excluded_paths: [...config.excluded_paths, selected] });
              }
            }
          }}
          className="flex items-center gap-2 rounded-xl border border-dashed border-[rgb(var(--border))]/15 px-4 py-3 text-[12px] text-[rgb(var(--t3))] hover:border-[rgb(var(--accent))]/30 hover:text-[rgb(var(--accent))] transition-colors cursor-pointer w-full justify-center"
        >
          <Plus size={14} />
          {i18n.t("settings.add_folder")}
        </button>
        {config.excluded_paths.length > 0 && (
          <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-3">
            {i18n.t("settings.paths_excluded").replace("{count}", String(config.excluded_paths.length))}
          </p>
        )}
      </Section>

      <Section title={i18n.t("settings.detection_excl")} desc={i18n.t("settings.detection_excl_full_desc")}>
        <ExclusionList
          items={config.excluded_detections}
          onAdd={(v) => update({ excluded_detections: [...config.excluded_detections, v] })}
          onRemove={(i) => update({ excluded_detections: config.excluded_detections.filter((_, j) => j !== i) })}
          placeholder='e.g. "Win.Test.EICAR_HDB-1" or "ARGUS/Suspicious.Generic"'
          icon={<ShieldOff size={14} className="text-[rgb(var(--t3))] flex-shrink-0" />}
          addLabel={i18n.t("settings.add_detection")}
        />
      </Section>

      <Section title={i18n.t("settings.trusted_hashes")} desc={i18n.t("settings.trusted_hashes_full_desc")}>
        <ExclusionList
          items={config.trusted_hashes}
          onAdd={(v) => {
            const clean = v.trim().toLowerCase();
            if (clean.length === 64 && /^[0-9a-f]+$/.test(clean)) {
              update({ trusted_hashes: [...config.trusted_hashes, clean] });
            }
          }}
          onRemove={(i) => update({ trusted_hashes: config.trusted_hashes.filter((_, j) => j !== i) })}
          placeholder={i18n.t("settings.trusted_hash_placeholder")}
          icon={<CheckCircle size={14} className="text-[rgb(var(--green))] flex-shrink-0" />}
          addLabel={i18n.t("settings.add_hash")}
          mono
        />
      </Section>

      <Section title={i18n.t("settings.logging")} desc={i18n.t("settings.logging_desc")}>
        <select value={config.log_level} onChange={e => update({ log_level: e.target.value })}
          className="w-48 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none">
          <option value="error">{i18n.t("settings.log_error")}</option><option value="warn">{i18n.t("settings.log_warn")}</option><option value="info">{i18n.t("settings.log_info")}</option>
          <option value="debug">{i18n.t("settings.log_debug")}</option><option value="trace">{i18n.t("settings.log_trace")}</option>
        </select>
      </Section>
      <Section title={i18n.t("settings.engine_limits")}>
        <div className="space-y-3 text-[13px]">
          <LR l={i18n.t("settings.max_file_size")} v={`${config.max_file_size_mb} MB`} />
          <LR l={i18n.t("settings.named_pipe")} v="\\.\pipe\sentinelld" />
          <LR l={i18n.t("settings.quarantine_retention")} v={`${config.quarantine_retention_days} ${i18n.t("settings.days_unit")}`} />
          <LR l={i18n.t("settings.update_mirror")} v={config.update_mirror} />
        </div>
      </Section>

      {/* Protection Shutdown — guarded by confirmation */}
      <Section title={i18n.t("settings.protection_control")} desc={i18n.t("settings.protection_control_desc")}>
        {!showShutdown ? (
          <button onClick={() => setShowShutdown(true)}
            className="flex items-center gap-2 text-[12px] text-[rgb(var(--red))]/60 hover:text-[rgb(var(--red))] cursor-pointer transition-colors">
            <AlertTriangle size={13} />
            {i18n.t("settings.disable_protection")}
          </button>
        ) : (
          <div className="rounded-xl border border-[rgb(var(--red))]/15 bg-[rgb(var(--red))]/5 p-5">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle size={18} className="text-[rgb(var(--red))] flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-[13px] font-semibold text-[rgb(var(--red))]">{i18n.t("settings.disable_all_protection")}</p>
                <p className="text-[12px] text-[rgb(var(--t2))] mt-1.5 leading-relaxed">
                  {i18n.t("settings.shutdown_warning")}
                </p>
              </div>
            </div>
            <p className="text-[11px] text-[rgb(var(--t3))] mb-3">
              {i18n.t("settings.type_to_confirm").replace("{phrase}", "")}
              <strong className="text-[rgb(var(--red))] font-mono">DISABLE PROTECTION</strong>
            </p>
            <input
              type="text"
              value={shutdownPhrase}
              onChange={(e) => { setShutdownPhrase(e.target.value); setShutdownError(""); }}
              placeholder={i18n.t("settings.confirmation_placeholder")}
              className="w-full rounded-xl border border-[rgb(var(--red))]/20 bg-[rgb(var(--base))] px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none font-mono mb-3"
              autoComplete="off"
              spellCheck={false}
            />
            {shutdownError && (
              <p className="text-[11px] text-[rgb(var(--red))] mb-3">{shutdownError}</p>
            )}
            <div className="flex gap-3">
              <button onClick={async () => {
                if (shutdownPhrase !== "DISABLE PROTECTION") {
                  setShutdownError(i18n.t("settings.incorrect_phrase"));
                  return;
                }
                try {
                  const result = await invoke<any>("confirmed_shutdown", { confirmation: shutdownPhrase });
                  if (result?.requires_elevation) {
                    setShutdownError(result.error || i18n.t("settings.requires_admin"));
                    return;
                  }
                } catch (e) {
                  setShutdownError(String(e));
                }
              }} disabled={shutdownPhrase.length < 5}
                className="px-4 py-2 rounded-xl bg-[rgb(var(--red))] text-white text-[12px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-30">
                {i18n.t("settings.confirm_shutdown")}
              </button>
              <button onClick={() => { setShowShutdown(false); setShutdownPhrase(""); setShutdownError(""); }}
                className="px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] cursor-pointer">
                {i18n.t("common.cancel")}
              </button>
            </div>
          </div>
        )}
      </Section>

      <DeveloperSection />
    </>
  );
}

/**
 * Developer mode (v0.1.6) — password-gated, per-machine, LOCAL ONLY. Enabling it
 * turns on a perf-telemetry dump written to a txt file in the AV data dir so the
 * author can compare behavior across hardware. Nothing leaves the machine. The
 * section only appears once an unlock password hash has been provisioned in the
 * daemon config (out-of-band). The plaintext password is verified daemon-side
 * and never stored by the GUI.
 */
function DeveloperSection() {
  const [status, setStatus] = useState<DeveloperStatus | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [benchBusy, setBenchBusy] = useState(false);
  const [bench, setBench] = useState<BenchmarkReport | null>(null);
  const [benchError, setBenchError] = useState("");

  const refresh = async () => {
    try { setStatus(await getDeveloperStatus()); } catch { /* daemon may be offline */ }
  };
  useEffect(() => { void refresh(); }, []);

  const toggle = async (enabled: boolean, telemetry?: boolean) => {
    if (password.length === 0) { setError(i18n.t("settings.dev_password_required")); return; }
    setBusy(true); setError("");
    try {
      const res = await setDeveloperMode(password, enabled, telemetry);
      if (res?.error) { setError(res.error); }
      else { setPassword(""); await refresh(); }
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  };

  const doBenchmark = async () => {
    setBenchBusy(true); setBenchError(""); setBench(null);
    try {
      const r = await runBenchmark(3);
      if (r?.error) { setBenchError(r.error); }
      else { setBench(r); await refresh(); }
    } catch (e) { setBenchError(String(e)); }
    finally { setBenchBusy(false); }
  };

  // Hidden entirely until the daemon reports dev mode is provisioned.
  if (!status || !status.provisioned) return null;

  return (
    <Section title={i18n.t("settings.developer_mode")} desc={i18n.t("settings.developer_mode_desc")}>
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Terminal size={14} className="text-[rgb(var(--t3))]" />
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${status.enabled ? "bg-[rgb(var(--green))]/15 text-[rgb(var(--green))]" : "bg-[rgb(var(--raised))]/40 text-[rgb(var(--t3))]"}`}>
            {status.enabled ? i18n.t("settings.dev_on") : i18n.t("settings.dev_off")}
          </span>
        </div>

        <input
          type="password"
          value={password}
          onChange={(e) => { setPassword(e.target.value); setError(""); }}
          placeholder={i18n.t("settings.dev_password_placeholder")}
          className="w-full rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--base))] px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none"
          autoComplete="off"
          spellCheck={false}
        />
        {error && <p className="text-[11px] text-[rgb(var(--red))]">{error}</p>}

        <div className="flex gap-3">
          {!status.enabled ? (
            <button onClick={() => toggle(true)} disabled={busy || password.length === 0}
              className="px-4 py-2 rounded-xl bg-[rgb(var(--accent))] text-white text-[12px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-30">
              {i18n.t("settings.dev_enable")}
            </button>
          ) : (
            <button onClick={() => toggle(false)} disabled={busy || password.length === 0}
              className="px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] cursor-pointer disabled:opacity-30">
              {i18n.t("settings.dev_disable")}
            </button>
          )}
        </div>

        {status.enabled && (
          <div className="border-t border-[rgb(var(--border))]/8 pt-2">
            <Toggle
              icon={<Bug size={14} />}
              label={i18n.t("settings.dev_telemetry")}
              desc={i18n.t("settings.dev_telemetry_desc")}
              checked={status.telemetry_enabled}
              onChange={(v) => toggle(true, v)}
            />
            <div className="space-y-2 text-[12px] mt-2">
              <LR l={i18n.t("settings.dev_dump_path")} v={status.dump_path} />
              <LR l={i18n.t("settings.dev_dump_size")} v={`${status.dump_size_kb} / ${status.telemetry_max_kb} KB`} />
            </div>

            <div className="mt-4 border-t border-[rgb(var(--border))]/8 pt-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-[13px] font-medium">{i18n.t("settings.dev_benchmark")}</p>
                  <p className="mt-0.5 text-[11px] text-[rgb(var(--t3))]">{i18n.t("settings.dev_benchmark_desc")}</p>
                </div>
                <button onClick={doBenchmark} disabled={benchBusy}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[rgb(var(--accent))] text-white text-[12px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-40 flex-shrink-0">
                  {benchBusy && <Loader2 size={13} className="animate-spin" />}
                  {benchBusy ? i18n.t("settings.dev_benchmark_running") : i18n.t("settings.dev_benchmark_run")}
                </button>
              </div>
              {benchError && <p className="text-[11px] text-[rgb(var(--red))] mt-3">{benchError}</p>}
              {bench && (
                <div className="mt-3 rounded-xl bg-[rgb(var(--raised))]/15 p-4 space-y-2 text-[12px]">
                  <LR l={i18n.t("settings.dev_bench_index")} v={String(bench.performance_index ?? "—")} />
                  <LR l={i18n.t("settings.dev_bench_throughput")} v={`${(bench.files_per_sec ?? 0).toFixed(1)} files/s · ${(bench.mb_per_sec ?? 0).toFixed(1)} MB/s`} />
                  <LR l={i18n.t("settings.dev_bench_latency")} v={`p50 ${bench.per_file_us?.p50 ?? 0}µs · p95 ${bench.per_file_us?.p95 ?? 0}µs`} />
                  <LR l={i18n.t("settings.dev_bench_system")} v={`${bench.system?.logical_cores ?? 0} cores · ${(bench.system?.simd ?? []).join(",") || "—"}`} />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}

function LR({ l, v }: { l: string; v: string }) {
  return <div className="flex justify-between"><span className="text-[rgb(var(--t3))]">{l}</span><span className="font-mono text-[12px] bg-[rgb(var(--raised))]/25 px-2 py-0.5 rounded text-[rgb(var(--t2))]">{v}</span></div>;
}

function ExclusionList({ items, onAdd, onRemove, placeholder, icon, addLabel, mono }: {
  items: string[];
  onAdd: (v: string) => void;
  onRemove: (i: number) => void;
  placeholder: string;
  icon: React.ReactNode;
  addLabel: string;
  mono?: boolean;
}) {
  const [input, setInput] = useState("");
  return (
    <>
      {items.length > 0 && (
        <div className="space-y-2 mb-4">
          {items.map((item, i) => (
            <div key={i} className="flex items-center gap-3 rounded-xl bg-[rgb(var(--raised))]/15 px-4 py-2.5 group">
              {icon}
              <span className={`text-[12px] text-[rgb(var(--t2))] flex-1 min-w-0 truncate ${mono ? "font-mono" : ""}`} title={item}>{item}</span>
              <button
                onClick={() => onRemove(i)}
                className="opacity-0 group-hover:opacity-100 flex-shrink-0 p-1 rounded-lg hover:bg-[rgb(var(--red))]/10 text-[rgb(var(--t3))] hover:text-[rgb(var(--red))] transition-all cursor-pointer"
                title={i18n.t("settings.remove")}
              >
                <X size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={placeholder}
          className={`flex-1 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/15 px-4 py-2.5 text-[12px] text-[rgb(var(--t1))] placeholder-[rgb(var(--t3))]/30 outline-none ${mono ? "font-mono" : ""}`}
          onKeyDown={e => {
            if (e.key === "Enter" && input.trim()) {
              onAdd(input.trim());
              setInput("");
            }
          }}
        />
        <button
          onClick={() => { if (input.trim()) { onAdd(input.trim()); setInput(""); } }}
          disabled={!input.trim()}
          className="flex items-center gap-2 rounded-xl border border-dashed border-[rgb(var(--border))]/15 px-4 py-2.5 text-[12px] text-[rgb(var(--t3))] hover:border-[rgb(var(--accent))]/30 hover:text-[rgb(var(--accent))] transition-colors cursor-pointer disabled:opacity-30"
        >
          <Plus size={14} />
          {addLabel}
        </button>
      </div>
      {items.length > 0 && (
        <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-3">
          {i18n.t("settings.entries_count").replace("{count}", String(items.length))}
        </p>
      )}
    </>
  );
}

// ── Notifications Tab ────────────────────────────────────────

function NotificationsTab() {
  const [ns, setNs] = useState<NotificationSettings>(loadNotificationSettings);

  const toggle = (key: keyof NotificationSettings) => {
    const updated = { ...ns, [key]: !ns[key] };
    setNs(updated);
    saveNotificationSettings(updated);
  };

  return (
    <>
      <Section title={i18n.t("settings.win_notifications")} desc={i18n.t("settings.win_notifications_desc")}>
        <Toggle label={i18n.t("settings.enable_notifications")} desc={i18n.t("settings.enable_notifications_desc")} checked={ns.enabled} onChange={() => toggle("enabled")} />
      </Section>

      <Section title={i18n.t("settings.notification_events")} desc={i18n.t("settings.notification_events_desc")}>
        <Toggle label={i18n.t("settings.threat_detected")} desc={i18n.t("settings.threat_detected_desc")} checked={ns.onThreat} onChange={() => toggle("onThreat")} disabled={!ns.enabled} />
        <Toggle label={i18n.t("settings.file_quarantined")} desc={i18n.t("settings.file_quarantined_desc")} checked={ns.onQuarantine} onChange={() => toggle("onQuarantine")} disabled={!ns.enabled} />
        <Toggle label={i18n.t("settings.scan_completed_threats")} desc={i18n.t("settings.scan_completed_threats_desc")} checked={ns.onScanComplete} onChange={() => toggle("onScanComplete")} disabled={!ns.enabled} />
        <Toggle label={i18n.t("settings.sig_update_failed")} desc={i18n.t("settings.sig_update_failed_desc")} checked={ns.onUpdateFailure} onChange={() => toggle("onUpdateFailure")} disabled={!ns.enabled} />
        <Toggle label={i18n.t("settings.protection_degraded")} desc={i18n.t("settings.protection_degraded_desc")} checked={ns.onDegraded} onChange={() => toggle("onDegraded")} disabled={!ns.enabled} />
      </Section>

      <Section title={i18n.t("settings.severity_threshold")} desc={i18n.t("settings.severity_threshold_desc")}>
        <div className={`grid grid-cols-4 gap-1 rounded-xl bg-[rgb(var(--raised))]/15 p-1 ${!ns.enabled ? "opacity-40 pointer-events-none" : ""}`}>
          {(["info", "warning", "threat", "critical"] as NotificationSeverity[]).map((level) => (
            <button key={level} onClick={() => {
              const updated = { ...ns, minSeverity: level };
              setNs(updated);
              saveNotificationSettings(updated);
            }} className={`py-2 rounded-lg text-[11px] font-medium capitalize cursor-pointer transition-colors ${
              ns.minSeverity === level
                ? "bg-[rgb(var(--accent))] text-white shadow-sm"
                : "text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/30"
            }`}>{level === "info" ? i18n.t("settings.severity_all") : level}</button>
          ))}
        </div>
        <p className="text-[11px] text-[rgb(var(--t3))] mt-2">
          {ns.minSeverity === "info" && i18n.t("settings.severity_info_desc")}
          {ns.minSeverity === "warning" && i18n.t("settings.severity_warning_desc")}
          {ns.minSeverity === "threat" && i18n.t("settings.severity_threat_desc")}
          {ns.minSeverity === "critical" && i18n.t("settings.severity_critical_desc")}
        </p>
      </Section>

      <Section title={i18n.t("settings.quiet_mode")} desc={i18n.t("settings.quiet_mode_desc")}>
        <Toggle label={i18n.t("settings.quiet_toggle")} desc={i18n.t("settings.quiet_toggle_desc")} checked={ns.quietMode} onChange={() => toggle("quietMode")} disabled={!ns.enabled} />
      </Section>
    </>
  );
}

import { useState } from "react";
import { Archive, Bell, Bug, CheckCircle, Clock, Eye, FileSearch, FolderOpen, Globe, Palette, RefreshCw, Shield, ShieldOff, Wrench, Loader2, Plus, X, AlertTriangle } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { Card } from "../components/Card";
import { useSettings, type DaemonConfig } from "../hooks/useSettings";
import { loadNotificationSettings, saveNotificationSettings, type NotificationSettings, type NotificationSeverity } from "../notifications";
import * as i18n from "../i18n";

type Tab = "general" | "appearance" | "protection" | "notifications" | "updates" | "advanced";

const tabs: { id: Tab; label: string; Icon: React.ComponentType<{ size?: number }> }[] = [
  { id: "general", label: "General", Icon: Globe },
  { id: "appearance", label: "Appearance", Icon: Palette },
  { id: "protection", label: "Protection", Icon: Shield },
  { id: "notifications", label: "Notifications", Icon: Bell },
  { id: "updates", label: "Updates", Icon: RefreshCw },
  { id: "advanced", label: "Advanced", Icon: Wrench },
];

export function SettingsPage() {
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
              <item.Icon size={16} />{item.label}
            </button>
          ))}
        </div>
        {settings.saving && <p className="text-[9px] text-[rgb(var(--accent))] mt-3 px-4">Saving...</p>}
        {settings.saveOk && <p className="text-[9px] text-[rgb(var(--green))] mt-1 px-4">Saved</p>}
        {settings.saveError && <p className="text-[9px] text-[rgb(var(--red))] mt-1 px-4 truncate" title={settings.saveError}>Save failed</p>}
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
      <Section title="Language" desc="Display language. Takes effect on next page navigation.">
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
      <Section title="Theme" desc="Appearance mode.">
        <div className="flex flex-wrap gap-3">
          {(["dark", "light"] as const).map(t => (
            <button key={t} onClick={() => handleTheme(t)} className={`rounded-xl border px-5 py-2 text-[13px] font-medium capitalize cursor-pointer ${
              theme === t ? "border-[rgb(var(--accent))]/20 bg-[rgb(var(--accent))]/6 text-[rgb(var(--accent))]" : "border-[rgb(var(--border))]/15 text-[rgb(var(--t2))]"
            }`}>{t}</button>
          ))}
        </div>
      </Section>
      <Section title="Accent Color" desc="Primary highlight color.">
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
      <Section title="Real-time Protection" desc="Filesystem monitoring. Changes require administrator privileges.">
        <Toggle icon={<Eye size={14} />} label="Enable real-time protection" desc="User-mode watcher"
          checked={config.realtime_enabled} onChange={async (v) => {
            const { setCriticalProtection } = await import("../api/sentinella");
            const result = await setCriticalProtection({ realtimeEnabled: v });
            if (result?.ok) {
              update({}); // Reload config from daemon.
            }
          }} />
        <Toggle icon={<Archive size={14} />} label="Auto-quarantine" desc="Automatically isolate detected threats"
          checked={config.auto_quarantine} onChange={async (v) => {
            const { setCriticalProtection } = await import("../api/sentinella");
            const result = await setCriticalProtection({ autoQuarantine: v });
            if (result?.ok) {
              update({});
            }
          }} />
      </Section>
      <Section title="Scan Options" desc="Default scan behavior.">
        <Toggle icon={<FileSearch size={14} />} label="Scan archives" desc="ZIP, 7z, TAR"
          checked={config.scan_archives} onChange={(v) => update({ scan_archives: v })} />
        <Toggle icon={<Bug size={14} />} label="Heuristic alerts" desc="Suspicious patterns"
          checked={config.heuristic_alerts} onChange={(v) => update({ heuristic_alerts: v })} />
      </Section>
      <Section title="Quarantine Retention" desc="Auto-cleanup period.">
        <select value={String(config.quarantine_retention_days)} onChange={e => update({ quarantine_retention_days: parseInt(e.target.value) })}
          className="w-56 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none">
          <option value="30">30 days</option><option value="60">60 days</option><option value="90">90 days</option>
          <option value="180">180 days</option><option value="365">1 year</option>
        </select>
      </Section>
    </>
  );
}

function UpdatesTab({ config, update }: { config: DaemonConfig; update: (p: Partial<DaemonConfig>) => void }) {
  return (
    <>
      <Section title="Automatic Updates" desc="Signature database updates.">
        <Toggle icon={<RefreshCw size={14} />} label="Auto-update signatures" desc="Check periodically"
          checked={config.auto_update} onChange={(v) => update({ auto_update: v })} />
        <div className="pt-3">
          <p className="text-[13px] font-medium mb-2">Interval</p>
          <select value={String(config.update_interval_hours)} onChange={e => update({ update_interval_hours: parseInt(e.target.value) })}
            disabled={!config.auto_update}
            className="w-48 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
            <option value="1">Every hour</option><option value="2">2 hours</option><option value="4">4 hours</option>
            <option value="12">12 hours</option><option value="24">Daily</option>
          </select>
        </div>
      </Section>
      <Section title="Scheduled Scans" desc="Automatic daily scan.">
        <Toggle icon={<Clock size={14} />} label="Enable scheduled scan" desc="Run automatically at the configured time"
          checked={config.scheduled_scan_enabled} onChange={(v) => update({ scheduled_scan_enabled: v })} />
        <div className="flex flex-wrap gap-4 pt-3">
          <div>
            <p className="text-[13px] font-medium mb-2">Time</p>
            <select value={String(config.scheduled_scan_hour)} onChange={e => update({ scheduled_scan_hour: parseInt(e.target.value) })}
              disabled={!config.scheduled_scan_enabled}
              className="w-36 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
              {Array.from({ length: 24 }, (_, i) => (
                <option key={i} value={String(i)}>{String(i).padStart(2, "0")}:00</option>
              ))}
            </select>
          </div>
          <div>
            <p className="text-[13px] font-medium mb-2">Scan Type</p>
            <select value={config.scheduled_scan_type} onChange={e => update({ scheduled_scan_type: e.target.value })}
              disabled={!config.scheduled_scan_enabled}
              className="w-36 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none disabled:opacity-40">
              <option value="quick">Quick Scan</option>
              <option value="full">Full Scan</option>
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
      <Section title="Exclusions" desc="Paths excluded from all scans and real-time monitoring.">
        {config.excluded_paths.length > 0 && (
          <div className="space-y-2 mb-4">
            {config.excluded_paths.map((p, i) => (
              <div key={i} className="flex items-center gap-3 rounded-xl bg-[rgb(var(--raised))]/15 px-4 py-2.5 group">
                <FolderOpen size={14} className="text-[rgb(var(--t3))] flex-shrink-0" />
                <span className="text-[12px] text-[rgb(var(--t2))] flex-1 min-w-0 truncate font-mono" title={p}>{p}</span>
                <button
                  onClick={() => update({ excluded_paths: config.excluded_paths.filter((_, j) => j !== i) })}
                  className="opacity-0 group-hover:opacity-100 flex-shrink-0 p-1 rounded-lg hover:bg-[rgb(var(--red))]/10 text-[rgb(var(--t3))] hover:text-[rgb(var(--red))] transition-all cursor-pointer"
                  title="Remove exclusion"
                >
                  <X size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
        <button
          onClick={async () => {
            const selected = await open({ multiple: false, directory: true, title: "Select folder to exclude" });
            if (selected && typeof selected === "string") {
              if (!config.excluded_paths.includes(selected)) {
                update({ excluded_paths: [...config.excluded_paths, selected] });
              }
            }
          }}
          className="flex items-center gap-2 rounded-xl border border-dashed border-[rgb(var(--border))]/15 px-4 py-3 text-[12px] text-[rgb(var(--t3))] hover:border-[rgb(var(--accent))]/30 hover:text-[rgb(var(--accent))] transition-colors cursor-pointer w-full justify-center"
        >
          <Plus size={14} />
          Add Excluded Folder
        </button>
        {config.excluded_paths.length > 0 && (
          <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-3">
            {config.excluded_paths.length} path{config.excluded_paths.length > 1 ? "s" : ""} excluded from scanning
          </p>
        )}
      </Section>

      <Section title="Detection Exclusions" desc="Detection names to ignore. Use names from scan results (case-insensitive substring match).">
        <ExclusionList
          items={config.excluded_detections}
          onAdd={(v) => update({ excluded_detections: [...config.excluded_detections, v] })}
          onRemove={(i) => update({ excluded_detections: config.excluded_detections.filter((_, j) => j !== i) })}
          placeholder='e.g. "Win.Test.EICAR_HDB-1" or "ARGUS/Suspicious.Generic"'
          icon={<ShieldOff size={14} className="text-[rgb(var(--t3))] flex-shrink-0" />}
          addLabel="Add Detection Exclusion"
        />
      </Section>

      <Section title="Trusted Hashes" desc="SHA-256 hashes of files to always allow. Paste full 64-character hex hash.">
        <ExclusionList
          items={config.trusted_hashes}
          onAdd={(v) => {
            const clean = v.trim().toLowerCase();
            if (clean.length === 64 && /^[0-9a-f]+$/.test(clean)) {
              update({ trusted_hashes: [...config.trusted_hashes, clean] });
            }
          }}
          onRemove={(i) => update({ trusted_hashes: config.trusted_hashes.filter((_, j) => j !== i) })}
          placeholder="Paste SHA-256 hash (64 hex characters)"
          icon={<CheckCircle size={14} className="text-[rgb(var(--green))] flex-shrink-0" />}
          addLabel="Add Trusted Hash"
          mono
        />
      </Section>

      <Section title="Logging" desc="Daemon log level.">
        <select value={config.log_level} onChange={e => update({ log_level: e.target.value })}
          className="w-48 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/30 px-4 py-2.5 text-[13px] text-[rgb(var(--t1))] outline-none">
          <option value="error">Error</option><option value="warn">Warning</option><option value="info">Info</option>
          <option value="debug">Debug</option><option value="trace">Trace</option>
        </select>
      </Section>
      <Section title="Engine Limits">
        <div className="space-y-3 text-[13px]">
          <LR l="Max file size" v={`${config.max_file_size_mb} MB`} />
          <LR l="Named pipe" v="\\.\pipe\sentinelld" />
          <LR l="Quarantine retention" v={`${config.quarantine_retention_days} days`} />
          <LR l="Update mirror" v={config.update_mirror} />
        </div>
      </Section>

      {/* Protection Shutdown — guarded by confirmation */}
      <Section title="Protection Control" desc="Disable protection and exit Sentinella.">
        {!showShutdown ? (
          <button onClick={() => setShowShutdown(true)}
            className="flex items-center gap-2 text-[12px] text-[rgb(var(--red))]/60 hover:text-[rgb(var(--red))] cursor-pointer transition-colors">
            <AlertTriangle size={13} />
            Disable Protection & Exit...
          </button>
        ) : (
          <div className="rounded-xl border border-[rgb(var(--red))]/15 bg-[rgb(var(--red))]/5 p-5">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle size={18} className="text-[rgb(var(--red))] flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-[13px] font-semibold text-[rgb(var(--red))]">Disable All Protection</p>
                <p className="text-[12px] text-[rgb(var(--t2))] mt-1.5 leading-relaxed">
                  This will stop the Sentinella GUI. The daemon will continue running independently,
                  but real-time monitoring, ARGUS heuristics, and scheduled scans will no longer be
                  visible or controllable.
                </p>
              </div>
            </div>
            <p className="text-[11px] text-[rgb(var(--t3))] mb-3">
              Type <strong className="text-[rgb(var(--red))] font-mono">DISABLE PROTECTION</strong> to confirm:
            </p>
            <input
              type="text"
              value={shutdownPhrase}
              onChange={(e) => { setShutdownPhrase(e.target.value); setShutdownError(""); }}
              placeholder="Type confirmation phrase..."
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
                  setShutdownError("Incorrect confirmation phrase.");
                  return;
                }
                try {
                  await invoke("confirmed_shutdown", { confirmation: shutdownPhrase });
                } catch (e) {
                  setShutdownError(String(e));
                }
              }} disabled={shutdownPhrase.length < 5}
                className="px-4 py-2 rounded-xl bg-[rgb(var(--red))] text-white text-[12px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-30">
                Confirm Shutdown
              </button>
              <button onClick={() => { setShowShutdown(false); setShutdownPhrase(""); setShutdownError(""); }}
                className="px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/40 text-[12px] text-[rgb(var(--t2))] cursor-pointer">
                Cancel
              </button>
            </div>
          </div>
        )}
      </Section>
    </>
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
                title="Remove"
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
          {items.length} entr{items.length > 1 ? "ies" : "y"}
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
      <Section title="Windows Notifications" desc="Control when Sentinella shows desktop toasts.">
        <Toggle label="Enable notifications" desc="Master switch for all Windows toasts" checked={ns.enabled} onChange={() => toggle("enabled")} />
      </Section>

      <Section title="Notification Events" desc="Choose which events trigger a toast.">
        <Toggle label="Threat detected" desc="A virus or suspicious file was found" checked={ns.onThreat} onChange={() => toggle("onThreat")} disabled={!ns.enabled} />
        <Toggle label="File quarantined" desc="A threat was moved to the quarantine vault" checked={ns.onQuarantine} onChange={() => toggle("onQuarantine")} disabled={!ns.enabled} />
        <Toggle label="Scan completed with threats" desc="A scan finished and found threats (clean scans are always silent)" checked={ns.onScanComplete} onChange={() => toggle("onScanComplete")} disabled={!ns.enabled} />
        <Toggle label="Signature update failed" desc="Virus definitions could not be updated" checked={ns.onUpdateFailure} onChange={() => toggle("onUpdateFailure")} disabled={!ns.enabled} />
        <Toggle label="Protection degraded" desc="A subsystem went down or became unavailable" checked={ns.onDegraded} onChange={() => toggle("onDegraded")} disabled={!ns.enabled} />
      </Section>

      <Section title="Severity Threshold" desc="Only show notifications at or above this level.">
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
            }`}>{level === "info" ? "All" : level}</button>
          ))}
        </div>
        <p className="text-[11px] text-[rgb(var(--t3))] mt-2">
          {ns.minSeverity === "info" && "All meaningful events will trigger toasts."}
          {ns.minSeverity === "warning" && "Only warnings, threats, and critical events."}
          {ns.minSeverity === "threat" && "Only threat detections and critical events."}
          {ns.minSeverity === "critical" && "Only critical events (quarantine failure, protection loss)."}
        </p>
      </Section>

      <Section title="Quiet Mode" desc="Temporarily suppress all notifications without changing individual settings.">
        <Toggle label="Quiet mode" desc="No toasts until you turn this off" checked={ns.quietMode} onChange={() => toggle("quietMode")} disabled={!ns.enabled} />
      </Section>
    </>
  );
}

import { useState } from "react";
import {
  Settings as SettingsIcon,
  Globe,
  Palette,
  Shield,
  RefreshCw,
  Wrench,
  Eye,
  Archive,
  FileSearch,
  Mail,
  Bug,
  FolderOpen,
  Clock,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { SettingsSection } from "../components/SettingsSection";
import { ToggleCard } from "../components/ToggleCard";

type SettingsTab = "general" | "appearance" | "protection" | "updates" | "advanced";

const tabs: { id: SettingsTab; label: string; icon: React.ReactNode }[] = [
  { id: "general", label: "General", icon: <Globe size={18} /> },
  { id: "appearance", label: "Appearance", icon: <Palette size={18} /> },
  { id: "protection", label: "Protection", icon: <Shield size={18} /> },
  { id: "updates", label: "Updates", icon: <RefreshCw size={18} /> },
  { id: "advanced", label: "Advanced", icon: <Wrench size={18} /> },
];

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("general");

  return (
    <div>
      <PageHeader
        icon={<SettingsIcon size={22} />}
        title="Settings"
        subtitle="Configure Sentinella to your preferences"
      />

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium
                transition-colors duration-150 cursor-pointer
                ${
                  activeTab === tab.id
                    ? "bg-[rgb(var(--accent))]/15 text-[rgb(var(--accent))]"
                    : "text-[rgb(var(--text-muted))] hover:bg-[rgb(var(--bg-elevated))] hover:text-[rgb(var(--text-primary))]"
                }
              `}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {activeTab === "general" && <GeneralSettings />}
          {activeTab === "appearance" && <AppearanceSettings />}
          {activeTab === "protection" && <ProtectionSettings />}
          {activeTab === "updates" && <UpdateSettings />}
          {activeTab === "advanced" && <AdvancedSettings />}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════ */

function GeneralSettings() {
  const [startWithSystem, setStartWithSystem] = useState(true);
  const [startMinimized, setStartMinimized] = useState(false);
  const [notifications, setNotifications] = useState(true);

  return (
    <>
      <SettingsSection title="Language" description="The language used throughout the application.">
        <div className="py-2">
          <select className="bg-[rgb(var(--bg-elevated))] border border-[rgb(var(--border))] rounded-xl px-4 py-2.5 text-sm w-64 text-[rgb(var(--text-primary))] outline-none focus:border-[rgb(var(--accent))]">
            <option value="en">English</option>
            <option value="es">Español</option>
            <option value="fr">Français</option>
            <option value="de">Deutsch</option>
            <option value="pt">Português</option>
            <option value="it">Italiano</option>
            <option value="ja">日本語</option>
          </select>
        </div>
      </SettingsSection>

      <SettingsSection title="Startup" description="Control how Sentinella behaves at system startup.">
        <ToggleCard
          icon={<Globe size={16} />}
          label="Start with system"
          description="Launch Sentinella automatically when you log in"
          checked={startWithSystem}
          onChange={setStartWithSystem}
        />
        <ToggleCard
          icon={<Archive size={16} />}
          label="Start minimized"
          description="Open in the system tray instead of showing the window"
          checked={startMinimized}
          onChange={setStartMinimized}
        />
        <ToggleCard
          label="Desktop notifications"
          description="Show toast notifications for scan results and updates"
          checked={notifications}
          onChange={setNotifications}
        />
      </SettingsSection>
    </>
  );
}

function AppearanceSettings() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [accentIdx, setAccentIdx] = useState(0);

  const accentColors = [
    { name: "Blue", value: "#3b82f6", rgb: "59 130 246" },
    { name: "Teal", value: "#14b8a6", rgb: "20 184 166" },
    { name: "Purple", value: "#a855f7", rgb: "168 85 247" },
    { name: "Pink", value: "#ec4899", rgb: "236 72 153" },
    { name: "Orange", value: "#f97316", rgb: "249 115 22" },
    { name: "Cyan", value: "#06b6d4", rgb: "6 182 212" },
  ];

  return (
    <>
      <SettingsSection title="Mode" description="Choose between dark and light appearance.">
        <div className="flex gap-3 py-2">
          {(["dark", "light"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTheme(t)}
              className={`
                flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium border transition-all cursor-pointer capitalize
                ${
                  theme === t
                    ? "border-[rgb(var(--accent))] text-[rgb(var(--accent))] bg-[rgb(var(--accent))]/10"
                    : "border-[rgb(var(--border))] text-[rgb(var(--text-muted))] hover:border-[rgb(var(--text-muted))]"
                }
              `}
            >
              {t === "dark" ? "🌙" : "☀️"} {t}
            </button>
          ))}
        </div>
      </SettingsSection>

      <SettingsSection title="Accent Color" description="The primary color used for buttons, links, and highlights.">
        <div className="flex gap-3 py-3">
          {accentColors.map((c, i) => (
            <button
              key={c.name}
              onClick={() => setAccentIdx(i)}
              title={c.name}
              className={`
                w-10 h-10 rounded-full transition-all cursor-pointer
                ${accentIdx === i ? "ring-2 ring-white ring-offset-2 ring-offset-[rgb(var(--bg-surface))] scale-110" : "hover:scale-105"}
              `}
              style={{ backgroundColor: c.value }}
            />
          ))}
        </div>
      </SettingsSection>
    </>
  );
}

function ProtectionSettings() {
  const [realtime, setRealtime] = useState(true);
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [scanArchives, setScanArchives] = useState(true);
  const [scanMail, setScanMail] = useState(true);
  const [heuristics, setHeuristics] = useState(true);
  const [retention, setRetention] = useState("90");

  return (
    <>
      <SettingsSection title="Real-time Protection" description="Monitor your file system for threats in real time.">
        <ToggleCard
          icon={<Eye size={16} />}
          label="Enable real-time protection"
          description="Scan files as they are created or modified (user-mode watcher)"
          checked={realtime}
          onChange={setRealtime}
        />
        <ToggleCard
          icon={<Archive size={16} />}
          label="Auto-quarantine threats"
          description="Automatically isolate detected threats without asking"
          checked={autoQuarantine}
          onChange={setAutoQuarantine}
        />
      </SettingsSection>

      <SettingsSection title="Scan Options" description="Default options for all on-demand scans.">
        <ToggleCard
          icon={<FileSearch size={16} />}
          label="Scan archives"
          description="Look inside ZIP, 7z, TAR, and other archive formats"
          checked={scanArchives}
          onChange={setScanArchives}
        />
        <ToggleCard
          icon={<Mail size={16} />}
          label="Scan email files"
          description="Check EML, MBOX, and PST formats"
          checked={scanMail}
          onChange={setScanMail}
        />
        <ToggleCard
          icon={<Bug size={16} />}
          label="Heuristic alerts"
          description="Detect suspicious patterns beyond known signatures"
          checked={heuristics}
          onChange={setHeuristics}
        />
      </SettingsSection>

      <SettingsSection title="Quarantine Retention" description="How long quarantined items are kept before automatic cleanup.">
        <div className="py-2">
          <select
            value={retention}
            onChange={(e) => setRetention(e.target.value)}
            className="bg-[rgb(var(--bg-elevated))] border border-[rgb(var(--border))] rounded-xl px-4 py-2.5 text-sm w-56 text-[rgb(var(--text-primary))] outline-none focus:border-[rgb(var(--accent))]"
          >
            <option value="30">30 days</option>
            <option value="60">60 days</option>
            <option value="90">90 days (default)</option>
            <option value="180">180 days</option>
            <option value="365">1 year</option>
            <option value="0">Never delete</option>
          </select>
        </div>
      </SettingsSection>
    </>
  );
}

function UpdateSettings() {
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [interval, setInterval_] = useState("4");

  return (
    <>
      <SettingsSection title="Automatic Updates" description="Keep your signature database current.">
        <ToggleCard
          icon={<RefreshCw size={16} />}
          label="Auto-update signatures"
          description="Periodically check for and download new virus definitions"
          checked={autoUpdate}
          onChange={setAutoUpdate}
        />
        <div className="py-3 pl-1">
          <label className="text-sm font-medium block mb-2">Check interval</label>
          <select
            value={interval}
            onChange={(e) => setInterval_(e.target.value)}
            disabled={!autoUpdate}
            className="bg-[rgb(var(--bg-elevated))] border border-[rgb(var(--border))] rounded-xl px-4 py-2.5 text-sm w-48 text-[rgb(var(--text-primary))] outline-none focus:border-[rgb(var(--accent))] disabled:opacity-50"
          >
            <option value="1">Every hour</option>
            <option value="2">Every 2 hours</option>
            <option value="4">Every 4 hours (default)</option>
            <option value="12">Every 12 hours</option>
            <option value="24">Once daily</option>
          </select>
        </div>
      </SettingsSection>

      <SettingsSection title="Update Source" description="Where to download signature databases.">
        <div className="py-2">
          <select className="bg-[rgb(var(--bg-elevated))] border border-[rgb(var(--border))] rounded-xl px-4 py-2.5 text-sm w-full text-[rgb(var(--text-primary))] outline-none focus:border-[rgb(var(--accent))]">
            <option value="official">Official ClamAV mirror (database.clamav.net)</option>
            <option value="custom">Custom mirror...</option>
          </select>
        </div>
      </SettingsSection>

      <SettingsSection title="Scheduled Scans" description="Automated scans run at specific times.">
        <div className="py-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-[rgb(var(--bg-elevated))]">
            <Clock size={16} className="text-[rgb(var(--accent))]" />
            <div className="flex-1">
              <p className="text-sm font-medium">Weekly full scan</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">
                Every Sunday at 03:00 AM
              </p>
            </div>
            <span className="text-xs text-[rgb(var(--success))] bg-[rgb(var(--success))]/10 px-2 py-1 rounded-lg font-medium">
              Active
            </span>
          </div>
        </div>
      </SettingsSection>
    </>
  );
}

function AdvancedSettings() {
  return (
    <>
      <SettingsSection title="Exclusions" description="Files and folders to skip during scans.">
        <div className="py-3">
          <div className="bg-[rgb(var(--bg-elevated))] rounded-xl p-4 min-h-[80px] text-sm text-[rgb(var(--text-muted))] border border-dashed border-[rgb(var(--border))] flex items-center justify-center gap-2 cursor-pointer hover:border-[rgb(var(--accent))]/40 transition-colors">
            <FolderOpen size={16} />
            Click to add exclusion paths or patterns
          </div>
        </div>
      </SettingsSection>

      <SettingsSection title="Logging" description="Control daemon log verbosity.">
        <div className="py-2">
          <select className="bg-[rgb(var(--bg-elevated))] border border-[rgb(var(--border))] rounded-xl px-4 py-2.5 text-sm w-48 text-[rgb(var(--text-primary))] outline-none focus:border-[rgb(var(--accent))]">
            <option value="error">Error</option>
            <option value="warn">Warning</option>
            <option value="info">Info (default)</option>
            <option value="debug">Debug</option>
            <option value="trace">Trace</option>
          </select>
        </div>
      </SettingsSection>

      <SettingsSection title="Engine Limits" description="Advanced engine configuration. Change with care.">
        <div className="space-y-3 py-2">
          <LimitRow label="Max file size" value="100 MB" />
          <LimitRow label="Max scan size" value="400 MB" />
          <LimitRow label="Max recursion depth" value="17" />
          <LimitRow label="Max files per scan" value="10,000" />
          <LimitRow label="Scan timeout per file" value="120 s" />
        </div>
      </SettingsSection>

      <SettingsSection title="Daemon" description="IPC and service configuration.">
        <div className="space-y-3 py-2">
          <LimitRow label="Named pipe" value="\\.\pipe\sentinelld" />
          <LimitRow label="Watcher mode" value="User-mode (v1)" />
          <LimitRow label="Protocol version" value="1" />
          <LimitRow label="Config path" value="C:\ProgramData\Sentinella\config.toml" />
        </div>
      </SettingsSection>
    </>
  );
}

function LimitRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center text-sm">
      <span className="text-[rgb(var(--text-muted))]">{label}</span>
      <span className="font-medium font-mono text-xs bg-[rgb(var(--bg-elevated))] px-2 py-1 rounded-lg">
        {value}
      </span>
    </div>
  );
}

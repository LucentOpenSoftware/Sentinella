import { Info, ExternalLink, Heart, Shield, Code2, Scale } from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/Card";

export function AboutPage() {
  return (
    <div>
      <PageHeader
        icon={<Info size={22} />}
        title="About"
        subtitle="Sentinella antivirus suite"
      />

      {/* ── Hero ───────────────────────────────────────────── */}
      <Card className="text-center mb-5">
        <div className="py-8">
          <div className="w-20 h-20 mx-auto mb-5 rounded-3xl bg-gradient-to-br from-[rgb(var(--accent))]/20 to-[rgb(var(--accent))]/5 border border-[rgb(var(--accent))]/20 flex items-center justify-center">
            <Shield size={36} className="text-[rgb(var(--accent))]" />
          </div>
          <h3 className="text-2xl font-bold mb-1">Sentinella</h3>
          <p className="text-sm text-[rgb(var(--text-muted))] mb-1">
            Version 0.1.0 &middot; Development build
          </p>
          <p className="text-xs text-[rgb(var(--text-muted))]">
            A calm guardian for your system
          </p>
          <p className="text-sm text-[rgb(var(--text-muted))] mt-4 max-w-lg mx-auto leading-relaxed">
            A modern, open-source antivirus suite built on the ClamAV scanning
            engine. Designed to be trustworthy, transparent, lightweight,
            and beginner-friendly. No cloud dependencies, no telemetry, no
            fear-driven marketing.
          </p>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-4 mb-5">
        {/* ── Technology ───────────────────────────────────── */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Code2 size={16} className="text-[rgb(var(--accent))]" />
            <h4 className="text-sm font-semibold">Technology</h4>
          </div>
          <div className="space-y-2.5 text-sm">
            <AboutRow label="Scanning engine" value="ClamAV (unmodified)" />
            <AboutRow label="Daemon" value="Rust + tokio" />
            <AboutRow label="GUI framework" value="Tauri 2.x" />
            <AboutRow label="Frontend" value="React + TypeScript" />
            <AboutRow label="Styling" value="Tailwind CSS" />
            <AboutRow label="IPC protocol" value="JSON-RPC 2.0" />
            <AboutRow label="Quarantine encryption" value="AES-256-GCM" />
            <AboutRow label="Real-time watcher" value="User-mode (v1)" />
          </div>
        </Card>

        {/* ── License ──────────────────────────────────────── */}
        <Card>
          <div className="flex items-center gap-2 mb-4">
            <Scale size={16} className="text-[rgb(var(--accent))]" />
            <h4 className="text-sm font-semibold">License & Attribution</h4>
          </div>
          <div className="space-y-3 text-sm">
            <p className="text-[rgb(var(--text-muted))] leading-relaxed">
              Licensed under the <strong className="text-[rgb(var(--text-primary))]">GNU General
              Public License v2</strong> (GPLv2). Source code is publicly available.
            </p>
            <p className="text-[rgb(var(--text-muted))] leading-relaxed">
              Scanning engine powered by <strong className="text-[rgb(var(--text-primary))]">ClamAV</strong>.
              ClamAV is a registered trademark of Cisco Systems, Inc.
              Sentinella is not affiliated with or endorsed by Cisco.
            </p>
            <div className="flex items-center gap-4 pt-1">
              <a href="#" className="inline-flex items-center gap-1.5 text-xs text-[rgb(var(--accent))] hover:underline font-medium">
                <ExternalLink size={12} /> Source Code
              </a>
              <a href="#" className="inline-flex items-center gap-1.5 text-xs text-[rgb(var(--accent))] hover:underline font-medium">
                <ExternalLink size={12} /> ClamAV
              </a>
              <a href="#" className="inline-flex items-center gap-1.5 text-xs text-[rgb(var(--accent))] hover:underline font-medium">
                <ExternalLink size={12} /> GPLv2 License
              </a>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Lucent Open Software ───────────────────────────── */}
      <Card className="mb-5">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-6 h-6 rounded-md bg-[rgb(var(--accent))]/15 flex items-center justify-center">
            <span className="text-xs font-bold text-[rgb(var(--accent))]">L</span>
          </div>
          <h4 className="text-sm font-semibold">Lucent Open Software</h4>
        </div>
        <p className="text-sm text-[rgb(var(--text-muted))] leading-relaxed">
          Sentinella is part of the Lucent Open Software initiative — building
          transparent, privacy-respecting tools that put users first. We believe
          security software should be trustworthy by design: open source, locally
          executed, and free from hidden data collection.
        </p>
      </Card>

      {/* ── Footer ─────────────────────────────────────────── */}
      <div className="text-center text-xs text-[rgb(var(--text-muted))] pb-4">
        <p className="inline-flex items-center gap-1">
          Made with <Heart size={11} className="text-[rgb(var(--danger))]" /> by
          the Sentinella community
        </p>
      </div>
    </div>
  );
}

function AboutRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-[rgb(var(--text-muted))]">{label}</span>
      <span className="font-medium text-xs bg-[rgb(var(--bg-elevated))] px-2 py-1 rounded-lg">{value}</span>
    </div>
  );
}

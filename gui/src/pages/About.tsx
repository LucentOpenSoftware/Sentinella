import { useState } from "react";
import {
  Code2, Scale, ExternalLink, Heart,
  ChevronLeft, Cpu, ShieldCheck, Eye, Lock,
  Gauge, GitBranch, EyeOff, BookOpen,
  Layers, Microscope, Box, Zap, Server,
  Download, Loader2, CheckCircle2, AlertTriangle,
} from "lucide-react";
import { Card } from "../components/Card";
import { ShieldIcon } from "../components/ShieldIcon";
import { check } from "@tauri-apps/plugin-updater";
import aboutBanner from "../../../assets/about1.png";

// ── Sub-page type ────────────────────────────────────────
type HelpTopic =
  | null
  | "what-is-sentinella"
  | "what-is-argus"
  | "why-clamav"
  | "why-sandbox"
  | "why-workers"
  | "why-realtime-first"
  | "performance"
  | "open-source"
  | "privacy"
  | "technical-architecture";

// ── Topic cards shown on Overview ────────────────────────
const topics: { id: HelpTopic; icon: typeof Cpu; title: string; teaser: string }[] = [
  { id: "what-is-sentinella", icon: ShieldCheck, title: "What is Sentinella?",       teaser: "Security software that protects your computer, not fights against it." },
  { id: "what-is-argus",      icon: Layers,      title: "What is ARGUS?",            teaser: "Layered suspicion scoring powered by ASTRA adaptive analysis." },
  { id: "why-clamav",         icon: Microscope,  title: "Why ClamAV?",               teaser: "Battle-tested signatures, open-source trust." },
  { id: "why-sandbox",        icon: Box,          title: "Why behavioral sandboxing?", teaser: "Detonate the unknown in a sealed room." },
  { id: "why-workers",        icon: Server,       title: "Why modular workers?",       teaser: "If one crashes, the rest survive." },
  { id: "why-realtime-first", icon: Zap,          title: "Why realtime-first?",        teaser: "Realtime protection never waits for anything." },
  { id: "performance",        icon: Gauge,        title: "Performance philosophy",     teaser: "Your computer is yours. Sentinella borrows it gently." },
  { id: "open-source",        icon: GitBranch,    title: "Open-source philosophy",     teaser: "Security through transparency, not obscurity." },
  { id: "privacy",            icon: EyeOff,       title: "Privacy & telemetry",        teaser: "Zero telemetry. Zero cloud. Zero exceptions." },
];

// ══════════════════════════════════════════════════════════
//  About Page — overview + help topics
// ══════════════════════════════════════════════════════════

export function AboutPage() {
  const [topic, setTopic] = useState<HelpTopic>(null);

  if (topic) {
    return <TopicPage topic={topic} onBack={() => setTopic(null)} />;
  }

  return (
    <div className="page-stack">
      {/* Banner */}
      <Card className="relative h-[260px] overflow-hidden rounded-3xl !p-0">
        <img
          src={aboutBanner}
          alt="Sentinella cinematic banner"
          className="absolute inset-0 h-full w-full object-cover object-center"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-black/40 via-black/10 to-black/30" />
        <div className="absolute bottom-6 left-8 flex items-center gap-4">
          <ShieldIcon icon="sentinelAlt" size={48} className="brightness-0 invert opacity-80" />
          <div>
            <p className="text-[20px] font-bold text-white/90 leading-none">Sentinella</p>
            <p className="text-[12px] text-white/50 mt-1.5">Antivirus Suite v0.1.5</p>
          </div>
        </div>
      </Card>

      {/* Update checker */}
      <UpdateChecker />

      {/* Technology + License */}
      <div className="card-grid-2">
        <Card>
          <div className="flex items-center gap-2.5 mb-4">
            <Code2 size={15} className="text-[rgb(var(--accent))]" />
            <h4 className="text-[14px] font-semibold">Technology</h4>
          </div>
          <div className="space-y-3 text-[13px]">
            <AR l="Heuristic engine" v="ARGUS" />
            <AR l="Adaptive analysis" v="ASTRA" />
            <AR l="Signature engine" v="ClamAV" />
            <AR l="Behavioral sandbox" v="ETW + Job Object" />
            <AR l="Process isolation" v="Restricted token" />
            <AR l="Daemon" v="Rust" />
            <AR l="GUI framework" v="Tauri 2.x" />
            <AR l="Frontend" v="React + TypeScript" />
            <AR l="IPC protocol" v="JSON-RPC 2.0" />
            <AR l="Quarantine" v="AES-256-GCM" />
            <AR l="File analysis" v="PE / ELF / Script" />
            <AR l="Watcher" v="User-mode (v1)" />
          </div>
        </Card>

        <Card>
          <div className="flex items-center gap-2.5 mb-4">
            <Scale size={15} className="text-[rgb(var(--accent))]" />
            <h4 className="text-[14px] font-semibold">License & Attribution</h4>
          </div>
          <p className="text-[13px] text-[rgb(var(--t2))] leading-relaxed mb-4">
            Licensed under the <strong className="text-[rgb(var(--t1))]">GNU General Public License v2</strong> (GPLv2).
            Source code is publicly available.
          </p>
          <p className="text-[13px] text-[rgb(var(--t2))] leading-relaxed mb-4">
            Heuristic analysis powered by <strong className="text-[rgb(var(--t1))]">ARGUS</strong> — Sentinella's layered suspicion engine.
            Signature scanning powered by <strong className="text-[rgb(var(--t1))]">ClamAV</strong>.
          </p>
          <div className="flex gap-4">
            <ExtLink label="Source Code" />
            <ExtLink label="ClamAV" />
            <ExtLink label="GPLv2" />
          </div>
        </Card>
      </div>

      {/* Learn about Sentinella */}
      <div>
        <div className="flex items-center gap-2.5 mb-4 px-1">
          <BookOpen size={15} className="text-[rgb(var(--accent))]" />
          <h4 className="text-[14px] font-semibold">Learn about Sentinella</h4>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {topics.map(t => (
            <TopicCard key={t.id} icon={t.icon} title={t.title} teaser={t.teaser} onClick={() => setTopic(t.id)} />
          ))}
        </div>
      </div>

      {/* Advanced / future */}
      <div>
        <div className="flex items-center gap-2.5 mb-3 px-1">
          <Cpu size={14} className="text-[rgb(var(--t3))]/60" />
          <h4 className="text-[13px] font-medium text-[rgb(var(--t3))]">For developers</h4>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <TopicCard icon={Cpu} title="Technical architecture" teaser="Daemon internals, IPC protocol, scan pipeline, and process model." onClick={() => setTopic("technical-architecture")} />
          <PlaceholderCard icon={Eye} label="Architecture diagrams" />
          <PlaceholderCard icon={Lock} label="Changelog & milestones" />
        </div>
      </div>

      <p className="text-center text-[11px] text-[rgb(var(--t3))]/20 flex items-center justify-center gap-1 mt-2">
        Made with <Heart size={10} className="text-[rgb(var(--red))]" /> by the Sentinella community
      </p>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  Update checker
// ══════════════════════════════════════════════════════════

type UpdateState = "idle" | "checking" | "available" | "downloading" | "ready" | "up-to-date" | "error";

function UpdateChecker() {
  const [state, setState] = useState<UpdateState>("idle");
  const [version, setVersion] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async () => {
    setState("checking");
    setError(null);
    try {
      const update = await check();
      if (update) {
        setVersion(update.version);
        setState("available");
      } else {
        setState("up-to-date");
      }
    } catch (e) {
      setError(String(e));
      setState("error");
    }
  };

  const handleDownloadAndInstall = async () => {
    setState("downloading");
    try {
      const update = await check();
      if (!update) { setState("up-to-date"); return; }
      let downloaded = 0;
      let total = 0;
      await update.downloadAndInstall((ev) => {
        if (ev.event === "Started" && ev.data.contentLength) {
          total = ev.data.contentLength;
        } else if (ev.event === "Progress") {
          downloaded += ev.data.chunkLength;
          if (total > 0) setProgress(Math.round((downloaded / total) * 100));
        } else if (ev.event === "Finished") {
          setState("ready");
        }
      });
      setState("ready");
    } catch (e) {
      setError(String(e));
      setState("error");
    }
  };

  return (
    <Card>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-[rgb(var(--accent))]/8 flex items-center justify-center">
            <Download size={16} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <p className="text-[14px] font-semibold">Software Updates</p>
            <p className="text-[11px] text-[rgb(var(--t3))]">
              {state === "up-to-date" ? "You're running the latest version" :
               state === "available" ? `Version ${version} is available` :
               state === "downloading" ? `Downloading update... ${progress}%` :
               state === "ready" ? "Update ready — restart to apply" :
               state === "error" ? "Update check failed" :
               state === "checking" ? "Checking for updates..." :
               "Check for new versions"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {state === "up-to-date" && <CheckCircle2 size={16} className="text-[rgb(var(--green))]" />}
          {state === "error" && <AlertTriangle size={16} className="text-[rgb(var(--amber))]" />}
          {state === "checking" || state === "downloading" ? (
            <Loader2 size={16} className="text-[rgb(var(--accent))] animate-spin" />
          ) : state === "available" ? (
            <button
              onClick={handleDownloadAndInstall}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/20 transition-colors cursor-pointer"
            >
              Install Update
            </button>
          ) : state === "ready" ? (
            <button
              onClick={() => { import("@tauri-apps/plugin-updater").then(() => { /* app will restart via NSIS */ }); }}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--green))]/10 text-[rgb(var(--green))] hover:bg-[rgb(var(--green))]/20 transition-colors cursor-pointer"
            >
              Restart Now
            </button>
          ) : (
            <button
              onClick={handleCheck}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--raised))]/30 text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/50 transition-colors cursor-pointer"
            >
              Check for Updates
            </button>
          )}
        </div>
      </div>
      {state === "downloading" && (
        <div className="mt-3 h-1.5 bg-[rgb(var(--raised))]/20 rounded-full overflow-hidden">
          <div className="h-full bg-[rgb(var(--accent))] rounded-full transition-all" style={{ width: `${progress}%` }} />
        </div>
      )}
      {error && <p className="mt-2 text-[11px] text-[rgb(var(--amber))]">{error}</p>}
    </Card>
  );
}

// ══════════════════════════════════════════════════════════
//  Topic detail page
// ══════════════════════════════════════════════════════════

function TopicPage({ topic, onBack }: { topic: NonNullable<HelpTopic>; onBack: () => void }) {
  const content = topicContent[topic];
  if (!content) return null;

  return (
    <div className="page-stack">
      {/* Back button */}
      <button
        onClick={onBack}
        className="flex items-center gap-1.5 text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--accent))] transition-colors cursor-pointer w-fit"
      >
        <ChevronLeft size={14} />
        Back to About
      </button>

      {/* Header */}
      <Card>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 rounded-lg bg-[rgb(var(--accent))]/10 flex items-center justify-center">
            <content.icon size={18} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h3 className="text-[16px] font-semibold">{content.title}</h3>
            <p className="text-[12px] text-[rgb(var(--t3))]">{content.subtitle}</p>
          </div>
        </div>

        <div className="space-y-6">
          {content.sections.map((section, i) => (
            <HelpSection key={i} heading={section.heading} body={section.body} />
          ))}
        </div>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  Topic content — static, no markdown engine
// ══════════════════════════════════════════════════════════

interface TopicData {
  icon: typeof Cpu;
  title: string;
  subtitle: string;
  sections: { heading: string; body: string[] }[];
}

const topicContent: Record<NonNullable<HelpTopic>, TopicData> = {
  "what-is-sentinella": {
    icon: ShieldCheck,
    title: "What is Sentinella?",
    subtitle: "A local-first antivirus built to protect your computer — not fight against it",
    sections: [
      {
        heading: "",
        body: [
          "Sentinella is an open-source antivirus suite for Windows designed around a simple idea: security software should be understandable, lightweight, and respectful of the machine it protects.",
          "Everything runs locally on your computer. No cloud dependency, no hidden telemetry, and no subscriptions required.",
          "Sentinella combines trusted signature scanning with layered behavioral analysis to help detect both known threats and suspicious activity, while staying responsive during everyday use.",
        ],
      },
      {
        heading: "How protection works",
        body: [
          "Real-time protection watches important areas like Downloads and Desktop for new or modified files. Background scans run quietly when your system is idle and yield automatically under pressure. Suspicious files can be isolated in a secure quarantine and analyzed safely. Manual scans never interrupt real-time protection.",
        ],
      },
      {
        heading: "Design philosophy",
        body: [
          "Real-time protection comes first. Your computer should stay responsive. Detections should be explainable. Quarantined files should be recoverable. Open-source software should be auditable. Security should not rely on fear or mystery.",
          "Sentinella was built for people who want security software they can trust — not just because it detects threats, but because it explains itself honestly.",
        ],
      },
    ],
  },

  "what-is-argus": {
    icon: Layers,
    title: "What is ARGUS?",
    subtitle: "Sentinella's layered suspicion engine",
    sections: [
      {
        heading: "Beyond binary verdicts",
        body: [
          "Traditional antivirus gives binary answers: infected or clean. ARGUS, powered by ASTRA adaptive analysis, takes a different approach. It assigns a suspicion score from 0 to 100 based on evidence from multiple independent analysis layers. No single layer can declare a file malicious alone.",
          "This means a file with one suspicious trait stays in the \"Unusual\" range, while a file exhibiting credential theft patterns, network exfiltration, and process injection converges toward \"Malicious\" through multiple independent signals.",
        ],
      },
      {
        heading: "The layers",
        body: [
          "Layer 0 (Signatures): ClamAV's database of known malware signatures. Layer 1 (MIME/Type): Detects files disguised as other formats, double extensions, and right-to-left override tricks. Layer 2 (PE Heuristics): Analyzes Windows executables for exploit techniques, suspicious imports, packing, and structural anomalies.",
          "Layer 3 (Reputation): Checks file metadata against known software patterns. Layer 4 (Context): Considers where the file was found, how it was named, and suspicious environmental signals. Layer 5 (IOC): Matches file hashes against known indicators of compromise.",
          "Layer 6 (YARA): Custom behavioral rules written in the YARA pattern matching language. Layer 7 (Correlation): Cross-references findings across all layers to build convergence chains and detect multi-stage attack patterns. Layer 8 (Behavioral Runtime): Optional sandbox detonation feeds behavioral observations back into the scoring system.",
        ],
      },
      {
        heading: "Convergence, not thresholds",
        body: [
          "ARGUS scores, driven by ASTRA's adaptive convergence logic, are not arbitrary thresholds. A file reaches \"High Risk\" or \"Malicious\" only when multiple categories of evidence converge: credential theft + network activity, or process injection + persistence + anti-analysis. Single-category findings are capped to prevent one noisy signal from triggering false positives.",
          "Every finding carries a BehaviorTag, an AttackStage, and a confidence weight. The final score reflects how many independent lines of evidence point to the same conclusion.",
        ],
      },
    ],
  },

  "why-clamav": {
    icon: Microscope,
    title: "Why ClamAV?",
    subtitle: "Battle-tested open-source signature engine",
    sections: [
      {
        heading: "Known threats, known answers",
        body: [
          "For malware that has already been identified and catalogued, signature scanning is fast and definitive. ClamAV maintains a database of millions of malware signatures that can identify known threats in milliseconds.",
          "ARGUS handles the unknown; ClamAV handles the known. Together, they cover both sides of the detection problem without either component trying to do everything.",
        ],
      },
      {
        heading: "Open-source trust",
        body: [
          "ClamAV is developed by Cisco's Talos Intelligence Group and is the most widely deployed open-source antivirus engine in the world. Its signature database is updated multiple times per day and is freely available.",
          "Using ClamAV means Sentinella's signature scanning is not a black box. The engine's source code, signature format, and detection logic are publicly auditable.",
        ],
      },
      {
        heading: "Subprocess isolation",
        body: [
          "ClamAV loads a large signature database into memory (~400 MB). Sentinella optionally runs ClamAV in an isolated subprocess (clamavd) so that if a malformed sample triggers a crash in the parsing engine, only the worker process dies. The daemon survives and can spawn a new worker.",
          "This crash isolation is configurable. For machines with limited RAM, in-process scanning uses the already-loaded engine with no extra memory cost.",
        ],
      },
    ],
  },

  "why-sandbox": {
    icon: Box,
    title: "Why behavioral sandboxing?",
    subtitle: "Observing what suspicious files actually do",
    sections: [
      {
        heading: "The gap between static and dynamic",
        body: [
          "Static analysis (reading a file's structure) can only tell you what a program could do. Behavioral analysis tells you what it actually does when executed. Some malware is designed specifically to look clean under static analysis and only reveals its true behavior at runtime.",
          "Sentinella's sandbox runs suspicious files in a tightly controlled environment, observes their behavior, and feeds the results back into the ARGUS scoring system.",
        ],
      },
      {
        heading: "Containment layers",
        body: [
          "Sandboxed processes run with a restricted Windows token (most privileges stripped), at Low Integrity level (cannot write to system locations), inside a Job Object (cannot spawn escape processes, limited to 512 MB memory), and with per-process firewall rules blocking all network access.",
          "The process is created in a suspended state. All containment is applied before the first instruction runs. There is no window where the sample can act before restrictions take effect.",
        ],
      },
      {
        heading: "ETW runtime observation",
        body: [
          "Event Tracing for Windows (ETW) is a kernel-level instrumentation framework built into Windows. Sentinella uses ETW to observe sandboxed processes without injecting code or modifying the sample. This captures process creation, DLL loading from suspicious paths, registry persistence attempts, and network connection attempts.",
          "ETW is a local observation mechanism. It does not transmit data anywhere. It is the same infrastructure that Windows uses internally for performance monitoring and debugging.",
        ],
      },
      {
        heading: "Non-blocking by design",
        body: [
          "Sandbox detonation can take 30+ seconds. Real-time protection never waits for it. When the watcher identifies a file that needs sandboxing, detonation runs on a background thread while the watcher continues scanning the next file immediately. If the sandbox later determines the file is dangerous, quarantine happens asynchronously.",
        ],
      },
    ],
  },

  "why-workers": {
    icon: Server,
    title: "Why modular workers?",
    subtitle: "Process isolation for resilience",
    sections: [
      {
        heading: "The crash boundary principle",
        body: [
          "Sentinella separates its work into independent processes: the main daemon (sentinelld), the ClamAV scanner (clamavd), the behavioral sandbox (sandboxd), and optionally an external ARGUS worker. Each runs as a separate OS process.",
          "If ClamAV crashes while parsing a malformed PDF, only clamavd dies. The daemon continues running, real-time protection stays active, and the user sees no interruption. A new clamavd worker is spawned on the next scan.",
        ],
      },
      {
        heading: "Memory boundaries",
        body: [
          "Each ClamAV subprocess loads ~400 MB of signatures independently. Sentinella limits concurrent ClamAV workers to prevent memory explosion. The sandbox worker runs at most one detonation at a time. These are hard limits enforced by atomic counters, not configuration suggestions.",
        ],
      },
      {
        heading: "Panic recovery",
        body: [
          "Inside the daemon, the scan orchestrator uses panic-catching wrappers around every job. If a scan thread panics (a programming error, not a security event), the worker thread recovers, increments a crash counter for diagnostics, and continues processing the next job. No user intervention required.",
        ],
      },
    ],
  },

  "why-realtime-first": {
    icon: Zap,
    title: "Why realtime-first?",
    subtitle: "Protection that never yields",
    sections: [
      {
        heading: "The non-negotiable rule",
        body: [
          "Real-time protection is the most important function of any antivirus. If a user starts a full disk scan, real-time protection must continue working at full speed. If the system is under memory pressure, manual scans degrade first. Real-time never degrades silently.",
        ],
      },
      {
        heading: "Architectural separation",
        body: [
          "The real-time watcher runs on its own dedicated thread, independent of the scan orchestrator. Manual scans (quick, folder, full) run on separate worker threads. The idle background scanner runs on yet another thread and automatically pauses when a manual scan is active.",
          "These are not priorities in a shared queue. They are physically separate execution paths. The watcher cannot be starved by a busy scan queue because it does not use the scan queue.",
        ],
      },
      {
        heading: "Graceful degradation",
        body: [
          "When system resources are constrained, Sentinella degrades in a specific order: the idle scanner pauses first (CPU, disk, battery, fullscreen, memory pressure all trigger pause). Manual scans continue but with bounded thread count. Real-time protection continues unconditionally.",
          "If ClamAV subprocess slots are all occupied by manual scans, the watcher falls back to in-process ClamAV scanning. This is slightly less isolated but functionally identical. Detection quality is never reduced.",
        ],
      },
    ],
  },

  performance: {
    icon: Gauge,
    title: "Performance philosophy",
    subtitle: "Your computer is yours",
    sections: [
      {
        heading: "Invisible when idle",
        body: [
          "The idle background scanner monitors CPU load, disk I/O, battery state, and whether the user is in a fullscreen application. It only scans when system resources are genuinely available. During compilation, gaming, or video editing, it pauses automatically.",
          "There is no fixed scan schedule that interrupts work. The scanner asks: \"Can I scan without the user noticing?\" If the answer is no, it waits.",
        ],
      },
      {
        heading: "Smart file filtering",
        body: [
          "Not every file needs deep analysis. ARGUS uses a scan strategy system: known-safe file types (images, fonts, logs) get signature-only checks. Executables and scripts get full multi-layer analysis. Build artifacts and package caches are skipped entirely during quick scans.",
          "The real-time watcher applies extension filtering to avoid scanning files that cannot contain executable code: images, fonts, audio/video, lock files, and build intermediates.",
        ],
      },
      {
        heading: "Bounded resource usage",
        body: [
          "Manual scans use a fixed thread count (4 workers). ClamAV subprocesses are capped at 2 concurrent instances. Sandbox detonations are limited to 1 at a time. These are hard limits, not suggestions. Sentinella will never scale up to consume all available CPU or RAM.",
          "A memory pressure system monitors the daemon's RSS. Under elevated pressure, new scans route to external workers to keep the daemon's memory footprint stable. Under critical pressure, the idle scanner pauses entirely.",
        ],
      },
    ],
  },

  "open-source": {
    icon: GitBranch,
    title: "Open-source philosophy",
    subtitle: "Security through transparency",
    sections: [
      {
        heading: "Why open source matters for security",
        body: [
          "An antivirus runs with some of the highest privileges on your system. It reads every file, monitors every process, and can quarantine anything it deems suspicious. You should be able to read its source code and verify that it does exactly what it claims.",
          "Sentinella is licensed under GPLv2. The detection logic, the quarantine implementation, the IPC protocol, and every scan decision are publicly auditable. There is no proprietary detection engine hiding behind a marketing name.",
        ],
      },
      {
        heading: "Explainable detections",
        body: [
          "Every ARGUS finding includes the layer that produced it, the behavior tag it matched, the confidence weight assigned, and the attack stage classification. When Sentinella quarantines a file, you can see exactly why: which rules fired, what evidence converged, and what the final score was.",
          "This is not just for developers. It means you can distinguish between a false positive (one rule firing on a legitimate installer) and a real threat (multiple independent signals converging on credential theft + exfiltration).",
        ],
      },
      {
        heading: "Community and attribution",
        body: [
          "Sentinella is built by Lucent Open Software and the Sentinella community. It uses ClamAV (developed by Cisco's Talos Intelligence Group) for signature scanning and the YARA pattern matching engine for behavioral rules. All dependencies are open-source and properly attributed.",
        ],
      },
    ],
  },

  privacy: {
    icon: EyeOff,
    title: "Privacy & telemetry",
    subtitle: "What Sentinella does not do",
    sections: [
      {
        heading: "Zero telemetry",
        body: [
          "Sentinella does not collect, transmit, or store any usage data, scan results, detection statistics, or system information. There is no analytics endpoint, no crash reporting service, no \"anonymous usage data\" toggle. The daemon makes exactly one type of outgoing network connection: downloading ClamAV signature updates from ClamAV's official mirror.",
        ],
      },
      {
        heading: "No cloud scanning",
        body: [
          "Your files are never uploaded anywhere. All analysis (ClamAV scanning, ARGUS heuristics, YARA rules, behavioral sandbox) runs locally on your machine. There is no cloud lookup, no hash submission, no file sample sharing. This is a deliberate design choice, not a limitation.",
          "Commercial antivirus products often upload suspicious files or file hashes to cloud services for additional analysis. Sentinella does not. The trade-off is that Sentinella relies on its local engines and cannot benefit from real-time cloud intelligence. The benefit is that your files stay on your machine.",
        ],
      },
      {
        heading: "No HTTPS interception",
        body: [
          "Sentinella does not install root certificates, proxy HTTPS traffic, or inspect encrypted network connections. Some security products intercept TLS connections to scan web traffic. This approach weakens the security of every HTTPS connection on the machine and is architecturally incompatible with Sentinella's philosophy.",
        ],
      },
      {
        heading: "No kernel driver (v1)",
        body: [
          "Sentinella v1 operates entirely in user mode. It does not install kernel drivers, minifilter filesystem drivers, or kernel-level hooks. This limits some detection capabilities (pre-execution blocking, kernel rootkit detection) but eliminates an entire class of system stability risks.",
          "The real-time watcher uses ReadDirectoryChangesW (a standard Windows API) and the behavioral sandbox uses ETW (Event Tracing for Windows) for runtime observation. Both are documented, stable, user-mode interfaces.",
        ],
      },
    ],
  },

  "technical-architecture": {
    icon: Cpu,
    title: "Technical architecture",
    subtitle: "Developer-oriented reference for Sentinella's internals",
    sections: [
      {
        heading: "System architecture",
        body: [
          "Sentinella runs as a Rust daemon (sentinelld) that exposes a JSON-RPC 2.0 API over Windows named pipes. The GUI is a Tauri 2.x application (React + TypeScript) that communicates with the daemon for all security operations. The daemon owns all state: scan engine, quarantine vault, real-time watcher, and background scanner.",
          "Protection layers run independently: a real-time filesystem watcher monitors Downloads, Desktop, and Temp for new files; an idle background scanner proactively checks dormant files during low system activity; and user-initiated scans (quick, folder, full) run on demand without interfering with real-time protection.",
        ],
      },
      {
        heading: "Scan orchestrator",
        body: [
          "The orchestrator manages three independent queues: Realtime (1 worker), Manual (2 workers), and Idle (1 worker). Each queue has its own mpsc channel and worker threads. Jobs carry a CancellationToken for cooperative cancellation. Worker threads use panic-catching wrappers for crash recovery.",
          "Queue pressure is monitored via atomic counters. Idle workers add a 250ms delay between jobs to prevent CPU spikes. Manual scan workers use 4 threads internally (SCAN_THREADS) with chunked file distribution.",
        ],
      },
      {
        heading: "Process model",
        body: [
          "Sentinella separates work into independent OS processes for crash isolation: sentinelld (main daemon), clamavd (isolated ClamAV scanner, max 2 concurrent), sandboxd (behavioral detonation, max 1 concurrent), and optionally an external ARGUS worker. Each process boundary means a crash in one component does not bring down the others.",
          "ClamAV subprocess isolation is configurable. Each clamavd instance loads ~400 MB of signatures independently. Concurrency is gate by atomic counters with RAII guards for automatic cleanup.",
        ],
      },
      {
        heading: "Behavioral sandbox internals",
        body: [
          "Sandboxed processes run with a restricted Windows token (DISABLE_MAX_PRIVILEGE), at Low Integrity level (S-1-16-4096), inside a Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, no breakaway, 512 MB memory cap), and with per-PID firewall rules (netsh advfirewall) blocking all network access.",
          "The process is created via CreateProcessAsUserW in CREATE_SUSPENDED state. All containment (Job Object assignment, firewall rules) is applied before ResumeThread is called. ETW kernel sessions (StartTraceW/OpenTraceW/ProcessTrace) monitor process creation, DLL loads, registry persistence, and TCP connections via EVENT_RECORD callbacks.",
        ],
      },
      {
        heading: "IPC protocol",
        body: [
          "The daemon listens on a named pipe (\\\\.\\pipe\\sentinella). Requests use JSON-RPC 2.0 with method routing (scan.start, scan.status, quarantine.list, etc.). Dangerous commands (quarantine.restore, protection.set_critical) require a challenge-response flow: the GUI requests a single-use token via challenge.request (authenticated with an IPC secret), then passes the token to the protected command.",
          "Scan status uses a lock-free fast path: atomic counters (files_scanned, threats_found, status) are read without acquiring the inner mutex, so IPC polling never blocks scan worker threads.",
        ],
      },
      {
        heading: "ARGUS engine layers · ASTRA adaptive analysis",
        body: [
          "Layer 0: ClamAV signature database. Layer 1: MIME/type analysis (double extensions, RTLO, PE-as-PDF). Layer 2: PE heuristic analysis (exploit detection, import analysis, packing, structural anomalies). Layer 3: Reputation matching (domain-gated, word-boundary patterns). Layer 4: Context analysis (path, filename, environmental signals). Layer 5: IOC hash matching. Layer 6: YARA behavioral rules. Layer 7: Cross-layer correlation (convergence chains, attack stage progression). Layer 8: Behavioral runtime (sandbox detonation feedback). ASTRA orchestrates these layers with profile-aware bounded execution, ensuring deterministic and resource-intelligent analysis.",
          "Scores are not arbitrary thresholds. Single-category findings are capped. A file reaches High Risk or Malicious only through multi-category convergence. Every finding carries a BehaviorTag, AttackStage, confidence weight, and ThreatMaturity classification.",
        ],
      },
    ],
  },
};

// ══════════════════════════════════════════════════════════
//  Small presentational components
// ══════════════════════════════════════════════════════════

function AR({ l, v }: { l: string; v: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-[rgb(var(--t3))]">{l}</span>
      <span className="font-medium text-[12px] bg-[rgb(var(--raised))]/20 px-2 py-0.5 rounded text-[rgb(var(--t2))]">{v}</span>
    </div>
  );
}

function ExtLink({ label }: { label: string }) {
  return (
    <a href="#" className="text-[11px] text-[rgb(var(--accent))] flex items-center gap-1 hover:underline">
      <ExternalLink size={10} />{label}
    </a>
  );
}

function TopicCard({ icon: Icon, title, teaser, onClick }: { icon: typeof Cpu; title: string; teaser: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="glass-card p-5 text-left cursor-pointer transition-all hover:translate-y-[-1px] group"
    >
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className="w-7 h-7 rounded-md bg-[rgb(var(--accent))]/8 flex items-center justify-center">
          <Icon size={14} className="text-[rgb(var(--accent))]" />
        </div>
        <h5 className="text-[13px] font-semibold group-hover:text-[rgb(var(--accent))] transition-colors">{title}</h5>
      </div>
      <p className="text-[12px] text-[rgb(var(--t3))] leading-relaxed">{teaser}</p>
    </button>
  );
}

function HelpSection({ heading, body }: { heading: string; body: string[] }) {
  return (
    <div>
      {heading && <h4 className="text-[13px] font-semibold text-[rgb(var(--t1))] mb-2.5">{heading}</h4>}
      <div className="space-y-2.5">
        {body.map((paragraph, i) => (
          <p key={i} className="text-[13px] text-[rgb(var(--t2))] leading-[1.75]">{paragraph}</p>
        ))}
      </div>
    </div>
  );
}

function PlaceholderCard({ icon: Icon, label }: { icon: typeof Eye; label: string }) {
  return (
    <div className="glass-card p-5 opacity-40 cursor-default">
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className="w-7 h-7 rounded-md bg-[rgb(var(--raised))]/10 flex items-center justify-center">
          <Icon size={14} className="text-[rgb(var(--t3))]" />
        </div>
        <h5 className="text-[13px] font-semibold text-[rgb(var(--t3))]">{label}</h5>
      </div>
      <p className="text-[12px] text-[rgb(var(--t3))]">
        Coming soon
      </p>
    </div>
  );
}

import { useState, useEffect, useRef } from "react";
import { CheckCircle, Loader2, AlertCircle, RefreshCw } from "lucide-react";
import { getEngineStatus, getWatcherStatus, getRuntimeStats } from "../api/sentinella";
import loadBg from "../assets/load_ui.png";

export type StartupState =
  | "launching"
  | "connecting"
  | "loading_engine"
  | "loading_argus"
  | "starting_watcher"
  | "ready"
  | "degraded"
  | "failed";

interface SubsystemStatus {
  daemon: "waiting" | "ok" | "error";
  engine: "waiting" | "ok" | "error";
  argus: "waiting" | "ok" | "error";
  watcher: "waiting" | "ok" | "error";
  signatures: "waiting" | "ok" | "error";
}

const STEP_LABELS: Record<string, string> = {
  launching: "Starting protection...",
  connecting: "Connecting to daemon...",
  loading_engine: "Loading ClamAV engine...",
  loading_argus: "Preparing ARGUS intelligence...",
  starting_watcher: "Starting real-time monitoring...",
  ready: "Protection active",
  degraded: "Protection started with limitations",
  failed: "Could not start protection",
};

export function StartupScreen({ onReady }: { onReady: (degraded: boolean) => void }) {
  const [state, setState] = useState<StartupState>("launching");
  const [subs, setSubs] = useState<SubsystemStatus>({
    daemon: "waiting", engine: "waiting", argus: "waiting",
    watcher: "waiting", signatures: "waiting",
  });
  const [elapsed, setElapsed] = useState(0);
  const [showRetry, setShowRetry] = useState(false);
  const startTime = useRef(Date.now());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    // Elapsed timer.
    const timer = setInterval(() => {
      const s = Math.floor((Date.now() - startTime.current) / 1000);
      setElapsed(s);
      if (s >= 15) setShowRetry(true);
    }, 1000);

    // Poll daemon status.
    const poll = async () => {
      try {
        const engine = await getEngineStatus();
        const stats = await getRuntimeStats();

        // Daemon connected.
        setSubs(prev => ({ ...prev, daemon: "ok" }));
        setState("loading_engine");

        // Engine.
        if (engine.state === "ready") {
          setSubs(prev => ({ ...prev, engine: "ok" }));
          setState("loading_argus");
        } else if (engine.state === "error") {
          setSubs(prev => ({ ...prev, engine: "error" }));
        }

        // Signatures.
        if (engine.signature_count > 0) {
          setSubs(prev => ({ ...prev, signatures: "ok" }));
        }

        // ARGUS.
        if (stats.argus_yara_rules > 0 && stats.argus_active_layers > 0) {
          setSubs(prev => ({ ...prev, argus: "ok" }));
          setState("starting_watcher");
        }

        // Watcher.
        try {
          const w = await getWatcherStatus();
          if (w.enabled) {
            setSubs(prev => ({ ...prev, watcher: "ok" }));
          }
        } catch { /* watcher check optional */ }

        // Ready check.
        if (engine.state === "ready" && engine.signature_count > 0) {
          const allOk = stats.argus_active_layers > 0;
          if (allOk) {
            setState("ready");
            setTimeout(() => onReady(false), 800); // Brief pause to show "ready"
          } else {
            setState("degraded");
            setTimeout(() => onReady(true), 1500);
          }
          if (pollRef.current) clearInterval(pollRef.current);
        }
      } catch {
        // Daemon not available yet.
        setState("connecting");
        setSubs(prev => ({ ...prev, daemon: "waiting" }));
      }
    };

    // Initial + polling.
    poll();
    pollRef.current = setInterval(poll, 1000);

    return () => {
      clearInterval(timer);
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [onReady]);

  // Hard timeout → failed.
  useEffect(() => {
    if (elapsed >= 60 && state !== "ready" && state !== "degraded") {
      setState("failed");
      if (pollRef.current) clearInterval(pollRef.current);
    }
  }, [elapsed, state]);

  const retry = () => {
    startTime.current = Date.now();
    setElapsed(0);
    setShowRetry(false);
    setState("connecting");
    setSubs({ daemon: "waiting", engine: "waiting", argus: "waiting", watcher: "waiting", signatures: "waiting" });
    // Re-poll will be handled by existing interval or restart it.
    if (!pollRef.current) {
      pollRef.current = setInterval(async () => {
        try {
          const engine = await getEngineStatus();
          if (engine.state === "ready") {
            setState("ready");
            setTimeout(() => onReady(false), 500);
            if (pollRef.current) clearInterval(pollRef.current);
          }
        } catch { /* still waiting */ }
      }, 1000);
    }
  };

  return (
    <div className="h-screen w-screen relative overflow-hidden bg-[rgb(var(--base))]">
      {/* Background image */}
      <img
        src={loadBg}
        alt=""
        className="absolute inset-0 w-full h-full object-cover opacity-60"
        style={{ filter: "brightness(0.5) saturate(0.8)" }}
      />

      {/* Content overlay — checklist pinned to bottom-right */}
      <div className="absolute z-10 bottom-10 right-10 flex flex-col items-end gap-5">
        {/* Subsystem checklist */}
        <div className="p-4 min-w-[240px] rounded-lg" style={{ background: "rgba(0,0,0,0.45)", backdropFilter: "blur(8px)" }}>
          <SubLine label="Connecting to daemon" status={subs.daemon} />
          <SubLine label="Loading ClamAV engine" status={subs.engine} />
          <SubLine label="Loading signatures" status={subs.signatures} />
          <SubLine label="Initializing ARGUS · ASTRA analysis" status={subs.argus} />
          <SubLine label="Preparing real-time monitoring" status={subs.watcher} />
        </div>

        {/* Status + elapsed */}
        {state !== "ready" && state !== "degraded" && state !== "failed" && (
          <p className="text-[11px] text-white/35 pr-1">
            {STEP_LABELS[state]}{elapsed > 0 ? ` · ${elapsed}s` : ""}
          </p>
        )}

        {/* Actions on failure */}
        {state === "failed" && (
          <div className="flex flex-col items-end gap-2">
            <p className="text-[11px] text-white/40 text-right max-w-[260px]">
              Could not connect to daemon. Make sure sentinelld is running.
            </p>
            <button onClick={retry} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/10 text-white/70 text-[12px] font-medium hover:bg-white/15 cursor-pointer">
              <RefreshCw size={12} /> Retry
            </button>
            <button onClick={() => onReady(true)} className="text-[10px] text-white/25 hover:text-white/40 cursor-pointer">
              Continue in limited mode
            </button>
          </div>
        )}

        {showRetry && state !== "failed" && state !== "ready" && state !== "degraded" && (
          <p className="text-[10px] text-white/25 animate-pulse pr-1">
            Still starting...
          </p>
        )}
      </div>
    </div>
  );
}

function SubLine({ label, status }: { label: string; status: "waiting" | "ok" | "error" }) {
  return (
    <div className="flex items-center gap-3 py-1.5">
      {status === "waiting" && <Loader2 size={13} className="text-white/30 animate-spin" />}
      {status === "ok" && <CheckCircle size={13} className="text-emerald-400" />}
      {status === "error" && <AlertCircle size={13} className="text-amber-400" />}
      <span className={`text-[12px] ${status === "ok" ? "text-white/70" : status === "error" ? "text-amber-300/70" : "text-white/40"}`}>
        {label}
      </span>
    </div>
  );
}

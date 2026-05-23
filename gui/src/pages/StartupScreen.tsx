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
    <div className="h-screen w-screen flex items-center justify-center relative overflow-hidden bg-[rgb(var(--base))]">
      {/* Background image */}
      <img
        src={loadBg}
        alt=""
        className="absolute inset-0 w-full h-full object-cover opacity-60"
        style={{ filter: "brightness(0.5) saturate(0.8)" }}
      />

      {/* Content overlay */}
      <div className="relative z-10 flex flex-col items-center gap-8 px-8">
        {/* Status message */}
        <div className="text-center">
          <p className="text-[18px] font-semibold text-white/90 mb-2">
            {STEP_LABELS[state]}
          </p>
          {state !== "failed" && state !== "ready" && (
            <p className="text-[12px] text-white/40">
              {elapsed > 0 && `${elapsed}s`}
            </p>
          )}
        </div>

        {/* Subsystem checklist */}
        <div className="glass-card p-5 min-w-[280px]" style={{ background: "rgba(0,0,0,0.5)" }}>
          <SubLine label="Daemon connection" status={subs.daemon} />
          <SubLine label="ClamAV engine" status={subs.engine} />
          <SubLine label="Signature database" status={subs.signatures} />
          <SubLine label="ARGUS intelligence" status={subs.argus} />
          <SubLine label="Real-time watcher" status={subs.watcher} />
        </div>

        {/* Actions */}
        {state === "failed" && (
          <div className="flex flex-col items-center gap-3">
            <p className="text-[12px] text-white/50 text-center max-w-xs">
              Sentinella could not connect to the daemon. Make sure sentinelld is running.
            </p>
            <button onClick={retry} className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/10 text-white/80 text-[13px] font-medium hover:bg-white/15 cursor-pointer">
              <RefreshCw size={14} /> Retry Connection
            </button>
            <button onClick={() => onReady(true)} className="text-[11px] text-white/30 hover:text-white/50 cursor-pointer">
              Continue in limited mode
            </button>
          </div>
        )}

        {showRetry && state !== "failed" && state !== "ready" && state !== "degraded" && (
          <p className="text-[11px] text-white/30 animate-pulse">
            Still starting... this may take a moment.
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

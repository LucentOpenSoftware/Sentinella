import { ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";
import type { EngineStatus } from "../data/mock";

interface StatusCardProps {
  status: EngineStatus;
}

export function StatusCard({ status }: StatusCardProps) {
  const isReady = status.state === "ready";
  const isError = status.state === "error";

  return (
    <div
      className={`
        rounded-2xl p-6 border
        ${isError
          ? "bg-[rgb(var(--danger))]/5 border-[rgb(var(--danger))]/20"
          : isReady
            ? "bg-[rgb(var(--success))]/5 border-[rgb(var(--success))]/20"
            : "bg-[rgb(var(--accent))]/5 border-[rgb(var(--accent))]/20"
        }
      `}
    >
      <div className="flex items-center gap-4">
        {/* Shield icon */}
        <div
          className={`
            w-14 h-14 rounded-2xl flex items-center justify-center
            ${isError
              ? "bg-[rgb(var(--danger))]/15"
              : isReady
                ? "bg-[rgb(var(--success))]/15"
                : "bg-[rgb(var(--accent))]/15"
            }
          `}
        >
          {status.state === "loading" || status.state === "updating" ? (
            <Loader2 size={28} className="text-[rgb(var(--accent))] animate-spin" />
          ) : isError ? (
            <ShieldAlert size={28} className="text-[rgb(var(--danger))]" />
          ) : (
            <ShieldCheck size={28} className="text-[rgb(var(--success))]" />
          )}
        </div>

        <div className="flex-1">
          <h3 className="text-lg font-semibold">
            {isError
              ? "Protection Issue"
              : isReady
                ? "Your System is Protected"
                : status.state === "updating"
                  ? "Updating Signatures..."
                  : "Engine Loading..."}
          </h3>
          <p className="text-sm text-[rgb(var(--text-muted))] mt-0.5">
            {status.signatureCount.toLocaleString()} signatures loaded
            {status.dbVersion && <> &middot; DB v{status.dbVersion}</>}
          </p>
        </div>

        {/* Mini stats */}
        <div className="text-right">
          <p className="text-xs text-[rgb(var(--text-muted))]">Last update</p>
          <p className="text-sm font-medium">{status.lastUpdate}</p>
        </div>
      </div>
    </div>
  );
}

export function MiniStatusBadge({ status }: { status: EngineStatus }) {
  const color = status.state === "ready" ? "success" : status.state === "error" ? "danger" : "accent";
  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[rgb(var(--${color}))]/10 border border-[rgb(var(--${color}))]/20`}>
      <div className={`w-1.5 h-1.5 rounded-full bg-[rgb(var(--${color}))]`} />
      <span className={`text-xs font-medium text-[rgb(var(--${color}))]`}>
        {status.state === "ready" ? "Protected" : status.state === "error" ? "Error" : "Loading"}
      </span>
    </div>
  );
}

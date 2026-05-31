// Sentinella APP updater (the Tauri updater for sentinella.exe + the
// shipped daemon binaries). Distinct from the SIGNATURE updater on the
// same page, which only refreshes the ClamAV virus-definition DB.
//
// v0.1.9 consolidation (formerly lived in About.tsx as `UpdateChecker`;
// moved here so Update.tsx — the natural home for "anything that
// updates" — can render it alongside the signature update card. About
// is now pure informational content + license + tech stack.

import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Loader2,
} from "lucide-react";
import { check } from "@tauri-apps/plugin-updater";
import { Card } from "./Card";
import { t } from "../i18n";

type UpdateState =
  | "idle"
  | "checking"
  | "available"
  | "downloading"
  | "ready"
  | "up-to-date"
  | "error";

export function AppUpdater() {
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
      if (!update) {
        setState("up-to-date");
        return;
      }
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
            <p className="text-[14px] font-semibold">{t("about.sw_updates")}</p>
            <p className="text-[11px] text-[rgb(var(--t3))]">
              {state === "up-to-date"
                ? t("about.upd_latest")
                : state === "available"
                  ? `${t("about.upd_version")} ${version} ${t("about.upd_available")}`
                  : state === "downloading"
                    ? `${t("about.upd_downloading")} ${progress}%`
                    : state === "ready"
                      ? t("about.upd_ready")
                      : state === "error"
                        ? t("about.upd_failed")
                        : state === "checking"
                          ? t("about.upd_checking")
                          : t("about.upd_check_new")}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {state === "up-to-date" && (
            <CheckCircle2 size={16} className="text-[rgb(var(--green))]" />
          )}
          {state === "error" && (
            <AlertTriangle size={16} className="text-[rgb(var(--amber))]" />
          )}
          {state === "checking" || state === "downloading" ? (
            <Loader2 size={16} className="text-[rgb(var(--accent))] animate-spin" />
          ) : state === "available" ? (
            <button
              onClick={handleDownloadAndInstall}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--accent))]/10 text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/20 transition-colors cursor-pointer"
            >
              {t("about.upd_install")}
            </button>
          ) : state === "ready" ? (
            <button
              onClick={() => {
                import("@tauri-apps/plugin-updater").then(() => {
                  /* app will restart via NSIS */
                });
              }}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--green))]/10 text-[rgb(var(--green))] hover:bg-[rgb(var(--green))]/20 transition-colors cursor-pointer"
            >
              {t("about.upd_restart")}
            </button>
          ) : (
            <button
              onClick={handleCheck}
              className="text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-[rgb(var(--raised))]/30 text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/50 transition-colors cursor-pointer"
            >
              {t("about.upd_check")}
            </button>
          )}
        </div>
      </div>
      {state === "downloading" && (
        <div className="mt-3 h-1.5 bg-[rgb(var(--raised))]/20 rounded-full overflow-hidden">
          <div
            className="h-full bg-[rgb(var(--accent))] rounded-full transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}
      {error && (
        <p className="mt-2 text-[11px] text-[rgb(var(--amber))]">{error}</p>
      )}
    </Card>
  );
}

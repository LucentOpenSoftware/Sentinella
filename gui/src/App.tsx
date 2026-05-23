import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AppShell } from "./components/AppShell";
import { TopBarNotice } from "./components/ui";
import { startSignatureUpdate } from "./api/sentinella";
import { initLocale, t } from "./i18n";
import { DaemonProvider } from "./hooks/DaemonContext";
import type { Page } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { ScanPage } from "./pages/Scan";
import { QuarantinePage } from "./pages/Quarantine";
import { HistoryPage } from "./pages/History";
import { UpdatePage } from "./pages/Update";
import { SettingsPage } from "./pages/Settings";
import { AboutPage } from "./pages/About";
import { NotificationsPage } from "./pages/Notifications";
import { FirstRunWizard, isFirstRunComplete } from "./pages/FirstRun";
import { useDaemon } from "./hooks/useDaemon";
import "./App.css";

function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [droppedFile, setDroppedFile] = useState<string | null>(null);
  const [showWizard, setShowWizard] = useState(!isFirstRunComplete());
  const daemon = useDaemon();

  // Initialize locale from saved preference or browser language.
  useEffect(() => { initLocale(); }, []);

  // Disable right-click context menu + keyboard shortcuts in production.
  useEffect(() => {
    if (import.meta.env.PROD) {
      const blockMenu = (e: MouseEvent) => e.preventDefault();
      const blockKeys = (e: KeyboardEvent) => {
        // Block F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        if (e.key === "F12") e.preventDefault();
        if (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J")) e.preventDefault();
        if (e.ctrlKey && e.key === "u") e.preventDefault();
      };
      document.addEventListener("contextmenu", blockMenu);
      document.addEventListener("keydown", blockKeys);
      return () => {
        document.removeEventListener("contextmenu", blockMenu);
        document.removeEventListener("keydown", blockKeys);
      };
    }
  }, []);

  // Restore persisted theme + accent color on startup.
  useEffect(() => {
    const savedTheme = localStorage.getItem("sentinella-theme");
    if (savedTheme === "light" || savedTheme === "dark") {
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
    const colors = ["#3b82f6", "#14b8a6", "#a855f7", "#ec4899", "#f97316", "#06b6d4"];
    const savedIdx = localStorage.getItem("sentinella-accent-idx");
    if (savedIdx) {
      const idx = parseInt(savedIdx);
      if (idx >= 0 && idx < colors.length) {
        const hex = colors[idx];
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        document.documentElement.style.setProperty("--accent", `${r} ${g} ${b}`);
      }
    }
  }, []);

  // Drag-and-drop.
  useEffect(() => {
    if (showWizard) return;
    const webview = getCurrentWebviewWindow();
    const unlisten = webview.onDragDropEvent((event) => {
      if (event.payload.type === "drop") {
        const paths = event.payload.paths;
        if (paths.length > 0) {
          setDroppedFile(paths[0]);
          setPage("scan");
        }
      }
    });
    return () => { unlisten.then((fn) => fn()); };
  }, [showWizard]);

  const consumeDroppedFile = () => {
    const file = droppedFile;
    setDroppedFile(null);
    return file;
  };

  // First-run wizard gate.
  if (showWizard) {
    return (
      <ErrorBoundary>
        <FirstRunWizard onComplete={() => setShowWizard(false)} />
      </ErrorBoundary>
    );
  }

  // ── Scan completion notice (auto-dismiss after 15s) ─────
  const [scanDoneNotice, setScanDoneNotice] = useState<{ type: string; files: number; threats: number } | null>(null);
  const scanDoneTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevScanRunningRef = useRef(false);

  useEffect(() => {
    const scan = daemon.data?.scan;
    if (!scan) return;

    const wasRunning = prevScanRunningRef.current;
    const isRunning = scan.running;
    prevScanRunningRef.current = isRunning;

    // Detect scan completion transition.
    if (wasRunning && !isRunning && scan.state === "completed") {
      setScanDoneNotice({
        type: scan.scan_type || "scan",
        files: scan.files_scanned,
        threats: scan.threats_found,
      });
      // Auto-dismiss after 15 seconds.
      if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current);
      scanDoneTimerRef.current = setTimeout(() => setScanDoneNotice(null), 15_000);
    }
  }, [daemon.data?.scan?.running, daemon.data?.scan?.state]);

  // Clean up timer on unmount.
  useEffect(() => () => { if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current); }, []);

  const dismissScanDone = useCallback(() => {
    setScanDoneNotice(null);
    if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current);
  }, []);

  // ── TopBar notices — up to 3, priority-ordered ────────
  const topNotices = useMemo(() => {
    const notices: React.ReactNode[] = [];

    // Priority 1: connection/protection state (max 1).
    const cs = daemon.connectionState;
    if (cs === "recovering") {
      notices.push(<TopBarNotice key="recovering" variant="info" message={t("notice.recovering")} dismissKey="recovering" />);
    } else if (cs === "degraded") {
      notices.push(<TopBarNotice key="degraded-recovery" variant="warning" message={t("notice.degraded_recovery")} dismissKey="degraded-recovery" />);
    } else if (cs === "user_disabled") {
      notices.push(<TopBarNotice key="user-disabled" variant="error" message={t("notice.user_disabled")} dismissKey="user-disabled" />);
    } else if (!daemon.connected) {
      notices.push(<TopBarNotice key="disconnected" variant="warning" message={t("notice.disconnected")} dismissKey="disconnected" />);
    } else {
      const recoveryAudit = daemon.data?.stats && (daemon.data.stats as any).daemon_mode === "audit";
      if (recoveryAudit) {
        notices.push(<TopBarNotice key="audit" variant="warning" message={t("notice.audit_mode")} dismissKey="audit-mode" />);
      }

      const stats = daemon.data?.stats;
      if (stats) {
        const ps = stats.protection_state;
        if (ps === "degraded" || ps === "minimal") {
          notices.push(<TopBarNotice key="degraded" variant="warning" message={stats.protection_detail || "Protection degraded"} dismissKey="degraded" />);
        }
        if (stats.db_stale && notices.length < 3) {
          const msg = stats.db_stale_hours > 24
            ? `Signatures ${Math.floor(stats.db_stale_hours / 24)}d old`
            : stats.db_stale_hours > 0
              ? `Signatures ${stats.db_stale_hours}h old`
              : "Signatures never updated";
          notices.push(
            <TopBarNotice
              key="stale-db"
              variant="warning"
              message={msg}
              dismissKey="stale-db"
              actions={
                <button
                  onClick={() => { startSignatureUpdate().catch(() => {}); }}
                  className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
                >
                  {t("notice.update_now")}
                </button>
              }
            />
          );
        }
      }
    }

    // Priority 2: active scan progress.
    const scan = daemon.data?.scan;
    if (scan?.running && notices.length < 3) {
      const label = scan.scan_type
        ? scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)
        : "Scan";
      notices.push(
        <TopBarNotice
          key="scan-running"
          variant="info"
          message={`${label} scan in progress`}
          actions={
            <button
              onClick={() => setPage("scan")}
              className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
            >
              View progress
            </button>
          }
        />
      );
    }

    // Priority 3: scan completed (auto-dismissing).
    if (scanDoneNotice && !scan?.running && notices.length < 3) {
      const label = scanDoneNotice.type.charAt(0).toUpperCase() + scanDoneNotice.type.slice(1);
      const msg = scanDoneNotice.threats > 0
        ? `${label} scan done — ${scanDoneNotice.threats} threat${scanDoneNotice.threats > 1 ? "s" : ""} found`
        : `${label} scan complete — ${scanDoneNotice.files.toLocaleString()} files clean`;
      notices.push(
        <TopBarNotice
          key="scan-done"
          variant={scanDoneNotice.threats > 0 ? "error" : "success"}
          message={msg}
          onDismiss={dismissScanDone}
          actions={
            scanDoneNotice.threats > 0 ? (
              <button
                onClick={() => { setPage("quarantine"); dismissScanDone(); }}
                className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
              >
                View quarantine
              </button>
            ) : undefined
          }
        />
      );
    }

    return notices;
  }, [daemon.connected, daemon.connectionState, daemon.data?.stats, daemon.data?.scan, scanDoneNotice, dismissScanDone]);

  return (
    <ErrorBoundary>
      <DaemonProvider value={daemon}>
        <AppShell
          currentPage={page}
          onNavigate={setPage}
          connected={daemon.connected}
          onRefresh={daemon.refresh}
          notices={topNotices}
        >
          {page === "dashboard" && <Dashboard onNavigate={setPage} />}
          {page === "scan" && <ScanPage droppedFile={droppedFile} onConsumeDroppedFile={consumeDroppedFile} connected={daemon.connected} engineStatus={daemon.data?.engine ?? null} />}
          {page === "quarantine" && <QuarantinePage />}
          {page === "history" && <HistoryPage />}
          {page === "update" && <UpdatePage />}
          {page === "settings" && <SettingsPage />}

          {page === "notifications" && <NotificationsPage />}
          {page === "about" && <AboutPage />}
        </AppShell>
      </DaemonProvider>
    </ErrorBoundary>
  );
}

export default App;

import { useState } from "react";
import { AppShell } from "./components/AppShell";
import type { Page } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { ScanPage } from "./pages/Scan";
import { QuarantinePage } from "./pages/Quarantine";
import { HistoryPage } from "./pages/History";
import { SettingsPage } from "./pages/Settings";
import { AboutPage } from "./pages/About";
import { useDaemon } from "./hooks/useDaemon";
import "./App.css";

function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const daemon = useDaemon();

  return (
    <AppShell
      currentPage={page}
      onNavigate={setPage}
      connected={daemon.connected}
      onRefresh={daemon.refresh}
    >
      {page === "dashboard" && <Dashboard />}
      {page === "scan" && <ScanPage />}
      {page === "quarantine" && <QuarantinePage />}
      {page === "history" && <HistoryPage />}
      {page === "settings" && <SettingsPage />}
      {page === "about" && <AboutPage />}
    </AppShell>
  );
}

export default App;

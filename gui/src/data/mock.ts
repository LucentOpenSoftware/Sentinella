// Mock data for GUI shell development.
// All of this will be replaced by real IPC calls to sentinelld.

export interface EngineStatus {
  state: "ready" | "loading" | "updating" | "error" | "starting";
  signatureCount: number;
  dbVersion: number | null;
  lastUpdate: string;
  engineVersion: string;
  realtimeActive: boolean;
  watchedFolders: number;
  uptime: string;
}

export interface ScanHistoryEntry {
  id: string;
  type: "quick" | "full" | "custom";
  date: string;
  filesScanned: number;
  threatsFound: number;
  duration: string;
  status: "clean" | "threats" | "cancelled" | "error";
}

export interface QuarantineItem {
  id: string;
  filename: string;
  originalPath: string;
  signature: string;
  severity: "critical" | "high" | "medium" | "low";
  quarantinedAt: string;
  size: string;
  sha256: string;
}

export interface ActivityEvent {
  id: string;
  type: "scan_complete" | "threat_found" | "update" | "quarantine" | "realtime";
  message: string;
  timestamp: string;
  detail?: string;
}

export const mockEngineStatus: EngineStatus = {
  state: "ready",
  signatureCount: 8_721_403,
  dbVersion: 27458,
  lastUpdate: "2 hours ago",
  engineVersion: "0.1.0",
  realtimeActive: true,
  watchedFolders: 4,
  uptime: "3d 14h 22m",
};

export const mockScanHistory: ScanHistoryEntry[] = [
  {
    id: "1",
    type: "quick",
    date: "Today, 09:32 AM",
    filesScanned: 14_203,
    threatsFound: 0,
    duration: "2m 14s",
    status: "clean",
  },
  {
    id: "2",
    type: "full",
    date: "Yesterday, 03:00 AM",
    filesScanned: 284_710,
    threatsFound: 1,
    duration: "47m 03s",
    status: "threats",
  },
  {
    id: "3",
    type: "quick",
    date: "May 10, 10:15 AM",
    filesScanned: 13_987,
    threatsFound: 0,
    duration: "2m 08s",
    status: "clean",
  },
  {
    id: "4",
    type: "full",
    date: "May 8, 03:00 AM",
    filesScanned: 281_042,
    threatsFound: 0,
    duration: "45m 11s",
    status: "clean",
  },
  {
    id: "5",
    type: "custom",
    date: "May 6, 02:14 PM",
    filesScanned: 342,
    threatsFound: 0,
    duration: "8s",
    status: "clean",
  },
];

export const mockQuarantine: QuarantineItem[] = [
  {
    id: "q1",
    filename: "keygen.exe",
    originalPath: "C:\\Users\\Nicolas\\Downloads\\keygen.exe",
    signature: "Win.Trojan.Agent-1234",
    severity: "high",
    quarantinedAt: "Yesterday, 03:21 AM",
    size: "1.2 MB",
    sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  },
  {
    id: "q2",
    filename: "crack_v2.dll",
    originalPath: "C:\\Users\\Nicolas\\Downloads\\tools\\crack_v2.dll",
    signature: "Win.Malware.Riskware-9876",
    severity: "medium",
    quarantinedAt: "May 8, 11:44 AM",
    size: "384 KB",
    sha256: "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2",
  },
];

export const mockActivity: ActivityEvent[] = [
  {
    id: "a1",
    type: "scan_complete",
    message: "Quick scan completed",
    timestamp: "Today, 09:34 AM",
    detail: "14,203 files scanned — no threats found",
  },
  {
    id: "a2",
    type: "update",
    message: "Signatures updated",
    timestamp: "Today, 07:00 AM",
    detail: "Database v27458 — 12 new signatures",
  },
  {
    id: "a3",
    type: "threat_found",
    message: "Threat detected and quarantined",
    timestamp: "Yesterday, 03:21 AM",
    detail: "keygen.exe — Win.Trojan.Agent-1234",
  },
  {
    id: "a4",
    type: "realtime",
    message: "Real-time protection active",
    timestamp: "Yesterday, 12:00 AM",
    detail: "Monitoring Downloads, Desktop, Documents, Temp",
  },
  {
    id: "a5",
    type: "scan_complete",
    message: "Full scan completed",
    timestamp: "Yesterday, 03:47 AM",
    detail: "284,710 files scanned — 1 threat quarantined",
  },
];

// Lightweight local notification history.
// No personal content collected. Nothing uploaded.

export interface NotificationRecord {
  timestamp: number;
  type: string;
  title: string;
  relatedFile: string | null;
  scanId: string | null;
}

const HISTORY_KEY = "sentinella-notification-history";
const MAX_ENTRIES = 100;

export function recordNotification(
  type: string,
  title: string,
  relatedFile?: string,
  scanId?: string,
): void {
  try {
    const history = loadHistory();
    history.push({
      timestamp: Date.now(),
      type,
      title,
      relatedFile: relatedFile ?? null,
      scanId: scanId ?? null,
    });
    // Trim to max.
    while (history.length > MAX_ENTRIES) history.shift();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    // localStorage full or unavailable — silent.
  }
}

export function loadHistory(): NotificationRecord[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function clearHistory(): void {
  localStorage.removeItem(HISTORY_KEY);
}

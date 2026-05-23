// Notification preference storage — persisted in localStorage.

export type NotificationSeverity = "info" | "warning" | "threat" | "critical";

export interface NotificationSettings {
  enabled: boolean;
  onThreat: boolean;
  onQuarantine: boolean;
  onUpdateFailure: boolean;
  onDegraded: boolean;
  onScanComplete: boolean; // only when threats found
  quietMode: boolean; // suppress all toasts temporarily
  /** Minimum severity to show. "info" = all, "threat" = threats+critical only. */
  minSeverity: NotificationSeverity;
}

const STORAGE_KEY = "sentinella-notification-settings";

const DEFAULTS: NotificationSettings = {
  enabled: true,
  onThreat: true,
  onQuarantine: true,
  onUpdateFailure: true,
  onDegraded: true,
  onScanComplete: true,
  quietMode: false,
  minSeverity: "info",
};

export function loadNotificationSettings(): NotificationSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULTS };
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveNotificationSettings(s: NotificationSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

// Severity ranking for threshold comparison.
const SEVERITY_RANK: Record<NotificationSeverity, number> = {
  info: 0,
  warning: 1,
  threat: 2,
  critical: 3,
};

export function meetsMinSeverity(level: NotificationSeverity, min: NotificationSeverity): boolean {
  return SEVERITY_RANK[level] >= SEVERITY_RANK[min];
}

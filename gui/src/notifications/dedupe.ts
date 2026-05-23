// Notification deduplication and storm control.
//
// Prevents:
// - Same notification firing twice within cooldown window.
// - Rapid-fire events producing 20+ separate toasts (aggregates instead).

/** Default cooldown: 5 minutes. */
const DEFAULT_COOLDOWN_MS = 5 * 60 * 1000;

/** Storm window: aggregate events within this period. */
const STORM_WINDOW_MS = 15_000; // 15 seconds

/** Max individual toasts before switching to aggregate mode. */
const STORM_THRESHOLD = 3;

// ── Dedupe cache ──────────────────────────────────────────────

interface CacheEntry {
  key: string;
  timestamp: number;
}

const dedupeCache: CacheEntry[] = [];

/** Returns true if this notification should be shown (not a duplicate). */
export function dedupeCheck(key: string, cooldownMs = DEFAULT_COOLDOWN_MS): boolean {
  const now = Date.now();

  // Prune expired entries.
  while (dedupeCache.length > 0 && now - dedupeCache[0].timestamp > cooldownMs) {
    dedupeCache.shift();
  }

  // Check for duplicate.
  if (dedupeCache.some(e => e.key === key)) return false;

  dedupeCache.push({ key, timestamp: now });

  // Cap cache size (safety).
  if (dedupeCache.length > 200) dedupeCache.splice(0, dedupeCache.length - 100);

  return true;
}

// ── Storm aggregation ─────────────────────────────────────────

interface StormBucket {
  category: string;
  count: number;
  firstAt: number;
  lastAt: number;
  timer: ReturnType<typeof setTimeout> | null;
  flush: (count: number) => void;
}

const stormBuckets = new Map<string, StormBucket>();

/**
 * Storm-controlled notification dispatch.
 *
 * If fewer than STORM_THRESHOLD events arrive within STORM_WINDOW,
 * each fires individually via `sendOne`. If more arrive, they're
 * aggregated and `sendSummary(count)` fires once after the window.
 */
export function stormControlled(
  category: string,
  sendOne: () => void,
  sendSummary: (count: number) => void,
): void {
  const now = Date.now();
  let bucket = stormBuckets.get(category);

  if (!bucket || now - bucket.lastAt > STORM_WINDOW_MS) {
    // Clear any leftover timer from the previous bucket to prevent it from
    // deleting the newly created bucket when it fires.
    if (bucket?.timer) clearTimeout(bucket.timer);
    // New storm window — send immediately.
    bucket = { category, count: 1, firstAt: now, lastAt: now, timer: null, flush: sendSummary };
    stormBuckets.set(category, bucket);
    sendOne();
    return;
  }

  bucket.count++;
  bucket.lastAt = now;

  if (bucket.count <= STORM_THRESHOLD) {
    // Still under threshold — send individually.
    sendOne();
  } else if (bucket.count === STORM_THRESHOLD + 1) {
    // Just crossed threshold — schedule aggregate summary.
    if (bucket.timer) clearTimeout(bucket.timer);
    const b = bucket;
    bucket.timer = setTimeout(() => {
      b.flush(b.count);
      stormBuckets.delete(category);
    }, STORM_WINDOW_MS);
  }
  // If count > threshold+1, do nothing — summary timer already pending.
}

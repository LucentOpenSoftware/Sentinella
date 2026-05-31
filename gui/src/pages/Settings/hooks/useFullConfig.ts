// useFullConfig — Settings page state container.
//
// Fetches FullConfig + defaults + restart-requirements once on mount,
// holds a working draft the tabs mutate via `update(patch)`. On save:
//   - Splits the draft into NON-critical fields and kill-vector fields
//   - Sends non-critical via save_full_settings (challenge token only)
//   - Sends kill-vector via set_critical_settings (UAC required)
//   - Surfaces any rejection (insufficient_privilege, validation error)
//     back to the calling tab so it can render the inline error.
//
// Why one hook: keeping the tabs as dumb leaf components means the
// reset / restart / elevation logic lives in one place. Tabs only
// know how to render fields and call `update`.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getDefaultSettings,
  getFullSettings,
  getRestartRequirements,
  saveFullSettings,
  setCriticalSettings,
} from "../../../api/sentinella";
import {
  CRITICAL_FIELDS,
  type FullConfig,
  type RestartRequirementMap,
  type SettingsWriteResult,
} from "../../../types/sentinella";

// ─── Session-level caches ───────────────────────────────────────
//
// `defaults` and `restartReqs` are STATIC for the lifetime of a
// connected daemon — they only change when the daemon binary itself
// changes (new fields, restart-classification shifts). Caching at
// module scope means we fetch them exactly ONCE per daemon session
// instead of on every Settings mount. That matters because the
// daemon's `Status` rate bucket is shared with the dashboard's
// 9-endpoint poll loop; three extra parallel reads on every Settings
// open were tipping it into "rate limited" (-32020) on busy systems.
//
// v0.1.9 audit HIGH-3 fix: the v0.1.8 version of this comment claimed
// "STATIC per daemon version — they never change while the GUI is
// running". That's false if the daemon hot-restarts (tray restart,
// service auto-restart, scheduled-update reload). After such a
// restart the cached defaults / restart_requirements could be stale
// against a new daemon binary — isDefault() would return wrong
// booleans, resetField() would write old defaults into new schemas,
// dirtyFlags would iterate the stale field set and miss newly-added
// fields entirely. Fix: expose `invalidateSettingsCache()` and call
// it from the daemon-disconnected→reconnected transition (see
// useDaemon.ts).
//
// Promises are kept so concurrent callers share the in-flight fetch
// instead of racing to start three more.

let defaultsCache: FullConfig | null = null;
let defaultsPromise: Promise<FullConfig> | null = null;
let restartReqsCache: RestartRequirementMap | null = null;
let restartReqsPromise: Promise<RestartRequirementMap> | null = null;

/**
 * Drop the module-scope defaults + restart-requirements caches so the
 * next mount of useFullConfig re-fetches both. Called from useDaemon
 * on a disconnect→reconnect transition (daemon binary may have changed).
 */
export function invalidateSettingsCache(): void {
  defaultsCache = null;
  defaultsPromise = null;
  restartReqsCache = null;
  restartReqsPromise = null;
}

function fetchDefaultsOnce(): Promise<FullConfig> {
  if (defaultsCache) return Promise.resolve(defaultsCache);
  if (defaultsPromise) return defaultsPromise;
  defaultsPromise = getDefaultSettings()
    .then((d) => {
      defaultsCache = d;
      return d;
    })
    .finally(() => {
      defaultsPromise = null;
    });
  return defaultsPromise;
}

function fetchRestartReqsOnce(): Promise<RestartRequirementMap> {
  if (restartReqsCache) return Promise.resolve(restartReqsCache);
  if (restartReqsPromise) return restartReqsPromise;
  restartReqsPromise = getRestartRequirements()
    .then((r) => {
      restartReqsCache = r;
      return r;
    })
    .finally(() => {
      restartReqsPromise = null;
    });
  return restartReqsPromise;
}

/** Get the value of a possibly-nested path like "fish.window_seconds". */
function getPath(obj: unknown, path: string): unknown {
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur && typeof cur === "object" && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** Deep-equality for primitives + arrays of primitives. Sufficient for FullConfig. */
function eqValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => v === b[i]);
  }
  return a === b;
}

export type FullConfigStatus =
  | { kind: "loading" }
  | { kind: "ready" }
  | { kind: "saving" }
  | { kind: "error"; message: string };

export interface UseFullConfigResult {
  status: FullConfigStatus;
  draft: FullConfig | null;
  defaults: FullConfig | null;
  restartReqs: RestartRequirementMap | null;
  /** Replace a top-level field (or nested via dot-path through update()). */
  update: (patch: Partial<FullConfig>) => void;
  /** Apply a nested patch via dot-path, e.g. updatePath("fish.window_seconds", 60). */
  updatePath: (path: string, value: unknown) => void;
  /** Persist the draft (split between non-critical and critical writes). */
  save: () => Promise<SettingsWriteResult>;
  /** True if any field differs from the loaded baseline. */
  isDirty: boolean;
  /** True if at least one CRITICAL field differs from baseline (UAC required). */
  isCriticalDirty: boolean;
  /** True if the draft value of `path` equals the default. Hides reset btn. */
  isDefault: (path: string) => boolean;
  /** Reset a single field to its default. */
  resetField: (path: string) => void;
  /** Discard all unsaved changes. */
  reload: () => Promise<void>;
}

export function useFullConfig(): UseFullConfigResult {
  const [status, setStatus] = useState<FullConfigStatus>({ kind: "loading" });
  const [baseline, setBaseline] = useState<FullConfig | null>(null);
  const [draft, setDraft] = useState<FullConfig | null>(null);
  const [defaults, setDefaults] = useState<FullConfig | null>(null);
  const [restartReqs, setRestartReqs] = useState<RestartRequirementMap | null>(
    null,
  );

  const reload = useCallback(async () => {
    setStatus({ kind: "loading" });
    try {
      // Defaults + restart_requirements are session-immutable — served
      // from cache after the first fetch ever. Only getFullSettings
      // actually hits the daemon on subsequent Settings opens.
      // Sequence the calls (not Promise.all) so the daemon's Status
      // rate bucket sees them one at a time, sharing budget with the
      // dashboard poll instead of competing in a burst.
      const cfg = await getFullSettings();
      const def = await fetchDefaultsOnce();
      const rr = await fetchRestartReqsOnce();
      setBaseline(cfg);
      setDraft(structuredClone(cfg));
      setDefaults(def);
      setRestartReqs(rr);
      setStatus({ kind: "ready" });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // If the error is the daemon's rate-limit response, retry once
      // after a brief wait — the bucket refills quickly. Avoids a
      // hard error on busy systems where the user opened Settings
      // mid-dashboard-poll.
      if (msg.includes("-32020") || msg.toLowerCase().includes("rate limit")) {
        await new Promise((r) => setTimeout(r, 1200));
        try {
          const cfg = await getFullSettings();
          const def = await fetchDefaultsOnce();
          const rr = await fetchRestartReqsOnce();
          setBaseline(cfg);
          setDraft(structuredClone(cfg));
          setDefaults(def);
          setRestartReqs(rr);
          setStatus({ kind: "ready" });
          return;
        } catch (e2) {
          setStatus({
            kind: "error",
            message: e2 instanceof Error ? e2.message : String(e2),
          });
          return;
        }
      }
      setStatus({ kind: "error", message: msg });
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const update = useCallback((patch: Partial<FullConfig>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
  }, []);

  // Apply a value into a possibly-nested key path. Currently supports
  // one level of nesting (e.g. "fish.window_seconds") — enough for
  // FullConfig's shape.
  const updatePath = useCallback((path: string, value: unknown) => {
    setDraft((d) => {
      if (!d) return d;
      const parts = path.split(".");
      if (parts.length === 1) {
        return { ...d, [parts[0]]: value } as FullConfig;
      }
      if (parts.length === 2) {
        const [outer, inner] = parts;
        const outerObj = (d as unknown as Record<string, Record<string, unknown>>)[outer];
        return {
          ...d,
          [outer]: { ...outerObj, [inner]: value },
        } as FullConfig;
      }
      // No 3-deep nesting in FullConfig today.
      return d;
    });
  }, []);

  const resetField = useCallback(
    (path: string) => {
      if (!defaults) return;
      const v = getPath(defaults, path);
      updatePath(path, v);
    },
    [defaults, updatePath],
  );

  const isDefault = useCallback(
    (path: string) => {
      if (!draft || !defaults) return true;
      return eqValue(getPath(draft, path), getPath(defaults, path));
    },
    [draft, defaults],
  );

  const dirtyFlags = useMemo(() => {
    if (!draft || !baseline)
      return { isDirty: false, isCriticalDirty: false };
    let isDirty = false;
    let isCriticalDirty = false;
    // Top-level and one-deep nested fields covered by RestartRequirementMap.
    const paths = Object.keys(restartReqs?.fields ?? {});
    for (const p of paths) {
      if (!eqValue(getPath(draft, p), getPath(baseline, p))) {
        isDirty = true;
        if (CRITICAL_FIELDS.has(p)) isCriticalDirty = true;
      }
    }
    return { isDirty, isCriticalDirty };
  }, [draft, baseline, restartReqs]);

  const save = useCallback(async (): Promise<SettingsWriteResult> => {
    if (!draft || !baseline) {
      return { ok: false, error: "No draft loaded" };
    }
    setStatus({ kind: "saving" });

    // 1) Split into critical and non-critical diff
    const criticalDiff: Record<string, unknown> = {};
    for (const path of CRITICAL_FIELDS) {
      const dv = getPath(draft, path);
      const bv = getPath(baseline, path);
      if (!eqValue(dv, bv)) {
        criticalDiff[path] = dv;
      }
    }

    // 2) Send critical first (UAC required); if it fails, do NOT send
    //    the non-critical write so the user sees the one error path.
    if (Object.keys(criticalDiff).length > 0) {
      try {
        const r = await setCriticalSettings(criticalDiff);
        if (!r.ok) {
          setStatus({ kind: "ready" });
          return r;
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setStatus({ kind: "ready" });
        return { ok: false, error: msg };
      }
    }

    // 3) Send the full draft via save_full_settings. The daemon rejects
    //    with INSUFFICIENT_PRIVILEGE if any critical field still differs
    //    — which shouldn't happen since we just applied them — but
    //    surface that as the error path anyway.
    try {
      const r = await saveFullSettings(draft);
      if (r.ok) {
        await reload(); // refresh baseline from disk
      } else {
        setStatus({ kind: "ready" });
      }
      return r;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setStatus({ kind: "ready" });
      return { ok: false, error: msg };
    }
  }, [draft, baseline, reload]);

  return {
    status,
    draft,
    defaults,
    restartReqs,
    update,
    updatePath,
    save,
    resetField,
    isDefault,
    reload,
    isDirty: dirtyFlags.isDirty,
    isCriticalDirty: dirtyFlags.isCriticalDirty,
  };
}

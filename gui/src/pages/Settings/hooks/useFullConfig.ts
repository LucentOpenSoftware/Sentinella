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
      const [cfg, def, rr] = await Promise.all([
        getFullSettings(),
        getDefaultSettings(),
        getRestartRequirements(),
      ]);
      setBaseline(cfg);
      setDraft(structuredClone(cfg));
      setDefaults(def);
      setRestartReqs(rr);
      setStatus({ kind: "ready" });
    } catch (e) {
      setStatus({
        kind: "error",
        message: e instanceof Error ? e.message : String(e),
      });
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

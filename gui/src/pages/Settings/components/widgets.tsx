// Shared widgets for the v0.1.8 Settings tabs.
//
// Visual rules:
//   - Section: titled block with subtitle, used to group related rows.
//   - SettingRow: label + description + right-aligned control + per-row metadata
//     (reset-to-default button, "needs restart" pill, lock icon for kill-vector).
//   - Toggle / Slider / NumberInput / TextInput / SelectInput: typed
//     controls that take `value` + `onChange` like uncontrolled HTMLish inputs.
//   - ListEditor: chip-based string list editor with optional path picker.
//
// Every control is a leaf — no API calls. State and persistence live in
// the tab and the useFullConfig hook.

import { useState, type ReactNode } from "react";
import {
  AlertTriangle,
  FolderOpen,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  X,
} from "lucide-react";
import * as i18n from "../../../i18n";
import type { RestartRequirement } from "../../../types/sentinella";

// ─── Section ────────────────────────────────────────────────────

export function Section({
  title,
  subtitle,
  children,
  icon,
  experimental,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  icon?: ReactNode;
  experimental?: boolean;
}) {
  return (
    <section className="bg-[rgb(var(--surface))]/40 border border-[rgb(var(--border))]/30 rounded-xl p-5 mb-5">
      <header className="flex items-start gap-3 mb-4">
        {icon && <div className="text-[rgb(var(--accent))] mt-0.5">{icon}</div>}
        <div className="flex-1 min-w-0">
          <h3 className="text-base font-semibold flex items-center gap-2">
            {title}
            {experimental && (
              <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30">
                {i18n.t("settings.experimental")}
              </span>
            )}
          </h3>
          {subtitle && (
            <p className="text-xs text-[rgb(var(--muted))] mt-0.5">
              {subtitle}
            </p>
          )}
        </div>
      </header>
      <div className="space-y-3">{children}</div>
    </section>
  );
}

// ─── SettingRow ─────────────────────────────────────────────────

export function SettingRow({
  label,
  description,
  control,
  isDefault,
  onReset,
  restartRequirement,
  locked,
  warning,
}: {
  label: string;
  description?: string;
  control: ReactNode;
  /** True when current value matches default — hides the reset button. */
  isDefault?: boolean;
  /** Called when user clicks the per-row "↺" reset-to-default. Hidden if absent. */
  onReset?: () => void;
  /** "engine_reload" or "daemon_restart" → render a "needs restart" pill. */
  restartRequirement?: RestartRequirement;
  /** Kill-vector field — render a lock icon + reminder. */
  locked?: boolean;
  /** Optional inline warning under the description. */
  warning?: string;
}) {
  const restartLabel =
    restartRequirement === "engine_reload"
      ? i18n.t("settings.needs_engine_reload")
      : restartRequirement === "daemon_restart"
        ? i18n.t("settings.needs_daemon_restart")
        : null;

  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-[rgb(var(--border))]/15 last:border-b-0">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          {locked && (
            <Lock
              className="w-3.5 h-3.5 text-amber-400"
              strokeWidth={2.2}
              aria-label={i18n.t("settings.locked_field")}
            />
          )}
          <label className="text-sm font-medium">{label}</label>
          {restartLabel && (
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/30">
              {restartLabel}
            </span>
          )}
        </div>
        {description && (
          <p className="text-xs text-[rgb(var(--muted))] leading-snug">
            {description}
          </p>
        )}
        {warning && (
          <p className="text-xs text-amber-400 leading-snug mt-1 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> {warning}
          </p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {!isDefault && onReset && (
          <button
            onClick={onReset}
            className="opacity-50 hover:opacity-100 transition-opacity p-1 rounded hover:bg-[rgb(var(--surface))]/60"
            title={i18n.t("settings.reset_to_default")}
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        )}
        {control}
      </div>
    </div>
  );
}

// ─── Toggle ─────────────────────────────────────────────────────

export function Toggle({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={() => onChange(!checked)}
      disabled={disabled}
      className={`relative w-10 h-5 rounded-full transition-colors ${
        checked ? "bg-[rgb(var(--accent))]" : "bg-[rgb(var(--surface))]/80"
      } ${disabled ? "opacity-40 cursor-not-allowed" : "cursor-pointer"}`}
      role="switch"
      aria-checked={checked}
    >
      <span
        className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
          checked ? "translate-x-5" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

// ─── NumberInput (with min/max + suffix) ────────────────────────

export function NumberInput({
  value,
  onChange,
  min,
  max,
  step,
  suffix,
  disabled,
  width = "w-24",
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  suffix?: string;
  disabled?: boolean;
  width?: string;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        onChange={(e) => {
          const n = Number(e.target.value);
          if (Number.isFinite(n)) onChange(n);
        }}
        className={`${width} bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 rounded px-2 py-1 text-sm text-right focus:border-[rgb(var(--accent))] focus:outline-none ${disabled ? "opacity-40 cursor-not-allowed" : ""}`}
      />
      {suffix && (
        <span className="text-xs text-[rgb(var(--muted))]">{suffix}</span>
      )}
    </div>
  );
}

// ─── Slider ─────────────────────────────────────────────────────

export function Slider({
  value,
  onChange,
  min,
  max,
  step = 1,
  suffix,
  disabled,
  showValue = true,
}: {
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step?: number;
  suffix?: string;
  disabled?: boolean;
  showValue?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 min-w-[200px]">
      <input
        type="range"
        value={value}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className={`flex-1 accent-[rgb(var(--accent))] ${disabled ? "opacity-40 cursor-not-allowed" : "cursor-pointer"}`}
      />
      {showValue && (
        <span className="text-xs tabular-nums text-[rgb(var(--muted))] w-20 text-right">
          {value}
          {suffix && ` ${suffix}`}
        </span>
      )}
    </div>
  );
}

// ─── SelectInput ────────────────────────────────────────────────

export function SelectInput<T extends string>({
  value,
  onChange,
  options,
  disabled,
}: {
  value: T;
  onChange: (v: T) => void;
  options: Array<{ value: T; label: string }>;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value as T)}
      className={`bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 rounded px-2 py-1 text-sm focus:border-[rgb(var(--accent))] focus:outline-none ${disabled ? "opacity-40 cursor-not-allowed" : ""}`}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

// ─── TextInput ──────────────────────────────────────────────────

export function TextInput({
  value,
  onChange,
  placeholder,
  disabled,
  width = "w-64",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
  width?: string;
}) {
  return (
    <input
      type="text"
      value={value}
      placeholder={placeholder}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className={`${width} bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 rounded px-2 py-1 text-sm focus:border-[rgb(var(--accent))] focus:outline-none ${disabled ? "opacity-40 cursor-not-allowed" : ""}`}
    />
  );
}

// ─── ListEditor (chip-based) ────────────────────────────────────

export function ListEditor({
  items,
  onChange,
  placeholder,
  validator,
  withPathPicker,
  pathPickerOptions,
  disabled,
  maxEntries,
}: {
  items: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  /** Returns null if valid, error string otherwise. */
  validator?: (s: string) => string | null;
  /** Render a "browse" button that opens the OS file/directory picker. */
  withPathPicker?: boolean;
  pathPickerOptions?: { directory?: boolean; multiple?: boolean };
  disabled?: boolean;
  /** Soft cap — disables add button when reached. Defaults to 64. */
  maxEntries?: number;
}) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const cap = maxEntries ?? 64;
  const atCap = items.length >= cap;

  const tryAdd = (raw: string) => {
    const v = raw.trim();
    if (!v) {
      setError(i18n.t("settings.empty_entry"));
      return;
    }
    if (items.includes(v)) {
      setError(i18n.t("settings.duplicate_entry"));
      return;
    }
    if (validator) {
      const msg = validator(v);
      if (msg) {
        setError(msg);
        return;
      }
    }
    onChange([...items, v]);
    setDraft("");
    setError(null);
  };

  const browse = async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const picked = await open({
        directory: pathPickerOptions?.directory ?? true,
        multiple: pathPickerOptions?.multiple ?? false,
      });
      if (picked) {
        if (Array.isArray(picked)) {
          for (const p of picked) tryAdd(p);
        } else {
          tryAdd(picked);
        }
      }
    } catch {
      // user cancelled
    }
  };

  return (
    <div className="w-full">
      <div className="flex flex-wrap gap-1.5 mb-2 min-h-[1.5rem]">
        {items.length === 0 ? (
          <span className="text-xs text-[rgb(var(--muted))] italic">
            {i18n.t("settings.empty_list")}
          </span>
        ) : (
          items.map((item, i) => (
            <span
              key={`${item}-${i}`}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 text-xs"
            >
              <span className="font-mono truncate max-w-[28rem]">{item}</span>
              {!disabled && (
                <button
                  onClick={() => onChange(items.filter((_, j) => j !== i))}
                  className="text-[rgb(var(--muted))] hover:text-red-400"
                  aria-label="Remove"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </span>
          ))
        )}
      </div>
      {!disabled && (
        <div className="flex items-center gap-1.5">
          <input
            type="text"
            value={draft}
            placeholder={placeholder}
            onChange={(e) => {
              setDraft(e.target.value);
              setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                tryAdd(draft);
              }
            }}
            className="flex-1 bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 rounded px-2 py-1 text-xs font-mono focus:border-[rgb(var(--accent))] focus:outline-none"
          />
          {withPathPicker && (
            <button
              onClick={browse}
              disabled={atCap}
              className="p-1.5 rounded bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 hover:border-[rgb(var(--accent))] disabled:opacity-40 disabled:cursor-not-allowed"
              title={i18n.t("settings.browse")}
            >
              <FolderOpen className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={() => tryAdd(draft)}
            disabled={atCap || !draft.trim()}
            className="px-2 py-1 rounded bg-[rgb(var(--accent))]/10 border border-[rgb(var(--accent))]/40 text-[rgb(var(--accent))] text-xs hover:bg-[rgb(var(--accent))]/20 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1"
          >
            <Plus className="w-3 h-3" /> {i18n.t("settings.add")}
          </button>
        </div>
      )}
      {error && (
        <p className="text-xs text-red-400 mt-1.5 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> {error}
        </p>
      )}
      <p className="text-[10px] text-[rgb(var(--muted))] mt-1">
        {items.length}/{cap} {i18n.t("settings.entries")}
      </p>
    </div>
  );
}

// ─── ElevationBanner ────────────────────────────────────────────

export function ElevationBanner({ onRestartAsAdmin }: { onRestartAsAdmin?: () => void }) {
  return (
    <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-between gap-3">
      <div className="flex items-center gap-2 text-sm">
        <Lock className="w-4 h-4 text-amber-400" />
        <span>{i18n.t("settings.elevation_required_banner")}</span>
      </div>
      {onRestartAsAdmin && (
        <button
          onClick={onRestartAsAdmin}
          className="px-3 py-1 rounded text-xs bg-amber-500/20 border border-amber-500/40 text-amber-200 hover:bg-amber-500/30 flex items-center gap-1.5"
        >
          <RefreshCw className="w-3 h-3" />
          {i18n.t("settings.restart_as_admin")}
        </button>
      )}
    </div>
  );
}

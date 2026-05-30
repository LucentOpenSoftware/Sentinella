// Appearance tab — theme, accent color, locale.
//
// These are GUI-local settings stored in localStorage (theme + accent)
// or in the i18n loader's runtime state (locale). They do NOT travel
// through the FullConfig IPC — every install picks its own UI flavour
// independent of the daemon's config file.

import { useEffect, useState } from "react";
import { Globe, Palette, Sun } from "lucide-react";
import * as i18n from "../../../i18n";
import { Section, SettingRow } from "../components/widgets";

const ACCENT_COLORS = [
  { n: "Blue", v: "#3b82f6" },
  { n: "Teal", v: "#14b8a6" },
  { n: "Purple", v: "#a855f7" },
  { n: "Pink", v: "#ec4899" },
  { n: "Orange", v: "#f97316" },
  { n: "Cyan", v: "#06b6d4" },
];

function applyAccent(hex: string) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  document.documentElement.style.setProperty("--accent", `${r} ${g} ${b}`);
}

export function AppearanceTab() {
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem("sentinella-theme") as "dark" | "light") || "dark",
  );
  const [accentIdx, setAccentIdx] = useState(() => {
    const saved = localStorage.getItem("sentinella-accent-idx");
    return saved ? parseInt(saved, 10) : 0;
  });
  const [locale, setLocale] = useState(() => i18n.getLocale());

  // Apply on mount so the theme/accent stick even when index.tsx remounts.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    applyAccent(ACCENT_COLORS[accentIdx].v);
  }, [theme, accentIdx]);

  const handleTheme = (t: "dark" | "light") => {
    setTheme(t);
    localStorage.setItem("sentinella-theme", t);
    document.documentElement.setAttribute("data-theme", t);
  };

  const handleAccent = (idx: number) => {
    setAccentIdx(idx);
    localStorage.setItem("sentinella-accent-idx", String(idx));
    applyAccent(ACCENT_COLORS[idx].v);
  };

  return (
    <div>
      {/* ── Theme ──────────────────────────────────── */}
      <Section
        icon={<Sun />}
        title={i18n.t("settings.theme")}
        subtitle={i18n.t("settings.theme_desc")}
      >
        <SettingRow
          label={i18n.t("settings.theme_mode")}
          control={
            <div className="flex gap-1.5">
              {(["dark", "light"] as const).map((t) => {
                const active = theme === t;
                return (
                  <button
                    key={t}
                    onClick={() => handleTheme(t)}
                    className={`px-3 py-1 rounded text-xs capitalize transition-colors ${
                      active
                        ? "bg-[rgb(var(--accent))]/15 border border-[rgb(var(--accent))]/40 text-[rgb(var(--accent))]"
                        : "border border-[rgb(var(--border))]/40 text-[rgb(var(--muted))] hover:bg-[rgb(var(--surface))]/60"
                    }`}
                  >
                    {i18n.t(`settings.theme_${t}`)}
                  </button>
                );
              })}
            </div>
          }
        />
      </Section>

      {/* ── Accent ─────────────────────────────────── */}
      <Section
        icon={<Palette />}
        title={i18n.t("settings.accent")}
        subtitle={i18n.t("settings.accent_desc")}
      >
        <SettingRow
          label={i18n.t("settings.accent_color")}
          control={
            <div className="flex gap-1.5">
              {ACCENT_COLORS.map((c, i) => (
                <button
                  key={c.n}
                  onClick={() => handleAccent(i)}
                  title={c.n}
                  className={`w-6 h-6 rounded-full transition-transform ${
                    accentIdx === i
                      ? "ring-2 ring-white ring-offset-2 ring-offset-[rgb(var(--surface))] scale-110"
                      : "hover:scale-105"
                  }`}
                  style={{ background: c.v }}
                />
              ))}
            </div>
          }
        />
      </Section>

      {/* ── Locale ─────────────────────────────────── */}
      <Section
        icon={<Globe />}
        title={i18n.t("settings.language")}
        subtitle={i18n.t("settings.language_desc")}
      >
        <SettingRow
          label={i18n.t("settings.language")}
          control={
            <select
              value={locale}
              onChange={(e) => {
                i18n.setLocale(e.target.value);
                setLocale(e.target.value);
              }}
              className="bg-[rgb(var(--surface))]/80 border border-[rgb(var(--border))]/40 rounded px-2 py-1 text-sm focus:border-[rgb(var(--accent))] focus:outline-none"
            >
              {i18n.availableLocales().map((l) => (
                <option key={l.code} value={l.code}>
                  {l.label}
                </option>
              ))}
            </select>
          }
        />
      </Section>
    </div>
  );
}

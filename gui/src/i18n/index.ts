// Sentinella i18n — lightweight translation system.
// No external deps. Just a key→string map per locale.

import { en } from "./en";
import { es } from "./es";
import { pt_br } from "./pt-br";
import { ja } from "./ja";
import { fr } from "./fr";
import { de } from "./de";
import { it } from "./it";
import { ru } from "./ru";
import { zh_cn } from "./zh-cn";

export type TranslationKey = keyof typeof en;

const locales: Record<string, Record<string, string>> = {
  en,
  es,
  "pt-br": pt_br,
  ja,
  fr,
  de,
  it,
  ru,
  "zh-cn": zh_cn,
};

let currentLocale = "en";

/**
 * Dev-only drift detector: report how far the active locale has fallen behind
 * `en`. There is no test runner in the GUI (gui/package.json ships no
 * vitest/jest) and `t()` takes a plain `string`, so nothing in the build
 * notices when a locale is missing keys — the user just gets English islands
 * inside an otherwise translated page. This at least puts it in the console of
 * whoever is working on the app. Vite substitutes `import.meta.env.DEV` at
 * build time, so this is a no-op in production.
 */
function warnIfLocaleIncomplete(locale: string): void {
  if (!import.meta.env.DEV || locale === "en") return;
  const table = locales[locale];
  if (!table) return;
  const allKeys = Object.keys(en);
  const missing = allKeys.filter((k) => !(k in table));
  if (missing.length > 0) {
    console.warn(
      `[i18n] locale "${locale}" is missing ${missing.length}/${allKeys.length} keys ` +
        `and will render English for them. First: ${missing.slice(0, 5).join(", ")}`,
    );
  }
}

/** Set the active locale. Falls back to "en" if unavailable. */
export function setLocale(locale: string): void {
  currentLocale = locales[locale] ? locale : "en";
  localStorage.setItem("sentinella-locale", currentLocale);
  warnIfLocaleIncomplete(currentLocale);
}

/** Get the active locale code. */
export function getLocale(): string {
  return currentLocale;
}

/** Initialize locale from persisted preference or system. */
export function initLocale(): void {
  currentLocale = resolveInitialLocale();
  warnIfLocaleIncomplete(currentLocale);
}

/** Persisted preference, else browser language, else "en". */
function resolveInitialLocale(): string {
  const saved = localStorage.getItem("sentinella-locale");
  if (saved && locales[saved]) return saved;
  // Auto-detect from browser.
  const raw = (navigator.language || "en").toLowerCase();
  // Full BCP-47 tag match first (e.g. "pt-br", "zh-cn").
  if (locales[raw]) return raw;
  // Primary language fallbacks for regional variants we don't separately ship.
  const primary = raw.split("-")[0];
  // Portuguese — any pt-* variant maps to Brazilian Portuguese (only variant we ship).
  if (primary === "pt") return "pt-br";
  // Chinese — any zh-* (zh-tw, zh-hk, zh-sg, bare zh) maps to Simplified mainland.
  if (primary === "zh") return "zh-cn";
  if (locales[primary]) return primary;
  return "en";
}

/** Translate a key. Returns the key itself if no translation found. */
export function t(key: string): string {
  const locale = locales[currentLocale];
  if (locale && key in locale) return locale[key];
  // Fallback to English.
  if (key in en) return en[key];
  return key;
}

/**
 * Translate `key`, or return `fallback` when no locale — not even `en` —
 * defines it.
 *
 * `t()` returns the KEY on a miss, and a key is truthy, so the natural-looking
 * `t("settings.list_full") || "list full"` is dead code: the user sees the raw
 * identifier. Use `tf` for any string whose key may legitimately be absent
 * (not yet added to the locale files), and keep the fallback readable English
 * so a miss degrades to a sentence instead of a dotted identifier.
 */
export function tf(key: string, fallback: string): string {
  const locale = locales[currentLocale];
  if (locale && key in locale) return locale[key];
  if (key in en) return en[key];
  return fallback;
}

/** Available locales. */
export function availableLocales(): { code: string; label: string }[] {
  return [
    { code: "en", label: "English" },
    { code: "es", label: "Español" },
    { code: "pt-br", label: "Português (Brasil)" },
    { code: "fr", label: "Français" },
    { code: "de", label: "Deutsch" },
    { code: "it", label: "Italiano" },
    { code: "ru", label: "Русский" },
    { code: "ja", label: "日本語" },
    { code: "zh-cn", label: "简体中文" },
  ];
}

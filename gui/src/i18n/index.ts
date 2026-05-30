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

/** Set the active locale. Falls back to "en" if unavailable. */
export function setLocale(locale: string): void {
  currentLocale = locales[locale] ? locale : "en";
  localStorage.setItem("sentinella-locale", currentLocale);
}

/** Get the active locale code. */
export function getLocale(): string {
  return currentLocale;
}

/** Initialize locale from persisted preference or system. */
export function initLocale(): void {
  const saved = localStorage.getItem("sentinella-locale");
  if (saved && locales[saved]) {
    currentLocale = saved;
    return;
  }
  // Auto-detect from browser.
  const raw = (navigator.language || "en").toLowerCase();
  // Full BCP-47 tag match first (e.g. "pt-br", "zh-cn").
  if (locales[raw]) {
    currentLocale = raw;
    return;
  }
  // Primary language fallbacks for regional variants we don't separately ship.
  const primary = raw.split("-")[0];
  // Portuguese — any pt-* variant maps to Brazilian Portuguese (only variant we ship).
  if (primary === "pt") {
    currentLocale = "pt-br";
    return;
  }
  // Chinese — any zh-* (zh-tw, zh-hk, zh-sg, bare zh) maps to Simplified mainland.
  if (primary === "zh") {
    currentLocale = "zh-cn";
    return;
  }
  if (locales[primary]) {
    currentLocale = primary;
  }
}

/** Translate a key. Returns the key itself if no translation found. */
export function t(key: string): string {
  const locale = locales[currentLocale];
  if (locale && key in locale) return locale[key];
  // Fallback to English.
  if (key in en) return en[key];
  return key;
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

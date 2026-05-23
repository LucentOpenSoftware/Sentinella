// Sentinella i18n — lightweight translation system.
// No external deps. Just a key→string map per locale.

import { en } from "./en";
import { es } from "./es";

export type TranslationKey = keyof typeof en;

const locales: Record<string, Record<string, string>> = { en, es };

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
  const browser = navigator.language.split("-")[0].toLowerCase();
  if (locales[browser]) {
    currentLocale = browser;
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
  ];
}

// Single source of truth for the GUI version string.
//
// Bump this on every release. Anything in the UI that needs to display
// the app version MUST import APP_VERSION from here instead of hardcoding
// a literal — that was the v0.1.5 → v0.1.6 frustration cause: a literal
// like `v0.1.5` was scattered across 3+ component files and 9 locale
// files, and refactor-grep across all of them every release is brittle.
//
// The i18n locale files (gui/src/i18n/*.ts) still store the version as a
// translation value (`app.version`, `meta.about_sub`) because the i18n
// loader is template-free. Those must still be bumped per release until
// the loader gains placeholder interpolation. Until then: bump THIS
// constant + run `npm run version:bump-locales` (or grep & sed the 9
// locale files) and you're done.
export const APP_VERSION = "0.1.8";
export const APP_VERSION_TAG = `v${APP_VERSION}`;

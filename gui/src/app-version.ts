// Single source of truth for the GUI version string.
//
// Bump this on every release. Anything in the UI that needs to display
// the app version MUST import APP_VERSION from here instead of hardcoding
// a literal — that was the v0.1.5 → v0.1.6 frustration cause: a literal
// like `v0.1.5` was scattered across 3+ component files and 9 locale
// files, and refactor-grep across all of them every release is brittle.
//
// Bumping this constant is the WHOLE release step for the GUI version.
// There is no `npm run version:bump-locales` (gui/package.json has scripts
// dev/build/preview/tauri/preflight:staging/release:build and nothing else) —
// an earlier version of this comment told the release engineer to run it.
//
// The locale files used to carry `"app.version"` and `"meta.about_sub"`,
// both holding the version as literal text. Nothing read either one — every
// version the user sees comes from APP_VERSION_TAG below (Sidebar.tsx,
// AppShell.tsx, About.tsx) — so they were 18 sites (9 locales x 2) that had
// to be hand-edited every release and silently went stale when they were not.
// They are deleted. Do not reintroduce them: a component wired to a locale
// key would make the displayed version depend on the active language.
//
// THIS CONSTANT IS THE ONLY PLACE THE VERSION LIVES ON THE TS SIDE.
export const APP_VERSION = "0.1.13";
export const APP_VERSION_TAG = `v${APP_VERSION}`;

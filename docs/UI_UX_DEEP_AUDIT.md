# Sentinella UI/UX Deep Audit

**Date**: May 2026  
**Scope**: Full GUI audit — pages, components, flows, design system  
**Goal**: Identify improvements, do not rewrite yet

---

## Executive Summary

Sentinella's GUI is functional and visually cohesive with a frosted-glass aesthetic. The core pages (Dashboard, Scan, Quarantine, History, Update, Settings, About) cover all essential AV functions. However, several areas need polish for daily-driver trust:

**Current UI Score: 6.5/10**

Strengths:
- Frosted glass cards create visual depth
- Calm color palette (no fearware)
- Sidebar navigation is clean
- System tray integration works
- Loading screen exists

Weaknesses:
- Status inconsistencies (Connected vs Disconnected)
- Dense information without hierarchy
- Missing empty/error states on some pages
- Settings page too technical
- Scan flow lacks clear lifecycle feedback
- No visual difference between scan types in progress
- Quarantine lacks threat context summary
- History drill-down is basic

---

## Top 10 Issues

| # | Issue | Severity | Page |
|---|---|---|---|
| 1 | **Status contradiction**: TopBar "Connected" while Scan shows "Daemon unavailable" | Critical | Scan/TopBar |
| 2 | **Scan cancel feedback**: No "Cancelling..." state shown, UI just stops | High | Scan |
| 3 | **Dashboard too dense**: 5 status tiles + warnings + activity in one scroll | Medium | Dashboard |
| 4 | **Settings tabs not discoverable**: 6 tabs including Notifications buried | Medium | Settings |
| 5 | **Quarantine lacks threat explanation**: Only shows detection name, no ARGUS context | Medium | Quarantine |
| 6 | **History drill-down minimal**: No ARGUS verdict details in scan history | Medium | History |
| 7 | **Empty states missing**: Some pages show nothing when daemon disconnected | Low | Multiple |
| 8 | **About page static**: No dynamic version/build info from daemon | Low | About |
| 9 | **First-run wizard basic**: 3 steps, no visual progress indicator | Low | FirstRun |
| 10 | **No keyboard navigation**: Focus rings and tab order not implemented | Low | All |

---

## Page-by-Page Audit

### Dashboard
**What works**: Hero card with protection status, 5 status tiles, ARGUS intelligence summary, recent activity, stale DB warning.

**Issues**:
- 5 tiles in 4-column grid → last tile wraps awkwardly
- Background tile shows scanning/paused states but no visual context for what "Background" means to a new user
- Activity list uses raw timestamps, no relative time ("2 minutes ago")
- Degraded protection warning text is dense
- No visual hierarchy between "everything is fine" and "action needed"

**Recommendations**:
- Reduce to 4 tiles (merge Background into Watcher or remove)
- Add relative timestamps to activity
- Make action items (update, scan) more prominent when protection degraded
- Consider two-column layout: status left, activity right

### Scan
**What works**: File/Quick/Folder scan cards, progress bar, file count, elapsed time, recent scans list, drag-and-drop.

**Issues**:
- "Daemon not connected" banner persists even when TopBar shows Connected (FIXED in code, but UI contract still fragile)
- Cancel button doesn't show "Cancelling..." state (now "cancelling" IPC state exists but UI doesn't render it)
- Scan result cards are dense — findings list is raw
- No visual distinction between scan types in progress (Quick vs Folder look identical)
- Recent scans list doesn't show scan duration in human-readable format
- No "scan again" quick action after completion

**Recommendations**:
- Add "Cancelling..." UI state with spinner
- Show scan type icon/label in progress card
- Add "Scan Again" button on completion
- Truncate long paths with tooltip
- Show human-readable duration ("5m 32s" not "332s")

### Quarantine
**What works**: Item list with expand/collapse, SHA-256, path, signature, restore/delete with confirmation dialogs, toast feedback.

**Issues**:
- No ARGUS score/confidence shown (just detection name)
- No behavior tag summary
- No explanation of why file was quarantined
- Restore button disabled when vault missing but no explanation tooltip
- Delete confirmation is text-only, could show file details

**Recommendations**:
- Add ARGUS score badge + confidence label to each item
- Add "Why quarantined" expandable section with top 3 findings
- Show clear message when vault file is missing/corrupted
- Add batch operations (select multiple → delete/restore)

### History
**What works**: Scan list with status icons, file count, threat count, date. Drill-down shows detections and ARGUS verdicts.

**Issues**:
- Drill-down ARGUS verdicts are raw JSON-like display
- No visual timeline
- No filtering beyond "threats only"
- Duration shown as milliseconds in some views
- Export button exists but format unclear to user

**Recommendations**:
- Improve drill-down with finding cards
- Add date-range filter
- Show duration in human format
- Add scan type filter (quick/folder/file)

### Settings
**What works**: 6 tabs (General, Appearance, Protection, Notifications, Updates, Advanced), toggle components, save feedback.

**Issues**:
- Too many tabs — "Notifications" is easily missed
- "Advanced" contains shutdown flow which is critical safety feature buried
- No search/filter in settings
- Toggle descriptions are small and easy to miss
- Notification severity threshold picker is a 4-button segmented control — not obvious what it does
- No preview of notification behavior

**Recommendations**:
- Merge Notifications into General or Protection
- Make Advanced's shutdown flow more prominent with warning
- Add settings descriptions as tooltips
- Consider accordion layout instead of tabs

### Update
**What works**: Signature info, update button, progress bar, ARGUS intelligence packs list.

**Issues**:
- Update progress reloads entire dashboard poll during update
- ARGUS pack list is dense — rule counts are technical
- No visual indicator of "database freshness" (how old)
- "Reload Rules" button purpose unclear to non-developer

**Recommendations**:
- Add "Last updated: 2 hours ago" human-readable freshness
- Simplify pack list — collapse by default, show total only
- Hide "Reload Rules" unless in developer/advanced mode

### About
**What works**: Shows version, branding image.

**Issues**:
- Static content — doesn't pull version from daemon
- No system info (OS, architecture)
- No links to documentation, GitHub, support
- Large about image (1MB) loads even if user never visits page

**Recommendations**:
- Pull version + build info from daemon/IPC
- Add system info section
- Add links to docs/GitHub
- Lazy-load about image

### First-Run Wizard
**What works**: 3-step flow (Welcome → Signatures → Optional Scan), daemon polling, signature update.

**Issues**:
- No visual step indicator (progress bar/stepper)
- Text is dense on welcome page
- No skip option for experienced users
- First-run toast notification fires before user understands the app

**Recommendations**:
- Add step indicator (1/3, 2/3, 3/3)
- Add "Skip setup" for advanced users
- Delay first notification until wizard completes

### Startup/Loading Screen
**What works**: Splash.html with background image, 5-step checklist, calm wording.

**Issues**:
- Splash controlled by Rust timer — may not reflect actual daemon state
- Step animation is time-based, not state-based
- If daemon loads fast, user still sees animation for 9+ seconds
- Main window starts hidden but may flash briefly in dev mode

**Recommendations**:
- Connect splash steps to actual daemon state (needs IPC bridge or faster Rust polling)
- Skip splash if daemon already ready (< 2s startup)
- Add "Skip" link after 5 seconds

---

## Design System Findings

### Strengths
- CSS variables for colors (dark/light themes)
- Frosted glass cards (`glass-card` class)
- Consistent border radius (16px cards, 12px buttons)
- Segoe UI Variable font stack
- 8px spacing grid

### Issues
- Too many one-off inline styles (Tailwind classes vary per component)
- Badge styles not unified (some `bg-[rgb(var(--green))]/8`, some `bg-emerald-400`)
- Button styles inconsistent (some rounded-xl, some rounded-2xl)
- Modal/dialog not a shared component (Quarantine has inline dialog)
- Toggle component defined inside Settings, not reusable
- Status colors not consistently applied (green/amber/red meaning varies)
- Glass card opacity values differ slightly between dark/light

### Recommended Design Tokens
```css
--radius-card: 16px
--radius-button: 12px
--radius-badge: 9999px (pill)
--gap-page: 40px
--gap-card: 32px
--gap-section: 24px
--gap-inline: 12px
```

---

## Status Model Issues

| State | Current Display | Problem |
|---|---|---|
| Connected + scan running | TopBar: Connected, Scan: may show disconnected | **Contradictory** — now fixed with shared state |
| Cancelling scan | No visual difference from "running" | **Missing** — "cancelling" state added to IPC |
| Draining (cancel finishing) | No visual feedback | **Missing** — needs UI |
| Idle scanner active | Dashboard tile only | **Buried** — most users won't notice |
| Protection degraded | Yellow banner | **Good** but text is dense |
| First-run incomplete | Wizard shows | **Good** |
| Signatures stale | Yellow banner with hours | **Good** |

---

## Component Architecture Recommendations

### Extract These Components
| Component | Current Location | Reuse |
|---|---|---|
| `ConfirmDialog` | Quarantine (inline) | Quarantine + Settings + Scan |
| `StatusBadge` | TopBar (inline) | TopBar + Dashboard + Tray |
| `MetricCard` | Dashboard (StatusTile) | Dashboard + Scan + Update |
| `FindingCard` | Scan (inline) | Scan + History + Quarantine |
| `EmptyState` | Various (inconsistent) | All pages |
| `Toast` | Quarantine (inline) | Global |
| `Toggle` | Settings (inline) | Settings + future pages |

---

## Accessibility Findings

| Issue | Severity | Fix |
|---|---|---|
| No focus rings on interactive elements | Medium | Add `focus-visible` outlines |
| No `aria-label` on icon-only buttons | Medium | Add labels to refresh/notification buttons |
| Color-only status indicators (green dot = connected) | Low | Add text labels (already present) |
| No skip-to-content link | Low | Add for keyboard users |
| Sidebar buttons lack active state announcement | Low | Add `aria-current="page"` |
| Reduced motion not respected | Low | Add `prefers-reduced-motion` media query |

---

## Performance Findings

| Issue | Impact | Fix |
|---|---|---|
| Dashboard polls 10+ IPC calls every 5s | Medium | Batch into single `fetchDashboard` (already done) |
| Scan status polls every 2s during scan | Low | Acceptable after reduction from 500ms |
| About page loads 1MB image on mount | Low | Lazy-load with `loading="lazy"` |
| Notification history in localStorage | Low | Cap at 100 entries (already done) |
| All pages render even when not visible | Low | Add lazy page loading |

---

## Recommended Redesign Waves

### Wave 1: Design System Cleanup
- Extract shared components (ConfirmDialog, StatusBadge, EmptyState, Toast)
- Unify button/badge/card styles
- Add focus rings
- Add `prefers-reduced-motion`

### Wave 2: Dashboard Rewrite
- 4-tile grid (not 5)
- Two-column layout: status | activity
- Relative timestamps
- Action buttons when degraded
- Cleaner hero card

### Wave 3: Scan Flow Rewrite
- Cancelling/draining state UI
- Scan type indicator in progress
- "Scan Again" button
- Human-readable duration
- Better result cards with ARGUS findings

### Wave 4: Quarantine + History Polish
- ARGUS score + confidence on quarantine items
- "Why quarantined" section
- History drill-down with finding cards
- Date-range filter

### Wave 5: Settings Simplification
- Merge Notifications into Protection tab
- Accordion layout
- Better descriptions
- Hide advanced features by default

### Wave 6: Startup + Tray UX
- State-based splash (not timer-based)
- Skip splash on fast startup
- Tray-first mode config
- Dynamic tray icon states

### Wave 7: Accessibility + Performance
- Focus management
- ARIA labels
- Lazy page loading
- Reduced motion support
- Color contrast verification

---

*This audit is diagnostic, not prescriptive. Each redesign wave should be
validated against the "calm security" aesthetic and tested with field users
before committing to full implementation.*

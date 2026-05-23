# Windows Toast Actions Roadmap

**Status**: Not yet implemented  
**Date**: May 2026

---

## Goal

Add actionable buttons to Windows toast notifications so users can respond
directly from the notification without opening the full GUI.

## Desired Actions

| Notification | Action 1 | Action 2 |
|---|---|---|
| Threat detected | View threat | Open Sentinella |
| File quarantined | Open quarantine | Dismiss |
| Scan complete (threats) | View results | Run full scan |
| Update failed | Retry update | Dismiss |
| Protection degraded | Open Sentinella | Dismiss |

## Current Limitation

Tauri's `tauri-plugin-notification` (v2.x) provides `sendNotification()` with
`title` and `body` but does **not** support:

- Action buttons on toasts
- Click-to-open deep linking
- Toast activation (user clicking the toast body)
- Inline reply or input fields
- Custom toast templates (XML)

The plugin wraps `winrt::Windows::UI::Notifications::ToastNotification` but
only exposes the simple text notification path.

## Implementation Options

### Option A: Tauri Plugin PR

Upstream a PR to `tauri-plugin-notification` adding:

```rust
ToastButton { content: String, arguments: String }
```

Pros: clean integration, community benefit.  
Cons: review cycle, may not align with plugin maintainer goals.

### Option B: Native Rust Side-Channel

Bypass the plugin. From `gui/src-tauri/src/lib.rs`, call Windows toast APIs
directly via the `windows` crate:

```rust
use windows::UI::Notifications::*;
use windows::Data::Xml::Dom::*;

fn send_actionable_toast(title: &str, body: &str, actions: &[(&str, &str)]) {
    // Build XML template with <action> elements
    // Register activation handler via COM
    // Send via ToastNotificationManager
}
```

Pros: full control, no plugin dependency.  
Cons: COM registration, AUMID handling, activation callback complexity.

### Option C: PowerShell Fallback

Shell out to PowerShell for toast with buttons:

```powershell
[Windows.UI.Notifications.ToastNotificationManager, ...]::...
```

Pros: simple, no native code.  
Cons: PowerShell startup cost (~200ms), hard to handle activation callbacks.

## Recommended Approach

**Option B** (native Rust) for v1.5+. Reasons:

1. Full control over toast XML template.
2. Can register protocol handler (`sentinella://view-threat?id=...`).
3. Works with Tauri's window management.
4. No external dependency.

## Prerequisites

1. Register an AUMID (Application User Model ID) during installation.
2. Create a COM activation server or use protocol activation.
3. Handle toast activation in the Tauri app's window event loop.

## Protocol Activation Sketch

Register `sentinella://` protocol in the installer. When user clicks a toast
action, Windows launches:

```
sentinella://quarantine/view
sentinella://scan/results?id=abc123
sentinella://update/retry
```

The Tauri app catches the deep link and navigates to the appropriate page.

## Timeline

- **v1.0**: Text-only toasts (current)
- **v1.5**: Native Rust toast actions + protocol handler
- **v2.0**: Rich toast templates (progress bars, images)

---

*This document tracks the roadmap for actionable Windows toast notifications.*

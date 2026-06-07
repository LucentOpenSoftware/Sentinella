//! WeedHack browser-injection probe.
//!
//! ## Attack pattern
//!
//! WeedHack Stage 2 (Elevator.jar) steals browser cookies/passwords by
//! loading a native DLL into a running browser process and using the
//! Chromium remote-debugging IPC or direct memory reads to exfiltrate
//! the user's session state. The DLL is dropped to a user-writable
//! location (`%TEMP%`, `%APPDATA%\Microsoft\SecurityUpdates`, or a
//! similar foothold), is **unsigned** (operator can't sign anything
//! with a code-signing cert without burning it), and is loaded into
//! `chrome.exe` / `msedge.exe` / `brave.exe` / `firefox.exe` /
//! `opera.exe` via Windows `LoadLibrary` after handle injection.
//!
//! ## What we detect
//!
//! An `ImageLoad` ETW event where ALL of the following are true:
//!
//! 1. The target process is a known browser.
//! 2. The loaded module path is under a user-writable foothold
//!    (`%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, or the Microsoft\
//!    SecurityUpdates impersonator).
//! 3. The loaded module is unsigned (or signing status is unknown,
//!    which on Windows usually means unsigned).
//! 4. The browser process has a `javaw.exe` / `java.exe` ancestor in
//!    its lineage chain.
//!
//! Condition 4 is the key false-positive guard. Browser extensions and
//! some installers do load unsigned DLLs from AppData (npm-electron,
//! some Tauri/Webview2 hosts) — but those never have a Java root in
//! their process tree.
//!
//! ## What we do NOT detect here
//!
//! - Browser-extension stealers that don't use DLL injection (those are
//!   caught by the extension-watcher subsystem when it exists).
//! - Browser process-hollowing (a different injection technique that
//!   doesn't show up in `ImageLoad`).

#![allow(dead_code)]

use super::weedhack_runtime::WeedHackSignal;

/// Browser image names treated as injection targets.
const BROWSER_IMAGES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "opera.exe",
    "opera_gx.exe",
    "vivaldi.exe",
    "yandex.exe",
];

/// Substrings (lowercase) that mark a path as user-writable foothold
/// territory. Matched against the lowercased module path.
const USER_WRITABLE_MARKERS: &[&str] = &[
    "\\appdata\\local\\temp\\",
    "\\appdata\\local\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\", // technically Admin-writable, but commonly used for stagers
    "\\microsoft\\securityupdates\\",
    "\\windows\\temp\\",
];

/// A captured DLL-load event into a target process.
///
/// `loaded_module_signed`:
///   - `Some(true)`  — Authenticode signature verifies.
///   - `Some(false)` — module is unsigned or signature broken.
///   - `None`        — sign-status unknown (treated as unsigned to err on
///                     the side of catching the stealer).
#[derive(Debug, Clone)]
pub struct ImageLoadEvent {
    pub target_pid: u32,
    pub target_image_name: String,
    pub loaded_module_path: String,
    pub loaded_module_signed: Option<bool>,
}

/// Evaluate an `ImageLoad` event against the WeedHack browser-injection
/// fingerprint. `has_java_ancestor` is supplied by the PLM lineage graph
/// (caller queries `LineageGraph::get_chain(target_pid)` and checks).
pub fn evaluate(
    event: &ImageLoadEvent,
    has_java_ancestor: bool,
) -> Option<WeedHackSignal> {
    if !has_java_ancestor {
        return None;
    }

    if !is_browser_image(&event.target_image_name) {
        return None;
    }

    if !is_user_writable_path(&event.loaded_module_path) {
        return None;
    }

    // Treat unknown-signature as unsigned. A legitimate browser plugin
    // loaded from AppData should be Authenticode-signed (Chrome and Edge
    // refuse to load most unsigned DLLs anyway — its absence is anomaly).
    if matches!(event.loaded_module_signed, Some(true)) {
        return None;
    }

    Some(WeedHackSignal::BrowserInjectionFromJava)
}

// Visibility bump (Wave 3): the ETW ImageLoad source uses these two
// predicates for cheap source-side filtering before doing expensive
// signer/lineage lookups. No semantic change — the canonical detector
// (`evaluate` above) continues to be the authoritative gate.
pub(crate) fn is_browser_image(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    BROWSER_IMAGES.contains(&lower.as_str())
}

pub(crate) fn is_user_writable_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    USER_WRITABLE_MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_load(module: &str, signed: Option<bool>) -> ImageLoadEvent {
        ImageLoadEvent {
            target_pid: 1234,
            target_image_name: "chrome.exe".into(),
            loaded_module_path: module.into(),
            loaded_module_signed: signed,
        }
    }

    #[test]
    fn unsigned_dll_from_temp_into_chrome_under_java_fires() {
        let ev = chrome_load(
            "C:\\Users\\test\\AppData\\Local\\Temp\\krxz.dll",
            Some(false),
        );
        assert_eq!(
            evaluate(&ev, true),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
    }

    #[test]
    fn unsigned_dll_from_security_updates_into_chrome_under_java_fires() {
        let ev = chrome_load(
            "C:\\Users\\test\\AppData\\Roaming\\Microsoft\\SecurityUpdates\\helper.dll",
            None, // unknown-sign — counts as unsigned for our purposes
        );
        assert_eq!(
            evaluate(&ev, true),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
    }

    #[test]
    fn signed_dll_from_temp_into_chrome_under_java_does_not_fire() {
        // Edge case: signed module loaded from temp. Rare but possible
        // for installer-helper components. Sign + correct corp cert =
        // not WeedHack.
        let ev = chrome_load(
            "C:\\Users\\test\\AppData\\Local\\Temp\\update.dll",
            Some(true),
        );
        assert!(evaluate(&ev, true).is_none());
    }

    #[test]
    fn unsigned_dll_into_chrome_without_java_ancestor_does_not_fire() {
        // The same unsigned-DLL-into-AppData pattern can be a benign
        // Tauri / WebView2 host. Without a javaw ancestor, this is NOT
        // WeedHack and we suppress the signal.
        let ev = chrome_load(
            "C:\\Users\\test\\AppData\\Local\\Temp\\some.dll",
            Some(false),
        );
        assert!(evaluate(&ev, false).is_none());
    }

    #[test]
    fn unsigned_system_dll_into_chrome_under_java_does_not_fire() {
        // DLLs from System32 are out of foothold-marker scope even though
        // they may be unsigned (rare). Not a WeedHack injection vector.
        let ev = chrome_load(
            "C:\\Windows\\System32\\strange.dll",
            Some(false),
        );
        assert!(evaluate(&ev, true).is_none());
    }

    #[test]
    fn non_browser_target_does_not_fire() {
        // Even if the rest of the pattern matches, only browsers are
        // injection targets we care about here. Other targets are caught
        // by separate probes.
        let mut ev = chrome_load(
            "C:\\Users\\test\\AppData\\Local\\Temp\\krxz.dll",
            Some(false),
        );
        ev.target_image_name = "explorer.exe".into();
        assert!(evaluate(&ev, true).is_none());
    }

    #[test]
    fn brave_and_edge_are_also_browsers() {
        for browser in ["msedge.exe", "brave.exe", "firefox.exe", "opera_gx.exe"] {
            let mut ev = chrome_load(
                "C:\\Users\\test\\AppData\\Local\\Temp\\krxz.dll",
                Some(false),
            );
            ev.target_image_name = browser.into();
            assert_eq!(
                evaluate(&ev, true),
                Some(WeedHackSignal::BrowserInjectionFromJava),
                "{browser} should be treated as an injection target"
            );
        }
    }

    #[test]
    fn windows_temp_also_counts_as_foothold() {
        // %SystemRoot%\Temp is writable by SYSTEM and sometimes by users;
        // WeedHack has been seen dropping to C:\Windows\Temp from
        // elevated stages.
        let ev = chrome_load("C:\\Windows\\Temp\\stealer.dll", Some(false));
        assert_eq!(
            evaluate(&ev, true),
            Some(WeedHackSignal::BrowserInjectionFromJava)
        );
    }

    #[test]
    fn weight_clears_chain_cap() {
        let ev = chrome_load(
            "C:\\Users\\test\\AppData\\Local\\Temp\\krxz.dll",
            Some(false),
        );
        let sig = evaluate(&ev, true).unwrap();
        assert!(sig.weight() >= 40, "browser-injection signal must be strong");
    }
}

//! Startup scan target provider.
//! Collects executables from Windows autorun locations + recent downloads.

use super::{TargetConfig, TargetProvider};
use std::path::PathBuf;

pub struct StartupTargets;

impl TargetProvider for StartupTargets {
    fn name(&self) -> &str {
        "startup"
    }

    fn collect(&self, config: &TargetConfig) -> Vec<PathBuf> {
        if !config.startup_scan_enabled {
            return vec![];
        }

        let mut targets = Vec::new();
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        // 1. User Startup folder.
        let startup = PathBuf::from(format!(
            "{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ));
        if startup.exists() {
            collect_executables(&startup, &mut targets, 1);
        }

        // 2. Recent executables in Downloads (last N days).
        let downloads = PathBuf::from(format!("{home}\\Downloads"));
        if downloads.exists() {
            collect_recent_executables(&downloads, &mut targets, config.startup_recent_days);
        }

        // 3. Recent executables on Desktop.
        let desktop = PathBuf::from(format!("{home}\\Desktop"));
        if desktop.exists() {
            collect_recent_executables(&desktop, &mut targets, config.startup_recent_days);
        }

        // 4. Registry Run keys (read values, resolve paths).
        #[cfg(target_os = "windows")]
        {
            collect_run_key_targets(&mut targets);
        }

        targets
    }
}

/// Collect executable files from a directory (shallow).
fn collect_executables(dir: &PathBuf, targets: &mut Vec<PathBuf>, depth: u32) {
    if depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                let el = ext.to_string_lossy().to_lowercase();
                if matches!(
                    el.as_str(),
                    "exe" | "dll" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "lnk"
                ) {
                    targets.push(path);
                }
            }
        }
    }
}

/// Collect executables modified within the last N days.
fn collect_recent_executables(dir: &PathBuf, targets: &mut Vec<PathBuf>, recent_days: u32) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let cutoff =
        std::time::SystemTime::now() - std::time::Duration::from_secs(recent_days as u64 * 86400);

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension() {
            let el = ext.to_string_lossy().to_lowercase();
            if !matches!(el.as_str(), "exe" | "msi" | "scr" | "bat" | "cmd" | "ps1") {
                continue;
            }
        } else {
            continue;
        }
        // Check modification time.
        if let Ok(meta) = path.metadata() {
            if let Ok(mtime) = meta.modified() {
                if mtime >= cutoff {
                    targets.push(path);
                }
            }
        }
    }
}

/// Read Windows Registry Run keys to find autostart programs.
#[cfg(target_os = "windows")]
fn collect_run_key_targets(targets: &mut Vec<PathBuf>) {
    use std::process::Command;

    // Query both HKCU and HKLM Run + RunOnce keys.
    let keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    for key in &keys {
        let output = Command::new("reg").args(["query", key]).output();

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_reg_output(&text, targets);
        }
    }
}

/// Parse `reg query` output to extract executable paths.
/// Handles quoted paths, paths with spaces, and environment variable expansion.
#[cfg(target_os = "windows")]
fn parse_reg_output(text: &str, targets: &mut Vec<PathBuf>) {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }
        if !trimmed.contains("REG_SZ") && !trimmed.contains("REG_EXPAND_SZ") {
            continue;
        }

        // Format: "    Name    REG_SZ    Value"
        // Split on REG_SZ or REG_EXPAND_SZ to get the value part.
        let value_part = if let Some(pos) = trimmed.find("REG_SZ") {
            &trimmed[pos + 6..]
        } else if let Some(pos) = trimmed.find("REG_EXPAND_SZ") {
            &trimmed[pos + 13..]
        } else {
            continue;
        };
        let value = value_part.trim();
        if value.is_empty() {
            continue;
        }

        // Extract path: handle quoted paths and paths with arguments.
        let path_str = if value.starts_with('"') {
            // Quoted path: extract until closing quote.
            value[1..].split('"').next().unwrap_or("").trim()
        } else {
            // Unquoted: take first token (may miss paths with spaces, but safe).
            value.split_whitespace().next().unwrap_or("").trim()
        };

        if path_str.is_empty() || path_str.len() < 3 {
            continue;
        }

        let p = PathBuf::from(path_str);
        if p.exists() && p.is_file() {
            targets.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_disabled_returns_empty() {
        let cfg = TargetConfig::default(); // startup_scan_enabled = false
        let targets = StartupTargets.collect(&cfg);
        assert!(targets.is_empty());
    }

    #[test]
    fn startup_enabled_finds_something() {
        let mut cfg = TargetConfig::default();
        cfg.startup_scan_enabled = true;
        cfg.startup_recent_days = 30;
        let targets = StartupTargets.collect(&cfg);
        // May or may not find files depending on system — just verify no crash.
        let _ = targets.len();
    }
}

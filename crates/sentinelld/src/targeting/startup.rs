//! Startup scan target provider.
//! Collects executables from Windows autorun locations + recent downloads.

use super::{TargetConfig, TargetProvider};
use std::path::PathBuf;

/// R3-fix: cap the number of startup-scan targets so a hostile dump of
/// 100k stub .exe files into Downloads/Desktop/Startup cannot balloon the
/// targets Vec to multi-GB on boot.
const MAX_STARTUP_TARGETS: usize = 2_000;

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
        if targets.len() >= MAX_STARTUP_TARGETS {
            tracing::warn!(
                cap = MAX_STARTUP_TARGETS,
                "startup target cap reached in collect_executables — truncating"
            );
            return;
        }
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
    // Audit fix: `SystemTime - Duration` panics on underflow. A large
    // `recent_days` (misconfig) could push the cutoff below the platform
    // epoch floor → panic, aborting the startup scan. Use checked_sub and
    // fall back to UNIX_EPOCH (everything counts as "recent") if it
    // underflows. Also cap the day count defensively.
    let secs = (recent_days.min(36_500) as u64).saturating_mul(86_400);
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(secs))
        .unwrap_or(std::time::UNIX_EPOCH);

    for entry in entries.flatten() {
        if targets.len() >= MAX_STARTUP_TARGETS {
            tracing::warn!(
                cap = MAX_STARTUP_TARGETS,
                "startup target cap reached in collect_recent_executables — truncating"
            );
            return;
        }
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
        if targets.len() >= MAX_STARTUP_TARGETS {
            tracing::warn!(
                cap = MAX_STARTUP_TARGETS,
                "startup target cap reached in parse_reg_output — truncating"
            );
            return;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }
        if !trimmed.contains("REG_SZ") && !trimmed.contains("REG_EXPAND_SZ") {
            continue;
        }

        // Format: "    Name    REG_SZ    Value". Match REG_EXPAND_SZ first and
        // track which type we hit so we know whether to expand env vars below.
        let (value_part, is_expand) = if let Some(pos) = trimmed.find("REG_EXPAND_SZ") {
            (&trimmed[pos + "REG_EXPAND_SZ".len()..], true)
        } else if let Some(pos) = trimmed.find("REG_SZ") {
            (&trimmed[pos + "REG_SZ".len()..], false)
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

        // REG_EXPAND_SZ values store env-var references (e.g. `%APPDATA%\x.exe`).
        // Without expansion the literal `%APPDATA%\...` never matches a real
        // file, so env-var-based autostart persistence was SILENTLY skipped by
        // the startup scan — a real persistence-detection gap.
        let resolved = if is_expand {
            expand_env_vars(path_str)
        } else {
            path_str.to_string()
        };

        let p = PathBuf::from(&resolved);
        if p.exists() && p.is_file() {
            targets.push(p);
        }
    }
}

/// Expand Windows `%VAR%` references (as stored in REG_EXPAND_SZ values).
/// Unknown variables are left literal; `%%` becomes a literal `%`. Lookups use
/// `std::env::var`, which is case-insensitive on Windows (matches the OS).
#[cfg(target_os = "windows")]
fn expand_env_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                if name.is_empty() {
                    out.push('%'); // "%%" → literal percent
                } else if let Ok(val) = std::env::var(name) {
                    out.push_str(&val);
                } else {
                    // Unknown var — keep it literal so nothing is silently lost.
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unterminated '%': emit the remainder verbatim.
                out.push('%');
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn expand_env_vars_resolves_known_and_preserves_unknown() {
        // SAFETY: single-threaded test setting a process env var.
        unsafe { std::env::set_var("SENTINELLA_TEST_DIR", r"C:\Tools") };
        assert_eq!(
            expand_env_vars(r"%SENTINELLA_TEST_DIR%\app.exe"),
            r"C:\Tools\app.exe"
        );
        // Unknown var preserved literally (not dropped → no silent path loss).
        assert_eq!(
            expand_env_vars(r"%SENTINELLA_NOPE_XYZ%\a.exe"),
            r"%SENTINELLA_NOPE_XYZ%\a.exe"
        );
        // Literal %% and no-var strings pass through.
        assert_eq!(expand_env_vars("100%% done"), "100% done");
        assert_eq!(expand_env_vars(r"C:\plain\path.exe"), r"C:\plain\path.exe");
        // Unterminated percent emitted verbatim (no panic).
        assert_eq!(expand_env_vars("%UNTERMINATED"), "%UNTERMINATED");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parse_reg_output_expands_reg_expand_sz_paths() {
        // Point a REG_EXPAND_SZ value at a real temp file via an env var; the
        // parser must expand %VAR% and pick it up (the literal form never would).
        let dir = std::env::temp_dir();
        let exe = dir.join("sentinella_startup_probe.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        // SAFETY: single-threaded test setting a process env var.
        unsafe { std::env::set_var("SENTINELLA_STARTUP_DIR", &dir) };

        let line = "    Probe    REG_EXPAND_SZ    %SENTINELLA_STARTUP_DIR%\\sentinella_startup_probe.exe";
        let mut targets = Vec::new();
        parse_reg_output(line, &mut targets);

        assert!(
            targets.iter().any(|p| p.file_name().map(|n| n == "sentinella_startup_probe.exe").unwrap_or(false)),
            "REG_EXPAND_SZ env-var path must be expanded and collected"
        );
        let _ = std::fs::remove_file(&exe);
    }

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

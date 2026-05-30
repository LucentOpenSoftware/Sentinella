//! File deception detection — extension tricks, Unicode abuse, disguised executables.
//!
//! This layer focuses on social engineering at the file level: tricks that
//! make malicious files look like harmless documents to the user.

use crate::verdict::{Finding, Layer, Severity};

/// Executable file extensions that are dangerous when disguised.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsh", "wsf", "msi",
    "msp", "ps1", "reg",
];

/// Analyze a file path for deception techniques.
/// This runs even before reading file contents — pure path analysis.
pub fn analyze_path(path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // ── Suspicious path locations ──────────────────────────────
    let path_lower = path.to_lowercase();

    // Executables in temp directories deserve extra scrutiny.
    let in_temp = path_lower.contains("\\temp\\")
        || path_lower.contains("\\tmp\\")
        || path_lower.contains("/tmp/");

    let ext = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if in_temp && EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::Low,
            weight: 5,
            description: "Executable file in a temporary directory — common staging location for downloaded threats.".into(),
            technical_detail: Some(format!("Path: {path}")),
        });
    }

    // Executables in user Downloads directory.
    let in_downloads = path_lower.contains("\\downloads\\") || path_lower.contains("/downloads/");

    if in_downloads && EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
        // Informational only — very common for legitimate software too.
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::Info,
            weight: 0,
            description: "Executable found in Downloads directory.".into(),
            technical_detail: Some(format!("Path: {path}")),
        });
    }

    // ── Suspicious filename patterns ───────────────────────────

    let name_lower = name.to_lowercase();

    // Filenames mimicking system utilities.
    let system_mimics = [
        "svchost", "csrss", "lsass", "smss", "services", "winlogon", "explorer", "taskhost",
        "conhost",
    ];

    for mimic in system_mimics {
        if name_lower.starts_with(mimic)
            && !path_lower.contains("\\windows\\system32\\")
            && !path_lower.contains("\\windows\\syswow64\\")
            && EXECUTABLE_EXTENSIONS.contains(&ext.as_str())
        {
            findings.push(Finding {
                layer: Layer::FileDeception,
                severity: Severity::High,
                weight: 25,
                description: format!(
                    "Executable name mimics the Windows system process '{mimic}' but is located outside the System32 directory.",
                ),
                technical_detail: Some(format!("Name: {name} | Path: {path}")),
            });
            break;
        }
    }

    // Filenames with many whitespace chars before the real extension (hiding it).
    // Count any Unicode whitespace (tab, NBSP, U+2000-U+200B, etc) so attackers
    // can't bypass the heuristic with non-ASCII spacing.
    let ws_run = name
        .chars()
        .fold((0usize, 0usize), |(cur, max), c| {
            if c.is_whitespace() {
                let n = cur + 1;
                (n, max.max(n))
            } else {
                (0, max)
            }
        })
        .1;
    if ws_run >= 16 && EXECUTABLE_EXTENSIONS.contains(&ext.as_str()) {
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::High,
            weight: 20,
            description:
                "Filename uses excessive whitespace to hide the real file extension from the user."
                    .into(),
            technical_detail: Some(format!("Name: {name:?}")),
        });
    }

    findings
}

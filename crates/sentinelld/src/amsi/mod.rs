//! AMSI Runtime Integration — ASTRA runtime script inspection.
//!
//! Intercepts deobfuscated PowerShell, JScript, VBScript, and mshta
//! content via Windows AMSI (Antimalware Scan Interface) ETW events.
//!
//! Architecture: ETW consumer approach (not COM provider).
//! Windows logs AMSI scan events to ETW provider `{2A576B87-09A7-520E-C21A-4942F0271D67}`.
//! We consume these events to capture deobfuscated script content and
//! feed it through the ASTRA runtime analysis pipeline.
//!
//! This approach avoids COM DLL registration complexity while still
//! capturing runtime-deobfuscated content from PowerShell, cscript, etc.

#[allow(dead_code)]
pub mod ps_bridge;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Serialize;

/// AMSI runtime inspection state (reserved for future COM provider).
#[allow(dead_code)]
pub struct AmsiMonitor {
    running: Arc<AtomicBool>,
    diagnostics: Arc<AmsiDiagnostics>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

/// Runtime scan diagnostics — atomic, lock-free.
#[derive(Default)]
pub struct AmsiDiagnostics {
    pub buffers_seen: AtomicU64,
    pub buffers_scanned: AtomicU64,
    pub buffers_suspicious: AtomicU64,
    pub buffers_blocked: AtomicU64,
    pub powershell_buffers: AtomicU64,
    pub jscript_buffers: AtomicU64,
    pub vbscript_buffers: AtomicU64,
    pub other_buffers: AtomicU64,
    pub avg_scan_us: AtomicU64,
    pub runtime_timeouts: AtomicU64,
    pub scan_errors: AtomicU64,
}

impl AmsiDiagnostics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "buffers_seen": self.buffers_seen.load(Ordering::Relaxed),
            "buffers_scanned": self.buffers_scanned.load(Ordering::Relaxed),
            "buffers_suspicious": self.buffers_suspicious.load(Ordering::Relaxed),
            "buffers_blocked": self.buffers_blocked.load(Ordering::Relaxed),
            "powershell_buffers": self.powershell_buffers.load(Ordering::Relaxed),
            "jscript_buffers": self.jscript_buffers.load(Ordering::Relaxed),
            "vbscript_buffers": self.vbscript_buffers.load(Ordering::Relaxed),
            "other_buffers": self.other_buffers.load(Ordering::Relaxed),
            "avg_scan_us": self.avg_scan_us.load(Ordering::Relaxed),
            "runtime_timeouts": self.runtime_timeouts.load(Ordering::Relaxed),
            "scan_errors": self.scan_errors.load(Ordering::Relaxed),
        })
    }
}

/// A captured runtime script buffer from AMSI.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeBuffer {
    /// Source application (e.g., "powershell.exe", "cscript.exe").
    pub source_app: String,
    /// Process ID of the source.
    pub source_pid: u32,
    /// Content name/identifier from AMSI.
    pub content_name: String,
    /// Script language detected.
    pub language: ScriptLanguage,
    /// The deobfuscated content (bounded).
    pub content: Vec<u8>,
    /// Content size before truncation.
    pub original_size: usize,
    /// Timestamp (unix seconds).
    pub timestamp: i64,
}

/// Script language classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptLanguage {
    PowerShell,
    JScript,
    VBScript,
    Mshta,
    DotNet,
    Other,
}

impl ScriptLanguage {
    pub fn from_app_name(app: &str) -> Self {
        let lower = app.to_lowercase();
        if lower.contains("powershell") {
            Self::PowerShell
        } else if lower.contains("cscript") || lower.contains("wscript") {
            // Ambiguous — could be JS or VBS. Default to JScript.
            Self::JScript
        } else if lower.contains("mshta") {
            Self::Mshta
        } else if lower.contains("dotnet") || lower.contains("clr") {
            Self::DotNet
        } else {
            Self::Other
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::PowerShell => "PowerShell",
            Self::JScript => "JScript",
            Self::VBScript => "VBScript",
            Self::Mshta => "mshta",
            Self::DotNet => ".NET",
            Self::Other => "Other",
        }
    }
}

/// Result of scanning a runtime buffer.
#[derive(Debug, Clone)]
pub struct RuntimeScanResult {
    /// Findings from YARA/heuristic analysis of the buffer content.
    pub findings: Vec<argus::Finding>,
    /// ARGUS score for this buffer.
    pub score: u32,
    /// Whether the buffer should be blocked (high-confidence malicious).
    pub should_block: bool,
    /// Scan duration in microseconds.
    pub scan_duration_us: u64,
}

/// Max buffer size to accept for runtime scanning (1 MB).
const MAX_RUNTIME_BUFFER: usize = 1024 * 1024;

/// Scan a runtime buffer through the ASTRA runtime profile.
///
/// Uses a special runtime profile: YARA-heavy, no PE heuristics,
/// no archive parsing, extremely bounded.
pub fn scan_runtime_buffer(
    buffer: &RuntimeBuffer,
    engine: &argus::ArgusEngine,
) -> RuntimeScanResult {
    let start = std::time::Instant::now();

    // Truncate to max size.
    let content = if buffer.content.len() > MAX_RUNTIME_BUFFER {
        &buffer.content[..MAX_RUNTIME_BUFFER]
    } else {
        &buffer.content
    };

    if content.is_empty() {
        return RuntimeScanResult {
            findings: vec![],
            score: 0,
            should_block: false,
            scan_duration_us: 0,
        };
    }

    // Feed to ARGUS buffer analysis (YARA + pattern matching).
    let name = format!("amsi://{}:{}", buffer.source_app, buffer.content_name);
    let verdict = engine.analyze_buffer(&name, content);

    let elapsed = start.elapsed().as_micros() as u64;

    // High-confidence blocking: only for very high scores from runtime content.
    // Runtime content is deobfuscated → signals are stronger → lower threshold OK.
    let should_block = verdict.score >= 80;

    RuntimeScanResult {
        findings: verdict.findings,
        score: verdict.score,
        should_block,
        scan_duration_us: elapsed,
    }
}

/// Runtime scan profile — extremely bounded, YARA-heavy.
pub fn runtime_profile() -> argus::profile::ScanProfile {
    argus::profile::ScanProfile {
        kind: argus::profile::ProfileKind::Realtime, // Reuses realtime kind for now.
        budget: argus::budget::ScanExecutionBudget {
            max_duration: std::time::Duration::from_secs(2),
            max_clamav_duration: std::time::Duration::from_millis(500),
            max_yara_duration: std::time::Duration::from_secs(1),
            max_structural_duration: std::time::Duration::from_millis(100),
            max_archive_depth: 0, // No archive parsing for runtime buffers.
            max_extracted_bytes: 0,
            max_yara_matches: 30,
        },
        yara_enabled: true,
        yara_max_matches: 30,
        pe_heuristics_enabled: false, // Runtime buffers are not PE files.
        reputation_enabled: false,
        context_enabled: false,
        ioc_enabled: true, // Hash matching still useful.
        packer_detection_enabled: false,
        convergence_threshold: 20, // Lower threshold — deobfuscated content is cleaner signal.
        quarantine_threshold: 80,
        max_archive_depth: 0,
        max_extracted_bytes: 0,
        downgrade_transient: false,
        pe_min_size_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_language_detection() {
        assert_eq!(
            ScriptLanguage::from_app_name("powershell.exe"),
            ScriptLanguage::PowerShell
        );
        assert_eq!(
            ScriptLanguage::from_app_name(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            ),
            ScriptLanguage::PowerShell
        );
        assert_eq!(
            ScriptLanguage::from_app_name("cscript.exe"),
            ScriptLanguage::JScript
        );
        assert_eq!(
            ScriptLanguage::from_app_name("mshta.exe"),
            ScriptLanguage::Mshta
        );
        assert_eq!(
            ScriptLanguage::from_app_name("notepad.exe"),
            ScriptLanguage::Other
        );
    }

    #[test]
    fn runtime_profile_is_bounded() {
        let profile = runtime_profile();
        assert!(profile.budget.max_duration.as_secs() <= 2);
        assert!(!profile.pe_heuristics_enabled);
        assert!(!profile.reputation_enabled);
        assert!(profile.yara_enabled);
        assert_eq!(profile.max_archive_depth, 0);
    }

    #[test]
    fn empty_buffer_returns_clean() {
        let engine = argus::ArgusEngine::with_defaults();
        let buf = RuntimeBuffer {
            source_app: "powershell.exe".into(),
            source_pid: 1234,
            content_name: "test".into(),
            language: ScriptLanguage::PowerShell,
            content: vec![],
            original_size: 0,
            timestamp: 0,
        };
        let result = scan_runtime_buffer(&buf, &engine);
        assert_eq!(result.score, 0);
        assert!(!result.should_block);
    }

    #[test]
    fn diagnostics_json() {
        let d = AmsiDiagnostics::new();
        d.buffers_seen.store(42, Ordering::Relaxed);
        let j = d.to_json();
        assert_eq!(j["buffers_seen"], 42);
    }

    #[test]
    fn benign_powershell_scores_low() {
        let engine = argus::ArgusEngine::with_defaults();
        let buf = RuntimeBuffer {
            source_app: "powershell.exe".into(),
            source_pid: 1234,
            content_name: "benign.ps1".into(),
            language: ScriptLanguage::PowerShell,
            content: b"Write-Host 'Hello World'\nGet-Date\nGet-Process | Format-Table".to_vec(),
            original_size: 60,
            timestamp: chrono::Utc::now().timestamp(),
        };
        let result = scan_runtime_buffer(&buf, &engine);
        // Benign PowerShell should not trigger high scores.
        assert!(result.score < 50, "benign PS scored {}", result.score);
        assert!(!result.should_block);
    }

    #[test]
    fn runtime_scan_respects_max_buffer() {
        let engine = argus::ArgusEngine::with_defaults();
        let large_content = vec![b'A'; MAX_RUNTIME_BUFFER + 1000];
        let buf = RuntimeBuffer {
            source_app: "powershell.exe".into(),
            source_pid: 0,
            content_name: "large".into(),
            language: ScriptLanguage::PowerShell,
            content: large_content,
            original_size: MAX_RUNTIME_BUFFER + 1000,
            timestamp: 0,
        };
        // Should not panic, should truncate to MAX_RUNTIME_BUFFER.
        let result = scan_runtime_buffer(&buf, &engine);
        assert!(result.scan_duration_us > 0 || result.score == 0);
    }

    #[test]
    fn language_labels() {
        assert_eq!(ScriptLanguage::PowerShell.label(), "PowerShell");
        assert_eq!(ScriptLanguage::JScript.label(), "JScript");
        assert_eq!(ScriptLanguage::VBScript.label(), "VBScript");
        assert_eq!(ScriptLanguage::Mshta.label(), "mshta");
        assert_eq!(ScriptLanguage::DotNet.label(), ".NET");
        assert_eq!(ScriptLanguage::Other.label(), "Other");
    }
}

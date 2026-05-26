//! NTFS Alternate Data Stream (ADS) scanning — ASTRA adaptive analysis.
//!
//! Files on NTFS can contain hidden data streams beyond the default `:$DATA`.
//! Malware uses ADS to hide payloads: `file.txt:hidden.ps1:$DATA`.
//!
//! This module enumerates non-default streams, reads their content, and feeds
//! it through the normal ARGUS analysis pipeline. Profile-aware: realtime
//! scans only executable/script streams, manual scans everything.

#![allow(dead_code)]

#[cfg(target_os = "windows")]
use std::path::Path;

use std::sync::atomic::AtomicU64;

/// Max ADS content size to read for analysis (10 MB).
const MAX_ADS_CONTENT_SIZE: u64 = 10 * 1024 * 1024;

/// Max number of ADS streams to process per file.
const MAX_STREAMS_PER_FILE: usize = 16;

/// An alternate data stream attached to a file.
#[derive(Debug, Clone)]
pub struct AlternateStream {
    /// Full path including stream name: `C:\path\file.txt:hidden.ps1`
    pub full_path: String,
    /// Stream name only (e.g., `hidden.ps1`).
    pub stream_name: String,
    /// Stream size in bytes.
    pub size: u64,
    /// Whether this stream has a suspicious name (executable/script extension).
    pub suspicious: bool,
}

/// Result of scanning an ADS stream's content.
#[derive(Debug, Clone)]
pub struct AdsContentResult {
    /// The stream metadata.
    pub stream: AlternateStream,
    /// ARGUS findings from content analysis (may be empty).
    pub content_findings: Vec<argus::Finding>,
    /// Whether ClamAV flagged the stream content.
    pub clamav_infected: bool,
    /// ClamAV virus name if infected.
    pub clamav_virus_name: Option<String>,
    /// Whether content was actually read and analyzed.
    pub content_scanned: bool,
    /// Reason content was not scanned (if applicable).
    pub skip_reason: Option<String>,
}

/// ADS scan policy — what to look for based on profile.
#[derive(Debug, Clone, Copy)]
pub enum AdsScanPolicy {
    /// Only scan streams with executable/script extensions.
    ExecutableOnly,
    /// Scan all non-default streams.
    All,
    /// Skip ADS scanning entirely.
    Disabled,
}

/// ADS diagnostics counters — atomic, lock-free.
pub struct AdsDiagnostics {
    pub files_with_ads: AtomicU64,
    pub streams_seen: AtomicU64,
    pub streams_scanned: AtomicU64,
    pub streams_skipped_by_profile: AtomicU64,
    pub suspicious_stream_names: AtomicU64,
    pub malicious_streams: AtomicU64,
    pub ads_scan_errors: AtomicU64,
    pub ads_timeouts: AtomicU64,
}

impl AdsDiagnostics {
    pub fn new() -> Self {
        use std::sync::atomic::AtomicU64;
        Self {
            files_with_ads: AtomicU64::new(0),
            streams_seen: AtomicU64::new(0),
            streams_scanned: AtomicU64::new(0),
            streams_skipped_by_profile: AtomicU64::new(0),
            suspicious_stream_names: AtomicU64::new(0),
            malicious_streams: AtomicU64::new(0),
            ads_scan_errors: AtomicU64::new(0),
            ads_timeouts: AtomicU64::new(0),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        serde_json::json!({
            "files_with_ads": self.files_with_ads.load(Ordering::Relaxed),
            "streams_seen": self.streams_seen.load(Ordering::Relaxed),
            "streams_scanned": self.streams_scanned.load(Ordering::Relaxed),
            "streams_skipped_by_profile": self.streams_skipped_by_profile.load(Ordering::Relaxed),
            "suspicious_stream_names": self.suspicious_stream_names.load(Ordering::Relaxed),
            "malicious_streams": self.malicious_streams.load(Ordering::Relaxed),
            "ads_scan_errors": self.ads_scan_errors.load(Ordering::Relaxed),
            "ads_timeouts": self.ads_timeouts.load(Ordering::Relaxed),
        })
    }
}

/// Enumerate alternate data streams on a file.
/// Returns non-default streams (excludes the primary `::$DATA` stream).
#[cfg(target_os = "windows")]
pub fn enumerate_ads(path: &Path) -> Vec<AlternateStream> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        WIN32_FIND_STREAM_DATA,
    };

    let mut streams = Vec::new();

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

    let handle = unsafe {
        FindFirstStreamW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut std::ffi::c_void,
            0,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => h,
        _ => return streams,
    };

    loop {
        if streams.len() >= MAX_STREAMS_PER_FILE {
            break;
        }

        let stream_name = wide_to_string(&data.cStreamName);

        // Skip the default data stream (::$DATA).
        if !stream_name.is_empty() && stream_name != "::$DATA" {
            let name = extract_stream_name(&stream_name);
            let size = data.StreamSize as u64;

            if !name.is_empty() && size > 0 {
                let full = format!("{}:{}", path.display(), name);
                let suspicious = is_suspicious_stream_name(&name);
                streams.push(AlternateStream {
                    full_path: full,
                    stream_name: name,
                    size,
                    suspicious,
                });
            }
        }

        let ok = unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut std::ffi::c_void) };
        if ok.is_err() {
            break;
        }
    }

    unsafe {
        let _ = FindClose(handle);
    }

    streams
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_ads(_path: &std::path::Path) -> Vec<AlternateStream> {
    Vec::new()
}

/// Read ADS stream content for analysis.
/// Opens the stream via `file.txt:streamname` path syntax.
/// Returns content bytes, capped at MAX_ADS_CONTENT_SIZE.
#[cfg(target_os = "windows")]
pub fn read_ads_content(stream: &AlternateStream) -> Result<Vec<u8>, String> {
    use std::io::Read;

    if stream.size > MAX_ADS_CONTENT_SIZE {
        return Err(format!(
            "ADS too large: {} bytes (max {})",
            stream.size, MAX_ADS_CONTENT_SIZE
        ));
    }

    let file = std::fs::File::open(&stream.full_path)
        .map_err(|e| format!("cannot open ADS '{}': {e}", stream.full_path))?;

    let mut buf = Vec::with_capacity(stream.size.min(MAX_ADS_CONTENT_SIZE) as usize);
    file.take(MAX_ADS_CONTENT_SIZE)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read ADS '{}': {e}", stream.full_path))?;

    Ok(buf)
}

#[cfg(not(target_os = "windows"))]
pub fn read_ads_content(_stream: &AlternateStream) -> Result<Vec<u8>, String> {
    Err("ADS not available on this platform".into())
}

/// Scan a single ADS stream: read content → feed to ARGUS buffer analysis.
/// Returns content findings that should be added to the parent file's verdict.
pub fn scan_ads_content(
    stream: &AlternateStream,
    argus_engine: &argus::ArgusEngine,
) -> AdsContentResult {
    // Try to read content.
    let content = match read_ads_content(stream) {
        Ok(data) => data,
        Err(reason) => {
            return AdsContentResult {
                stream: stream.clone(),
                content_findings: vec![ads_metadata_finding(stream)],
                clamav_infected: false,
                clamav_virus_name: None,
                content_scanned: false,
                skip_reason: Some(reason),
            };
        }
    };

    if content.is_empty() {
        return AdsContentResult {
            stream: stream.clone(),
            content_findings: vec![ads_metadata_finding(stream)],
            clamav_infected: false,
            clamav_virus_name: None,
            content_scanned: false,
            skip_reason: Some("empty content".into()),
        };
    }

    // Feed content to ARGUS buffer analysis.
    let verdict = argus_engine.analyze_buffer(&stream.stream_name, &content);
    let mut findings = Vec::new();

    // Add metadata finding (stream name analysis).
    findings.push(ads_metadata_finding(stream));

    // Add content findings from ARGUS, tagged as ADS-sourced.
    for mut f in verdict.findings {
        f.description = format!("[ADS:{}] {}", stream.stream_name, f.description);
        f.technical_detail = Some(format!(
            "Source: ADS stream '{}' on parent file. {}",
            stream.stream_name,
            f.technical_detail.unwrap_or_default()
        ));
        findings.push(f);
    }

    AdsContentResult {
        stream: stream.clone(),
        content_findings: findings,
        clamav_infected: false, // ClamAV integration done at caller level if needed.
        clamav_virus_name: None,
        content_scanned: true,
        skip_reason: None,
    }
}

/// Create a metadata-only finding for a detected ADS.
/// Severity tuned: name alone = Medium, not High.
pub fn ads_metadata_finding(stream: &AlternateStream) -> argus::Finding {
    // Phase 6 severity tuning: suspicious NAME = Medium, not High.
    // Content findings from ARGUS carry their own severity.
    let (weight, severity) = if stream.suspicious {
        (8, argus::verdict::Severity::Medium)
    } else {
        (3, argus::verdict::Severity::Low)
    };

    let desc = if stream.suspicious {
        format!(
            "Alternate data stream with executable name: '{}' ({} bytes)",
            stream.stream_name, stream.size
        )
    } else {
        format!(
            "Non-default alternate data stream: '{}' ({} bytes)",
            stream.stream_name, stream.size
        )
    };

    argus::Finding {
        layer: argus::verdict::Layer::AlternateDataStream,
        severity,
        weight,
        description: desc,
        technical_detail: Some(stream.full_path.clone()),
    }
}

// Keep old name as alias for callers not yet updated.
pub fn ads_finding(stream: &AlternateStream) -> argus::Finding {
    ads_metadata_finding(stream)
}

/// Check if a stream name suggests executable/script content.
fn is_suspicious_stream_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "exe"
            | "dll"
            | "scr"
            | "com"
            | "pif"
            | "sys"
            | "bat"
            | "cmd"
            | "ps1"
            | "vbs"
            | "js"
            | "wsh"
            | "wsf"
            | "hta"
            | "msi"
            | "reg"
            | "lnk"
            | "inf"
            | "sct"
            | "wsc"
    )
}

/// Extract stream name from NTFS format `:name:$DATA` → `name`.
fn extract_stream_name(raw: &str) -> String {
    let trimmed = raw.trim_start_matches(':');
    if let Some(pos) = trimmed.find(':') {
        trimmed[..pos].to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(target_os = "windows")]
fn wide_to_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// Determine ADS scan policy based on profile.
pub fn ads_policy_for_profile(profile: &argus::profile::ScanProfile) -> AdsScanPolicy {
    match profile.kind {
        argus::profile::ProfileKind::Realtime => AdsScanPolicy::ExecutableOnly,
        argus::profile::ProfileKind::Manual => AdsScanPolicy::All,
        argus::profile::ProfileKind::Idle => AdsScanPolicy::All,
        argus::profile::ProfileKind::Startup => AdsScanPolicy::ExecutableOnly,
        argus::profile::ProfileKind::Archive => AdsScanPolicy::Disabled,
        argus::profile::ProfileKind::Document => AdsScanPolicy::Disabled,
    }
}

/// Filter streams based on scan policy.
pub fn filter_streams(
    streams: Vec<AlternateStream>,
    policy: AdsScanPolicy,
) -> Vec<AlternateStream> {
    match policy {
        AdsScanPolicy::Disabled => vec![],
        AdsScanPolicy::All => streams,
        AdsScanPolicy::ExecutableOnly => streams.into_iter().filter(|s| s.suspicious).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_stream_name_standard() {
        assert_eq!(extract_stream_name(":hidden.ps1:$DATA"), "hidden.ps1");
    }

    #[test]
    fn extract_stream_name_no_data_suffix() {
        assert_eq!(extract_stream_name(":payload"), "payload");
    }

    #[test]
    fn suspicious_extensions() {
        assert!(is_suspicious_stream_name("payload.exe"));
        assert!(is_suspicious_stream_name("hidden.ps1"));
        assert!(is_suspicious_stream_name("script.vbs"));
        assert!(!is_suspicious_stream_name("notes.txt"));
        assert!(!is_suspicious_stream_name("data.json"));
    }

    #[test]
    fn filter_executable_only() {
        let streams = vec![
            AlternateStream {
                full_path: "a:b.exe".into(),
                stream_name: "b.exe".into(),
                size: 100,
                suspicious: true,
            },
            AlternateStream {
                full_path: "a:c.txt".into(),
                stream_name: "c.txt".into(),
                size: 50,
                suspicious: false,
            },
        ];
        let filtered = filter_streams(streams, AdsScanPolicy::ExecutableOnly);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn filter_all_keeps_everything() {
        let streams = vec![
            AlternateStream {
                full_path: "a:b.exe".into(),
                stream_name: "b.exe".into(),
                size: 100,
                suspicious: true,
            },
            AlternateStream {
                full_path: "a:c.txt".into(),
                stream_name: "c.txt".into(),
                size: 50,
                suspicious: false,
            },
        ];
        let filtered = filter_streams(streams, AdsScanPolicy::All);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_disabled_returns_empty() {
        let streams = vec![AlternateStream {
            full_path: "a:b.exe".into(),
            stream_name: "b.exe".into(),
            size: 100,
            suspicious: true,
        }];
        let filtered = filter_streams(streams, AdsScanPolicy::Disabled);
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn policy_for_profiles() {
        assert!(matches!(
            ads_policy_for_profile(&argus::profile::ScanProfile::realtime()),
            AdsScanPolicy::ExecutableOnly
        ));
        assert!(matches!(
            ads_policy_for_profile(&argus::profile::ScanProfile::manual()),
            AdsScanPolicy::All
        ));
        assert!(matches!(
            ads_policy_for_profile(&argus::profile::ScanProfile::archive()),
            AdsScanPolicy::Disabled
        ));
    }

    #[test]
    fn metadata_finding_severity_tuned() {
        let suspicious = AlternateStream {
            full_path: "test:evil.ps1".into(),
            stream_name: "evil.ps1".into(),
            size: 100,
            suspicious: true,
        };
        let finding = ads_metadata_finding(&suspicious);
        // Phase 6: suspicious NAME = Medium, not High.
        assert_eq!(finding.severity, argus::verdict::Severity::Medium);
        assert_eq!(finding.weight, 8);

        let benign = AlternateStream {
            full_path: "test:notes.txt".into(),
            stream_name: "notes.txt".into(),
            size: 50,
            suspicious: false,
        };
        let finding = ads_metadata_finding(&benign);
        assert_eq!(finding.severity, argus::verdict::Severity::Low);
        assert_eq!(finding.weight, 3);
    }

    #[test]
    fn diagnostics_json() {
        let d = AdsDiagnostics::new();
        let j = d.to_json();
        assert_eq!(j["files_with_ads"], 0);
        assert_eq!(j["streams_scanned"], 0);
    }
}

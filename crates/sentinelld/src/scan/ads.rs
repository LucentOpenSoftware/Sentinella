//! NTFS Alternate Data Stream (ADS) scanning.
//!
//! Files on NTFS can contain hidden data streams beyond the default `:$DATA`.
//! Malware uses ADS to hide payloads: `file.txt:hidden.ps1:$DATA`.
//!
//! This module enumerates non-default streams and returns those that
//! match suspicious patterns (executable/script content in ADS).

#![allow(dead_code)]

#[cfg(target_os = "windows")]
use std::path::Path;

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
        let stream_name = wide_to_string(&data.cStreamName);

        // Skip the default data stream (::$DATA).
        if !stream_name.is_empty() && stream_name != "::$DATA" {
            // Stream names look like `:hidden.ps1:$DATA`
            // Extract the name part between the first and second colon.
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
    // ADS is NTFS-only. Other platforms: no streams.
    Vec::new()
}

/// Check if a stream name suggests executable/script content.
fn is_suspicious_stream_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "exe" | "dll" | "scr" | "com" | "pif" | "sys"
            | "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsh" | "wsf"
            | "hta" | "msi" | "reg"
            | "lnk" | "inf" | "sct" | "wsc"
    )
}

/// Extract stream name from NTFS format `:name:$DATA` → `name`.
fn extract_stream_name(raw: &str) -> String {
    // Format: `:streamname:$DATA`
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
pub fn filter_streams(streams: Vec<AlternateStream>, policy: AdsScanPolicy) -> Vec<AlternateStream> {
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
    fn extract_stream_name_default_stream() {
        // Default stream is "::$DATA" → after trim_start(':') = ":$DATA" → pos=0 → empty
        let name = extract_stream_name("::$DATA");
        // This returns "$DATA" which is fine — we filter default stream by full name check above.
        assert!(!name.is_empty());
    }

    #[test]
    fn suspicious_extensions() {
        assert!(is_suspicious_stream_name("payload.exe"));
        assert!(is_suspicious_stream_name("hidden.ps1"));
        assert!(is_suspicious_stream_name("script.vbs"));
        assert!(is_suspicious_stream_name("evil.bat"));
        assert!(!is_suspicious_stream_name("notes.txt"));
        assert!(!is_suspicious_stream_name("data.json"));
        assert!(!is_suspicious_stream_name("image.png"));
    }

    #[test]
    fn filter_executable_only() {
        let streams = vec![
            AlternateStream { full_path: "a:b.exe".into(), stream_name: "b.exe".into(), size: 100, suspicious: true },
            AlternateStream { full_path: "a:c.txt".into(), stream_name: "c.txt".into(), size: 50, suspicious: false },
        ];
        let filtered = filter_streams(streams, AdsScanPolicy::ExecutableOnly);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].stream_name, "b.exe");
    }

    #[test]
    fn filter_all_keeps_everything() {
        let streams = vec![
            AlternateStream { full_path: "a:b.exe".into(), stream_name: "b.exe".into(), size: 100, suspicious: true },
            AlternateStream { full_path: "a:c.txt".into(), stream_name: "c.txt".into(), size: 50, suspicious: false },
        ];
        let filtered = filter_streams(streams, AdsScanPolicy::All);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_disabled_returns_empty() {
        let streams = vec![
            AlternateStream { full_path: "a:b.exe".into(), stream_name: "b.exe".into(), size: 100, suspicious: true },
        ];
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
}

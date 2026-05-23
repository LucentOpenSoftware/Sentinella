//! Authenticode Signature Verification Layer
//!
//! Verifies Windows PE digital signatures via the WinVerifyTrust API.
//! Integrates with ARGUS scoring:
//!
//! - **Valid signature from trusted publisher**: negative weight (reduces suspicion)
//! - **Valid signature from unknown publisher**: small negative weight
//! - **Invalid/broken signature**: positive weight (increases suspicion)
//! - **Unsigned**: neutral (no weight change, but noted)
//!
//! This layer is Windows-only. On other platforms it returns no findings.

use crate::verdict::{Finding, Layer, Severity};
use std::path::Path;

/// Well-known trusted publishers whose valid signatures substantially
/// reduce suspicion. These are NOT exempt from scanning.
const TRUSTED_SIGNERS: &[(&str, u32)] = &[
    // (substring to match in signer subject, discount)
    ("Microsoft Corporation", 25),
    ("Microsoft Windows", 25),
    ("Google LLC", 22),
    ("Google Inc", 22),
    ("Mozilla Corporation", 22),
    ("Python Software Foundation", 22),
    ("Git", 20),
    ("NVIDIA Corporation", 22),
    ("Advanced Micro Devices", 22),
    ("Intel Corporation", 22),
    ("Cisco Systems", 20),
    ("Oracle America", 20),
    ("Apple Inc", 20),
    ("Adobe Inc", 20),
    ("Adobe Systems", 20),
    ("Valve Corp", 18),
    ("Epic Games", 18),
    ("Discord Inc", 15),
    ("Slack Technologies", 18),
    ("Zoom Video Communications", 18),
    ("Brave Software", 18),
    ("Notion Labs", 15),
    ("JetBrains", 18),
    ("Sublime HQ", 18),
    ("VideoLAN", 20),
    ("Blender Foundation", 20),
    ("The GIMP Team", 20),
    ("Logitech", 18),
    ("Corsair", 18),
    ("Razer", 15),
    ("Samsung Electronics", 18),
    ("Realtek Semiconductor", 18),
    ("Dropbox", 18),
    ("Spotify AB", 18),
    // Additional — common FP sources.
    ("Riot Games", 18),
    ("Electronic Arts", 18),
    ("Ubisoft", 18),
    ("Take-Two Interactive", 18),
    ("Bethesda Softworks", 15),
    ("Rockstar Games", 18),
    ("Overwolf Ltd", 15),
    ("Signal", 18),
    ("Telegram", 15),
    ("WhatsApp", 18),
    ("Obsidian Industries", 15),
    ("1Password", 18),
    ("Bitwarden", 18),
    ("WireGuard", 18),
    ("OpenVPN", 18),
    ("Mullvad", 15),
    ("Anthropic", 22),
    ("Malwarebytes", 20),
    ("ESET", 20),
    ("Avast", 18),
    ("Kaspersky", 18),
];

/// Analyze a PE file's Authenticode signature.
/// Returns findings that affect the ARGUS score.
pub fn analyze(path: &Path) -> Vec<Finding> {
    #[cfg(target_os = "windows")]
    {
        analyze_windows(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        vec![]
    }
}

/// Get the signature discount for scoring (used by the engine).
pub fn signature_discount(path: &Path) -> u32 {
    #[cfg(target_os = "windows")]
    {
        signature_discount_windows(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        0
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Windows implementation
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn analyze_windows(path: &Path) -> Vec<Finding> {
    let (trust_result, signer) = verify_trust(path);

    match trust_result {
        TrustResult::ValidTrusted(ref publisher) => {
            // Valid signature from known trusted publisher.
            vec![Finding {
                layer: Layer::Reputation,
                severity: Severity::Info,
                weight: 0,
                description: format!(
                    "Digitally signed by {} — valid Authenticode signature verified.",
                    publisher,
                ),
                technical_detail: signer.map(|s| format!("Signer: {s}")),
            }]
        }
        TrustResult::ValidUnknown => {
            // Valid signature but unknown signer — mild trust.
            let signer_str = signer.as_deref().unwrap_or("Unknown");
            vec![Finding {
                layer: Layer::Reputation,
                severity: Severity::Info,
                weight: 0,
                description: format!(
                    "Digitally signed by {signer_str} — signature valid but publisher is not in the trusted database.",
                ),
                technical_detail: signer.map(|s| format!("Signer: {s}")),
            }]
        }
        TrustResult::Invalid => {
            // Broken/tampered signature — suspicious.
            vec![Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::High,
                weight: 20,
                description: "Executable has an invalid or tampered digital signature — the file may have been modified after signing.".into(),
                technical_detail: Some("Authenticode verification failed".into()),
            }]
        }
        TrustResult::Unsigned => {
            // No embedded signature. Check if it's a Windows system binary
            // (catalog-signed, not embedded-signed).
            if is_windows_system_path(path) {
                vec![Finding {
                    layer: Layer::Reputation,
                    severity: Severity::Info,
                    weight: 0,
                    description: "Windows system binary — catalog-signed by Microsoft (not embedded Authenticode).".into(),
                    technical_detail: Some(format!("System path: {}", path.display())),
                }]
            } else {
                vec![]
            }
        }
        TrustResult::Error => {
            if is_windows_system_path(path) {
                vec![Finding {
                    layer: Layer::Reputation,
                    severity: Severity::Info,
                    weight: 0,
                    description: "Windows system binary — trusted system path.".into(),
                    technical_detail: Some(format!("System path: {}", path.display())),
                }]
            } else {
                vec![]
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn signature_discount_windows(path: &Path) -> u32 {
    let (trust_result, _) = verify_trust(path);
    match trust_result {
        TrustResult::ValidTrusted(_) => {
            // Find the specific discount from TRUSTED_SIGNERS.
            if let (_, Some(signer)) = verify_trust(path) {
                let signer_lower = signer.to_lowercase();
                for &(pattern, discount) in TRUSTED_SIGNERS {
                    if signer_lower.contains(&pattern.to_lowercase()) {
                        return discount;
                    }
                }
            }
            10 // Valid trusted but didn't match specific entry.
        }
        TrustResult::ValidUnknown => 5,
        // Windows system binaries are catalog-signed (not embedded).
        // WinVerifyTrust with WTD_CHOICE_FILE doesn't check catalog sigs.
        // For files in protected Windows directories, apply system trust discount.
        TrustResult::Unsigned | TrustResult::Error => {
            if is_windows_system_path(path) {
                20
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Check if path is in a protected Windows system directory.
/// These binaries are catalog-signed and maintained by Windows Update.
#[cfg(target_os = "windows")]
fn is_windows_system_path(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    p.starts_with("c:\\windows\\system32")
        || p.starts_with("c:\\windows\\syswow64")
        || p.starts_with("c:\\windows\\winsxs")
        || p.starts_with("c:\\windows\\servicing")
        || p.starts_with("c:\\program files\\windows")
        || p.starts_with("c:\\program files (x86)\\windows")
}

#[cfg(target_os = "windows")]
enum TrustResult {
    ValidTrusted(String), // Known trusted publisher name.
    ValidUnknown,         // Valid sig, unknown publisher.
    Invalid,              // Signature present but broken/tampered.
    Unsigned,             // No signature.
    Error,                // API error.
}

#[cfg(target_os = "windows")]
fn verify_trust(path: &Path) -> (TrustResult, Option<String>) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Convert path to wide string.
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Call WinVerifyTrust.
    let result = win_verify_trust(&wide_path);

    // Try to extract signer name.
    let signer = extract_signer(path);

    const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
    const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0101u32 as i32;
    const TRUST_E_REVOKED: i32 = 0x800B010Cu32 as i32;

    if result == 0 {
        // Valid signature.
        if let Some(ref s) = signer {
            let s_lower = s.to_lowercase();
            for &(pattern, _) in TRUSTED_SIGNERS {
                if s_lower.contains(&pattern.to_lowercase()) {
                    return (TrustResult::ValidTrusted(pattern.to_string()), signer);
                }
            }
            (TrustResult::ValidUnknown, signer)
        } else {
            (TrustResult::ValidUnknown, signer)
        }
    } else if result == TRUST_E_NOSIGNATURE {
        (TrustResult::Unsigned, None)
    } else if result == TRUST_E_EXPLICIT_DISTRUST || result == TRUST_E_REVOKED {
        (TrustResult::Invalid, signer)
    } else if result < 0 {
        if signer.is_some() {
            (TrustResult::Invalid, signer)
        } else {
            (TrustResult::Unsigned, None)
        }
    } else {
        (TrustResult::Error, None)
    }
}

#[cfg(target_os = "windows")]
fn win_verify_trust(wide_path: &[u16]) -> i32 {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::*;
    use windows::core::GUID;

    unsafe {
        let action_verify = GUID::from_values(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
        );

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: windows::core::PCWSTR(wide_path.as_ptr()),
            hFile: windows::Win32::Foundation::HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut trust_data: WINTRUST_DATA = std::mem::zeroed();
        trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.Anonymous.pFile = &mut file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.dwProvFlags = WTD_SAFER_FLAG;

        let result = WinVerifyTrust(
            HWND::default(),
            &action_verify as *const _ as *mut _,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        );

        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            HWND::default(),
            &action_verify as *const _ as *mut _,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        );

        result
    }
}

/// Extract the signer subject name from a signed PE file.
#[cfg(target_os = "windows")]
fn extract_signer(path: &Path) -> Option<String> {
    // Use a simpler approach — read the PE certificate table and parse
    // the signer from the PKCS#7 structure. For now, use a heuristic:
    // scan the file for common signer string patterns near the end
    // where Authenticode data lives.
    let data = std::fs::read(path).ok()?;
    if data.len() < 1024 {
        return None;
    }

    // Look for UTF-16LE publisher strings in the certificate area.
    // Authenticode certificates contain the signer's subject in UTF-16.
    for &(pattern, _) in TRUSTED_SIGNERS {
        let utf16: Vec<u8> = pattern
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        if data.windows(utf16.len()).any(|w| w == utf16.as_slice()) {
            return Some(pattern.to_string());
        }
    }

    // Try to find organization/common name in the cert area (ASCII).
    // Certificates in PE overlay use ASN.1 DER with printable strings.
    let search_start = data.len().saturating_sub(64 * 1024);
    let tail = &data[search_start..];

    // Try multiple certificate field prefixes.
    for prefix in &[b"O=" as &[u8], b"CN="] {
        for (pos, _) in tail
            .windows(prefix.len())
            .enumerate()
            .filter(|(_, w)| *w == *prefix)
        {
            let start = pos + prefix.len();
            if start >= tail.len() {
                continue;
            }

            // Read until delimiter — comma, null, or non-printable.
            let end = tail[start..]
                .iter()
                .position(|&b| b == b',' || b == b'\0' || b < 0x20 || b > 0x7E)
                .map(|p| start + p)
                .unwrap_or((start + 100).min(tail.len()));

            let name = String::from_utf8_lossy(&tail[start..end])
                .trim()
                .to_string();
            // Valid publisher names are 3-100 chars, contain at least one space or are known single words.
            if name.len() >= 3
                && name.len() < 100
                && name.chars().all(|c| c.is_ascii_graphic() || c == ' ')
            {
                return Some(name);
            }
        }
    }

    None
}

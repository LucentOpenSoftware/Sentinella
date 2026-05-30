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

/// Combined: run Authenticode verification ONCE and return both the findings
/// list and the score discount. Engine should prefer this over calling
/// `analyze` and `signature_discount` separately — those each invoke
/// `verify_trust` (WinVerifyTrust + cert chain walk), so calling both runs the
/// expensive PE+CryptoAPI work 2-3× per file. This collapses it to one call.
pub fn analyze_with_discount(path: &Path) -> (Vec<Finding>, u32) {
    #[cfg(target_os = "windows")]
    {
        analyze_with_discount_windows(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        (vec![], 0)
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

/// Combined Windows implementation: one verify_trust call drives both the
/// findings list and the score discount, replacing the 2-3 calls the legacy
/// pair (`analyze` + `signature_discount`) made per PE.
#[cfg(target_os = "windows")]
fn analyze_with_discount_windows(path: &Path) -> (Vec<Finding>, u32) {
    let (trust_result, signer) = verify_trust(path);

    let findings = match &trust_result {
        TrustResult::ValidTrusted(publisher) => vec![Finding {
            layer: Layer::Reputation,
            severity: Severity::Info,
            weight: 0,
            description: format!(
                "Digitally signed by {} — valid Authenticode signature verified.",
                publisher,
            ),
            technical_detail: signer.as_ref().map(|s| format!("Signer: {s}")),
        }],
        TrustResult::ValidUnknown => {
            let signer_str = signer.as_deref().unwrap_or("Unknown");
            vec![Finding {
                layer: Layer::Reputation,
                severity: Severity::Info,
                weight: 0,
                description: format!(
                    "Digitally signed by {signer_str} — signature valid but publisher is not in the trusted database.",
                ),
                technical_detail: signer.as_ref().map(|s| format!("Signer: {s}")),
            }]
        }
        TrustResult::Invalid => vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Executable has an invalid or tampered digital signature — the file may have been modified after signing.".into(),
            technical_detail: Some("Authenticode verification failed".into()),
        }],
        TrustResult::Unsigned | TrustResult::Error => {
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
    };

    let discount = match &trust_result {
        TrustResult::ValidTrusted(_) => {
            if let Some(ref s) = signer {
                let signer_lower = s.to_lowercase();
                let mut d = 10; // Valid trusted but didn't match a specific entry.
                for &(pattern, val) in TRUSTED_SIGNERS {
                    if signer_lower.contains(&pattern.to_lowercase()) {
                        d = val;
                        break;
                    }
                }
                d
            } else {
                10
            }
        }
        TrustResult::ValidUnknown => 5,
        TrustResult::Unsigned | TrustResult::Error => {
            if is_windows_system_path(path) { 20 } else { 0 }
        }
        TrustResult::Invalid => 0,
    };

    (findings, discount)
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

/// Extract the signer subject (CN/O) from a PE file's embedded Authenticode
/// signature using the Windows CryptoAPI.
///
/// Returns `None` if the file is unsigned, the signature cannot be parsed,
/// or any API call fails. Critically, the returned string is the subject
/// embedded in the actual signing certificate — it cannot be forged by
/// embedding plaintext bytes inside the file body (the old implementation
/// scanned the raw file for UTF-16 substrings and was trivially spoofable
/// by an attacker putting "Microsoft Corporation" in `.rsrc` of an
/// unsigned PE).
#[cfg(target_os = "windows")]
pub(crate) fn extract_signer(path: &Path) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_ISSUER_SERIAL_NUMBER,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
        CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
        CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
        CryptQueryObject, HCERTSTORE, X509_ASN_ENCODING,
    };

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hstore: HCERTSTORE = HCERTSTORE::default();
        let mut hmsg: *mut std::ffi::c_void = std::ptr::null_mut();

        // 1. Query the file for an embedded PKCS#7 Authenticode signature.
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut hstore),
            Some(&mut hmsg),
            None,
        )
        .ok()?;

        // RAII-ish cleanup via a closure on early returns.
        let cleanup = |store: HCERTSTORE, msg: *mut std::ffi::c_void| {
            if !msg.is_null() {
                let _ = CryptMsgClose(Some(msg));
            }
            if !store.is_invalid() {
                let _ = CertCloseStore(store, 0);
            }
        };

        // 2. Get size of CMSG_SIGNER_INFO blob.
        let mut signer_size: u32 = 0;
        if CryptMsgGetParam(hmsg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_size).is_err()
            || signer_size == 0
        {
            cleanup(hstore, hmsg);
            return None;
        }

        let mut signer_buf = vec![0u8; signer_size as usize];
        if CryptMsgGetParam(
            hmsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_buf.as_mut_ptr() as *mut std::ffi::c_void),
            &mut signer_size,
        )
        .is_err()
        {
            cleanup(hstore, hmsg);
            return None;
        }

        let signer_info = &*(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO);

        // 3. Look up the signer's cert in the store by issuer + serial.
        let issuer_serial = CERT_ISSUER_SERIAL_NUMBER {
            Issuer: signer_info.Issuer,
            SerialNumber: signer_info.SerialNumber,
        };

        let cert_ctx: *mut CERT_CONTEXT = CertFindCertificateInStore(
            hstore,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&issuer_serial as *const _ as *const std::ffi::c_void),
            None,
        );

        if cert_ctx.is_null() {
            cleanup(hstore, hmsg);
            return None;
        }

        // 4. Get the display name (CN, falling back to O).
        let needed = CertGetNameStringW(
            cert_ctx as *const CERT_CONTEXT,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            None,
        );

        let result = if needed > 1 {
            let mut name_buf = vec![0u16; needed as usize];
            let written = CertGetNameStringW(
                cert_ctx as *const CERT_CONTEXT,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name_buf),
            );
            if written > 1 {
                let len = (written as usize).saturating_sub(1); // drop NUL
                Some(String::from_utf16_lossy(&name_buf[..len]))
            } else {
                None
            }
        } else {
            None
        };

        let _ = CertFreeCertificateContext(Some(cert_ctx as *const CERT_CONTEXT));
        cleanup(hstore, hmsg);

        result.filter(|s| !s.is_empty())
    }
}

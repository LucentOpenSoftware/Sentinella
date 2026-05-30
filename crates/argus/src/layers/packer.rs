//! Layer 3: Packer / Protector Detection
//!
//! Identifies known packers and protectors by section names, structural
//! patterns, and import table characteristics. Packing alone is not
//! malicious, but it adds suspicion weight — especially when combined
//! with other indicators.

use crate::verdict::{Finding, Layer, Severity};
use goblin::pe::PE;

/// Known packer/protector signatures based on PE section names.
const PACKER_SIGNATURES: &[PackerSignature] = &[
    // ── Compressors ──
    PackerSignature {
        names: &["UPX0", "UPX1", "UPX!"],
        packer: "UPX",
        category: PackerCategory::Compressor,
        weight: 5,
        description: "Executable is compressed with UPX — a common open-source packer used by both legitimate software and malware.",
    },
    PackerSignature {
        names: &[".MPRESS1", ".MPRESS2"],
        packer: "MPRESS",
        category: PackerCategory::Compressor,
        weight: 10,
        description: "Executable is compressed with MPRESS — less common than UPX, occasionally used by malware to evade detection.",
    },
    PackerSignature {
        names: &[".aspack", ".adata"],
        packer: "ASPack",
        category: PackerCategory::Compressor,
        weight: 12,
        description: "Executable is compressed with ASPack — a commercial packer frequently observed in malware distribution.",
    },
    PackerSignature {
        names: &[".nsp0", ".nsp1", ".nsp2"],
        packer: "NSPack",
        category: PackerCategory::Compressor,
        weight: 12,
        description: "Executable is compressed with NSPack.",
    },
    PackerSignature {
        names: &[".petite"],
        packer: "Petite",
        category: PackerCategory::Compressor,
        weight: 10,
        description: "Executable is compressed with Petite packer.",
    },
    // ── Protectors ──
    PackerSignature {
        names: &[".themida"],
        packer: "Themida/WinLicense",
        category: PackerCategory::Protector,
        weight: 22,
        description: "Executable is protected with Themida/WinLicense — a commercial protector that heavily obfuscates code, frequently abused by malware.",
    },
    PackerSignature {
        names: &[".vmp0", ".vmp1", ".vmp2"],
        packer: "VMProtect",
        category: PackerCategory::Protector,
        weight: 22,
        description: "Executable is protected with VMProtect — a code virtualizer that converts code to virtual machine bytecode, heavily used by malware.",
    },
    PackerSignature {
        names: &[".enigma1", ".enigma2"],
        packer: "Enigma Protector",
        category: PackerCategory::Protector,
        weight: 18,
        description: "Executable is protected with Enigma Protector — a commercial protector sometimes used to shield malicious code.",
    },
    // ── .NET protectors ──
    PackerSignature {
        names: &["ConfuserEx"],
        packer: "ConfuserEx",
        category: PackerCategory::DotNetProtector,
        weight: 15,
        description: "Executable is protected with ConfuserEx — an open-source .NET obfuscator commonly used by .NET malware.",
    },
];

struct PackerSignature {
    names: &'static [&'static str],
    packer: &'static str,
    #[allow(dead_code)]
    category: PackerCategory,
    weight: u32,
    description: &'static str,
}

#[allow(dead_code)]
enum PackerCategory {
    Compressor,
    Protector,
    DotNetProtector,
}

/// Analyze PE for packer/protector indicators.
pub fn analyze(pe: &PE, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    detect_by_sections(pe, &mut findings);
    detect_by_structure(pe, data, &mut findings);
    detect_pyinstaller(data, &mut findings);
    detect_node_sea(data, &mut findings);

    findings
}

// ── Section-name-based detection ───────────────────────────────────

fn detect_by_sections(pe: &PE, findings: &mut Vec<Finding>) {
    let section_names: Vec<String> = pe
        .sections
        .iter()
        .map(|s| {
            let raw = &s.name;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).to_string()
        })
        .collect();

    for sig in PACKER_SIGNATURES {
        let matched = sig.names.iter().any(|&name| {
            section_names
                .iter()
                .any(|sec| sec.eq_ignore_ascii_case(name))
        });

        if matched {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: if sig.weight >= 20 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                weight: sig.weight,
                description: sig.description.into(),
                technical_detail: Some(format!(
                    "Packer: {} | Sections: [{}]",
                    sig.packer,
                    section_names.join(", "),
                )),
            });
        }
    }
}

// ── Structure-based detection ──────────────────────────────────────

fn detect_by_structure(pe: &PE, data: &[u8], findings: &mut Vec<Finding>) {
    let sections = &pe.sections;
    if sections.is_empty() {
        return;
    }

    // Count sections with high entropy + executable flag.
    let high_entropy_exec_count = sections
        .iter()
        .filter(|s| {
            let executable = s.characteristics & 0x2000_0000 != 0;
            if !executable {
                return false;
            }
            let offset = s.pointer_to_raw_data as usize;
            let size = s.size_of_raw_data as usize;
            // Defensive: same checked_add reasoning as pe_heuristics —
            // attacker-controlled u32+u32 wraps to a tiny value on 32-bit
            // usize, then bypasses the bounds check.
            let end = match offset.checked_add(size) {
                Some(e) if e <= data.len() => e,
                _ => return false,
            };
            if size < 256 {
                return false;
            }
            let ent = entropy::shannon_entropy(&data[offset..end]);
            ent > 7.0
        })
        .count();

    if high_entropy_exec_count >= 2 {
        findings.push(Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: format!(
                "Multiple executable sections ({high_entropy_exec_count}) have near-random entropy — strong indicator of packing or encryption.",
            ),
            technical_detail: Some(format!("{high_entropy_exec_count} sections with entropy > 7.0 and EXECUTE flag")),
        });
    }

    // Very few sections (1-2) in a binary > 100KB — compressor signature.
    let total_raw: u64 = sections.iter().map(|s| s.size_of_raw_data as u64).sum();
    if sections.len() <= 2 && total_raw > 100_000 {
        let ent = entropy::shannon_entropy(&data[..data.len().min(65536)]);
        if ent > 6.5 {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Info,
                weight: 3,
                description: "Executable has an unusually low section count for its size — consistent with a packed binary.".into(),
                technical_detail: Some(format!("{} sections, {} bytes total, overall entropy {ent:.2}", sections.len(), total_raw)),
            });
        }
    }
}

// ── PyInstaller detection ──────────────────────────────────────────

fn detect_pyinstaller(data: &[u8], findings: &mut Vec<Finding>) {
    // PyInstaller magic at end of file: MEI\014\013\012\013\016
    let magic = b"MEI\x0C\x0B\x0A\x0B\x0E";

    if data.len() > 64 {
        // Check last 4KB for the PyInstaller magic.
        let search_start = data.len().saturating_sub(4096);
        let tail = &data[search_start..];

        if tail.windows(magic.len()).any(|w| w == magic) {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 10,
                description: "Executable was built with PyInstaller — a Python packaging tool. While legitimate, it is frequently used to package Python-based stealers and malware.".into(),
                technical_detail: Some("PyInstaller CArchive magic (MEI\\x0C\\x0B\\x0A\\x0B\\x0E) found in overlay".into()),
            });
        }
    }

    // Also check for _MEIPASS string.
    if data.windows(8).any(|w| w == b"_MEIPASS") {
        // Already found via magic, just add technical detail.
        if !findings.iter().any(|f| {
            f.technical_detail
                .as_ref()
                .is_some_and(|d| d.contains("PyInstaller"))
        }) {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 10,
                description: "Executable contains PyInstaller runtime markers.".into(),
                technical_detail: Some("String '_MEIPASS' found in binary".into()),
            });
        }
    }
}

// ── Node.js SEA (Single Executable Application) detection ──────────

fn detect_node_sea(data: &[u8], findings: &mut Vec<Finding>) {
    let fuse = b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

    if data.windows(fuse.len()).any(|w| w == fuse) {
        findings.push(Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: "Executable is a Node.js Single Executable Application (SEA). While legitimate, this format is used to package Node.js-based stealers and malware.".into(),
            technical_detail: Some("NODE_SEA_FUSE sentinel string found".into()),
        });
    }

    // Also check for NODE_SEA_BLOB resource name.
    if data.windows(13).any(|w| w == b"NODE_SEA_BLOB") {
        if !findings.iter().any(|f| {
            f.technical_detail
                .as_ref()
                .is_some_and(|d| d.contains("NODE_SEA"))
        }) {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 10,
                description: "Executable contains a Node.js SEA resource blob.".into(),
                technical_detail: Some("NODE_SEA_BLOB PE resource found".into()),
            });
        }
    }
}

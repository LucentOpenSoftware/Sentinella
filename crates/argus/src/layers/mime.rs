//! Layer 1: MIME / Magic Byte Validation
//!
//! Detects file type mismatches — the gap between what a file claims to be
//! (via its extension) and what it actually is (via magic bytes). This is
//! one of the highest-signal, lowest-cost checks in ARGUS.

use crate::verdict::{Finding, Layer, Severity};

/// Analyze file type integrity. Compares magic-byte-detected type against
/// the file extension to catch disguised executables.
pub fn analyze(path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = file_extension(path);
    let detected = infer::get(data);

    // ── Check for RTLO (Right-to-Left Override) in filename ─────
    if path.as_bytes().windows(3).any(|w| w == [0xE2, 0x80, 0xAE]) {
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::Critical,
            weight: 50,
            description: "Filename contains a Right-to-Left Override character, a technique used to disguise executable file extensions.".into(),
            technical_detail: Some(format!("Unicode U+202E (RTLO) found in path: {path}")),
        });
    }

    // ── Check for double extensions ────────────────────────────
    if let Some(double) = detect_double_extension(path) {
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::High,
            weight: 35,
            description: format!(
                "File uses a double extension (.{}) to disguise an executable as a document.",
                double,
            ),
            technical_detail: Some(format!("Double extension detected in: {path}")),
        });
    }

    // ── Extension vs magic byte mismatch ──────────────────────
    if let Some(info) = detected {
        let actual_mime = info.mime_type();
        let is_executable = is_executable_mime(actual_mime);

        if is_executable && is_document_extension(&ext) {
            findings.push(Finding {
                layer: Layer::MimeValidation,
                severity: Severity::Critical,
                weight: 45,
                description: format!(
                    "File presents as a {} but contains executable code — likely a disguised threat.",
                    extension_description(&ext),
                ),
                technical_detail: Some(format!(
                    "Extension: .{ext} | Actual MIME: {actual_mime} | Magic: {:02X?}",
                    &data[..data.len().min(8)],
                )),
            });
        }

        if is_executable && is_image_extension(&ext) {
            findings.push(Finding {
                layer: Layer::MimeValidation,
                severity: Severity::Critical,
                weight: 45,
                description: format!(
                    "File presents as an image (.{ext}) but contains executable code.",
                ),
                technical_detail: Some(format!("Extension: .{ext} | Actual MIME: {actual_mime}",)),
            });
        }
    } else {
        // infer couldn't detect type — check manually for PE magic.
        if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
            // MZ header present.
            if is_document_extension(&ext) || is_image_extension(&ext) {
                findings.push(Finding {
                    layer: Layer::MimeValidation,
                    severity: Severity::Critical,
                    weight: 45,
                    description: format!(
                        "File has a .{ext} extension but begins with an executable header (MZ).",
                    ),
                    technical_detail: Some("PE executable magic bytes (4D 5A) at offset 0".into()),
                });
            }
        }
    }

    // ── Polyglot detection ────────────────────────────────────
    // Check for multiple valid file signatures in the same file.
    let has_mz = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    let has_pdf = data.windows(5).take(1024).any(|w| w == b"%PDF-");
    let has_pk = data.len() >= 4 && data[0..4] == [0x50, 0x4B, 0x03, 0x04];

    if has_mz && has_pdf {
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::High,
            weight: 35,
            description: "File contains both executable and PDF signatures — possible polyglot used to bypass security filters.".into(),
            technical_detail: Some("Both MZ (PE) and %PDF- headers detected in the same file".into()),
        });
    }

    if has_mz && has_pk {
        // This is sometimes legitimate (self-extracting archives), but worth noting.
        findings.push(Finding {
            layer: Layer::FileDeception,
            severity: Severity::Low,
            weight: 5,
            description: "File contains both executable and archive signatures.".into(),
            technical_detail: Some("Both MZ (PE) and PK (ZIP) headers detected".into()),
        });
    }

    findings
}

// ── Helpers ────────────────────────────────────────────────────────

fn file_extension(path: &str) -> String {
    std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn is_executable_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/x-dosexec"
            | "application/x-executable"
            | "application/x-mach-binary"
            | "application/x-elf"
            | "application/vnd.microsoft.portable-executable"
    )
}

fn is_document_extension(ext: &str) -> bool {
    matches!(
        ext,
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "odt"
            | "ods"
            | "odp"
            | "rtf"
            | "txt"
            | "csv"
    )
}

fn is_image_extension(ext: &str) -> bool {
    matches!(
        ext,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tiff" | "tif"
    )
}

fn extension_description(ext: &str) -> &'static str {
    match ext {
        "pdf" => "PDF document",
        "doc" | "docx" => "Word document",
        "xls" | "xlsx" => "Excel spreadsheet",
        "ppt" | "pptx" => "PowerPoint presentation",
        "txt" => "text file",
        "rtf" => "Rich Text document",
        _ => "document",
    }
}

/// Detect double extensions like `.pdf.exe`, `.doc.scr`.
fn detect_double_extension(path: &str) -> Option<String> {
    let executable_exts = [
        "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsh", "wsf", "msi",
        "msp",
    ];

    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Count dots (excluding the leading dot of hidden files).
    let trimmed = name.trim_start_matches('.');
    let dots: Vec<usize> = trimmed.match_indices('.').map(|(i, _)| i).collect();

    if dots.len() >= 2 {
        let final_ext = &trimmed[dots[dots.len() - 1] + 1..];
        let penult_ext = &trimmed[dots[dots.len() - 2] + 1..dots[dots.len() - 1]];

        if executable_exts.contains(&final_ext)
            && (is_document_extension(penult_ext) || is_image_extension(penult_ext))
        {
            return Some(format!("{penult_ext}.{final_ext}"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtlo_detection() {
        let path = "resume_2025\u{202E}exe.pdf";
        let data = b"just some text";
        let findings = analyze(path, data);
        assert!(
            findings
                .iter()
                .any(|f| f.layer == Layer::FileDeception && f.weight == 50)
        );
    }

    #[test]
    fn test_pe_as_pdf() {
        let mut data = vec![0x4D, 0x5A]; // MZ header
        data.extend_from_slice(&[0; 100]);
        let findings = analyze("invoice.pdf", &data);
        assert!(
            findings
                .iter()
                .any(|f| f.layer == Layer::MimeValidation && f.severity == Severity::Critical)
        );
    }

    #[test]
    fn test_double_extension() {
        assert!(detect_double_extension("report.pdf.exe").is_some());
        assert!(detect_double_extension("normal.exe").is_none());
        assert!(detect_double_extension("photo.jpg.scr").is_some());
    }

    #[test]
    fn test_clean_file() {
        let data = b"%PDF-1.4 some pdf content";
        let findings = analyze("report.pdf", data);
        // No deception findings for a legitimate PDF.
        assert!(
            findings
                .iter()
                .all(|f| f.layer != Layer::FileDeception || f.severity <= Severity::Low)
        );
    }
}

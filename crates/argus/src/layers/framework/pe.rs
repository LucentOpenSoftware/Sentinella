//! Bounded PE header parsing for the framework detectors and the scoring
//! layer.
//!
//! WHY hand-rolled instead of reusing `goblin` (already used by
//! `pe_heuristics.rs`): the framework detectors need a *small, total* view of
//! exactly the header facts they cite as structural evidence — e_lfanew, the
//! section table with raw ranges, the overlay extent, the resource data
//! directory — with every intermediate offset computed under checked
//! arithmetic and every anomaly surfaced as a warning the detectors can merge
//! into their [`super::FrameworkDetection`]. `pe_heuristics.rs` has no raw
//! parsing of its own to share (it consumes goblin's already-parsed `PE`), so
//! this module is the single home for bounded header parsing under
//! `layers/framework`. Re-pointing `pe_heuristics` at these helpers is a
//! later-wave decision and deliberately NOT done here.
//!
//! Totality contract: [`parse`] and every helper in this module are total —
//! no panics, no indexing, no unchecked arithmetic on attacker-controlled
//! bytes. All multi-byte reads go through [`get`]/[`read_u16_le`]/
//! [`read_u32_le`], which bounds-check via `checked_add` and slice indexing
//! through `data.get(..)`. All offset arithmetic widens to `u64` first, so
//! `u32::MAX` header fields cannot wrap.

use std::ops::Range;

/// Hard cap on the accepted section count.
///
/// WHY 96: the PE spec allows 96 sections (0x60); real-world binaries have a
/// handful. The count is attacker-controlled and drives the `sections` Vec
/// allocation, so values above the spec maximum are rejected outright rather
/// than clamped — a header claiming thousands of sections is malformed, and
/// parsing an attacker-chosen prefix of it as authoritative would be worse
/// than failing closed.
pub const MAX_SECTIONS: u16 = 96;

/// Cap on recorded warnings. Pathological headers (96 mutually-overlapping
/// sections) would otherwise produce thousands of diagnostic strings.
const MAX_WARNINGS: usize = 128;

// DOS / PE structure constants.
const DOS_MAGIC: &[u8; 2] = b"MZ";
const PE_MAGIC: &[u8; 4] = b"PE\0\0";
const E_LFANEW_OFFSET: u64 = 0x3C;
const COFF_HEADER_LEN: u64 = 20;
const SECTION_HEADER_LEN: u64 = 40;

const OPTIONAL_MAGIC_PE32: u16 = 0x10B;
const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x20B;

// Field offsets within the optional header (from its start).
const OPT_ENTRY_POINT_OFF: u64 = 16;
const OPT_SIZE_OF_IMAGE_OFF: u64 = 56;
const OPT32_NUMBER_OF_RVA_OFF: u64 = 92;
const OPT32_DATA_DIRS_OFF: u64 = 96;
const OPT64_NUMBER_OF_RVA_OFF: u64 = 108;
const OPT64_DATA_DIRS_OFF: u64 = 112;
const DATA_DIR_ENTRY_LEN: u64 = 8;
const RESOURCE_DIR_INDEX: u64 = 2;

/// Bounded slice read — the only way bytes leave the buffer in this module.
///
/// Returns `None` when `offset` does not fit `usize` or `offset + len`
/// overflows or exceeds the buffer. Total on any inputs.
pub fn get(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

/// Bounded little-endian u16 read.
pub fn read_u16_le(data: &[u8], offset: u64) -> Option<u16> {
    let bytes: [u8; 2] = get(data, offset, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Bounded little-endian u32 read.
pub fn read_u32_le(data: &[u8], offset: u64) -> Option<u32> {
    let bytes: [u8; 4] = get(data, offset, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// One parsed section-table entry.
///
/// All fields are the *declared* header values, exactly as attacker-written —
/// consumers must not slice the file with `raw_ptr`/`raw_size` directly; use
/// [`SectionInfo::raw_range`] for a bounds-clamped range instead.
// Fields are consumed by the detector + scoring-integration waves that land
// next; only the parser tests read most of them today.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SectionInfo {
    /// Section name, NUL-trimmed and lossy-decoded from the 8 header bytes.
    pub name: String,
    /// `VirtualAddress` (RVA) from the section header.
    pub virtual_address: u32,
    /// `VirtualSize` from the section header.
    pub virtual_size: u32,
    /// `PointerToRawData` — declared file offset of the section body.
    pub raw_ptr: u32,
    /// `SizeOfRawData` — declared on-disk size.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl SectionInfo {
    /// The declared raw range clamped to the file bounds — safe for slicing.
    ///
    /// Returns `None` when the declared range starts past EOF or declares zero
    /// raw bytes. Widening to u64/u64-checked math means `u32::MAX` fields
    /// cannot wrap.
    // Consumed by the detector wave that lands next; only tests use it today.
    #[allow(dead_code)]
    pub fn raw_range(&self, file_len: usize) -> Option<Range<usize>> {
        if self.raw_size == 0 {
            return None;
        }
        let start = usize::try_from(self.raw_ptr).ok()?;
        if start >= file_len {
            return None;
        }
        let declared_end = u64::from(self.raw_ptr) + u64::from(self.raw_size);
        let end = usize::try_from(declared_end).unwrap_or(usize::MAX).min(file_len);
        Some(start..end)
    }
}

/// Parsed PE header facts for the framework detectors.
///
/// This is a *facts only* view: no finding generation, no scoring. Detectors
/// cite these facts as [`super::EvidenceItem`]s; anomalies encountered while
/// parsing are collected in [`PeInfo::warnings`] so they can be merged into
/// the detection result instead of being silently dropped.
// Fields are consumed by the detector + scoring-integration waves that land
// next; only the parser tests read most of them today.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeInfo {
    /// `e_lfanew` — file offset of the PE signature, as declared in the DOS
    /// header.
    pub e_lfanew: u32,
    /// COFF `Machine` field.
    pub machine: u16,
    /// Optional-header magic (`0x10B` PE32 / `0x20B` PE32+), or `0` when the
    /// optional header is absent or carries an unrecognized magic.
    pub optional_magic: u16,
    /// `SizeOfImage` from the optional header (0 when absent/unparsed).
    pub size_of_image: u32,
    /// `AddressOfEntryPoint` RVA from the optional header (0 when
    /// absent/unparsed).
    pub entry_point: u32,
    /// Parsed section table (at most [`MAX_SECTIONS`] entries).
    pub sections: Vec<SectionInfo>,
    /// File offset where the overlay begins: the maximum over sections of
    /// `raw_ptr + raw_size`, clamped to EOF. Computed with u64 arithmetic so
    /// no declared range can wrap; by construction (max over section ends)
    /// the overlay can never begin inside a section.
    pub overlay_start: u64,
    /// Overlay length in bytes (`0` when there is no overlay).
    pub overlay_len: u64,
    /// Whether the resource data directory (entry 2) is present and non-empty.
    pub has_resources: bool,
    /// First file offset past the section table — the earliest offset a
    /// section's raw range may legitimately occupy.
    pub headers_end: u64,
    /// Non-fatal anomalies found while parsing (clamped ranges, overlapping
    /// sections, ...). Never fatal; surfaced for diagnostics.
    pub warnings: Vec<String>,
}

/// Parse the PE headers of `data`.
///
/// Returns `None` — fail-closed — when no trustworthy structural surface
/// exists: missing `MZ`/`PE\0\0` magic, `e_lfanew` pointing anywhere the
/// signature cannot be read (past EOF, into the overlay), a truncated COFF or
/// section table, zero sections, or a section count above [`MAX_SECTIONS`].
///
/// Parse-policy decisions (all documented at the call sites below):
///
/// - **Reject (None)**: structural anchors the detectors would cite are
///   untrustworthy — bad magic, bad `e_lfanew`, absurd section count,
///   truncated section table, zero sections.
/// - **Clamp + warning**: individual section raw ranges that run past EOF are
///   clamped to the file bounds for overlay computation (fail-safe: the
///   overlay shrinks to nothing rather than smuggling bytes into it) while
///   the *declared* values stay in [`SectionInfo`] for diagnostics.
/// - **Flag + keep**: raw ranges overlapping the headers and mutually
///   overlapping sections are recorded in `warnings` but do not abort
///   parsing — the remaining structure is still usable evidence.
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    let mut warnings: Vec<String> = Vec::new();

    // DOS header + e_lfanew.
    if get(data, 0, 2)? != DOS_MAGIC {
        return None;
    }
    let e_lfanew = read_u32_le(data, E_LFANEW_OFFSET)?;
    // The signature read bounds-checks e_lfanew for free: past EOF, into the
    // overlay, or into any non-signature bytes all fail here. u32→u64 cannot
    // overflow.
    if get(data, u64::from(e_lfanew), 4)? != PE_MAGIC {
        return None;
    }

    // COFF header, immediately after the signature.
    let coff_off = u64::from(e_lfanew) + 4;
    let machine = read_u16_le(data, coff_off)?;
    let number_of_sections = read_u16_le(data, coff_off + 2)?;
    let size_of_optional_header = read_u16_le(data, coff_off + 16)?;

    // Reject absurd section counts rather than clamping (see MAX_SECTIONS).
    if number_of_sections == 0 {
        tracing::debug!("PE parse: zero sections — no structural surface");
        return None;
    }
    if number_of_sections > MAX_SECTIONS {
        tracing::debug!(
            number_of_sections,
            "PE parse: section count above {MAX_SECTIONS} — rejecting malformed header"
        );
        return None;
    }

    // The whole section table must be in-file; a truncated table means no
    // section entry is trustworthy. u16/u32 fields widened to u64: no wrap.
    let opt_off = coff_off + COFF_HEADER_LEN;
    let table_off = opt_off + u64::from(size_of_optional_header);
    let table_end = table_off + u64::from(number_of_sections) * SECTION_HEADER_LEN;
    if get(data, table_off, (table_end - table_off) as usize).is_none() {
        tracing::debug!("PE parse: section table extends past EOF — rejecting");
        return None;
    }
    let headers_end = table_end;

    // Optional header. Absent (size 0) or unrecognized magic is NOT fatal:
    // the section table is still structural evidence, so we zero the
    // optional-derived facts and record a warning instead of rejecting.
    let mut optional_magic = 0u16;
    let mut size_of_image = 0u32;
    let mut entry_point = 0u32;
    let mut has_resources = false;
    if size_of_optional_header == 0 {
        push_warning(
            &mut warnings,
            "no optional header — entry point, image size and data directories unavailable"
                .into(),
        );
    } else {
        let magic = read_u16_le(data, opt_off)?; // in-file: table follows it
        let (num_rva_off, dirs_off) = match magic {
            OPTIONAL_MAGIC_PE32 => (OPT32_NUMBER_OF_RVA_OFF, OPT32_DATA_DIRS_OFF),
            OPTIONAL_MAGIC_PE32PLUS => (OPT64_NUMBER_OF_RVA_OFF, OPT64_DATA_DIRS_OFF),
            other => {
                push_warning(
                    &mut warnings,
                    format!(
                        "unrecognized optional-header magic 0x{other:04X} — entry point, \
                         image size and data directories unavailable"
                    ),
                );
                (0, 0)
            }
        };
        if dirs_off != 0 {
            optional_magic = magic;
            // Field reads are gated on the declared optional-header size, so
            // a truncated optional header degrades to zeros instead of
            // reading section-table bytes as header fields.
            if u64::from(size_of_optional_header) >= OPT_ENTRY_POINT_OFF + 4 {
                entry_point = read_u32_le(data, opt_off + OPT_ENTRY_POINT_OFF)?;
            }
            if u64::from(size_of_optional_header) >= OPT_SIZE_OF_IMAGE_OFF + 4 {
                size_of_image = read_u32_le(data, opt_off + OPT_SIZE_OF_IMAGE_OFF)?;
            }
            // Resource data directory (entry 2): present, within the declared
            // optional header, and non-empty.
            if u64::from(size_of_optional_header) >= num_rva_off + 4 {
                let number_of_rva_and_sizes = read_u32_le(data, opt_off + num_rva_off)?;
                let dir2_off = dirs_off + RESOURCE_DIR_INDEX * DATA_DIR_ENTRY_LEN;
                if u64::from(number_of_rva_and_sizes) > RESOURCE_DIR_INDEX
                    && u64::from(size_of_optional_header)
                        >= dir2_off + DATA_DIR_ENTRY_LEN
                {
                    let rva = read_u32_le(data, opt_off + dir2_off)?;
                    let size = read_u32_le(data, opt_off + dir2_off + 4)?;
                    has_resources = rva != 0 && size != 0;
                }
            }
        }
    }

    // Section table.
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections {
        let sec_off = table_off + u64::from(i) * SECTION_HEADER_LEN;
        // In-file by the table_end check above.
        let name_raw = get(data, sec_off, 8)?;
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();
        sections.push(SectionInfo {
            name,
            virtual_size: read_u32_le(data, sec_off + 8)?,
            virtual_address: read_u32_le(data, sec_off + 12)?,
            raw_size: read_u32_le(data, sec_off + 16)?,
            raw_ptr: read_u32_le(data, sec_off + 20)?,
            characteristics: read_u32_le(data, sec_off + 36)?,
        });
    }

    let file_len = data.len() as u64;

    // Per-section raw-range validation. Declared ranges are widened to u64
    // (raw_ptr + raw_size ≤ 2^33, cannot wrap); ranges past EOF are clamped
    // for overlay computation, ranges overlapping the headers are flagged.
    // Both stay parseable: the declared values are preserved in SectionInfo.
    let mut overlay_start = 0u64;
    for sec in &sections {
        if sec.raw_size == 0 {
            continue; // BSS-like: occupies no file bytes.
        }
        let raw_end = u64::from(sec.raw_ptr) + u64::from(sec.raw_size);
        if u64::from(sec.raw_ptr) < headers_end {
            push_warning(
                &mut warnings,
                format!(
                    "section '{}': raw range starts at 0x{:X}, inside the headers \
                     (headers end at 0x{headers_end:X})",
                    sec.name, sec.raw_ptr
                ),
            );
        }
        if raw_end > file_len {
            push_warning(
                &mut warnings,
                format!(
                    "section '{}': raw range 0x{:X}..0x{raw_end:X} extends past EOF \
                     (0x{file_len:X}) — clamped for overlay computation",
                    sec.name, sec.raw_ptr
                ),
            );
        }
        // Fail-safe: clamping to EOF shrinks the overlay rather than letting
        // a past-EOF declared range smuggle bytes into it.
        overlay_start = overlay_start.max(raw_end.min(file_len));
    }

    // Mutually overlapping raw ranges are flagged, not rejected — the file
    // still parses, but a detector must not treat shared ranges as
    // independent evidence.
    for (i, a) in sections.iter().enumerate() {
        if a.raw_size == 0 {
            continue;
        }
        let a_end = u64::from(a.raw_ptr) + u64::from(a.raw_size);
        for b in sections.iter().skip(i + 1) {
            if b.raw_size == 0 {
                continue;
            }
            let b_end = u64::from(b.raw_ptr) + u64::from(b.raw_size);
            if u64::from(a.raw_ptr) < b_end && u64::from(b.raw_ptr) < a_end {
                push_warning(
                    &mut warnings,
                    format!(
                        "sections '{}' and '{}' declare overlapping raw ranges",
                        a.name, b.name
                    ),
                );
            }
        }
    }

    let overlay_len = file_len.saturating_sub(overlay_start);

    Some(PeInfo {
        e_lfanew,
        machine,
        optional_magic,
        size_of_image,
        entry_point,
        sections,
        overlay_start,
        overlay_len,
        has_resources,
        headers_end,
        warnings,
    })
}

fn push_warning(warnings: &mut Vec<String>, msg: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(msg);
    } else if warnings.len() == MAX_WARNINGS {
        warnings.push("further warnings truncated".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::framework::fixtures::{PeBuilder, SectionSpec, patch_u32_le};

    // ── valid fixtures ─────────────────────────────────────────────

    #[test]
    fn parses_minimal_valid_pe() {
        let data = PeBuilder::new()
            .section(".text", 0x180, 0x200)
            .section(".rdata", 0x80, 0x100)
            .build();
        let pe = parse(&data).expect("valid fixture must parse");
        assert_eq!(pe.optional_magic, OPTIONAL_MAGIC_PE32);
        assert_eq!(pe.machine, 0x14C);
        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[1].name, ".rdata");
        assert_eq!(pe.entry_point, 0x1000);
        assert_eq!(pe.size_of_image, 0x4000);
        assert!(!pe.has_resources);
        assert!(pe.warnings.is_empty(), "warnings: {:?}", pe.warnings);
        // No overlay appended: overlay_start lands exactly at EOF.
        assert_eq!(pe.overlay_start, data.len() as u64);
        assert_eq!(pe.overlay_len, 0);
        // Sections occupy the raw ranges the builder laid out.
        assert_eq!(pe.sections[0].raw_ptr, pe.headers_end as u32);
        let r0 = pe.sections[0].raw_range(data.len()).unwrap();
        assert_eq!(r0.end - r0.start, 0x200);
    }

    #[test]
    fn overlay_extent_is_computed_from_last_raw_end() {
        let data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"OVERLAY-DATA")
            .build();
        let pe = parse(&data).unwrap();
        assert_eq!(pe.overlay_len, 12);
        let overlay = get(&data, pe.overlay_start, pe.overlay_len as usize).unwrap();
        assert_eq!(overlay, b"OVERLAY-DATA");
    }

    #[test]
    fn overlay_start_is_max_section_end_regardless_of_table_order() {
        // The first table entry declares the raw range that ENDS EARLIER on
        // disk — the overlay must still start at the MAX raw end, never
        // inside a section (by construction of the max computation).
        let data = PeBuilder::new()
            .add_section(SectionSpec::new(".late", 0x100, 0x100).raw_ptr_override(0x600))
            .add_section(SectionSpec::new(".early", 0x100, 0x100).raw_ptr_override(0x400))
            .build();
        let pe = parse(&data).unwrap();
        assert_eq!(pe.overlay_start, 0x700);
        for s in &pe.sections {
            let end = u64::from(s.raw_ptr) + u64::from(s.raw_size);
            assert!(pe.overlay_start >= end.min(data.len() as u64));
        }
    }

    #[test]
    fn has_resources_from_data_directory() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section(".rsrc", 0x100, 0x100)
            .resource_directory(0x2000, 0x180)
            .build();
        let pe = parse(&data).unwrap();
        assert!(pe.has_resources);
    }

    #[test]
    fn absent_optional_header_degrades_with_warning() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .size_of_optional_override(0)
            .build();
        let pe = parse(&data).unwrap();
        assert_eq!(pe.optional_magic, 0);
        assert_eq!(pe.entry_point, 0);
        assert_eq!(pe.size_of_image, 0);
        assert!(!pe.has_resources);
        assert_eq!(pe.warnings.len(), 1);
        // Section table still parsed — structural evidence survives.
        assert_eq!(pe.sections.len(), 1);
    }

    #[test]
    fn unrecognized_optional_magic_degrades_with_warning() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .optional_magic(0x9999)
            .build();
        let pe = parse(&data).unwrap();
        assert_eq!(pe.optional_magic, 0);
        assert_eq!(pe.entry_point, 0);
        assert!(pe.warnings.iter().any(|w| w.contains("magic")));
    }

    // ── rejection cases ────────────────────────────────────────────

    #[test]
    fn rejects_zero_byte_and_mz_only_files() {
        assert_eq!(parse(b"").map(|_| ()), None);
        assert_eq!(parse(b"MZ").map(|_| ()), None);
        assert_eq!(parse(b"M").map(|_| ()), None);
    }

    #[test]
    fn rejects_non_mz() {
        let data = PeBuilder::new().section(".text", 0x100, 0x100).build();
        let mut bad = data.clone();
        bad[0] = b'N';
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn rejects_e_lfanew_past_eof_and_u32_max() {
        let mut data = PeBuilder::new().section(".text", 0x100, 0x100).build();
        let past_eof = data.len() as u32 + 0x1000;
        patch_u32_le(&mut data, E_LFANEW_OFFSET as usize, past_eof);
        assert!(parse(&data).is_none());
        patch_u32_le(&mut data, E_LFANEW_OFFSET as usize, u32::MAX);
        assert!(parse(&data).is_none());
    }

    #[test]
    fn rejects_e_lfanew_pointing_into_overlay() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .overlay(&[0xAA; 64])
            .build();
        let mut bad = data.clone();
        // In-file but past the headers: signature check fails there.
        let overlay_off = data.len() as u32 - 32;
        patch_u32_le(&mut bad, E_LFANEW_OFFSET as usize, overlay_off);
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn rejects_zero_sections() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section_count_override(0)
            .build();
        assert!(parse(&data).is_none());
    }

    #[test]
    fn section_count_boundary_96_ok_97_rejected() {
        let mut b = PeBuilder::new();
        for i in 0..96 {
            b = b.add_section(SectionSpec::new(format!(".s{i:02}"), 0x10, 0x10));
        }
        let data96 = b.section_count_override(96).build();
        let pe = parse(&data96).unwrap();
        assert_eq!(pe.sections.len(), 96);

        let data97 = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section_count_override(97)
            .build();
        assert!(parse(&data97).is_none());
    }

    #[test]
    fn rejects_truncated_section_table() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section(".rdata", 0x100, 0x100)
            .build();
        let pe = parse(&data).unwrap();
        // Cut two bytes before the section table ends.
        let cut = pe.headers_end as usize - 2;
        assert!(parse(&data[..cut]).is_none());
    }

    // ── clamp / flag cases ─────────────────────────────────────────

    #[test]
    fn section_raw_range_past_eof_is_clamped_with_warning() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(SectionSpec::new(".fat", 0x100, 0x10_000).body_len(0x100))
            .build();
        let pe = parse(&data).unwrap();
        assert!(
            pe.warnings.iter().any(|w| w.contains("past EOF")),
            "warnings: {:?}",
            pe.warnings
        );
        // Declared values preserved for diagnostics...
        let fat = pe.sections.iter().find(|s| s.name == ".fat").unwrap();
        assert_eq!(fat.raw_size, 0x10_000);
        // ...but the overlay computation clamped to EOF: no phantom overlay,
        // and raw_range() is safe to slice with.
        assert_eq!(pe.overlay_start, data.len() as u64);
        assert_eq!(pe.overlay_len, 0);
        let r = fat.raw_range(data.len()).unwrap();
        assert_eq!(r.end, data.len());
    }

    #[test]
    fn u32_max_section_fields_cannot_wrap() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(
                SectionSpec::new(".evil", u32::MAX, u32::MAX)
                    .raw_ptr_override(u32::MAX)
                    .body_len(0),
            )
            .build();
        let pe = parse(&data).unwrap(); // must not panic, must not reject
        assert!(pe.warnings.iter().any(|w| w.contains("past EOF")));
        // u32::MAX + u32::MAX widened to u64 = 0x1_FFFF_FFFE, clamped to EOF:
        // overlay shrinks to nothing (fail-safe).
        assert_eq!(pe.overlay_start, data.len() as u64);
        assert_eq!(pe.overlay_len, 0);
        // raw_range() refuses a start past EOF.
        let evil = pe.sections.iter().find(|s| s.name == ".evil").unwrap();
        assert!(evil.raw_range(data.len()).is_none());
    }

    #[test]
    fn overlapping_sections_are_flagged_not_rejected() {
        let data = PeBuilder::new()
            .add_section(SectionSpec::new(".a", 0x100, 0x200).raw_ptr_override(0x400))
            .add_section(SectionSpec::new(".b", 0x100, 0x200).raw_ptr_override(0x500))
            .build();
        let pe = parse(&data).unwrap();
        assert!(
            pe.warnings.iter().any(|w| w.contains("overlapping")),
            "warnings: {:?}",
            pe.warnings
        );
    }

    #[test]
    fn section_overlapping_headers_is_flagged() {
        let data = PeBuilder::new()
            .add_section(SectionSpec::new(".hdr", 0x100, 0x100).raw_ptr_override(0x10).body_len(0))
            .build();
        let pe = parse(&data).unwrap();
        assert!(
            pe.warnings.iter().any(|w| w.contains("inside the headers")),
            "warnings: {:?}",
            pe.warnings
        );
    }

    // ── totality sweep ─────────────────────────────────────────────

    #[test]
    fn truncation_at_every_length_never_panics() {
        let data = PeBuilder::new()
            .section(".text", 0x180, 0x200)
            .section(".rdata", 0x80, 0x100)
            .resource_directory(0x2000, 0x80)
            .overlay(b"OVERLAY")
            .build();
        assert!(parse(&data).is_some());
        for cut in 0..data.len() {
            // The assertion is the absence of a panic; every prefix must
            // return cleanly (Some only when the cut is past the last byte
            // any check needs).
            let _ = parse(&data[..cut]);
        }
    }

    #[test]
    fn byte_mutation_fuzz_never_panics() {
        // Deterministic single-byte corruption sweep over the header region:
        // totality must hold for ANY byte string, not just truncation.
        let base = PeBuilder::new()
            .section(".text", 0x180, 0x200)
            .section(".rsrc", 0x80, 0x100)
            .resource_directory(0x2000, 0x80)
            .overlay(b"OVERLAY")
            .build();
        let header_len = base.len().min(0x400);
        for off in 0..header_len {
            for val in [0x00u8, 0xFF, 0x7F, 0x80] {
                let mut m = base.clone();
                m[off] = val;
                let _ = parse(&m);
            }
        }
    }

    // ── get() helper ───────────────────────────────────────────────

    #[test]
    fn get_bounds_checks() {
        let data = [0u8; 16];
        assert_eq!(get(&data, 0, 16).unwrap().len(), 16);
        assert!(get(&data, 0, 17).is_none());
        assert!(get(&data, 15, 2).is_none());
        assert!(get(&data, 16, 0).is_some()); // empty slice at EOF is fine
        assert!(get(&data, 17, 0).is_none());
        assert!(get(&data, u64::MAX, 1).is_none());
        assert!(get(&data, u64::from(u32::MAX), 1).is_none());
    }
}

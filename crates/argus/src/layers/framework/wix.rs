//! WiX Burn bootstrapper-bundle detector — structural.
//!
//! ## What `engine.rs::has_wix` actually was
//!
//! The legacy check was `has_wix = contains(b"Windows Installer")` — an
//! unanchored full-buffer substring scan. That byte string is *terminological
//! text*, not structure: it appears in MSI-invoking applications (any binary
//! linking `msi.dll` carries it in import descriptions and error strings), in
//! documentation payloads, and in genuine WiX-built bundles alike. It proves
//! NOTHING about how the file was built, and because the old code OR-ed it
//! into the installer leniency discount, any attacker could embed it in a
//! file they fully control and earn Structural/Packer findings /3 plus
//! installer-class YARA findings /2 — the confirmed score-collapse evasion
//! this module tree replaces.
//!
//! ## Concept separation (the "WiX" conflation, split)
//!
//! "WiX" in the legacy code conflated three unrelated things:
//!
//! 1. **Native MSI packages** — OLE2 compound files, not PEs. Handled
//!    extension-only by [`super::detect_msi`] (never `mitigation_safe`).
//!    A structural MSI indicator (validating the OLE2 stream directory for
//!    MSI-specific storages/streams, e.g. the `_Tables`/`_Columns` storage
//!    pair every MSI database carries) requires an OLE2 directory parser and
//!    is OUT OF SCOPE here — flagged as future work in `mod.rs::detect_msi`.
//! 2. **WiX Burn bootstrapper bundles** — PE files (the Burn stub engine)
//!    with an attached container layout described by a dedicated `.wixburn`
//!    PE section. THIS detector. Structural evidence below.
//! 3. **Generic PEs that *use* Windows Installer** (import `msi.dll` /
//!    call `MsiInstallProduct`). Deliberately NOT a classification input:
//!    an `msi.dll` import proves MSI-*usage*, not installer-framework
//!    identity — installers, updaters, configuration tools, and malware
//!    droppers all call MSI APIs. Worse, `Imports` is a *structural*
//!    [`EvidenceSource`], so pairing it with `>= Corroborated` confidence
//!    would flip `mitigation_safe` on and re-open the evasion this module
//!    exists to close. (`PeInfo` also does not expose the import directory
//!    today, so this would need a `pe.rs` extension — reported to the
//!    coordinator as a need, not implemented.) If MSI-usage is ever
//!    reported, it must be `WeakHint` confidence at most, which is
//!    never mitigation-relevant regardless of evidence source.
//!
//! ## Structural evidence: the Burn `.wixburn` section
//!
//! Verified against the WiX Toolset source (v3 and v4):
//!
//! - The Burn stub carries its engine state in a PE section named exactly
//!   `.wixburn` (8 bytes, fills the section-name field). The engine scans
//!   the section table for the FIRST entry with that name.
//!   v3: <https://github.com/wixtoolset/wix3/blob/develop/src/burn/engine/section.cpp>
//!   (`BURN_SECTION_NAME ".wixburn"`) and
//!   <https://github.com/wixtoolset/wix3/blob/develop/src/burn/stub/StubSection.cpp>
//!   (`#pragma section(".wixburn",read)`)
//! - At offset 0 of that section's raw data sits `BURN_SECTION_HEADER`
//!   (all fields naturally 4-byte aligned, no padding; offsets verified
//!   against both the v3 struct and the v4 stub's
//!   `(512 - 48) / 4` container-slot comment):
//!
//!   | offset | field                      | expected value            |
//!   |--------|----------------------------|---------------------------|
//!   | 0x00   | `dwMagic`                  | `0x00F14300`              |
//!   | 0x04   | `dwVersion`                | `2`                       |
//!   | 0x08   | `guidBundleId/BundleCode`  | any GUID (not validated)  |
//!   | 0x18   | `dwStubSize`               | file offset where the     |
//!   |        |                            | attached UX container     |
//!   |        |                            | begins (= stub EXE size)  |
//!   | 0x1C   | `dwOriginalChecksum`       | not validated             |
//!   | 0x20   | `dwOriginalSignatureOffset`| not validated             |
//!   | 0x24   | `dwOriginalSignatureSize`  | not validated             |
//!   | 0x28   | `dwFormat`                 | `1` = CABINET (see below) |
//!   | 0x2C   | `cContainers`              | `>= 1` (index 0 = UX)     |
//!   | 0x30   | `rgcbContainers[]`         | u32 sizes; [0] = UX size  |
//!
//!   v3 constants: `BURN_SECTION_MAGIC 0x00f14300`, `BURN_SECTION_VERSION 2`
//!   in `section.cpp`; the stub writes the same values (`StubSection.cpp`).
//!   v4 keeps the identical layout:
//!   <https://github.com/wixtoolset/wix/blob/main/src/burn/engine/section.cpp>
//!   and adds the bounds check `cContainers <= (SizeOfRawData - 48) / 4`,
//!   which this detector also enforces.
//! - The UX container (index 0) is ALWAYS attached at file offset
//!   `dwStubSize` with size `rgcbContainers[0]`
//!   (`SectionGetAttachedContainerInfo`: container 0 is "right after the
//!   stub"; `ContainerOpenUX` asserts "The BA container must always be
//!   found attached"). Its type is hardcoded CABINET — the v3 engine
//!   implements no other format ("TODO: Read type from manifest. Today
//!   only CABINET is supported.",
//!   <https://github.com/wixtoolset/wix3/blob/develop/src/burn/engine/container.cpp>;
//!   `BURN_CONTAINER_TYPE_SEVENZIP` exists in the enum but is
//!   unimplemented). A cabinet begins with the CFHEADER signature "MSCF"
//!   (0x4D 0x53 0x43 0x46) per the Microsoft Cabinet Format specification
//!   (<https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)>).
//!
//! ## Confidence policy
//!
//! - **Structural**: section present + header magic/version valid +
//!   container count bounded and fitting + `dwStubSize` self-consistent
//!   (covers the `.wixburn` section, inside the file) + UX container fully
//!   in-file + "MSCF" magic at `dwStubSize`. The whole chain is at parsed
//!   offsets; forging it means shipping a coherent Burn container layout.
//! - **Corroborated**: the header chain fully validates but the UX
//!   container cannot be verified — it extends past EOF (partial download /
//!   truncated sample), the magic bytes aren't fully readable, or `dwFormat`
//!   is not CABINET (Burn implements nothing else, so there is no documented
//!   magic to check against). Still genuinely structural; a warning records
//!   exactly which check could not run.
//! - **WeakHint**: anything contradictory — bad magic/version, zero or
//!   impossible container count, `dwStubSize` excluding the `.wixburn`
//!   section itself or reaching past EOF, zero UX size, or bytes at the
//!   claimed container offset that are NOT a cabinet when the format says
//!   CABINET. A bare `.wixburn` section NAME with garbage contents is
//!   exactly the old text-marker evasion wearing a section hat; it is
//!   reported diagnostically (with a forgery-suspect warning) and never
//!   authorizes mitigation.
//! - **WeakHint (TextHint)**: no `.wixburn` section, but the legacy
//!   "Windows Installer" byte string occurs anywhere — diagnostic parity
//!   with the old `has_wix`, never mitigation-safe by construction.
//! - **Unknown**: neither.
//!
//! ## Residual uncertainties (documented honestly)
//!
//! - The v3 magic/version VALUES are verified inline in v3 `section.cpp`.
//!   v4/v5 use named constants (`BURN_SECTION_MAGIC`/`BURN_SECTION_VERSION`)
//!   whose defining header was not located during research; continuity is
//!   inferred from the identical struct layout, identical stub field
//!   sequence, and the v3 cross-file "update both" comment contract. If a
//!   future WiX version ever bumps these values, real bundles downgrade to
//!   WeakHint (fail-safe direction) rather than being misclassified.
//! - Section characteristics flags are NOT validated (the Burn engine does
//!   not check them either).
//! - `guidBundleId`, checksum, and signature fields are not validated — the
//!   engine itself only cross-checks the GUID against the *running process*
//!   image, which is meaningless for a static scanner.

use super::pe::{self, PeInfo, SectionInfo};
use super::{Confidence, EvidenceItem, EvidenceSource, FrameworkDetection, FrameworkKind};

/// The PE section the Burn stub keeps its engine state in (8 bytes exactly,
/// filling the section-name field — verified in v3/v4 `StubSection.cpp`).
const BURN_SECTION_NAME: &str = ".wixburn";
/// `BURN_SECTION_MAGIC` — verified in v3 `section.cpp`.
const BURN_SECTION_MAGIC: u32 = 0x00F1_4300;
/// `BURN_SECTION_VERSION` — verified in v3 `section.cpp`.
const BURN_SECTION_VERSION: u32 = 2;

// Field offsets within BURN_SECTION_HEADER (see module docs table).
const OFF_MAGIC: u64 = 0x00;
const OFF_VERSION: u64 = 0x04;
const OFF_STUB_SIZE: u64 = 0x18;
const OFF_FORMAT: u64 = 0x28;
const OFF_COUNT: u64 = 0x2C;
const OFF_SIZES: u64 = 0x30;
/// Smallest useful section body: fixed header (0x30) + one container size.
const MIN_HEADER_LEN: u64 = OFF_SIZES + 4;

/// `BURN_CONTAINER_TYPE_CABINET` — the only container format the Burn
/// engine implements; hardcoded for the UX container in `ContainerOpenUX`.
const CONTAINER_FORMAT_CABINET: u32 = 1;
/// CFHEADER signature per the Microsoft Cabinet Format specification.
const CABINET_MAGIC: &[u8; 4] = b"MSCF";

/// Hard cap on the accepted container count. Real bundles have 1–2 (v3
/// stub reserves 2 slots) up to 117 (v4 stub reserves 116 attached slots).
/// The count drives a read loop, so it is capped independently of the
/// section-size bound; 512 is generous headroom over the v4 maximum.
const MAX_CONTAINERS: u32 = 512;

/// The legacy substring marker, kept for diagnostic parity only.
const TEXT_MARKER: &[u8] = b"Windows Installer";

/// Detect WiX Burn bundles from parsed PE structure.
///
/// Total on any inputs: every byte read goes through [`pe::get`] /
/// [`pe::read_u32_le`], all offset arithmetic is u64-widened, and the only
/// scan is a bounded `windows()` search for the diagnostic text marker.
pub(crate) fn detect(data: &[u8], pe: &PeInfo) -> FrameworkDetection {
    // The Burn engine scans the section table and stops at the FIRST entry
    // named ".wixburn" — mirror that, but record duplicates as a warning.
    let mut matches = pe.sections.iter().filter(|s| s.name == BURN_SECTION_NAME);
    let Some(section) = matches.next() else {
        return text_hint(data);
    };
    let mut warnings = Vec::new();
    if matches.next().is_some() {
        warnings.push(
            "multiple '.wixburn' sections — evaluating the first, matching the Burn \
             engine's scan order"
                .to_string(),
        );
    }
    detect_burn_section(data, section, warnings)
}

/// Evaluate a `.wixburn` section's raw body against the Burn container
/// layout. Every contradiction downgrades to `WeakHint` with a specific
/// warning; nothing here can panic.
fn detect_burn_section(
    data: &[u8],
    sec: &SectionInfo,
    mut warnings: Vec<String>,
) -> FrameworkDetection {
    let file_len = data.len() as u64;
    let base = u64::from(sec.raw_ptr);

    // Every WeakHint return shares this shape: the section NAME is real
    // (SectionTable evidence) but its contents contradict the Burn layout.
    let weak = |warnings: Vec<String>, detail: String| {
        FrameworkDetection::build(
            FrameworkKind::WixBurn,
            Confidence::WeakHint,
            vec![EvidenceItem::new(
                EvidenceSource::SectionTable,
                Some(base),
                detail,
            )],
            warnings,
        )
    };

    let Some(range) = sec.raw_range(data.len()) else {
        warnings.push(format!(
            "'.wixburn' section declares raw range 0x{base:X}+0x{:X} with no readable \
             in-file bytes — forged section name",
            sec.raw_size
        ));
        return weak(
            warnings,
            "'.wixburn' section present but has no readable body".to_string(),
        );
    };
    let avail = (range.end - range.start) as u64;
    if avail < MIN_HEADER_LEN {
        warnings.push(format!(
            "'.wixburn' section body is {avail} readable bytes — smaller than a minimal \
             BURN_SECTION_HEADER ({MIN_HEADER_LEN}); forged or truncated container header"
        ));
        return weak(
            warnings,
            "'.wixburn' section too small for the Burn section header".to_string(),
        );
    }

    // Fixed-field reads. avail >= MIN_HEADER_LEN covers all of them; the
    // Option handling keeps the function total regardless.
    let (Some(magic), Some(version), Some(stub_size), Some(format), Some(count)) = (
        pe::read_u32_le(data, base + OFF_MAGIC),
        pe::read_u32_le(data, base + OFF_VERSION),
        pe::read_u32_le(data, base + OFF_STUB_SIZE),
        pe::read_u32_le(data, base + OFF_FORMAT),
        pe::read_u32_le(data, base + OFF_COUNT),
    ) else {
        warnings.push("unexpected short read inside a bounds-checked section body".into());
        return weak(warnings, "'.wixburn' section header unreadable".to_string());
    };

    if magic != BURN_SECTION_MAGIC {
        warnings.push(format!(
            "'.wixburn' section magic 0x{magic:08X} != 0x{BURN_SECTION_MAGIC:08X} — \
             section name without Burn contents (forgery-suspect)"
        ));
        return weak(
            warnings,
            "'.wixburn' section with non-Burn magic at offset 0".to_string(),
        );
    }
    if version != BURN_SECTION_VERSION {
        warnings.push(format!(
            "'.wixburn' Burn header version {version} != {BURN_SECTION_VERSION} — \
             unsupported/unknown Burn layout; refusing to classify structurally"
        ));
        return weak(
            warnings,
            "'.wixburn' section with unknown Burn header version".to_string(),
        );
    }
    if count == 0 {
        warnings.push(
            "'.wixburn' Burn header declares zero containers — matches the unbound stub \
             template (or a forgery), not a real bundle"
                .into(),
        );
        return weak(
            warnings,
            "'.wixburn' section with no attached containers".to_string(),
        );
    }
    // The v4 engine's own bound: cContainers <= (SizeOfRawData - 48) / 4.
    // Checked against the DECLARED size (as the engine does) and the
    // in-file size (so the size array is actually readable). u64 math: no wrap.
    let sizes_end = OFF_SIZES + 4 * u64::from(count);
    if u64::from(count) > u64::from(MAX_CONTAINERS)
        || sizes_end > u64::from(sec.raw_size)
        || sizes_end > avail
    {
        warnings.push(format!(
            "'.wixburn' Burn header declares {count} containers — exceeds the sanity cap \
             ({MAX_CONTAINERS}) or the section body (declared 0x{:X}, readable 0x{avail:X})",
            sec.raw_size
        ));
        return weak(
            warnings,
            "'.wixburn' section with impossible container count".to_string(),
        );
    }

    let Some(ux_size) = pe::read_u32_le(data, base + OFF_SIZES) else {
        warnings.push("container size array unreadable despite bounds check".into());
        return weak(warnings, "'.wixburn' container sizes unreadable".to_string());
    };

    // dwStubSize consistency: the stub EXE (including the .wixburn section)
    // is a strict prefix of the bundle, and the UX container is appended
    // right after it. u64-widened: no wrap on u32::MAX fields.
    let stub = u64::from(stub_size);
    let section_end = u64::from(sec.raw_ptr) + u64::from(sec.raw_size);
    if stub_size == 0 || stub < section_end {
        warnings.push(format!(
            "'.wixburn' Burn header stub size 0x{stub:X} contradicts the section layout \
             (the '.wixburn' section ends at 0x{section_end:X} and must be INSIDE the \
             stub) — conflicting structure, forgery-suspect"
        ));
        return weak(
            warnings,
            "'.wixburn' header stub size conflicts with section layout".to_string(),
        );
    }
    if stub >= file_len {
        warnings.push(format!(
            "'.wixburn' Burn header stub size 0x{stub:X} reaches/passes EOF \
             (0x{file_len:X}) — a real bundle always appends the UX container after \
             the stub; conflicting structure, forgery-suspect"
        ));
        return weak(
            warnings,
            "'.wixburn' header stub size exceeds the file".to_string(),
        );
    }
    if ux_size == 0 {
        warnings.push(
            "'.wixburn' Burn header declares a zero-size UX container — a real bundle \
             always carries one (Burn: 'The BA container must always be found attached')"
                .into(),
        );
        return weak(
            warnings,
            "'.wixburn' header with zero-size UX container".to_string(),
        );
    }

    // Header chain validated. Evidence so far (both structural):
    let mut evidence = vec![
        EvidenceItem::new(
            EvidenceSource::SectionTable,
            Some(base),
            "'.wixburn' section (Burn engine state) present in the parsed section table",
        ),
        EvidenceItem::new(
            EvidenceSource::EmbeddedArchive,
            Some(base),
            format!(
                "BURN_SECTION_HEADER at '.wixburn' section start: magic 0x{BURN_SECTION_MAGIC:08X}, \
                 version {BURN_SECTION_VERSION}, {count} container(s), stub size 0x{stub:X}"
            ),
        ),
    ];

    // UX container verification. Anything that prevents the check (rather
    // than contradicting it) caps at Corroborated with a warning.
    let ux_end = stub + u64::from(ux_size);
    if format != CONTAINER_FORMAT_CABINET {
        warnings.push(format!(
            "Burn container format {format} is not CABINET (1) — the only format the Burn \
             engine implements; no documented container magic to verify against"
        ));
        return FrameworkDetection::build(
            FrameworkKind::WixBurn,
            Confidence::Corroborated,
            evidence,
            warnings,
        );
    }
    if ux_end > file_len || pe::get(data, stub, CABINET_MAGIC.len()).is_none() {
        warnings.push(format!(
            "UX container at 0x{stub:X}+0x{ux_size:X} is not fully in-file (EOF \
             0x{file_len:X}) — partial/truncated bundle or detached layout; container \
             magic unverifiable"
        ));
        return FrameworkDetection::build(
            FrameworkKind::WixBurn,
            Confidence::Corroborated,
            evidence,
            warnings,
        );
    }

    // In-file and readable: the magic comparison itself cannot fail to run.
    if pe::get(data, stub, CABINET_MAGIC.len()) == Some(CABINET_MAGIC.as_slice()) {
        evidence.push(EvidenceItem::new(
            EvidenceSource::EmbeddedArchive,
            Some(stub),
            "UX container at declared stub end begins with cabinet magic 'MSCF' \
             (Microsoft Cabinet Format CFHEADER)",
        ));
        FrameworkDetection::build(
            FrameworkKind::WixBurn,
            Confidence::Structural,
            evidence,
            warnings,
        )
    } else {
        warnings.push(format!(
            "bytes at the declared UX container offset 0x{stub:X} are NOT cabinet magic \
             'MSCF' although the header declares CABINET format — claimed container \
             offsets contradict section data, forgery-suspect"
        ));
        weak(
            warnings,
            "'.wixburn' header points at a non-cabinet UX container".to_string(),
        )
    }
}

/// Legacy-parity diagnostic: the "Windows Installer" substring with no
/// structural backing. `WeakHint` with `TextHint`-only evidence by
/// construction — the centralized invariant makes this never
/// mitigation-safe no matter what a future edit claims.
fn text_hint(data: &[u8]) -> FrameworkDetection {
    let Some(off) = data.windows(TEXT_MARKER.len()).position(|w| w == TEXT_MARKER) else {
        return FrameworkDetection::unknown();
    };
    FrameworkDetection::build(
        FrameworkKind::WixBurn,
        Confidence::WeakHint,
        vec![EvidenceItem::new(
            EvidenceSource::TextHint,
            Some(off as u64),
            "'Windows Installer' byte string — terminological text present in \
             MSI-invoking apps, docs, and bundles alike; proves nothing \
             structural (legacy has_wix equivalent, diagnostic only)",
        )],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::framework::fixtures::{patch_u32_le, PeBuilder, SectionSpec};
    use crate::layers::framework::pe;

    /// Offset of `rgcbContainers[0]` inside the section body.
    const FIX_OFF: usize = 0x30;

    /// Build a coherent synthetic Burn bundle: a `.wixburn` section whose
    /// body is patched with the real documented header values (magic,
    /// version 2, one CABINET container) and an overlay at `dwStubSize`
    /// starting with the real "MSCF" cabinet signature. Returns the file
    /// plus the section-body offset for further patching.
    fn genuine_burn_fixture() -> (Vec<u8>, usize) {
        let mut overlay = vec![0u8; 0x80];
        overlay[..4].copy_from_slice(CABINET_MAGIC);
        let ux_len = overlay.len() as u32;
        let mut data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
            .overlay(&overlay)
            .build();
        let pe = pe::parse(&data).expect("fixture must parse");
        let base = pe
            .sections
            .iter()
            .find(|s| s.name == ".wixburn")
            .expect("fixture has the section")
            .raw_ptr as usize;
        let stub = pe.overlay_start as u32;
        patch_u32_le(&mut data, base + OFF_MAGIC as usize, BURN_SECTION_MAGIC);
        patch_u32_le(&mut data, base + OFF_VERSION as usize, BURN_SECTION_VERSION);
        patch_u32_le(&mut data, base + OFF_STUB_SIZE as usize, stub);
        patch_u32_le(&mut data, base + OFF_FORMAT as usize, CONTAINER_FORMAT_CABINET);
        patch_u32_le(&mut data, base + OFF_COUNT as usize, 1);
        patch_u32_le(&mut data, base + FIX_OFF, ux_len);
        (data, base)
    }

    fn run(data: &[u8]) -> FrameworkDetection {
        let pe = pe::parse(data).expect("fixture must parse");
        detect(data, &pe)
    }

    // ── genuine structure ──────────────────────────────────────────

    #[test]
    fn genuine_burn_bundle_is_structural_and_mitigation_safe() {
        let (data, base) = genuine_burn_fixture();
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
        let sources: Vec<_> = d.evidence().iter().map(|e| e.source).collect();
        assert!(sources.contains(&EvidenceSource::SectionTable));
        assert_eq!(
            sources
                .iter()
                .filter(|&&s| s == EvidenceSource::EmbeddedArchive)
                .count(),
            2,
            "header + UX container magic are separate EmbeddedArchive anchors"
        );
        // Anchors are real offsets: the section body and the container.
        assert!(d.evidence().iter().any(|e| e.offset == Some(base as u64)));
        let pe = pe::parse(&data).unwrap();
        assert!(d
            .evidence()
            .iter()
            .any(|e| e.offset == Some(pe.overlay_start)));
    }

    #[test]
    fn genuine_burn_bundle_survives_full_dispatch() {
        let (data, _) = genuine_burn_fixture();
        let d = super::super::detect(&data, "bundle.exe");
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
    }

    #[test]
    fn duplicate_wixburn_sections_use_first_with_warning() {
        let (data, _base) = genuine_burn_fixture();
        // Append a second, garbage-filled .wixburn section before the overlay.
        let pe = pe::parse(&data).unwrap();
        let overlay_start = pe.overlay_start as usize;
        let overlay = data[overlay_start..].to_vec();
        let mut rebuilt = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
            .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
            .overlay(&overlay)
            .build();
        // Copy the patched first-section body into the rebuilt fixture and
        // re-point the stub size at the (shifted) overlay start.
        let first_base = pe
            .sections
            .iter()
            .find(|s| s.name == ".wixburn")
            .unwrap()
            .raw_ptr as usize;
        let body: Vec<u8> = data[first_base..first_base + 0x40].to_vec();
        let pe2 = pe::parse(&rebuilt).unwrap();
        let new_base = pe2
            .sections
            .iter()
            .find(|s| s.name == ".wixburn")
            .unwrap()
            .raw_ptr as usize;
        rebuilt[new_base..new_base + 0x40].copy_from_slice(&body);
        patch_u32_le(
            &mut rebuilt,
            new_base + OFF_STUB_SIZE as usize,
            pe2.overlay_start as u32,
        );
        let d = run(&rebuilt);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.warnings().iter().any(|w| w.contains("multiple")));
    }

    // ── rejection: forged / contradictory sections ─────────────────

    #[test]
    fn fake_wixburn_section_garbage_body_is_weak_hint() {
        // Section NAME is right but the body is builder fill (0x41...).
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
            .build();
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("magic")));
    }

    #[test]
    fn truncated_burn_header_is_weak_hint_even_with_valid_magic() {
        // 32-byte section body: smaller than the minimal header (52) even
        // though the magic at offset 0 is correct.
        let mut data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .add_section(SectionSpec::new(".wixburn", 0x20, 0x20))
            .build();
        let pe = pe::parse(&data).unwrap();
        let base = pe
            .sections
            .iter()
            .find(|s| s.name == ".wixburn")
            .unwrap()
            .raw_ptr as usize;
        patch_u32_le(&mut data, base, BURN_SECTION_MAGIC);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("too small") || w.contains("smaller")));
    }

    #[test]
    fn impossible_container_count_is_weak_hint() {
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + OFF_COUNT as usize, 0x1000);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("sanity cap")));
    }

    #[test]
    fn zero_containers_is_weak_hint() {
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + OFF_COUNT as usize, 0);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn stub_size_conflicting_with_section_layout_is_weak_hint() {
        // Stub size INSIDE the .wixburn section itself: the claimed UX
        // container offset contradicts the section table.
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + OFF_STUB_SIZE as usize, 0x10);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("contradicts")));
    }

    #[test]
    fn stub_size_past_eof_is_weak_hint() {
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + OFF_STUB_SIZE as usize, u32::MAX);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn ux_container_magic_mismatch_is_weak_hint() {
        // Header valid but the bytes at the claimed container offset are
        // not a cabinet: claimed offsets contradict section data.
        let (mut data, _) = genuine_burn_fixture();
        let pe = pe::parse(&data).unwrap();
        let stub = pe.overlay_start as usize;
        data[stub..stub + 4].copy_from_slice(b"NOPE");
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("NOT cabinet magic")));
    }

    #[test]
    fn unknown_container_format_caps_at_corroborated() {
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + OFF_FORMAT as usize, 7);
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::Corroborated);
        assert!(d.warnings().iter().any(|w| w.contains("not CABINET")));
    }

    #[test]
    fn ux_container_past_eof_caps_at_corroborated() {
        let (mut data, base) = genuine_burn_fixture();
        patch_u32_le(&mut data, base + FIX_OFF, 0x00FF_FFFF);
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::Corroborated);
        assert!(d.warnings().iter().any(|w| w.contains("not fully in-file")));
    }

    // ── legacy text marker ─────────────────────────────────────────

    #[test]
    fn text_marker_in_overlay_only_is_weak_hint_forever() {
        let data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .overlay(b"junk Windows Installer junk")
            .build();
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d
            .evidence()
            .iter()
            .all(|e| e.source == EvidenceSource::TextHint));
    }

    #[test]
    fn text_marker_in_section_body_is_weak_hint_forever() {
        // Marker planted inside .rdata — the classic evasion placement.
        let mut data = PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section(".rdata", 0x100, 0x100)
            .build();
        let pe = pe::parse(&data).unwrap();
        let rdata = pe
            .sections
            .iter()
            .find(|s| s.name == ".rdata")
            .unwrap()
            .raw_ptr as usize;
        data[rdata..rdata + TEXT_MARKER.len()].copy_from_slice(TEXT_MARKER);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d
            .evidence()
            .iter()
            .all(|e| e.source == EvidenceSource::TextHint));
    }

    #[test]
    fn no_section_no_marker_is_unknown() {
        let data = PeBuilder::new().section(".text", 0x100, 0x100).build();
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert_eq!(d.confidence(), Confidence::Unknown);
        assert!(!d.mitigation_safe());
    }

    // ── PE / MSI separation ────────────────────────────────────────

    #[test]
    fn pe_named_setup_msi_is_not_msi_classified() {
        // A PE named .msi is nonsense: the OLE2/MSI extension path must not
        // leak into the PE route through any marker.
        let data = PeBuilder::new().section(".text", 0x100, 0x100).build();
        let d = super::super::detect(&data, "setup.msi");
        assert_ne!(d.kind(), FrameworkKind::MsiOle2);
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn genuine_burn_named_setup_msi_is_burn_not_msi() {
        let (data, _) = genuine_burn_fixture();
        let d = super::super::detect(&data, "setup.msi");
        assert_eq!(d.kind(), FrameworkKind::WixBurn);
        assert_ne!(d.kind(), FrameworkKind::MsiOle2);
    }

    // ── totality ───────────────────────────────────────────────────

    #[test]
    fn truncation_at_every_length_never_panics() {
        let (data, _) = genuine_burn_fixture();
        for cut in 0..data.len() {
            if let Some(pe) = pe::parse(&data[..cut]) {
                let d = detect(&data[..cut], &pe);
                // Even on truncated input the invariant must hold:
                // mitigation requires >= Corroborated AND structural evidence
                // (enforced by build; asserted here for the detector's claims).
                if d.confidence() >= Confidence::Corroborated {
                    assert!(d.evidence().iter().any(|e| e.source.is_structural()));
                }
            }
        }
    }

    #[test]
    fn byte_mutation_fuzz_never_panics_or_overclaims() {
        let (base_data, _) = genuine_burn_fixture();
        for off in 0..base_data.len() {
            for val in [0x00u8, 0xFF, 0x7F, 0x80] {
                let mut m = base_data.clone();
                m[off] = val;
                if let Some(pe) = pe::parse(&m) {
                    let d = detect(&m, &pe);
                    if d.confidence() >= Confidence::Corroborated {
                        assert!(d.evidence().iter().any(|e| e.source.is_structural()));
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_pe_with_all_markers_never_panics_and_stays_low() {
        // Header parse fails entirely -> the WiX detector never runs; the
        // dispatcher can only offer a legacy WeakHint at best.
        let mut data = b"MZ".to_vec();
        data.resize(0x400, 0xAA);
        data.extend_from_slice(b".wixburn Windows Installer");
        let d = super::super::detect(&data, "evil.exe");
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }
}

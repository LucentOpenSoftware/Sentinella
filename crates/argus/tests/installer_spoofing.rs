//! Adversarial regression suite: installer-framework spoofing (workstreams X+Y).
//!
//! This is an INTEGRATION test: it exercises only the crate's public surface
//! (`argus::layers::framework::detect`, `argus::layers::framework::pe::parse`)
//! so the whole dispatch path — PE parsing, NSIS/Inno/WiX detectors, the
//! centralized `FrameworkDetection::build` invariant — is tested exactly as a
//! downstream consumer sees it.
//!
//! ## WHY a duplicated PE builder (decision record)
//!
//! The lib's `fixtures::PeBuilder` is `#[cfg(test)] pub(crate)` — integration
//! tests under `tests/` are a separate crate and cannot see it. The options
//! were: (a) move it to a public `testutil` module gated on a new cargo
//! feature — REJECTED (no new features this round, and shipping test
//! scaffolding in the public API is worse than duplication); (b) widen it to
//! `pub` unconditionally — REJECTED (same API-surface cost); (c) duplicate a
//! minimal, deterministic builder here — CHOSEN. The duplication is
//! deliberate and small; the builder logic is a test fixture, not production
//! parsing code, so drift risk is acceptable and both copies are pinned by
//! the same detector tests.
//!
//! Scoring-relevant assertions (`FrameworkMitigation::evaluate` weight math,
//! veto, final score/verdict) live LIB-SIDE in
//! `crates/argus/src/engine/adversarial.rs`, because `FrameworkMitigation`
//! and `aggregate_score` are private to the engine module — that is the
//! minimal-visibility choice; this file asserts the detection-level half
//! (kind, confidence, mitigation_safe, evidence sources) of every fixture.

use argus::layers::framework::pe;
use argus::layers::framework::{Confidence, EvidenceSource, FrameworkDetection, FrameworkKind, detect};

// ═══════════════════════════════════════════════════════════════
//  Minimal PE fixture builder (duplicate of fixtures::PeBuilder —
//  see the decision record in the module docs above)
// ═══════════════════════════════════════════════════════════════

/// Section fields as written into the section-table entry.
#[derive(Debug, Clone)]
struct SectionSpec {
    name: String,
    virtual_size: u32,
    declared_raw_size: u32,
    body_len: usize,
    fill: u8,
    characteristics: u32,
    raw_ptr_override: Option<u32>,
}

impl SectionSpec {
    fn new(name: impl Into<String>, virtual_size: u32, raw_size: u32) -> Self {
        Self {
            name: name.into(),
            virtual_size,
            declared_raw_size: raw_size,
            body_len: raw_size as usize,
            fill: 0x41,
            characteristics: 0x6000_0020, // CODE | MEM_EXECUTE | MEM_READ
            raw_ptr_override: None,
        }
    }

    fn body_len(mut self, n: usize) -> Self {
        self.body_len = n;
        self
    }

    fn fill(mut self, b: u8) -> Self {
        self.fill = b;
        self
    }

    fn characteristics(mut self, c: u32) -> Self {
        self.characteristics = c;
        self
    }

    fn raw_ptr_override(mut self, ptr: u32) -> Self {
        self.raw_ptr_override = Some(ptr);
        self
    }
}

/// Minimal-PE fixture builder (PE32, e_lfanew 0x80, machine 0x14C, entry
/// 0x1000, SizeOfImage 0x4000, 16 data directories — same defaults as the
/// lib-side builder so detector behavior is identical).
struct PeBuilder {
    sections: Vec<SectionSpec>,
    section_count_override: Option<u16>,
    overlay: Vec<u8>,
}

impl PeBuilder {
    fn new() -> Self {
        Self {
            sections: Vec::new(),
            section_count_override: None,
            overlay: Vec::new(),
        }
    }

    fn section(self, name: &str, virtual_size: u32, raw_size: u32) -> Self {
        self.add_section(SectionSpec::new(name, virtual_size, raw_size))
    }

    fn add_section(mut self, spec: SectionSpec) -> Self {
        self.sections.push(spec);
        self
    }

    fn section_count_override(mut self, n: u16) -> Self {
        self.section_count_override = Some(n);
        self
    }

    fn overlay(mut self, bytes: &[u8]) -> Self {
        self.overlay = bytes.to_vec();
        self
    }

    fn build(self) -> Vec<u8> {
        let size_of_optional: u16 = 224; // PE32
        let e_lfanew = 0x80usize;
        let mut buf = vec![0u8; e_lfanew];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());

        let declared_count = self
            .section_count_override
            .unwrap_or(self.sections.len() as u16);

        buf.extend_from_slice(b"PE\0\0");
        buf.extend_from_slice(&0x14Cu16.to_le_bytes()); // i386
        buf.extend_from_slice(&declared_count.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        buf.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        buf.extend_from_slice(&size_of_optional.to_le_bytes());
        buf.extend_from_slice(&0x0102u16.to_le_bytes()); // EXECUTABLE | 32BIT

        let opt_start = buf.len();
        buf.resize(opt_start + usize::from(size_of_optional), 0);
        let opt_put = |buf: &mut [u8], off: usize, bytes: &[u8]| {
            buf[opt_start + off..opt_start + off + bytes.len()].copy_from_slice(bytes);
        };
        opt_put(&mut buf, 0, &0x10Bu16.to_le_bytes()); // PE32 magic
        opt_put(&mut buf, 16, &0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        opt_put(&mut buf, 56, &0x4000u32.to_le_bytes()); // SizeOfImage
        opt_put(&mut buf, 92, &16u32.to_le_bytes()); // NumberOfRvaAndSizes

        let mut raw_cursor = buf.len() + self.sections.len() * 40;
        let mut vaddr_cursor = 0x1000u32;
        let mut raw_ptrs = Vec::with_capacity(self.sections.len());
        for spec in &self.sections {
            let raw_ptr = spec.raw_ptr_override.unwrap_or(raw_cursor as u32);
            raw_ptrs.push(raw_ptr);
            raw_cursor = raw_cursor.max(raw_ptr as usize + spec.body_len);
            let vaddr = vaddr_cursor;
            vaddr_cursor = vaddr
                .saturating_add(spec.virtual_size)
                .saturating_add(0xFFF)
                & !0xFFF;

            let mut entry = [0u8; 40];
            let name_bytes = spec.name.as_bytes();
            let n = name_bytes.len().min(8);
            entry[..n].copy_from_slice(&name_bytes[..n]);
            entry[8..12].copy_from_slice(&spec.virtual_size.to_le_bytes());
            entry[12..16].copy_from_slice(&vaddr.to_le_bytes());
            entry[16..20].copy_from_slice(&spec.declared_raw_size.to_le_bytes());
            entry[20..24].copy_from_slice(&raw_ptr.to_le_bytes());
            entry[36..40].copy_from_slice(&spec.characteristics.to_le_bytes());
            buf.extend_from_slice(&entry);
        }

        for (spec, &raw_ptr) in self.sections.iter().zip(&raw_ptrs) {
            let start = raw_ptr as usize;
            let end = start + spec.body_len;
            if buf.len() < end {
                buf.resize(end, 0);
            }
            for b in &mut buf[start..end] {
                *b = spec.fill;
            }
        }

        buf.extend_from_slice(&self.overlay);
        buf
    }
}

/// Patch a little-endian u32 in a built fixture.
fn patch_u32_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
}

// ═══════════════════════════════════════════════════════════════
//  Framework-structure helpers (mirror the detectors' own fixture
//  patterns — NSIS firstheader, Inno offset table, Burn section)
// ═══════════════════════════════════════════════════════════════

/// Standard zlib CRC-32 (reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF).
fn crc32(buf: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The 16-byte NSIS archive signature at firstheader+4.
const NSIS_SIGNATURE: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
    b't',
];
const NSIS_FIRSTHEADER_LEN: u32 = 28;
const NSIS_FH_NO_CRC: u32 = 4;

fn nsis_firstheader(flags: u32, header_len: u32, arc_size: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    v.extend_from_slice(b"NullsoftInst");
    v.extend_from_slice(&header_len.to_le_bytes());
    v.extend_from_slice(&arc_size.to_le_bytes());
    v
}

/// A minimal PE whose overlay starts at 512-aligned 0x400 (section raw body
/// occupies [0x200, 0x400)), carrying `overlay`.
fn pe_with_aligned_overlay(overlay: &[u8]) -> Vec<u8> {
    PeBuilder::new()
        .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
        .overlay(overlay)
        .build()
}

const ALIGNED_OVERLAY_START: usize = 0x400;

/// Structurally valid NSIS overlay (firstheader + payload, NO_CRC).
fn nsis_overlay_no_crc(payload_len: u32) -> Vec<u8> {
    let arc_size = NSIS_FIRSTHEADER_LEN + payload_len;
    let mut v = nsis_firstheader(NSIS_FH_NO_CRC, 0x100, arc_size);
    v.extend(std::iter::repeat_n(0xCC, payload_len as usize));
    v
}

/// Structurally valid NSIS PE with a CORRECT CRC trailer.
fn nsis_pe_with_crc(payload_len: u32) -> Vec<u8> {
    let arc_size = NSIS_FIRSTHEADER_LEN + payload_len + 4;
    let mut overlay = nsis_firstheader(0, 0x100, arc_size);
    overlay.extend(std::iter::repeat_n(0xCC, payload_len as usize));
    overlay.extend_from_slice(&[0u8; 4]); // CRC placeholder
    let mut data = pe_with_aligned_overlay(&overlay);
    let crc_end = ALIGNED_OVERLAY_START + arc_size as usize - 4;
    let computed = crc32(&data[0x200..crc_end]);
    data[crc_end..crc_end + 4].copy_from_slice(&computed.to_le_bytes());
    data
}

/// `SetupLdrOffsetTableID`: 'rDlPtS' + CD E6 D7 7B 0B 2A.
const INNO_LDR_TABLE_ID: [u8; 12] = [
    b'r', b'D', b'l', b'P', b't', b'S', 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A,
];
const INNO_V2_RECORD_LEN: usize = 64;

/// Write a CRC-valid v2 TSetupLdrOffsetTable into `buf` at `off`.
fn inno_write_table_v2(
    buf: &mut [u8],
    off: usize,
    total_size: u64,
    offset_exe: u64,
    offset0: u64,
    offset1: u64,
) {
    let mut rec = vec![0u8; INNO_V2_RECORD_LEN];
    rec[..12].copy_from_slice(&INNO_LDR_TABLE_ID);
    rec[12..16].copy_from_slice(&2u32.to_le_bytes()); // version 2
    rec[16..24].copy_from_slice(&total_size.to_le_bytes());
    rec[24..32].copy_from_slice(&offset_exe.to_le_bytes());
    rec[40..48].copy_from_slice(&offset0.to_le_bytes());
    rec[48..56].copy_from_slice(&offset1.to_le_bytes());
    let crc = crc32(&rec[..INNO_V2_RECORD_LEN - 4]);
    rec[INNO_V2_RECORD_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    buf[off..off + INNO_V2_RECORD_LEN].copy_from_slice(&rec);
}

fn inno_setup_id(version: &str) -> [u8; 64] {
    let mut id = [0u8; 64];
    let s = format!("Inno Setup Setup Data ({version})");
    id[..s.len()].copy_from_slice(s.as_bytes());
    id
}

/// A coherent Inno-like fixture: `.text` + zeroed `.rsrc` + overlay laid out
/// as [embedded file data][64-byte SetupID][setup-0 payload][setup.e32], with
/// the v2 offset table written into `.rsrc`. Mirrors inno.rs's own fixture.
fn inno_pe() -> Vec<u8> {
    let mut overlay = Vec::new();
    overlay.extend_from_slice(&[0x61; 32]); // embedded setup-1 file data
    let off0_in_overlay = overlay.len() as u64;
    overlay.extend_from_slice(&inno_setup_id("6.5.0"));
    overlay.extend_from_slice(&[0x62; 100]); // rest of setup-0
    let offexe_in_overlay = overlay.len() as u64;
    overlay.extend_from_slice(&[0x63; 50]); // compressed setup.e32

    let mut data = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
        .overlay(&overlay)
        .build();
    let pe = pe::parse(&data).expect("fixture must parse");
    let rsrc = pe
        .sections
        .iter()
        .find(|s| s.name == ".rsrc")
        .expect("fixture has .rsrc");
    let table_off = u64::from(rsrc.raw_ptr) + 0x20;
    let overlay_start = pe.overlay_start;
    let total_size = data.len() as u64;
    inno_write_table_v2(
        &mut data,
        table_off as usize,
        total_size,                        // TotalSize == file size
        overlay_start + offexe_in_overlay, // OffsetEXE
        overlay_start + off0_in_overlay,   // Offset0 (setup data)
        overlay_start,                     // Offset1 (embedded files)
    );
    data
}

// Burn (.wixburn) header field offsets.
const BURN_OFF_MAGIC: usize = 0x00;
const BURN_OFF_VERSION: usize = 0x04;
const BURN_OFF_STUB_SIZE: usize = 0x18;
const BURN_OFF_FORMAT: usize = 0x28;
const BURN_OFF_COUNT: usize = 0x2C;
const BURN_OFF_SIZES: usize = 0x30;
const BURN_MAGIC: u32 = 0x00F1_4300;
const BURN_VERSION: u32 = 2;
const BURN_FORMAT_CABINET: u32 = 1;

/// A coherent synthetic WiX Burn bundle: valid `.wixburn` section header and
/// an "MSCF" cabinet at `dwStubSize`. Returns (file, .wixburn body offset).
fn burn_pe() -> (Vec<u8>, usize) {
    let mut overlay = vec![0u8; 0x80];
    overlay[..4].copy_from_slice(b"MSCF");
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
    patch_u32_le(&mut data, base + BURN_OFF_MAGIC, BURN_MAGIC);
    patch_u32_le(&mut data, base + BURN_OFF_VERSION, BURN_VERSION);
    patch_u32_le(&mut data, base + BURN_OFF_STUB_SIZE, stub);
    patch_u32_le(&mut data, base + BURN_OFF_FORMAT, BURN_FORMAT_CABINET);
    patch_u32_le(&mut data, base + BURN_OFF_COUNT, 1);
    patch_u32_le(&mut data, base + BURN_OFF_SIZES, ux_len);
    (data, base)
}

// ═══════════════════════════════════════════════════════════════
//  Deterministic PRNG (xorshift64*) — no rand crate, no thread_rng;
//  fixed seeds make every sweep reproducible.
// ═══════════════════════════════════════════════════════════════

struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        // Never allow the zero state (xorshift fixed point).
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

// ═══════════════════════════════════════════════════════════════
//  Assertion helpers
// ═══════════════════════════════════════════════════════════════

/// The core spoof-resistance assertion: nothing attacker-planted may exceed
/// WeakHint confidence, and nothing about it may be mitigation-safe.
fn assert_spoof_neutralized(d: &FrameworkDetection, ctx: &str) {
    assert!(
        d.confidence() <= Confidence::WeakHint,
        "{ctx}: expected <= WeakHint, got {:?} (kind {:?})",
        d.confidence(),
        d.kind()
    );
    assert!(
        !d.mitigation_safe(),
        "{ctx}: planted markers must never be mitigation-safe (kind {:?})",
        d.kind()
    );
}

fn assert_structural_safe(d: &FrameworkDetection, kind: FrameworkKind, ctx: &str) {
    assert_eq!(d.kind(), kind, "{ctx}");
    assert_eq!(d.confidence(), Confidence::Structural, "{ctx}");
    assert!(d.mitigation_safe(), "{ctx}: structural detection must be safe");
    assert!(
        d.evidence().iter().any(|e| e.source.is_structural()),
        "{ctx}: structural detection must cite structural evidence"
    );
}

// ═══════════════════════════════════════════════════════════════
//  TASK 1 — ADVERSARIAL FIXTURE SUITE
//  Each test: fixture → detector result + confidence + mitigation
//  eligibility (+ evidence provenance where relevant).
// ═══════════════════════════════════════════════════════════════

/// Clean minimal PE: no framework, no confidence, never safe.
#[test]
fn clean_minimal_pe_is_unknown_and_not_safe() {
    let data = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .overlay(b"ordinary overlay bytes")
        .build();
    let d = detect(&data, "app.exe");
    assert_eq!(d.kind(), FrameworkKind::Unknown);
    assert_eq!(d.confidence(), Confidence::Unknown);
    assert!(!d.mitigation_safe());
    assert!(d.evidence().is_empty());
}

/// Marker planted in .text — the classic score-collapse primitive.
#[test]
fn nsis_marker_in_text_section_is_spoof_neutralized() {
    let mut data = pe_with_aligned_overlay(&[0x22; 128]);
    // Section body occupies [0x200, 0x400).
    data[0x280..0x290].copy_from_slice(&NSIS_SIGNATURE);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "NSIS signature in .text");
    // If a hint is reported at all, it must cite ONLY non-structural evidence.
    for e in d.evidence() {
        assert!(
            !e.source.is_structural(),
            "text-plant cited structural evidence: {:?}",
            e.source
        );
    }
}

/// Inno text marker planted in .rdata.
#[test]
fn inno_text_marker_in_rdata_is_spoof_neutralized() {
    let mut data = PeBuilder::new()
        .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
        .add_section(SectionSpec::new(".rdata", 0x200, 0x200).raw_ptr_override(0x400))
        .overlay(&[0x11; 64])
        .build();
    data[0x480..0x48A].copy_from_slice(b"Inno Setup");
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "'Inno Setup' text in .rdata");
}

/// NSIS archive signature planted in .rsrc raw data.
#[test]
fn nsis_marker_in_rsrc_section_is_spoof_neutralized() {
    let mut data = PeBuilder::new()
        .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
        .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).raw_ptr_override(0x600))
        .overlay(&[0x33; 64])
        .build();
    data[0x640..0x650].copy_from_slice(&NSIS_SIGNATURE);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "NSIS signature in .rsrc");
}

/// Marker planted in the debug/header slack region (between the section
/// table and the first section body — dead header bytes, "debug data"
/// grade: parsed by nobody, attacker-writable).
#[test]
fn marker_in_header_slack_is_spoof_neutralized() {
    let mut data = pe_with_aligned_overlay(&[0x44; 64]);
    // Headers end at 0x1A0; slack up to the section body at 0x200.
    data[0x1B0..0x1C0].copy_from_slice(&NSIS_SIGNATURE);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "NSIS signature in header slack");
}

/// Marker at an unaligned offset inside an arbitrary overlay.
#[test]
fn marker_in_arbitrary_overlay_unaligned_is_spoof_neutralized() {
    let mut overlay = vec![0x77; 300];
    overlay[101..117].copy_from_slice(&NSIS_SIGNATURE); // offset 0x400+101: unaligned
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "unaligned NSIS signature in overlay");
}

/// Every marker in one malformed PE (e_lfanew past EOF): parsing fails
/// closed, no detector runs, no legacy hint upgrades anything.
#[test]
fn all_markers_in_one_malformed_pe_is_spoof_neutralized() {
    let mut data = pe_with_aligned_overlay(&nsis_overlay_no_crc(128));
    // Stuff every textual marker somewhere in the section body.
    data[0x220..0x22A].copy_from_slice(b"Inno Setup");
    data[0x240..0x251].copy_from_slice(b"Windows Installer");
    data[0x260..0x268].copy_from_slice(b".wixburn");
    // Break the PE: e_lfanew past EOF — header parsing must fail closed.
    let past_eof = data.len() as u32 + 0x1000;
    patch_u32_le(&mut data, 0x3C, past_eof);
    assert!(pe::parse(&data).is_none(), "fixture must be unparseable");
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "all markers in malformed PE");
}

/// Fake NSIS marker + packer-like structure (a high-entropy section with
/// no imports worth speaking of): detection stays WeakHint-grade. The
/// scoring half (mitigation must NOT divide the packer findings) is
/// asserted lib-side in engine/adversarial.rs.
#[test]
fn fake_nsis_plus_packer_like_structure_is_spoof_neutralized() {
    // High-entropy .text (seeded random fill — deterministic), few imports
    // (empty import directory by construction), NSIS marker planted inside.
    let mut rng = XorShift::new(0xBA55_BAAD);
    let entropy = rng.bytes(0x400);
    let mut data = PeBuilder::new()
        .add_section(
            SectionSpec::new(".text", 0x400, 0x400)
                .raw_ptr_override(0x200)
                .characteristics(0xE000_0020), // CODE|EXEC|READ|WRITE — packer-like
        )
        .overlay(&[0x55; 0x200])
        .build();
    data[0x200..0x600].copy_from_slice(&entropy);
    data[0x300..0x310].copy_from_slice(&NSIS_SIGNATURE);
    let d = detect(&data, "packed_setup.exe");
    assert_spoof_neutralized(&d, "NSIS marker in packer-like PE");
}

/// Fake Inno marker — the detection-level half of the veto fixture
/// (malicious-YARA-evidence veto is asserted lib-side).
#[test]
fn fake_inno_marker_is_spoof_neutralized() {
    let mut overlay = b"prefix Inno Setup S trailing".to_vec();
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "Inno text marker in overlay");
}

/// 'Windows Installer' text with no Burn structure: WiX text-hint parity
/// path — WeakHint by construction, never safe.
#[test]
fn windows_installer_text_without_structure_is_weak_hint_only() {
    let mut overlay = b"this app uses Windows Installer technology".to_vec();
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert_eq!(d.kind(), FrameworkKind::WixBurn);
    assert_eq!(d.confidence(), Confidence::WeakHint);
    assert!(!d.mitigation_safe());
    assert!(
        d.evidence()
            .iter()
            .all(|e| e.source == EvidenceSource::TextHint)
    );
}

/// Truncated overlay: full 16-byte signature visible but the firstheader
/// is cut short — must not reach Structural.
#[test]
fn truncated_overlay_firstheader_is_spoof_neutralized() {
    let overlay = &nsis_firstheader(NSIS_FH_NO_CRC, 0x100, 128)[..24];
    let data = pe_with_aligned_overlay(overlay);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "truncated firstheader");
}


/// Oversized offsets: declared archive size / Inno Offset0 far past EOF.
#[test]
fn oversized_offsets_are_rejected() {
    // NSIS: ArcSize = INT32_MAX against a small overlay.
    let mut overlay = nsis_firstheader(NSIS_FH_NO_CRC, 0x100, 0x7FFF_FFFF);
    overlay.extend_from_slice(&[0x55; 256]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "NSIS ArcSize = INT32_MAX");
    assert!(
        d.warnings().iter().any(|w| w.contains("past EOF")),
        "oversized ArcSize must be diagnosed: {:?}",
        d.warnings()
    );

    // Inno: CRC-valid table whose Offset0 points far past EOF (incoherent).
    let mut data = inno_pe();
    let pe = pe::parse(&data).unwrap();
    let rsrc = pe.sections.iter().find(|s| s.name == ".rsrc").unwrap();
    let table_off = u64::from(rsrc.raw_ptr) + 0x20;
    let total_size = data.len() as u64;
    inno_write_table_v2(
        &mut data,
        table_off as usize,
        total_size,
        0x400,                   // OffsetEXE (plausible)
        u64::from(u32::MAX) * 2, // Offset0 far past EOF
        0,                       // Offset1
    );
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "Inno Offset0 past EOF");
}

/// Integer-overflow header fields (u32::MAX raw ranges) cannot wrap the
/// overlay computation, panic, or become mitigation-safe. The u32::MAX
/// values are PATCHED into the section header after building (the builder
/// physically backs declared raw ranges with body bytes — declaring
/// u32::MAX through it would allocate ~4 GiB of fixture).
#[test]
fn integer_overflow_section_fields_fail_safe() {
    let mut data = PeBuilder::new()
        .section(".text", 0x100, 0x100)
        .section(".evil", 0x100, 0x100)
        .overlay(&nsis_overlay_no_crc(64))
        .build();
    // Section table starts at e_lfanew+4+20+224 = 0x178; entry 1 at 0x1A0;
    // SizeOfRawData at +16, PointerToRawData at +20.
    patch_u32_le(&mut data, 0x1A0 + 16, u32::MAX);
    patch_u32_le(&mut data, 0x1A0 + 20, u32::MAX);
    let pe = pe::parse(&data).expect("must not reject; must not panic");
    // u32::MAX + u32::MAX widened to u64 and clamped to EOF: the overlay
    // shrinks to nothing, so the appended NSIS bytes are NOT an overlay.
    assert_eq!(pe.overlay_len, 0);
    assert!(pe.warnings.iter().any(|w| w.contains("past EOF")));
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "u32::MAX section fields");
}

/// Overlapping sections are flagged (warning) but parsing continues; a
/// planted marker in the shared range still earns nothing.
#[test]
fn overlapping_sections_are_flagged_and_markers_stay_weak() {
    let mut data = PeBuilder::new()
        .add_section(SectionSpec::new(".a", 0x100, 0x200).raw_ptr_override(0x400))
        .add_section(SectionSpec::new(".b", 0x100, 0x200).raw_ptr_override(0x500))
        .overlay(&[0x66; 64])
        .build();
    let pe = pe::parse(&data).unwrap();
    assert!(
        pe.warnings.iter().any(|w| w.contains("overlapping")),
        "overlap must be diagnosed: {:?}",
        pe.warnings
    );
    // Plant the signature in the mutually-claimed range.
    data[0x520..0x530].copy_from_slice(&NSIS_SIGNATURE);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "marker in overlapping section range");
}

/// Invalid section raw ranges (declared past EOF) are clamped, diagnosed,
/// and never smuggle bytes into a phantom overlay.
#[test]
fn invalid_section_raw_ranges_clamp_fail_safe() {
    let data = PeBuilder::new()
        .section(".text", 0x100, 0x100)
        .add_section(SectionSpec::new(".fat", 0x100, 0x10_000).body_len(0x100))
        .overlay(&nsis_overlay_no_crc(64))
        .build();
    let pe = pe::parse(&data).unwrap();
    assert!(pe.warnings.iter().any(|w| w.contains("past EOF")));
    // Clamped to EOF → the "overlay" after the truncated section is gone.
    assert_eq!(pe.overlay_len, 0);
    let d = detect(&data, "setup.exe");
    assert_spoof_neutralized(&d, "declared range past EOF");
}

/// Structural invariant: the overlay can NEVER begin inside a section —
/// overlay_start is the max over section raw ends by construction.
/// Sweeps several layouts including adversarial table orderings.
#[test]
fn overlay_never_begins_inside_a_section() {
    let fixtures = [
        PeBuilder::new()
            .add_section(SectionSpec::new(".late", 0x100, 0x100).raw_ptr_override(0x600))
            .add_section(SectionSpec::new(".early", 0x100, 0x100).raw_ptr_override(0x400))
            .overlay(&[0x11; 32])
            .build(),
        PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .section(".rdata", 0x100, 0x100)
            .overlay(&[0x22; 64])
            .build(),
        PeBuilder::new()
            .add_section(SectionSpec::new(".a", 0x80, 0x80).raw_ptr_override(0x300))
            .add_section(SectionSpec::new(".b", 0x80, 0x200).raw_ptr_override(0x380))
            .overlay(&[0x33; 16])
            .build(),
    ];
    for (i, data) in fixtures.iter().enumerate() {
        let pe = pe::parse(data).expect("fixture must parse");
        for s in &pe.sections {
            if s.raw_size == 0 {
                continue;
            }
            let end = (u64::from(s.raw_ptr) + u64::from(s.raw_size)).min(data.len() as u64);
            assert!(
                pe.overlay_start >= end,
                "fixture {i}: overlay 0x{:X} begins inside section '{}' (ends 0x{end:X})",
                pe.overlay_start,
                s.name
            );
        }
    }
}

/// Duplicate/contradictory headers: the FIRST structural claim is the one
/// the format's own loader would use; contradictions downgrade, never
/// upgrade.
#[test]
fn duplicate_and_contradictory_headers_never_upgrade() {
    // NSIS: two valid firstheaders — the first (lowest offset) wins,
    // deterministically.
    let mut overlay = nsis_overlay_no_crc(64);
    overlay.resize(512, 0x77);
    overlay.extend_from_slice(&nsis_overlay_no_crc(32));
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(
        d.evidence()
            .iter()
            .filter(|e| e.source == EvidenceSource::Overlay)
            .all(|e| e.offset == Some(ALIGNED_OVERLAY_START as u64)),
        "first candidate must win: {:?}",
        d.evidence()
    );

    // Burn: a garbage .wixburn FIRST and a valid one second — the Burn
    // engine scans for the first section with that name, so the
    // contradiction caps at WeakHint even though a valid header exists
    // deeper in the file.
    let (valid, _) = burn_pe();
    let pe = pe::parse(&valid).unwrap();
    let overlay_bytes = valid[pe.overlay_start as usize..].to_vec();
    let mut rebuilt = PeBuilder::new()
        .section(".text", 0x100, 0x100)
        .add_section(SectionSpec::new(".wixburn", 0x200, 0x200).fill(0x41)) // garbage
        .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
        .overlay(&overlay_bytes)
        .build();
    // Copy the VALID header into the SECOND .wixburn section and re-point
    // its stub size at the rebuilt overlay.
    let first_base = pe
        .sections
        .iter()
        .find(|s| s.name == ".wixburn")
        .unwrap()
        .raw_ptr as usize;
    let body: Vec<u8> = valid[first_base..first_base + 0x40].to_vec();
    let pe2 = pe::parse(&rebuilt).unwrap();
    let second_base = pe2
        .sections
        .iter()
        .filter(|s| s.name == ".wixburn")
        .nth(1)
        .unwrap()
        .raw_ptr as usize;
    rebuilt[second_base..second_base + 0x40].copy_from_slice(&body);
    patch_u32_le(
        &mut rebuilt,
        second_base + BURN_OFF_STUB_SIZE,
        pe2.overlay_start as u32,
    );
    let d = detect(&rebuilt, "bundle.exe");
    assert_spoof_neutralized(&d, "garbage-first duplicate .wixburn");
}

/// Representative structural NSIS — dispatch-level positive control.
#[test]
fn structural_nsis_is_detected_and_mitigation_safe() {
    let data = nsis_pe_with_crc(200);
    let d = detect(&data, "setup.exe");
    assert_structural_safe(&d, FrameworkKind::Nsis, "structural NSIS");
    assert!(
        d.evidence().iter().any(|e| e.detail.contains("CRC32 verified")),
        "evidence: {:?}",
        d.evidence()
    );
}

/// Representative structural Inno — dispatch-level positive control.
#[test]
fn structural_inno_is_detected_and_mitigation_safe() {
    let data = inno_pe();
    let d = detect(&data, "setup.exe");
    assert_structural_safe(&d, FrameworkKind::InnoSetup, "structural Inno");
    assert!(
        d.evidence().iter().any(|e| e.source == EvidenceSource::Resource),
        "evidence: {:?}",
        d.evidence()
    );
}

/// Representative structural WiX Burn — dispatch-level positive control.
#[test]
fn structural_burn_is_detected_and_mitigation_safe() {
    let (data, base) = burn_pe();
    let d = detect(&data, "bundle.exe");
    assert_structural_safe(&d, FrameworkKind::WixBurn, "structural Burn");
    assert!(
        d.evidence().iter().any(|e| e.offset == Some(base as u64)),
        "evidence must cite the .wixburn body: {:?}",
        d.evidence()
    );
}

/// Installer-shaped file with independent malicious indicators: at the
/// DETECTION level the structure is still genuinely NSIS (detection is
/// content-independent); the IoC-weight veto that keeps the score high is
/// asserted lib-side in engine/adversarial.rs.
#[test]
fn installer_structure_with_ioc_indicators_still_detects_structurally() {
    let data = nsis_pe_with_crc(200);
    let d = detect(&data, "setup.exe");
    assert_structural_safe(&d, FrameworkKind::Nsis, "structural NSIS (IoC veto is engine-side)");
}

/// Signed ordinary software carrying installer terminology: an ordinary PE
/// with "Windows Installer" strings and an installer-ish name but no
/// framework structure — WeakHint at most, no mitigation.
#[test]
fn ordinary_software_with_installer_terminology_is_weak_hint_at_most() {
    let mut overlay = b"Windows Installer is required. uninstall support included.".to_vec();
    overlay.extend_from_slice(&[0u8; 128]);
    let data = pe_with_aligned_overlay(&overlay);
    // Small file: the name+size+body-hint legacy heuristic cannot fire.
    let d = detect(&data, "MyApp_setup.exe");
    assert_spoof_neutralized(&d, "ordinary app with installer terminology");

    // Large variant: name + generic body hint + size → the legacy heuristic
    // fires — but it is WeakHint BY CONSTRUCTION, still never safe.
    let mut big = PeBuilder::new().section(".text", 0x200, 0x200).build();
    big.resize(2_500_000, 0u8);
    big.extend_from_slice(b"uninstall");
    let d = detect(&big, "MyApp_setup.exe");
    assert_eq!(d.kind(), FrameworkKind::GenericFramework);
    assert_eq!(d.confidence(), Confidence::WeakHint);
    assert!(!d.mitigation_safe());
}

/// Polyglot: MZ + PDF — a PE that is also a PDF payload. The PDF part is
/// decoration; planted markers inside it earn nothing.
#[test]
fn polyglot_mz_pdf_is_spoof_neutralized() {
    let mut overlay = b"%PDF-1.7\n1 0 obj\n<<>>\n".to_vec();
    overlay.extend_from_slice(&NSIS_SIGNATURE);
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "invoice.exe");
    assert_spoof_neutralized(&d, "MZ+PDF polyglot with planted NSIS signature");
}

/// Polyglot: MZ + ZIP — overlay begins (512-aligned) with a ZIP local
/// header; the ZIP structure is not an NSIS firstheader and must not
/// become one.
#[test]
fn polyglot_mz_zip_is_spoof_neutralized() {
    let mut overlay = Vec::new();
    overlay.extend_from_slice(b"PK\x03\x04"); // ZIP local file header
    overlay.extend_from_slice(&[0u8; 60]);
    overlay.extend_from_slice(&NSIS_SIGNATURE); // planted deeper, unaligned
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "archive.exe");
    assert_spoof_neutralized(&d, "MZ+ZIP polyglot");
}

// ═══════════════════════════════════════════════════════════════
//  TASK 2 — METAMORPHIC / PROPERTY TESTS (detection level)
//  Each maps to one invariant from the brief; the score-level half
//  of each lives lib-side in engine/adversarial.rs.
// ═══════════════════════════════════════════════════════════════

/// M1 (detection half): appending arbitrary installer text to ANY file
/// cannot raise confidence above WeakHint. Sweep: every marker × several
/// carrier files. The score half (cannot LOWER the threat score) is
/// engine-side.
#[test]
fn m1_appending_installer_text_never_raises_confidence() {
    let markers: [&[u8]; 6] = [
        b"Nullsoft Inst",
        &NSIS_SIGNATURE,
        b"Inno Setup",
        b"Windows Installer",
        b".wixburn",
        b"InnoSetupLdr",
    ];
    let carriers: Vec<Vec<u8>> = vec![
        PeBuilder::new().section(".text", 0x200, 0x200).build(),
        pe_with_aligned_overlay(&[0x99; 256]),
        PeBuilder::new()
            .section(".text", 0x100, 0x100)
            .section(".rdata", 0x100, 0x100)
            .build(),
    ];
    for (ci, carrier) in carriers.iter().enumerate() {
        for (mi, marker) in markers.iter().enumerate() {
            let mut data = carrier.clone();
            data.extend_from_slice(marker);
            let d = detect(&data, "setup.exe");
            assert!(
                d.confidence() <= Confidence::WeakHint,
                "carrier {ci} + marker {mi}: {:?} (kind {:?})",
                d.confidence(),
                d.kind()
            );
            assert!(!d.mitigation_safe(), "carrier {ci} + marker {mi}");
        }
    }
}

/// M2: moving a valid marker OUTSIDE its structural region cannot preserve
/// high confidence — for every framework.
#[test]
fn m2_moving_marker_outside_structural_region_loses_confidence() {
    // NSIS: valid firstheader at the aligned overlay start = Structural...
    let good = pe_with_aligned_overlay(&nsis_overlay_no_crc(200));
    assert_eq!(detect(&good, "s.exe").confidence(), Confidence::Structural);
    // ...shifted one byte deeper (unaligned) = gone.
    let mut overlay = vec![0u8; 1];
    overlay.extend_from_slice(&nsis_overlay_no_crc(200));
    let moved = pe_with_aligned_overlay(&overlay);
    let d = detect(&moved, "s.exe");
    assert!(d.confidence() < Confidence::Structural);
    assert!(!d.mitigation_safe());

    // Inno: the SAME CRC-valid table bytes that validate inside .rsrc...
    let good = inno_pe();
    assert_eq!(detect(&good, "s.exe").confidence(), Confidence::Structural);
    // ...written into the overlay instead (wrong region) = WeakHint.
    let mut overlay = Vec::new();
    overlay.extend_from_slice(&[0x61; 32]);
    let off0_in_overlay = overlay.len() as u64;
    overlay.extend_from_slice(&inno_setup_id("6.5.0"));
    overlay.extend_from_slice(&[0x62; 100]);
    let offexe_in_overlay = overlay.len() as u64;
    overlay.extend_from_slice(&[0x63; 50]);
    let table_in_overlay_at = overlay.len() as u64;
    overlay.extend_from_slice(&[0u8; INNO_V2_RECORD_LEN]);
    let mut data = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
        .overlay(&overlay)
        .build();
    let pe = pe::parse(&data).unwrap();
    let overlay_start = pe.overlay_start;
    let total = data.len() as u64;
    inno_write_table_v2(
        &mut data,
        (overlay_start + table_in_overlay_at) as usize,
        total,
        overlay_start + offexe_in_overlay,
        overlay_start + off0_in_overlay,
        overlay_start,
    );
    let d = detect(&data, "s.exe");
    assert!(
        d.confidence() <= Confidence::WeakHint,
        "table in overlay: {:?}",
        d.confidence()
    );
    assert!(!d.mitigation_safe());
}

/// M3: truncating a valid structure cannot increase confidence — sweep
/// every cut point of a Structural Inno installer and a Structural Burn
/// bundle (the NSIS sweep exists detector-side; these cover the other two).
#[test]
fn m3_truncation_never_increases_confidence() {
    let inno = inno_pe();
    let full_conf = detect(&inno, "s.exe").confidence();
    assert_eq!(full_conf, Confidence::Structural);
    let rsrc_end = {
        let pe = pe::parse(&inno).unwrap();
        pe.sections
            .iter()
            .find(|s| s.name == ".rsrc")
            .map(|s| u64::from(s.raw_ptr))
            .unwrap()
    } as usize;
    // NOTE on the assertion shape: a truncated Inno installer can reach
    // Corroborated, and `FrameworkDetection::build` marks Corroborated +
    // structural evidence `mitigation_safe` — that flag is necessary but
    // NOT sufficient for mitigation. The barrier that matters is the
    // engine's policy-1 gate (Structural confidence required, tested
    // lib-side in engine/adversarial.rs), so here we assert exactly what
    // that gate consumes: no cut may PRESERVE Structural confidence.
    for cut in rsrc_end..inno.len() {
        let d = detect(&inno[..cut], "s.exe");
        assert!(
            d.confidence() < Confidence::Structural,
            "inno cut at {cut}: {:?}",
            d.confidence()
        );
    }

    let (burn, _) = burn_pe();
    assert_eq!(detect(&burn, "b.exe").confidence(), Confidence::Structural);
    for cut in 1..burn.len() {
        let d = detect(&burn[..cut], "b.exe");
        assert!(
            d.confidence() < Confidence::Structural,
            "burn cut at {cut}: {:?}",
            d.confidence()
        );
    }
}

/// M4 (detection half): adding independent malicious evidence to a valid
/// installer cannot make it SAFER. Detection is content-independent, so
/// the structure still detects as Structural; the score-level veto that
/// keeps the file unsafe is engine-side (engine/adversarial.rs).
#[test]
fn m4_malicious_evidence_does_not_change_detection_safety() {
    let data = nsis_pe_with_crc(200);
    let clean = detect(&data, "setup.exe");
    // Same bytes, scanned under a path that screams malware — detection
    // must be identical (path only feeds legacy WeakHint heuristics).
    let shady = detect(&data, "C:\\Temp\\crack_keygen_setup.exe");
    assert_eq!(clean.kind(), shady.kind());
    assert_eq!(clean.confidence(), shady.confidence());
    assert_eq!(clean.mitigation_safe(), shady.mitigation_safe());
}

/// M5 (detection half): multiple weak strings cannot stack into anything
/// above WeakHint — all frameworks' markers in ONE file at once.
#[test]
fn m5_multiple_weak_strings_cannot_stack() {
    let mut overlay = Vec::new();
    overlay.extend_from_slice(b"Nullsoft Inst");
    overlay.extend_from_slice(&NSIS_SIGNATURE);
    overlay.extend_from_slice(b"Inno Setup InnoSetupLdr");
    overlay.extend_from_slice(b"Windows Installer");
    overlay.extend_from_slice(b".wixburn");
    overlay.extend_from_slice(&INNO_LDR_TABLE_ID); // even the real table ID
    overlay.extend_from_slice(&[0u8; 128]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert!(
        d.confidence() <= Confidence::WeakHint,
        "stacked markers: {:?}",
        d.confidence()
    );
    assert!(!d.mitigation_safe());
}

/// M6 (detection half): parser failure cannot become mitigation_safe.
/// Every malformed-PE variant carrying a FULLY VALID NSIS archive must
/// fail closed. The scoring half (no mitigation applied) is engine-side.
#[test]
fn m6_parser_failure_never_becomes_mitigation_safe() {
    let archive = nsis_overlay_no_crc(200);
    let mut malformed: Vec<(&str, Vec<u8>)> = Vec::new();

    // e_lfanew past EOF.
    let mut d1 = pe_with_aligned_overlay(&archive);
    let past_eof = d1.len() as u32 + 0x1000;
    patch_u32_le(&mut d1, 0x3C, past_eof);
    malformed.push(("e_lfanew past EOF", d1));

    // e_lfanew = u32::MAX.
    let mut d2 = pe_with_aligned_overlay(&archive);
    patch_u32_le(&mut d2, 0x3C, u32::MAX);
    malformed.push(("e_lfanew = u32::MAX", d2));

    // Zero sections declared.
    let d3 = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .section_count_override(0)
        .overlay(&archive)
        .build();
    malformed.push(("zero sections", d3));

    // Section count above the spec maximum (97 > 96).
    let d4 = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .section_count_override(97)
        .overlay(&archive)
        .build();
    malformed.push(("97 sections", d4));

    // Truncated section table.
    let d5_full = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .overlay(&archive)
        .build();
    let cut = pe::parse(&d5_full).unwrap().headers_end as usize - 2;
    malformed.push(("truncated section table", d5_full[..cut].to_vec()));

    // Not a PE at all.
    let mut d6 = b"NO".to_vec();
    d6.extend_from_slice(&archive);
    malformed.push(("non-PE carrier", d6));

    for (name, data) in &malformed {
        let d = detect(data, "setup.exe");
        assert!(
            !d.mitigation_safe(),
            "{name}: parser failure became mitigation-safe"
        );
        assert!(
            d.confidence() <= Confidence::WeakHint,
            "{name}: {:?}",
            d.confidence()
        );
    }
}

/// M7: arbitrary bytes cannot panic any new parser — deterministic seeded
/// sweeps over `detect` AND `pe::parse` together (detect drives all three
/// framework detectors; pe::parse is the header parser). Assertions: no
/// panic, and the centralized invariant holds on every output
/// (mitigation_safe ⇒ Corroborated-or-better + structural evidence).
#[test]
fn m7_seeded_random_sweeps_never_panic_never_violate_invariant() {
    let mut rng = XorShift::new(0xC0FF_EE11_2233_4455);
    for i in 0..512 {
        let len = (rng.next() % 4096) as usize;
        let mut buf = rng.bytes(len);
        // Every third buffer is MZ-forced to reach the PE path; every
        // ninth gets a plausible e_lfanew so parsing goes deeper.
        if i % 3 == 0 && buf.len() >= 2 {
            buf[0] = b'M';
            buf[1] = b'Z';
        }
        if i % 9 == 0 && buf.len() >= 0x80 {
            let lfanew = (rng.next() % 0x40) as u32 + 0x40;
            buf[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
        }
        // pe::parse: total on any input.
        let _ = pe::parse(&buf);
        // detect: full dispatch, all detectors.
        let d = detect(&buf, "fuzz.exe");
        // The centralized invariant must hold for ANY bytes.
        if d.mitigation_safe() {
            assert!(d.confidence() >= Confidence::Corroborated);
            assert!(d.evidence().iter().any(|e| e.source.is_structural()));
        }
        // Confidence can never exceed Structural, kind/confidence coherence:
        if d.kind() == FrameworkKind::Unknown {
            assert_eq!(d.confidence(), Confidence::Unknown);
            assert!(!d.mitigation_safe());
        }
    }
}

/// M7b: mutation sweeps over VALID structural fixtures — single-byte
/// corruption of a genuine NSIS archive must never silently PRESERVE a
/// Structural verdict (every byte is either firstheader-critical or
/// CRC-covered), and must never panic.
#[test]
fn m7b_byte_mutation_of_structural_fixtures_never_panics() {
    let base = nsis_pe_with_crc(64);
    for off in ALIGNED_OVERLAY_START..base.len() {
        for val in [0x00u8, 0xFF, 0xEF, 0xDE] {
            if base[off] == val {
                continue;
            }
            let mut m = base.clone();
            m[off] = val;
            let d = detect(&m, "setup.exe");
            assert_ne!(
                d.confidence(),
                Confidence::Structural,
                "mutation at 0x{off:X} to 0x{val:02X} kept Structural"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  TASK 3 (smoke half) — SEED CORPUS REPLAY
//  Replays the committed cargo-fuzz seed corpus through the SAME
//  public entry points the fuzz harness uses, without requiring
//  cargo-fuzz / nightly. Seeds: fuzz/corpus/framework_detect/.
// ═══════════════════════════════════════════════════════════════

/// One replayed seed: bytes + the path it is scanned under.
struct Seed {
    name: &'static str,
    path: &'static str,
    bytes: &'static [u8],
}

const FRAMEWORK_SEEDS: &[Seed] = &[
    Seed {
        name: "seed00-minimal-pe",
        path: "app.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed00-minimal-pe.bin"),
    },
    Seed {
        name: "seed01-structural-nsis",
        path: "setup.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed01-structural-nsis.bin"),
    },
    Seed {
        name: "seed02-structural-inno",
        path: "setup.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed02-structural-inno.bin"),
    },
    Seed {
        name: "seed03-structural-burn",
        path: "bundle.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed03-structural-burn.bin"),
    },
    Seed {
        name: "seed04-spoofed-markers",
        path: "setup.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed04-spoofed-markers.bin"),
    },
    Seed {
        name: "seed05-malformed-all-markers",
        path: "setup.exe",
        bytes: include_bytes!(
            "../../../fuzz/corpus/framework_detect/seed05-malformed-all-markers.bin"
        ),
    },
    Seed {
        name: "seed06-polyglot-mz-zip",
        path: "archive.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed06-polyglot-mz-zip.bin"),
    },
    Seed {
        name: "seed07-random",
        path: "fuzz.exe",
        bytes: include_bytes!("../../../fuzz/corpus/framework_detect/seed07-random.bin"),
    },
];

/// Replay every seed through `pe::parse` + `detect` (the exact entry
/// points of the `framework_pe_parse` / `framework_detect` fuzz targets)
/// and assert the invariant bundle holds for each.
#[test]
fn seed_corpus_replays_cleanly() {
    assert!(
        FRAMEWORK_SEEDS.len() >= 8,
        "corpus shrank? regenerate with fuzz/tools/gen_framework_corpus.py"
    );
    for seed in FRAMEWORK_SEEDS {
        // pe::parse must be total.
        let _ = pe::parse(seed.bytes);
        // detect must be total and invariant-preserving.
        let d = detect(seed.bytes, seed.path);
        if d.mitigation_safe() {
            assert!(
                d.confidence() >= Confidence::Corroborated,
                "{}: safe without corroboration",
                seed.name
            );
            assert!(
                d.evidence().iter().any(|e| e.source.is_structural()),
                "{}: safe without structural evidence",
                seed.name
            );
        }
    }

    // Per-seed expectations (the corpus is fixed, so these are exact).
    let expectation = |name: &str| {
        let seed = FRAMEWORK_SEEDS.iter().find(|s| s.name == name).unwrap();
        detect(seed.bytes, seed.path)
    };
    let d = expectation("seed01-structural-nsis");
    assert_eq!(d.kind(), FrameworkKind::Nsis);
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    let d = expectation("seed02-structural-inno");
    assert_eq!(d.kind(), FrameworkKind::InnoSetup);
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    let d = expectation("seed03-structural-burn");
    assert_eq!(d.kind(), FrameworkKind::WixBurn);
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    // Spoof/malformed/polyglot/random seeds: never above WeakHint.
    for name in [
        "seed04-spoofed-markers",
        "seed05-malformed-all-markers",
        "seed06-polyglot-mz-zip",
        "seed07-random",
    ] {
        let d = expectation(name);
        assert!(
            d.confidence() <= Confidence::WeakHint,
            "{name}: {:?}",
            d.confidence()
        );
        assert!(!d.mitigation_safe(), "{name}");
    }
}

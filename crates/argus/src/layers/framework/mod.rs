//! Installer / bundle framework detection — structural evidence model.
//!
//! This module tree replaces the legacy `is_known_installer` substring scans
//! in `engine.rs` (unanchored `windows(needle)` searches over the whole file
//! buffer). Those scans were a confirmed spoof primitive: any attacker could
//! embed "Nullsoft Inst" / "Inno Setup S" / "Windows Installer" anywhere in a
//! file they fully control and earn the installer leniency discount
//! (Structural/Packer findings /3, installer-class YARA findings /2).
//!
//! The replacement is evidence-based: each framework detector (NSIS, Inno,
//! WiX — this wave ships the API with stub detectors; the detector bodies
//! land in the next wave) must cite *where* in the file structure its claim
//! comes from, and a single centralized rule decides whether that claim may
//! ever reduce suspicion.
//!
//! ## THE CENTRALIZED INVARIANT
//!
//! **Weak textual hints may be reported diagnostically, but must never by
//! themselves activate a security-reducing installer classification.**
//!
//! Concretely, [`FrameworkDetection::mitigation_safe`] is `true` only when
//! BOTH hold:
//!
//! 1. `confidence >= Confidence::Corroborated`, and
//! 2. `evidence` contains at least one item whose [`EvidenceSource`] is
//!    structural — i.e. anchored in parsed file structure (PE headers,
//!    section table, resources, overlay, imports, version info, or an
//!    embedded archive found at a structural offset). `TextHint` and
//!    `Filename` evidence NEVER counts, no matter how many items exist.
//!
//! The invariant is enforced in exactly one place —
//! [`FrameworkDetection::build`], the only constructor. `mitigation_safe` is
//! a private field with no setter, so no detector can assert it directly; a
//! detector that *claims* `Corroborated`/`Structural` confidence while
//! presenting only textual/filename evidence is silently downgraded to
//! `WeakHint` (and the downgrade is logged + recorded as a warning).
//!
//! ## Legacy hints
//!
//! The old substring heuristics for bundle frameworks (Electron, Go, Rust,
//! Qt, Squirrel, name+generic-hint, InstallShield/AdvancedInstaller marker
//! strings) are preserved in [`legacy_framework_hint`] so their diagnostic
//! value is not lost while the structural detectors are built out. They are
//! modeled as `WeakHint` confidence **by construction**, which means they are
//! never `mitigation_safe`. How (or whether) the score aggregator should
//! treat `WeakHint` detections is the scoring-integration wave's decision —
//! nothing in this module wires them to any mitigation.

#[cfg(test)]
pub(crate) mod fixtures;
pub(crate) mod inno;
pub(crate) mod nsis;
// WHY `pub`: the bounded header parser is exposed so the cargo-fuzz harness
// (`fuzz/fuzz_targets/framework_pe_parse.rs`, a separate crate) can drive
// `pe::parse` directly, not only through `detect`. It is a facts-only,
// total parser — exposing it grants no mitigation authority (that decision
// lives in `FrameworkDetection::build`, unchanged). The detectors and the
// test fixture builder stay crate-private.
pub mod pe;
pub(crate) mod wix;

/// The installer/bundle framework a file is built with, if any.
///
/// Used for two things: diagnostics (explanation strings) and — only when
/// the evidence justifies it — reducing the weight of findings that are
/// *expected* for that framework (large overlay, few imports, high entropy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameworkKind {
    /// Nullsoft Scriptable Install System.
    Nsis,
    /// Inno Setup.
    InnoSetup,
    /// WiX Burn bootstrapper bundle (bundle.exe hosting an attached container).
    WixBurn,
    /// Windows Installer database — an OLE2 compound file, not a PE.
    MsiOle2,
    /// InstallShield.
    InstallShield,
    /// Advanced Installer.
    AdvancedInstaller,
    /// Electron app bundle (ASAR archive).
    ElectronBundle,
    /// Go static binary (large, few imports, unusual sections — but not packed).
    GoStatic,
    /// Rust static binary (large, few imports — but not packed).
    RustStatic,
    /// Other recognized bundle/installer framework (Qt IFW, Squirrel, NW.js,
    /// Tauri, Flutter, Unity, Unreal, name+generic-hint) that has no dedicated
    /// structural detector.
    GenericFramework,
    /// No framework recognized.
    Unknown,
}

impl FrameworkKind {
    /// Stable human-readable name for explanations, provenance, and the
    /// `VerdictExplanation.framework` display field.
    pub fn label(self) -> &'static str {
        match self {
            FrameworkKind::Nsis => "NSIS",
            FrameworkKind::InnoSetup => "Inno Setup",
            FrameworkKind::WixBurn => "WiX Burn",
            FrameworkKind::MsiOle2 => "Windows Installer (MSI/OLE2)",
            FrameworkKind::InstallShield => "InstallShield",
            FrameworkKind::AdvancedInstaller => "Advanced Installer",
            FrameworkKind::ElectronBundle => "Electron",
            FrameworkKind::GoStatic => "Go (static)",
            FrameworkKind::RustStatic => "Rust (static)",
            FrameworkKind::GenericFramework => "Generic bundle framework",
            FrameworkKind::Unknown => "Unknown",
        }
    }
}

/// Where a piece of detection evidence was found.
///
/// The structural/non-structural split is the security-relevant property:
/// structural sources require the file to actually *be* built a certain way
/// (an attacker embedding them incurs the cost of shipping that structure,
/// and the anchors are at parsed offsets rather than free-floating text),
/// while `TextHint`/`Filename` are fully attacker-controlled decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    /// Parsed DOS/PE/COFF/optional headers (structural).
    PeHeaders,
    /// A parsed section-table entry — name, flags, or raw range (structural).
    SectionTable,
    /// A resource-directory entry at a parsed `.rsrc` offset (structural).
    Resource,
    /// The overlay — bytes past the end of the last section's raw range
    /// (structural).
    Overlay,
    /// The parsed import table (structural).
    Imports,
    /// A parsed VERSIONINFO resource field (structural).
    VersionInfo,
    /// An embedded archive/container magic found at a structural offset,
    /// e.g. inside the overlay or a specific resource (structural).
    EmbeddedArchive,
    /// An unanchored byte/string marker somewhere in the file buffer.
    /// **Not structural — attacker-controlled.**
    TextHint,
    /// The file name or extension. **Not structural — trivially forgeable.**
    Filename,
}

impl EvidenceSource {
    /// Whether this source is anchored in parsed file structure and may
    /// therefore count toward `mitigation_safe`. `TextHint` and `Filename`
    /// are the only non-structural sources; keep it that way unless a new
    /// source is genuinely attacker-unforgeable.
    pub fn is_structural(self) -> bool {
        !matches!(self, EvidenceSource::TextHint | EvidenceSource::Filename)
    }
}

/// How strongly the evidence supports the framework classification.
///
/// Ordered: `Unknown < WeakHint < Corroborated < Structural`.
/// The ordering is load-bearing — the centralized invariant compares
/// `confidence >= Confidence::Corroborated`.
///
/// - `Structural`: one strong structural anchor alone suffices
///   (e.g. an NSIS first-header struct at the exact overlay start).
/// - `Corroborated`: several weaker structural signals agree
///   (e.g. section name + resource string at parsed offsets).
/// - `WeakHint`: only non-structural signals (text markers, filename).
///   Diagnostically useful, never mitigation-authorizing.
/// - `Unknown`: nothing found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Unknown,
    WeakHint,
    Corroborated,
    Structural,
}

/// A single piece of evidence backing a framework classification.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    /// Where the evidence was found.
    pub source: EvidenceSource,
    /// Absolute file offset of the evidence, when it has one. `None` for
    /// evidence that has no single location (filename, aggregate signals).
    pub offset: Option<u64>,
    /// Human-readable description for the explanation/trace output.
    pub detail: String,
}

impl EvidenceItem {
    /// Construct an evidence item. `detail` should say *what* was found and
    /// *why* it indicates the framework — it ends up in analyst-facing output.
    pub fn new(source: EvidenceSource, offset: Option<u64>, detail: impl Into<String>) -> Self {
        Self {
            source,
            offset,
            detail: detail.into(),
        }
    }
}

/// The result of framework detection for one file.
///
/// Construction is ONLY possible via [`FrameworkDetection::build`] (or
/// [`FrameworkDetection::unknown`]); all fields are private. This is what
/// makes the centralized invariant enforceable: no detector — including the
/// sibling detector modules in this tree — has a sanctioned way to fabricate
/// a `mitigation_safe: true` result; `build` recomputes it from the
/// confidence + evidence every time.
#[derive(Debug, Clone)]
pub struct FrameworkDetection {
    kind: FrameworkKind,
    confidence: Confidence,
    evidence: Vec<EvidenceItem>,
    warnings: Vec<String>,
    /// Whether this detection may authorize security-reducing treatment
    /// (finding-weight discounts). Recomputed exclusively by `build`.
    mitigation_safe: bool,
}

impl FrameworkDetection {
    /// The only constructor — enforces the centralized invariant:
    ///
    /// `mitigation_safe = (confidence >= Corroborated) && evidence.contains_structural()`
    ///
    /// Enforcement is bidirectional and fail-closed:
    ///
    /// - A detector claiming `>= Corroborated` confidence with NO structural
    ///   evidence is **downgraded to `WeakHint`** (logged via `tracing::warn!`
    ///   and recorded in `warnings`) — so `mitigation_safe` is false and the
    ///   reported confidence no longer misrepresents the evidence quality.
    /// - Even at `Structural`/`Corroborated` confidence with structural
    ///   evidence present, `mitigation_safe` is computed here, never taken
    ///   from the caller.
    /// - `FrameworkKind::Unknown` is normalized to `Confidence::Unknown` —
    ///   a "nothing found" result must not carry confidence.
    pub fn build(
        kind: FrameworkKind,
        claimed_confidence: Confidence,
        evidence: Vec<EvidenceItem>,
        mut warnings: Vec<String>,
    ) -> Self {
        let has_structural = evidence.iter().any(|e| e.source.is_structural());

        let mut confidence = claimed_confidence;
        if kind == FrameworkKind::Unknown {
            confidence = Confidence::Unknown;
        } else if confidence >= Confidence::Corroborated && !has_structural {
            // THE invariant: a full-buffer text marker or a filename must
            // never by itself authorize security mitigation. A detector that
            // overclaims gets downgraded rather than trusted — fail-closed.
            tracing::warn!(
                ?kind,
                ?claimed_confidence,
                evidence_sources = ?evidence.iter().map(|e| e.source).collect::<Vec<_>>(),
                "framework detector claimed corroborated confidence without structural \
                 evidence — downgrading to WeakHint (text/filename hints never \
                 authorize mitigation)"
            );
            warnings.push(format!(
                "confidence downgraded {claimed_confidence:?} -> WeakHint: no structural \
                 evidence (only TextHint/Filename) for {kind:?}"
            ));
            confidence = Confidence::WeakHint;
        }

        let mitigation_safe =
            confidence >= Confidence::Corroborated && has_structural;

        Self {
            kind,
            confidence,
            evidence,
            warnings,
            mitigation_safe,
        }
    }

    /// A "nothing detected" result.
    pub fn unknown() -> Self {
        Self {
            kind: FrameworkKind::Unknown,
            confidence: Confidence::Unknown,
            evidence: Vec::new(),
            warnings: Vec::new(),
            mitigation_safe: false,
        }
    }

    /// The detected framework.
    pub fn kind(&self) -> FrameworkKind {
        self.kind
    }

    /// Confidence in the classification (after invariant enforcement).
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Evidence backing the classification.
    pub fn evidence(&self) -> &[EvidenceItem] {
        &self.evidence
    }

    /// Non-fatal anomalies encountered during detection (malformed headers,
    /// downgraded confidence, ...). Surfaced for diagnostics; never fatal.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether this detection may authorize security-reducing treatment.
    /// True only when the centralized invariant holds (see [`build`]).
    pub fn mitigation_safe(&self) -> bool {
        self.mitigation_safe
    }

    /// Merge warnings from other detectors' results into this one. The
    /// dispatcher runs every detector (so warnings are never lost) even
    /// though only one detection "wins". Warnings are diagnostic text only;
    /// merging them cannot affect `mitigation_safe`, which is fixed at
    /// construction time.
    pub(crate) fn append_warnings<I: IntoIterator<Item = String>>(&mut self, extra: I) {
        self.warnings.extend(extra);
    }
}

/// Detect the installer/bundle framework of a file.
///
/// Dispatch:
///
/// - **PE** (`MZ`): parse headers via [`pe::parse`], then run every PE
///   framework detector (`nsis`, `inno`, `wix`). The first detector reaching
///   `>= Corroborated` confidence wins; warnings from ALL detectors are
///   merged into the result so diagnostic information is never lost.
///   If no detector reaches `Corroborated`, fall back to
///   [`legacy_framework_hint`] (WeakHint by construction, never
///   `mitigation_safe`).
/// - **OLE2 compound file** (not PE): MSI handling — extension-only, moved
///   verbatim from `engine.rs::is_known_installer` (see [`detect_msi`]).
/// - **Anything else**: `Unknown`.
///
/// This function never authorizes mitigation on its own; callers must check
/// [`FrameworkDetection::mitigation_safe`].
pub fn detect(data: &[u8], path: &str) -> FrameworkDetection {
    let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    // OLE2 compound document magic (MSI, but also legacy Office docs).
    let is_ole2 =
        data.len() >= 8 && data[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    // OLE2 / PE magic are mutually exclusive (both are offset-0 checks).
    if is_ole2 && !is_pe {
        return detect_msi(data, path);
    }
    if !is_pe {
        return FrameworkDetection::unknown();
    }

    // Malformed PE headers: no structural parsing possible. Fail-closed —
    // structural detectors cannot run, so the best we can offer is a legacy
    // WeakHint (never mitigation_safe).
    let Some(pe_info) = pe::parse(data) else {
        tracing::debug!(path, "PE magic present but header parsing failed; legacy hints only");
        return legacy_or_unknown(data, path, Vec::new());
    };

    // Run ALL detectors, not just until the first hit: every detector's
    // warnings (malformed structures, near-misses) are diagnostic gold and
    // must survive even when another detector wins.
    let results = [
        nsis::detect(data, &pe_info),
        inno::detect(data, &pe_info),
        wix::detect(data, &pe_info),
    ];

    let all_warnings: Vec<String> = results
        .iter()
        .flat_map(|r| r.warnings().iter().cloned())
        .collect();

    // First detector reaching Corroborated-or-better wins. The detectors run
    // in a fixed order (NSIS, Inno, WiX) so results are deterministic.
    if let Some(mut winner) = results
        .iter()
        .find(|r| r.confidence() >= Confidence::Corroborated)
        .cloned()
    {
        winner.append_warnings(all_warnings);
        tracing::debug!(
            path,
            kind = ?winner.kind(),
            confidence = ?winner.confidence(),
            mitigation_safe = winner.mitigation_safe(),
            "framework detected with structural confidence"
        );
        return winner;
    }

    // No structural detection. Prefer a detector's WeakHint over the legacy
    // substring path when one exists — detector hints at least ran against
    // parsed structure.
    if let Some(mut hint) = results
        .iter()
        .find(|r| r.confidence() == Confidence::WeakHint)
        .cloned()
    {
        hint.append_warnings(all_warnings);
        return hint;
    }

    legacy_or_unknown(data, path, all_warnings)
}

/// MSI handling for OLE2 compound files — moved verbatim from
/// `engine.rs::is_known_installer` (the `msi_ext` logic).
///
/// WHY extension-only: OLE2 magic is shared with macro-laden Office
/// documents, and in-body markers ("Windows Installer", "Installation
/// Database") are attacker-controlled plain text — both previously handed
/// macro droppers the installer discount. A renamed installer merely loses a
/// leniency discount (fail-safe direction).
///
/// WHY this is NOT `mitigation_safe`: the only evidence here is the
/// filename, which is trivially forgeable (`evil.doc` → `evil.msi`). Under
/// the centralized invariant, `Filename` evidence can never authorize
/// mitigation, so this reports `MsiOle2` at `WeakHint` confidence. Restoring
/// mitigation for genuine MSIs requires a *structural* MSI indicator (e.g.
/// validating the OLE2 stream directory for MSI-specific storage names) —
/// future work, flagged here so the scoring-integration wave does not
/// assume the old extension-based discount still applies through this path.
fn detect_msi(_data: &[u8], path: &str) -> FrameworkDetection {
    let lower = path.to_lowercase();
    let msi_ext = lower.ends_with(".msi") || lower.ends_with(".msp");
    if !msi_ext {
        return FrameworkDetection::unknown();
    }
    FrameworkDetection::build(
        FrameworkKind::MsiOle2,
        Confidence::WeakHint,
        vec![EvidenceItem::new(
            EvidenceSource::Filename,
            None,
            "MSI/MSP extension on an OLE2 compound file (extension-only; \
             filename evidence is forgeable, so this is never mitigation-safe)",
        )],
        Vec::new(),
    )
}

/// Legacy substring fallback, wrapped into the evidence model.
///
/// `WeakHint` confidence is asserted by construction — the ONLY evidence
/// attached is a single `TextHint` item, so even if this code were changed
/// to claim higher confidence, [`FrameworkDetection::build`] would downgrade
/// it. The scoring-integration wave decides whether WeakHint results get any
/// treatment at all; this module deliberately does not wire one.
fn legacy_or_unknown(
    data: &[u8],
    path: &str,
    warnings: Vec<String>,
) -> FrameworkDetection {
    match legacy_framework_hint(data, path) {
        Some(kind) => FrameworkDetection::build(
            kind,
            Confidence::WeakHint,
            vec![EvidenceItem::new(
                EvidenceSource::TextHint,
                None,
                format!(
                    "legacy unanchored substring marker matched ({kind:?}); \
                     diagnostic only — never mitigation-safe"
                ),
            )],
            warnings,
        ),
        None => {
            let mut d = FrameworkDetection::unknown();
            d.append_warnings(warnings);
            d
        }
    }
}

/// Legacy substring framework hints, preserved from
/// `engine.rs::is_known_installer`.
///
/// These are UNANCHORED full-buffer substring scans: every one of them is
/// spoofable by embedding the marker string in a file the attacker controls.
/// They therefore produce [`Confidence::WeakHint`] by construction (see
/// [`legacy_or_unknown`]) and MUST NOT be upgraded to mitigation-authorizing
/// detections without re-deriving them from parsed structure.
///
/// Returns only the kind; the caller builds the (WeakHint) detection.
/// PE-gated exactly like the old code: these checks only ever ran on PE
/// files (OLE2 branched away earlier).
pub fn legacy_framework_hint(data: &[u8], path: &str) -> Option<FrameworkKind> {
    let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    if !is_pe {
        return None;
    }

    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);

    // Installer frameworks without a structural detector yet. The marker
    // strings are spoofable; modeled as WeakHint.
    if contains(b"InstallShiel") {
        return Some(FrameworkKind::InstallShield);
    }
    if contains(b"Advanced Installer") {
        return Some(FrameworkKind::AdvancedInstaller);
    }

    // Bundle frameworks — Electron, NW.js, Tauri, Squirrel, Qt IFW, Flutter,
    // Unity, Unreal. Unusual PE characteristics (large overlay, few imports)
    // that trigger structural false positives.
    let has_electron = contains(b"ASAR")
        || contains(b"electron.asar")
        || contains(b"Electron Framework")
        || contains(b"electron.exe");
    if has_electron {
        return Some(FrameworkKind::ElectronBundle);
    }
    let has_nwjs = contains(b"nw.exe") || contains(b"nwjs");
    let has_tauri = contains(b"tauri") && contains(b"webview");
    let has_squirrel = contains(b"Squirrel") && contains(b"Update.exe");
    let has_qt_installer =
        contains(b"Qt Installer Framework") || contains(b"QtInstallerFramework");
    let has_flutter = contains(b"flutter_engine") || contains(b"FlutterDesktop");
    let has_unity = contains(b"UnityPlayer") || contains(b"Unity Technologies");
    let has_unreal = contains(b"UnrealEngine") || contains(b"EpicGames");
    if has_nwjs
        || has_tauri
        || has_squirrel
        || has_qt_installer
        || has_flutter
        || has_unity
        || has_unreal
    {
        return Some(FrameworkKind::GenericFramework);
    }

    // Go binaries — large static binaries with unusual sections but NOT
    // packed/malicious. Size gate preserved from the old code: the markers
    // alone are short strings any binary can embed.
    let has_go = contains(b"Go build ID:") || contains(b"runtime.main");
    if has_go && data.len() > 3_000_000 {
        return Some(FrameworkKind::GoStatic);
    }

    // Rust binaries — large static binaries via musl or similar.
    let has_rust_static = contains(b"rust_begin_unwind") || contains(b"rust_panic");
    if has_rust_static && data.len() > 2_000_000 {
        return Some(FrameworkKind::RustStatic);
    }

    // Name heuristic. The filename alone is trivially forgeable (rename
    // malware to "setup.exe" + pad past 2 MB), so the old code required a
    // generic installer body hint too. Both halves stay WeakHint-grade.
    let path_lower = path.to_lowercase();
    let name_indicators = [
        "setup",
        "install",
        "installer",
        "update",
        "updater",
        "_setup",
        "-setup",
    ];
    let has_installer_name = name_indicators.iter().any(|p| path_lower.contains(p));
    let has_generic_installer_hint = contains(b"uninstall")
        || contains(b"Uninstall")
        || contains(b".cab")
        || contains(b"Cabinet")
        || contains(b"SFX")
        || contains(b"7-Zip")
        || contains(b"setup.ico");
    if has_installer_name && data.len() > 2_000_000 && has_generic_installer_hint {
        return Some(FrameworkKind::GenericFramework);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_evidence() -> Vec<EvidenceItem> {
        vec![EvidenceItem::new(
            EvidenceSource::TextHint,
            Some(0x1234),
            "marker string found in buffer",
        )]
    }

    fn structural_evidence() -> Vec<EvidenceItem> {
        vec![EvidenceItem::new(
            EvidenceSource::Overlay,
            Some(0x400),
            "framework header at overlay start",
        )]
    }

    // ── THE CENTRALIZED INVARIANT ────────────────────────────────

    /// A detector claiming Structural confidence on TextHint-only evidence
    /// must be DOWNGRADED — enforcement mechanism #1.
    #[test]
    fn text_hint_only_downgrades_claimed_structural_confidence() {
        let d = FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::Structural,
            text_evidence(),
            Vec::new(),
        );
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.warnings().is_empty(), "downgrade must be recorded");
    }

    /// The same overclaim must never be mitigation_safe — enforcement
    /// mechanism #2 (the two are tested separately so a regression in either
    /// is caught even if the other mechanism is removed).
    #[test]
    fn text_hint_only_is_never_mitigation_safe() {
        let d = FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::Structural,
            text_evidence(),
            Vec::new(),
        );
        assert!(!d.mitigation_safe());
    }

    /// Filename evidence is equally non-structural (forgeable by rename).
    #[test]
    fn filename_only_is_never_mitigation_safe() {
        let d = FrameworkDetection::build(
            FrameworkKind::MsiOle2,
            Confidence::Corroborated,
            vec![EvidenceItem::new(
                EvidenceSource::Filename,
                None,
                ".msi extension",
            )],
            Vec::new(),
        );
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    /// WeakHint with structural evidence is still not enough — confidence
    /// must reach Corroborated.
    #[test]
    fn weak_hint_with_structural_evidence_is_not_mitigation_safe() {
        let d = FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::WeakHint,
            structural_evidence(),
            Vec::new(),
        );
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    /// The positive case: Corroborated + structural evidence IS safe.
    #[test]
    fn corroborated_with_structural_evidence_is_mitigation_safe() {
        let d = FrameworkDetection::build(
            FrameworkKind::InnoSetup,
            Confidence::Corroborated,
            structural_evidence(),
            Vec::new(),
        );
        assert!(d.mitigation_safe());
        assert_eq!(d.confidence(), Confidence::Corroborated);
    }

    /// Mixed evidence: one structural item among text hints suffices.
    #[test]
    fn single_structural_item_among_text_hints_suffices() {
        let mut ev = text_evidence();
        ev.push(EvidenceItem::new(
            EvidenceSource::SectionTable,
            Some(0x200),
            "framework-specific section name",
        ));
        let d = FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::Corroborated,
            ev,
            Vec::new(),
        );
        assert!(d.mitigation_safe());
    }

    /// Unknown kind carries no confidence, regardless of claim.
    #[test]
    fn unknown_kind_is_normalized_to_unknown_confidence() {
        let d = FrameworkDetection::build(
            FrameworkKind::Unknown,
            Confidence::Structural,
            structural_evidence(),
            Vec::new(),
        );
        assert_eq!(d.confidence(), Confidence::Unknown);
        assert!(!d.mitigation_safe());
    }

    /// Confidence ordering is load-bearing for the invariant.
    #[test]
    fn confidence_ordering() {
        assert!(Confidence::Unknown < Confidence::WeakHint);
        assert!(Confidence::WeakHint < Confidence::Corroborated);
        assert!(Confidence::Corroborated < Confidence::Structural);
    }

    // ── dispatch ─────────────────────────────────────────────────

    #[test]
    fn non_pe_non_ole2_is_unknown() {
        let d = detect(b"just some text", "file.txt");
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn ole2_without_msi_extension_is_unknown() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0u8; 64]);
        let d = detect(&data, "document.doc");
        assert_eq!(d.kind(), FrameworkKind::Unknown);
    }

    /// Extension-only MSI keeps working diagnostically but is NOT
    /// mitigation_safe (filename evidence only — see detect_msi docs).
    #[test]
    fn ole2_msi_extension_is_weak_hint_not_mitigation_safe() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0u8; 64]);
        let d = detect(&data, "setup.msi");
        assert_eq!(d.kind(), FrameworkKind::MsiOle2);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    /// Legacy hint path: a Go marker in a large PE yields GoStatic at
    /// WeakHint — and even that is never mitigation_safe.
    #[test]
    fn legacy_go_hint_is_weak_hint_never_mitigation_safe() {
        let mut data = b"MZ".to_vec();
        data.resize(3_500_000, 0u8);
        data.extend_from_slice(b"Go build ID:");
        let d = detect(&data, "tool.exe");
        assert_eq!(d.kind(), FrameworkKind::GoStatic);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    /// Non-PE files must not get legacy hints even with markers present
    /// (the old PE gate is preserved).
    #[test]
    fn legacy_hint_requires_pe() {
        let mut data = b"NO".to_vec();
        data.resize(3_500_000, 0u8);
        data.extend_from_slice(b"Go build ID:");
        assert_eq!(legacy_framework_hint(&data, "tool.bin"), None);
    }

    /// End-to-end dispatch on a minimal VALID PE: header parsing succeeds,
    /// all three stub detectors run without panicking, none reaches
    /// Corroborated (they return Unknown until the next wave), and no legacy
    /// marker is present — so the result is plain Unknown, never
    /// mitigation_safe.
    #[test]
    fn dispatch_on_minimal_valid_pe_runs_detectors_and_returns_unknown() {
        let data = fixtures::PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"overlay-bytes")
            .build();
        let d = detect(&data, "app.exe");
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert_eq!(d.confidence(), Confidence::Unknown);
        assert!(!d.mitigation_safe());
    }
}

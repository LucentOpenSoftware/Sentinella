//! Inno Setup detector — stub.
//!
//! The detector body lands in the next wave; this file exists so the
//! dispatcher plumbing, the [`PeInfo`] API, and the shared test fixtures are
//! exercised end-to-end before the real detection logic arrives. The next
//! wave REPLACES this file entirely — only the [`detect`] signature is a
//! contract.
//!
//! Planned structural anchors (for the detector agent): the `rjjzs` /
//! `Inno Setup` setup-loader magic at the overlay start
//! ([`PeInfo::overlay_start`]), Inno version-resource fields, setup data
//! blocks at parsed offsets — cite them as [`super::EvidenceItem`]s with
//! structural [`super::EvidenceSource`]s (`Overlay`, `VersionInfo`), never
//! as free-floating `TextHint`s.

use super::FrameworkDetection;
use super::pe::PeInfo;

/// Detect Inno Setup installers from parsed PE structure.
///
/// Detector lands in the next wave — always returns
/// [`FrameworkDetection::unknown`] for now.
pub(crate) fn detect(_data: &[u8], _pe: &PeInfo) -> FrameworkDetection {
    FrameworkDetection::unknown()
}

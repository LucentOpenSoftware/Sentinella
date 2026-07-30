//! ARGUS evaluation harness — external review workstream A.
//!
//! Single-purpose: scan a file or directory with the real ArgusEngine and
//! print per-file verdicts with per-layer weight attribution, plus a summary.
//!
//! Usage:
//!   cargo run --example eval -p argus -- <path> [options]
//!
//! Options:
//!   --max-files N     cap number of files scanned (default 1000)
//!   --max-size MB     skip files larger than this (default 50)
//!   --ext exe,dll     only scan these extensions (default: all)
//!   --sort size|name  scan order (default: name; size = smallest first)
//!   --verbose         print every finding per file
//!   --yara-dir PATH   YARA rule dir (default: <repo>/runtime/argus/rules/yara)
//!   --ioc-file PATH   IOC hash file (default: <repo>/runtime/rules/ioc_hashes.txt)
//!
//! Output (TSV on stdout):
//!   FILE\tpath\tverdict\tscore\traw_score\trep_disc\tauth_disc\tinstaller\tconfidence\tsize
//!   FINDING\tpath\tlayer\tseverity\tweight\tdescription        (verbose or score>0)
//!   RECON\tpath\tscore_without_installer_discount              (REPLICA, see below)
//!   Summary block at the end (prefixed with '#').
//!
//! RECON is a REPLICA: the API does not expose a "disable installer discount"
//! switch, so for files where installer_discount_applied is true we multiply
//! Structural/Packer finding weights by 3 and installer-class YARA weights by
//! 2 (the inverse of engine.rs:499-526), re-apply the category caps from
//! engine.rs:982-1016, and re-derive the score. Because the original division
//! truncated (w/3 loses remainder), the reconstruction is a LOWER BOUND on the
//! pre-discount score. Dedup zeroing is preserved (0 * n = 0).

use argus::budget::ScanExecutionBudget;
use argus::verdict::Layer;
use argus::{ArgusConfig, ArgusEngine, ArgusVerdict};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Opts {
    target: PathBuf,
    max_files: usize,
    max_size: u64,
    exts: Option<Vec<String>>,
    sort_size: bool,
    verbose: bool,
    yara_dir: PathBuf,
    ioc_file: PathBuf,
}

fn parse_args() -> Opts {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let repo = manifest.join("../..");
    let mut opts = Opts {
        target: PathBuf::from("."),
        max_files: 1000,
        max_size: 50 * 1024 * 1024,
        exts: None,
        sort_size: false,
        verbose: false,
        yara_dir: repo.join("runtime/argus/rules/yara"),
        ioc_file: repo.join("runtime/rules/ioc_hashes.txt"),
    };
    let mut args = std::env::args().skip(1);
    let mut target_set = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--max-files" => opts.max_files = args.next().unwrap().parse().unwrap(),
            "--max-size" => opts.max_size = args.next().unwrap().parse::<u64>().unwrap() * 1024 * 1024,
            "--ext" => {
                opts.exts = Some(
                    args.next()
                        .unwrap()
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect(),
                )
            }
            "--sort" => opts.sort_size = args.next().unwrap() == "size",
            "--verbose" => opts.verbose = true,
            "--yara-dir" => opts.yara_dir = PathBuf::from(args.next().unwrap()),
            "--ioc-file" => opts.ioc_file = PathBuf::from(args.next().unwrap()),
            other if !other.starts_with("--") && !target_set => {
                opts.target = PathBuf::from(other);
                target_set = true;
            }
            other => eprintln!("unknown arg: {other}"),
        }
    }
    opts
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

/// Caps from engine.rs:982-988 — duplicated here ONLY for the REPLICA
/// reconstruction (the real caps run inside the engine on real scans).
fn replica_caps() -> [(Layer, u32); 7] {
    [
        (Layer::StructuralAnalysis, 30),
        (Layer::YaraRules, 40),
        (Layer::Context, 15),
        (Layer::PackerDetection, 20),
        (Layer::PatternDetection, 25),
        (Layer::ScriptAnalysis, 40),
        (Layer::FileDeception, 50),
    ]
}

/// REPLICA: reconstruct an approximate pre-installer-discount score.
/// Lower bound (integer division in the engine truncated remainders).
fn reconstruct_without_installer_discount(v: &ArgusVerdict) -> u32 {
    // (layer, weight) after undoing the engine's /3 and /2 reductions.
    let mut undone: Vec<(Layer, u32)> = v
        .findings
        .iter()
        .map(|f| {
            let w = match f.layer {
                Layer::StructuralAnalysis | Layer::PackerDetection => f.weight * 3,
                Layer::YaraRules => {
                    let dl = f
                        .technical_detail
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase();
                    let installer_class = ["dropper", "updater", "installer", "persistence",
                        "temp_extraction", "fake_updater"]
                        .iter()
                        .any(|k| dl.contains(k));
                    if installer_class {
                        f.weight * 2
                    } else {
                        f.weight
                    }
                }
                _ => f.weight,
            };
            (f.layer, w)
        })
        .collect();

    // Re-apply per-category caps (same floor-scaling as engine.rs:994-1008).
    for (layer, cap) in replica_caps() {
        let total: u32 = undone
            .iter()
            .filter(|(l, _)| *l == layer)
            .map(|(_, w)| *w)
            .sum();
        if total > cap && total > 0 {
            let ratio = cap as f64 / total as f64;
            for (l, w) in undone.iter_mut() {
                if *l == layer {
                    *w = (*w as f64 * ratio).floor() as u32;
                }
            }
        }
    }

    let raw: u32 = undone.iter().map(|(_, w)| *w).sum();
    let discount = v
        .explanation
        .reputation_discount
        .max(v.explanation.authenticode_discount);
    raw.saturating_sub(discount).min(100)
}

fn main() {
    let opts = parse_args();

    // --eicar-buffer: build the EICAR test string IN MEMORY and scan it via
    // analyze_buffer (no disk read — host AV cannot interpose).
    if std::env::args().any(|a| a == "--eicar-buffer") {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let engine = ArgusEngine::new(ArgusConfig::default());
        eprintln!("# yara={:?}", engine.yara.load_rules_on_large_stack(&[opts.yara_dir.clone()]));
        eprintln!("# ioc={:?}", engine.ioc.load_from_file(&opts.ioc_file));
        let v = engine.analyze_buffer("eicar.com", eicar);
        println!(
            "FILE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}",
            v.path, v.verdict.label(), v.score, v.explanation.raw_score,
            v.explanation.reputation_discount, v.explanation.authenticode_discount,
            v.explanation.installer_discount_applied, v.explanation.confidence_label, v.file_size,
        );
        for f in &v.findings {
            println!("FINDING\t{}\t{:?}\t{:?}\t{}\t{}", v.path, f.layer, f.severity, f.weight,
                f.description.replace('\t', " "));
        }
        return;
    }

    let engine = ArgusEngine::new(ArgusConfig::default());
    let yara_loaded = engine
        .yara
        .load_rules_on_large_stack(&[opts.yara_dir.clone()]);
    let ioc_loaded = engine.ioc.load_from_file(&opts.ioc_file);
    eprintln!(
        "# engine init: yara={:?} ioc={:?} (yara_dir={}, ioc_file={})",
        yara_loaded, ioc_loaded, opts.yara_dir.display(), opts.ioc_file.display()
    );

    // ── Collect files ─────────────────────────────────────────
    let mut files: Vec<PathBuf> = Vec::new();
    if opts.target.is_file() {
        files.push(opts.target.clone());
    } else {
        walk(&opts.target, &mut files);
    }
    if let Some(exts) = &opts.exts {
        files.retain(|p| {
            p.extension()
                .map(|e| exts.contains(&e.to_string_lossy().to_lowercase()))
                .unwrap_or(false)
        });
    }
    if opts.sort_size {
        files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0));
    } else {
        files.sort();
    }
    files.truncate(opts.max_files);

    // ── Scan ──────────────────────────────────────────────────
    let mut verdict_counts: BTreeMap<String, u64> = BTreeMap::new();
    // layer -> (total weight, files with findings, files where layer sum == cap)
    let mut layer_stats: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut skipped_size = 0u64;
    let mut installer_count = 0u64;
    let mut scanned = 0u64;

    let caps = replica_caps();

    for path in &files {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > opts.max_size {
            skipped_size += 1;
            continue;
        }
        let v = engine.analyze_file_with_budget(path, ScanExecutionBudget::manual());
        scanned += 1;

        let ex = &v.explanation;
        println!(
            "FILE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}",
            path.display(),
            v.verdict.label(),
            v.score,
            ex.raw_score,
            ex.reputation_discount,
            ex.authenticode_discount,
            ex.installer_discount_applied,
            ex.confidence_label,
            size,
        );

        if opts.verbose || v.score > 0 {
            for f in &v.findings {
                println!(
                    "FINDING\t{}\t{:?}\t{:?}\t{}\t{}",
                    path.display(),
                    f.layer,
                    f.severity,
                    f.weight,
                    f.description.replace('\t', " ").replace('\n', " "),
                );
            }
        }

        if ex.installer_discount_applied {
            installer_count += 1;
            let recon = reconstruct_without_installer_discount(&v);
            println!("RECON\t{}\t{}", path.display(), recon);
        }

        *verdict_counts.entry(v.verdict.label().to_string()).or_insert(0) += 1;

        // Per-layer attribution for this file.
        let mut per_layer: BTreeMap<String, u64> = BTreeMap::new();
        for f in &v.findings {
            *per_layer.entry(format!("{:?}", f.layer)).or_insert(0) += f.weight as u64;
        }
        for (layer, w) in per_layer {
            let st = layer_stats.entry(layer.clone()).or_insert((0, 0, 0));
            st.0 += w;
            st.1 += 1;
            // Cap-saturation inference: post-cap layer total equals the cap
            // ⇒ the cap was (almost certainly) hit. Labeled as inference.
            if let Some(l) = caps.iter().find(|(cl, _)| format!("{cl:?}") == layer) {
                if w == l.1 as u64 {
                    st.2 += 1;
                }
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────
    println!("# SUMMARY");
    println!("# scanned={scanned} skipped_size={skipped_size} total_listed={}", files.len());
    println!("# verdict_buckets:");
    for (k, n) in &verdict_counts {
        println!("#\t{k}\t{n}");
    }
    println!("# installer_discount_applied={installer_count}");
    println!("# layer_totals (layer\ttotal_weight\tfiles_with_findings\tcap_saturation_inferred):");
    let mut layers: Vec<_> = layer_stats.iter().collect();
    layers.sort_by_key(|(_, (w, _, _))| std::cmp::Reverse(*w));
    for (layer, (w, nf, sat)) in layers {
        println!("#\t{layer}\t{w}\t{nf}\t{sat}");
    }
}

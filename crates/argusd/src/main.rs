//! `argusd` - one-shot ARGUS worker process.

use std::path::{Path, PathBuf};

use argus::{ArgusConfig, ArgusEngine};
use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};

const EXIT_CLEAN: i32 = 0;
const EXIT_SUSPICIOUS: i32 = 1;
const EXIT_HIGH_RISK: i32 = 2;
const EXIT_SCAN_ERROR: i32 = 3;
const EXIT_RULES_ERROR: i32 = 4;
const EXIT_INVALID_ARGS: i32 = 5;

#[derive(Parser)]
#[command(name = "argusd", version, about = "Sentinella ARGUS isolated worker")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// YARA rules directory override.
    #[arg(long, global = true)]
    rules_dir: Option<PathBuf>,

    /// IOC hashes file override.
    #[arg(long, global = true)]
    ioc_file: Option<PathBuf>,

    /// Maximum ARGUS file size in MB.
    #[arg(long, default_value_t = 100, global = true)]
    max_size_mb: u64,
}

#[derive(Subcommand)]
enum Command {
    /// Scan one file and emit a worker verdict.
    ScanFile {
        /// Target file path.
        path: PathBuf,
        /// Emit JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Verify worker engine health.
    SelfTest,
    /// Show loaded rule summary.
    Rules,
    /// Benchmark ARGUS scan throughput on this machine (v0.1.6 hardware-parity
    /// tool). Runs the real ARGUS pipeline over a corpus and reports files/sec,
    /// MB/sec, per-file latency percentiles, and CPU/SIMD capability so results
    /// across different hardware are comparable + interpretable.
    Benchmark {
        /// Directory of files to scan. If omitted, a small safe corpus is
        /// generated in a temp dir (deterministic, comparable across machines).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Timed passes (after one untimed warm-up). Median across passes.
        #[arg(long, default_value_t = 3)]
        passes: u32,
        /// Emit JSON output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct WorkerOutput<'a> {
    path: &'a str,
    file_size: u64,
    sha256: String,
    mime_type: &'a Option<String>,
    score: u32,
    verdict: argus::verdict::Verdict,
    confidence_label: argus::verdict::ConfidenceLabel,
    threat_maturity: argus::verdict::ThreatMaturity,
    framework: &'a Option<String>,
    strategy: Option<argus::verdict::ScanStrategy>,
    timing: &'a argus::verdict::ScanTiming,
    findings: &'a [argus::Finding],
    analysis_time_us: u64,
    engine_version: &'static str,
    timestamp: i64,
    explanation: &'a argus::verdict::VerdictExplanation,
    errors: Vec<String>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let (engine, load_errors) = build_engine(&cli);

    let code = match cli.command {
        Command::ScanFile { path, json } => scan_file(&engine, &path, json, load_errors),
        Command::SelfTest => self_test(&engine, load_errors),
        Command::Rules => rules(&engine, load_errors),
        Command::Benchmark { dir, passes, json } => {
            benchmark(&engine, dir.as_deref(), passes, json, load_errors)
        }
    };

    std::process::exit(code);
}

fn build_engine(cli: &Cli) -> (ArgusEngine, Vec<String>) {
    let mut errors = Vec::new();
    let engine = ArgusEngine::new(ArgusConfig {
        max_file_size: cli.max_size_mb.saturating_mul(1024 * 1024),
        ..ArgusConfig::default()
    });

    let yara_dirs = if let Some(dir) = &cli.rules_dir {
        vec![dir.clone()]
    } else {
        candidate_paths(&[
            "runtime/argus/rules/yara",
            "runtime/rules",
            "argus/rules/yara",
            "rules/yara",
        ])
    };

    let existing_yara: Vec<_> = yara_dirs.into_iter().filter(|p| p.exists()).collect();
    if !existing_yara.is_empty() {
        if let Err(e) = engine.yara.load_rules_on_large_stack(&existing_yara) {
            errors.push(format!("YARA load failed: {e}"));
        }
    }

    let ioc_files = if let Some(file) = &cli.ioc_file {
        vec![file.clone()]
    } else {
        candidate_paths(&[
            "runtime/rules/ioc_hashes.txt",
            "runtime/argus/rules/ioc/ioc_hashes.txt",
            "runtime/signatures/ioc_hashes.txt",
            "argus/rules/ioc/ioc_hashes.txt",
            "rules/ioc_hashes.txt",
        ])
    };

    for file in ioc_files {
        if file.exists() {
            if let Err(e) = engine.ioc.load_from_file(&file) {
                errors.push(format!("IOC load failed: {e}"));
            }
            break;
        }
    }

    (engine, errors)
}

fn candidate_paths(relatives: &[&str]) -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(".")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
        }
    }

    let mut out = Vec::new();
    for root in roots {
        for rel in relatives {
            out.push(root.join(rel));
        }
    }
    out
}

fn scan_file(engine: &ArgusEngine, path: &Path, json: bool, load_errors: Vec<String>) -> i32 {
    if !path.exists() || !path.is_file() {
        let msg = format!("file not found: {}", path.display());
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "path": path.to_string_lossy(),
                    "file_size": 0,
                    "sha256": "",
                    "mime_type": null,
                    "score": 0,
                    "verdict": "clean",
                    "confidence_label": "normal",
                    "threat_maturity": "benign",
                    "framework": null,
                    "strategy": null,
                    "timing": null,
                    "findings": [],
                    "analysis_time_us": 0,
                    "engine_version": argus::ENGINE_VERSION,
                    "timestamp": 0,
                    "explanation": null,
                    "errors": [msg],
                })
            );
        } else {
            eprintln!("{msg}");
        }
        return EXIT_SCAN_ERROR;
    }

    let verdict = engine.analyze_file(path);
    let sha256 = if verdict.sha256.is_empty() {
        sha256_file(path).unwrap_or_default()
    } else {
        verdict.sha256.clone()
    };
    let file_size = if verdict.file_size == 0 {
        path.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        verdict.file_size
    };
    let strategy = verdict
        .timing
        .as_ref()
        .and_then(|t| t.strategy)
        .or_else(|| {
            Some(argus::verdict::ScanStrategy::classify(
                &verdict.path,
                file_size,
            ))
        });
    let fallback_timing;
    let timing = if let Some(timing) = verdict.timing.as_ref() {
        timing
    } else {
        fallback_timing = argus::verdict::ScanTiming {
            hash_us: 0,
            clamav_us: 0,
            argus_total_us: verdict.analysis_time_us,
            yara_us: 0,
            structural_us: 0,
            strategy,
            timeout_reasons: Vec::new(),
            completed_within_budget: true,
        };
        &fallback_timing
    };

    let output = WorkerOutput {
        path: &verdict.path,
        file_size,
        sha256,
        mime_type: &verdict.mime_type,
        score: verdict.score,
        verdict: verdict.verdict,
        confidence_label: verdict.explanation.confidence_label,
        threat_maturity: verdict.explanation.threat_maturity,
        framework: &verdict.explanation.framework,
        strategy,
        timing,
        findings: &verdict.findings,
        analysis_time_us: verdict.analysis_time_us,
        engine_version: verdict.engine_version,
        timestamp: verdict.timestamp,
        explanation: &verdict.explanation,
        errors: load_errors,
    };

    if json {
        match serde_json::to_string(&output) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("json encode failed: {e}");
                return EXIT_SCAN_ERROR;
            }
        }
    } else {
        println!(
            "{} {}/100 {}",
            verdict.path,
            verdict.score,
            verdict.verdict.label()
        );
    }

    score_to_exit(verdict.score)
}

fn self_test(engine: &ArgusEngine, load_errors: Vec<String>) -> i32 {
    let stats = engine.stats();
    println!("ARGUS worker self-test");
    println!("engine_version={}", stats.engine_version);
    println!("active_layers={}", stats.active_layers);
    println!("yara_rules={}", stats.yara_rules_loaded);
    println!("ioc_hashes={}", stats.ioc_hashes_loaded);

    if stats.active_layers == 0 {
        eprintln!("no active ARGUS layers");
        return EXIT_RULES_ERROR;
    }
    if !load_errors.is_empty() {
        for e in load_errors {
            eprintln!("{e}");
        }
        return EXIT_RULES_ERROR;
    }
    EXIT_CLEAN
}

fn rules(engine: &ArgusEngine, load_errors: Vec<String>) -> i32 {
    let stats = engine.stats();
    println!("ARGUS rules");
    println!("yara_rules={}", stats.yara_rules_loaded);
    println!("ioc_hashes={}", stats.ioc_hashes_loaded);
    println!("active_layers={}", stats.active_layers);
    println!("engine_version={}", stats.engine_version);

    if !load_errors.is_empty() {
        for e in load_errors {
            eprintln!("{e}");
        }
        return EXIT_RULES_ERROR;
    }
    EXIT_CLEAN
}

fn score_to_exit(score: u32) -> i32 {
    match score {
        0..=25 => EXIT_CLEAN,
        26..=75 => EXIT_SUSPICIOUS,
        _ => EXIT_HIGH_RISK,
    }
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// ARGUS hardware-parity benchmark (v0.1.6).
///
/// Runs the *real* ARGUS pipeline over a corpus so that throughput and latency
/// can be compared across machines (i7-7200U, Core 2 Quad, Skylake, Ryzen vs.
/// the dev i5-1265U). The question this answers is **trust parity** — does
/// Sentinella behave acceptably on weak/old hardware — not raw speed records.
fn benchmark(
    engine: &ArgusEngine,
    dir: Option<&Path>,
    passes: u32,
    json: bool,
    load_errors: Vec<String>,
) -> i32 {
    let passes = passes.max(1);
    let mut errors = load_errors;

    // 1. Build the corpus: caller-supplied dir, or a generated temp corpus that
    //    is deterministic + identical across machines (so results compare).
    let mut temp_dir: Option<PathBuf> = None;
    let (files, source) = match dir {
        Some(d) => {
            let mut out = Vec::new();
            collect_dir(d, &mut out, 0, 4096);
            (out, format!("dir:{}", d.display()))
        }
        None => {
            // Unique dir name (pid + nanos) so the path is not predictable —
            // blunts a pre-planted-symlink attack on shared /tmp when the tool
            // runs with elevated privileges.
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let td = std::env::temp_dir()
                .join(format!("argus-bench-{}-{unique}", std::process::id()));
            let generated = generate_corpus(&td, &mut errors);
            temp_dir = Some(td);
            (generated, "generated".to_string())
        }
    };

    if files.is_empty() {
        let msg = "benchmark corpus is empty (no scannable files found)".to_string();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "argus_benchmark": true,
                    "engine_version": argus::ENGINE_VERSION,
                    "errors": [msg],
                })
            );
        } else {
            eprintln!("{msg}");
        }
        cleanup_temp(temp_dir.as_deref());
        return EXIT_SCAN_ERROR;
    }

    let total_bytes: u64 = files
        .iter()
        .filter_map(|p| p.metadata().ok().map(|m| m.len()))
        .sum();

    // 2. One untimed warm-up pass to prime caches / page-in mmap / JIT YARA.
    for f in &files {
        let _ = engine.analyze_file(f);
    }

    // 3. N timed passes. Capture per-file latency from the median pass and the
    //    median total wall time across passes for throughput.
    let mut pass_totals_us: Vec<u128> = Vec::with_capacity(passes as usize);
    let mut per_file_us: Vec<u64> = Vec::with_capacity(files.len());

    for pass in 0..passes {
        let mut this_pass: Vec<u64> = Vec::with_capacity(files.len());
        let pass_start = std::time::Instant::now();
        for f in &files {
            let t = std::time::Instant::now();
            let _ = engine.analyze_file(f);
            this_pass.push(t.elapsed().as_micros() as u64);
        }
        pass_totals_us.push(pass_start.elapsed().as_micros());

        // Keep the latency distribution from the middle pass.
        if pass == passes / 2 {
            per_file_us = this_pass;
        }
    }

    pass_totals_us.sort_unstable();
    let median_total_us = pass_totals_us[pass_totals_us.len() / 2];
    let median_total_secs = median_total_us as f64 / 1_000_000.0;

    per_file_us.sort_unstable();
    let n = per_file_us.len();
    let pct = |p: f64| -> u64 {
        if n == 0 {
            return 0;
        }
        let idx = ((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
        per_file_us[idx]
    };
    let p50 = pct(0.50);
    let p95 = pct(0.95);
    let max = *per_file_us.last().unwrap_or(&0);
    let mean = if n > 0 {
        per_file_us.iter().sum::<u64>() / n as u64
    } else {
        0
    };

    let files_per_sec = if median_total_secs > 0.0 {
        files.len() as f64 / median_total_secs
    } else {
        0.0
    };
    let mb_per_sec = if median_total_secs > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / median_total_secs
    } else {
        0.0
    };

    let (logical_cores, simd) = cpu_features();

    // ARGUS Performance Index: a single comparable number. Calibrated so the dev
    // i5-1265U lands near 100 on a RELEASE build (~48 files/sec over the
    // generated corpus). Throughput-weighted (files/sec) since that is what
    // end-to-end scan responsiveness depends on. NOTE: only meaningful for a
    // release build; a debug build scores ~10x lower.
    let performance_index = (files_per_sec * 2.0).round() as u64;

    cleanup_temp(temp_dir.as_deref());

    if json {
        let out = serde_json::json!({
            "argus_benchmark": true,
            "engine_version": argus::ENGINE_VERSION,
            "system": {
                "logical_cores": logical_cores,
                "arch": std::env::consts::ARCH,
                "simd": simd,
            },
            "corpus": {
                "files": files.len(),
                "total_bytes": total_bytes,
                "source": source,
            },
            "passes": passes,
            "files_per_sec": (files_per_sec * 100.0).round() / 100.0,
            "mb_per_sec": (mb_per_sec * 100.0).round() / 100.0,
            "per_file_us": {
                "p50": p50,
                "p95": p95,
                "max": max,
                "mean": mean,
            },
            "performance_index": performance_index,
            "errors": errors,
        });
        match serde_json::to_string(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("json encode failed: {e}");
                return EXIT_SCAN_ERROR;
            }
        }
    } else {
        println!("ARGUS benchmark (engine {})", argus::ENGINE_VERSION);
        println!(
            "system: {} logical cores, {}, simd=[{}]",
            logical_cores,
            std::env::consts::ARCH,
            simd.join(",")
        );
        println!(
            "corpus: {} files, {:.2} MB ({source})",
            files.len(),
            total_bytes as f64 / (1024.0 * 1024.0)
        );
        println!("passes: {passes} (median total {median_total_secs:.3}s)");
        println!(
            "throughput: {files_per_sec:.1} files/sec, {mb_per_sec:.1} MB/sec"
        );
        println!(
            "latency/file: p50={p50}us p95={p95}us max={max}us mean={mean}us"
        );
        println!("performance_index: {performance_index} (i5-1265U baseline ~= 100)");
        for e in &errors {
            eprintln!("warn: {e}");
        }
    }

    EXIT_CLEAN
}

/// Logical core count + detected SIMD capability (most-capable first).
fn cpu_features() -> (usize, Vec<&'static str>) {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut simd = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            simd.push("avx2");
        }
        if is_x86_feature_detected!("avx") {
            simd.push("avx");
        }
        if is_x86_feature_detected!("sse4.2") {
            simd.push("sse4.2");
        }
        if is_x86_feature_detected!("sse2") {
            simd.push("sse2");
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            simd.push("neon");
        }
    }
    (cores, simd)
}

/// Recursively collect regular files under `dir`, bounded by depth + count so a
/// stray `--dir C:\` cannot enumerate the whole disk.
fn collect_dir(dir: &Path, out: &mut Vec<PathBuf>, depth: u32, max: usize) {
    if depth > 12 || out.len() >= max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= max {
            return;
        }
        let path = entry.path();
        // Skip reparse points to avoid junction/symlink loops.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_dir(&path, out, depth + 1, max);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

/// Generate a deterministic, SAFE corpus in `dir`. Same bytes on every machine
/// so throughput/latency are comparable. Mixes the file shapes ARGUS routes
/// differently: pseudo-PE, scripts, documents, and opaque blobs of varied size.
fn generate_corpus(dir: &Path, errors: &mut Vec<String>) -> Vec<PathBuf> {
    // Start from a clean slate so a stale/attacker-seeded dir can't supply
    // symlinks that `corpus_write` (create_new) would otherwise collide with.
    let _ = std::fs::remove_dir_all(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        errors.push(format!("corpus dir create failed: {e}"));
        return Vec::new();
    }

    let mut out = Vec::new();

    // Deterministic pseudo-random byte generator (xorshift) so blobs are
    // identical across runs/machines without shipping fixtures.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next_bytes = |len: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            v.push((state & 0xFF) as u8);
        }
        v
    };

    // Pseudo-PE files (MZ + PE header + padded body) at a few sizes.
    for (i, size) in [4 * 1024usize, 64 * 1024, 512 * 1024].iter().enumerate() {
        let mut body = Vec::with_capacity(*size);
        body.extend_from_slice(b"MZ");
        body.extend_from_slice(&[0u8; 58]);
        body.extend_from_slice(&[0x80, 0, 0, 0]); // e_lfanew -> 0x80
        body.resize(0x80, 0);
        body.extend_from_slice(b"PE\0\0");
        body.extend_from_slice(&next_bytes(size.saturating_sub(body.len())));
        corpus_write(dir, &format!("sample_{i}.exe"), &body, &mut out, errors);
    }

    // Scripts (text the script/heuristic layers inspect).
    let ps = b"# benign benchmark script\n$ErrorActionPreference='Stop'\nGet-ChildItem -Path $env:TEMP | Measure-Object\nWrite-Output 'argus benchmark sample'\n";
    corpus_write(dir, "sample.ps1", ps, &mut out, errors);
    let bat = b"@echo off\r\nrem benign benchmark batch\r\necho argus benchmark sample\r\nset /a x=1+1\r\n";
    corpus_write(dir, "sample.bat", bat, &mut out, errors);
    let js = b"// benign benchmark js\nfunction add(a,b){return a+b;}\nconsole.log(add(2,3));\n";
    corpus_write(dir, "sample.js", js, &mut out, errors);

    // Document-ish (ZIP/OOXML local file header so type sniffing engages).
    let mut docx = Vec::new();
    docx.extend_from_slice(b"PK\x03\x04");
    docx.extend_from_slice(&next_bytes(32 * 1024));
    corpus_write(dir, "sample.docx", &docx, &mut out, errors);

    // Opaque blobs of varied size (the common-case data path).
    for (i, size) in [1024usize, 16 * 1024, 256 * 1024, 1024 * 1024]
        .iter()
        .enumerate()
    {
        let blob = next_bytes(*size);
        corpus_write(dir, &format!("blob_{i}.bin"), &blob, &mut out, errors);
    }

    out
}

fn corpus_write(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    out: &mut Vec<PathBuf>,
    errors: &mut Vec<String>,
) {
    use std::io::Write as _;
    let path = dir.join(name);
    // create_new: refuse to open if the path already exists — in particular it
    // will NOT follow a pre-planted symlink, closing the elevated-overwrite hole.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => match f.write_all(bytes) {
            Ok(()) => out.push(path),
            Err(e) => errors.push(format!("corpus write {name} failed: {e}")),
        },
        Err(e) => errors.push(format!("corpus open {name} failed: {e}")),
    }
}

/// Remove a generated temp corpus dir (best-effort; ignore errors).
fn cleanup_temp(dir: Option<&Path>) {
    if let Some(d) = dir {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[allow(dead_code)]
fn invalid_args() -> i32 {
    EXIT_INVALID_ARGS
}

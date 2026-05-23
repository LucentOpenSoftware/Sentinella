//! `sentinella-argus` — standalone ARGUS heuristics CLI scanner.
//!
//! Independent from the Sentinella daemon. Uses the ARGUS engine directly
//! for file analysis, FP regression testing, and rule auditing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use argus::{ArgusConfig, ArgusEngine};
use clap::{Parser, Subcommand};

/// ARGUS Heuristics Engine — standalone CLI scanner.
#[derive(Parser)]
#[command(name = "sentinella-argus", version, about = "ARGUS standalone scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format: text or json.
    #[arg(long, default_value = "text", global = true)]
    format: String,

    /// YARA rules directory.
    #[arg(long, global = true)]
    rules_dir: Option<String>,

    /// IOC hashes file.
    #[arg(long, global = true)]
    ioc_file: Option<String>,

    /// Max file size in MB.
    #[arg(long, default_value = "100", global = true)]
    max_size_mb: u64,

    /// YARA timeout in seconds.
    #[arg(long, default_value = "10", global = true)]
    yara_timeout_sec: u64,

    /// Disable YARA scanning.
    #[arg(long, global = true)]
    no_yara: bool,

    /// Disable context analysis.
    #[arg(long, global = true)]
    no_context: bool,

    /// Exit with error if any file scores >= this threshold.
    #[arg(long, global = true)]
    fail_on_score: Option<u32>,

    /// Number of parallel scan threads (folder scan).
    #[arg(long, default_value = "4", global = true)]
    threads: usize,

    /// Single-use mode: scan one file and exit immediately.
    /// Intended for memory-pressure subprocess isolation — process loads
    /// ARGUS, scans one file, outputs verdict, exits. All memory is
    /// returned to the OS when the process terminates.
    #[arg(long, global = true)]
    single_use: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a single file.
    ScanFile {
        /// Path to file.
        path: String,
    },
    /// Scan a folder recursively.
    ScanFolder {
        /// Path to folder.
        path: String,
        /// Recursive depth limit.
        #[arg(long, default_value = "10")]
        depth: u32,
    },
    /// Explain a file verdict in detail.
    Explain {
        /// Path to file.
        path: String,
    },
    /// Show loaded rules summary.
    Rules,
    /// Run self-test to verify engine health.
    SelfTest,
    /// Run FP regression against a manifest file.
    FpRegression {
        /// Path to JSON manifest.
        manifest: String,
    },
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    // Single-use mode: only valid with scan-file.
    if cli.single_use && !matches!(cli.command, Command::ScanFile { .. }) {
        eprintln!("--single-use is only valid with scan-file");
        std::process::exit(3);
    }

    let engine = build_engine(&cli);
    let json = cli.format == "json";

    let exit_code = match cli.command {
        Command::ScanFile { ref path } => cmd_scan_file(&engine, path, json, cli.fail_on_score),
        Command::ScanFolder { ref path, depth } => cmd_scan_folder(
            Arc::clone(&engine),
            path,
            depth,
            cli.threads,
            json,
            cli.fail_on_score,
        ),
        Command::Explain { ref path } => cmd_explain(&engine, path),
        Command::Rules => cmd_rules(&engine),
        Command::SelfTest => cmd_self_test(&engine),
        Command::FpRegression { ref manifest } => cmd_fp_regression(&engine, manifest),
    };

    std::process::exit(exit_code);
}

fn build_engine(cli: &Cli) -> Arc<ArgusEngine> {
    let config = ArgusConfig {
        max_file_size: cli.max_size_mb * 1024 * 1024,
        ..ArgusConfig::default()
    };

    let engine = Arc::new(ArgusEngine::new(config));

    // Load YARA rules.
    if !cli.no_yara {
        let yara_dirs = if let Some(ref dir) = cli.rules_dir {
            vec![PathBuf::from(dir)]
        } else {
            vec![
                PathBuf::from("runtime/argus/rules/yara"),
                PathBuf::from("runtime/rules"),
            ]
        };
        let existing: Vec<_> = yara_dirs.iter().filter(|d| d.exists()).cloned().collect();
        if !existing.is_empty() {
            match engine.yara.load_rules_on_large_stack(&existing) {
                Ok(count) => eprintln!("YARA: {count} rules loaded"),
                Err(e) => eprintln!("YARA error: {e}"),
            }
        }
    }

    // Load IOC hashes.
    let ioc_paths = if let Some(ref f) = cli.ioc_file {
        vec![PathBuf::from(f)]
    } else {
        vec![
            PathBuf::from("runtime/rules/ioc_hashes.txt"),
            PathBuf::from("runtime/argus/rules/ioc/ioc_hashes.txt"),
        ]
    };
    for p in &ioc_paths {
        if p.exists() {
            if let Ok(c) = engine.ioc.load_from_file(p) {
                eprintln!("IOC: {c} hashes loaded");
                break;
            }
        }
    }

    engine
}

// ── Commands ──────────────────────────────────────────────

fn cmd_scan_file(engine: &ArgusEngine, path: &str, json: bool, fail_score: Option<u32>) -> i32 {
    let p = Path::new(path);
    if !p.exists() {
        eprintln!("File not found: {path}");
        return 3;
    }

    let verdict = engine.analyze_file(p);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&verdict).unwrap_or_default()
        );
    } else {
        print_verdict_text(&verdict);
    }

    score_to_exit(verdict.score, fail_score)
}

fn cmd_scan_folder(
    engine: Arc<ArgusEngine>,
    path: &str,
    depth: u32,
    threads: usize,
    json: bool,
    fail_score: Option<u32>,
) -> i32 {
    let dir = Path::new(path);
    if !dir.is_dir() {
        eprintln!("Not a directory: {path}");
        return 3;
    }

    let start = Instant::now();
    let mut files = Vec::new();
    collect_files(dir, &mut files, depth);

    eprintln!("Collected {} files", files.len());

    // Parallel scan.
    let num_threads = threads.max(1).min(files.len().max(1));

    let results: Vec<_> = if files.is_empty() {
        Vec::new()
    } else if num_threads <= 1 {
        files.iter().map(|f| engine.analyze_file(f)).collect()
    } else {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let files = Arc::new(files);
        let next_file = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let eng = Arc::clone(&engine);
            let tx = tx.clone();
            let files_ref = Arc::clone(&files);
            let next_ref = Arc::clone(&next_file);
            handles.push(std::thread::spawn(move || {
                loop {
                    let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    if idx >= files_ref.len() {
                        break;
                    }
                    let file = &files_ref[idx];
                    let v = eng.analyze_file(file);
                    let _ = tx.send(v);
                }
            }));
        }
        drop(tx);

        let mut results: Vec<_> = rx.iter().collect();
        for h in handles {
            let _ = h.join();
        }
        results.sort_by(|a, b| b.score.cmp(&a.score));
        results
    };

    let elapsed = start.elapsed();
    let total = results.len();
    let threats = results.iter().filter(|v| v.score >= 76).count();
    let suspicious = results
        .iter()
        .filter(|v| v.score >= 26 && v.score < 76)
        .count();
    let max_score = results.iter().map(|v| v.score).max().unwrap_or(0);

    if json {
        let summary = serde_json::json!({
            "directory": path,
            "total_files": total,
            "threats": threats,
            "suspicious": suspicious,
            "max_score": max_score,
            "elapsed_ms": elapsed.as_millis(),
            "files_per_sec": if elapsed.as_secs() > 0 { total as u64 / elapsed.as_secs() } else { total as u64 },
            "results": results.iter().filter(|v| v.score > 0).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
    } else {
        println!(
            "\n  Scan complete: {} files in {:.1}s",
            total,
            elapsed.as_secs_f64()
        );
        println!(
            "  Threats: {}  Suspicious: {}  Max score: {}/100",
            threats, suspicious, max_score
        );
        if threats + suspicious > 0 {
            println!("\n  Notable files:");
            for v in results.iter().filter(|v| v.score > 0).take(20) {
                let short = v.path.rsplit(['/', '\\']).next().unwrap_or(&v.path);
                println!(
                    "    {:>3}/100  {:12}  {}",
                    v.score,
                    v.verdict.label(),
                    short
                );
            }
        }
        println!();
    }

    score_to_exit(max_score, fail_score)
}

fn cmd_explain(engine: &ArgusEngine, path: &str) -> i32 {
    let p = Path::new(path);
    if !p.exists() {
        eprintln!("File not found: {path}");
        return 3;
    }

    let v = engine.analyze_file(p);
    let e = &v.explanation;

    println!("\n  ARGUS Detailed Analysis");
    println!("  ========================================");
    println!("  File: {}", v.path);
    println!("  Size: {} bytes", v.file_size);
    println!("  SHA-256: {}", v.sha256);
    println!("  MIME: {}", v.mime_type.as_deref().unwrap_or("unknown"));
    println!();
    println!("  Score: {}/100", v.score);
    println!("  Verdict: {}", v.verdict.label());
    println!("  Confidence: {}", e.confidence_label.label());
    println!("  Maturity: {:?}", e.threat_maturity);
    if let Some(ref fw) = e.framework {
        println!("  Framework: {fw}");
    }
    if let Some(ref timing) = v.timing {
        println!("  Strategy: {:?}", timing.strategy);
        println!(
            "  Timing: hash={}us yara={}us total={}us",
            timing.hash_us, timing.yara_us, timing.argus_total_us
        );
    }
    println!("  Progression depth: {}", e.progression_depth);
    println!();

    if !e.suspicion_reasons.is_empty() {
        println!("  Why suspicious:");
        for r in &e.suspicion_reasons {
            println!("    {r}");
        }
        println!();
    }

    if !e.trust_reasons.is_empty() {
        println!("  Trust factors:");
        for r in &e.trust_reasons {
            println!("    {r}");
        }
        println!();
    }

    if e.raw_score != e.final_score {
        println!("  Score breakdown:");
        println!("    Raw: {}", e.raw_score);
        println!("    Reputation discount: -{}", e.reputation_discount);
        println!("    Authenticode discount: -{}", e.authenticode_discount);
        println!(
            "    Installer: {}",
            if e.installer_discount_applied {
                "yes (weights reduced)"
            } else {
                "no"
            }
        );
        println!("    Final: {}", e.final_score);
        println!();
    }

    if !v.findings.is_empty() {
        println!("  All findings ({}):", v.findings.len());
        for f in &v.findings {
            let tag = f
                .behavior_tag()
                .map(|t| format!(" [{t:?}]"))
                .unwrap_or_default();
            println!(
                "    [{:>2}] {:16} {:8?}  {}{}",
                f.weight,
                f.layer.display_name(),
                f.severity,
                f.description,
                tag
            );
        }
        println!();
    }

    0
}

fn cmd_rules(engine: &ArgusEngine) -> i32 {
    let stats = engine.stats();
    println!("\n  ARGUS Rules Summary");
    println!("  ========================================");
    println!("  YARA rules: {}", stats.yara_rules_loaded);
    println!("  IOC hashes: {}", stats.ioc_hashes_loaded);
    println!("  Active layers: {}", stats.active_layers);
    println!("  Engine version: {}", stats.engine_version);

    // List YARA rule files if directory exists.
    let yara_dir = PathBuf::from("runtime/argus/rules/yara");
    if yara_dir.exists() {
        let files: Vec<_> = std::fs::read_dir(&yara_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "yar").unwrap_or(false))
            .collect();
        println!("  YARA files: {}", files.len());
        for f in &files {
            println!("    {}", f.file_name().to_string_lossy());
        }
    }
    println!();
    0
}

fn cmd_self_test(engine: &ArgusEngine) -> i32 {
    println!("\n  ARGUS Self-Test");
    println!("  ========================================");
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Engine loaded.
    let stats = engine.stats();
    if stats.active_layers > 0 {
        println!("  [OK] Engine loaded ({} layers)", stats.active_layers);
        passed += 1;
    } else {
        println!("  [FAIL] Engine has 0 active layers");
        failed += 1;
    }

    // Test 2: YARA rules.
    if stats.yara_rules_loaded > 0 {
        println!(
            "  [OK] YARA rules compiled ({} rules)",
            stats.yara_rules_loaded
        );
        passed += 1;
    } else {
        println!("  [WARN] No YARA rules loaded");
        // Not a failure — rules may not exist in all environments.
    }

    // Test 3: IOC database.
    if stats.ioc_hashes_loaded > 0 {
        println!(
            "  [OK] IOC database loaded ({} hashes)",
            stats.ioc_hashes_loaded
        );
        passed += 1;
    } else {
        println!("  [WARN] No IOC hashes loaded");
    }

    // Test 4: Strategy classifier.
    use argus::verdict::ScanStrategy;
    let s1 = ScanStrategy::classify("test.exe", 1_000_000);
    let s2 = ScanStrategy::classify("test.log", 100);
    let s3 = ScanStrategy::classify("test.jpg", 5_000_000);
    if s1 == ScanStrategy::FullAnalysis
        && s2 == ScanStrategy::SkipSafe
        && s3 == ScanStrategy::SignatureOnly
    {
        println!("  [OK] Strategy classifier working");
        passed += 1;
    } else {
        println!("  [FAIL] Strategy classifier unexpected results");
        failed += 1;
    }

    // Test 5: Analyze a known-safe system file.
    let notepad = Path::new("C:\\Windows\\System32\\notepad.exe");
    if notepad.exists() {
        let v = engine.analyze_file(notepad);
        if v.score <= 25 {
            println!("  [OK] notepad.exe scored {}/100 (expected <=25)", v.score);
            passed += 1;
        } else {
            println!(
                "  [WARN] notepad.exe scored {}/100 (higher than expected)",
                v.score
            );
        }
    }

    println!();
    println!("  Result: {} passed, {} failed", passed, failed);
    println!();

    if failed > 0 { 4 } else { 0 }
}

fn cmd_fp_regression(engine: &ArgusEngine, manifest_path: &str) -> i32 {
    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Cannot read manifest: {e}");
            return 3;
        }
    };

    #[derive(serde::Deserialize)]
    struct TestCase {
        path: String,
        expected_max_score: u32,
        #[serde(default)]
        #[allow(dead_code)]
        expected_max_confidence: Option<String>,
        #[serde(default)]
        must_not_quarantine: bool,
    }

    let cases: Vec<TestCase> = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Invalid manifest JSON: {e}");
            return 4;
        }
    };

    let mut passed = 0u32;
    let mut failed = 0u32;

    for case in &cases {
        let p = Path::new(&case.path);
        if !p.exists() {
            println!("  [SKIP] {} — file not found", case.path);
            continue;
        }

        let v = engine.analyze_file(p);
        let score_ok = v.score <= case.expected_max_score;
        let quarantine_ok = if case.must_not_quarantine {
            v.score < 85
        } else {
            true
        };

        if score_ok && quarantine_ok {
            println!(
                "  [PASS] {} — score {}/{}",
                case.path, v.score, case.expected_max_score
            );
            passed += 1;
        } else {
            println!(
                "  [FAIL] {} — score {}/{} quarantine={}",
                case.path,
                v.score,
                case.expected_max_score,
                v.score >= 85
            );
            if !v.explanation.suspicion_reasons.is_empty() {
                for r in v.explanation.suspicion_reasons.iter().take(3) {
                    println!("         {r}");
                }
            }
            failed += 1;
        }
    }

    println!();
    println!("  FP Regression: {} passed, {} failed", passed, failed);
    if failed > 0 { 1 } else { 0 }
}

// ── Helpers ──────────────────────────────────────────────

fn print_verdict_text(v: &argus::ArgusVerdict) {
    let e = &v.explanation;
    let short = v.path.rsplit(['/', '\\']).next().unwrap_or(&v.path);
    println!();
    println!("  {} — {}/100 {}", short, v.score, v.verdict.label());
    println!(
        "  Confidence: {}  Maturity: {:?}",
        e.confidence_label.label(),
        e.threat_maturity
    );
    if let Some(ref fw) = e.framework {
        println!("  Framework: {fw}");
    }
    if let Some(ref timing) = v.timing {
        println!(
            "  Timing: hash={}ms yara={}ms total={}ms",
            timing.hash_us / 1000,
            timing.yara_us / 1000,
            timing.argus_total_us / 1000
        );
    }
    if !e.suspicion_reasons.is_empty() {
        println!("  Findings:");
        for r in e.suspicion_reasons.iter().take(5) {
            println!("    {r}");
        }
    }
    if !e.trust_reasons.is_empty() {
        for r in &e.trust_reasons {
            println!("    {r}");
        }
    }
    println!();
}

fn score_to_exit(score: u32, fail_threshold: Option<u32>) -> i32 {
    if let Some(thresh) = fail_threshold {
        if score >= thresh {
            return 2;
        }
    }
    match score {
        0..=25 => 0,
        26..=75 => 1,
        _ => 2,
    }
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>, max_depth: u32) {
    if max_depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if matches!(
                name.as_str(),
                "target" | "node_modules" | ".git" | "dist" | "build" | ".cargo" | ".rustup"
            ) {
                continue;
            }
            collect_files(&path, files, max_depth - 1);
        } else if path.is_file() {
            files.push(path);
        }
    }
}

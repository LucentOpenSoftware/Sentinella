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

#[allow(dead_code)]
fn invalid_args() -> i32 {
    EXIT_INVALID_ARGS
}

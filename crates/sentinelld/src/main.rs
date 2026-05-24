//! `sentinelld` — the Sentinella daemon.
//!
//! Hosts the ClamAV scanning engine, serves the JSON-RPC IPC protocol,
//! manages the quarantine vault, drives the real-time watcher, and
//! orchestrates signature updates.

mod argus_worker;
#[allow(dead_code)]
mod clamav_worker;
mod config;
// Sandbox worker is called from scan flow when config.sandbox.enabled = true.
pub mod db;
mod engine;
mod fish;
mod footprint;
mod idle_scanner;
mod ipc;
mod memory_scanner;
mod orchestrator;
mod quarantine;
#[allow(dead_code)]
mod sandbox_worker;
mod scan;
mod scheduler;
mod targeting;
mod updater;
mod watcher;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sentinelld", about = "Sentinella antivirus daemon")]
struct Args {
    /// Run in foreground (don't daemonize). Useful for development.
    #[arg(long, default_value_t = true)]
    foreground: bool,

    /// Config file path override.
    #[arg(long)]
    config: Option<String>,

    /// Log level override (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Directory containing libclamav.dll and its dependencies.
    #[arg(long)]
    dll_dir: Option<String>,

    /// Directory containing ClamAV signature databases (.cvd files).
    #[arg(long)]
    db_dir: Option<String>,

    /// Path to the SQLite state database.
    #[arg(long)]
    state_db: Option<String>,

    /// Audit mode: reduced features for stability after repeated crashes.
    /// Disables idle scanner, forces external ARGUS, reduces worker count.
    #[arg(long)]
    audit_mode: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Bootstrap runtime directories — daemon creates them if missing.
    for dir in &[
        "runtime/logs",
        "runtime/config",
        "runtime/state",
        "runtime/signatures",
        "runtime/quarantine",
        "runtime/rules",
        "runtime/argus/rules/yara",
        "runtime/argus/compiled",
        "runtime/argus/manifests",
    ] {
        let _ = std::fs::create_dir_all(dir);
    }

    // Initialize tracing with file + stdout output.
    let log_dir = std::path::PathBuf::from("runtime/logs");

    // Log rotation: if current log > 10 MB, rotate.
    let log_path = log_dir.join("sentinelld.log");
    if let Ok(meta) = std::fs::metadata(&log_path) {
        if meta.len() > 10 * 1024 * 1024 {
            // Rotate: .log.2 → delete, .log.1 → .log.2, .log → .log.1
            let _ = std::fs::remove_file(log_dir.join("sentinelld.log.2"));
            let _ = std::fs::rename(
                log_dir.join("sentinelld.log.1"),
                log_dir.join("sentinelld.log.2"),
            );
            let _ = std::fs::rename(&log_path, log_dir.join("sentinelld.log.1"));
        }
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    if let Some(file) = log_file {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        // Build log filter: apply user-requested level but suppress noisy
        // third-party crates. wasmtime/cranelift emit huge volumes at debug;
        // ClamAV's scanned_bytes UINT32_MAX warning is a known harmless issue.
        let filter_str = format!(
            "{level},walrus=warn,wasmtime=warn,wasmtime_internal_cranelift=warn,cranelift_codegen=warn,regalloc2=warn,goblin=warn",
            level = args.log_level,
        );
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter_str));

        let stdout_layer = tracing_subscriber::fmt::layer().with_target(true);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file));

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
            )
            .init();
    }

    info!(
        version = sentinella_common::PRODUCT_VERSION,
        "sentinelld starting"
    );

    // Load configuration.
    let config = config::load(args.config.as_deref())?;
    info!(?config.realtime_enabled, "configuration loaded");

    // Resolve ClamAV paths.
    // Priority: CLI args > auto-detect relative to exe.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let dll_dir = args.dll_dir.map(PathBuf::from).or_else(|| {
        // Auto-detect: look for libclamav.dll in common locations.
        let candidates = [
            exe_dir.as_ref().map(|d| d.join(".")),
            Some(PathBuf::from("build/clamav/libclamav/Release")),
        ];
        for c in candidates.iter().flatten() {
            if c.join("libclamav.dll").exists() {
                info!(path = %c.display(), "auto-detected DLL directory");
                return Some(c.clone());
            }
        }
        None
    });

    let db_dir = args.db_dir.map(PathBuf::from).or_else(|| {
        let candidates = [
            Some(PathBuf::from("runtime/signatures")),
            exe_dir.as_ref().map(|d| d.join("signatures")),
        ];
        for c in candidates.iter().flatten() {
            if c.exists() && c.is_dir() {
                info!(path = %c.display(), "auto-detected signature directory");
                return Some(c.clone());
            }
        }
        None
    });

    if dll_dir.is_none() {
        warn!("libclamav.dll directory not found — daemon will start without scanning");
    }
    if db_dir.is_none() {
        warn!("signature database directory not found — run freshclam first");
    }

    // Open persistent state database.
    let state_db_path = args
        .state_db
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("runtime/state/sentinella.db"));
    let database = match db::Database::open(&state_db_path) {
        Ok(d) => {
            info!(path = %state_db_path.display(), "state database opened");
            Some(d)
        }
        Err(e) => {
            warn!(%e, "failed to open state database — history will not persist");
            None
        }
    };

    // Start IPC server with engine + database.
    let server = ipc::Server::with_engine(dll_dir, db_dir, database)?;
    info!("IPC server listening");

    // Load ClamAV isolation config.
    if config.clamav_isolation == "subprocess" {
        server
            .state()
            .set_clamav_subprocess(true, config.clamav_worker_timeout_sec);
        info!("ClamAV isolation: subprocess mode");
    }

    // Check sandbox binary availability.
    if config.sandbox.enabled {
        if sandbox_worker::find_sandboxd_public().is_some() {
            info!("behavioral sandbox enabled (experimental) — sandboxd found");
        } else {
            warn!(
                "sandbox.enabled=true but sandboxd.exe not found — sandbox detonation will not work"
            );
        }
    }

    // Load FISH config from config file.
    server.state().load_fish_config(config.fish.clone());

    // Load detection exclusions from config.
    if !config.excluded_detections.is_empty() {
        info!(
            count = config.excluded_detections.len(),
            "detection exclusions loaded"
        );
        server
            .state()
            .load_detection_exclusions(config.excluded_detections.clone());
    }
    if !config.trusted_hashes.is_empty() {
        info!(count = config.trusted_hashes.len(), "trusted hashes loaded");
        server
            .state()
            .load_trusted_hashes(config.trusted_hashes.clone());
    }

    // Log memory footprint at startup (post-engine-load baseline).
    server.state().record_startup_footprint();
    let startup_footprint = server.state().capture_footprint();
    footprint::log_footprint("startup", &startup_footprint);
    let pressure = server.state().update_pressure();
    info!(?pressure, "initial memory pressure state");

    // Set daemon operating mode.
    if args.audit_mode {
        server.state().set_audit_mode(true);
        warn!("AUDIT MODE — reduced features for stability recovery");
        warn!("  idle scanner: disabled");
        warn!("  external ARGUS: forced");
        warn!("  worker concurrency: reduced");
    }

    // Start real-time watcher (if engine is available).
    // Watcher runs even in audit mode (minimal protection).
    server.state().start_watcher();

    // Post-boot critical areas scan — lightweight, 1 thread, BELOW_NORMAL.
    // Fires AFTER watcher so realtime is never delayed.
    // Skips in audit mode (minimal footprint).
    if !args.audit_mode && config.startup_critical_scan {
        server.state().start_startup_critical_scan();
    } else if !config.startup_critical_scan {
        info!("startup critical scan disabled by config");
    }

    // Start idle background scanner (resource-aware) — skip in audit mode.
    if !args.audit_mode {
        server.state().start_idle_scanner();
    } else {
        info!("idle scanner skipped (audit mode)");
    }

    // Start scan scheduler — skip in audit mode.
    let scheduler = if !args.audit_mode {
        Some(scheduler::Scheduler::start(Arc::clone(server.state())))
    } else {
        info!("scheduler skipped (audit mode)");
        None
    };

    // Handle graceful shutdown on Ctrl+C.
    let shutdown_state = Arc::clone(server.state());
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("shutdown signal received");
            shutdown_state.log_activity(
                "info",
                "system",
                "Daemon shutting down",
                "Graceful shutdown",
                None,
            );
        }
    });

    // Main event loop.
    if let Err(e) = server.run().await {
        error!(%e, "daemon shutting down due to error");
        return Err(e);
    }

    // Cleanup.
    if let Some(s) = scheduler {
        s.stop();
    }
    info!("sentinelld stopped gracefully");
    Ok(())
}

//! `sentinelld` — the Sentinella daemon.
//!
//! Hosts the ClamAV scanning engine, serves the JSON-RPC IPC protocol,
//! manages the quarantine vault, drives the real-time watcher, and
//! orchestrates signature updates.

mod ipc;
mod scan;
mod watcher;
mod quarantine;
mod config;
mod engine;
mod updater;
mod scheduler;

use clap::Parser;
use tracing::{info, error};
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    info!(
        version = sentinella_common::PRODUCT_VERSION,
        "sentinelld starting"
    );

    // Load configuration.
    let config = config::load(args.config.as_deref())?;
    info!(?config.realtime_enabled, "configuration loaded");

    // Start IPC server.
    let server = ipc::Server::new()?;
    info!("IPC server listening");

    // Main event loop: accept connections and dispatch.
    if let Err(e) = server.run().await {
        error!(%e, "daemon shutting down due to error");
        return Err(e);
    }

    info!("sentinelld stopped");
    Ok(())
}

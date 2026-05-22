//! `sentinella` CLI — command-line interface to the Sentinella daemon.
//!
//! Usage:
//!   sentinella status          — show engine status
//!   sentinella scan <path>     — request a scan
//!   sentinella update          — trigger signature update
//!   sentinella quarantine list — list quarantined items

use anyhow::Result;
use clap::{Parser, Subcommand};
use sentinella_ipc_proto::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "sentinella", about = "Sentinella antivirus CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show engine status.
    Status,
    /// Start a scan.
    Scan {
        /// Paths to scan.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Trigger a signature update.
    Update,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let resp = send_request("engine.status", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Scan { paths } => {
            let params = serde_json::to_value(sentinella_ipc_proto::scan::ScanRequest {
                targets: paths,
                options: Default::default(),
            })?;
            let resp = send_request("scan.start", params).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Update => {
            let resp = send_request("update.start", serde_json::Value::Null).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    Ok(())
}

/// Connect to the daemon, send a single request, return the response.
async fn send_request(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let req = RpcRequest {
        jsonrpc: JSONRPC_VERSION.into(),
        id: 1,
        method: method.into(),
        params,
    };

    let payload = serde_json::to_vec(&req)?;

    #[cfg(target_os = "windows")]
    let response = {
        use tokio::net::windows::named_pipe::ClientOptions;
        let mut client = ClientOptions::new().open(sentinella_common::IPC_PIPE_NAME)?;

        // Write length-prefixed request.
        let len_bytes = (payload.len() as u32).to_be_bytes();
        client.write_all(&len_bytes).await?;
        client.write_all(&payload).await?;

        // Read length-prefixed response.
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await?;
        serde_json::from_slice::<serde_json::Value>(&resp_buf)?
    };

    #[cfg(not(target_os = "windows"))]
    let response = {
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(sentinella_common::IPC_SOCKET_PATH).await?;

        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&payload).await?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        serde_json::from_slice::<serde_json::Value>(&resp_buf)?
    };

    Ok(response)
}

//! Manual smoke binary for the dnsguard proxy.
//!
//! Usage:
//!   dnsguard-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53 \
//!       --blocklist <hosts-file> [--allow <file>] [--zero-ip]
//!
//! Prints one line per query decision to stdout. Ctrl+C to stop.

use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;

use tokio::sync::watch;

use dnsguard::filter::{FilterEngine, ListKind};
use dnsguard::proxy::{BlockResponse, DecisionEvent, DecisionHook, Proxy, ProxyConfig};

fn usage() -> ! {
    eprintln!(
        "usage: dnsguard-proxy [--listen 127.0.0.1:5353] --upstream <addr>...\n\
         \x20   [--blocklist <hosts-file>]... [--allow <hosts-file>]... [--zero-ip]"
    );
    exit(2);
}

struct Args {
    listen: SocketAddr,
    upstreams: Vec<SocketAddr>,
    blocklists: Vec<String>,
    allows: Vec<String>,
    zero_ip: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        listen: SocketAddr::from(([127, 0, 0, 1], 5353)),
        upstreams: Vec::new(),
        blocklists: Vec::new(),
        allows: Vec::new(),
        zero_ip: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => {
                args.listen = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
            }
            "--upstream" => args
                .upstreams
                .push(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--blocklist" => args.blocklists.push(it.next().unwrap_or_else(|| usage())),
            "--allow" => args.allows.push(it.next().unwrap_or_else(|| usage())),
            "--zero-ip" => args.zero_ip = true,
            _ => usage(),
        }
    }
    if args.upstreams.is_empty() {
        usage();
    }
    args
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();
    let args = parse_args();

    let mut engine = FilterEngine::new();
    for (kind, paths) in [
        (ListKind::Block, &args.blocklists),
        (ListKind::Allow, &args.allows),
    ] {
        for path in paths {
            let file = File::open(path)?;
            let stats = engine.load_hosts(kind, BufReader::new(file))?;
            println!(
                "loaded {path}: {} rules ({} lines, {} skipped{})",
                stats.rules_added,
                stats.lines_read,
                stats.lines_skipped,
                if stats.truncated { ", TRUNCATED" } else { "" },
            );
        }
    }
    println!("{} rules total (canary always blocked)", engine.rule_count());

    let hook: Arc<dyn DecisionHook> = Arc::new(|e: &DecisionEvent| {
        println!(
            "{:?} {} qtype={} qclass={} client={}",
            e.outcome, e.qname, e.qtype, e.qclass, e.client
        );
    });

    let config = ProxyConfig {
        listen: args.listen,
        upstreams: args.upstreams,
        block_response: if args.zero_ip {
            BlockResponse::ZeroIp
        } else {
            BlockResponse::Nxdomain
        },
        ..ProxyConfig::default()
    };
    let proxy = Proxy::bind(config, engine, hook).await?;
    println!("listening on {} (UDP+TCP)", proxy.local_addr());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    proxy.run(shutdown_rx).await
}

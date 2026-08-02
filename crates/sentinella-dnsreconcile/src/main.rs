//! Boot-time NRPT reconciler.
//!
//! # What it is for
//!
//! An NRPT rule points the whole machine's DNS at our proxy, lives in the
//! registry, and survives reboots. The daemon that serves that DNS is
//! delayed-auto start, so for the first minutes of every boot the rule is
//! live and nothing is listening. And a crash, a failed upgrade, a
//! quarantined binary or a disabled service can leave that state
//! indefinitely — on a machine whose user cannot search for the fix,
//! because search does not resolve.
//!
//! This runs at startup, before the daemon, and enforces one rule:
//!
//! > **The NRPT rule may exist only while our proxy is provably answering.**
//!
//! Under any uncertainty the machine degrades to "no filtering", never to
//! "no DNS". So the daemon owns INSTALLING the rule — it does that only
//! after its own four-step self-test passes — and this owns REMOVING it.
//!
//! # What it deliberately does not do
//!
//! No list loading, no proxy start, no signature download, no config
//! parsing, no network beyond one loopback datagram. It reconciles a state
//! and exits. That is what makes it safe to run on every boot: idempotent,
//! milliseconds, and incapable of making anything worse.
//!
//! It also never INSTALLS a rule. Installing is a decision that requires
//! proof the proxy works, and this process is deliberately too dumb to
//! obtain that proof.

mod task;

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use dnsguard::filter::CANARY_DOMAIN;
use dnsguard::proxy::is_canary_signature;
use dnsguard::wire;

/// The address NRPT points at. Hardcoded, not read from the daemon's
/// config: NRPT `NameServers` carries no port syntax, so the DNS Client
/// always queries 53, and a reconciler that trusted a config file could be
/// pointed away from the thing it is supposed to check.
const PROBE_ADDR: &str = "127.0.0.1:53";

/// One probe's patience. Short: this runs at boot and a healthy proxy on
/// loopback answers in well under a millisecond.
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// A single failed probe is not proof of death — the proxy sheds under
/// load, and a shed probe looks identical to a dead one. Three tries with
/// a short gap turns "momentarily busy" into "answered", while a genuinely
/// absent listener still fails all three in well under two seconds.
const PROBE_ATTEMPTS: usize = 3;
const PROBE_GAP: Duration = Duration::from_millis(150);

/// Keep the forensic trail from growing without bound on a machine that
/// boots daily for years.
const LOG_MAX_BYTES: u64 = 256 * 1024;

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        None => Mode::Reconcile,
        Some("--dry-run") => Mode::DryRun,
        Some("--remove") => Mode::ForceRemove,
        Some("--install-task") => return install_task(),
        Some("--remove-task") => return remove_task(),
        Some("--version" | "-V") => {
            println!("sentinella-dnsreconcile {VERSION}");
            return;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return;
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    std::process::exit(run(mode));
}

/// Embedded so the binary carries its own version. The installer staging
/// script greps every staged binary for the workspace version to catch a
/// stale artifact being shipped — a check that exists because a stale
/// daemon shipped twice — and a binary with no version string anywhere in
/// it fails that check, correctly.
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
sentinella-dnsreconcile - removes Sentinella's NRPT rule unless the proxy is alive

  (no args)   reconcile: remove the rule unless 127.0.0.1:53 answers as ours
  --dry-run   report what would happen, change nothing
  --remove    remove the rule unconditionally (the uninstall path)

  --install-task  register the boot-time Scheduled Task (installer only)
  --remove-task   unregister it (uninstaller only)

  --help      this text
  --version   print the version

Exit 0 = the system is in the intended state. Exit 1 = it is not and we
could not fix it (almost always: not running as SYSTEM/Administrator).";

/// Installer entry point. Separate from reconciliation on purpose: this
/// binary must be able to register its own task WITHOUT touching NRPT
/// state, so the MSI can create the task before any rule can exist.
fn install_task() {
    match task::install() {
        Ok(()) => println!("registered {}", task::TASK_NAME),
        Err(e) => {
            eprintln!("sentinella-dnsreconcile: cannot register task: {e}");
            std::process::exit(1);
        }
    }
}

/// Uninstaller entry point.
///
/// REFUSES while a rule is still live. The uninstall ladder is meant to
/// remove the RULE first (`--remove`) and the task second, but that
/// ordering lives in MSI sequencing — which a future edit, a partial
/// uninstall, or someone running this by hand can all get wrong. Deleting
/// the remover while a rule is still installed is precisely the state this
/// design exists to prevent, so the refusal belongs HERE, where it holds
/// regardless of who is calling and in what order.
fn remove_task() {
    let state_file = nrpt::default_state_file();
    if let Some(guid) = nrpt::recorded_guid(&state_file) {
        match nrpt::rule_exists(&guid) {
            Ok(true) => {
                let msg = format!(
                    "refusing to unregister {}: NRPT rule {guid} is still installed.                      Remove the rule first (--remove); deleting the task now would                      leave this machine's DNS pointed at a proxy with nothing able                      to undo it.",
                    task::TASK_NAME
                );
                log(&state_file, &msg);
                eprintln!("sentinella-dnsreconcile: {msg}");
                std::process::exit(1);
            }
            // Unreadable registry is not "confirmed absent". Same reasoning
            // as the reconcile path: refuse rather than act on a guess.
            Err(e) => {
                let msg = format!("refusing to unregister {}: cannot confirm the rule is gone ({e})", task::TASK_NAME);
                log(&state_file, &msg);
                eprintln!("sentinella-dnsreconcile: {msg}");
                std::process::exit(1);
            }
            Ok(false) => {}
        }
    }
    match task::remove() {
        Ok(()) => {
            log(&state_file, "unregistered the boot reconciler task");
            println!("unregistered {}", task::TASK_NAME);
        }
        Err(e) => {
            eprintln!("sentinella-dnsreconcile: cannot unregister task: {e}");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Reconcile,
    DryRun,
    ForceRemove,
}

fn run(mode: Mode) -> i32 {
    let state_file = nrpt::default_state_file();

    // No recorded GUID means no rule was ever created: record_guid writes
    // the file BEFORE the rule exists, so this direction is safe. Nothing
    // to reconcile.
    let Some(guid) = nrpt::recorded_guid(&state_file) else {
        log(&state_file, "no recorded rule - nothing to reconcile");
        return 0;
    };

    match nrpt::rule_exists(&guid) {
        Ok(false) => {
            // The rule is gone but our record lingers — after a manual
            // removal, a registry restore, or a GPO takeover. Tidy up so a
            // later install starts from a clean slate.
            log(&state_file, &format!("recorded rule {guid} is absent - clearing stale record"));
            if mode != Mode::DryRun {
                let _ = nrpt::clear_guid(&state_file);
            }
            return 0;
        }
        Ok(true) => {}
        Err(e) => {
            // CANNOT READ is not CAN CONFIRM ABSENT. Refusing to act on an
            // unreadable registry is the whole reason those are separate
            // error variants: acting would mean deleting on a guess.
            log(&state_file, &format!("cannot determine rule state: {e}"));
            eprintln!("sentinella-dnsreconcile: {e}");
            return 1;
        }
    }

    if mode == Mode::ForceRemove {
        return remove(&state_file, &guid, mode, "unconditional removal requested");
    }

    // The rule is live. The only thing that justifies leaving it there is
    // proof that OUR proxy is answering at the address it points to.
    if probe_is_ours() {
        log(&state_file, &format!("rule {guid} is live and the proxy answers - leaving it"));
        return 0;
    }

    remove(
        &state_file,
        &guid,
        mode,
        "rule is live but 127.0.0.1:53 did not answer with our signature",
    )
}

fn remove(state_file: &Path, guid: &str, mode: Mode, why: &str) -> i32 {
    if mode == Mode::DryRun {
        log(state_file, &format!("DRY RUN: would remove {guid} ({why})"));
        println!("would remove {guid}: {why}");
        return 0;
    }
    match nrpt::remove_rule(guid) {
        Ok(()) => {
            // Rule first, record second. The reverse order would leave a
            // moment where the rule exists and nothing names it.
            let _ = nrpt::clear_guid(state_file);
            log(state_file, &format!("REMOVED {guid} ({why}) - DNS restored to system defaults"));
            println!("removed {guid}: {why}");
            0
        }
        Err(e) => {
            log(state_file, &format!("FAILED to remove {guid}: {e}"));
            eprintln!("sentinella-dnsreconcile: failed to remove {guid}: {e}");
            // Leave the record in place: the rule is still there, and the
            // next boot must try again rather than forget about it.
            1
        }
    }
}

/// Ask `127.0.0.1:53` for the canary and require OUR signature back.
///
/// The signature — NOERROR, AA=1, one answer, A `0.0.0.0`, our txid echoed
/// — is synthesized by the serving path itself and can come from neither
/// the cache nor an upstream. A `.invalid` name NXDOMAINs on every stock
/// resolver, so an NXDOMAIN proves nothing; only the signature identifies
/// a local zero-IP blocker on that socket.
///
/// `wire::build_query` emits NO EDNS0 OPT, which is required: the trailing
/// rdata test is only valid for a response that carries none, and the
/// proxy appends an OPT whenever the requester sent one.
fn probe_is_ours() -> bool {
    match PROBE_ADDR.parse::<SocketAddr>() {
        Ok(addr) => probe_addr(addr),
        Err(_) => false,
    }
}

/// The address-taking half, so the positive case can be tested against a
/// real proxy on an ephemeral port.
fn probe_addr(addr: SocketAddr) -> bool {
    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PROBE_GAP);
        }
        if probe_once(addr) {
            return true;
        }
    }
    false
}

fn probe_once(addr: SocketAddr) -> bool {
    // A fresh ephemeral socket per attempt, connected so the kernel drops
    // datagrams from anywhere else.
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    if sock.set_read_timeout(Some(PROBE_TIMEOUT)).is_err() || sock.connect(addr).is_err() {
        return false;
    }
    // The txid does not need to be unguessable here — this is loopback and
    // the socket is connected — but it must be echoed, which is what makes
    // a stale datagram from a previous attempt fail the check.
    let id = (std::process::id() as u16) ^ 0xA5A5;
    let Some(query) = wire::build_query(id, CANARY_DOMAIN, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&query).is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    match sock.recv(&mut buf) {
        Ok(n) => is_canary_signature(&buf[..n], id),
        Err(_) => false,
    }
}

/// Append one line to a bounded log next to the state file.
///
/// This process has no console at boot and Task Scheduler keeps no output,
/// so without this a removal would be invisible — and "my DNS changed and I
/// do not know why" is exactly the question this file has to answer.
/// Every failure here is swallowed: logging must never be the reason the
/// machine keeps a broken rule.
///
/// Messages are ASCII-only on purpose. This file gets read with `type`,
/// Notepad, or whatever a support engineer has to hand on a machine with
/// no working DNS; a UTF-8 em-dash renders as mojibake in a legacy-codepage
/// console, and the one artifact that has to be readable in an emergency
/// should not depend on the reader's encoding.
fn log(state_file: &Path, msg: &str) {
    let Some(dir) = state_file.parent().and_then(Path::parent) else {
        return;
    };
    let path: PathBuf = dir.join("logs").join("dnsreconcile.log");
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > LOG_MAX_BYTES {
        let _ = std::fs::write(&path, b"");
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing listening, the probe must fail — and fail in bounded
    /// time. A reconciler that hung here would delay every boot.
    #[test]
    fn probe_fails_fast_when_nothing_listens() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dead = sock.local_addr().expect("addr");
        drop(sock);
        let started = std::time::Instant::now();
        assert!(!probe_once(dead));
        assert!(
            started.elapsed() < PROBE_TIMEOUT * 2,
            "a dead port must not cost more than one timeout"
        );
    }

    /// Something answering on the port is NOT enough — an impostor, or a
    /// different resolver that happens to own 53, must not keep our rule
    /// alive. Only the signature counts.
    #[test]
    fn a_wrong_answer_is_not_our_proxy() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let addr = server.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, peer)) = server.recv_from(&mut buf) {
                // Echo the query back with QR set: a plausible-looking DNS
                // answer that carries none of the signature.
                let mut resp = buf[..n].to_vec();
                if resp.len() > 2 {
                    resp[2] |= 0x80;
                }
                let _ = server.send_to(&resp, peer);
            }
        });
        assert!(
            !probe_once(addr),
            "a generic DNS answer must not be mistaken for our proxy"
        );
    }

    /// The forensic log and the usage text are read on a machine with no
    /// DNS, by whoever is trying to find out why. A non-ASCII byte renders
    /// as mojibake in a legacy-codepage console, so every string this
    /// binary can emit is pinned to ASCII.
    #[test]
    fn everything_this_binary_prints_is_ascii() {
        let guid = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";
        let why = "rule is live but 127.0.0.1:53 did not answer with our signature";
        for m in [
            "no recorded rule - nothing to reconcile".to_string(),
            format!("recorded rule {guid} is absent - clearing stale record"),
            format!("rule {guid} is live and the proxy answers - leaving it"),
            format!("REMOVED {guid} ({why}) - DNS restored to system defaults"),
            format!("FAILED to remove {guid}: access denied"),
            format!("DRY RUN: would remove {guid} ({why})"),
            USAGE.to_string(),
        ] {
            assert!(m.is_ascii(), "not ASCII, will render as mojibake: {m}");
        }
    }

    /// THE POSITIVE CASE, and the most important test here. If the probe
    /// cannot recognise a genuinely healthy proxy, the reconciler removes
    /// the rule on every single boot and web protection silently never
    /// works — a failure that looks like "the feature does nothing" rather
    /// than like a bug.
    ///
    /// Runs a REAL dnsguard proxy on an ephemeral port and probes it the
    /// same way the boot path probes 127.0.0.1:53.
    #[test]
    fn a_real_proxy_is_recognised_as_ours() {
        use dnsguard::filter::FilterEngine;
        use dnsguard::proxy::{NoopDecisionHook, Proxy, ProxyConfig};
        use std::sync::Arc;

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let (addr, _guard) = rt.block_on(async {
            // A dead upstream is fine: the canary is short-circuited before
            // decide/cache/forward, so it never touches one. That is
            // precisely what makes the signature un-forgeable by an
            // upstream, and it is why the reconciler can trust it.
            let cfg = ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec!["127.0.0.1:9".parse().unwrap()],
                ..ProxyConfig::default()
            };
            let proxy = Proxy::bind(cfg, FilterEngine::new(), Arc::new(NoopDecisionHook))
                .await
                .expect("bind");
            let addr = proxy.local_addr();
            let (tx, rx) = tokio::sync::watch::channel(false);
            let task = tokio::spawn(proxy.run(rx));
            (addr, (tx, task))
        });

        // Probed from a plain blocking thread, exactly as the boot path
        // does — no async runtime involved in the reconciler itself.
        assert!(
            probe_addr(addr),
            "the probe must recognise a healthy dnsguard as ours"
        );
    }

    /// The whole-of-probe budget must stay well inside a boot's patience
    /// even when every attempt times out.
    #[test]
    fn total_probe_budget_is_bounded() {
        let budget = PROBE_TIMEOUT * PROBE_ATTEMPTS as u32
            + PROBE_GAP * (PROBE_ATTEMPTS as u32 - 1);
        assert!(
            budget < Duration::from_secs(2),
            "probe budget {budget:?} is too long for a startup task"
        );
    }
}

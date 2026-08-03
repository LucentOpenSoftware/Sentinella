//! Discovering the machine's real DNS servers.
//!
//! `upstreams = ["system"]` means "whatever the active adapters are
//! configured to use". There is no registry location that answers this
//! correctly across DHCP, VPN tunnels and per-interface overrides —
//! `GetAdaptersAddresses` is the supported way, and it is what the DNS
//! Client itself resolves against.
//!
//! # The filter that matters
//!
//! A DNS server entry pointing at OUR OWN listener is an infinite loop:
//! one client query becomes an in-flight query to ourselves, which becomes
//! another, until the in-flight pool is saturated and every query on the
//! machine SERVFAILs. Measured on the crate under test: with
//! `max_in_flight = 64`, ONE client query produced 65 internal queries in
//! 26 ms.
//!
//! This is not a theoretical shape. `127.0.0.1` is the normal adapter DNS
//! on any machine that has ever run dnscrypt-proxy, Acrylic, a local
//! Pi-hole, or a previous install of this product. So loopback entries are
//! dropped, and if that leaves nothing we report NO upstreams rather than
//! inventing one — the design forbids a hardcoded public resolver, and a
//! resolver silently pointed somewhere the operator did not choose is
//! worse than a resolver that refuses to start.
//!
//! Dropped ENTRY BY ENTRY, by the same test `dnsguard` applies at bind
//! (see `is_self_referential`). The two halves of one safety rule have to
//! agree: dnsguard rejects the whole list on one bad address, so anything
//! this filter lets through and dnsguard then refuses costs us every good
//! upstream that was in the list alongside it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tracing::{debug, warn};

/// DNS is always port 53 here: adapter configuration carries no port, and
/// NRPT's `NameServers` has no port syntax either.
const DNS_PORT: u16 = 53;

/// Windows hands out these site-local IPv6 anycast addresses as
/// PLACEHOLDERS on interfaces with no real IPv6 DNS configured. They are
/// deprecated (RFC 3879) and forwarding to them times out, which would
/// make `upstream_ok` false on a machine whose IPv4 DNS is perfectly
/// healthy. Recognised and dropped.
const IPV6_PLACEHOLDER_PREFIX: [u16; 4] = [0xfec0, 0, 0, 0xffff];

/// Why discovery produced nothing usable. Distinguished because the fixes
/// differ: "no adapters" is a machine problem, "only loopback" is a
/// configuration problem the operator can solve by naming upstreams
/// explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The API call itself failed.
    QueryFailed(String),
    /// No up, non-loopback adapter reported any DNS server.
    NoneConfigured,
    /// Every discovered server was dropped by the self-reference filter.
    OnlyLoopback { dropped: usize },
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryFailed(e) => write!(f, "adapter enumeration failed: {e}"),
            Self::NoneConfigured => write!(f, "no active adapter reports a DNS server"),
            Self::OnlyLoopback { dropped } => write!(
                f,
                "all {dropped} configured DNS server(s) are loopback addresses — \
                 forwarding to them would point this proxy at itself; \
                 set web_protection.upstreams explicitly"
            ),
        }
    }
}

/// Resolve the configured `upstreams` list into concrete addresses.
///
/// `"system"` expands to discovery; explicit `IP:port` entries pass
/// through. Order is preserved and duplicates are removed, because
/// `pick_upstream` is round-robin and a duplicated entry would silently
/// get double the share of queries.
pub fn resolve(configured: &[String], listen: SocketAddr) -> Result<Vec<SocketAddr>, DiscoveryError> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut discovery_error: Option<DiscoveryError> = None;

    for entry in configured {
        if entry == super::config::UPSTREAM_SYSTEM {
            match discover(listen) {
                Ok(found) => push_unique(&mut out, found),
                // Hold the error: an explicit entry later in the list may
                // still make the config workable, and refusing then would
                // be worse than the operator's stated intent.
                Err(e) => discovery_error = Some(e),
            }
        } else if let Ok(addr) = entry.parse::<SocketAddr>() {
            push_unique(&mut out, vec![addr]);
        } else {
            // Config validation already rejects this shape and forces the
            // section off; reaching here means validation was bypassed.
            warn!(entry = %entry, "web_protection upstream is not IP:port — ignored");
        }
    }

    if out.is_empty() {
        return Err(discovery_error.unwrap_or(DiscoveryError::NoneConfigured));
    }
    Ok(out)
}

fn push_unique(out: &mut Vec<SocketAddr>, more: Vec<SocketAddr>) {
    for a in more {
        if !out.contains(&a) {
            out.push(a);
        }
    }
}

/// Enumerate the machine's DNS servers, dropping the ones we must not
/// forward to.
pub fn discover(listen: SocketAddr) -> Result<Vec<SocketAddr>, DiscoveryError> {
    let raw = platform::enumerate_dns_servers().map_err(DiscoveryError::QueryFailed)?;
    if raw.is_empty() {
        return Err(DiscoveryError::NoneConfigured);
    }
    let total = raw.len();
    let kept = filter_usable(raw, listen);
    if kept.is_empty() {
        return Err(DiscoveryError::OnlyLoopback { dropped: total });
    }
    debug!(
        found = total,
        kept = kept.len(),
        "discovered system DNS servers"
    );
    Ok(kept)
}

/// The filtering half, split out so it is testable without a network
/// stack. Takes bare IPs (adapter config has no port) and returns
/// `SocketAddr`s on 53.
fn filter_usable(raw: Vec<IpAddr>, listen: SocketAddr) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for ip in raw {
        if is_ipv6_placeholder(&ip) {
            debug!(%ip, "dropping IPv6 site-local DNS placeholder");
            continue;
        }
        if ip.is_unspecified() || ip.is_multicast() {
            debug!(%ip, "dropping unusable DNS server address");
            continue;
        }
        let addr = SocketAddr::new(ip, DNS_PORT);
        // THE LOOP GUARD. A loopback DNS server on our own port is us, and
        // even a loopback server on a DIFFERENT port is a local resolver
        // that may itself be configured to point back here. We keep the
        // latter — it is a legitimate chained-resolver setup and refusing
        // it would break dnscrypt users — but never the former.
        if is_self_referential(addr, listen) {
            warn!(%ip, %listen, "dropping DNS server that is this proxy itself");
            continue;
        }
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Would `dnsguard` refuse this upstream as self-referential?
///
/// THIS MUST MATCH `dnsguard::proxy::validate_upstreams` EXACTLY, because
/// the two run in sequence and the narrower one runs FIRST. `filter_usable`
/// used to drop only the exact `ip:53 == listen` match, so `[::1]` or
/// `127.0.0.2` survived discovery on a machine that had once run
/// dnscrypt-proxy / AdGuard Home / a host Pi-hole (they configure both
/// families, and 127/8 is all loopback). `Proxy::bind` then rejected the
/// WHOLE list on that one entry and web protection refused to start —
/// throwing away the perfectly usable LAN resolver that was sitting next to
/// it. Dropping the entry keeps the list; rejecting it loses the list.
///
/// The rule is about the LISTEN PORT, not about loopback: a local resolver
/// on some other port is a legitimate chained setup and must survive.
fn is_self_referential(upstream: SocketAddr, listen: SocketAddr) -> bool {
    upstream == listen
        || (listen.port() != 0
            && upstream.port() == listen.port()
            && upstream.ip().is_loopback()
            && (listen.ip().is_loopback() || listen.ip().is_unspecified()))
}

fn is_ipv6_placeholder(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            seg[0..4] == IPV6_PLACEHOLDER_PREFIX
        }
        IpAddr::V4(_) => false,
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    /// Bounded retry on the grow-the-buffer dance. Between two calls the
    /// adapter set can change and the required size can grow again; three
    /// attempts is generous, and a bound means a machine churning through
    /// VPN connects can never spin here forever.
    const MAX_ATTEMPTS: usize = 3;
    /// MSDN recommends 15 KB as the starting allocation.
    const INITIAL_BUF: usize = 15 * 1024;
    /// Refuse to keep growing past this. A legitimate answer is a few tens
    /// of KB; anything larger means something is wrong and we would rather
    /// report a failure than allocate unboundedly inside a service.
    const MAX_BUF: usize = 4 * 1024 * 1024;

    pub fn enumerate_dns_servers() -> Result<Vec<IpAddr>, String> {
        // SKIP_UNICAST/ANYCAST/MULTICAST/FRIENDLY_NAME: we want ONLY the
        // DNS server lists, and every skipped section is memory the API
        // does not have to write and we do not have to walk.
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;

        let mut size = INITIAL_BUF as u32;
        for _ in 0..MAX_ATTEMPTS {
            if size as usize > MAX_BUF {
                return Err(format!("adapter table exceeds {MAX_BUF} bytes"));
            }
            // IP_ADAPTER_ADDRESSES_LH has pointer alignment; a Vec<u8>
            // gives us no such guarantee, so allocate a Vec of the struct
            // and use it as a byte buffer.
            let count = (size as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
            let mut buf: Vec<IP_ADAPTER_ADDRESSES_LH> = Vec::with_capacity(count.max(1));
            let ptr = buf.as_mut_ptr();

            // SAFETY: `ptr` is a valid, properly aligned allocation of at
            // least `size` bytes (count * size_of rounds up). The API
            // either fills it and returns NO_ERROR, or writes nothing and
            // returns ERROR_BUFFER_OVERFLOW with the needed size in
            // `size`. We only read the buffer in the NO_ERROR case.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    Some(std::ptr::null_mut::<c_void>()),
                    Some(ptr),
                    &mut size,
                )
            };

            match windows::Win32::Foundation::WIN32_ERROR(rc) {
                NO_ERROR => {
                    // SAFETY: the call succeeded, so the API wrote a
                    // NULL-terminated linked list starting at `ptr`.
                    return Ok(unsafe { walk_adapters(ptr) });
                }
                ERROR_BUFFER_OVERFLOW => {
                    // `size` now holds the required length; loop and retry.
                    continue;
                }
                other => {
                    return Err(format!("GetAdaptersAddresses failed: {}", other.0));
                }
            }
        }
        Err(format!(
            "GetAdaptersAddresses did not settle in {MAX_ATTEMPTS} attempts"
        ))
    }

    /// SAFETY: `head` must be either null or the start of a valid
    /// NULL-terminated `IP_ADAPTER_ADDRESSES_LH` list written by
    /// `GetAdaptersAddresses`, and must outlive this call.
    unsafe fn walk_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut adapter = head;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };

            // Only adapters that are actually up. A disconnected NIC keeps
            // its stale DNS servers in the table, and forwarding to them
            // just burns the upstream timeout on every query.
            let usable = a.OperStatus == IfOperStatusUp
                && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK;
            if usable {
                let mut dns = a.FirstDnsServerAddress;
                while !dns.is_null() {
                    let d = unsafe { &*dns };
                    if let Some(ip) = unsafe { sockaddr_to_ip(d.Address.lpSockaddr as *const _) } {
                        out.push(ip);
                    }
                    dns = d.Next;
                }
            }
            adapter = a.Next;
        }
        out
    }

    /// SAFETY: `sa` must be null or point to a valid `SOCKADDR` whose
    /// `sa_family` correctly describes the storage behind it.
    unsafe fn sockaddr_to_ip(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        let family = unsafe { (*sa).sa_family };
        if family == AF_INET {
            let v4 = unsafe { &*(sa as *const SOCKADDR_IN) };
            // S_un is a union of byte/word/dword views of the same 4 bytes.
            let octets = unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        } else if family == AF_INET6 {
            let v6 = unsafe { &*(sa as *const SOCKADDR_IN6) };
            let octets = unsafe { v6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn enumerate_dns_servers() -> Result<Vec<IpAddr>, String> {
        Err("adapter DNS discovery is only implemented on Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen53() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    /// THE defect this filter exists for. A machine that has ever run a
    /// local resolver keeps 127.0.0.1 as its adapter DNS; forwarding there
    /// while we ARE 127.0.0.1:53 turns one client query into a
    /// pool-saturating storm against ourselves.
    #[test]
    fn our_own_listen_address_is_never_an_upstream() {
        let raw = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(kept, vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    /// REGRESSION. The filter used to compare against `listen` for exact
    /// equality, so a leftover `::1` or `127.0.0.2` adapter entry survived
    /// discovery — and `Proxy::bind` then rejected the ENTIRE list on it,
    /// taking the usable LAN resolver down with it. Web protection reported
    /// BindFailed on a machine whose DNS was perfectly serviceable.
    ///
    /// Both shapes are ordinary leftovers: removing dnscrypt-proxy /
    /// AdGuard Home / a host Pi-hole leaves loopback DNS configured on both
    /// families, and every address in 127/8 is loopback.
    #[test]
    fn any_loopback_alias_on_our_port_is_dropped_not_the_whole_list() {
        for leftover in ["::1", "127.0.0.2", "127.44.0.9"] {
            let raw = vec![
                leftover.parse().unwrap(),
                "192.168.1.1".parse().unwrap(),
            ];
            let kept = filter_usable(raw, listen53());
            assert_eq!(
                kept,
                vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()],
                "{leftover}: dnsguard would refuse the whole list over this entry"
            );
        }
    }

    /// The filter and `dnsguard::proxy::validate_upstreams` are one rule in
    /// two places, and the narrower one runs first. Anything this predicate
    /// calls safe must still be safe there.
    #[test]
    fn the_self_reference_test_matches_dnsguards() {
        let listen: SocketAddr = "127.0.0.1:53".parse().unwrap();
        for refused in ["127.0.0.1:53", "127.0.0.2:53", "[::1]:53"] {
            assert!(
                is_self_referential(refused.parse().unwrap(), listen),
                "{refused} is refused by dnsguard at bind"
            );
        }
        for allowed in ["127.0.0.1:5353", "192.168.1.1:53", "[2001:db8::1]:53"] {
            assert!(
                !is_self_referential(allowed.parse().unwrap(), listen),
                "{allowed} is accepted by dnsguard and must not be dropped here"
            );
        }
        // A wildcard listener receives loopback traffic, so dnsguard treats
        // loopback-on-the-listen-port as self-referential there too.
        let wildcard: SocketAddr = "0.0.0.0:53".parse().unwrap();
        assert!(is_self_referential("127.0.0.1:53".parse().unwrap(), wildcard));
        // Port 0 means the port is not chosen yet: only identity counts.
        let ephemeral: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(is_self_referential(ephemeral, ephemeral));
        assert!(!is_self_referential("127.0.0.1:53".parse().unwrap(), ephemeral));
    }

    /// A loopback resolver on a DIFFERENT port is a legitimate chained
    /// setup (dnscrypt-proxy on 5353, say) and must survive — dropping it
    /// would break those users for no safety gain.
    #[test]
    fn a_loopback_resolver_on_another_port_is_kept() {
        let listen: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let kept = filter_usable(vec!["127.0.0.1".parse().unwrap()], listen);
        assert_eq!(
            kept,
            vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()],
            "only the exact self-reference is a loop"
        );
    }

    #[test]
    fn ipv6_site_local_placeholders_are_dropped() {
        let raw = vec![
            "fec0:0:0:ffff::1".parse().unwrap(),
            "fec0:0:0:ffff::2".parse().unwrap(),
            "fec0:0:0:ffff::3".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec!["[2001:4860:4860::8888]:53".parse::<SocketAddr>().unwrap()],
            "the three Windows placeholders must not become upstreams"
        );
    }

    #[test]
    fn unspecified_and_multicast_are_dropped() {
        let raw = vec![
            "0.0.0.0".parse().unwrap(),
            "224.0.0.251".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(kept, vec!["9.9.9.9:53".parse::<SocketAddr>().unwrap()]);
    }

    /// Round-robin gives each entry an equal share, so a duplicate would
    /// silently double one server's load.
    #[test]
    fn duplicates_collapse_preserving_order() {
        let raw = vec![
            "1.1.1.1".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:53".parse::<SocketAddr>().unwrap()
            ]
        );
    }

    /// Explicit entries must not be silently replaced by discovery, and
    /// discovery failing must not discard them.
    #[test]
    fn explicit_upstreams_survive_a_failed_discovery() {
        let out = resolve(
            &["system".into(), "9.9.9.9:53".into()],
            "127.0.0.1:53".parse().unwrap(),
        );
        // Discovery may or may not find anything on the build machine; the
        // explicit entry must be present either way.
        let out = out.expect("an explicit upstream must keep the config usable");
        assert!(
            out.contains(&"9.9.9.9:53".parse::<SocketAddr>().unwrap()),
            "explicit upstream dropped: {out:?}"
        );
    }

    #[test]
    fn only_loopback_reports_the_actionable_error() {
        // filter_usable drops it; discover() turns that into the error
        // that names the fix rather than a bare "none configured".
        let kept = filter_usable(vec!["127.0.0.1".parse().unwrap()], listen53());
        assert!(kept.is_empty());
        let e = DiscoveryError::OnlyLoopback { dropped: 1 };
        assert!(
            e.to_string().contains("set web_protection.upstreams explicitly"),
            "the error must tell the operator what to do: {e}"
        );
    }

    /// Real discovery against the live machine. IGNORED by default because
    /// it asserts on whatever this box's adapters happen to say — but it is
    /// the only thing that exercises the unsafe FFI, so run it by hand when
    /// touching `platform`:
    ///
    ///   cargo test -p sentinelld real_discovery -- --ignored --nocapture
    #[test]
    #[ignore = "environment-dependent: exercises the live GetAdaptersAddresses FFI"]
    fn real_discovery_against_this_machine() {
        match discover(listen53()) {
            Ok(found) => {
                println!("discovered {} upstream(s):", found.len());
                for a in &found {
                    println!("  {a}");
                }
                assert!(!found.is_empty());
                for a in &found {
                    assert_eq!(a.port(), 53, "adapter DNS is always port 53");
                    assert_ne!(*a, listen53(), "self-reference must never survive");
                }
            }
            Err(e) => println!("no usable upstreams on this machine: {e}"),
        }
    }

    /// No hardcoded public resolver, ever: an empty result is an error,
    /// not a silent substitution.
    #[test]
    fn empty_configured_list_is_an_error_not_a_default() {
        let out = resolve(&[], "127.0.0.1:53".parse().unwrap());
        assert!(matches!(out, Err(DiscoveryError::NoneConfigured)));
    }
}

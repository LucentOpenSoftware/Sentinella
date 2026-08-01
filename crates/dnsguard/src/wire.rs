//! Minimal, dependency-free DNS wire codec (RFC 1035 subset).
//!
//! WHY hand-rolled: the design (docs/WEB_PROTECTION_DESIGN.md §3) forbids a
//! DNS-crate dependency and requires the same discipline as the framework's
//! binary parsers — bounded, total functions that cannot panic on arbitrary
//! bytes. Every offset into the packet is bounds-checked before use; all
//! fallible operations return `Option`/`Result`.
//!
//! Scope: we parse the header and exactly one question (all we need to
//! filter and to echo the question back), skip resource records safely for
//! TTL extraction, and build query/error/zero-IP responses. We never
//! decompress answer-section names — skipping a name only needs the pointer
//! bytes, which keeps the codec loop-free by construction.

use thiserror::Error;

pub const HEADER_LEN: usize = 12;
/// Maximum wire length of a domain name (RFC 1035 §3.1).
pub const MAX_NAME_WIRE_LEN: usize = 255;
/// Maximum label length (6-bit length field).
pub const MAX_LABEL_LEN: usize = 63;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
/// Authoritative-answer bit. Set ONLY on block answers we synthesize
/// locally (NXDOMAIN / zero-IP / canary): it is the self-identifying mark
/// that lets the health check tell "OUR filter answered" apart from "some
/// upstream produced the same rcode". Never set on relayed or error
/// (FORMERR/SERVFAIL) responses.
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
/// Authentic-data bit (RFC 4035 §3.2.3). We are a non-validating forwarder:
/// AD is CLEARED on every response we emit (see
/// [`rewrite_response_flags_for_client`]) because relaying the upstream's AD
/// verbatim would assert an authentication we never performed — over
/// loopback, the one channel where a stub is entitled to trust AD.
const FLAG_AD: u16 = 0x0020;
/// Checking-disabled bit (RFC 4035 §3.1.6): a self-validating stub sets it
/// to suspend upstream validation. Relayed verbatim to the upstream and
/// echoed back to the client, exactly like RD.
const FLAG_CD: u16 = 0x0010;

/// Classic DNS-over-UDP payload limit without EDNS0 (RFC 1035 §4.2.1).
/// This is the DEFAULT, applied only to clients that sent no EDNS0 OPT;
/// clients that advertise a larger buffer via EDNS0 are served up to that
/// size (clamped to [`MAX_EDNS_UDP_PAYLOAD`]) before truncation kicks in.
pub const MAX_UDP_PAYLOAD: usize = 512;
/// Largest EDNS0-advertised UDP payload we honour toward a client (and
/// advertise upstream). Matches the proxy's datagram buffer; anything
/// beyond still truncates to TCP. RFC 6891 §6.2.5 recommends 4096 as the
/// upper end of the useful range.
pub const MAX_EDNS_UDP_PAYLOAD: usize = 4096;
/// Smallest payload size honourable per RFC 6891 §6.2.3: advertised values
/// below 512 MUST be treated as 512.
const MIN_EDNS_UDP_PAYLOAD: usize = 512;

/// Clamp a client-advertised EDNS0 UDP payload size to the range we serve:
/// `[512, 4096]` per RFC 6891 and our datagram buffer.
pub fn clamp_edns_udp_size(size: u16) -> usize {
    usize::from(size).clamp(MIN_EDNS_UDP_PAYLOAD, MAX_EDNS_UDP_PAYLOAD)
}

/// Errors that make a packet unusable as a query. The proxy maps every one
/// of these to a FORMERR response (or drops the packet if not even a header
/// is present to echo).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireError {
    #[error("packet truncated")]
    Truncated,
    #[error("QR bit set: not a query")]
    NotAQuery,
    #[error("question count {0}, exactly 1 supported")]
    BadQuestionCount(u16),
    #[error("compression pointer in question section")]
    CompressionInQuestion,
    #[error("reserved label type bits (0x40/0x80)")]
    InvalidLabelType,
    #[error("name exceeds 255 wire bytes")]
    NameTooLong,
}

/// A parsed DNS query: header fields we act on plus the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub opcode: u8,
    pub recursion_desired: bool,
    /// Presentation form, no trailing dot, labels joined by `.`, with RFC
    /// 4343 escaping: a `.` or `\` INSIDE a label is emitted as `\.` /
    /// `\\` (non-printable octets as `\DDD`). This makes the string
    /// unambiguous — the single wire label `microsoft.com` decodes to
    /// `microsoft\.com`, which can never collide with the two-label name
    /// `microsoft.com`. Filtering splits on UNescaped dots only.
    pub qname: String,
    /// Raw wire-format qname bytes (length-prefixed labels + root). This —
    /// never the presentation string — is the cache-key ingredient: raw
    /// bytes are injective by construction, so a hostile dot-in-label
    /// encoding cannot alias a victim domain's cache entry.
    pub qname_wire: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question section — the slice
    /// `HEADER_LEN..question_end` is the exact question bytes to echo.
    pub question_end: usize,
    /// Checking-disabled bit from the client's header (RFC 4035 §3.1.6).
    pub checking_disabled: bool,
    /// DNSSEC-OK bit from the client's EDNS0 OPT record (RFC 3225 §3).
    /// Always false when the query carries no OPT (the bit lives there).
    pub dnssec_ok: bool,
    /// UDP payload size advertised by the client's EDNS0 OPT record (RFC
    /// 6891), unclamped — apply [`clamp_edns_udp_size`] before use. `None`
    /// when the query carries no (parseable) OPT record, meaning the client
    /// gets the classic 512-byte limit.
    pub edns_udp_size: Option<u16>,
}

/// Summary of an upstream response used for cache decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseInfo {
    pub rcode: u8,
    /// Smallest TTL across answer records (`None` when the answer section
    /// is empty).
    pub min_ttl: Option<u32>,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(pair))
}

/// Parse a DNS query packet: full header + exactly one question.
///
/// Total over arbitrary input: any violation returns `Err`, never panics.
pub fn parse_query(bytes: &[u8]) -> Result<Query, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    // Header is exactly 12 bytes; all indexing below is within it.
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & FLAG_QR != 0 {
        return Err(WireError::NotAQuery);
    }
    let opcode = ((flags & FLAG_OPCODE_MASK) >> 11) as u8;
    let recursion_desired = flags & FLAG_RD != 0;
    let checking_disabled = flags & FLAG_CD != 0;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    // WHY exactly 1: multi-question DNS has no interoperable semantics
    // (RFC 9619 reserves QDCOUNT > 1); answering would guess. FORMERR is
    // the specified response.
    if qdcount != 1 {
        return Err(WireError::BadQuestionCount(qdcount));
    }
    let (qname, name_end) = parse_question_name(bytes, HEADER_LEN)?;
    let qtype = read_u16(bytes, name_end).ok_or(WireError::Truncated)?;
    let qclass = read_u16(bytes, name_end + 2).ok_or(WireError::Truncated)?;
    let question_end = name_end + 4;
    let (dnssec_ok, edns_udp_size) = find_opt(
        bytes,
        question_end,
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
    );
    Ok(Query {
        id,
        opcode,
        recursion_desired,
        qname,
        qname_wire: bytes[HEADER_LEN..name_end].to_vec(),
        qtype,
        qclass,
        question_end,
        checking_disabled,
        dnssec_ok,
        edns_udp_size,
    })
}

/// Walk the answer/authority/additional sections of a QUERY looking for the
/// EDNS0 OPT pseudo-record (RFC 6891), returning its DO bit and advertised
/// UDP payload size. Queries normally carry AN=NS=0 and one OPT in AR, but
/// every count is honoured so a hostile count cannot hide the OPT we would
/// otherwise relay decisions on.
///
/// Total and bounded: every step goes through [`skip_name`] or an explicit
/// bounds check, each record consumes at least 11 bytes (1-byte root name +
/// 10-byte fixed fields), so iteration is bounded by the packet length.
/// Any malformed trailing record yields `(false, None)` — trailing garbage
/// must not invalidate an otherwise good question (the codec has always
/// tolerated it), it simply means "no EDNS negotiated".
fn find_opt(
    bytes: &[u8],
    mut offset: usize,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> (bool, Option<u16>) {
    // Bounded by construction: each iteration advances `offset` past at
    // least one record or returns.
    let records = usize::from(ancount) + usize::from(nscount) + usize::from(arcount);
    for _ in 0..records {
        let Some(after_name) = skip_name(bytes, offset) else {
            return (false, None);
        };
        let Some(fixed) = bytes.get(after_name..after_name + 10) else {
            return (false, None);
        };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        // TTL field: extended-rcode(8) | version(8) | flags(16); DO is the
        // top flag bit (RFC 3225 §3).
        let flags = u16::from_be_bytes([fixed[6], fixed[7]]);
        let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data_end = match after_name.checked_add(10).and_then(|o| o.checked_add(rdlength)) {
            Some(end) if end <= bytes.len() => end,
            _ => return (false, None),
        };
        if rtype == 41 {
            // OPT: class is the requestor's UDP payload size. First OPT
            // wins; anything after it is ignored (a second OPT is malformed
            // per RFC 6891 §6.1.1, but not ours to police here).
            return (flags & 0x8000 != 0, Some(class));
        }
        offset = data_end;
    }
    (false, None)
}

/// Parse a question-section name into presentation form with RFC 4343
/// escaping (`.` → `\.`, `\` → `\\`, non-printable octets → `\DDD`).
///
/// Compression pointers are *rejected* here: they are not legal in queries
/// from well-behaved clients, and refusing them removes the entire class of
/// pointer-loop attacks by construction (a self-pointer can never be
/// followed because no pointer is ever followed).
///
/// WHY escaping matters (security): a `.` byte is legal INSIDE a wire
/// label, so the single label `microsoft.com` and the two-label name
/// `microsoft.com` are distinct names that join to the identical naive
/// string. Joined naively and used as a cache key, a one-socket process
/// could poison/blackhole any domain machine-wide. The escaped form is
/// injective; the cache key is the raw wire bytes regardless.
fn parse_question_name(bytes: &[u8], mut offset: usize) -> Result<(String, usize), WireError> {
    let mut name = String::new();
    // Root label alone costs 1 byte; every label costs 1 + len.
    let mut wire_len = 1usize;
    loop {
        let len = *bytes.get(offset).ok_or(WireError::Truncated)?;
        if len == 0 {
            return Ok((name, offset + 1));
        }
        if len & 0xC0 == 0xC0 {
            return Err(WireError::CompressionInQuestion);
        }
        if len & 0xC0 != 0 {
            return Err(WireError::InvalidLabelType);
        }
        let len = len as usize; // top bits clear ⇒ len ≤ 63
        let end = offset + 1 + len;
        if end > bytes.len() {
            // Label length byte overruns the packet.
            return Err(WireError::Truncated);
        }
        wire_len += 1 + len;
        if wire_len > MAX_NAME_WIRE_LEN {
            return Err(WireError::NameTooLong);
        }
        if !name.is_empty() {
            name.push('.');
        }
        push_label_escaped(&mut name, &bytes[offset + 1..end]);
        offset = end;
    }
}

/// Append one wire label to a presentation string, escaping per RFC 4343:
/// `.` → `\.`, `\` → `\\`, octets outside printable ASCII → `\DDD`.
fn push_label_escaped(out: &mut String, label: &[u8]) {
    use std::fmt::Write as _;
    for &byte in label {
        match byte {
            b'.' => out.push_str("\\."),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(char::from(byte)),
            _ => {
                // Non-printable / non-ASCII octet: decimal escape. Label
                // bytes are arbitrary octets; lossy UTF-8 decode would be
                // ambiguous, so never decode — escape.
                let _ = write!(out, "\\{byte:03}");
            }
        }
    }
}

/// Skip over a (possibly compressed) name, returning the offset of the next
/// field. Used on response resource records, where pointers are legal.
///
/// Loop-free by construction: a pointer terminates the name immediately (we
/// return past its 2 bytes without following it), and every other step
/// advances at least one byte within the packet.
fn skip_name(bytes: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *bytes.get(offset)?;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            return if offset + 2 <= bytes.len() {
                Some(offset + 2)
            } else {
                None
            };
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset += 1 + len as usize;
        if offset > bytes.len() {
            return None;
        }
    }
}

/// Extract rcode and the minimum answer TTL from an upstream response.
/// Returns `None` if the packet is too malformed to walk safely.
///
/// NOTE: this performs NO trust validation (any packet with a parsable
/// layout yields a `ResponseInfo`). Accepting an upstream response for
/// answering/caching requires [`validate_response`].
pub fn response_info(bytes: &[u8]) -> Option<ResponseInfo> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut offset = HEADER_LEN;
    for _ in 0..qdcount {
        offset = skip_name(bytes, offset)?;
        offset = offset.checked_add(4)?;
        if offset > bytes.len() {
            return None;
        }
    }
    walk_answers(bytes, offset, ancount, rcode)
}

/// Validate an upstream response against the exchange that produced it
/// (design doc §5 "Upstream response forgery / cache poisoning"):
///
/// - QR bit set (it is a response);
/// - transaction ID equals the per-query ID WE generated for the upstream
///   exchange (never the client-supplied ID);
/// - exactly one question, matching the question we forwarded: the qname
///   wire bytes compared ASCII-case-insensitively (RFC 4343 — DNS names
///   preserve case but compare case-insensitively; home CPE forwarders
///   normalize case, and byte-exactness would break behind them), qtype
///   and qclass compared exactly.
///
/// Case-insensitivity here cannot weaken the label structure: label
/// length bytes are ≤ 63 and ASCII letters are ≥ 65, so a length byte can
/// never alias a letter (or vice versa) under case folding.
///
/// Anything else returns `None`: the caller drops the packet, counts an
/// upstream error, and never caches it. On success, returns the rcode/TTL
/// summary for cache decisions.
pub fn validate_response(bytes: &[u8], expected_id: u16, question: &[u8]) -> Option<ResponseInfo> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & FLAG_QR == 0 {
        return None;
    }
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qdcount != 1 {
        return None;
    }
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    // The echoed question must match what we sent: qname case-insensitive
    // (see doc header), qtype/qclass byte-exact. A misbehaving/forging
    // source that re-encodes labels or answers a different question is
    // dropped.
    if question.len() < 4 {
        return None;
    }
    let echoed = bytes.get(HEADER_LEN..HEADER_LEN.checked_add(question.len())?)?;
    let (echoed_name, echoed_tail) = echoed.split_at(echoed.len() - 4);
    let (question_name, question_tail) = question.split_at(question.len() - 4);
    if !echoed_name.eq_ignore_ascii_case(question_name) || echoed_tail != question_tail {
        return None;
    }
    walk_answers(bytes, HEADER_LEN + question.len(), ancount, rcode)
}

/// Walk the answer section from `offset`, collecting the minimum TTL.
fn walk_answers(
    bytes: &[u8],
    mut offset: usize,
    ancount: usize,
    rcode: u8,
) -> Option<ResponseInfo> {
    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        offset = skip_name(bytes, offset)?;
        if offset.checked_add(10)? > bytes.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
        offset += 10;
        if offset.checked_add(rdlength)? > bytes.len() {
            return None;
        }
        offset += rdlength;
        min_ttl = Some(match min_ttl {
            Some(current) => current.min(ttl),
            None => ttl,
        });
    }
    Some(ResponseInfo { rcode, min_ttl })
}

/// True if the response has the TC (truncation) bit set — the signal to
/// retry over TCP. Safe on any input.
pub fn is_truncated_response(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN && u16::from_be_bytes([bytes[2], bytes[3]]) & FLAG_TC != 0
}

/// Rewrite the client-facing header flags of a RELAYED upstream response in
/// place. The upstream answered the CLEAN query we rebuilt, so its flag
/// echo describes our exchange, not the client's; three bits must be
/// corrected before the response is served or cached:
///
/// - **RD** is set to the CLIENT's value (RFC 1035 §4.1.1: RD is copied
///   from query to response). We force RD=1 upstream, so without this a
///   `+norecurse` client is told it asked for recursion — and the relayed
///   path would disagree with the blocked/error paths, which echo the
///   client's RD (L04).
/// - **CD** is set to the CLIENT's value (RFC 4035 §3.1.6), same argument.
/// - **AD** is CLEARED unconditionally (RFC 4035 §3.2.3, RFC 6840 §5.7):
///   AD asserts the responder authenticated the answer. We validate
///   nothing (txid + question echo over plaintext UDP is not
///   authentication), so relaying the upstream's AD verbatim would be a
///   lie told over loopback — the one channel where a stub is entitled to
///   trust AD (L01). Clients that need authenticated data must validate
///   themselves; relaying CD/DO (which we do) makes that possible.
///
/// Total over arbitrary input: packets shorter than a header are left
/// untouched.
pub fn rewrite_response_flags_for_client(resp: &mut [u8], recursion_desired: bool, checking_disabled: bool) {
    if resp.len() < HEADER_LEN {
        return;
    }
    let mut flags = u16::from_be_bytes([resp[2], resp[3]]);
    flags &= !(FLAG_AD | FLAG_RD | FLAG_CD);
    if recursion_desired {
        flags |= FLAG_RD;
    }
    if checking_disabled {
        flags |= FLAG_CD;
    }
    resp[2..4].copy_from_slice(&flags.to_be_bytes());
}

/// Build a standard query packet. Returns `None` for names that cannot be
/// encoded (empty labels, label > 63, name > 255 wire bytes).
pub fn build_query(id: u16, qname: &str, qtype: u16, qclass: u16) -> Option<Vec<u8>> {
    let qname = qname.trim_end_matches('.');
    let mut out = Vec::with_capacity(HEADER_LEN + qname.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
    let mut wire_len = 1usize;
    if !qname.is_empty() {
        for label in qname.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return None;
            }
            wire_len += 1 + label.len();
            if wire_len > MAX_NAME_WIRE_LEN {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    Some(out)
}

/// Build the CLEAN query we send upstream for a client query: a fresh
/// (caller-generated) transaction ID, flags rebuilt from scratch (RD=1
/// always — we are a recursive forwarder; CD relayed verbatim from the
/// client per RFC 4035 §3.1.6 so a self-validating stub can suspend
/// upstream validation), QDCOUNT=1, zeroed AN/NS counts, and exactly the
/// question section.
///
/// EDNS0 policy (decided in round 3, L01): when the client sent an OPT
/// record, we send exactly ONE OPT upstream carrying the client's
/// advertised UDP size (clamped to `[512, 4096]` — we must be able to
/// buffer what we ask for, and RFC 6891 §6.2.3 floors sub-512 values) and
/// the client's DO bit (RFC 3225), so a client asking for DNSSEC records
/// gets them instead of a silent downgrade. NOTHING ELSE is relayed: no
/// ECS (it would steer the answer we then cache machine-wide), no cookies,
/// no client options of any kind — the OPT we emit is one we constructed.
/// `edns` is `(udp_size, dnssec_ok)`; `None` means the client sent no OPT
/// and the upstream query carries ARCOUNT=0, exactly as before.
///
/// `question` must be the exact wire question slice (name + qtype +
/// qclass) from a successfully parsed query.
pub fn build_upstream_query(
    id: u16,
    question: &[u8],
    checking_disabled: bool,
    edns: Option<(u16, bool)>,
) -> Vec<u8> {
    let flags = FLAG_RD | if checking_disabled { FLAG_CD } else { 0 };
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + 11);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0, 0, 0, 0]); // an/ns — always zero
    out.extend_from_slice(&u16::from(edns.is_some()).to_be_bytes()); // arcount
    out.extend_from_slice(question);
    if let Some((udp_size, dnssec_ok)) = edns {
        let size = clamp_edns_udp_size(udp_size) as u16;
        out.push(0); // name: root
        out.extend_from_slice(&41u16.to_be_bytes()); // type: OPT
        out.extend_from_slice(&size.to_be_bytes()); // class: our UDP size
        // ttl: extended-rcode 0 | version 0 | flags (DO only).
        out.extend_from_slice(&[0, 0, if dnssec_ok { 0x80 } else { 0 }, 0]);
        out.extend_from_slice(&[0, 0]); // rdlength: no options
    }
    out
}

/// Build a TRUNCATED response (TC bit set, question section only,
/// ANCOUNT/NSCOUNT/ARCOUNT zeroed) for a UDP client whose full answer
/// exceeds its UDP payload limit — RFC 2181-style truncation so the
/// client retries over TCP. WHY: replaying a large (e.g. TCP-fetched,
/// up to 65535-byte) answer to a UDP client produces an oversized
/// datagram the OS drops (WSAEMSGSIZE on Windows) with TC clear — the
/// client gets a hard failure with no retry signal, sticky for the cache
/// lifetime. This fires with NO attacker via ordinary TC-fallback
/// traffic.
///
/// `rcode` must be the RCODE of the full answer being truncated (L02): a
/// truncated NXDOMAIN must keep rcode=3 — hardcoding NOERROR turns a
/// cached negative answer into "name exists, no records" for any client
/// that reads TC=1/NOERROR/ANCOUNT=0 as NODATA, for the whole negative
/// cache window.
///
/// Returns `None` when the request is shorter than a header (nothing to
/// echo an ID from) — total over arbitrary input. Callers must treat
/// `None` as an error path (SERVFAIL or drop), NEVER as "send the full
/// oversized response" (L03).
pub fn build_truncated_response(request: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN {
        return None;
    }
    let flags_in = u16::from_be_bytes([request[2], request[3]]);
    let flags = FLAG_QR
        | (flags_in & FLAG_OPCODE_MASK)
        | (flags_in & FLAG_RD)
        | (flags_in & FLAG_CD)
        | FLAG_RA
        | FLAG_TC
        | u16::from(rcode & 0x0F);
    let question = parse_query(request)
        .ok()
        .map(|q| &request[HEADER_LEN..q.question_end]);
    let mut out = Vec::with_capacity(HEADER_LEN + question.map_or(0, <[u8]>::len));
    out.extend_from_slice(&request[0..2]); // same ID
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar zeroed
    if let Some(question) = question {
        out.extend_from_slice(question);
    }
    Some(out)
}

/// Build an error response (FORMERR / SERVFAIL / NXDOMAIN) echoing the
/// request's ID and — when the question parsed — the question section, with
/// QR and RA set and RD/opcode preserved.
///
/// `aa` sets the Authoritative-Answer bit ([`FLAG_AA`]): pass `true` ONLY
/// for locally synthesized BLOCK answers (the NXDOMAIN a blocked query
/// gets), where AA is the self-identifying mark the health check relies on
/// to distinguish "our filter fired" from "an upstream happened to return
/// the same rcode". FORMERR/SERVFAIL are not authoritative — pass `false`.
///
/// Returns `None` when the request is shorter than a header; there is no ID
/// to answer with, so the only safe behavior is to drop it.
pub fn build_error_response(request: &[u8], rcode: u8, aa: bool) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN {
        return None;
    }
    let flags_in = u16::from_be_bytes([request[2], request[3]]);
    let flags = FLAG_QR
        | (flags_in & FLAG_OPCODE_MASK)
        | (flags_in & FLAG_RD)
        | (flags_in & FLAG_CD)
        | FLAG_RA
        | if aa { FLAG_AA } else { 0 }
        | u16::from(rcode & 0x0F);
    let question = parse_query(request)
        .ok()
        .map(|q| &request[HEADER_LEN..q.question_end]);
    let mut out = Vec::with_capacity(HEADER_LEN + question.map_or(0, <[u8]>::len));
    out.extend_from_slice(&request[0..2]); // same ID
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    if let Some(question) = question {
        out.extend_from_slice(question);
    }
    Some(out)
}

/// Build the zero-IP block response: a NOERROR answer pointing A queries at
/// `0.0.0.0` and AAAA queries at `::` (for clients that mishandle NXDOMAIN;
/// design doc §3 policy option). Other qtypes get NXDOMAIN — there is no
/// sensible null answer for them.
///
/// This is ONLY ever a locally synthesized block/canary answer, so the AA
/// bit is set unconditionally: AA=1 + ancount=1 + rdata 0.0.0.0 is the
/// self-identifying signature no stock upstream produces, which is what the
/// health check's canary step asserts on.
pub fn build_zero_ip_response(request: &[u8], ttl: u32) -> Option<Vec<u8>> {
    let query = parse_query(request).ok()?;
    let rdata: &[u8] = match query.qtype {
        TYPE_A => &[0, 0, 0, 0],
        TYPE_AAAA => &[0; 16],
        _ => return build_error_response(request, RCODE_NXDOMAIN, true),
    };
    let flags_in = u16::from_be_bytes([request[2], request[3]]);
    let flags = FLAG_QR
        | (flags_in & FLAG_OPCODE_MASK)
        | (flags_in & FLAG_RD)
        | (flags_in & FLAG_CD)
        | FLAG_RA
        | FLAG_AA;
    let question = &request[HEADER_LEN..query.question_end];
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + 16 + rdata.len());
    out.extend_from_slice(&request[0..2]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // ns/ar
    out.extend_from_slice(question);
    // Answer name as a pointer back to the question name at offset 12 —
    // legal and compact in responses we build ourselves.
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical wire bytes of a real-world `example.com A IN` query
    /// (ID 0x1234, RD set), constructed by hand.
    fn example_com_query() -> Vec<u8> {
        let mut v = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', //
            0x03, b'c', b'o', b'm', //
            0x00, // root
            0x00, 0x01, // qtype A
            0x00, 0x01, // qclass IN
        ];
        v.shrink_to_fit();
        v
    }

    #[test]
    fn parses_real_world_example_com_query() {
        let bytes = example_com_query();
        let q = parse_query(&bytes).expect("canonical query must parse");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.opcode, 0);
        assert!(q.recursion_desired);
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        assert_eq!(q.question_end, bytes.len());
    }

    #[test]
    fn build_then_parse_roundtrips() {
        let built = build_query(0xABCD, "example.com", TYPE_A, CLASS_IN).expect("build");
        let q = parse_query(&built).expect("parse");
        assert_eq!(q.id, 0xABCD);
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        assert!(q.recursion_desired);
        // And the builder emits exactly the canonical layout.
        let mut canonical = example_com_query();
        canonical[0] = 0xAB;
        canonical[1] = 0xCD;
        assert_eq!(built, canonical);
    }

    #[test]
    fn rejects_qdcount_zero_and_two() {
        let mut bytes = example_com_query();
        bytes[5] = 0;
        assert_eq!(parse_query(&bytes), Err(WireError::BadQuestionCount(0)));
        bytes[5] = 2;
        assert_eq!(parse_query(&bytes), Err(WireError::BadQuestionCount(2)));
    }

    #[test]
    fn truncated_at_every_length_errors_without_panic() {
        let bytes = example_com_query();
        for len in 0..bytes.len() {
            assert!(
                parse_query(&bytes[..len]).is_err(),
                "prefix of {len} bytes must not parse as a full query"
            );
            // Error-response builder must also be total on every prefix.
            let _ = build_error_response(&bytes[..len], RCODE_FORMERR, false);
            let _ = response_info(&bytes[..len]);
        }
    }

    #[test]
    fn label_length_overrun_is_rejected() {
        let mut bytes = example_com_query();
        // First label claims 20 bytes; the packet doesn't hold them.
        bytes[HEADER_LEN] = 20;
        assert_eq!(parse_query(&bytes), Err(WireError::Truncated));
    }

    #[test]
    fn compression_pointer_to_itself_is_rejected() {
        // Question name = pointer to offset 12, i.e. to itself. Following it
        // would loop forever; we reject pointers in questions outright.
        let mut bytes = example_com_query();
        bytes.truncate(HEADER_LEN);
        bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_query(&bytes), Err(WireError::CompressionInQuestion));
    }

    #[test]
    fn overlong_name_is_rejected() {
        // Four 63-byte labels + root = 257 wire bytes > 255.
        let mut bytes = example_com_query();
        bytes.truncate(HEADER_LEN);
        for _ in 0..4 {
            bytes.push(63);
            bytes.extend_from_slice(&[b'a'; 63]);
        }
        bytes.push(0);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_query(&bytes), Err(WireError::NameTooLong));
    }

    #[test]
    fn error_response_echoes_id_and_question() {
        let bytes = example_com_query();
        let resp = build_error_response(&bytes, RCODE_NXDOMAIN, true).expect("response");
        assert_eq!(&resp[0..2], &[0x12, 0x34], "same ID");
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_QR, 0, "QR set");
        assert_ne!(flags & FLAG_RA, 0, "RA set");
        assert_ne!(flags & FLAG_AA, 0, "AA set on a locally synthesized block answer");
        assert_eq!(flags & 0x000F, u16::from(RCODE_NXDOMAIN));
        assert_eq!(&resp[4..6], &[0x00, 0x01], "qdcount 1");
        assert_eq!(
            &resp[HEADER_LEN..],
            &bytes[HEADER_LEN..],
            "question echoed verbatim"
        );
    }

    #[test]
    fn aa_bit_is_set_only_when_requested() {
        let bytes = example_com_query();
        // Errors (FORMERR/SERVFAIL) are NOT authoritative: AA stays clear.
        for rcode in [RCODE_FORMERR, RCODE_SERVFAIL] {
            let resp = build_error_response(&bytes, rcode, false).expect("response");
            let flags = u16::from_be_bytes([resp[2], resp[3]]);
            assert_eq!(flags & FLAG_AA, 0, "no AA on error responses");
            assert_eq!(flags & 0x000F, u16::from(rcode));
        }
        // Block answers (NXDOMAIN or zero-IP) always carry AA — the
        // self-identifying mark the health check asserts on.
        let resp = build_error_response(&bytes, RCODE_NXDOMAIN, true).expect("response");
        assert_ne!(u16::from_be_bytes([resp[2], resp[3]]) & FLAG_AA, 0);
        let query = build_query(0xBEEF, "blocked.example", TYPE_A, CLASS_IN).expect("build");
        let resp = build_zero_ip_response(&query, 60).expect("response");
        assert_ne!(
            u16::from_be_bytes([resp[2], resp[3]]) & FLAG_AA,
            0,
            "zero-IP block answer is authoritative"
        );
        // And the non-A/AAAA fallback inside the zero-IP builder keeps AA.
        let query = build_query(0xBEEF, "blocked.example", 16, CLASS_IN).expect("build");
        let resp = build_zero_ip_response(&query, 60).expect("response");
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_AA, 0, "AA on the NXDOMAIN fallback too");
        assert_eq!(flags & 0x000F, u16::from(RCODE_NXDOMAIN));
    }

    #[test]
    fn error_response_for_header_only_garbage_has_no_question() {
        let mut bytes = example_com_query();
        bytes.truncate(HEADER_LEN);
        let resp = build_error_response(&bytes, RCODE_FORMERR, false).expect("response");
        assert_eq!(&resp[4..6], &[0x00, 0x00], "no question echoed");
        // Shorter than a header: nothing to answer with.
        assert_eq!(build_error_response(&bytes[..5], RCODE_FORMERR, false), None);
    }

    #[test]
    fn zero_ip_response_shape() {
        let query = build_query(0xBEEF, "blocked.example", TYPE_A, CLASS_IN).expect("build");
        let resp = build_zero_ip_response(&query, 60).expect("response");
        let info = response_info(&resp).expect("walkable response");
        assert_eq!(info.rcode, RCODE_NOERROR);
        assert_eq!(info.min_ttl, Some(60));
        assert_eq!(&resp[resp.len() - 4..], &[0, 0, 0, 0], "0.0.0.0 rdata");

        let query = build_query(0xBEEF, "blocked.example", TYPE_AAAA, CLASS_IN).expect("build");
        let resp = build_zero_ip_response(&query, 60).expect("response");
        assert_eq!(&resp[resp.len() - 16..], &[0u8; 16], ":: rdata");
    }

    #[test]
    fn response_info_reads_ttl_through_compression_pointers() {
        // Hand-built response: question + answer whose name is a pointer.
        let mut resp = build_query(0x1, "example.com", TYPE_A, CLASS_IN).expect("build");
        resp[2] = 0x81;
        resp[3] = 0x80; // QR|RD|RA
        resp[7] = 1; // ancount
        resp.extend_from_slice(&[0xC0, 0x0C]); // name → question
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);
        let info = response_info(&resp).expect("info");
        assert_eq!(info.rcode, RCODE_NOERROR);
        assert_eq!(info.min_ttl, Some(300));
        assert!(!is_truncated_response(&resp));
    }

    #[test]
    fn dot_inside_label_is_escaped_and_never_collides() {
        // Single wire label carrying the bytes "microsoft.com" (13 bytes) —
        // legal on the wire. Naive joining would make it indistinguishable
        // from the two-label name; RFC 4343 escaping keeps them distinct.
        let mut hostile = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
            0x0D, // label length 13
        ];
        hostile.extend_from_slice(b"microsoft.com");
        hostile.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        let q = parse_query(&hostile).expect("hostile encoding still parses");
        assert_eq!(q.qname, "microsoft\\.com");
        assert_ne!(q.qname, "microsoft.com", "no collision with the two-label name");
        assert_eq!(q.qname_wire, &hostile[HEADER_LEN..q.question_end - 4]);

        // The genuine two-label name decodes plainly — and differs.
        let genuine = build_query(0x2, "microsoft.com", TYPE_A, CLASS_IN).expect("build");
        let q2 = parse_query(&genuine).expect("parse");
        assert_eq!(q2.qname, "microsoft.com");
        assert_ne!(q.qname_wire, q2.qname_wire, "wire keys are injective");
    }

    #[test]
    fn backslash_and_nonprintable_octets_are_escaped() {
        // Label bytes: 'a', '\', 'b', 0x01, 0x7F — must not confuse the
        // escape scheme or produce lossy UTF-8 replacements.
        let mut pkt = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05];
        pkt.extend_from_slice(&[b'a', b'\\', b'b', 0x01, 0x7F]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        let q = parse_query(&pkt).expect("parse");
        assert_eq!(q.qname, "a\\\\b\\001\\127");
    }

    #[test]
    fn built_queries_roundtrip_through_escaped_decoder() {
        for name in ["example.com", "a.b.c.d.example", "xn--nxasmq6b.example"] {
            let built = build_query(0x1, name, TYPE_A, CLASS_IN).expect("build");
            let q = parse_query(&built).expect("parse");
            assert_eq!(q.qname, name, "plain names roundtrip unchanged");
        }
    }

    #[test]
    fn validate_response_accepts_only_the_matching_exchange() {
        let query = build_query(0xAAAA, "example.com", TYPE_A, CLASS_IN).expect("build");
        let parsed = parse_query(&query).expect("parse");
        let question = &query[HEADER_LEN..parsed.question_end];

        // Well-formed response: QR set, matching ID, echoed question.
        let mut resp = query.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[7] = 1; // ancount
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);
        let info = validate_response(&resp, 0xAAAA, question).expect("valid response accepted");
        assert_eq!(info.rcode, RCODE_NOERROR);
        assert_eq!(info.min_ttl, Some(300));

        // Wrong txid → rejected.
        assert_eq!(validate_response(&resp, 0xBBBB, question), None);
        // QR unset → rejected.
        let mut no_qr = resp.clone();
        no_qr[2] = 0x01;
        assert_eq!(validate_response(&no_qr, 0xAAAA, question), None);
        // Question not echoed byte-for-byte → rejected.
        let mut mangled = resp.clone();
        mangled[HEADER_LEN + 1] = b'X';
        assert_eq!(validate_response(&mangled, 0xAAAA, question), None);
        // Question of a different name entirely → rejected.
        let other = build_query(0xAAAA, "other.example", TYPE_A, CLASS_IN).expect("build");
        let other_parsed = parse_query(&other).expect("parse");
        assert_eq!(
            validate_response(&resp, 0xAAAA, &other[HEADER_LEN..other_parsed.question_end]),
            None
        );
        // Truncated → rejected, never a panic.
        for len in 0..resp.len() {
            let _ = validate_response(&resp[..len], 0xAAAA, question);
        }
    }

    #[test]
    fn upstream_query_is_clean_question_only() {
        // Client query with a suspicious flag byte and an OPT additional
        // record: with `edns = None` the upstream query must carry ONLY the
        // question — fresh id slot, RD=1 flags, zeroed AN/NS/AR, nothing
        // trailing (the client in this case sent no OPT we honour).
        let mut client = build_query(0xBEEF, "example.com", TYPE_A, CLASS_IN).expect("build");
        client[2] |= 0x7F; // every non-QR high flag bit (opcode/AA/TC/RD)
        client[3] = 0x5A; // low flag byte garbage
        client[11] = 1; // arcount = 1
        client.extend_from_slice(&[0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0]); // OPT
        let parsed = parse_query(&client).expect("question parses");
        let question = &client[HEADER_LEN..parsed.question_end];
        let clean = build_upstream_query(0x1234, question, false, None);
        assert_eq!(&clean[0..2], &[0x12, 0x34]);
        assert_eq!(&clean[2..4], &FLAG_RD.to_be_bytes(), "RD=1, nothing else");
        assert_eq!(&clean[4..6], &[0, 1], "qdcount 1");
        assert_eq!(&clean[6..12], &[0; 6], "AN/NS/AR zeroed");
        assert_eq!(clean.len(), HEADER_LEN + question.len(), "no trailing bytes");
        assert_eq!(&clean[HEADER_LEN..], question);
    }

    #[test]
    fn upstream_query_relays_cd_and_a_minimal_self_built_opt() {
        // L01: CD is relayed verbatim; the client's OPT becomes ONE OPT we
        // constructed — clamped size + DO bit, no options, no ECS.
        let query = build_query(0xBEEF, "example.com", TYPE_A, CLASS_IN).expect("build");
        let parsed = parse_query(&query).expect("parse");
        let question = &query[HEADER_LEN..parsed.question_end];

        let clean = build_upstream_query(0x1234, question, true, Some((1232, true)));
        let flags = u16::from_be_bytes([clean[2], clean[3]]);
        assert_ne!(flags & FLAG_RD, 0, "RD always set");
        assert_ne!(flags & FLAG_CD, 0, "client CD relayed");
        assert_eq!(&clean[10..12], &[0, 1], "arcount 1");
        let opt = &clean[HEADER_LEN + question.len()..];
        assert_eq!(
            opt,
            &[0x00, 0x00, 0x29, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0],
            "one OPT: root name, type 41, size 1232, DO set, empty rdata"
        );

        // Without DO the flags byte of the OPT ttl is zero.
        let clean = build_upstream_query(0x1234, question, false, Some((1232, false)));
        let opt = &clean[HEADER_LEN + question.len()..];
        assert_eq!(opt[7], 0, "DO clear");
        assert_eq!(u16::from_be_bytes([clean[2], clean[3]]) & FLAG_CD, 0, "CD clear");

        // Sizes are clamped both ways: 65535 → 4096 (our buffer), 200 → 512
        // (RFC 6891 §6.2.3 floor).
        let clean = build_upstream_query(0x1234, question, false, Some((u16::MAX, false)));
        let n = clean.len();
        assert_eq!(&clean[n - 8..n - 6], &4096u16.to_be_bytes(), "size capped at 4096");
        let clean = build_upstream_query(0x1234, question, false, Some((200, false)));
        let n = clean.len();
        assert_eq!(&clean[n - 8..n - 6], &512u16.to_be_bytes(), "size floored at 512");
    }

    #[test]
    fn parse_query_extracts_edns_size_do_and_cd() {
        let mut query = build_query(0xBEEF, "example.com", TYPE_A, CLASS_IN).expect("build");
        query[3] |= 0x10; // CD
        query[11] = 1; // arcount = 1
        query.extend_from_slice(&[
            0x00, // name: root
            0x00, 0x29, // type OPT (41)
            0x04, 0xD0, // class: 1232 UDP payload
            0, 0, 0x80, 0, // ttl: DO bit set
            0x00, 0x00, // rdlength 0
        ]);
        let q = parse_query(&query).expect("parse");
        assert!(q.checking_disabled);
        assert!(q.dnssec_ok);
        assert_eq!(q.edns_udp_size, Some(1232));

        // No OPT at all: defaults, CD still read from the header.
        let mut plain = build_query(1, "example.com", TYPE_A, CLASS_IN).expect("build");
        plain[3] |= 0x10;
        let q = parse_query(&plain).expect("parse");
        assert!(q.checking_disabled);
        assert!(!q.dnssec_ok);
        assert_eq!(q.edns_udp_size, None);
    }

    #[test]
    fn edns_opt_is_found_past_other_records_and_garbage_yields_none() {
        // An (unusual but wire-legal) query carrying a junk additional
        // record BEFORE the OPT: the walker must skip it and find the OPT.
        let mut query = build_query(1, "example.com", TYPE_A, CLASS_IN).expect("build");
        query[11] = 2; // arcount = 2
        query.extend_from_slice(&[
            0x00, // name: root
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0, 0, 0, 0, // ttl
            0x00, 0x04, // rdlength 4
            127, 0, 0, 1, // rdata
        ]);
        query.extend_from_slice(&[
            0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0x80, 0, 0x00, 0x00,
        ]);
        let q = parse_query(&query).expect("parse");
        assert_eq!(q.edns_udp_size, Some(4096));
        assert!(q.dnssec_ok);

        // Truncated/garbage additional records: parse still succeeds, EDNS
        // simply absent (trailing garbage must not invalidate the question).
        let mut query = build_query(1, "example.com", TYPE_A, CLASS_IN).expect("build");
        query[11] = 1;
        query.extend_from_slice(&[0x00, 0x00, 0x29, 0x10]); // claims OPT, truncated
        let q = parse_query(&query).expect("parse despite trailing garbage");
        assert_eq!(q.edns_udp_size, None);
        assert!(!q.dnssec_ok);

        // A record whose rdlength overruns the packet: same story.
        let mut query = build_query(1, "example.com", TYPE_A, CLASS_IN).expect("build");
        query[11] = 1;
        query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0xFF, 0xFF]);
        let q = parse_query(&query).expect("parse despite overrun");
        assert_eq!(q.edns_udp_size, None);
    }

    #[test]
    fn truncated_response_has_tc_question_and_zero_counts() {
        let query = build_query(0x4242, "big.example", TYPE_A, CLASS_IN).expect("build");
        let resp = build_truncated_response(&query, RCODE_NOERROR).expect("truncated response");
        assert!(resp.len() <= MAX_UDP_PAYLOAD);
        assert_eq!(&resp[0..2], &[0x42, 0x42], "same ID");
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_TC, 0, "TC set");
        assert_ne!(flags & FLAG_QR, 0, "QR set");
        assert_eq!(flags & 0x000F, 0, "NOERROR");
        assert_eq!(&resp[6..12], &[0; 6], "AN/NS/AR zeroed");
        assert_eq!(&resp[HEADER_LEN..], &query[HEADER_LEN..], "question intact");
        assert!(is_truncated_response(&resp));
        // Total on short input.
        assert_eq!(build_truncated_response(&query[..5], RCODE_NOERROR), None);
    }

    #[test]
    fn truncated_response_preserves_the_real_rcode() {
        // L02: a truncated NXDOMAIN must keep rcode=3 — a hardcoded NOERROR
        // reads as NODATA ("exists, no records") to a client that does not
        // retry, for the whole negative-cache window. The OLD implementation
        // hardcoded NOERROR and the OLD test (asserting only `flags & 0xF
        // == 0` on a NOERROR input) passed on it — this test pins rcode
        // passthrough for every rcode, so a hardcoded-NOERROR builder fails.
        let query = build_query(0x4242, "gone.example", TYPE_A, CLASS_IN).expect("build");
        for rcode in [RCODE_NOERROR, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, 5u8] {
            let resp = build_truncated_response(&query, rcode).expect("truncated response");
            let flags = u16::from_be_bytes([resp[2], resp[3]]);
            assert_eq!(flags & 0x000F, u16::from(rcode), "rcode {rcode} must pass through");
            assert_ne!(flags & FLAG_TC, 0, "TC set regardless of rcode");
        }
    }

    #[test]
    fn rewrite_response_flags_echoes_rd_cd_and_clears_ad() {
        // Relayed upstream response: QR|RD|RA|AD set (upstream validated
        // and says so). The client asked with RD=0, CD=1.
        let query = build_query(0x1, "example.com", TYPE_A, CLASS_IN).expect("build");
        let mut resp = query.clone();
        resp[2] = 0x85; // QR|AA|RD
        resp[3] = 0xA0; // RA|AD
        rewrite_response_flags_for_client(&mut resp, false, true);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & FLAG_AD, 0, "AD always cleared (we validate nothing)");
        assert_eq!(flags & FLAG_RD, 0, "client RD=0 echoed");
        assert_ne!(flags & FLAG_CD, 0, "client CD=1 echoed");
        assert_ne!(flags & FLAG_QR, 0, "QR untouched");
        assert_ne!(flags & FLAG_AA, 0, "upstream AA untouched");
        assert_ne!(flags & FLAG_RA, 0, "RA untouched");
        assert_eq!(flags & 0x000F, 0, "rcode untouched");

        // RD=1, CD=0 client: RD echoed set, CD stays clear, AD cleared.
        let mut resp = query.clone();
        resp[2] = 0x81;
        resp[3] = 0xB0; // RA|AD|CD
        rewrite_response_flags_for_client(&mut resp, true, false);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_RD, 0);
        assert_eq!(flags & FLAG_CD, 0, "client CD=0 echoed (upstream CD stripped)");
        assert_eq!(flags & FLAG_AD, 0);

        // Total on short input: untouched, no panic.
        let mut short = vec![0u8; 4];
        rewrite_response_flags_for_client(&mut short, true, true);
        assert_eq!(short, vec![0u8; 4]);
    }

    #[test]
    fn validate_response_echo_is_case_insensitive_on_qname_only() {
        let query = build_query(0xAAAA, "ExAmPle.CoM", TYPE_A, CLASS_IN).expect("build");
        let parsed = parse_query(&query).expect("parse");
        let question = &query[HEADER_LEN..parsed.question_end];
        // Upstream lowercases the echoed question name (home CPE style).
        let mut resp = query.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        for byte in &mut resp[HEADER_LEN..parsed.question_end - 4] {
            *byte = byte.to_ascii_lowercase();
        }
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);
        let info =
            validate_response(&resp, 0xAAAA, question).expect("case-only diff must be accepted");
        assert_eq!(info.rcode, RCODE_NOERROR);

        // A REAL name change is still rejected.
        let mut mangled = resp.clone();
        mangled[HEADER_LEN + 1] = b'z'; // 'e' → 'z': differs case-insensitively
        assert_eq!(validate_response(&mangled, 0xAAAA, question), None);
        // qtype/qclass remain exact.
        let mut bad_type = resp.clone();
        let qtype_off = parsed.question_end - 4;
        bad_type[qtype_off + 1] ^= 0x01;
        assert_eq!(validate_response(&bad_type, 0xAAAA, question), None);
    }

    /// Deterministic xorshift64 so the sweeps are reproducible.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn byte(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    /// A valid 12-byte query header (QR=0, qdcount=1) — the shared prefix
    /// that gets sweeps PAST header validation and into the name parser.
    fn valid_query_header(rng: &mut XorShift) -> Vec<u8> {
        vec![
            rng.byte(), rng.byte(), // random txid
            0x01, 0x00, // flags: RD, QR clear
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    /// Structured sweep: valid header + random question-section bytes.
    /// Random bytes from offset 12 reach `parse_question_name` immediately,
    /// unlike a whole-packet random sweep which almost never survives header
    /// validation. The coverage marker makes a vacuous sweep a loud failure.
    #[test]
    fn structured_sweep_random_question_bytes_never_panic_and_reach_name_parser() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let mut reached_name_parsing = 0u32;
        for _ in 0..20_000 {
            let mut buf = valid_query_header(&mut rng);
            let extra = (rng.next() % 300) as usize;
            for _ in 0..extra {
                buf.push(rng.byte());
            }
            match parse_query(&buf) {
                Ok(_) => reached_name_parsing += 1,
                // These can only come from inside/after name parsing —
                // proof the sweep reached it.
                Err(
                    WireError::CompressionInQuestion
                    | WireError::InvalidLabelType
                    | WireError::NameTooLong,
                ) => reached_name_parsing += 1,
                Err(WireError::Truncated) => {}
                Err(e) => panic!("impossible error past header validation: {e}"),
            }
            let _ = build_error_response(&buf, RCODE_SERVFAIL, false);
            let _ = build_zero_ip_response(&buf, 60);
            let _ = response_info(&buf);
            let _ = is_truncated_response(&buf);
        }
        // Coverage marker: with random label-length bytes, essentially every
        // iteration enters name parsing; demand a solid floor so the sweep
        // can never silently stop reaching it.
        assert!(
            reached_name_parsing >= 1_000,
            "sweep reached name parsing only {reached_name_parsing} times — vacuous"
        );
    }

    /// Structured sweep: fully valid query + random trailing garbage.
    /// Exercises the "question parsed, junk after it" shape (forwarding and
    /// response-walking paths must stay total on it). A random ARCOUNT is
    /// set so the EDNS0 OPT walker in `parse_query` actually walks the
    /// garbage — a sweep that never enters it is evidence of nothing.
    #[test]
    fn structured_sweep_valid_query_with_trailing_garbage_never_panics() {
        let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
        let names = ["example.com", "a.b.example", "x.y.z.w.example"];
        for (i, name) in names.iter().cycle().take(20_000).enumerate() {
            let mut buf = build_query(i as u16, name, TYPE_A, CLASS_IN).expect("build");
            let extra = (rng.next() % 300) as usize;
            for _ in 0..extra {
                buf.push(rng.byte());
            }
            buf[11] = (rng.next() % 4) as u8; // arcount 0..=3 over the garbage
            let q = parse_query(&buf).expect("trailing garbage must not break the question");
            assert_eq!(q.qname, *name);
            let _ = build_error_response(&buf, RCODE_SERVFAIL, false);
            let _ = build_zero_ip_response(&buf, 60);
            let _ = response_info(&buf);
            let _ = validate_response(&buf, i as u16, &buf[HEADER_LEN..q.question_end]);
            let _ = is_truncated_response(&buf);
        }
    }
}

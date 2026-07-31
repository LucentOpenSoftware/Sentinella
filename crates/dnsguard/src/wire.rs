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

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

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
    Ok(Query {
        id,
        opcode,
        recursion_desired,
        qname,
        qname_wire: bytes[HEADER_LEN..name_end].to_vec(),
        qtype,
        qclass,
        question_end: name_end + 4,
    })
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
/// - exactly one question, byte-equal to the question we forwarded (name
///   wire bytes + qtype + qclass).
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
    // The echoed question must be byte-identical to what we sent. A
    // misbehaving/forging source that rewrites case, re-encodes labels, or
    // answers a different question is dropped.
    let echoed = bytes.get(HEADER_LEN..HEADER_LEN.checked_add(question.len())?)?;
    if echoed != question {
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

/// Build an error response (FORMERR / SERVFAIL / NXDOMAIN) echoing the
/// request's ID and — when the question parsed — the question section, with
/// QR and RA set and RD/opcode preserved.
///
/// Returns `None` when the request is shorter than a header; there is no ID
/// to answer with, so the only safe behavior is to drop it.
pub fn build_error_response(request: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN {
        return None;
    }
    let flags_in = u16::from_be_bytes([request[2], request[3]]);
    let flags = FLAG_QR
        | (flags_in & FLAG_OPCODE_MASK)
        | (flags_in & FLAG_RD)
        | FLAG_RA
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
pub fn build_zero_ip_response(request: &[u8], ttl: u32) -> Option<Vec<u8>> {
    let query = parse_query(request).ok()?;
    let rdata: &[u8] = match query.qtype {
        TYPE_A => &[0, 0, 0, 0],
        TYPE_AAAA => &[0; 16],
        _ => return build_error_response(request, RCODE_NXDOMAIN),
    };
    let flags_in = u16::from_be_bytes([request[2], request[3]]);
    let flags = FLAG_QR | (flags_in & FLAG_OPCODE_MASK) | (flags_in & FLAG_RD) | FLAG_RA;
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
            let _ = build_error_response(&bytes[..len], RCODE_FORMERR);
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
        let resp = build_error_response(&bytes, RCODE_NXDOMAIN).expect("response");
        assert_eq!(&resp[0..2], &[0x12, 0x34], "same ID");
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & FLAG_QR, 0, "QR set");
        assert_ne!(flags & FLAG_RA, 0, "RA set");
        assert_eq!(flags & 0x000F, u16::from(RCODE_NXDOMAIN));
        assert_eq!(&resp[4..6], &[0x00, 0x01], "qdcount 1");
        assert_eq!(
            &resp[HEADER_LEN..],
            &bytes[HEADER_LEN..],
            "question echoed verbatim"
        );
    }

    #[test]
    fn error_response_for_header_only_garbage_has_no_question() {
        let mut bytes = example_com_query();
        bytes.truncate(HEADER_LEN);
        let resp = build_error_response(&bytes, RCODE_FORMERR).expect("response");
        assert_eq!(&resp[4..6], &[0x00, 0x00], "no question echoed");
        // Shorter than a header: nothing to answer with.
        assert_eq!(build_error_response(&bytes[..5], RCODE_FORMERR), None);
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
            let _ = build_error_response(&buf, RCODE_SERVFAIL);
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
    /// response-walking paths must stay total on it).
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
            let q = parse_query(&buf).expect("trailing garbage must not break the question");
            assert_eq!(q.qname, *name);
            let _ = build_error_response(&buf, RCODE_SERVFAIL);
            let _ = build_zero_ip_response(&buf, 60);
            let _ = response_info(&buf);
            let _ = validate_response(&buf, i as u16, &buf[HEADER_LEN..q.question_end]);
            let _ = is_truncated_response(&buf);
        }
    }
}

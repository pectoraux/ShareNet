//! DNS packet parsing and response generation.
//!
//! This module provides:
//!
//! - [`DnsQuestion`] — parsed DNS question (transaction ID, QNAME, QTYPE, QCLASS).
//! - [`DnsQuery`] — a full parsed DNS query (header + questions).
//! - [`DnsResponse`] — a builder for synthetic DNS responses.
//! - [`DnsResolver`] — a configurable resolver that maps domain names to IP
//!   addresses and generates synthetic responses.
//! - [`is_dns_query`] — quick detection of DNS packets (UDP, port 53).
//!
//! ## DNS Ownership Invariant (FROZEN)
//!
//! **This invariant extends the Flow Ownership Invariant (N2.3.2).**
//!
//! The [`FlowTable`] is observational state only. DNS resolution behavior
//! belongs to the DNS subsystem ([`DnsResolver`]), NOT to the FlowTable.
//!
//! ```text
//! TCP flows:
//!     smoltcp owns transport behavior
//!
//! UDP DNS flows:
//!     DNS subsystem (DnsResolver) owns resolution behavior
//!
//! FlowTable:
//!     observes only — never resolves, never generates DNS responses
//! ```
//!
//! The FlowTable MUST NOT:
//! - Parse DNS questions.
//! - Generate DNS responses.
//! - Map domain names to IPs.
//! - Intercept DNS traffic.
//!
//! ## Scope (N2.3.4)
//!
//! - DNS query parsing (transaction ID, flags, question section, QNAME, QTYPE).
//! - DNS response generation (A, AAAA, NXDOMAIN).
//! - IPv4 and IPv6 DNS query support.
//! - Configurable domain → IP mappings (synthetic responses, no real
//!   resolution).
//! - End-to-end interception: raw UDP/53 packet → parse → resolve →
//!   generate response → raw UDP/53 response packet.
//!
//! ## Out of scope (future milestones)
//!
//! - Gateway DNS forwarding (forwarding queries to a real upstream resolver
//!   via the ShareNet mesh).
//! - Encrypted DNS (DoH, DoT).
//! - DNS caching.
//! - DNSSEC.
//! - Recursive resolution.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use snp_tun::IpPacket;

use crate::transport::{parse_transport, TransportHeader, UDP};

/// DNS port (53).
pub const DNS_PORT: u16 = 53;

/// DNS QTYPE values (RFC 1035 §3.2.3 + RFC 3596).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQtype {
    /// A record (IPv4 address, type 1).
    A = 1,
    /// AAAA record (IPv6 address, type 28).
    Aaaa = 28,
    /// CNAME record (canonical name, type 5).
    Cname = 5,
    /// MX record (mail exchange, type 15).
    Mx = 15,
    /// TXT record (type 16).
    Txt = 16,
    /// NS record (type 2).
    Ns = 2,
    /// SOA record (type 6).
    Soa = 6,
    /// PTR record (type 12).
    Ptr = 12,
    /// SRV record (type 33).
    Srv = 33,
    /// Any record (type 255, QTYPE=ANY).
    Any = 255,
}

impl DnsQtype {
    /// Parse a QTYPE from a raw u16 value. Returns `None` for unknown types.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            28 => Some(Self::Aaaa),
            5 => Some(Self::Cname),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            2 => Some(Self::Ns),
            6 => Some(Self::Soa),
            12 => Some(Self::Ptr),
            33 => Some(Self::Srv),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

/// DNS QCLASS values (RFC 1035 §3.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQclass {
    /// IN class (Internet, class 1).
    IN = 1,
    /// CH class (Chaos, class 3).
    CH = 3,
    /// HS class (Hesiod, class 4).
    HS = 4,
    /// ANY class (255).
    Any = 255,
}

impl DnsQclass {
    /// Parse a QCLASS from a raw u16 value. Returns `None` for unknown classes.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::IN),
            3 => Some(Self::CH),
            4 => Some(Self::HS),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

/// A parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// The queried domain name (e.g. "example.com").
    pub qname: String,
    /// The query type (A, AAAA, etc.).
    pub qtype: DnsQtype,
    /// The query class (IN, CH, etc.).
    pub qclass: DnsQclass,
}

/// A parsed DNS query (header + question section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Transaction ID (16-bit, used to match responses to queries).
    pub transaction_id: u16,
    /// Query flags (RD, AD, CD, etc.). Bit 15 is QR (0=query, 1=response).
    pub flags: u16,
    /// The question section (typically one question for standard queries).
    pub questions: Vec<DnsQuestion>,
}

impl DnsQuery {
    /// Returns true if this is a standard query (QR bit = 0).
    #[must_use]
    pub fn is_query(&self) -> bool {
        (self.flags & 0x8000) == 0
    }

    /// Returns true if recursion is desired (RD bit = 1).
    #[must_use]
    pub fn recursion_desired(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    /// Returns the first question, if any.
    #[must_use]
    pub fn first_question(&self) -> Option<&DnsQuestion> {
        self.questions.first()
    }
}

/// Errors from DNS parsing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    /// The packet is too short to contain a DNS header (12 bytes minimum).
    #[error("DNS packet too short: {actual} bytes (minimum 12)")]
    TooShort {
        /// Actual bytes available.
        actual: usize,
    },
    /// The QNAME is malformed (invalid label length, truncated, or contains
    /// an invalid pointer).
    #[error("malformed QNAME: {0}")]
    MalformedQname(String),
    /// The question section is truncated (declared count > available data).
    #[error("truncated question section: declared {declared} questions, only {actual} available")]
    TruncatedQuestions {
        /// Declared question count.
        declared: u16,
        /// Actual questions found.
        actual: usize,
    },
    /// Unknown QTYPE or QCLASS value.
    #[error("unknown DNS type/class: qtype={qtype}, qclass={qclass}")]
    UnknownTypeClass {
        /// Raw QTYPE value.
        qtype: u16,
        /// Raw QCLASS value.
        qclass: u16,
    },
}

/// Parse a DNS query from raw UDP payload bytes.
///
/// # Errors
/// Returns [`DnsError`] if the bytes are not a valid DNS query.
pub fn parse_dns_query(data: &[u8]) -> Result<DnsQuery, DnsError> {
    if data.len() < 12 {
        return Err(DnsError::TooShort { actual: data.len() });
    }

    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    // ancount (6-7), nscount (8-9), arcount (10-11) — ignored for queries.
    let mut offset = 12;

    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (qname, new_offset) = parse_qname(data, offset)?;
        offset = new_offset;
        if offset + 4 > data.len() {
            return Err(DnsError::TruncatedQuestions {
                declared: qdcount,
                actual: questions.len(),
            });
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
        let qtype_enum =
            DnsQtype::from_u16(qtype).ok_or(DnsError::UnknownTypeClass { qtype, qclass })?;
        let qclass_enum =
            DnsQclass::from_u16(qclass).ok_or(DnsError::UnknownTypeClass { qtype, qclass })?;
        questions.push(DnsQuestion {
            qname,
            qtype: qtype_enum,
            qclass: qclass_enum,
        });
    }

    Ok(DnsQuery {
        transaction_id,
        flags,
        questions,
    })
}

/// Parse a QNAME from the DNS wire format (label-length-prefixed labels,
/// terminated by a zero byte).
///
/// Returns the parsed domain name (e.g. "example.com") and the offset past
/// the QNAME (pointing at the QTYPE field).
fn parse_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        if offset >= data.len() {
            return Err(DnsError::MalformedQname("QNAME truncated".into()));
        }
        let label_len = data[offset];
        if label_len == 0 {
            offset += 1; // Skip the terminating zero byte.
            break;
        }
        // Check for compression pointer (top two bits = 11).
        if (label_len & 0xc0) == 0xc0 {
            return Err(DnsError::MalformedQname(
                "compression pointers not supported in QNAME".into(),
            ));
        }
        if (label_len & 0xc0) != 0 {
            return Err(DnsError::MalformedQname(format!(
                "invalid label length byte: 0x{label_len:02x}"
            )));
        }
        let label_len = label_len as usize;
        offset += 1;
        if offset + label_len > data.len() {
            return Err(DnsError::MalformedQname("label extends past packet".into()));
        }
        let label = std::str::from_utf8(&data[offset..offset + label_len])
            .map_err(|_| DnsError::MalformedQname("label is not valid UTF-8".into()))?;
        labels.push(label.to_string());
        offset += label_len;
    }
    let qname = labels.join(".");
    Ok((qname, offset))
}

/// Encode a domain name into DNS wire format (label-length-prefixed labels,
/// terminated by a zero byte). Used by the response builder and tests.
#[allow(dead_code)]
fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name.is_empty() {
        out.push(0);
        return out;
    }
    for label in name.split('.') {
        let label_bytes = label.as_bytes();
        // Label length is a byte (max 63 — we don't validate here, assume
        // the caller passes valid domain names).
        out.push(label_bytes.len() as u8);
        out.extend_from_slice(label_bytes);
    }
    out.push(0); // Terminating zero byte.
    out
}

/// A synthetic DNS response builder. Generates a DNS response packet for a
/// given query, with the specified answer records.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// The transaction ID (copied from the query).
    pub transaction_id: u16,
    /// The flags (QR=1, opcode copied from query, RD copied, RA=0, RCODE).
    pub flags: u16,
    /// The question section (copied from the query).
    pub question_bytes: Vec<u8>,
    /// The answer section (encoded resource records).
    pub answer_bytes: Vec<u8>,
}

impl DnsResponse {
    /// Build a response for an A record query. Returns the encoded DNS
    /// response packet bytes.
    #[must_use]
    pub fn build_a_response(query: &DnsQuery, question_bytes: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let transaction_id = query.transaction_id;
        // Flags: QR=1 (response), opcode=0 (standard query), RD copied from
        // query, RA=0 (no recursion available), Z=0, RCODE=0 (no error).
        let rd = if query.recursion_desired() { 0x0100 } else { 0 };
        let flags = 0x8000 | rd; // QR=1, RD=copied
        let qdcount: u16 = 1;
        let ancount: u16 = 1;

        let mut answer = Vec::new();
        // Answer resource record:
        //   NAME (pointer to the question's QNAME — 0xC00C = pointer to offset 12)
        //   TYPE (A = 1)
        //   CLASS (IN = 1)
        //   TTL (4 bytes, 300 seconds)
        //   RDLENGTH (2 bytes, 4 for IPv4)
        //   RDATA (4 bytes, the IPv4 address)
        answer.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        answer.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        answer.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300s
        answer.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        answer.extend_from_slice(&ip.octets()); // RDATA = IPv4

        Self::encode_response(
            transaction_id,
            flags,
            qdcount,
            ancount,
            question_bytes,
            &answer,
        )
    }

    /// Build a response for an AAAA record query. Returns the encoded DNS
    /// response packet bytes.
    #[must_use]
    pub fn build_aaaa_response(query: &DnsQuery, question_bytes: &[u8], ip: Ipv6Addr) -> Vec<u8> {
        let transaction_id = query.transaction_id;
        let rd = if query.recursion_desired() { 0x0100 } else { 0 };
        let flags = 0x8000 | rd;
        let qdcount: u16 = 1;
        let ancount: u16 = 1;

        let mut answer = Vec::new();
        answer.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        answer.extend_from_slice(&28u16.to_be_bytes()); // TYPE = AAAA
        answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        answer.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300s
        answer.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH = 16
        answer.extend_from_slice(&ip.octets()); // RDATA = IPv6

        Self::encode_response(
            transaction_id,
            flags,
            qdcount,
            ancount,
            question_bytes,
            &answer,
        )
    }

    /// Build an NXDOMAIN response (domain does not exist). Returns the
    /// encoded DNS response packet bytes.
    #[must_use]
    pub fn build_nxdomain_response(query: &DnsQuery, question_bytes: &[u8]) -> Vec<u8> {
        let transaction_id = query.transaction_id;
        let rd = if query.recursion_desired() { 0x0100 } else { 0 };
        // Flags: QR=1, RD=copied, RCODE=3 (NXDOMAIN).
        let flags = 0x8000 | rd | 0x0003;
        let qdcount: u16 = 1;
        let ancount: u16 = 0;

        Self::encode_response(transaction_id, flags, qdcount, ancount, question_bytes, &[])
    }

    /// Encode the full DNS response packet (header + question + answer).
    fn encode_response(
        transaction_id: u16,
        flags: u16,
        qdcount: u16,
        ancount: u16,
        question_bytes: &[u8],
        answer_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + question_bytes.len() + answer_bytes.len());
        // Header (12 bytes).
        out.extend_from_slice(&transaction_id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&qdcount.to_be_bytes());
        out.extend_from_slice(&ancount.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                                    // Question section.
        out.extend_from_slice(question_bytes);
        // Answer section.
        out.extend_from_slice(answer_bytes);
        out
    }
}

/// A DNS resolver with configurable domain → IP mappings.
///
/// The resolver holds a HashMap of domain name → IP address. When a DNS
/// query arrives, the resolver looks up the domain and generates a synthetic
/// response (A, AAAA, or NXDOMAIN).
///
/// ## No real resolution
///
/// This resolver does NOT perform real DNS resolution (no upstream queries,
/// no network access). It only returns pre-configured mappings. Real
/// resolution (via the ShareNet gateway) is a future milestone.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    /// Domain name → IP address mappings (case-insensitive).
    mappings: HashMap<String, IpAddr>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    /// Create an empty resolver (no mappings — all queries return NXDOMAIN).
    #[must_use]
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Create a resolver with the given domain → IP mappings.
    #[must_use]
    pub fn with_mappings(mappings: HashMap<String, IpAddr>) -> Self {
        // Normalize keys to lowercase for case-insensitive lookup.
        let normalized = mappings
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        Self {
            mappings: normalized,
        }
    }

    /// Add a domain → IP mapping. The domain is normalized to lowercase.
    pub fn add_mapping(&mut self, domain: &str, ip: IpAddr) {
        self.mappings.insert(domain.to_lowercase(), ip);
    }

    /// Look up a domain name. Returns the configured IP address, or `None`
    /// if no mapping exists.
    #[must_use]
    pub fn resolve(&self, domain: &str) -> Option<IpAddr> {
        self.mappings.get(&domain.to_lowercase()).copied()
    }

    /// Process a DNS query and generate a synthetic response.
    ///
    /// - For A queries: if the domain has an IPv4 mapping, returns an A
    ///   response. If it has an IPv6 mapping, returns NXDOMAIN (A query
    ///   cannot return an IPv6 address).
    /// - For AAAA queries: if the domain has an IPv6 mapping, returns an
    ///   AAAA response. If it has an IPv4 mapping, returns NXDOMAIN.
    /// - For unmapped domains: returns NXDOMAIN.
    /// - For unsupported QTYPEs (CNAME, MX, etc.): returns NXDOMAIN.
    ///
    /// Returns the encoded DNS response packet bytes.
    #[must_use]
    pub fn resolve_query(&self, query: &DnsQuery, question_bytes: &[u8]) -> Vec<u8> {
        let question = match query.first_question() {
            Some(q) => q,
            None => {
                return DnsResponse::build_nxdomain_response(query, question_bytes);
            }
        };

        match question.qtype {
            DnsQtype::A => {
                match self.resolve(&question.qname) {
                    Some(IpAddr::V4(ip)) => {
                        DnsResponse::build_a_response(query, question_bytes, ip)
                    }
                    Some(IpAddr::V6(_)) => {
                        // A query but only IPv6 mapping → NXDOMAIN (can't
                        // return IPv6 in an A response).
                        DnsResponse::build_nxdomain_response(query, question_bytes)
                    }
                    None => DnsResponse::build_nxdomain_response(query, question_bytes),
                }
            }
            DnsQtype::Aaaa => match self.resolve(&question.qname) {
                Some(IpAddr::V6(ip)) => DnsResponse::build_aaaa_response(query, question_bytes, ip),
                Some(IpAddr::V4(_)) => {
                    // AAAA query but only IPv4 mapping → NXDOMAIN.
                    DnsResponse::build_nxdomain_response(query, question_bytes)
                }
                None => DnsResponse::build_nxdomain_response(query, question_bytes),
            },
            _ => {
                // Unsupported QTYPE (CNAME, MX, TXT, etc.) → NXDOMAIN.
                DnsResponse::build_nxdomain_response(query, question_bytes)
            }
        }
    }

    /// Returns the number of configured domain mappings.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

/// Check if an [`IpPacket`] is a DNS query (UDP, destination port 53).
///
/// This is a quick check — it does NOT parse the DNS payload. Use
/// [`parse_dns_query`] to parse the payload.
///
/// # Errors
/// Returns [`crate::TransportError`] if the transport header cannot be parsed.
pub fn is_dns_query(packet: &IpPacket) -> Result<bool, crate::TransportError> {
    let transport = parse_transport(packet)?;
    match transport {
        Some(TransportHeader::Udp(udp)) => Ok(udp.dst_port == DNS_PORT),
        _ => Ok(false),
    }
}

/// Extract the DNS query bytes (UDP payload) from an [`IpPacket`].
/// Returns `None` if the packet is not a UDP DNS query to port 53.
fn extract_dns_payload(packet: &IpPacket) -> Option<&[u8]> {
    let transport = parse_transport(packet).ok()??;
    let udp = match transport {
        TransportHeader::Udp(ref udp) if udp.dst_port == DNS_PORT => udp,
        _ => return None,
    };
    let _ = udp; // We only needed to verify the port.
                 // The UDP payload starts after the 8-byte UDP header.
    let transport_payload = transport_payload(packet)?;
    if transport_payload.len() < 8 {
        return None;
    }
    Some(&transport_payload[8..])
}

/// Extract the DNS payload from a RESPONSE packet (src_port == 53).
/// Used in tests to verify the response content.
#[cfg(test)]
fn extract_dns_response_payload(packet: &IpPacket) -> Option<&[u8]> {
    let transport = parse_transport(packet).ok()??;
    let udp = match transport {
        TransportHeader::Udp(ref udp) if udp.src_port == DNS_PORT => udp,
        _ => return None,
    };
    let _ = udp;
    let transport_payload = transport_payload(packet)?;
    if transport_payload.len() < 8 {
        return None;
    }
    Some(&transport_payload[8..])
}

/// Extract the transport-layer payload (bytes after the IP header).
fn transport_payload(packet: &IpPacket) -> Option<&[u8]> {
    match packet {
        IpPacket::IPv4(p) => {
            let bytes = p.as_bytes();
            let ihl = (bytes[0] & 0x0f) as usize;
            let header_len = ihl * 4;
            if bytes.len() < header_len {
                return None;
            }
            Some(&bytes[header_len..])
        }
        IpPacket::IPv6(p) => {
            let bytes = p.as_bytes();
            const IPV6_HEADER_LEN: usize = 40;
            if bytes.len() < IPV6_HEADER_LEN {
                return None;
            }
            Some(&bytes[IPV6_HEADER_LEN..])
        }
    }
}

/// Extract the raw question section bytes (QNAME + QTYPE + QCLASS) from a
/// DNS query packet. This is needed to copy the question into the response.
fn extract_question_bytes(dns_payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    if dns_payload.len() < 12 {
        return Err(DnsError::TooShort {
            actual: dns_payload.len(),
        });
    }
    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        let (_, new_offset) = parse_qname(dns_payload, offset)?;
        offset = new_offset;
        if offset + 4 > dns_payload.len() {
            return Err(DnsError::TruncatedQuestions {
                declared: qdcount as u16,
                actual: 0,
            });
        }
        offset += 4; // QTYPE (2) + QCLASS (2)
    }
    Ok(dns_payload[12..offset].to_vec())
}

/// Intercept a DNS query packet: parse the DNS payload, resolve via the
/// resolver, and generate a synthetic response packet (ready to write back
/// to the TUN).
///
/// Returns `None` if the packet is not a DNS query.
///
/// # Errors
/// Returns [`DnsError`] if the DNS payload cannot be parsed.
pub fn intercept_dns_query(
    packet: &IpPacket,
    resolver: &DnsResolver,
) -> Result<Option<Vec<u8>>, DnsError> {
    let dns_payload = match extract_dns_payload(packet) {
        Some(p) => p,
        None => return Ok(None),
    };

    let query = parse_dns_query(dns_payload)?;
    let question_bytes = extract_question_bytes(dns_payload)?;
    let response_dns = resolver.resolve_query(&query, &question_bytes);

    // Build the response IP packet: swap src/dst IP, swap src/dst port,
    // set the DNS response as the UDP payload.
    let response_packet = build_udp_response_packet(packet, &response_dns);
    Ok(Some(response_packet))
}

/// Build a UDP response IP packet by swapping src/dst and inserting the
/// given payload. The response is a complete IP+UDP packet ready to write
/// to the TUN.
fn build_udp_response_packet(query_packet: &IpPacket, udp_payload: &[u8]) -> Vec<u8> {
    let (src_ip, dst_ip) = (
        query_packet.metadata().destination,
        query_packet.metadata().source,
    );
    // Extract the source/destination ports from the query (to swap them).
    let transport = parse_transport(query_packet).ok().flatten();
    let (src_port, dst_port) = match transport {
        Some(TransportHeader::Udp(udp)) => (udp.dst_port, udp.src_port),
        _ => return Vec::new(), // Should not happen (caller checked).
    };

    // Build the UDP header: src_port, dst_port, length, checksum(0).
    let udp_length = 8 + udp_payload.len() as u16;
    let mut udp_header = Vec::with_capacity(8 + udp_payload.len());
    udp_header.extend_from_slice(&src_port.to_be_bytes());
    udp_header.extend_from_slice(&dst_port.to_be_bytes());
    udp_header.extend_from_slice(&udp_length.to_be_bytes());
    udp_header.extend_from_slice(&0u16.to_be_bytes()); // Checksum (0 = not computed)
    udp_header.extend_from_slice(udp_payload);

    // Build the IP packet.
    match (src_ip, dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            build_ipv4_udp_packet(src_v4, dst_v4, &udp_header)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            build_ipv6_udp_packet(src_v6, dst_v6, &udp_header)
        }
        // Cross-family swaps don't happen in practice.
        _ => Vec::new(),
    }
}

/// Build an IPv4 + UDP packet.
fn build_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, udp_bytes: &[u8]) -> Vec<u8> {
    let total_length = 20 + udp_bytes.len();
    let mut packet = vec![0u8; total_length];
    // Version 4, IHL 5.
    packet[0] = 0x45;
    // Total length.
    packet[2] = (total_length >> 8) as u8;
    packet[3] = total_length as u8;
    // TTL.
    packet[8] = 64;
    // Protocol (UDP = 17).
    packet[9] = UDP;
    // Source IP.
    packet[12..16].copy_from_slice(&src.octets());
    // Destination IP.
    packet[16..20].copy_from_slice(&dst.octets());
    // UDP header + payload.
    packet[20..].copy_from_slice(udp_bytes);
    packet
}

/// Build an IPv6 + UDP packet.
fn build_ipv6_udp_packet(src: Ipv6Addr, dst: Ipv6Addr, udp_bytes: &[u8]) -> Vec<u8> {
    let payload_length = udp_bytes.len();
    let mut packet = vec![0u8; 40 + payload_length];
    // Version 6.
    packet[0] = 0x60;
    // Payload length.
    packet[4] = (payload_length >> 8) as u8;
    packet[5] = payload_length as u8;
    // Next header (UDP = 17).
    packet[6] = UDP;
    // Hop limit.
    packet[7] = 64;
    // Source address.
    packet[8..24].copy_from_slice(&src.octets());
    // Destination address.
    packet[24..40].copy_from_slice(&dst.octets());
    // UDP header + payload.
    packet[40..].copy_from_slice(udp_bytes);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use snp_tun::{build_test_ipv4_packet, build_test_ipv6_packet};

    /// Build a DNS query for the given domain and QTYPE.
    fn build_dns_query(transaction_id: u16, domain: &str, qtype: DnsQtype) -> Vec<u8> {
        let mut query = Vec::new();
        // Header (12 bytes).
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                      // Question: QNAME + QTYPE + QCLASS.
        query.extend_from_slice(&encode_qname(domain));
        query.extend_from_slice(&(qtype as u16).to_be_bytes()); // QTYPE
        query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        query
    }

    #[test]
    fn parse_dns_a_query() {
        let dns_bytes = build_dns_query(0x1234, "example.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).expect("parse must succeed");

        assert_eq!(query.transaction_id, 0x1234);
        assert!(query.is_query());
        assert!(query.recursion_desired());
        assert_eq!(query.questions.len(), 1);
        let q = &query.questions[0];
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, DnsQtype::A);
        assert_eq!(q.qclass, DnsQclass::IN);
    }

    #[test]
    fn parse_dns_aaaa_query() {
        let dns_bytes = build_dns_query(0x5678, "ipv6.example.com", DnsQtype::Aaaa);
        let query = parse_dns_query(&dns_bytes).expect("parse must succeed");

        assert_eq!(query.transaction_id, 0x5678);
        assert_eq!(query.questions[0].qname, "ipv6.example.com");
        assert_eq!(query.questions[0].qtype, DnsQtype::Aaaa);
    }

    #[test]
    fn parse_dns_query_too_short() {
        let result = parse_dns_query(&[0x12, 0x34]);
        assert!(
            matches!(result, Err(DnsError::TooShort { actual: 2 })),
            "short packet must return TooShort, got {:?}",
            result
        );
    }

    #[test]
    fn parse_dns_query_empty_qname() {
        // QNAME = just the terminating zero byte (root domain).
        let mut query = Vec::new();
        query.extend_from_slice(&0xABCDu16.to_be_bytes()); // Transaction ID
        query.extend_from_slice(&0u16.to_be_bytes()); // Flags
        query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        query.push(0); // QNAME = root (empty)
        query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

        let parsed = parse_dns_query(&query).expect("parse must succeed");
        assert_eq!(parsed.questions[0].qname, "");
    }

    #[test]
    fn parse_dns_multi_label_qname() {
        let dns_bytes = build_dns_query(0x0001, "a.b.c.d.example.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).expect("parse must succeed");
        assert_eq!(query.questions[0].qname, "a.b.c.d.example.com");
    }

    #[test]
    fn resolver_a_response() {
        let mut resolver = DnsResolver::new();
        resolver.add_mapping("example.com", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        let dns_bytes = build_dns_query(0x1234, "example.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).unwrap();
        let question_bytes = extract_question_bytes(&dns_bytes).unwrap();
        let response = resolver.resolve_query(&query, &question_bytes);

        // Check the response bytes directly (parse_dns_query expects a query
        // with QR=0, but a response has QR=1 — we verify via raw bytes).
        let txn = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(txn, 0x1234, "transaction ID must match");
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!((flags & 0x8000) != 0, "QR bit must be set (response)");
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1, "must have 1 answer");

        // The answer RDATA (last 4 bytes) must be the IPv4 address.
        let rdata = &response[response.len() - 4..];
        assert_eq!(rdata, &[93, 184, 216, 34]);
    }

    #[test]
    fn resolver_aaaa_response() {
        let mut resolver = DnsResolver::new();
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        resolver.add_mapping("ipv6.example.com", IpAddr::V6(ipv6));

        let dns_bytes = build_dns_query(0x5678, "ipv6.example.com", DnsQtype::Aaaa);
        let query = parse_dns_query(&dns_bytes).unwrap();
        let question_bytes = extract_question_bytes(&dns_bytes).unwrap();
        let response = resolver.resolve_query(&query, &question_bytes);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1, "must have 1 answer");
        // The answer RDATA (last 16 bytes) must be the IPv6 address.
        let rdata = &response[response.len() - 16..];
        assert_eq!(rdata, &ipv6.octets());
    }

    #[test]
    fn resolver_nxdomain_for_unmapped() {
        let resolver = DnsResolver::new(); // No mappings.

        let dns_bytes = build_dns_query(0x9999, "nonexistent.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).unwrap();
        let question_bytes = extract_question_bytes(&dns_bytes).unwrap();
        let response = resolver.resolve_query(&query, &question_bytes);

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000f, 3, "RCODE must be 3 (NXDOMAIN)");
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0, "NXDOMAIN must have 0 answers");
    }

    #[test]
    fn resolver_a_query_with_only_ipv6_mapping_returns_nxdomain() {
        let mut resolver = DnsResolver::new();
        resolver.add_mapping("dual.example.com", IpAddr::V6(Ipv6Addr::LOCALHOST));

        let dns_bytes = build_dns_query(0x1111, "dual.example.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).unwrap();
        let question_bytes = extract_question_bytes(&dns_bytes).unwrap();
        let response = resolver.resolve_query(&query, &question_bytes);

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000f, 3, "A query with only IPv6 → NXDOMAIN");
    }

    #[test]
    fn resolver_case_insensitive() {
        let mut resolver = DnsResolver::new();
        resolver.add_mapping("Example.COM", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        // Query with different case.
        let dns_bytes = build_dns_query(0x2222, "example.com", DnsQtype::A);
        let query = parse_dns_query(&dns_bytes).unwrap();
        let question_bytes = extract_question_bytes(&dns_bytes).unwrap();
        let response = resolver.resolve_query(&query, &question_bytes);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1, "case-insensitive lookup must succeed");
    }

    #[test]
    fn is_dns_query_detects_udp_53() {
        // Build a UDP packet to port 53.
        let mut udp_hdr = vec![0u8; 8];
        udp_hdr[0] = 0x12;
        udp_hdr[1] = 0x34; // src port 0x1234
        udp_hdr[2] = 0;
        udp_hdr[3] = 53; // dst port 53
        let dns_payload = build_dns_query(0xABCD, "test.com", DnsQtype::A);
        let mut udp = udp_hdr;
        udp.extend_from_slice(&dns_payload);
        let raw = build_test_ipv4_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            UDP,
            &udp,
        );
        let packet = IpPacket::parse(&raw).unwrap();

        assert!(is_dns_query(&packet).expect("is_dns_query must succeed"));
    }

    #[test]
    fn is_dns_query_rejects_non_dns_port() {
        // Build a UDP packet to port 80 (not DNS).
        let mut udp_hdr = vec![0u8; 8];
        udp_hdr[2] = 0;
        udp_hdr[3] = 80; // dst port 80
        let raw = build_test_ipv4_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            UDP,
            &udp_hdr,
        );
        let packet = IpPacket::parse(&raw).unwrap();

        assert!(!is_dns_query(&packet).expect("is_dns_query must succeed"));
    }

    #[test]
    fn intercept_dns_query_returns_response_packet() {
        let mut resolver = DnsResolver::new();
        resolver.add_mapping("example.com", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        // Build a DNS query packet (IPv4 UDP to port 53).
        let dns_payload = build_dns_query(0x1234, "example.com", DnsQtype::A);
        let mut udp_hdr = vec![0u8; 8];
        udp_hdr[0] = 0xCD;
        udp_hdr[1] = 0xAB; // src port 0xCDAB
        udp_hdr[2] = 0;
        udp_hdr[3] = 53; // dst port 53
        let mut udp = udp_hdr;
        udp.extend_from_slice(&dns_payload);
        let raw = build_test_ipv4_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            UDP,
            &udp,
        );
        let packet = IpPacket::parse(&raw).unwrap();

        let response = intercept_dns_query(&packet, &resolver)
            .expect("intercept must succeed")
            .expect("must return a response");

        // The response must be a valid IP packet.
        let resp_packet = IpPacket::parse(&response).expect("response must parse as IP");

        // Source/destination must be swapped.
        assert_eq!(
            resp_packet.metadata().source,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            resp_packet.metadata().destination,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))
        );

        // The UDP src/dst ports must be swapped.
        let resp_transport = parse_transport(&resp_packet).unwrap().unwrap();
        match resp_transport {
            TransportHeader::Udp(resp_udp) => {
                assert_eq!(resp_udp.src_port, 53, "response src port must be 53");
                assert_eq!(
                    resp_udp.dst_port, 0xCDAB,
                    "response dst port must be swapped"
                );
            }
            _ => panic!("expected UDP"),
        }

        // The DNS response must have the correct transaction ID and 1 answer.
        let resp_dns = extract_dns_response_payload(&resp_packet).expect("must have DNS payload");
        let txn = u16::from_be_bytes([resp_dns[0], resp_dns[1]]);
        assert_eq!(txn, 0x1234, "transaction ID must match");
        let ancount = u16::from_be_bytes([resp_dns[6], resp_dns[7]]);
        assert_eq!(ancount, 1, "must have 1 answer");
    }

    #[test]
    fn intercept_dns_query_returns_none_for_non_dns() {
        let resolver = DnsResolver::new();
        // Build a non-DNS UDP packet (port 80).
        let udp_hdr = vec![0u8; 8];
        let raw = build_test_ipv4_packet(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            UDP,
            &udp_hdr,
        );
        let packet = IpPacket::parse(&raw).unwrap();

        let result = intercept_dns_query(&packet, &resolver).expect("must not error");
        assert!(result.is_none(), "non-DNS packet must return None");
    }

    #[test]
    fn intercept_dns_query_ipv6() {
        let mut resolver = DnsResolver::new();
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        resolver.add_mapping("ipv6.test", IpAddr::V6(ipv6));

        let dns_payload = build_dns_query(0x4321, "ipv6.test", DnsQtype::Aaaa);
        let mut udp_hdr = vec![0u8; 8];
        udp_hdr[2] = 0;
        udp_hdr[3] = 53;
        let mut udp = udp_hdr;
        udp.extend_from_slice(&dns_payload);
        let raw = build_test_ipv6_packet(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            UDP,
            &udp,
        );
        let packet = IpPacket::parse(&raw).unwrap();

        let response = intercept_dns_query(&packet, &resolver)
            .expect("intercept must succeed")
            .expect("must return a response");

        let resp_packet = IpPacket::parse(&response).expect("response must parse");
        assert_eq!(
            resp_packet.metadata().source,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            resp_packet.metadata().destination,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        );

        let resp_dns = extract_dns_response_payload(&resp_packet).expect("must have DNS payload");
        let ancount = u16::from_be_bytes([resp_dns[6], resp_dns[7]]);
        assert_eq!(ancount, 1, "must have 1 answer");
    }
}

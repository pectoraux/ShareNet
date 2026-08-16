//! Transport-layer parsing (TCP/UDP) for flow classification.
//!
//! This module parses TCP and UDP headers from an [`IpPacket`] payload and
//! extracts a [`FlowKey`] — the 5-tuple (src_ip, dst_ip, src_port, dst_port,
//! protocol) that uniquely identifies a network flow.
//!
//! ## Scope (N2.3.2)
//!
//! - TCP header parsing (source port, destination port, flags).
//! - UDP header parsing (source port, destination port).
//! - TCP flag detection (SYN, ACK, FIN, RST) for connection tracking.
//! - [`FlowKey`] construction.
//!
//! ## Out of scope
//!
//! - TCP state machine (connection establishment/teardown tracking is in
//!   [`crate::flow_table`] — but only SYN/FIN/RST detection, not full
//!   RFC 793 state transitions).
//! - TCP sequence/acknowledgment tracking.
//! - Payload reassembly.
//! - smoltcp integration.
//! - Actual TCP proxying (N2.3.3+).

use std::net::IpAddr;

use snp_tun::IpPacket;

/// IP protocol number for TCP (RFC 793).
pub const PROTO_TCP: u8 = 6;

/// IP protocol number for UDP (RFC 768).
pub const UDP: u8 = 17;

/// Minimum TCP header size (20 bytes — data offset = 5, no options).
const TCP_MIN_HEADER_LEN: usize = 20;

/// Fixed UDP header size (8 bytes).
const UDP_HEADER_LEN: usize = 8;

/// TCP header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    /// FIN (0x01) — connection teardown requested.
    pub fin: bool,
    /// SYN (0x02) — connection establishment requested.
    pub syn: bool,
    /// RST (0x04) — connection reset (abort).
    pub rst: bool,
    /// PSH (0x08) — push data immediately to application.
    pub psh: bool,
    /// ACK (0x10) — acknowledgment number is valid.
    pub ack: bool,
    /// URG (0x20) — urgent pointer is valid.
    pub urg: bool,
}

impl TcpFlags {
    /// Parse TCP flags from the raw flag byte (offset 13 of the TCP header).
    #[must_use]
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: (flags & 0x01) != 0,
            syn: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            psh: (flags & 0x08) != 0,
            ack: (flags & 0x10) != 0,
            urg: (flags & 0x20) != 0,
        }
    }

    /// Returns true if this is a pure SYN (SYN set, ACK not set) — the first
    /// packet of a TCP connection.
    #[must_use]
    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    /// Returns true if this is a SYN-ACK (SYN and ACK both set) — the second
    /// packet of a TCP handshake.
    #[must_use]
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// Returns true if this packet initiates connection teardown (FIN or RST).
    #[must_use]
    pub fn is_teardown(&self) -> bool {
        self.fin || self.rst
    }
}

/// A parsed TCP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number (not validated — for informational use only).
    pub seq: u32,
    /// Acknowledgment number (not validated).
    pub ack: u32,
    /// TCP flags (SYN, ACK, FIN, RST, etc.).
    pub flags: TcpFlags,
    /// Header length in bytes (including options).
    pub header_len: usize,
}

/// A parsed UDP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Payload length (UDP header + data, as declared in the UDP length field).
    pub length: u16,
}

/// A transport-layer header — either TCP or UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportHeader {
    /// A TCP header.
    Tcp(TcpHeader),
    /// A UDP header.
    Udp(UdpHeader),
}

/// A 5-tuple identifying a network flow.
///
/// Two packets belong to the same flow if they have the same [`FlowKey`].
/// The key is order-sensitive: a flow from A→B is DIFFERENT from B→A (they
/// are the two directions of a bidirectional connection). The
/// [`FlowTable`](crate::flow_table::FlowTable) tracks flows per-direction;
/// the upper layers link the two directions via the connection's 4-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source transport port (TCP/UDP).
    pub src_port: u16,
    /// Destination transport port (TCP/UDP).
    pub dst_port: u16,
    /// Transport protocol (6 = TCP, 17 = UDP).
    pub protocol: u8,
}

impl FlowKey {
    /// Returns the REVERSE flow key (swap src↔dst for both IP and port).
    ///
    /// This is useful for finding the return direction of a bidirectional
    /// connection.
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

/// Parse the transport-layer header from an [`IpPacket`].
///
/// For TCP packets (protocol 6), parses the TCP header (source port,
/// destination port, flags, sequence/ack numbers, header length).
/// For UDP packets (protocol 17), parses the UDP header (source port,
/// destination port, length).
/// For other protocols (ICMP, etc.), returns `None` (no transport header
/// parsed at this layer — N2.3.2 scope is TCP/UDP only).
///
/// # Errors
/// Returns [`TransportError`] if the transport header is truncated or
/// malformed.
pub fn parse_transport(packet: &IpPacket) -> Result<Option<TransportHeader>, TransportError> {
    let protocol = packet.metadata().protocol;
    match protocol {
        PROTO_TCP => {
            let header = parse_tcp_header(packet)?;
            Ok(Some(TransportHeader::Tcp(header)))
        }
        UDP => {
            let header = parse_udp_header(packet)?;
            Ok(Some(TransportHeader::Udp(header)))
        }
        _ => Ok(None), // ICMP, ICMPv6, etc. — not parsed at this layer
    }
}

/// Extract a [`FlowKey`] from an [`IpPacket`] + parsed [`TransportHeader`].
///
/// # Errors
/// Returns [`TransportError`] if the transport header is missing (the caller
/// should have already called [`parse_transport`]).
pub fn flow_key(packet: &IpPacket, transport: &TransportHeader) -> Result<FlowKey, TransportError> {
    let (src_ip, dst_ip) = (
        packet.metadata().source,
        packet.metadata().destination,
    );
    let (src_port, dst_port, protocol) = match transport {
        TransportHeader::Tcp(tcp) => (tcp.src_port, tcp.dst_port, PROTO_TCP),
        TransportHeader::Udp(udp) => (udp.src_port, udp.dst_port, UDP),
    };
    Ok(FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    })
}

/// Parse a TCP header from the packet's transport-layer payload.
fn parse_tcp_header(packet: &IpPacket) -> Result<TcpHeader, TransportError> {
    let payload = transport_payload(packet);
    let payload = payload.ok_or(TransportError::NoTransportPayload)?;

    if payload.len() < TCP_MIN_HEADER_LEN {
        return Err(TransportError::TruncatedTcp {
            actual: payload.len(),
            minimum: TCP_MIN_HEADER_LEN,
        });
    }

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ack = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let data_offset = (payload[12] >> 4) as usize;
    let header_len = data_offset * 4;
    if header_len < TCP_MIN_HEADER_LEN {
        return Err(TransportError::InvalidTcpDataOffset { data_offset });
    }
    if payload.len() < header_len {
        return Err(TransportError::TruncatedTcp {
            actual: payload.len(),
            minimum: header_len,
        });
    }
    let flags = TcpFlags::from_byte(payload[13]);

    Ok(TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        header_len,
    })
}

/// Parse a UDP header from the packet's transport-layer payload.
fn parse_udp_header(packet: &IpPacket) -> Result<UdpHeader, TransportError> {
    let payload = transport_payload(packet);
    let payload = payload.ok_or(TransportError::NoTransportPayload)?;

    if payload.len() < UDP_HEADER_LEN {
        return Err(TransportError::TruncatedUdp {
            actual: payload.len(),
            minimum: UDP_HEADER_LEN,
        });
    }

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]);

    Ok(UdpHeader {
        src_port,
        dst_port,
        length,
    })
}

/// Extract the transport-layer payload (bytes after the IP header) from an
/// [`IpPacket`].
fn transport_payload(packet: &IpPacket) -> Option<&[u8]> {
    match packet {
        IpPacket::IPv4(p) => {
            let bytes = p.as_bytes();
            // IHL is in the low nibble of byte 0, in 4-byte units.
            let ihl = (bytes[0] & 0x0f) as usize;
            let header_len = ihl * 4;
            if bytes.len() < header_len {
                return None;
            }
            Some(&bytes[header_len..])
        }
        IpPacket::IPv6(p) => {
            let bytes = p.as_bytes();
            // IPv6 header is fixed 40 bytes. Extension headers are NOT
            // traversed (N2.3.1 limitation — documented in snp-tun). The
            // payload starts at byte 40.
            const IPV6_HEADER_LEN: usize = 40;
            if bytes.len() < IPV6_HEADER_LEN {
                return None;
            }
            Some(&bytes[IPV6_HEADER_LEN..])
        }
    }
}

/// Errors from transport-layer parsing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// The packet has no transport-layer payload (e.g. a truncated IP packet
    /// with no bytes after the IP header).
    #[error("no transport-layer payload in IP packet")]
    NoTransportPayload,
    /// TCP header is truncated (fewer bytes than the minimum 20-byte header
    /// or the declared data offset).
    #[error("truncated TCP header: {actual} bytes (minimum {minimum})")]
    TruncatedTcp {
        /// Actual bytes available in the transport payload.
        actual: usize,
        /// Minimum bytes required (20 or the declared data_offset * 4).
        minimum: usize,
    },
    /// UDP header is truncated (fewer than 8 bytes).
    #[error("truncated UDP header: {actual} bytes (minimum {minimum})")]
    TruncatedUdp {
        /// Actual bytes available.
        actual: usize,
        /// Minimum bytes required (8).
        minimum: usize,
    },
    /// TCP data offset is invalid (less than 5, meaning a header < 20 bytes).
    #[error("invalid TCP data offset: {data_offset} (minimum 5)")]
    InvalidTcpDataOffset {
        /// The declared data offset (in 4-byte units).
        data_offset: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use snp_tun::{build_test_ipv4_packet, build_test_ipv6_packet};
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build a TCP header (20 bytes, no options) with the given ports + flags.
    fn build_tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        // Source port
        hdr[0] = (src_port >> 8) as u8;
        hdr[1] = src_port as u8;
        // Destination port
        hdr[2] = (dst_port >> 8) as u8;
        hdr[3] = dst_port as u8;
        // Sequence number (0)
        // Acknowledgment number (0)
        // Data offset (5 = 20 bytes) + reserved → byte 12 = 0x50
        hdr[12] = 0x50;
        // Flags
        hdr[13] = flags;
        // Window size (1024)
        hdr[14] = 4;
        hdr[15] = 0;
        // Checksum (0 — not validated)
        // Urgent pointer (0)
        hdr
    }

    /// Build a UDP header (8 bytes) with the given ports + payload.
    fn build_udp_header(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
        let mut hdr = vec![0u8; 8];
        // Source port
        hdr[0] = (src_port >> 8) as u8;
        hdr[1] = src_port as u8;
        // Destination port
        hdr[2] = (dst_port >> 8) as u8;
        hdr[3] = dst_port as u8;
        // Length (8 header + payload)
        let length = 8 + payload_len;
        hdr[4] = (length >> 8) as u8;
        hdr[5] = length as u8;
        // Checksum (0 — not validated)
        hdr
    }

    #[test]
    fn parse_tcp_syn_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let tcp_hdr = build_tcp_header(52344, 443, 0x02); // SYN
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let transport = parse_transport(&packet).expect("parse transport");
        match transport {
            Some(TransportHeader::Tcp(tcp)) => {
                assert_eq!(tcp.src_port, 52344);
                assert_eq!(tcp.dst_port, 443);
                assert!(tcp.flags.is_syn(), "must be a pure SYN");
                assert!(!tcp.flags.is_syn_ack());
                assert_eq!(tcp.header_len, 20);
            }
            other => panic!("expected TCP, got {:?}", other),
        }
    }

    #[test]
    fn parse_tcp_syn_ack_packet() {
        let src = Ipv4Addr::new(93, 184, 216, 34);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let tcp_hdr = build_tcp_header(443, 52344, 0x12); // SYN + ACK
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let transport = parse_transport(&packet).expect("parse transport");
        match transport {
            Some(TransportHeader::Tcp(tcp)) => {
                assert!(tcp.flags.is_syn_ack(), "must be SYN-ACK");
                assert!(!tcp.flags.is_syn(), "SYN-ACK is not a pure SYN");
            }
            other => panic!("expected TCP, got {:?}", other),
        }
    }

    #[test]
    fn parse_tcp_fin_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let tcp_hdr = build_tcp_header(52344, 443, 0x01); // FIN
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let transport = parse_transport(&packet).expect("parse transport");
        match transport {
            Some(TransportHeader::Tcp(tcp)) => {
                assert!(tcp.flags.is_teardown(), "FIN must be teardown");
                assert!(!tcp.flags.is_syn());
            }
            other => panic!("expected TCP, got {:?}", other),
        }
    }

    #[test]
    fn parse_tcp_rst_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let tcp_hdr = build_tcp_header(52344, 443, 0x04); // RST
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let transport = parse_transport(&packet).expect("parse transport");
        match transport {
            Some(TransportHeader::Tcp(tcp)) => {
                assert!(tcp.flags.is_teardown(), "RST must be teardown");
            }
            other => panic!("expected TCP, got {:?}", other),
        }
    }

    #[test]
    fn parse_udp_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let udp_payload = b"DNS query";
        let udp_hdr = build_udp_header(53535, 53, udp_payload.len());
        let mut transport = udp_hdr;
        transport.extend_from_slice(udp_payload);
        let raw = build_test_ipv4_packet(src, dst, UDP, &transport);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let parsed = parse_transport(&packet).expect("parse transport");
        match parsed {
            Some(TransportHeader::Udp(udp)) => {
                assert_eq!(udp.src_port, 53535);
                assert_eq!(udp.dst_port, 53);
                assert_eq!(udp.length, 8 + udp_payload.len() as u16);
            }
            other => panic!("expected UDP, got {:?}", other),
        }
    }

    #[test]
    fn parse_udp_ipv6_packet() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let udp_payload = b"ipv6 udp";
        let udp_hdr = build_udp_header(12345, 53, udp_payload.len());
        let mut transport = udp_hdr;
        transport.extend_from_slice(udp_payload);
        let raw = build_test_ipv6_packet(src, dst, UDP, &transport);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let parsed = parse_transport(&packet).expect("parse transport");
        match parsed {
            Some(TransportHeader::Udp(udp)) => {
                assert_eq!(udp.src_port, 12345);
                assert_eq!(udp.dst_port, 53);
            }
            other => panic!("expected UDP, got {:?}", other),
        }
    }

    #[test]
    fn parse_tcp_ipv6_packet() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let tcp_hdr = build_tcp_header(52344, 443, 0x02); // SYN
        let raw = build_test_ipv6_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let parsed = parse_transport(&packet).expect("parse transport");
        match parsed {
            Some(TransportHeader::Tcp(tcp)) => {
                assert_eq!(tcp.src_port, 52344);
                assert_eq!(tcp.dst_port, 443);
                assert!(tcp.flags.is_syn());
            }
            other => panic!("expected TCP, got {:?}", other),
        }
    }

    #[test]
    fn parse_icmp_returns_none() {
        // ICMP (protocol 1) is not parsed at the transport layer in N2.3.2.
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let icmp_payload = [0x08, 0x00, 0x00, 0x00]; // Echo request
        let raw = build_test_ipv4_packet(src, dst, 1, &icmp_payload);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let result = parse_transport(&packet).expect("parse transport");
        assert!(result.is_none(), "ICMP must return None (not TCP/UDP)");
    }

    #[test]
    fn flow_key_extraction_tcp() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let tcp_hdr = build_tcp_header(52344, 443, 0x02);
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");
        let transport = parse_transport(&packet).expect("parse transport").unwrap();
        let key = flow_key(&packet, &transport).expect("flow key");

        assert_eq!(key.src_ip, IpAddr::V4(src));
        assert_eq!(key.dst_ip, IpAddr::V4(dst));
        assert_eq!(key.src_port, 52344);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol, PROTO_TCP);
    }

    #[test]
    fn flow_key_extraction_udp() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let udp_hdr = build_udp_header(53535, 53, 4);
        let raw = build_test_ipv4_packet(src, dst, UDP, &udp_hdr);
        let packet = IpPacket::parse(&raw).expect("parse IP");
        let transport = parse_transport(&packet).expect("parse transport").unwrap();
        let key = flow_key(&packet, &transport).expect("flow key");

        assert_eq!(key.src_port, 53535);
        assert_eq!(key.dst_port, 53);
        assert_eq!(key.protocol, UDP);
    }

    #[test]
    fn flow_key_reverse_swaps_src_dst() {
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dst_port: 443,
            protocol: PROTO_TCP,
        };
        let rev = key.reverse();
        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
        assert_eq!(rev.protocol, key.protocol);
    }

    #[test]
    fn truncated_tcp_returns_error() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        // Only 10 bytes of TCP header (less than minimum 20).
        let truncated_tcp = vec![0u8; 10];
        let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &truncated_tcp);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let result = parse_transport(&packet);
        assert!(
            matches!(result, Err(TransportError::TruncatedTcp { minimum: 20, .. })),
            "truncated TCP must return TruncatedTcp, got {:?}",
            result
        );
    }

    #[test]
    fn truncated_udp_returns_error() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        // Only 4 bytes of UDP header (less than minimum 8).
        let truncated_udp = vec![0u8; 4];
        let raw = build_test_ipv4_packet(src, dst, UDP, &truncated_udp);
        let packet = IpPacket::parse(&raw).expect("parse IP");

        let result = parse_transport(&packet);
        assert!(
            matches!(result, Err(TransportError::TruncatedUdp { minimum: 8, .. })),
            "truncated UDP must return TruncatedUdp, got {:?}",
            result
        );
    }

    #[test]
    fn tcp_flags_from_byte_all_combinations() {
        // SYN only
        let f = TcpFlags::from_byte(0x02);
        assert!(f.syn && !f.ack && !f.fin && !f.rst);

        // SYN+ACK
        let f = TcpFlags::from_byte(0x12);
        assert!(f.syn && f.ack);

        // FIN+ACK
        let f = TcpFlags::from_byte(0x11);
        assert!(f.fin && f.ack && !f.syn);

        // RST
        let f = TcpFlags::from_byte(0x04);
        assert!(f.rst && !f.ack);

        // PSH+ACK
        let f = TcpFlags::from_byte(0x18);
        assert!(f.psh && f.ack);
    }
}

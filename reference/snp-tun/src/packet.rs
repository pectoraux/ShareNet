//! IP packet abstraction for the TUN boundary.
//!
//! This module parses raw IP packets (as read from a TUN device) into typed
//! [`IpPacket`] values with extracted [`PacketMetadata`]. It supports:
//!
//! - **IPv4** (RFC 791): version, IHL, total length, protocol, source, destination.
//! - **IPv6** (RFC 8200): version, payload length, next header, source, destination.
//!
//! ## What this module does NOT do
//!
//! - TCP/UDP/ICMP transport-layer parsing (N2.3.2+).
//! - Packet construction/modification (write path sends pre-formed bytes).
//! - Fragment reassembly.
//! - Extension header parsing (IPv6 next-header chain).
//!
//! The abstraction is deliberately minimal: it knows about IP headers and
//! nothing else. This keeps the TUN boundary free of transport/application
//! concerns, matching the N2.3.1 scope.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::TunError;

/// Minimum IPv4 header size (20 bytes — IHL=5, no options).
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Fixed IPv6 header size (40 bytes).
const IPV6_HEADER_LEN: usize = 40;

/// Maximum IP packet size (max IPv4 total length = u16::MAX).
pub const MAX_PACKET_SIZE: usize = 65535;

/// Metadata extracted from an IP packet header.
///
/// This is the information a router/firewall needs to make a forwarding
/// decision WITHOUT inspecting the transport layer. The TUN boundary
/// extracts this metadata so the upper layers (future N2.3.2+) can decide
/// what to do with the packet without re-parsing the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    /// Source IP address (IPv4 or IPv6).
    pub source: IpAddr,
    /// Destination IP address (IPv4 or IPv6).
    pub destination: IpAddr,
    /// IPv4 protocol field or IPv6 next-header field (e.g. 6 = TCP, 17 = UDP,
    /// 58 = ICMPv6). For IPv6, this is the FIRST next-header value (extension
    /// header chains are NOT followed — N2.3.1 scope).
    pub protocol: u8,
    /// Total packet length in bytes (including the IP header).
    pub length: usize,
}

/// An IP packet — either IPv4 or IPv6.
///
/// The packet owns its bytes, so it can be sent across task boundaries without
/// lifetime concerns. The metadata is cached at parse time to avoid
/// re-parsing on every access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPacket {
    /// An IPv4 packet (RFC 791).
    IPv4(Ipv4Packet),
    /// An IPv6 packet (RFC 8200).
    IPv6(Ipv6Packet),
}

/// An IPv4 packet with parsed metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    /// The raw packet bytes (header + payload), truncated to the declared
    /// total length.
    bytes: Vec<u8>,
    /// Cached metadata (source, destination, protocol, length).
    metadata: PacketMetadata,
}

/// An IPv6 packet with parsed metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    /// The raw packet bytes (header + payload), truncated to the declared
    /// total length (40 + payload_length).
    bytes: Vec<u8>,
    /// Cached metadata (source, destination, next header, length).
    metadata: PacketMetadata,
}

impl IpPacket {
    /// Parse raw bytes into an [`IpPacket`].
    ///
    /// The version is determined from the high nibble of the first byte:
    /// - `4` → IPv4
    /// - `6` → IPv6
    /// - anything else → [`TunError::InvalidPacket`]
    ///
    /// The packet bytes are validated:
    /// - IPv4: minimum 20 bytes, IHL ≥ 5, total_length ≤ buffer length.
    /// - IPv6: minimum 40 bytes, payload_length + 40 ≤ buffer length.
    ///
    /// The returned packet owns its bytes (truncated to the declared total
    /// length if the buffer has trailing padding).
    ///
    /// # Errors
    /// Returns [`TunError::InvalidPacket`] if the bytes are empty, have an
    /// unknown version, or fail header validation.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Result<Self, TunError> {
        if bytes.is_empty() {
            return Err(TunError::InvalidPacket("empty packet (0 bytes)".into()));
        }
        let version = bytes[0] >> 4;
        match version {
            4 => Self::parse_ipv4(bytes).map(Self::IPv4),
            6 => Self::parse_ipv6(bytes).map(Self::IPv6),
            v => Err(TunError::InvalidPacket(format!(
                "unknown IP version: {v} (expected 4 or 6) — first byte = 0x{:02x}",
                bytes[0]
            ))),
        }
    }

    /// Parse an IPv4 packet from raw bytes.
    fn parse_ipv4(bytes: &[u8]) -> Result<Ipv4Packet, TunError> {
        if bytes.len() < IPV4_MIN_HEADER_LEN {
            return Err(TunError::InvalidPacket(format!(
                "IPv4 packet too short: {} bytes (minimum {IPV4_MIN_HEADER_LEN})",
                bytes.len()
            )));
        }
        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(TunError::InvalidPacket(format!(
                "not an IPv4 packet: version field = {version}"
            )));
        }
        let ihl = bytes[0] & 0x0f;
        if ihl < 5 {
            return Err(TunError::InvalidPacket(format!(
                "IPv4 IHL too small: {ihl} (minimum 5 = 20-byte header)"
            )));
        }
        let header_len = (ihl as usize) * 4;
        if bytes.len() < header_len {
            return Err(TunError::InvalidPacket(format!(
                "IPv4 packet shorter than declared header: {} bytes < IHL*4 = {header_len}",
                bytes.len()
            )));
        }
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total_length < header_len {
            return Err(TunError::InvalidPacket(format!(
                "IPv4 total length {total_length} < header length {header_len}"
            )));
        }
        if total_length > bytes.len() {
            return Err(TunError::InvalidPacket(format!(
                "IPv4 total length {total_length} > actual bytes {} (truncated packet)",
                bytes.len()
            )));
        }
        let protocol = bytes[9];
        let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

        Ok(Ipv4Packet {
            bytes: bytes[..total_length].to_vec(),
            metadata: PacketMetadata {
                source: IpAddr::V4(source),
                destination: IpAddr::V4(destination),
                protocol,
                length: total_length,
            },
        })
    }

    /// Parse an IPv6 packet from raw bytes.
    fn parse_ipv6(bytes: &[u8]) -> Result<Ipv6Packet, TunError> {
        if bytes.len() < IPV6_HEADER_LEN {
            return Err(TunError::InvalidPacket(format!(
                "IPv6 packet too short: {} bytes (minimum {IPV6_HEADER_LEN})",
                bytes.len()
            )));
        }
        let version = bytes[0] >> 4;
        if version != 6 {
            return Err(TunError::InvalidPacket(format!(
                "not an IPv6 packet: version field = {version}"
            )));
        }
        let payload_length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let next_header = bytes[6];
        let total_length = IPV6_HEADER_LEN + payload_length;
        if total_length > bytes.len() {
            return Err(TunError::InvalidPacket(format!(
                "IPv6 declared length {total_length} (40 + {payload_length} payload) > actual bytes {} (truncated packet)",
                bytes.len()
            )));
        }
        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&bytes[8..24]);
        let source = Ipv6Addr::from(src_octets);
        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&bytes[24..40]);
        let destination = Ipv6Addr::from(dst_octets);

        Ok(Ipv6Packet {
            bytes: bytes[..total_length].to_vec(),
            metadata: PacketMetadata {
                source: IpAddr::V6(source),
                destination: IpAddr::V6(destination),
                protocol: next_header,
                length: total_length,
            },
        })
    }

    /// Returns a reference to the cached metadata (source, destination,
    /// protocol, length).
    #[must_use]
    pub fn metadata(&self) -> &PacketMetadata {
        match self {
            IpPacket::IPv4(p) => &p.metadata,
            IpPacket::IPv6(p) => &p.metadata,
        }
    }

    /// Returns the raw packet bytes (header + payload).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            IpPacket::IPv4(p) => &p.bytes,
            IpPacket::IPv6(p) => &p.bytes,
        }
    }

    /// Consumes the packet and returns the owned raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            IpPacket::IPv4(p) => p.bytes,
            IpPacket::IPv6(p) => p.bytes,
        }
    }
}

impl Ipv4Packet {
    /// Returns a reference to the cached metadata.
    #[must_use]
    pub fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Returns the raw packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the source IPv4 address.
    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        match self.metadata.source {
            IpAddr::V4(addr) => addr,
            _ => unreachable!("IPv4Packet source is always V4"),
        }
    }

    /// Returns the destination IPv4 address.
    #[must_use]
    pub fn destination(&self) -> Ipv4Addr {
        match self.metadata.destination {
            IpAddr::V4(addr) => addr,
            _ => unreachable!("IPv4Packet destination is always V4"),
        }
    }

    /// Returns the IPv4 protocol field (e.g. 6 = TCP, 17 = UDP, 1 = ICMP).
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.metadata.protocol
    }

    /// Returns the total packet length (header + payload).
    #[must_use]
    pub fn length(&self) -> usize {
        self.metadata.length
    }
}

impl Ipv6Packet {
    /// Returns a reference to the cached metadata.
    #[must_use]
    pub fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Returns the raw packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the source IPv6 address.
    #[must_use]
    pub fn source(&self) -> Ipv6Addr {
        match self.metadata.source {
            IpAddr::V6(addr) => addr,
            _ => unreachable!("IPv6Packet source is always V6"),
        }
    }

    /// Returns the destination IPv6 address.
    #[must_use]
    pub fn destination(&self) -> Ipv6Addr {
        match self.metadata.destination {
            IpAddr::V6(addr) => addr,
            _ => unreachable!("IPv6Packet destination is always V6"),
        }
    }

    /// Returns the IPv6 next-header field (e.g. 6 = TCP, 17 = UDP, 58 = ICMPv6).
    #[must_use]
    pub fn next_header(&self) -> u8 {
        self.metadata.protocol
    }

    /// Returns the total packet length (40-byte header + payload).
    #[must_use]
    pub fn length(&self) -> usize {
        self.metadata.length
    }
}

/// Build a minimal IPv4 packet for testing. Creates a 20-byte header with no
/// payload, the given source/destination/protocol, and a zeroed checksum.
#[doc(hidden)]
pub fn build_test_ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_length = 20 + payload.len();
    let mut bytes = vec![0u8; 20 + payload.len()];
    // Version 4, IHL 5 → byte 0 = 0x45
    bytes[0] = 0x45;
    // Total length (big-endian)
    bytes[2] = (total_length >> 8) as u8;
    bytes[3] = total_length as u8;
    // TTL
    bytes[8] = 64;
    // Protocol
    bytes[9] = protocol;
    // Source address
    bytes[12..16].copy_from_slice(&source.octets());
    // Destination address
    bytes[16..20].copy_from_slice(&destination.octets());
    // Payload
    bytes[20..].copy_from_slice(payload);
    bytes
}

/// Build a minimal IPv6 packet for testing. Creates a 40-byte header with the
/// given source/destination/next-header, plus payload.
#[doc(hidden)]
pub fn build_test_ipv6_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> Vec<u8> {
    let payload_length = payload.len();
    let mut bytes = vec![0u8; 40 + payload.len()];
    // Version 6, traffic class 0, flow label 0 → byte 0 = 0x60
    bytes[0] = 0x60;
    // Payload length (big-endian)
    bytes[4] = (payload_length >> 8) as u8;
    bytes[5] = payload_length as u8;
    // Next header
    bytes[6] = next_header;
    // Hop limit
    bytes[7] = 64;
    // Source address (16 bytes)
    bytes[8..24].copy_from_slice(&source.octets());
    // Destination address (16 bytes)
    bytes[24..40].copy_from_slice(&destination.octets());
    // Payload
    bytes[40..].copy_from_slice(payload);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_ipv4_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let raw = build_test_ipv4_packet(src, dst, 6, b"hello");
        let packet = IpPacket::parse(&raw).expect("valid IPv4 must parse");
        match &packet {
            IpPacket::IPv4(p) => {
                assert_eq!(p.source(), src);
                assert_eq!(p.destination(), dst);
                assert_eq!(p.protocol(), 6, "protocol must be TCP (6)");
                assert_eq!(p.length(), 25, "length must be 20 header + 5 payload");
            }
            IpPacket::IPv6(_) => panic!("expected IPv4, got IPv6"),
        }
        assert_eq!(packet.as_bytes(), &raw[..]);
    }

    #[test]
    fn parse_valid_ipv4_metadata() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let raw = build_test_ipv4_packet(src, dst, 17, b"udp-data");
        let packet = IpPacket::parse(&raw).expect("valid IPv4 must parse");
        let meta = packet.metadata();
        assert_eq!(meta.source, IpAddr::V4(src));
        assert_eq!(meta.destination, IpAddr::V4(dst));
        assert_eq!(meta.protocol, 17, "protocol must be UDP (17)");
        assert_eq!(meta.length, 28, "length must be 20 header + 8 payload");
    }

    #[test]
    fn parse_ipv6_loopback() {
        let src = Ipv6Addr::LOCALHOST; // ::1
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let raw = build_test_ipv6_packet(src, dst, 6, b"ipv6-test");
        let packet = IpPacket::parse(&raw).expect("valid IPv6 must parse");
        match &packet {
            IpPacket::IPv6(p) => {
                assert_eq!(p.source(), src);
                assert_eq!(p.destination(), dst);
                assert_eq!(p.next_header(), 6, "next header must be TCP (6)");
                assert_eq!(p.length(), 49, "length must be 40 header + 9 payload");
            }
            IpPacket::IPv4(_) => panic!("expected IPv6, got IPv4"),
        }
    }

    #[test]
    fn parse_ipv6_global_address() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let raw = build_test_ipv6_packet(src, dst, 58, b"icmpv6");
        let packet = IpPacket::parse(&raw).expect("valid IPv6 must parse");
        let meta = packet.metadata();
        assert_eq!(meta.source, IpAddr::V6(src));
        assert_eq!(meta.destination, IpAddr::V6(dst));
        assert_eq!(meta.protocol, 58, "next header must be ICMPv6 (58)");
        assert_eq!(meta.length, 46, "length must be 40 header + 6 payload");
    }

    #[test]
    fn parse_malformed_random_bytes() {
        // 0xff has version nibble 0xf (15) — not 4 or 6.
        let raw = vec![0xff; 100];
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(_))),
            "random bytes with version 15 must return InvalidPacket, got {:?}",
            result
        );
    }

    #[test]
    fn parse_empty_packet() {
        let result = IpPacket::parse(&[]);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(_))),
            "empty packet must return InvalidPacket, got {:?}",
            result
        );
    }

    #[test]
    fn parse_too_short_ipv4() {
        // 10 bytes — less than minimum 20-byte IPv4 header.
        let raw = vec![0x45; 10];
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(_))),
            "10-byte IPv4 must return InvalidPacket, got {:?}",
            result
        );
    }

    #[test]
    fn parse_too_short_ipv6() {
        // 30 bytes — less than minimum 40-byte IPv6 header.
        let mut raw = vec![0u8; 30];
        raw[0] = 0x60; // version 6
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(_))),
            "30-byte IPv6 must return InvalidPacket, got {:?}",
            result
        );
    }

    #[test]
    fn parse_wrong_version_nibble() {
        // Version 5 (not 4 or 6).
        let mut raw = vec![0u8; 40];
        raw[0] = 0x50; // version 5, IHL 0
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(_))),
            "version 5 must return InvalidPacket, got {:?}",
            result
        );
    }

    #[test]
    fn parse_ipv4_truncated_by_total_length() {
        // Total length says 100 bytes but we only provide 30.
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = build_test_ipv4_packet(src, dst, 6, b"hi");
        // Override total length to 100 (but actual is 22).
        raw[2] = 0;
        raw[3] = 100;
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(ref msg)) if msg.contains("truncated")),
            "IPv4 with total_length > actual must return InvalidPacket (truncated), got {:?}",
            result
        );
    }

    #[test]
    fn parse_ipv4_bad_ihl() {
        // IHL = 0 (less than minimum 5).
        let mut raw = vec![0u8; 40];
        raw[0] = 0x40; // version 4, IHL 0
        raw[2] = 0;
        raw[3] = 40; // total length 40
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(ref msg)) if msg.contains("IHL")),
            "IPv4 with IHL=0 must return InvalidPacket (IHL), got {:?}",
            result
        );
    }

    #[test]
    fn parse_ipv6_truncated_by_payload_length() {
        // Payload length says 100 but we only provide 10.
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut raw = build_test_ipv6_packet(src, dst, 6, b"short");
        // Override payload length to 100 (but actual payload is 5).
        raw[4] = 0;
        raw[5] = 100;
        let result = IpPacket::parse(&raw);
        assert!(
            matches!(result, Err(TunError::InvalidPacket(ref msg)) if msg.contains("truncated")),
            "IPv6 with payload_length > actual must return InvalidPacket (truncated), got {:?}",
            result
        );
    }

    #[test]
    fn ipv4_packet_bytes_preserved() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let payload = b"test payload data";
        let raw = build_test_ipv4_packet(src, dst, 17, payload);
        let packet = IpPacket::parse(&raw).expect("parse must succeed");
        assert_eq!(packet.as_bytes(), &raw[..]);
        assert_eq!(packet.into_bytes(), raw);
    }

    #[test]
    fn ipv6_packet_bytes_preserved() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let payload = b"ipv6 payload here";
        let raw = build_test_ipv6_packet(src, dst, 6, payload);
        let packet = IpPacket::parse(&raw).expect("parse must succeed");
        assert_eq!(packet.as_bytes(), &raw[..]);
        assert_eq!(packet.into_bytes(), raw);
    }

    #[test]
    fn ipv4_packet_strips_trailing_padding() {
        // Some TUN drivers deliver packets with trailing padding. The parser
        // must truncate to the declared total length.
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = build_test_ipv4_packet(src, dst, 6, b"hi");
        // Add 10 bytes of trailing padding.
        raw.extend_from_slice(&[0u8; 10]);
        let packet = IpPacket::parse(&raw).expect("parse must succeed");
        // The packet length must be 22 (20 header + 2 payload), not 32.
        assert_eq!(packet.metadata().length, 22);
        assert_eq!(packet.as_bytes().len(), 22);
    }
}

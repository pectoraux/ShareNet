//! **N3-B — Destination extraction for transparent TCP.**
//!
//! Extracts the original TCP destination (IP + port) from raw IP packets
//! read from a TUN interface, and validates that the destination is a
//! routable Internet address (not private / loopback / link-local).
//!
//! ## Why this module exists
//!
//! The [`TunClient`](crate::tun_client) runtime reads raw IP packets from a
//! TUN device. To forward traffic transparently, it must determine the
//! original destination (the Internet endpoint the OS application was trying
//! to reach) from each TCP SYN packet, then open a ShareNet stream to that
//! destination.
//!
//! The extraction reuses the existing transport-layer parsing
//! ([`parse_transport`](crate::transport::parse_transport) +
//! [`flow_key`](crate::transport::flow_key)) — it does NOT duplicate packet
//! parsing logic.
//!
//! ## Destination validation
//!
//! The client-side validation is an EARLY REJECTION of destinations that the
//! gateway would reject anyway (private/loopback/link-local IPs). This is NOT
//! a security boundary — the gateway remains the authoritative egress policy
//! enforcer (see `gateway_stream.rs::handle_stream_open`). The client-side
//! check exists to:
//!
//! 1. Give the OS application an immediate RST (via smoltcp socket close)
//!    rather than a delayed rejection after a circuit round-trip.
//! 2. Avoid wasting ShareNet circuit bandwidth on destinations that will be
//!    rejected.
//!
//! ## What this does NOT do
//!
//! - It does NOT generate packets (FlowTable frozen invariant preserved).
//! - It does NOT modify packets (no NAT, no rewriting).
//! - It does NOT select routes or create circuits.
//! - It does NOT replace the gateway's SSRF defence.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use snp_tun::IpPacket;

use crate::transport::{flow_key, parse_transport, FlowKey, TcpFlags, TransportHeader, PROTO_TCP};

/// The result of extracting flow metadata from a raw IP packet.
///
/// Returned by [`extract_flow`]. Contains everything the TunClient needs to
/// decide whether to intercept the packet and how to forward it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMetadata {
    /// The 5-tuple identifying this flow.
    pub key: FlowKey,
    /// The TCP flags (if this is a TCP packet). `None` for UDP/ICMP.
    pub tcp_flags: Option<TcpFlags>,
}

/// Extract flow metadata (5-tuple + TCP flags) from a raw IP packet.
///
/// This is a thin wrapper around the existing
/// [`parse_transport`](crate::transport::parse_transport) +
/// [`flow_key`](crate::transport::flow_key) functions. It returns `None` if
/// the packet is not a TCP or UDP packet (e.g. ICMP) or if the transport
/// header is truncated/malformed.
///
/// # Arguments
/// * `packet` — A parsed [`IpPacket`] (from `IpPacket::parse`).
///
/// # Returns
/// `Some(FlowMetadata)` if the packet has a parseable TCP/UDP header,
/// `None` otherwise.
pub fn extract_flow(packet: &IpPacket) -> Option<FlowMetadata> {
    let transport = parse_transport(packet).ok()??;
    let key = flow_key(packet, &transport).ok()?;
    let tcp_flags = match &transport {
        TransportHeader::Tcp(tcp) => Some(tcp.flags),
        TransportHeader::Udp(_) => None,
    };
    Some(FlowMetadata { key, tcp_flags })
}

/// Returns true if the packet is a TCP SYN (connection initiation).
///
/// A pure SYN has the SYN flag set and the ACK flag clear. SYN-ACK packets
/// (SYN+ACK) are NOT connection initiations from the client's perspective —
/// they are the server side of the handshake.
#[must_use]
pub fn is_tcp_syn(meta: &FlowMetadata) -> bool {
    matches!(meta.tcp_flags, Some(flags) if flags.is_syn())
}

/// Returns the destination IP + port from a flow, if it is a TCP flow.
///
/// For TCP flows, returns `(dst_ip, dst_port)`. For non-TCP flows, returns
/// `None`.
#[must_use]
pub fn tcp_destination(meta: &FlowMetadata) -> Option<(IpAddr, u16)> {
    if meta.key.protocol == PROTO_TCP {
        Some((meta.key.dst_ip, meta.key.dst_port))
    } else {
        None
    }
}

/// Returns true if the IP address is a routable Internet address.
///
/// Returns `false` for:
/// - Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) per
///   RFC 1918.
/// - Loopback (127.0.0.0/8 for IPv4, ::1 for IPv6).
/// - Link-local (169.254.0.0/16 for IPv4, fe80::/10 for IPv6).
/// - Unspecified (0.0.0.0, ::).
/// - Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
///
/// This is the CLIENT-SIDE early rejection. The GATEWAY performs the
/// authoritative SSRF defence (see `gateway_stream.rs::is_private_ip_str`).
/// Both checks exist for defence-in-depth.
#[must_use]
pub fn is_routable_internet_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_routable_ipv4(v4),
        IpAddr::V6(v6) => is_routable_ipv6(v6),
    }
}

/// Check if an IPv4 address is a routable Internet address (not private).
#[must_use]
fn is_routable_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    // Unspecified (0.0.0.0)
    if addr.is_unspecified() {
        return false;
    }
    // Loopback (127.0.0.0/8)
    if addr.is_loopback() {
        return false;
    }
    // Private ranges (RFC 1918)
    if addr.is_private() {
        return false;
    }
    // Link-local (169.254.0.0/16)
    if addr.is_link_local() {
        return false;
    }
    // Documentation ranges (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return false;
    }
    true
}

/// Check if an IPv6 address is a routable Internet address (not private).
#[must_use]
fn is_routable_ipv6(addr: &Ipv6Addr) -> bool {
    // Unspecified (::)
    if addr.is_unspecified() {
        return false;
    }
    // Loopback (::1)
    if addr.is_loopback() {
        return false;
    }
    // Link-local (fe80::/10) — N3-B Step 4 FIX: was checking is_loopback()
    // twice instead of checking for link-local. This is the bug the user
    // identified: the documentation claimed link-local addresses were
    // rejected, but the code checked is_loopback() a second time.
    //
    // Rust std::net::Ipv6Addr does not have is_unicast_link_local() until
    // Rust 1.83+. We check manually: fe80::/10 means the first 10 bits are
    // 1111111010, i.e. segment[0] & 0xFFC0 == 0xFE80.
    let segments = addr.segments();
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return false;
    }
    // Unique local addresses (fc00::/7) — RFC 4193
    if (segments[0] & 0xFE00) == 0xFC00 {
        return false;
    }
    true
}

/// Validate that a destination is a routable Internet TCP endpoint.
///
/// Returns `Ok(())` if the destination is routable, or an `Err` with a
/// descriptive message if it is private/loopback/link-local.
///
/// # Arguments
/// * `ip` — The destination IP address.
/// * `port` — The destination TCP port.
#[must_use]
pub fn validate_destination(ip: &IpAddr, port: u16) -> Result<(), String> {
    if port == 0 {
        return Err(format!("destination port 0 is invalid"));
    }
    if !is_routable_internet_address(ip) {
        return Err(format!(
            "destination {ip} is private/loopback/link-local — rejected client-side (gateway SSRF defence is authoritative)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flow_key(src: &str, dst: &str, src_port: u16, dst_port: u16, protocol: u8) -> FlowKey {
        FlowKey {
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port,
            dst_port,
            protocol,
        }
    }

    #[test]
    fn is_tcp_syn_detects_pure_syn() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "93.184.216.34", 52344, 443, PROTO_TCP),
            tcp_flags: Some(TcpFlags::from_byte(0x02)), // SYN only
        };
        assert!(is_tcp_syn(&meta));
    }

    #[test]
    fn is_tcp_syn_rejects_syn_ack() {
        let meta = FlowMetadata {
            key: make_flow_key("93.184.216.34", "10.0.0.2", 443, 52344, PROTO_TCP),
            tcp_flags: Some(TcpFlags::from_byte(0x12)), // SYN+ACK
        };
        assert!(!is_tcp_syn(&meta));
    }

    #[test]
    fn is_tcp_syn_rejects_ack() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "93.184.216.34", 52344, 443, PROTO_TCP),
            tcp_flags: Some(TcpFlags::from_byte(0x10)), // ACK only
        };
        assert!(!is_tcp_syn(&meta));
    }

    #[test]
    fn is_tcp_syn_rejects_fin() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "93.184.216.34", 52344, 443, PROTO_TCP),
            tcp_flags: Some(TcpFlags::from_byte(0x01)), // FIN only
        };
        assert!(!is_tcp_syn(&meta));
    }

    #[test]
    fn is_tcp_syn_rejects_udp() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "8.8.8.8", 53535, 53, 17), // UDP
            tcp_flags: None,
        };
        assert!(!is_tcp_syn(&meta));
    }

    #[test]
    fn tcp_destination_extracts_dst_ip_and_port() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "93.184.216.34", 52344, 443, PROTO_TCP),
            tcp_flags: Some(TcpFlags::from_byte(0x02)),
        };
        let dst = tcp_destination(&meta).unwrap();
        assert_eq!(dst.0, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(dst.1, 443);
    }

    #[test]
    fn tcp_destination_returns_none_for_udp() {
        let meta = FlowMetadata {
            key: make_flow_key("10.0.0.2", "8.8.8.8", 53535, 53, 17),
            tcp_flags: None,
        };
        assert!(tcp_destination(&meta).is_none());
    }

    // ─── Destination validation tests ────────────────────────────────────────

    #[test]
    fn validate_destination_accepts_routable_ipv4() {
        assert!(validate_destination(&"93.184.216.34".parse().unwrap(), 443).is_ok());
        assert!(validate_destination(&"8.8.8.8".parse().unwrap(), 53).is_ok());
        assert!(validate_destination(&"1.1.1.1".parse().unwrap(), 443).is_ok());
    }

    #[test]
    fn validate_destination_rejects_private_10() {
        let result = validate_destination(&"10.0.0.1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn validate_destination_rejects_private_172_16() {
        let result = validate_destination(&"172.16.0.1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn validate_destination_rejects_private_192_168() {
        let result = validate_destination(&"192.168.1.1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn validate_destination_rejects_loopback() {
        let result = validate_destination(&"127.0.0.1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn validate_destination_rejects_link_local() {
        let result = validate_destination(&"169.254.1.1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn validate_destination_rejects_unspecified() {
        let result = validate_destination(&"0.0.0.0".parse().unwrap(), 443);
        assert!(result.is_err());
    }

    #[test]
    fn validate_destination_rejects_port_zero() {
        let result = validate_destination(&"93.184.216.34".parse().unwrap(), 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("port 0"));
    }

    #[test]
    fn validate_destination_rejects_documentation_range() {
        // 192.0.2.0/24 (TEST-NET-1)
        assert!(validate_destination(&"192.0.2.1".parse().unwrap(), 443).is_err());
        // 198.51.100.0/24 (TEST-NET-2)
        assert!(validate_destination(&"198.51.100.1".parse().unwrap(), 443).is_err());
        // 203.0.113.0/24 (TEST-NET-3)
        assert!(validate_destination(&"203.0.113.1".parse().unwrap(), 443).is_err());
    }

    #[test]
    fn is_routable_accepts_real_internet_ips() {
        assert!(is_routable_internet_address(
            &"93.184.216.34".parse().unwrap()
        ));
        assert!(is_routable_internet_address(&"8.8.8.8".parse().unwrap()));
        assert!(is_routable_internet_address(&"1.1.1.1".parse().unwrap()));
        assert!(is_routable_internet_address(
            &"140.82.121.4".parse().unwrap()
        )); // github.com
    }

    #[test]
    fn is_routable_rejects_all_private_ranges() {
        assert!(!is_routable_internet_address(&"10.0.0.1".parse().unwrap()));
        assert!(!is_routable_internet_address(
            &"10.255.255.255".parse().unwrap()
        ));
        assert!(!is_routable_internet_address(
            &"172.16.0.1".parse().unwrap()
        ));
        assert!(!is_routable_internet_address(
            &"172.31.255.255".parse().unwrap()
        ));
        assert!(!is_routable_internet_address(
            &"192.168.0.1".parse().unwrap()
        ));
        assert!(!is_routable_internet_address(
            &"192.168.255.255".parse().unwrap()
        ));
    }

    // ─── IPv6 validation tests (N3-B Step 4) ─────────────────────────────────

    #[test]
    fn validate_destination_rejects_ipv6_loopback() {
        // ::1
        let result = validate_destination(&"::1".parse().unwrap(), 443);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("private"),
            "loopback ::1 must be rejected"
        );
    }

    #[test]
    fn validate_destination_rejects_ipv6_unspecified() {
        // ::
        let result = validate_destination(&"::".parse().unwrap(), 443);
        assert!(result.is_err());
    }

    #[test]
    fn validate_destination_rejects_ipv6_link_local() {
        // fe80::/10 — the bug the user identified: was NOT rejected before
        // because is_routable_ipv6() checked is_loopback() twice instead of
        // checking for link-local.
        let result = validate_destination(&"fe80::1".parse().unwrap(), 443);
        assert!(
            result.is_err(),
            "fe80::1 (link-local) MUST be rejected — this was the N3-B Step 4 bug"
        );
        assert!(result.unwrap_err().contains("private"));

        // fe80::1234:5678
        let result = validate_destination(&"fe80::1234:5678".parse().unwrap(), 443);
        assert!(
            result.is_err(),
            "fe80::1234:5678 (link-local) MUST be rejected"
        );

        // febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff (last address in fe80::/10)
        let result = validate_destination(
            &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            443,
        );
        assert!(result.is_err(), "febf::/10 (link-local) MUST be rejected");
    }

    #[test]
    fn validate_destination_rejects_ipv6_unique_local() {
        // fc00::/7 (RFC 4193 unique local addresses)
        let result = validate_destination(&"fc00::1".parse().unwrap(), 443);
        assert!(result.is_err(), "fc00::1 (ULA) MUST be rejected");

        let result = validate_destination(&"fd00::1".parse().unwrap(), 443);
        assert!(result.is_err(), "fd00::1 (ULA) MUST be rejected");

        let result = validate_destination(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            443,
        );
        assert!(result.is_err(), "fdff::/7 (ULA) MUST be rejected");
    }

    #[test]
    fn validate_destination_accepts_public_ipv6() {
        // 2606:4700:4700::1111 (Cloudflare DNS)
        assert!(validate_destination(&"2606:4700:4700::1111".parse().unwrap(), 443).is_ok());
        // 2001:4860:4860::8888 (Google DNS)
        assert!(validate_destination(&"2001:4860:4860::8888".parse().unwrap(), 443).is_ok());
        // 2607:f8b0:4004:800::200e (google.com)
        assert!(validate_destination(&"2607:f8b0:4004:800::200e".parse().unwrap(), 443).is_ok());
    }

    #[test]
    fn is_routable_ipv6_rejects_link_local() {
        // This is the regression test for the N3-B Step 4 bug.
        assert!(!is_routable_internet_address(&"fe80::1".parse().unwrap()));
        assert!(!is_routable_internet_address(
            &"fe80::1234:5678".parse().unwrap()
        ));
        assert!(!is_routable_internet_address(
            &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn is_routable_ipv6_rejects_unique_local() {
        assert!(!is_routable_internet_address(&"fc00::1".parse().unwrap()));
        assert!(!is_routable_internet_address(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn is_routable_ipv6_rejects_loopback() {
        assert!(!is_routable_internet_address(&"::1".parse().unwrap()));
    }

    #[test]
    fn is_routable_ipv6_rejects_unspecified() {
        assert!(!is_routable_internet_address(&"::".parse().unwrap()));
    }

    #[test]
    fn is_routable_ipv6_accepts_public() {
        assert!(is_routable_internet_address(
            &"2606:4700:4700::1111".parse().unwrap()
        ));
        assert!(is_routable_internet_address(
            &"2001:4860:4860::8888".parse().unwrap()
        ));
    }

    // ─── Full extraction from raw IP packet ───────────────────────────────────

    #[test]
    fn extract_flow_from_real_syn_packet() {
        // Build a minimal IPv4 TCP SYN packet:
        // - src: 10.0.0.2:52344
        // - dst: 93.184.216.34:443
        // - flags: SYN (0x02)
        let mut packet_bytes = vec![0u8; 40]; // 20 IP header + 20 TCP header

        // IPv4 header
        packet_bytes[0] = 0x45; // version=4, IHL=5
        packet_bytes[2] = 0x00;
        packet_bytes[3] = 0x28; // total length = 40
        packet_bytes[9] = PROTO_TCP; // protocol = TCP
                                     // src IP: 10.0.0.2
        packet_bytes[12] = 10;
        packet_bytes[13] = 0;
        packet_bytes[14] = 0;
        packet_bytes[15] = 2;
        // dst IP: 93.184.216.34
        packet_bytes[16] = 93;
        packet_bytes[17] = 184;
        packet_bytes[18] = 216;
        packet_bytes[19] = 34;

        // TCP header
        // src port: 52344 = 0xCCB8
        packet_bytes[20] = 0xCC;
        packet_bytes[21] = 0xB8;
        // dst port: 443 = 0x01BB
        packet_bytes[22] = 0x01;
        packet_bytes[23] = 0xBB;
        // data offset = 5 (20 bytes), flags = SYN (0x02)
        packet_bytes[32] = 0x50; // data offset = 5
        packet_bytes[33] = 0x02; // SYN

        let packet = IpPacket::parse(&packet_bytes).expect("packet must parse");
        let meta = extract_flow(&packet).expect("flow must extract");

        assert_eq!(meta.key.src_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(meta.key.dst_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(meta.key.src_port, 52408); // 0xCCB8
        assert_eq!(meta.key.dst_port, 443);
        assert_eq!(meta.key.protocol, PROTO_TCP);
        assert!(is_tcp_syn(&meta));

        let dst = tcp_destination(&meta).unwrap();
        assert_eq!(dst.0, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(dst.1, 443);

        assert!(validate_destination(&dst.0, dst.1).is_ok());
    }

    #[test]
    fn extract_flow_from_syn_to_private_destination() {
        // SYN to 10.0.0.1 (private) — should extract but fail validation.
        let mut packet_bytes = vec![0u8; 40];
        packet_bytes[0] = 0x45;
        packet_bytes[2] = 0x00;
        packet_bytes[3] = 0x28; // total length = 40
        packet_bytes[9] = PROTO_TCP;
        packet_bytes[12] = 10;
        packet_bytes[13] = 0;
        packet_bytes[14] = 0;
        packet_bytes[15] = 2; // src: 10.0.0.2
        packet_bytes[16] = 10;
        packet_bytes[17] = 0;
        packet_bytes[18] = 0;
        packet_bytes[19] = 1; // dst: 10.0.0.1 (private)
        packet_bytes[22] = 0x01;
        packet_bytes[23] = 0xBB; // dst port 443
        packet_bytes[32] = 0x50;
        packet_bytes[33] = 0x02; // SYN

        let packet = IpPacket::parse(&packet_bytes).expect("packet must parse");
        let meta = extract_flow(&packet).expect("flow must extract");
        assert!(is_tcp_syn(&meta));

        let dst = tcp_destination(&meta).unwrap();
        assert!(validate_destination(&dst.0, dst.1).is_err());
    }

    #[test]
    fn extract_flow_returns_none_for_icmp() {
        // ICMP packet — protocol = 1, no TCP/UDP header.
        let mut packet_bytes = vec![0u8; 28]; // 20 IP + 8 ICMP
        packet_bytes[0] = 0x45;
        packet_bytes[2] = 0x00;
        packet_bytes[3] = 0x1C; // total length = 28
        packet_bytes[9] = 1; // ICMP
        packet_bytes[12] = 10;
        packet_bytes[13] = 0;
        packet_bytes[14] = 0;
        packet_bytes[15] = 1;
        packet_bytes[16] = 10;
        packet_bytes[17] = 0;
        packet_bytes[18] = 0;
        packet_bytes[19] = 2;

        let packet = IpPacket::parse(&packet_bytes).expect("packet must parse");
        assert!(extract_flow(&packet).is_none());
    }

    #[test]
    fn extract_flow_returns_none_for_truncated_tcp() {
        // IP packet with only 10 bytes of TCP header (truncated).
        let mut packet_bytes = vec![0u8; 30]; // 20 IP + 10 (truncated TCP)
        packet_bytes[0] = 0x45;
        packet_bytes[2] = 0x00;
        packet_bytes[3] = 0x1E; // total length = 30
        packet_bytes[9] = PROTO_TCP;
        packet_bytes[12] = 10;
        packet_bytes[13] = 0;
        packet_bytes[14] = 0;
        packet_bytes[15] = 1;
        packet_bytes[16] = 10;
        packet_bytes[17] = 0;
        packet_bytes[18] = 0;
        packet_bytes[19] = 2;

        let packet = IpPacket::parse(&packet_bytes).expect("packet must parse");
        // TCP header is truncated (only 10 bytes, need 20) → extract_flow returns None.
        assert!(extract_flow(&packet).is_none());
    }
}

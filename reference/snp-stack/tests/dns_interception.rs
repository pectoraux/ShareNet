//! N2.3.4 — Integration tests for DNS interception.
//!
//! These tests exercise the full DNS interception pipeline:
//!
//! 1. Build a raw DNS query IP packet (UDP, port 53).
//! 2. Call [`intercept_dns_query`] to parse + resolve + generate a response.
//! 3. Verify the response is a valid IP packet with swapped src/dst, correct
//!    DNS transaction ID, and the expected answer record.

#![allow(clippy::pedantic)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use snp_stack::{
    intercept_dns_query, is_dns_query, parse_dns_query, DnsQclass, DnsQtype, DnsResolver,
    DnsResponse, DNS_PORT,
};
use snp_tun::{build_test_ipv4_packet, build_test_ipv6_packet, IpPacket};

/// DNS QTYPE values we use in tests.
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// Build a DNS query payload (header + question) for the given domain + QTYPE.
fn build_dns_query_payload(transaction_id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    // Header (12 bytes).
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question: QNAME (label-length-prefixed) + QTYPE + QCLASS.
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // Root label.
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    query
}

/// Build a complete IPv4 UDP DNS query packet.
fn build_ipv4_dns_query(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    transaction_id: u16,
    domain: &str,
    qtype: u16,
) -> IpPacket {
    let dns_payload = build_dns_query_payload(transaction_id, domain, qtype);
    let mut udp = vec![0u8; 8];
    udp[0] = (src_port >> 8) as u8;
    udp[1] = src_port as u8;
    udp[2] = 0;
    udp[3] = DNS_PORT as u8; // dst port 53
    let udp_len = 8 + dns_payload.len();
    udp[4] = (udp_len >> 8) as u8;
    udp[5] = udp_len as u8;
    udp.extend_from_slice(&dns_payload);
    let raw = build_test_ipv4_packet(src_ip, dst_ip, 17, &udp); // 17 = UDP
    IpPacket::parse(&raw).unwrap()
}

/// Build a complete IPv6 UDP DNS query packet.
fn build_ipv6_dns_query(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    transaction_id: u16,
    domain: &str,
    qtype: u16,
) -> IpPacket {
    let dns_payload = build_dns_query_payload(transaction_id, domain, qtype);
    let mut udp = vec![0u8; 8];
    udp[0] = (src_port >> 8) as u8;
    udp[1] = src_port as u8;
    udp[2] = 0;
    udp[3] = DNS_PORT as u8;
    let udp_len = 8 + dns_payload.len();
    udp[4] = (udp_len >> 8) as u8;
    udp[5] = udp_len as u8;
    udp.extend_from_slice(&dns_payload);
    let raw = build_test_ipv6_packet(src_ip, dst_ip, 17, &udp);
    IpPacket::parse(&raw).unwrap()
}

/// Extract the DNS payload from a response packet (src_port == 53).
fn extract_response_dns(packet: &IpPacket) -> Vec<u8> {
    use snp_stack::{parse_transport, TransportHeader};
    let transport = parse_transport(packet).unwrap().unwrap();
    let udp = match transport {
        TransportHeader::Udp(u) => u,
        _ => panic!("expected UDP"),
    };
    assert_eq!(udp.src_port, DNS_PORT, "response src_port must be 53");
    // Get the transport payload (after IP header).
    let bytes = packet.as_bytes();
    let payload_start = match packet {
        IpPacket::IPv4(_) => ((bytes[0] & 0x0f) as usize) * 4,
        IpPacket::IPv6(_) => 40,
    };
    bytes[payload_start + 8..].to_vec()
}

// ════════════════════════════════════════════════════════════════════════════
// DNS query parsing tests
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn parse_dns_query_a_record() {
    let payload = build_dns_query_payload(0xABCD, "example.com", QTYPE_A);
    let query = parse_dns_query(&payload).expect("parse must succeed");

    assert_eq!(query.transaction_id, 0xABCD);
    assert!(query.is_query());
    assert!(query.recursion_desired());
    assert_eq!(query.questions.len(), 1);
    assert_eq!(query.questions[0].qname, "example.com");
    assert_eq!(query.questions[0].qtype, DnsQtype::A);
    assert_eq!(query.questions[0].qclass, DnsQclass::IN);
}

#[test]
fn parse_dns_query_aaaa_record() {
    let payload = build_dns_query_payload(0x1234, "ipv6.example.com", QTYPE_AAAA);
    let query = parse_dns_query(&payload).expect("parse");

    assert_eq!(query.questions[0].qtype, DnsQtype::Aaaa);
    assert_eq!(query.questions[0].qname, "ipv6.example.com");
}

#[test]
fn parse_dns_query_multi_label() {
    let payload = build_dns_query_payload(0x0001, "a.b.c.d.example.com", QTYPE_A);
    let query = parse_dns_query(&payload).expect("parse");
    assert_eq!(query.questions[0].qname, "a.b.c.d.example.com");
}

// ════════════════════════════════════════════════════════════════════════════
// DNS detection tests
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn is_dns_query_detects_udp_53() {
    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        53535,
        0x1234,
        "example.com",
        QTYPE_A,
    );
    assert!(is_dns_query(&packet).expect("is_dns_query"));
}

#[test]
fn is_dns_query_rejects_non_53_port() {
    // Build a UDP packet to port 80 (not DNS).
    let mut udp = vec![0u8; 8];
    udp[2] = 0;
    udp[3] = 80;
    let raw = build_test_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        17,
        &udp,
    );
    let packet = IpPacket::parse(&raw).unwrap();
    assert!(!is_dns_query(&packet).expect("is_dns_query"));
}

// ════════════════════════════════════════════════════════════════════════════
// DNS response generation tests
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dns_a_response_has_correct_ip() {
    let mut resolver = DnsResolver::new();
    let expected_ip = Ipv4Addr::new(93, 184, 216, 34);
    resolver.add_mapping("example.com", IpAddr::V4(expected_ip));

    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0x1234,
        "example.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("must return response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("response must parse as IP");

    // Verify swapped addresses.
    assert_eq!(
        resp_packet.metadata().source,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(
        resp_packet.metadata().destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );

    // Verify the DNS response has the A record.
    let dns = extract_response_dns(&resp_packet);
    let txn = u16::from_be_bytes([dns[0], dns[1]]);
    assert_eq!(txn, 0x1234);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 1, "must have 1 answer");
    // The last 4 bytes of the DNS payload are the A record RDATA (IPv4).
    let rdata = &dns[dns.len() - 4..];
    assert_eq!(rdata, &expected_ip.octets());
}

#[test]
fn dns_aaaa_response_has_correct_ipv6() {
    let mut resolver = DnsResolver::new();
    let expected_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    resolver.add_mapping("ipv6.example.com", IpAddr::V6(expected_ip));

    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0x5678,
        "ipv6.example.com",
        QTYPE_AAAA,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    let dns = extract_response_dns(&resp_packet);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 1);
    // The last 16 bytes are the AAAA record RDATA (IPv6).
    let rdata = &dns[dns.len() - 16..];
    assert_eq!(rdata, &expected_ip.octets());
}

#[test]
fn dns_nxdomain_for_unmapped_domain() {
    let resolver = DnsResolver::new(); // No mappings.

    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0x9999,
        "nonexistent.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    let dns = extract_response_dns(&resp_packet);
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    assert_eq!(flags & 0x000f, 3, "RCODE must be 3 (NXDOMAIN)");
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 0, "NXDOMAIN must have 0 answers");
}

#[test]
fn dns_a_query_with_only_ipv6_mapping_returns_nxdomain() {
    let mut resolver = DnsResolver::new();
    resolver.add_mapping(
        "dual.example.com",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    );

    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0x1111,
        "dual.example.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    let dns = extract_response_dns(&resp_packet);
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    assert_eq!(flags & 0x000f, 3, "A query with only IPv6 → NXDOMAIN");
}

#[test]
fn dns_response_transaction_id_matches_query() {
    let mut resolver = DnsResolver::new();
    resolver.add_mapping("example.com", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    let txn_id = 0xBEEF;
    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        txn_id,
        "example.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    let dns = extract_response_dns(&resp_packet);
    let resp_txn = u16::from_be_bytes([dns[0], dns[1]]);
    assert_eq!(resp_txn, txn_id, "transaction ID must match the query");
}

#[test]
fn dns_response_swaps_src_dst_ports() {
    let mut resolver = DnsResolver::new();
    resolver.add_mapping("example.com", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    let client_port = 52344;
    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        client_port,
        0x1234,
        "example.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    use snp_stack::{parse_transport, TransportHeader};
    let transport = parse_transport(&resp_packet).unwrap().unwrap();
    match transport {
        TransportHeader::Udp(udp) => {
            assert_eq!(udp.src_port, DNS_PORT, "response src_port must be 53");
            assert_eq!(
                udp.dst_port, client_port,
                "response dst_port must be the client's source port"
            );
        }
        _ => panic!("expected UDP"),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// IPv6 DNS interception
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dns_intercept_ipv6_query() {
    let mut resolver = DnsResolver::new();
    let expected_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
    resolver.add_mapping("ipv6.test", IpAddr::V6(expected_ip));

    let packet = build_ipv6_dns_query(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        53535,
        0x4321,
        "ipv6.test",
        QTYPE_AAAA,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");

    // Verify swapped IPv6 addresses.
    assert_eq!(
        resp_packet.metadata().source,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(
        resp_packet.metadata().destination,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
    );

    let dns = extract_response_dns(&resp_packet);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 1);
    let rdata = &dns[dns.len() - 16..];
    assert_eq!(rdata, &expected_ip.octets());
}

// ════════════════════════════════════════════════════════════════════════════
// Case-insensitive resolution
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dns_resolution_is_case_insensitive() {
    let mut resolver = DnsResolver::new();
    resolver.add_mapping("Example.COM", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    // Query with lowercase.
    let packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0x2222,
        "example.com",
        QTYPE_A,
    );

    let response_bytes = intercept_dns_query(&packet, &resolver)
        .expect("intercept")
        .expect("response");
    let resp_packet = IpPacket::parse(&response_bytes).expect("parse");
    let dns = extract_response_dns(&resp_packet);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 1, "case-insensitive lookup must succeed");
}

// ════════════════════════════════════════════════════════════════════════════
// Multiple mappings
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn dns_resolver_multiple_mappings() {
    let mut mappings = HashMap::new();
    mappings.insert("a.test".to_string(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
    mappings.insert("b.test".to_string(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)));
    mappings.insert(
        "c.test".to_string(),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 30)),
    );
    let resolver = DnsResolver::with_mappings(mappings);

    assert_eq!(resolver.mapping_count(), 3);
    assert_eq!(
        resolver.resolve("a.test"),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)))
    );
    assert_eq!(
        resolver.resolve("b.test"),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)))
    );
    assert_eq!(
        resolver.resolve("c.test"),
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 30)))
    );
    assert_eq!(resolver.resolve("d.test"), None);
}

// ════════════════════════════════════════════════════════════════════════════
// Non-DNS packets are not intercepted
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn intercept_returns_none_for_non_dns_packet() {
    let resolver = DnsResolver::new();
    // Build a non-DNS UDP packet (port 80).
    let mut udp = vec![0u8; 8];
    udp[2] = 0;
    udp[3] = 80;
    let raw = build_test_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        17,
        &udp,
    );
    let packet = IpPacket::parse(&raw).unwrap();

    let result = intercept_dns_query(&packet, &resolver).expect("must not error");
    assert!(result.is_none(), "non-DNS packet must return None");
}

#[test]
fn intercept_returns_none_for_tcp_packet() {
    let resolver = DnsResolver::new();
    // Build a TCP packet (not UDP).
    let tcp = vec![0u8; 20];
    let raw = build_test_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        6, // TCP
        &tcp,
    );
    let packet = IpPacket::parse(&raw).unwrap();

    let result = intercept_dns_query(&packet, &resolver).expect("must not error");
    assert!(result.is_none(), "TCP packet must return None");
}

// ════════════════════════════════════════════════════════════════════════════
// End-to-end: query → intercept → response → verify (simulating the TUN loop)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn end_to_end_dns_interception_pipeline() {
    // Simulate the full pipeline:
    // 1. Application sends a DNS query (we build it as a raw IP packet).
    // 2. ShareNet intercepts it (intercept_dns_query).
    // 3. ShareNet generates a synthetic response.
    // 4. The response is written back to the TUN (we verify it parses).

    let mut resolver = DnsResolver::new();
    resolver.add_mapping("sharenet.example", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)));

    // 1. Application DNS query.
    let query_packet = build_ipv4_dns_query(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        52344,
        0xCAFE,
        "sharenet.example",
        QTYPE_A,
    );

    // 2. Intercept.
    let response_bytes = intercept_dns_query(&query_packet, &resolver)
        .expect("intercept must succeed")
        .expect("must return a response");

    // 3. The response must be a valid IP packet that can be written to TUN.
    let response_packet = IpPacket::parse(&response_bytes).expect("response must parse as IP");

    // 4. Verify the response.
    assert_eq!(response_packet.metadata().source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(
        response_packet.metadata().destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );

    let dns = extract_response_dns(&response_packet);
    let txn = u16::from_be_bytes([dns[0], dns[1]]);
    assert_eq!(txn, 0xCAFE, "transaction ID must match");
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    assert!((flags & 0x8000) != 0, "QR bit must be set (response)");
    assert_eq!(flags & 0x000f, 0, "RCODE must be 0 (no error)");
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    assert_eq!(ancount, 1, "must have 1 answer");
    let rdata = &dns[dns.len() - 4..];
    assert_eq!(rdata, &[10, 0, 0, 100], "A record must be 10.0.0.100");

    eprintln!(
        "[dns-e2e] PASS: DNS query for sharenet.example → response 10.0.0.100 \
         (txn=0x{:04x}, 1 answer)",
        txn
    );
}

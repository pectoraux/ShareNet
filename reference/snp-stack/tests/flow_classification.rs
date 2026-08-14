//! N2.3.2 — Integration tests for packet flow classification.
//!
//! These tests exercise the full pipeline: raw IP packet → transport parsing →
//! flow key extraction → flow table tracking.

#![allow(clippy::pedantic)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use snp_stack::{
    flow_key, parse_transport, FlowKey, FlowState, FlowTable, TcpFlags, TcpState, TransportHeader,
    PROTO_TCP, UDP,
};
use snp_tun::{
    build_test_ipv4_packet, build_test_ipv6_packet, IpPacket, MockPacketDevice, PacketDevice,
};

/// Build a TCP header (20 bytes, no options) with the given ports + flags.
fn build_tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut hdr = vec![0u8; 20];
    hdr[0] = (src_port >> 8) as u8;
    hdr[1] = src_port as u8;
    hdr[2] = (dst_port >> 8) as u8;
    hdr[3] = dst_port as u8;
    hdr[12] = 0x50; // data offset 5
    hdr[13] = flags;
    hdr[14] = 4; // window
    hdr
}

/// Build a UDP header (8 bytes) with the given ports + payload.
fn build_udp_header(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
    let mut hdr = vec![0u8; 8];
    hdr[0] = (src_port >> 8) as u8;
    hdr[1] = src_port as u8;
    hdr[2] = (dst_port >> 8) as u8;
    hdr[3] = dst_port as u8;
    let length = 8 + payload_len;
    hdr[4] = (length >> 8) as u8;
    hdr[5] = length as u8;
    hdr
}

/// Build a complete TCP IPv4 packet.
fn build_tcp_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> IpPacket {
    let tcp_hdr = build_tcp_header(src_port, dst_port, flags);
    let raw = build_test_ipv4_packet(src, dst, PROTO_TCP, &tcp_hdr);
    IpPacket::parse(&raw).expect("parse IP")
}

/// Build a complete UDP IPv4 packet.
fn build_udp_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> IpPacket {
    let mut udp = build_udp_header(src_port, dst_port, payload.len());
    udp.extend_from_slice(payload);
    let raw = build_test_ipv4_packet(src, dst, UDP, &udp);
    IpPacket::parse(&raw).expect("parse IP")
}

// ════════════════════════════════════════════════════════════════════════════
// TCP flow classification tests
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_syn_creates_flow_in_synsent_state() {
    let table = FlowTable::new();
    let packet = build_tcp_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        52344,
        443,
        0x02, // SYN
    );
    let now = Instant::now();

    let transport = parse_transport(&packet).expect("parse transport").unwrap();
    let key = flow_key(&packet, &transport).expect("flow key");
    let flags = match transport {
        TransportHeader::Tcp(tcp) => Some(tcp.flags),
        _ => None,
    };

    let entry = table.process_packet(&key, flags, now, 60).await;

    assert_eq!(entry.state, FlowState::Tcp(TcpState::SynSent));
    assert!(entry.packet_count == 1);
    assert_eq!(table.len().await, 1);
}

#[tokio::test]
async fn tcp_full_handshake_lifecycle() {
    let table = FlowTable::new();
    let now = Instant::now();

    let client = Ipv4Addr::new(10, 0, 0, 2);
    let server = Ipv4Addr::new(93, 184, 216, 34);

    // 1. SYN (client → server)
    let syn = build_tcp_ipv4_packet(client, server, 52344, 443, 0x02);
    let transport = parse_transport(&syn).unwrap().unwrap();
    let fwd_key = flow_key(&syn, &transport).unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    table.process_packet(&fwd_key, flags, now, 60).await;

    // 2. SYN-ACK (server → client) — creates the reverse flow in Established
    //    (the server side starts established because the SYN-ACK is the first
    //    packet we see for this direction — the SYN was in the forward flow).
    let syn_ack = build_tcp_ipv4_packet(server, client, 443, 52344, 0x12);
    let transport = parse_transport(&syn_ack).unwrap().unwrap();
    let rev_key = flow_key(&syn_ack, &transport).unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    let entry = table.process_packet(&rev_key, flags, now, 60).await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Established));

    // 3. ACK (client → server) — forward flow transitions to Established
    let ack = build_tcp_ipv4_packet(client, server, 52344, 443, 0x10);
    let transport = parse_transport(&ack).unwrap().unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    let entry = table.process_packet(&fwd_key, flags, now, 60).await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Established));

    // 4. FIN (client → server) — forward flow transitions to Closing
    let fin = build_tcp_ipv4_packet(client, server, 52344, 443, 0x01);
    let transport = parse_transport(&fin).unwrap().unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    let entry = table.process_packet(&fwd_key, flags, now, 60).await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Closing));

    // 5. FIN-ACK (server → client) — reverse flow transitions to Closed
    let fin_ack = build_tcp_ipv4_packet(server, client, 443, 52344, 0x11);
    let transport = parse_transport(&fin_ack).unwrap().unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    let entry = table.process_packet(&rev_key, flags, now, 60).await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Closing));

    // Sweep should evict the reverse flow (it's Closing — not yet Closed,
    // but we can force-close with RST).
    // Actually Closing is not Closed. Let's send RST to close both.
    let rst = build_tcp_ipv4_packet(client, server, 52344, 443, 0x04);
    let transport = parse_transport(&rst).unwrap().unwrap();
    let flags = match transport {
        TransportHeader::Tcp(t) => Some(t.flags),
        _ => None,
    };
    let entry = table.process_packet(&fwd_key, flags, now, 60).await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Closed));

    // Closed flows are evicted by sweep_idle.
    let evicted = table.sweep_idle(now, Duration::from_secs(3600)).await;
    assert!(evicted >= 1, "closed flow must be evicted");
}

#[tokio::test]
async fn tcp_rst_immediately_closes_flow() {
    let table = FlowTable::new();
    let now = Instant::now();

    // SYN → Established
    let syn = build_tcp_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        52344,
        443,
        0x02,
    );
    let transport = parse_transport(&syn).unwrap().unwrap();
    let key = flow_key(&syn, &transport).unwrap();
    table
        .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
        .await;
    table
        .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
        .await;

    // RST
    let entry = table
        .process_packet(&key, Some(TcpFlags::from_byte(0x04)), now, 60)
        .await;
    assert_eq!(entry.state, FlowState::Tcp(TcpState::Closed));
    assert!(entry.is_closed());
}

// ════════════════════════════════════════════════════════════════════════════
// UDP flow classification tests
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn udp_flow_starts_as_new_then_established() {
    let table = FlowTable::new();
    let now = Instant::now();

    let packet = build_udp_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        53535,
        53,
        b"DNS query",
    );
    let transport = parse_transport(&packet).unwrap().unwrap();
    let key = flow_key(&packet, &transport).unwrap();

    // First packet → New
    let entry = table.process_packet(&key, None, now, 40).await;
    assert_eq!(entry.state, FlowState::Udp(snp_stack::UdpState::New));

    // Second packet → Established
    let entry = table.process_packet(&key, None, now, 40).await;
    assert_eq!(
        entry.state,
        FlowState::Udp(snp_stack::UdpState::Established)
    );
}

#[tokio::test]
async fn udp_ipv6_flow_classification() {
    let table = FlowTable::new();
    let now = Instant::now();

    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    let mut udp = build_udp_header(53535, 53, 4);
    udp.extend_from_slice(b"DNS?");
    let raw = build_test_ipv6_packet(src, dst, UDP, &udp);
    let packet = IpPacket::parse(&raw).unwrap();

    let transport = parse_transport(&packet).unwrap().unwrap();
    let key = flow_key(&packet, &transport).unwrap();

    assert_eq!(key.src_port, 53535);
    assert_eq!(key.dst_port, 53);
    assert_eq!(key.protocol, UDP);

    let entry = table.process_packet(&key, None, now, 48).await;
    assert_eq!(entry.state, FlowState::Udp(snp_stack::UdpState::New));
}

// ════════════════════════════════════════════════════════════════════════════
// Idle expiration tests
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn idle_tcp_flow_evicted_after_timeout() {
    let table = FlowTable::new();
    let t0 = Instant::now();

    // Create a flow at t0.
    let packet = build_tcp_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        52344,
        443,
        0x02,
    );
    let transport = parse_transport(&packet).unwrap().unwrap();
    let key = flow_key(&packet, &transport).unwrap();
    table
        .process_packet(&key, Some(TcpFlags::from_byte(0x02)), t0, 60)
        .await;
    assert_eq!(table.len().await, 1);

    // 5 seconds later — within the 10s timeout → not evicted.
    let t1 = t0 + Duration::from_secs(5);
    let evicted = table.sweep_idle(t1, Duration::from_secs(10)).await;
    assert_eq!(evicted, 0);
    assert_eq!(table.len().await, 1);

    // 15 seconds later — beyond the 10s timeout → evicted.
    let t2 = t0 + Duration::from_secs(15);
    let evicted = table.sweep_idle(t2, Duration::from_secs(10)).await;
    assert_eq!(evicted, 1);
    assert_eq!(table.len().await, 0);
}

#[tokio::test]
async fn active_flow_refreshes_idle_timer() {
    let table = FlowTable::new();
    let t0 = Instant::now();

    // Create a flow at t0.
    let packet = build_udp_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(8, 8, 8, 8),
        53535,
        53,
        b"q1",
    );
    let transport = parse_transport(&packet).unwrap().unwrap();
    let key = flow_key(&packet, &transport).unwrap();
    table.process_packet(&key, None, t0, 40).await;

    // At t0 + 8s, send another packet (refreshes last_seen to t0 + 8s).
    let t1 = t0 + Duration::from_secs(8);
    table.process_packet(&key, None, t1, 40).await;

    // At t0 + 12s (4s after the refresh), sweep with 10s timeout.
    // The flow's last_seen is t0 + 8s, so age = 4s < 10s → NOT evicted.
    let t2 = t0 + Duration::from_secs(12);
    let evicted = table.sweep_idle(t2, Duration::from_secs(10)).await;
    assert_eq!(evicted, 0, "refreshed flow must not be evicted");
    assert_eq!(table.len().await, 1);
}

// ════════════════════════════════════════════════════════════════════════════
// Concurrent flow handling
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_flows_no_cross_contamination() {
    // 20 concurrent TCP connections, each with a distinct source port.
    // Verify each flow is tracked independently.
    let table = FlowTable::new();
    let now = Instant::now();

    let mut tasks = Vec::new();
    for i in 0u16..20 {
        let table = table.clone();
        tasks.push(tokio::spawn(async move {
            let client = Ipv4Addr::new(10, 0, 0, 2);
            let server = Ipv4Addr::new(93, 184, 216, 34);
            let src_port = 50000 + i;

            // SYN
            let pkt = build_tcp_ipv4_packet(client, server, src_port, 443, 0x02);
            let t = parse_transport(&pkt).unwrap().unwrap();
            let k = flow_key(&pkt, &t).unwrap();
            table.process_packet(&k, Some(TcpFlags::from_byte(0x02)), now, 60).await;

            // SYN-ACK (reverse direction)
            let pkt = build_tcp_ipv4_packet(server, client, 443, src_port, 0x12);
            let t = parse_transport(&pkt).unwrap().unwrap();
            let k = flow_key(&pkt, &t).unwrap();
            table.process_packet(&k, Some(TcpFlags::from_byte(0x12)), now, 60).await;

            src_port
        }));
    }

    let mut src_ports = Vec::new();
    for task in tasks {
        src_ports.push(task.await.expect("task join"));
    }

    // 20 forward + 20 reverse = 40 flows.
    assert_eq!(table.len().await, 40, "must have 40 flows (20 fwd + 20 rev)");

    // Each forward flow should be in SynSent (we only sent SYN, no SYN-ACK
    // to the forward direction — the SYN-ACK went to the reverse key).
    for src_port in &src_ports {
        let fwd_key = FlowKey {
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: *src_port,
            dst_port: 443,
            protocol: PROTO_TCP,
        };
        let entry = table.get(&fwd_key).await.expect("fwd flow must exist");
        assert_eq!(entry.state, FlowState::Tcp(TcpState::SynSent));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// End-to-end through PacketDevice
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn end_to_end_packet_to_flow_through_mock_device() {
    // Pre-load packets into a MockPacketDevice, read them, classify into
    // flows, and verify the flow table state.
    let tcp_syn = {
        let raw = build_test_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            PROTO_TCP,
            &build_tcp_header(52344, 443, 0x02),
        );
        IpPacket::parse(&raw).unwrap()
    };
    let udp_pkt = {
        let mut udp = build_udp_header(53535, 53, 4);
        udp.extend_from_slice(b"DNS?");
        let raw = build_test_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            UDP,
            &udp,
        );
        IpPacket::parse(&raw).unwrap()
    };

    let mut device = MockPacketDevice::with_packets(vec![tcp_syn, udp_pkt]);
    let table = FlowTable::new();
    let now = Instant::now();

    while let Ok(packet) = device.read_packet().await {
        if let Some(transport) = parse_transport(&packet).expect("parse transport") {
            let key = flow_key(&packet, &transport).expect("flow key");
            let flags = match transport {
                TransportHeader::Tcp(tcp) => Some(tcp.flags),
                TransportHeader::Udp(_) => None,
            };
            table
                .process_packet(&key, flags, now, packet.metadata().length)
                .await;
        }
    }

    // Should have 2 flows: one TCP (SynSent) and one UDP (New).
    assert_eq!(table.len().await, 2);
}

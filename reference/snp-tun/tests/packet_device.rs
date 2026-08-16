//! N2.3.1 — Integration tests for the TUN packet boundary.
//!
//! These tests exercise:
//! - `LinuxTunDevice` creation (privilege failure, name validation).
//! - `MockPacketDevice` concurrent read/write (no corruption).
//! - End-to-end packet flow through the `PacketDevice` trait.

#![allow(clippy::pedantic)]

use std::net::{Ipv4Addr, Ipv6Addr};

use snp_tun::{
    build_test_ipv4_packet, build_test_ipv6_packet, IpPacket, MockPacketDevice, PacketDevice,
    TunError,
};

// ════════════════════════════════════════════════════════════════════════════
// LinuxTunDevice creation tests (Linux only)
// ════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;
    use snp_tun::LinuxTunDevice;

    #[test]
    fn privilege_failure_returns_error_not_panic() {
        // This test verifies that TUN creation fails GRACEFULLY (returns an
        // error) when the process lacks CAP_NET_ADMIN or /dev/net/tun is not
        // accessible. It must NOT panic.
        //
        // In a privileged environment (root + CAP_NET_ADMIN + /dev/net/tun):
        //   → creation succeeds, we clean up, test is inconclusive but passes.
        // In an unprivileged environment:
        //   → PermissionDenied (EPERM/EACCES) or DeviceNotFound (ENOENT).
        // In a container without /dev/net/tun:
        //   → DeviceNotFound (ENOENT).
        match LinuxTunDevice::create("snp-test-priv") {
            Ok(_device) => {
                eprintln!(
                    "[tun-priv] NOTE: TUN creation succeeded — env is privileged \
                     (test inconclusive for permission path, but no panic = pass)"
                );
            }
            Err(TunError::PermissionDenied(msg)) => {
                eprintln!("[tun-priv] PASS: PermissionDenied returned: {msg}");
            }
            Err(TunError::DeviceNotFound(msg)) => {
                eprintln!("[tun-priv] PASS: DeviceNotFound returned: {msg}");
            }
            Err(other) => {
                // Any error is acceptable as long as we didn't panic.
                eprintln!(
                    "[tun-priv] PASS: error returned (not panic): {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn name_too_long_returns_error_not_panic() {
        // A TUN interface name must be <= 15 bytes (IFNAMSIZ - 1 = 15).
        // This test is DETERMINISTIC — it doesn't depend on TUN permissions.
        // The name-length check fires BEFORE opening /dev/net/tun.
        let long_name = "a".repeat(16);
        let result = LinuxTunDevice::create(&long_name);
        assert!(
            matches!(result, Err(TunError::NameTooLong(_))),
            "name > 15 bytes must return NameTooLong, got {:?}",
            result
        );
        eprintln!("[tun-name] PASS: 16-byte name rejected with NameTooLong");

        // 15-byte name should pass the length check (it may fail later due
        // to permissions, but NOT with NameTooLong).
        let ok_name = "b".repeat(15);
        let result = LinuxTunDevice::create(&ok_name);
        match result {
            Ok(_) => eprintln!("[tun-name] PASS: 15-byte name accepted (privileged env)"),
            Err(TunError::NameTooLong(_)) => {
                panic!("15-byte name must NOT be rejected with NameTooLong")
            }
            Err(_) => {
                eprintln!("[tun-name] PASS: 15-byte name passed length check (failed on permissions/device — expected in unprivileged env)")
            }
        }
    }

    #[test]
    fn empty_name_is_accepted_by_length_check() {
        // An empty name ("" ) tells the kernel to auto-assign (e.g. "tun0").
        // This must pass the length check (it may fail on permissions, but
        // NOT with NameTooLong).
        let result = LinuxTunDevice::create("");
        match result {
            Ok(_) => eprintln!("[tun-empty] PASS: empty name accepted (privileged env)"),
            Err(TunError::NameTooLong(_)) => {
                panic!("empty name must NOT be rejected with NameTooLong")
            }
            Err(_) => {
                eprintln!("[tun-empty] PASS: empty name passed length check (failed on permissions/device — expected in unprivileged env)")
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MockPacketDevice tests (all platforms)
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn mock_device_packet_roundtrip_ipv4() {
    let src = Ipv4Addr::new(10, 0, 0, 2);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    let raw = build_test_ipv4_packet(src, dst, 6, b"hello world");
    let packet = IpPacket::parse(&raw).expect("parse");

    let mut device = MockPacketDevice::with_packets(vec![packet.clone()]);
    let read = device.read_packet().await.expect("read");
    assert_eq!(read, packet);
    assert_eq!(read.metadata().source, std::net::IpAddr::V4(src));
    assert_eq!(read.metadata().destination, std::net::IpAddr::V4(dst));
    assert_eq!(read.metadata().protocol, 6);
    assert_eq!(read.metadata().length, 31); // 20 header + 11 payload
}

#[tokio::test]
async fn mock_device_packet_roundtrip_ipv6() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let raw = build_test_ipv6_packet(src, dst, 17, b"ipv6 payload");
    let packet = IpPacket::parse(&raw).expect("parse");

    let mut device = MockPacketDevice::with_packets(vec![packet.clone()]);
    let read = device.read_packet().await.expect("read");
    assert_eq!(read, packet);
    assert_eq!(read.metadata().source, std::net::IpAddr::V6(src));
    assert_eq!(read.metadata().destination, std::net::IpAddr::V6(dst));
    assert_eq!(read.metadata().protocol, 17);
    assert_eq!(read.metadata().length, 52); // 40 header + 12 payload ("ipv6 payload")
}

#[tokio::test]
async fn mock_device_write_and_inspect() {
    let mut device = MockPacketDevice::new();

    let raw1 = build_test_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        6,
        b"first",
    );
    let packet1 = IpPacket::parse(&raw1).expect("parse");

    let raw2 = build_test_ipv4_packet(
        Ipv4Addr::new(10, 0, 0, 3),
        Ipv4Addr::new(10, 0, 0, 4),
        17,
        b"second",
    );
    let packet2 = IpPacket::parse(&raw2).expect("parse");

    device.write_packet(packet1.clone()).await.expect("write 1");
    device.write_packet(packet2.clone()).await.expect("write 2");

    let written = device.written_packets().await;
    assert_eq!(written.len(), 2);
    assert_eq!(written[0], packet1);
    assert_eq!(written[1], packet2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_packet_handling_no_corruption() {
    // Pre-load 20 distinct IPv4 packets with unique source IPs.
    let mut packets = Vec::new();
    for i in 0u8..20 {
        let raw = build_test_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, i),
            Ipv4Addr::new(93, 184, 216, 34),
            6,
            &[i; 1],
        );
        packets.push(IpPacket::parse(&raw).expect("parse"));
    }
    let device = MockPacketDevice::with_packets(packets.clone());

    // Spawn 10 concurrent readers, each reading up to 4 packets.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let mut dev = device.clone();
        tasks.push(tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..4 {
                match dev.read_packet().await {
                    Ok(p) => received.push(p),
                    Err(TunError::Closed) => break,
                    Err(e) => panic!("unexpected error: {e:?}"),
                }
            }
            received
        }));
    }

    // Collect all received packets.
    let mut all_received = Vec::new();
    for task in tasks {
        let received = task.await.expect("task join");
        all_received.extend(received);
    }

    // Verify all 20 packets were read exactly once (no duplication, no loss).
    assert_eq!(
        all_received.len(),
        20,
        "must read exactly 20 packets (no loss)"
    );
    for packet in &packets {
        let count = all_received.iter().filter(|p| **p == *packet).count();
        assert_eq!(
            count, 1,
            "each packet must be read exactly once (no duplication)"
        );
    }
    eprintln!(
        "[tun-concurrent] PASS: 20 packets read by 10 concurrent readers — no corruption"
    );
}

#[tokio::test]
async fn mock_device_closed_when_empty() {
    let mut device = MockPacketDevice::new();
    let result = device.read_packet().await;
    assert!(
        matches!(result, Err(TunError::Closed)),
        "read from empty mock must return Closed, got {:?}",
        result
    );
}

#[tokio::test]
async fn ip_packet_through_mock_device_full_roundtrip() {
    // End-to-end: parse → pre-load → read → write → verify (through the
    // trait, not directly accessing the packet).
    //
    // The MockPacketDevice separates reads (from the `pending` queue) and
    // writes (to the `written` buffer). This test exercises both paths:
    // 1. Pre-load a packet → read it back (read path).
    // 2. Write a packet → inspect written_packets (write path).
    let src = Ipv4Addr::new(192, 168, 1, 100);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let raw = build_test_ipv4_packet(src, dst, 17, b"DNS query");
    let original = IpPacket::parse(&raw).expect("parse");

    // 1. Read path: pre-load the packet, read it back.
    let mut device = MockPacketDevice::with_packets(vec![original.clone()]);
    let read = device.read_packet().await.expect("read");

    // Verify the packet metadata.
    assert_eq!(read.metadata().source, std::net::IpAddr::V4(src));
    assert_eq!(read.metadata().destination, std::net::IpAddr::V4(dst));
    assert_eq!(read.metadata().protocol, 17);
    assert_eq!(read.metadata().length, 29); // 20 header + 9 payload

    // Verify the raw bytes are preserved.
    assert_eq!(read.as_bytes(), original.as_bytes());

    // 2. Write path: write a packet, verify it's stored.
    let raw2 = build_test_ipv4_packet(dst, src, 6, b"response");
    let response = IpPacket::parse(&raw2).expect("parse");
    device.write_packet(response.clone()).await.expect("write");
    let written = device.written_packets().await;
    assert_eq!(written.len(), 1);
    assert_eq!(written[0], response);
}

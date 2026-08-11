//! N1.8 integration test — full Client → Relay → Gateway → real-Internet round-trip.
//!
//! This is the central thesis proof for the Rust minimal Internet bridge.
//! It spawns the gateway and relay in threads (on ephemeral ports), then
//! runs the client in the test thread. The client:
//!
//! 1. Builds a TransitRequest for `https://example.com/`.
//! 2. Signs it with the client's Ed25519 key.
//! 3. Wraps it in a Class B SNP frame, AEAD-encrypts it, sends to the relay.
//! 4. The relay forwards the encrypted blob to the gateway (NEVER decrypts — I8).
//! 5. The gateway decrypts, validates SSRF, resolves DNS, fetches the URL
//!    over real HTTPS, signs the TransitResponse.
//! 6. The relay forwards the encrypted response back to the client.
//! 7. The client decrypts, verifies the gateway's Ed25519 signature.
//!
//! Assertions:
//! - `success == true` — the round-trip completed without error
//! - `status == 200` — example.com returned HTTP 200
//! - `gateway_verified == true` — the client verified the gateway's signature
//!
//! The `mesh_demo_round_trip_real_internet` test requires real Internet
//! access (it fetches example.com over HTTPS). It is therefore marked
//! `ignore` by default — run with
//! `cargo test -p snp-node --test integration -- --ignored`.
//!
//! The `gateway_rejects_private_destinations` test does NOT require Internet
//! access — it asserts the SSRF defence rejects every private-IP literal
//! before any DNS resolution or fetch attempt.

#![allow(clippy::pedantic)]

use std::time::Duration;

use snp_gateway::{handle_transit_request, GatewayError, TransitRequest};

#[test]
fn gateway_rejects_private_destinations() {
    // SSRF defence (I18) — every private/loopback/link-local/multicast
    // destination MUST be rejected BEFORE any DNS or HTTP call.
    let gateway_sk = [42u8; 32];
    let private_urls = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.5.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://metadata.google.internal/",
    ];
    for url in &private_urls {
        let req = TransitRequest {
            req_id: [1u8; 16],
            method: "GET".into(),
            url: url.to_string(),
            tls_termination: "GATEWAY_PLAINTEXT".into(),
            max_response_bytes: 1024,
            deadline: 2_000_000_000,
            reply_to: [0u8; 32],
            client_sig: [0u8; 64],
        };
        let result = handle_transit_request(&req, &gateway_sk);
        match result {
            Ok(_) => panic!("SSRF defence failed: {url} should have been blocked"),
            Err(GatewayError::EgressBlocked(reason)) => {
                println!("OK blocked: {url} — {reason}");
            }
            Err(e) => panic!("unexpected error for {url}: {e:?} (expected EgressBlocked)"),
        }
    }
}

#[test]
#[ignore = "requires Internet access (fetches https://example.com/ over HTTPS)"]
fn mesh_demo_round_trip_real_internet() {
    // Spawn the gateway + relay + client the same way run_mesh_demo does.
    // We can't call run_mesh_demo directly because it prints to stdout and
    // exits the process on success; instead we replicate its wiring so we
    // can assert on the (status, verified) tuple.
    let gateway_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let relay_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    drop(gateway_listener);
    drop(relay_listener);

    let gateway_addr_str = gateway_addr.to_string();
    let gw_handle = std::thread::spawn(move || {
        let _ = snp_node::run_gateway(&gateway_addr_str);
    });

    std::thread::sleep(Duration::from_millis(150));

    let gateway_addr_for_relay = gateway_addr.to_string();
    let relay_addr_str = relay_addr.to_string();
    let relay_handle = std::thread::spawn(move || {
        let _ = snp_node::run_relay(&relay_addr_str, &gateway_addr_for_relay);
    });

    std::thread::sleep(Duration::from_millis(150));

    let (status, verified) = snp_node::run_client(&relay_addr.to_string(), "https://example.com/")
        .expect("client round-trip should succeed");

    let _ = gw_handle.join();
    let _ = relay_handle.join();

    assert_eq!(status, 200, "HTTP status from example.com should be 200");
    assert!(verified, "gateway signature must verify on the client");

    println!("N1.8 integration test PASSED: status={status}, gateway_verified={verified}");
}

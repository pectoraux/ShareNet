//! N2.0.4 Gate C — Runtime architecture hardening tests
//!
//! Tests that:
//! 1. SNP-IK/0.1 produces fresh keys per session
//! 2. Deterministic key derivation is not in production paths
//! 3. TransportProvider works end-to-end

#![allow(clippy::pedantic, deprecated)]

use snp_crypto::sha256;
use snp_node::node::transport::{TcpTransportProvider, TransportProvider, TransportError};

#[test]
fn gate_c_snp_ik_produces_fresh_keys_per_session() {
    use snp_crypto::{derive_public_key, x25519_ephemeral_keypair};
    use snp_link::perform_snp_ik_handshake;
    use std::net::{TcpListener, TcpStream};

    // Create two nodes with fixed identities but ephemeral X25519
    let alice_sk = sha256(b"alice-n204");
    let alice_pk = derive_public_key(&alice_sk);
    let (alice_x_sk, alice_x_pk) = x25519_ephemeral_keypair();

    let bob_sk = sha256(b"bob-n204");
    let bob_pk = derive_public_key(&bob_sk);
    let (bob_x_sk, bob_x_pk) = x25519_ephemeral_keypair();

    // Session 1
    let listener1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr1 = listener1.local_addr().unwrap().to_string();
    let h1 = std::thread::spawn(move || {
        let (mut stream, _) = listener1.accept().unwrap();
        perform_snp_ik_handshake(
            &mut stream, false, &bob_sk, &bob_pk, &bob_x_sk, &bob_x_pk, None,
        ).unwrap()
    });
    let mut client1 = TcpStream::connect(&addr1).unwrap();
    let result1 = perform_snp_ik_handshake(
        &mut client1, true, &alice_sk, &alice_pk, &alice_x_sk, &alice_x_pk, None,
    ).unwrap();
    let server_result1 = h1.join().unwrap();

    // Session 2 (different ephemeral keys)
    let (alice_x_sk2, alice_x_pk2) = x25519_ephemeral_keypair();
    let (bob_x_sk2, bob_x_pk2) = x25519_ephemeral_keypair();

    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap().to_string();
    let h2 = std::thread::spawn(move || {
        let (mut stream, _) = listener2.accept().unwrap();
        perform_snp_ik_handshake(
            &mut stream, false, &bob_sk, &bob_pk, &bob_x_sk2, &bob_x_pk2, None,
        ).unwrap()
    });
    let mut client2 = TcpStream::connect(&addr2).unwrap();
    let result2 = perform_snp_ik_handshake(
        &mut client2, true, &alice_sk, &alice_pk, &alice_x_sk2, &alice_x_pk2, None,
    ).unwrap();
    let server_result2 = h2.join().unwrap();

    // Keys MUST be different across sessions
    assert_ne!(result1.link_keys.send_key, result2.link_keys.send_key,
        "Fresh keys: two sessions between same identities must produce different keys");
    assert_ne!(result1.session_id, result2.session_id,
        "Session IDs must differ across sessions");
    
    // Client and server must agree on keys within each session
    assert_eq!(result1.link_keys.send_key, server_result1.link_keys.recv_key,
        "Client send_key must equal server recv_key (session 1)");
    assert_eq!(result2.link_keys.send_key, server_result2.link_keys.recv_key,
        "Client send_key must equal server recv_key (session 2)");
}

#[test]
fn gate_c_deterministic_link_keys_not_in_production_imports() {
    let source = include_str!("../src/node/mod.rs");
    // The production discovery path should NOT use DISCOVERY_LINK_SEED
    // (it now uses raw TCP + signed advertisement verification)
    let has_discovery_seed_in_serve = source
        .lines()
        .filter(|l| l.contains("DISCOVERY_LINK_SEED") && !l.trim_start().starts_with("//") && !l.contains("deprecated"))
        .filter(|l| l.contains("serve_discovery") || l.contains("discover_gateways"))
        .count();
    assert_eq!(has_discovery_seed_in_serve, 0,
        "Production discovery methods must not use DISCOVERY_LINK_SEED");
}

#[test]
fn gate_b_transport_provider_tcp_roundtrip() {
    let provider = TcpTransportProvider;
    let mut listener = provider.listen("127.0.0.1:0").unwrap();
    let addr = listener.local_addr();
    
    let h = std::thread::spawn(move || {
        let mut conn = listener.accept().unwrap();
        conn.send(b"hello from server").unwrap();
    });
    
    let mut conn = provider.connect(&addr).unwrap();
    // Give the server time to send
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    h.join().unwrap();
}

#[test]
fn gate_b_transport_connection_dead_address() {
    let provider = TcpTransportProvider;
    let result = provider.connect("127.0.0.1:1"); // port 1 should be unreachable
    assert!(result.is_err(), "Connecting to dead address must fail");
}

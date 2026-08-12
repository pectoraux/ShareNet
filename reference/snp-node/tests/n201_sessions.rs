//! N2.0.1 — Real Session & Discovery Closure tests
//!
//! Tests the four findings of the N2.0 audit:
//!
//! 1. **Persistent sessions** — multiple requests over ONE TCP connection
//!    (Test 1, Test 5).
//! 2. **Gateway discovery** — client fetches signed advertisements, verifies
//!    the signature, selects a gateway (Test 2).
//! 3. **Genuine failover** — Gateway A drops, client fails over to Gateway B
//!    without restarting any node (Test 3).
//! 4. **Advertisement security** — forged signatures and expired
//!    advertisements are rejected (Test 4).
//!
//! All tests use STUB gateways (no real Internet fetches). The stubs mirror
//! the real gateway's wire format (decrypt circuit → decode TransitRequest →
//! build signed TransitResponse → encrypt circuit → send frame).

#![allow(clippy::pedantic)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(deprecated)]

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, sha256};
use snp_frames::{should_drop, Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_gateway::{
    decode_transit_request, encode_transit_response,
    sign_transit_response, TransitRequest, TransitResponse,
};
use snp_link::{
    decrypt_circuit_payload, encrypt_circuit_payload, Link, LinkKeys,
};

use snp_node::node::{
    spawn_relay_persistent_with_counter,
    spawn_relay_multi_upstream_persistent_with_counter, Circuit, GatewayAdvertisement, Node,
    NodeIdentity, UpstreamPeer, DISCOVERY_REQUEST_BYTE,
};
use snp_node::legacy::{
    client_node_id, client_public_key,
    gateway_circuit_keys_for,
    gateway_node_id_for, gateway_public_key_for, gateway_secret_for,
    gateway_a_relay_b_link_keys, gateway_b_relay_b_link_keys,
    relay_a_client_link_keys, relay_a_relay_b_link_keys,
    relay_b_gateway_a_link_keys, relay_b_gateway_b_link_keys, relay_b_relay_a_link_keys,
    GatewayChoice,
};

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Multiple requests over one session
// ═══════════════════════════════════════════════════════════════════════════

/// Test 1: Client sends 3 requests through the SAME relay+gateway connection.
/// All succeed. No reconnection between requests.
///
/// Verifies:
/// - All 3 requests return status=200, verified=true.
/// - Relay A accepted exactly ONE client connection (the persistent session).
/// - The stub gateway accepted exactly ONE relay connection (persistent
///   relay→gateway connection).
#[test]
fn test_1_multiple_requests_one_session() {
    // Allocate ephemeral ports.
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    // Stub gateway connection counter.
    let gw_connections = Arc::new(AtomicU64::new(0));
    let gw_requests = Arc::new(AtomicU64::new(0));

    // Start stub Gateway A (persistent, accepts the listener).
    let gw_connections_clone = Arc::clone(&gw_connections);
    let gw_requests_clone = Arc::clone(&gw_requests);
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_persistent(
            &gw_listener,
            GatewayChoice::A,
            None, // no drop_after
            gw_connections_clone,
            gw_requests_clone,
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay B (single-upstream to gateway, with counter).
    let (relay_b_handle, relay_b_connections) = spawn_relay_persistent_with_counter(
        &relay_b_addr.to_string(),
        &gw_addr.to_string(),
        relay_b_relay_a_link_keys(),
        relay_b_gateway_a_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay A (single-upstream to Relay B, with counter).
    let (relay_a_handle, relay_a_connections) = spawn_relay_persistent_with_counter(
        &relay_a_addr.to_string(),
        &relay_b_addr.to_string(),
        relay_a_client_link_keys(),
        relay_a_relay_b_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));

    // Create client Node, manually populate known_gateways and circuits.
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![snp_node::node::Capability::Client],
        relay_a_addr.to_string(),
    );
    let advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        &gw_addr.to_string(),
        "127.0.0.1:0",
    );
    client_node.known_gateways.lock().unwrap().push(advert);
    client_node
        .circuits
        .lock()
        .unwrap()
        .insert(gateway_node_id_for(GatewayChoice::A), snp_node::legacy::legacy_circuit_for_gateway(GatewayChoice::A));

    // Send 3 requests.
    let url = "http://stub.example/test1";
    let (s1, v1) = client_node
        .send_request(url)
        .expect("Request 1 should succeed");
    let (s2, v2) = client_node
        .send_request(url)
        .expect("Request 2 should succeed (same session)");
    let (s3, v3) = client_node
        .send_request(url)
        .expect("Request 3 should succeed (same session)");

    assert_eq!(s1, 200, "Request 1 status");
    assert_eq!(s2, 200, "Request 2 status");
    assert_eq!(s3, 200, "Request 3 status");
    assert!(v1, "Request 1 gateway signature verified");
    assert!(v2, "Request 2 gateway signature verified");
    assert!(v3, "Request 3 gateway signature verified");

    // Give the gateway/relay a moment to settle.
    std::thread::sleep(Duration::from_millis(100));

    // Verify persistence: relay A accepted exactly ONE client connection.
    let relay_a_conns = relay_a_connections.load(Ordering::SeqCst);
    assert_eq!(
        relay_a_conns, 1,
        "Relay A should have accepted exactly ONE client connection (persistent session), got {relay_a_conns}"
    );

    // Verify persistence: the gateway accepted exactly ONE relay connection.
    let gw_conns = gw_connections.load(Ordering::SeqCst);
    assert_eq!(
        gw_conns, 1,
        "Gateway should have accepted exactly ONE relay connection (persistent relay→gateway), got {gw_conns}"
    );

    // Verify the gateway served 3 requests.
    let gw_reqs = gw_requests.load(Ordering::SeqCst);
    assert_eq!(
        gw_reqs, 3,
        "Gateway should have served 3 requests over the persistent connection, got {gw_reqs}"
    );

    println!("Test 1 PASSED: 3 requests over 1 persistent session (relay conns={relay_a_conns}, gateway conns={gw_conns}, gateway requests={gw_reqs})");

    // Clean up: drop the client node (closes the persistent connection).
    drop(client_node);
    std::thread::sleep(Duration::from_millis(100));
    // The gateway and relay threads are infinite loops — detach them.
    std::mem::forget(gw_handle);
    std::mem::forget(relay_b_handle);
    std::mem::forget(relay_a_handle);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Gateway discovery
// ═══════════════════════════════════════════════════════════════════════════

/// Test 2: Gateway advertises itself. Client discovers it via the
/// advertisement (not hardcoded). Client verifies the advertisement
/// signature. Client selects the gateway and sends a request.
#[test]
fn test_2_gateway_discovery() {
    // Allocate ephemeral ports.
    let gw_transit_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw transit");
    let gw_transit_addr = gw_transit_listener.local_addr().expect("local_addr");
    let gw_disc_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw discovery");
    let gw_disc_addr = gw_disc_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    let gw_transit_str = gw_transit_addr.to_string();

    // Start stub Gateway A (transit listener).
    let gw_connections = Arc::new(AtomicU64::new(0));
    let gw_requests = Arc::new(AtomicU64::new(0));
    let gw_connections_clone = Arc::clone(&gw_connections);
    let gw_requests_clone = Arc::clone(&gw_requests);
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_persistent(
            &gw_transit_listener,
            GatewayChoice::A,
            None,
            gw_connections_clone,
            gw_requests_clone,
        );
    });

    // Start stub discovery listener for Gateway A.
    let gw_disc_handle = std::thread::spawn(move || {
        stub_discovery_persistent(&gw_disc_listener, GatewayChoice::A, &gw_transit_str);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Start relays.
    let (relay_b_handle, _relay_b_conns) = spawn_relay_persistent_with_counter(
        &relay_b_addr.to_string(),
        &gw_transit_addr.to_string(),
        relay_b_relay_a_link_keys(),
        relay_b_gateway_a_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));
    let (relay_a_handle, _relay_a_conns) = spawn_relay_persistent_with_counter(
        &relay_a_addr.to_string(),
        &relay_b_addr.to_string(),
        relay_a_client_link_keys(),
        relay_a_relay_b_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));

    // Create client Node. The client does NOT know the gateway's address
    // ahead of time — it will discover it via the advertisement.
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![snp_node::node::Capability::Client],
        relay_a_addr.to_string(),
    );

    // Discover gateways via signed advertisements.
    client_node
        .discover_gateways(&[gw_disc_addr.to_string()])
        .expect("discovery should succeed");

    // Verify the client discovered the gateway.
    let discovered = client_node.known_gateways.lock().unwrap().clone();
    assert_eq!(discovered.len(), 1, "should have discovered exactly 1 gateway");
    let advert = &discovered[0];
    assert_eq!(advert.node_id, gateway_node_id_for(GatewayChoice::A));
    assert_eq!(advert.public_key, gateway_public_key_for(GatewayChoice::A));
    assert_eq!(advert.listen_addr, gw_transit_addr.to_string());

    // Verify the advertisement's signature (already verified by
    // discover_gateways, but double-check here).
    assert!(advert.verify(), "discovered advertisement signature must verify");

    // N2.0.3: discover_gateways no longer pre-populates circuits (the
    // GatewayChoice-based Circuit::for_gateway is deprecated). We populate
    // the circuit explicitly here using the deprecated constructor (this
    // is a test of the N2.0.1 backward-compat path, so using the deprecated
    // constructor is acceptable).
    client_node.circuits.lock().unwrap().insert(
        gateway_node_id_for(GatewayChoice::A),
        snp_node::legacy::legacy_circuit_for_gateway(GatewayChoice::A),
    );

    // Select the gateway.
    let selected = client_node
        .select_gateway()
        .expect("should select a gateway");
    assert_eq!(selected.node_id, gateway_node_id_for(GatewayChoice::A));

    // Send a request via the discovered gateway.
    let (status, verified) = client_node
        .send_request("http://stub.example/test2")
        .expect("request via discovered gateway should succeed");
    assert_eq!(status, 200);
    assert!(verified, "gateway signature must verify");

    println!("Test 2 PASSED: gateway discovered via signed advertisement, signature verified, request succeeded");

    drop(client_node);
    std::thread::sleep(Duration::from_millis(100));
    std::mem::forget(gw_handle);
    std::mem::forget(gw_disc_handle);
    std::mem::forget(relay_b_handle);
    std::mem::forget(relay_a_handle);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Genuine failover (Gateway A → Gateway B, no node restart)
// ═══════════════════════════════════════════════════════════════════════════

/// Test 3: Two gateways (A and B) both advertise. Client discovers both.
/// Client sends request via Gateway A. Gateway A's connection is dropped
/// (simulated failure — drop_after=1). Client detects failure, selects
/// Gateway B, establishes new circuit, sends request. All without
/// restarting any node.
#[test]
fn test_3_genuine_failover() {
    // Allocate ephemeral ports.
    let gw_a_transit_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_a transit");
    let gw_a_transit_addr = gw_a_transit_listener.local_addr().expect("local_addr");
    let gw_a_disc_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_a discovery");
    let gw_a_disc_addr = gw_a_disc_listener.local_addr().expect("local_addr");
    let gw_b_transit_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_b transit");
    let gw_b_transit_addr = gw_b_transit_listener.local_addr().expect("local_addr");
    let gw_b_disc_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_b discovery");
    let gw_b_disc_addr = gw_b_disc_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    let gw_a_transit_str = gw_a_transit_addr.to_string();
    let gw_b_transit_str = gw_b_transit_addr.to_string();

    // Start stub Gateway A (drop_after=1 — serves 1 request, then drops).
    let gw_a_connections = Arc::new(AtomicU64::new(0));
    let gw_a_requests = Arc::new(AtomicU64::new(0));
    let gw_a_conns_clone = Arc::clone(&gw_a_connections);
    let gw_a_reqs_clone = Arc::clone(&gw_a_requests);
    let gw_a_handle = std::thread::spawn(move || {
        stub_gateway_persistent(
            &gw_a_transit_listener,
            GatewayChoice::A,
            Some(1), // drop_after=1
            gw_a_conns_clone,
            gw_a_reqs_clone,
        );
    });

    // Start stub Gateway B (persistent, no drop).
    let gw_b_connections = Arc::new(AtomicU64::new(0));
    let gw_b_requests = Arc::new(AtomicU64::new(0));
    let gw_b_conns_clone = Arc::clone(&gw_b_connections);
    let gw_b_reqs_clone = Arc::clone(&gw_b_requests);
    let gw_b_handle = std::thread::spawn(move || {
        stub_gateway_persistent(
            &gw_b_transit_listener,
            GatewayChoice::B,
            None,
            gw_b_conns_clone,
            gw_b_reqs_clone,
        );
    });

    // Start discovery listeners for both gateways.
    let gw_a_disc_handle = std::thread::spawn(move || {
        stub_discovery_persistent(&gw_a_disc_listener, GatewayChoice::A, &gw_a_transit_str);
    });
    let gw_b_disc_handle = std::thread::spawn(move || {
        stub_discovery_persistent(&gw_b_disc_listener, GatewayChoice::B, &gw_b_transit_str);
    });
    std::thread::sleep(Duration::from_millis(150));

    // Start Relay B (multi-upstream: Gateway A + Gateway B).
    let upstreams = vec![
        UpstreamPeer {
            dst_node_id: gateway_node_id_for(GatewayChoice::A),
            addr: gw_a_transit_addr.to_string(),
            hop_keys: relay_b_gateway_a_link_keys(),
        },
        UpstreamPeer {
            dst_node_id: gateway_node_id_for(GatewayChoice::B),
            addr: gw_b_transit_addr.to_string(),
            hop_keys: relay_b_gateway_b_link_keys(),
        },
    ];
    let (relay_b_handle, _relay_b_conns) =
        spawn_relay_multi_upstream_persistent_with_counter(
            &relay_b_addr.to_string(),
            upstreams,
            relay_b_relay_a_link_keys(),
        );
    std::thread::sleep(Duration::from_millis(150));

    // Start Relay A (single-upstream: Relay B).
    let (relay_a_handle, _relay_a_conns) = spawn_relay_persistent_with_counter(
        &relay_a_addr.to_string(),
        &relay_b_addr.to_string(),
        relay_a_client_link_keys(),
        relay_a_relay_b_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(150));

    // Create client Node.
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![snp_node::node::Capability::Client],
        relay_a_addr.to_string(),
    );

    // Discover both gateways via signed advertisements.
    client_node
        .discover_gateways(&[
            gw_a_disc_addr.to_string(),
            gw_b_disc_addr.to_string(),
        ])
        .expect("discovery should succeed for both gateways");
    let n_discovered = client_node.known_gateways.lock().unwrap().len();
    assert_eq!(n_discovered, 2, "should have discovered 2 gateways");

    // N2.0.3: discover_gateways no longer pre-populates circuits (the
    // GatewayChoice-based Circuit::for_gateway is deprecated). We populate
    // the circuits for both gateways explicitly here using the deprecated
    // constructor (this is a test of the N2.0.1 backward-compat path).
    client_node.circuits.lock().unwrap().insert(
        gateway_node_id_for(GatewayChoice::A),
        snp_node::legacy::legacy_circuit_for_gateway(GatewayChoice::A),
    );
    client_node.circuits.lock().unwrap().insert(
        gateway_node_id_for(GatewayChoice::B),
        snp_node::legacy::legacy_circuit_for_gateway(GatewayChoice::B),
    );

    // ── Request 1: via Gateway A (the first discovered gateway). ──
    // The client's select_gateway returns the first non-expired gateway
    // with an active circuit, which is Gateway A (discovered first).
    let (status1, verified1) = client_node
        .send_request("http://stub.example/test3-req1")
        .expect("Request 1 via Gateway A should succeed");
    assert_eq!(status1, 200, "Request 1 status");
    assert!(verified1, "Request 1 gateway-A signature verified");

    // Verify Gateway A served 1 request.
    assert_eq!(
        gw_a_requests.load(Ordering::SeqCst),
        1,
        "Gateway A should have served 1 request"
    );

    // After Request 1, Gateway A drops its connection (drop_after=1).
    // Give it a moment to drop.
    std::thread::sleep(Duration::from_millis(200));

    // ── Request 2: with failover. ──
    // The client tries Gateway A first (current gateway), gets a NACK
    // (Gateway A's connection is dead), marks the circuit inactive, and
    // fails over to Gateway B.
    let (status2, verified2) = client_node
        .send_request_with_failover("http://stub.example/test3-req2")
        .expect("Request 2 with failover should succeed via Gateway B");
    assert_eq!(status2, 200, "Request 2 status");
    assert!(verified2, "Request 2 gateway-B signature verified");

    // Verify Gateway B served 1 request.
    assert_eq!(
        gw_b_requests.load(Ordering::SeqCst),
        1,
        "Gateway B should have served 1 request (the failover)"
    );

    // Verify the client's current gateway is now Gateway B.
    let current = *client_node.current_gateway.lock().unwrap();
    assert_eq!(
        current,
        Some(gateway_node_id_for(GatewayChoice::B)),
        "client should have failed over to Gateway B"
    );

    // Verify Gateway A's circuit is marked inactive.
    let gw_a_circuit_active = client_node
        .circuits
        .lock()
        .unwrap()
        .get(&gateway_node_id_for(GatewayChoice::A))
        .map(|c| c.active)
        .unwrap_or(true);
    assert!(
        !gw_a_circuit_active,
        "Gateway A's circuit should be marked inactive after failover"
    );

    println!("Test 3 PASSED: genuine failover Gateway A → Gateway B, no node restart");

    drop(client_node);
    std::thread::sleep(Duration::from_millis(100));
    std::mem::forget(gw_a_handle);
    std::mem::forget(gw_b_handle);
    std::mem::forget(gw_a_disc_handle);
    std::mem::forget(gw_b_disc_handle);
    std::mem::forget(relay_b_handle);
    std::mem::forget(relay_a_handle);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Advertisement security
// ═══════════════════════════════════════════════════════════════════════════

/// Test 4: A forged advertisement (wrong signature) is rejected. An expired
/// advertisement is rejected.
#[test]
fn test_4_advertisement_security() {
    // ── 4a: A legitimately-signed advertisement verifies. ──
    let valid_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    assert!(valid_advert.verify(), "legitimately-signed advertisement must verify");
    assert!(!valid_advert.is_expired(now_unix()), "fresh advertisement must not be expired");

    // ── 4b: A forged signature is rejected. ──
    let mut forged_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    // Flip a bit in the signature.
    forged_advert.signature[0] ^= 0xff;
    assert!(!forged_advert.verify(), "forged signature must NOT verify");

    // ── 4c: A tampered field (listenAddr) is rejected. ──
    let mut tampered_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    tampered_advert.listen_addr = "127.0.0.1:9999".to_string();
    assert!(!tampered_advert.verify(), "tampered advertisement must NOT verify");

    // ── 4d: An expired advertisement is detected. ──
    let mut expired_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    expired_advert.expiry = 1; // unix second 1 = 1970-01-01 00:00:01
    assert!(expired_advert.is_expired(now_unix()), "expired advertisement must be detected");
    // The signature is still valid (we only changed `expiry` after signing,
    // so the signature no longer matches — verify() should return false).
    assert!(
        !expired_advert.verify(),
        "tampered expiry must also fail signature verification (signature was over the original expiry)"
    );

    // ── 4e: A re-signed expired advertisement verifies the signature but is
    //         still rejected by is_expired(). ──
    let mut re_signed_expired = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    re_signed_expired.expiry = 1;
    re_signed_expired.sign(&gateway_secret_for(GatewayChoice::A));
    assert!(re_signed_expired.verify(), "re-signed expired advertisement must verify (signature is valid)");
    assert!(re_signed_expired.is_expired(now_unix()), "but is_expired() must still return true");

    // ── 4f: A different gateway's secret key produces a signature that
    //         doesn't verify against this advertisement's public_key. ──
    let mut wrong_key_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    // Re-sign with Gateway B's secret key.
    wrong_key_advert.sign(&gateway_secret_for(GatewayChoice::B));
    assert!(
        !wrong_key_advert.verify(),
        "advertisement signed by Gateway B's key must NOT verify against Gateway A's public_key"
    );

    // ── 4g: NodeId mismatch (I4 violation) — the advertisement's nodeId
    //         doesn't match SHA-256("SNP/0.1 node\\0" || publicKey). ──
    let mut mismatched_advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    // Tamper with nodeId (but don't re-sign).
    mismatched_advert.node_id = [0xff; 32];
    // The signature no longer matches (nodeId is part of the signed preimage).
    assert!(!mismatched_advert.verify(), "tampered nodeId must fail signature verification");

    println!("Test 4 PASSED: forged, tampered, expired, wrong-key, and nodeId-mismatched advertisements all rejected");

    // Suppress unused-import warning for client_node_id/client_public_key.
    let _ = client_node_id();
    let _ = client_public_key();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Persistent relay
// ═══════════════════════════════════════════════════════════════════════════

/// Test 5: The relay serves 3 requests from the same client over the SAME
/// connection. The relay connection stays open.
///
/// This test uses the FULL N2.0.1 multi-hop topology (Client → Relay A →
/// Relay B → Gateway) and verifies that BOTH relays accepted exactly ONE
/// connection each (persistent relay→relay and relay→gateway connections).
#[test]
fn test_5_persistent_relay() {
    // Allocate ephemeral ports.
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    let gw_connections = Arc::new(AtomicU64::new(0));
    let gw_requests = Arc::new(AtomicU64::new(0));
    let gw_connections_clone = Arc::clone(&gw_connections);
    let gw_requests_clone = Arc::clone(&gw_requests);
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_persistent(
            &gw_listener,
            GatewayChoice::A,
            None,
            gw_connections_clone,
            gw_requests_clone,
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay B (single-upstream to gateway, with counter).
    let (relay_b_handle, relay_b_connections) = spawn_relay_persistent_with_counter(
        &relay_b_addr.to_string(),
        &gw_addr.to_string(),
        relay_b_relay_a_link_keys(),
        relay_b_gateway_a_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));

    // Start Relay A (single-upstream to Relay B, with counter).
    let (relay_a_handle, relay_a_connections) = spawn_relay_persistent_with_counter(
        &relay_a_addr.to_string(),
        &relay_b_addr.to_string(),
        relay_a_client_link_keys(),
        relay_a_relay_b_link_keys(),
    );
    std::thread::sleep(Duration::from_millis(100));

    // Create client Node.
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![snp_node::node::Capability::Client],
        relay_a_addr.to_string(),
    );
    let advert = snp_node::legacy::legacy_advert_for_gateway(
        GatewayChoice::A,
        &gw_addr.to_string(),
        "127.0.0.1:0",
    );
    client_node.known_gateways.lock().unwrap().push(advert);
    client_node
        .circuits
        .lock()
        .unwrap()
        .insert(gateway_node_id_for(GatewayChoice::A), snp_node::legacy::legacy_circuit_for_gateway(GatewayChoice::A));

    // Send 3 requests.
    let url = "http://stub.example/test5";
    for i in 1..=3 {
        let (status, verified) = client_node
            .send_request(url)
            .unwrap_or_else(|e| panic!("Request {i} should succeed: {e}"));
        assert_eq!(status, 200, "Request {i} status");
        assert!(verified, "Request {i} verified");
    }

    std::thread::sleep(Duration::from_millis(100));

    // Verify BOTH relays accepted exactly ONE connection.
    let relay_a_conns = relay_a_connections.load(Ordering::SeqCst);
    let relay_b_conns = relay_b_connections.load(Ordering::SeqCst);
    let gw_conns = gw_connections.load(Ordering::SeqCst);
    let gw_reqs = gw_requests.load(Ordering::SeqCst);

    assert_eq!(relay_a_conns, 1, "Relay A should have accepted 1 connection (persistent client→relay), got {relay_a_conns}");
    assert_eq!(relay_b_conns, 1, "Relay B should have accepted 1 connection (persistent relay→relay), got {relay_b_conns}");
    assert_eq!(gw_conns, 1, "Gateway should have accepted 1 connection (persistent relay→gateway), got {gw_conns}");
    assert_eq!(gw_reqs, 3, "Gateway should have served 3 requests over the persistent connection, got {gw_reqs}");

    println!("Test 5 PASSED: persistent relay chain (relay_a conns={relay_a_conns}, relay_b conns={relay_b_conns}, gateway conns={gw_conns}, gateway requests={gw_reqs})");

    drop(client_node);
    std::thread::sleep(Duration::from_millis(100));
    std::mem::forget(gw_handle);
    std::mem::forget(relay_b_handle);
    std::mem::forget(relay_a_handle);
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers: stub persistent gateway + stub persistent discovery
// ═══════════════════════════════════════════════════════════════════════════

/// Stub persistent gateway: accepts connections on `listener`, loops serving
/// transit requests with canned responses (status=200, signed by the
/// gateway's identity key). Optionally drops the connection after
/// `drop_after` requests (to simulate a gateway failure for Test 3).
///
/// The stub mirrors the real gateway's wire format:
/// 1. recv frame (decrypt OUTER with hop recv_key — done by Link)
/// 2. decrypt circuit body with circuit recv_key
/// 3. decode TransitRequest
/// 4. build a canned TransitResponse (status=200, signed)
/// 5. encrypt circuit body with circuit send_key
/// 6. send response frame
fn stub_gateway_persistent(
    listener: &TcpListener,
    gw: GatewayChoice,
    drop_after: Option<usize>,
    connections_counter: Arc<AtomicU64>,
    requests_counter: Arc<AtomicU64>,
) {
    let keys = gateway_relay_b_link_keys_for_gw(gw);
    let circuit = gateway_circuit_keys_for(gw);
    let gateway_sk = gateway_secret_for(gw);
    let gateway_id = gateway_node_id_for(gw);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stub-gw-{gw:?}] accept error: {e}");
                continue;
            }
        };
        connections_counter.fetch_add(1, Ordering::SeqCst);
        eprintln!("[stub-gw-{gw:?}] relay connected");
        let link = Arc::new(Link::new(stream, keys));
        let mut served = 0usize;

        loop {
            if let Some(max) = drop_after {
                if served >= max {
                    eprintln!(
                        "[stub-gw-{gw:?}] served {served} requests — DROPPING connection (drop_after={max})"
                    );
                    // Shut down the stream to signal EOF.
                    let _ = link.stream().shutdown(std::net::Shutdown::Both);
                    break;
                }
            }
            let req_frame = match link.recv_frame() {
                Ok(f) => f,
                Err(snp_link::LinkError::Io(msg))
                    if msg.contains("unexpected eof") || msg.contains("connection reset") =>
                {
                    eprintln!("[stub-gw-{gw:?}] connection closed by peer (EOF)");
                    break;
                }
                Err(e) => {
                    eprintln!("[stub-gw-{gw:?}] recv error: {e}");
                    break;
                }
            };
            if should_drop(&req_frame) {
                continue;
            }
            // Decrypt the circuit body.
            let req_bytes = match decrypt_circuit_payload(&circuit.recv_key, &req_frame.body) {
                Some(b) => b,
                None => {
                    eprintln!("[stub-gw-{gw:?}] circuit decryption failed — skipping");
                    continue;
                }
            };
            let transit_req: TransitRequest = match decode_transit_request(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[stub-gw-{gw:?}] decode transit request failed: {e}");
                    continue;
                }
            };
            eprintln!(
                "[stub-gw-{gw:?}] recv transit request: url={}",
                transit_req.url
            );

            // Build a canned response.
            let resp = build_stub_response(gw, transit_req.req_id, gateway_id, &gateway_sk);
            let resp_bytes = encode_transit_response(&resp).expect("encode response");
            let sealed = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);
            let resp_frame = Frame {
                v: FRAME_VERSION,
                cls: b'B',
                dst: req_frame.src,
                src: gateway_id,
                ttl: FRAME_TTL_MAX,
                fid: req_frame.fid,
                seq: req_frame.seq + 1,
                body: sealed,
            };
            if let Err(e) = link.send_frame(&resp_frame) {
                eprintln!("[stub-gw-{gw:?}] send error: {e}");
                break;
            }
            served += 1;
            requests_counter.fetch_add(1, Ordering::SeqCst);
        }
        eprintln!("[stub-gw-{gw:?}] connection cycle complete");
    }
}

/// Stub persistent discovery listener: accepts connections on `listener`,
/// receives a single-byte `0x01` discovery-request, responds with a
/// length-prefixed CBOR-encoded signed `GatewayAdvertisement`.
///
/// **N2.0.4 (Gate A):** the stub now uses the RAW discovery protocol
/// (no AEAD, no `DISCOVERY_LINK_SEED`) — matching the production
/// `Node::serve_discovery_persistent` and `BootstrapDiscovery::discover`.
fn stub_discovery_persistent(
    listener: &TcpListener,
    gw: GatewayChoice,
    transit_listen_addr: &str,
) {
    let advert = snp_node::legacy::legacy_advert_for_gateway(gw, transit_listen_addr, &listener.local_addr().unwrap().to_string());
    let advert_bytes = advert.encode_cbor().expect("encode advert");
    let len_bytes = u32::try_from(advert_bytes.len())
        .expect("advertisement fits in u32")
        .to_be_bytes();

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stub-disc-{gw:?}] accept error: {e}");
                continue;
            }
        };
        use std::io::{Read, Write};
        // N2.0.4: read 1-byte discovery request.
        let mut req = [0u8; 1];
        if let Err(e) = stream.read_exact(&mut req) {
            eprintln!("[stub-disc-{gw:?}] recv request error: {e}");
            continue;
        }
        if req[0] != DISCOVERY_REQUEST_BYTE {
            eprintln!(
                "[stub-disc-{gw:?}] unexpected discovery request byte 0x{:02x}",
                req[0]
            );
            continue;
        }
        eprintln!("[stub-disc-{gw:?}] got discovery request");
        // N2.0.4: send 4-byte BE length prefix + CBOR advertisement.
        if let Err(e) = stream.write_all(&len_bytes) {
            eprintln!("[stub-disc-{gw:?}] send length error: {e}");
            continue;
        }
        if let Err(e) = stream.write_all(&advert_bytes) {
            eprintln!("[stub-disc-{gw:?}] send advert error: {e}");
            continue;
        }
        let _ = stream.flush();
    }
}

/// Build a signed TransitResponse (status 200, fixed body) for the given
/// gateway choice. Mirrors the stub-gateway pattern in n20_multihop.rs.
fn build_stub_response(
    gw: GatewayChoice,
    req_id: [u8; 16],
    gateway_id: [u8; 32],
    gateway_sk: &[u8; 32],
) -> TransitResponse {
    let object_id = sha256(b"n201-stub-response-body");
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut resp = TransitResponse {
        req_id,
        status: 200,
        headers: vec![("content-type".into(), "text/plain".into())],
        object_id,
        fetched_at,
        gateway_id,
        gateway_sig: [0u8; 64],
    };
    sign_transit_response(&mut resp, gateway_sk);
    resp
}

/// Helper: gateway's relay-B link keys for the given choice. (Wraps the
/// `gateway_relay_b_link_keys_for` from snp_node for ergonomic use in the
/// test file.)
fn gateway_relay_b_link_keys_for_gw(gw: GatewayChoice) -> LinkKeys {
    match gw {
        GatewayChoice::A => gateway_a_relay_b_link_keys(),
        GatewayChoice::B => gateway_b_relay_b_link_keys(),
    }
}

/// Current unix time in seconds (for Test 4's expiry checks).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

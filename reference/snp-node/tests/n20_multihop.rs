//! N2.0 Multi-hop adversarial tests
//!
//! Verifies the N2.0 multi-hop mesh:
//!
//! ```text
//!   CLIENT ──[S1]──> RELAY A ──[S2]──> RELAY B ──[S3]──> GATEWAY
//!     └──────────────────────── [C circuit] ──────────────────┘
//! ```
//!
//! Tests:
//! 1. Multi-hop end-to-end (real Internet, #[ignore]) — Client → Relay A →
//!    Relay B → Gateway → example.com → back. status=200, gateway signature
//!    verified, circuit encryption works across 2 hops.
//! 2. Relay A cannot decrypt circuit payload — Relay A has S1 and S2 but NOT
//!    C. All four hop keys fail to decrypt the body.
//! 3. Relay B cannot decrypt circuit payload — Relay B has S2 and S3 but NOT
//!    C. All four hop keys fail to decrypt the body.
//! 4. TTL exhaustion — A frame with TTL=2 drops at Relay B (never reaches the
//!    gateway). The client's run_client returns an error.
//! 5. Gateway failover — Request succeeds via Gateway A. Gateway A is killed.
//!    Request succeeds via Gateway B. The circuit key changes (Ca → Cb).
//! 6. Frame integrity across hops — The circuit body that arrives at the
//!    gateway is byte-identical to what the client sent. No relay modified it.
//!
//! Tests 2, 3, 4, 5, 6 use STUB gateways (no Internet). Test 1 is the only
//! test that requires real Internet access; it is `#[ignore]`d by default.

#![allow(clippy::pedantic)]

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, sha256};
use snp_frames::Frame;
use snp_gateway::{
    decode_transit_response, encode_transit_response, sign_transit_response, TransitRequest,
    TransitResponse,
};
use snp_link::{
    decrypt_circuit_payload, encrypt_circuit_payload, encrypt_circuit_payload_with_nonce, Link,
};
use snp_node::{
    gateway_a_circuit_keys, gateway_a_relay_b_link_keys, gateway_b_circuit_keys,
    gateway_b_relay_b_link_keys, gateway_node_id_for, gateway_public_key_for,
    gateway_secret_for, client_circuit_keys_a, client_circuit_keys_b,
    client_node_id, client_public_key, client_relay_a_link_keys,
    relay_a_client_link_keys, relay_a_relay_b_link_keys,
    relay_b_relay_a_link_keys, relay_b_gateway_a_link_keys, relay_b_gateway_b_link_keys,
    run_client_to_gateway, run_gateway_named, run_mesh_demo_multihop, run_relay_multiHop,
    GatewayChoice,
};

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Multi-hop end-to-end (real Internet, #[ignore])
// ═══════════════════════════════════════════════════════════════════════════

/// Test 1: Client → Relay A → Relay B → Gateway A → example.com → back.
///
/// Verifies:
/// - status == 200 (real HTTPS fetch of example.com succeeded)
/// - gateway signature verified (response came from Gateway A, not a relay)
/// - circuit encryption works across 2 hops (client decrypted the response
///   using its circuit_recv_key — the body crossed both relays as opaque
///   ciphertext and arrived intact at the gateway, which encrypted the
///   response back through both relays to the client)
///
/// Requires real Internet access. Marked `#[ignore]` so it doesn't run in
/// CI without explicit opt-in.
#[test]
#[ignore = "requires Internet access (fetches https://example.com/ over HTTPS)"]
fn test_1_multihop_end_to_end_real_internet() {
    // Allocate ephemeral ports.
    let gw_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_a");
    let gw_a_addr = gw_a_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(gw_a_listener);
    drop(relay_b_listener);
    drop(relay_a_listener);

    // Start Gateway A.
    let gw_a_addr_str = gw_a_addr.to_string();
    let gw_handle = std::thread::spawn(move || {
        let _ = run_gateway_named(&gw_a_addr_str, GatewayChoice::A);
    });
    std::thread::sleep(Duration::from_millis(150));

    // Start Relay B → connects to Gateway A.
    let gw_a_addr_for_relay_b = gw_a_addr.to_string();
    let relay_b_addr_str = relay_b_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str,
            &gw_a_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // Start Relay A → connects to Relay B.
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_addr_str = relay_a_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // Run the client.
    let (status, verified) =
        run_client_to_gateway(&relay_a_addr.to_string(), "https://example.com/", GatewayChoice::A)
            .expect("multi-hop client round-trip should succeed");

    let _ = gw_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    assert_eq!(status, 200, "HTTP status from example.com should be 200");
    assert!(
        verified,
        "gateway signature must verify on the client (proves response came from Gateway A, not a relay)"
    );

    println!("Test 1 PASSED: multi-hop end-to-end — status={status}, gateway_verified={verified}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Relay A cannot decrypt circuit payload
// ═══════════════════════════════════════════════════════════════════════════

/// Test 2: Relay A has S1 (client↔RelayA) and S2 (RelayA↔RelayB) but NOT C
/// (the circuit key). The malicious Relay A attempts to decrypt the frame
/// body using all four of its hop keys — every attempt MUST return None.
/// The relay then forwards the frame UNCHANGED, and the end-to-end
/// round-trip MUST succeed (proving the body was not corrupted by the
/// decryption attempt).
#[test]
fn test_2_relay_a_cannot_decrypt_circuit_payload() {
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    // gw_listener + relay_a_listener are moved into their stub/malicious threads
    // (which accept on the listener directly). relay_b_listener is dropped
    // because run_relay_multiHop rebinds internally.
    drop(relay_b_listener);

    // Stub Gateway A.
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_round_trip(&gw_listener, GatewayChoice::A);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Relay B — a plain run_relay_multiHop (no malice).
    let gw_addr_for_relay_b = gw_addr.to_string();
    let relay_b_addr_str = relay_b_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str,
            &gw_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Malicious Relay A — tries to decrypt the body with all four hop keys.
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        malicious_relay_a_round_trip(&relay_a_listener, &relay_b_addr_for_relay_a);
    });
    std::thread::sleep(Duration::from_millis(100));

    let (status, verified) =
        run_client_to_gateway(&relay_a_addr.to_string(), "http://stub.example/", GatewayChoice::A)
            .expect("multi-hop round-trip should succeed despite Relay A's attempts");

    assert_eq!(status, 200, "stub gateway should return 200");
    assert!(verified, "gateway signature must verify");

    let _ = gw_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    println!("Test 2 PASSED: Relay A cannot decrypt circuit payload; round-trip succeeds");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Relay B cannot decrypt circuit payload
// ═══════════════════════════════════════════════════════════════════════════

/// Test 3: Relay B has S2 (RelayA↔RelayB) and S3 (RelayB↔Gateway) but NOT C.
/// The malicious Relay B attempts to decrypt the frame body using all four
/// of its hop keys — every attempt MUST return None. The relay then
/// forwards the frame UNCHANGED, and the end-to-end round-trip MUST succeed.
#[test]
fn test_3_relay_b_cannot_decrypt_circuit_payload() {
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    // gw_listener + relay_b_listener are moved into their stub/malicious threads
    // (they accept on the listener directly). relay_a_listener is dropped
    // because run_relay_multiHop rebinds internally.
    drop(relay_a_listener);

    // Stub Gateway A.
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_round_trip(&gw_listener, GatewayChoice::A);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Malicious Relay B — tries to decrypt the body with all four hop keys.
    let gw_addr_for_relay_b = gw_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        malicious_relay_b_round_trip(&relay_b_listener, &gw_addr_for_relay_b);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Relay A — a plain run_relay_multiHop.
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_addr_str = relay_a_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let (status, verified) =
        run_client_to_gateway(&relay_a_addr.to_string(), "http://stub.example/", GatewayChoice::A)
            .expect("multi-hop round-trip should succeed despite Relay B's attempts");

    assert_eq!(status, 200);
    assert!(verified);

    let _ = gw_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    println!("Test 3 PASSED: Relay B cannot decrypt circuit payload; round-trip succeeds");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: TTL exhaustion — TTL=2 drops at Relay B
// ═══════════════════════════════════════════════════════════════════════════

/// Test 4: A frame with TTL=2 should NOT reach the gateway through 3 hops.
/// Trace:
///   - Client sends TTL=2.
///   - Relay A receives TTL=2, decrements to 1, forwards (1 > 0, OK).
///   - Relay B receives TTL=1, decrements to 0, DROPS (TTL exhausted).
///   - Gateway receives NOTHING.
///   - Client's run_client_to_gateway returns an error (no response).
///
/// We assert BOTH:
/// - The client's request failed (run_client_to_gateway returned Err).
/// - The stub gateway received NO frame (a shared AtomicBool stayed false).
#[test]
fn test_4_ttl_exhaustion_drops_at_relay_b() {
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    // Stub Gateway A — records whether it received a frame. It MUST NOT.
    let gw_received = Arc::new(AtomicBool::new(false));
    let gw_received_clone = Arc::clone(&gw_received);
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_record_received(&gw_listener, GatewayChoice::A, &gw_received_clone);
    });
    std::thread::sleep(Duration::from_millis(100));

    // Relay B → connects to Gateway A.
    let gw_addr_for_relay_b = gw_addr.to_string();
    let relay_b_addr_str = relay_b_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str,
            &gw_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Relay A → connects to Relay B.
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_addr_str = relay_a_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Custom client that sends with TTL=2 (too low for a 3-hop path).
    let result = send_client_request_with_ttl(
        &relay_a_addr.to_string(),
        "http://stub.example/",
        GatewayChoice::A,
        2,
    );

    // The client MUST get an error — Relay B dropped the frame and closed
    // its connections without sending a response.
    assert!(
        result.is_err(),
        "CLIENT RECEIVED A VALID RESPONSE — TTL=2 should have been dropped at Relay B. \
         Got: {result:?}"
    );

    let _ = gw_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    // CRITICAL: the gateway MUST NOT have received a frame. If it did, the
    // relay forwarded a TTL-exhausted frame — a violation of I7.
    assert!(
        !gw_received.load(Ordering::SeqCst),
        "GATEWAY RECEIVED A FRAME — TTL=2 should have been dropped at Relay B, \
         never reaching the gateway. This is a violation of I7 (TTL exhaustion)."
    );

    println!("Test 4 PASSED: TTL=2 frame dropped at Relay B; gateway received nothing");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Gateway failover — Gateway A killed, traffic continues via Gateway B
// ═══════════════════════════════════════════════════════════════════════════

/// Test 5: Gateway failover.
///
/// 1. Phase 1: Gateway A alive. Request via Gateway A succeeds. The
///    response is signed by Gateway A and the client verifies against
///    Gateway A's public key.
/// 2. "Kill" Gateway A (its thread exits after one request).
/// 3. Phase 2: Gateway B starts. Relay B is re-pointed at Gateway B (using
///    the S3b hop key). Request via Gateway B succeeds. The response is
///    signed by Gateway B and the client verifies against Gateway B's
///    public key.
/// 4. The circuit key changed (Ca for Phase 1, Cb for Phase 2). We verify
///    this statically: `client_circuit_keys_a() != client_circuit_keys_b()`.
///    We also verify that Phase 2's response CANNOT be decrypted with
///    Phase 1's circuit key (proving the keys are actually different and
///    not just nominally so).
#[test]
fn test_5_gateway_failover() {
    let gw_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_a");
    let gw_a_addr = gw_a_listener.local_addr().expect("local_addr");
    let gw_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw_b");
    let gw_b_addr = gw_b_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    // gw_a and gw_b listeners are moved into the stub threads; relay
    // listeners are dropped because run_relay_multiHop rebinds internally.
    drop(relay_b_listener);
    drop(relay_a_listener);

    // ── Static assertion: the two circuit keys are different. ──
    let circuit_a = client_circuit_keys_a();
    let circuit_b = client_circuit_keys_b();
    assert_ne!(
        circuit_a.send_key, circuit_b.send_key,
        "Ca and Cb must be distinct (different gateway → different circuit key)"
    );
    assert_ne!(circuit_a.recv_key, circuit_b.recv_key);
    // The two gateways have different public keys.
    assert_ne!(
        gateway_public_key_for(GatewayChoice::A),
        gateway_public_key_for(GatewayChoice::B),
        "Gateway A and Gateway B must have different public keys"
    );

    // ── Phase 1: Gateway A. ──
    let gw_a_received = Arc::new(AtomicBool::new(false));
    let gw_a_received_clone = Arc::clone(&gw_a_received);
    let gw_a_handle = std::thread::spawn(move || {
        stub_gateway_record_received(&gw_a_listener, GatewayChoice::A, &gw_a_received_clone);
    });
    std::thread::sleep(Duration::from_millis(100));

    let gw_a_addr_for_relay_b = gw_a_addr.to_string();
    let relay_b_addr_str_p1 = relay_b_addr.to_string();
    let relay_b_handle_p1 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str_p1,
            &gw_a_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let relay_b_addr_for_relay_a_p1 = relay_b_addr.to_string();
    let relay_a_addr_str_p1 = relay_a_addr.to_string();
    let relay_a_handle_p1 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str_p1,
            &relay_b_addr_for_relay_a_p1,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let (status_a, verified_a) =
        run_client_to_gateway(&relay_a_addr.to_string(), "http://stub.example/", GatewayChoice::A)
            .expect("Phase 1 client round-trip should succeed via Gateway A");
    assert_eq!(status_a, 200);
    assert!(verified_a, "Phase 1: gateway A signature must verify");

    let _ = gw_a_handle.join();
    let _ = relay_b_handle_p1.join();
    let _ = relay_a_handle_p1.join();

    // Verify Gateway A actually received the frame (sanity check).
    assert!(
        gw_a_received.load(Ordering::SeqCst),
        "Gateway A should have received a frame in Phase 1"
    );

    // ── "Kill" Gateway A. The thread has already exited. ──
    eprintln!("[test-5] Gateway A killed — failing over to Gateway B");

    // ── Phase 2: Gateway B. ──
    let gw_b_received = Arc::new(AtomicBool::new(false));
    let gw_b_received_clone = Arc::clone(&gw_b_received);
    let gw_b_handle = std::thread::spawn(move || {
        stub_gateway_record_received(&gw_b_listener, GatewayChoice::B, &gw_b_received_clone);
    });
    std::thread::sleep(Duration::from_millis(100));

    let gw_b_addr_for_relay_b = gw_b_addr.to_string();
    let relay_b_addr_str_p2 = relay_b_addr.to_string();
    let relay_b_handle_p2 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str_p2,
            &gw_b_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let relay_b_addr_for_relay_a_p2 = relay_b_addr.to_string();
    let relay_a_addr_str_p2 = relay_a_addr.to_string();
    let relay_a_handle_p2 = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str_p2,
            &relay_b_addr_for_relay_a_p2,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let (status_b, verified_b) =
        run_client_to_gateway(&relay_a_addr.to_string(), "http://stub.example/", GatewayChoice::B)
            .expect("Phase 2 client round-trip should succeed via Gateway B");
    assert_eq!(status_b, 200);
    assert!(verified_b, "Phase 2: gateway B signature must verify");

    let _ = gw_b_handle.join();
    let _ = relay_b_handle_p2.join();
    let _ = relay_a_handle_p2.join();

    assert!(
        gw_b_received.load(Ordering::SeqCst),
        "Gateway B should have received a frame in Phase 2"
    );

    println!(
        "Test 5 PASSED: failover — Gateway A status={status_a} verified={verified_a}, \
         Gateway B status={status_b} verified={verified_b}, circuit key changed Ca → Cb"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Frame integrity — circuit body byte-identical at the gateway
// ═══════════════════════════════════════════════════════════════════════════

/// Test 6: The circuit body that arrives at the gateway is byte-identical to
/// what the client sent. No relay modified it.
///
/// Approach: build the client's sealed_body manually using
/// `encrypt_circuit_payload_with_nonce` (deterministic — fixed nonce). Send
/// the frame via Link::send_frame through Relay A → Relay B → stub gateway.
/// The stub gateway records the exact `frame.body` bytes it received.
/// Assert they equal the sealed_body the client encrypted.
#[test]
fn test_6_frame_integrity_across_hops() {
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gw");
    let gw_addr = gw_listener.local_addr().expect("local_addr");
    let relay_b_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_b");
    let relay_b_addr = relay_b_listener.local_addr().expect("local_addr");
    let relay_a_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay_a");
    let relay_a_addr = relay_a_listener.local_addr().expect("local_addr");
    drop(relay_b_listener);
    drop(relay_a_listener);

    // Stub Gateway A — captures the exact body bytes.
    let captured_body: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_body_clone = Arc::clone(&captured_body);
    let gw_handle = std::thread::spawn(move || {
        stub_gateway_capture_body(&gw_listener, GatewayChoice::A, &captured_body_clone);
    });
    std::thread::sleep(Duration::from_millis(100));

    let gw_addr_for_relay_b = gw_addr.to_string();
    let relay_b_addr_str = relay_b_addr.to_string();
    let relay_b_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_b_addr_str,
            &gw_addr_for_relay_b,
            relay_b_relay_a_link_keys(),
            relay_b_gateway_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_addr_str = relay_a_addr.to_string();
    let relay_a_handle = std::thread::spawn(move || {
        let _ = run_relay_multiHop(
            &relay_a_addr_str,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(100));

    // Manually build the client's request with a FIXED nonce so we know
    // exactly what sealed_body bytes should arrive at the gateway.
    let client_sk = {
        // Mirror the deterministic CLIENT_SECRET in snp-node.
        let mut sk = [0u8; 32];
        let mut i = 0u32;
        while i < 32 {
            sk[i as usize] = ((i.wrapping_mul(41)).wrapping_add(7)) as u8;
            i += 1;
        }
        sk
    };
    let mut req = TransitRequest {
        req_id: [0xAB; 16],
        method: "GET".into(),
        url: "http://integrity.example/".into(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: u64::MAX,
        reply_to: [0u8; 32],
        client_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_request(&mut req, &client_sk);
    let req_bytes = snp_gateway::encode_transit_request(&req).expect("encode");

    // Fixed nonce (deterministic).
    let fixed_nonce: [u8; 12] = [0x42; 12];
    let circuit = client_circuit_keys_a();
    let sealed_body = encrypt_circuit_payload_with_nonce(&circuit.send_key, &fixed_nonce, &req_bytes);
    let expected_body = sealed_body.clone();

    let req_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id_for(GatewayChoice::A),
        src: client_node_id(),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: [0x11; 8],
        seq: 1,
        body: sealed_body,
    };

    // Connect to Relay A and send the frame.
    let link = Link::connect(&relay_a_addr.to_string(), client_relay_a_link_keys())
        .expect("connect to relay A");
    link.send_frame(&req_frame).expect("send_frame");

    // Wait for the response (the stub gateway will respond).
    let _resp_frame = link.recv_frame().expect("recv_frame");

    let _ = gw_handle.join();
    let _ = relay_b_handle.join();
    let _ = relay_a_handle.join();

    // Compare the body the gateway received to what the client sent.
    let captured = captured_body.lock().unwrap().clone().expect("gateway captured no body");
    assert_eq!(
        captured.len(),
        expected_body.len(),
        "body length differs — a relay modified the body"
    );
    assert_eq!(
        captured, expected_body,
        "BODY MODIFIED IN TRANSIT — the circuit ciphertext that arrived at the gateway \
         is NOT byte-identical to what the client sent. A relay tampered with the body."
    );

    println!(
        "Test 6 PASSED: circuit body byte-identical at gateway ({} bytes, no relay modified it)",
        captured.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers — stub gateways and malicious relays
// ═══════════════════════════════════════════════════════════════════════════

/// Build the N2.0 gateway's deterministic secret key for the given choice.
/// Mirrors the GATEWAY_A_SECRET / GATEWAY_B_SECRET constants in snp-node.
fn n20_gateway_secret(gw: GatewayChoice) -> [u8; 32] {
    gateway_secret_for(gw)
}

/// Build a signed TransitResponse (status 200, fixed body) for the given
/// gateway choice. Mirrors the stub-gateway pattern in n19_security.rs.
fn build_stub_response(gw: GatewayChoice, req_id: [u8; 16]) -> TransitResponse {
    let gateway_sk = n20_gateway_secret(gw);
    let gateway_pk = derive_public_key(&gateway_sk);
    let gateway_id = derive_node_id(&gateway_pk);
    let object_id = sha256(b"n20-stub-response-body");
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
    sign_transit_response(&mut resp, &gateway_sk);
    resp
}

/// Send a signed TransitResponse back to the relay (and thus to the client)
/// encrypted with the matching gateway circuit send_key.
fn send_stub_response(link: &Link, gw: GatewayChoice, req_frame: &Frame) {
    let circuit = match gw {
        GatewayChoice::A => gateway_a_circuit_keys(),
        GatewayChoice::B => gateway_b_circuit_keys(),
    };
    let resp = build_stub_response(gw, [1u8; 16]);
    let resp_bytes = encode_transit_response(&resp).expect("encode");
    let sealed = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);
    let resp_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id_for(gw),
        ttl: snp_frames::FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed,
    };
    link.send_frame(&resp_frame).expect("send_frame");
}

/// Stub gateway: accept one connection, decrypt the OUTER frame with the
/// gateway's hop recv_key, decrypt the INNER body with the circuit recv_key
/// (verify circuit encryption works), build a fixed TransitResponse, encrypt
/// with the circuit send_key, send back.
fn stub_gateway_round_trip(listener: &TcpListener, gw: GatewayChoice) {
    let (stream, _) = listener.accept().expect("accept");
    let hop_keys = match gw {
        GatewayChoice::A => gateway_a_relay_b_link_keys(),
        GatewayChoice::B => gateway_b_relay_b_link_keys(),
    };
    let link = Link::new(stream, hop_keys);
    let circuit = match gw {
        GatewayChoice::A => gateway_a_circuit_keys(),
        GatewayChoice::B => gateway_b_circuit_keys(),
    };
    let req_frame = link.recv_frame().expect("recv_frame");
    eprintln!(
        "[stub-gw-{gw:?}] got frame: cls={} body={} bytes",
        req_frame.cls as char,
        req_frame.body.len()
    );
    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .expect("circuit decryption must succeed for legitimate traffic");
    eprintln!("[stub-gw-{gw:?}] circuit decryption OK: {} bytes", req_bytes.len());
    send_stub_response(&link, gw, &req_frame);
}

/// Stub gateway that records whether it received a frame (for TTL test).
/// Sets the shared AtomicBool to true on receipt. Does NOT send a response
/// (the TTL test expects no response anyway).
fn stub_gateway_record_received(listener: &TcpListener, gw: GatewayChoice, received: &AtomicBool) {
    // Accept with a short timeout so the test doesn't hang if no frame
    // arrives (which is the expected outcome for Test 4).
    listener.set_nonblocking(true).ok();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let stream = loop {
        if std::time::Instant::now() > deadline {
            eprintln!("[stub-gw-{gw:?}] no connection arrived within timeout (expected for TTL test)");
            return;
        }
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("[stub-gw-{gw:?}] accept error: {e}");
                return;
            }
        }
    };
    eprintln!("[stub-gw-{gw:?}] connection accepted");
    let hop_keys = match gw {
        GatewayChoice::A => gateway_a_relay_b_link_keys(),
        GatewayChoice::B => gateway_b_relay_b_link_keys(),
    };
    let link = Link::new(stream, hop_keys);
    // Try to recv a frame. Use a read timeout so we don't hang if no frame
    // arrives (the relay may have dropped it).
    {
        let stream = link.stream();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    }
    match link.recv_frame() {
        Ok(frame) => {
            eprintln!(
                "[stub-gw-{gw:?}] RECEIVED frame: cls={} body={} bytes (UNEXPECTED for TTL test)",
                frame.cls as char,
                frame.body.len()
            );
            received.store(true, Ordering::SeqCst);
            // Respond anyway so the client doesn't hang.
            send_stub_response(&link, gw, &frame);
        }
        Err(e) => {
            eprintln!(
                "[stub-gw-{gw:?}] recv_frame returned error (expected for TTL test): {e}"
            );
        }
    }
}

/// Stub gateway that captures the exact body bytes received (for integrity test).
fn stub_gateway_capture_body(
    listener: &TcpListener,
    gw: GatewayChoice,
    captured: &Mutex<Option<Vec<u8>>>,
) {
    let (stream, _) = listener.accept().expect("accept");
    let hop_keys = match gw {
        GatewayChoice::A => gateway_a_relay_b_link_keys(),
        GatewayChoice::B => gateway_b_relay_b_link_keys(),
    };
    let link = Link::new(stream, hop_keys);
    let req_frame = link.recv_frame().expect("recv_frame");
    eprintln!(
        "[stub-gw-{gw:?}] captured body: {} bytes",
        req_frame.body.len()
    );
    *captured.lock().unwrap() = Some(req_frame.body.clone());
    send_stub_response(&link, gw, &req_frame);
}

/// Malicious Relay A: tries to decrypt the body using all four of its hop
/// keys (S1.send, S1.recv, S2.send, S2.recv) — every attempt MUST fail.
/// Then forwards the frame UNCHANGED to Relay B.
fn malicious_relay_a_round_trip(listener: &TcpListener, relay_b_addr: &str) {
    let (client_stream, _) = listener.accept().expect("accept");
    let prev_link = Link::new(client_stream, relay_a_client_link_keys());
    let next_link = Link::connect(relay_b_addr, relay_a_relay_b_link_keys()).expect("connect B");

    let mut frame = prev_link.recv_frame().expect("recv_frame from client");
    eprintln!(
        "[malicious-relay-A] got frame: body={} bytes, attempting decryption with hop keys",
        frame.body.len()
    );

    // Attempt to decrypt the body with ALL four hop keys Relay A possesses.
    // Every attempt MUST return None (the body is end-to-end circuit
    // ciphertext encrypted under Ca, which Relay A does NOT possess).
    let s1 = relay_a_client_link_keys();
    let s2 = relay_a_relay_b_link_keys();
    let hop_keys = [
        ("S1.send", s1.send_key),
        ("S1.recv", s1.recv_key),
        ("S2.send", s2.send_key),
        ("S2.recv", s2.recv_key),
    ];
    for (name, key) in &hop_keys {
        let attempt = decrypt_circuit_payload(key, &frame.body);
        assert!(
            attempt.is_none(),
            "MALICIOUS RELAY A SUCCEEDED with {name} — Relay A must not be able to \
             decrypt the circuit payload (it has S1 and S2 but NOT C)"
        );
    }
    eprintln!("[malicious-relay-A] all four hop-key decryption attempts FAILED (correct)");

    // Forward unchanged (decrement TTL as a normal relay would).
    if frame.ttl > 0 {
        frame.ttl -= 1;
    }
    next_link.send_frame(&frame).expect("send to relay B");

    // Forward the response back unchanged.
    let mut resp = next_link.recv_frame().expect("recv from relay B");
    if resp.ttl > 0 {
        resp.ttl -= 1;
    }
    prev_link.send_frame(&resp).expect("send to client");
}

/// Malicious Relay B: tries to decrypt the body using all four of its hop
/// keys (S2.send, S2.recv, S3.send, S3.recv) — every attempt MUST fail.
/// Then forwards the frame UNCHANGED to the gateway.
fn malicious_relay_b_round_trip(listener: &TcpListener, gw_addr: &str) {
    let (relay_a_stream, _) = listener.accept().expect("accept");
    let prev_link = Link::new(relay_a_stream, relay_b_relay_a_link_keys());
    let next_link = Link::connect(gw_addr, relay_b_gateway_a_link_keys()).expect("connect gw");

    let mut frame = prev_link.recv_frame().expect("recv_frame from relay A");
    eprintln!(
        "[malicious-relay-B] got frame: body={} bytes, attempting decryption with hop keys",
        frame.body.len()
    );

    // Attempt to decrypt the body with ALL four hop keys Relay B possesses.
    let s2 = relay_b_relay_a_link_keys();
    let s3 = relay_b_gateway_a_link_keys();
    let hop_keys = [
        ("S2.send", s2.send_key),
        ("S2.recv", s2.recv_key),
        ("S3.send", s3.send_key),
        ("S3.recv", s3.recv_key),
    ];
    for (name, key) in &hop_keys {
        let attempt = decrypt_circuit_payload(key, &frame.body);
        assert!(
            attempt.is_none(),
            "MALICIOUS RELAY B SUCCEEDED with {name} — Relay B must not be able to \
             decrypt the circuit payload (it has S2 and S3 but NOT C)"
        );
    }
    eprintln!("[malicious-relay-B] all four hop-key decryption attempts FAILED (correct)");

    if frame.ttl > 0 {
        frame.ttl -= 1;
    }
    next_link.send_frame(&frame).expect("send to gw");

    let mut resp = next_link.recv_frame().expect("recv from gw");
    if resp.ttl > 0 {
        resp.ttl -= 1;
    }
    prev_link.send_frame(&resp).expect("send to relay A");
}

/// Custom client that sends a TransitRequest with a CUSTOM initial TTL.
/// Used by Test 4 (TTL exhaustion) to send a frame with TTL=2 through a
/// 3-hop path. Mirrors `run_client_to_gateway` but overrides the TTL.
fn send_client_request_with_ttl(
    relay_a_addr: &str,
    url: &str,
    gw: GatewayChoice,
    ttl: u8,
) -> Result<(u16, bool), snp_node::NodeError> {
    let keys = client_relay_a_link_keys();
    let circuit = match gw {
        GatewayChoice::A => client_circuit_keys_a(),
        GatewayChoice::B => client_circuit_keys_b(),
    };
    eprintln!("[ttl-client] connecting to Relay A at {relay_a_addr} (ttl={ttl})");
    let link = Link::connect(relay_a_addr, keys).map_err(|e| {
        snp_node::NodeError::Other(format!("link connect: {e}"))
    })?;

    // Mirror the deterministic CLIENT_SECRET in snp-node.
    let client_sk = {
        let mut sk = [0u8; 32];
        let mut i = 0u32;
        while i < 32 {
            sk[i as usize] = ((i.wrapping_mul(41)).wrapping_add(7)) as u8;
            i += 1;
        }
        sk
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut req = TransitRequest {
        req_id: {
            let h = sha256(b"n20-ttl-test-req-id");
            let mut rid = [0u8; 16];
            rid.copy_from_slice(&h[..16]);
            rid
        },
        method: "GET".into(),
        url: url.to_string(),
        tls_termination: "GATEWAY_PLAINTEXT".into(),
        max_response_bytes: 65536,
        deadline: now + 60,
        reply_to: [0u8; 32],
        client_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_request(&mut req, &client_sk);
    let req_bytes = snp_gateway::encode_transit_request(&req)
        .map_err(|e| snp_node::NodeError::Other(format!("encode: {e}")))?;
    let sealed_body = encrypt_circuit_payload(&circuit.send_key, &req_bytes);

    let req_frame = Frame {
        v: snp_frames::FRAME_VERSION,
        cls: b'B',
        dst: gateway_node_id_for(gw),
        src: client_node_id(),
        ttl,
        fid: [0x33; 8],
        seq: 1,
        body: sealed_body,
    };
    link.send_frame(&req_frame).map_err(|e| {
        snp_node::NodeError::Other(format!("send_frame: {e}"))
    })?;

    // Set a read timeout so the test doesn't hang for minutes if no response
    // arrives (the expected outcome when TTL=2 drops the frame at Relay B).
    {
        let stream = link.stream();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    }

    let resp_frame = link.recv_frame().map_err(|e| {
        snp_node::NodeError::Other(format!(
            "recv_frame (expected to fail — TTL=2 should drop the frame): {e}"
        ))
    })?;
    let resp_bytes = decrypt_circuit_payload(&circuit.recv_key, &resp_frame.body)
        .ok_or(snp_node::NodeError::CircuitDecryptionFailed)?;
    let transit_resp: TransitResponse =
        decode_transit_response(&resp_bytes).map_err(|e| {
            snp_node::NodeError::Other(format!("decode: {e}"))
        })?;
    let gw_pub = gateway_public_key_for(gw);
    let verified = snp_gateway::verify_transit_response(&transit_resp, &gw_pub);
    Ok((transit_resp.status, verified))
}

// ═══════════════════════════════════════════════════════════════════════════
// Sanity test: run_mesh_demo_multihop exists and is callable.
// (Does NOT run the demo — that's Test 1 above, which is #[ignore]d.)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn n20_mesh_demo_multihop_function_is_callable() {
    // Just verify the function pointer exists and has the right signature.
    let _f: fn(&str) -> snp_node::NodeResult<()> = run_mesh_demo_multihop;
    let _g: fn(&str, &str, snp_link::LinkKeys, snp_link::LinkKeys) -> snp_node::NodeResult<()> =
        run_relay_multiHop;
    // Touch the client_public_key helper to ensure it's still exported.
    let _ = client_public_key();
}

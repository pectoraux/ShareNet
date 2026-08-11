//! N2.0.3 Gate K — Local HTTP gateway integration test
//!
//! End-to-end test of the gateway fetching from a LOCAL HTTP server
//! (127.0.0.1). The local HTTP server is the test's own mock — production
//! gateways MUST NOT fetch from local/private addresses (the SSRF defence
//! in `PinnedConnector::new` rejects 127.0.0.1 via `is_private_destination`).
//!
//! ## What this test verifies
//!
//! 1. **End-to-end transit through a real relay.** A Client sends a
//!    TransitRequest through a Relay to a Gateway. The Gateway fetches
//!    from a local HTTP server, signs the response, and returns it. The
//!    Client receives the response and verifies the gateway's signature.
//!    This exercises the full N2.0 multi-hop path (circuit encryption +
//!    hop encryption + frame routing) with a REAL HTTP fetch at the
//!    gateway (not a stub).
//! 2. **Body integrity.** The TransitResponse's `object_id` equals
//!    `SHA-256("Hello, World!")` — proving the gateway fetched exactly
//!    the bytes the HTTP server returned (no tampering at the relay, no
//!    truncation, no substitution).
//! 3. **Gateway failure → client failure (not a hang).** After the
//!    gateway serves one request and exits, the client's NEXT request
//!    fails fast (the relay's upstream connection is dead; the relay
//!    either sends a NACK or closes the client connection). The test
//!    enforces a 5-second timeout to catch any hang regression.
//!
//! ## SSRF bypass — TEST-ONLY
//!
//! The local HTTP server lives on `127.0.0.1`, an address that
//! [`snp_gateway::is_private_destination`] rejects. Production gateways
//! call [`snp_gateway::handle_transit_request`], which builds the
//! `PinnedConnector` via [`snp_gateway::PinnedConnector::new`] and
//! enforces the SSRF defence (invariant I18).
//!
//! This test uses [`snp_node::node::serve_one_gateway_request_with_connector_factory`]
//! with a custom connector factory that calls
//! [`snp_gateway::PinnedConnector::from_parts`] — bypassing the SSRF
//! check. The factory pins to the test's own mock HTTP server (NOT to
//! any real internal service). **Production gateways MUST NOT use this
//! escape hatch** — see the docstring on
//! `serve_one_gateway_request_with_connector_factory` for the rationale.

#![allow(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use snp_crypto::sha256;
use snp_gateway::PinnedConnector;
use snp_link::Link;

use snp_node::node::{
    serve_one_gateway_request_with_connector_factory, spawn_relay_persistent_with_counter,
    Capability, Circuit, Node, NodeIdentity, ServeOutcome,
};
use snp_node::{
    client_circuit_keys_a, gateway_a_circuit_keys, gateway_a_node_id, gateway_a_public_key,
    gateway_a_relay_b_link_keys, gateway_a_secret, relay_a_client_link_keys,
    relay_b_gateway_a_link_keys,
};

// ═══════════════════════════════════════════════════════════════════════════
// Test constants
// ═══════════════════════════════════════════════════════════════════════════

/// The deterministic body the local HTTP server returns.
const HTTP_BODY: &str = "Hello, World!";

/// The expected `object_id` of the TransitResponse (SHA-256 of the body).
fn expected_object_id() -> [u8; 32] {
    sha256(HTTP_BODY.as_bytes())
}

/// Maximum time to wait for the client's second request to fail. The test
/// uses a 5-second timeout — if the client hangs for longer than this, the
/// test fails (regression on the "no hang on gateway death" requirement).
const FAILURE_TIMEOUT: Duration = Duration::from_secs(5);

// ═══════════════════════════════════════════════════════════════════════════
// Test
// ═══════════════════════════════════════════════════════════════════════════

/// **N2.0.3 Gate K.** End-to-end local-HTTP gateway integration test.
///
/// Topology:
/// ```text
///   Client ──[S1]──> Relay ──[S3a]──> Gateway ──[HTTP]──> local HTTP server
///     └────────────[Ca]────────────────> Gateway (end-to-end circuit)
/// ```
///
/// - S1 = `CLIENT_RELAY_A_SEED` (Client ↔ Relay, using the N2.0 test seed).
/// - S3a = `RELAY_B_GATEWAY_A_SEED` (Relay ↔ Gateway, using the N2.0 test
///   seed — the relay plays the "Relay B" role for the gateway link).
/// - Ca = `CIRCUIT_SEED_A` (Client ↔ Gateway end-to-end circuit).
///
/// The relay is a SINGLE relay (not the N2.0 Relay A → Relay B chain) — Gate
/// K only needs one relay to verify the end-to-end flow. The N2.0 multi-hop
/// chain is verified by `tests/n20_multihop.rs` and `tests/n201_sessions.rs`.
///
/// Steps:
/// 1. Start a local HTTP server on an ephemeral port. The server accepts
///    connections, reads the HTTP request, and returns a deterministic
///    `200 OK` response with body `"Hello, World!"`.
/// 2. Start a Gateway (arbitrary identity — uses the N2.0 test seed
///    `gateway_a_secret`) that accepts a relay connection and serves
///    exactly ONE request via
///    `serve_one_gateway_request_with_connector_factory`. The connector
///    factory pins to `127.0.0.1:HTTP_PORT` (TEST-ONLY SSRF bypass).
/// 3. Start a Relay (single-upstream, using
///    `spawn_relay_persistent_with_counter`).
/// 4. Start a Client (arbitrary identity — uses the N2.0 test seed
///    `client_secret_key`). Pre-populate the client's circuit table with
///    the gateway's circuit keys.
/// 5. Client sends a TransitRequest for `http://test.local/` through the
///    Relay to the Gateway. The gateway fetches from the local HTTP
///    server, signs the response, and returns it.
/// 6. Verify the client's response: status=200, `object_id ==
///    SHA-256("Hello, World!")`, gateway signature verified.
/// 7. Wait for the Gateway thread to exit (it exits after serving 1
///    request).
/// 8. Client sends a SECOND TransitRequest. The gateway is dead — the
///    relay's upstream connection is closed. The client's request MUST
///    fail (not hang). The test enforces a 5-second timeout.
#[test]
fn n203_local_http_gateway_round_trip() {
    println!("=== N2.0.3 Gate K — Local HTTP gateway integration test ===");

    // ─── 1. Start the local HTTP server ───────────────────────────────────
    let http_listener = TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let http_addr = http_listener.local_addr().expect("http local_addr");
    let http_port = http_addr.port();
    println!("[test] local HTTP server at http://127.0.0.1:{http_port}/");

    let http_request_counter = Arc::new(AtomicU64::new(0));
    let http_request_counter_clone = Arc::clone(&http_request_counter);
    let http_handle = thread::spawn(move || {
        // Accept up to 8 connections (to handle retries / extra requests
        // during the failure phase). Each connection gets the same
        // deterministic response.
        for _ in 0..8 {
            let Ok((mut stream, _)) = http_listener.accept() else {
                return;
            };
            // Read the request (we don't care about its content — we always
            // return the same response).
            let mut buf = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.read(&mut buf);
            // Write the deterministic response.
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                HTTP_BODY.len(),
                HTTP_BODY,
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            http_request_counter_clone.fetch_add(1, Ordering::SeqCst);
        }
    });
    // Give the HTTP server a moment to start.
    thread::sleep(Duration::from_millis(50));

    // ─── 2. Start the Gateway ────────────────────────────────────────────
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("bind gateway");
    let gw_addr = gw_listener.local_addr().expect("gateway local_addr");
    let gw_addr_str = gw_addr.to_string();
    println!("[test] gateway transit listener at {gw_addr_str}");

    let gateway_identity = NodeIdentity::from_secret(gateway_a_secret());
    let gateway_node_id = gateway_identity.node_id;
    let gateway_sk = gateway_identity.secret_key;
    let gateway_pk = gateway_a_public_key();
    let gw_link_keys = gateway_a_relay_b_link_keys();
    let gw_circuit_keys = gateway_a_circuit_keys();

    // The gateway serves exactly ONE request, then exits (drops the
    // listener, releases the port). This simulates a gateway that dies
    // after serving one request — the client's next request MUST fail.
    let gw_handle = thread::spawn(move || {
        let mut served = 0usize;
        for stream in gw_listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gw-test] accept error: {e}");
                    break;
                }
            };
            eprintln!(
                "[gw-test] relay connected from {}",
                stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, gw_link_keys));
            let mut seen_req_ids: HashSet<[u8; 16]> = HashSet::new();
            // Serve exactly 1 request, then break (exit the gateway).
            let outcome = serve_one_gateway_request_with_connector_factory(
                &link,
                gateway_node_id,
                &gateway_sk,
                &gw_circuit_keys,
                &mut seen_req_ids,
                // TEST-ONLY connector factory: bypass the SSRF check and
                // pin to the local HTTP server. PRODUCTION GATEWAYS MUST
                // NOT DO THIS — they MUST use PinnedConnector::new (which
                // enforces the SSRF defence, invariant I18).
                &|_url: &str| {
                    eprintln!(
                        "[gw-test] TEST-ONLY SSRF bypass: pinning to local HTTP server at 127.0.0.1:{http_port}"
                    );
                    Ok(PinnedConnector::from_parts(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        "test.local".to_string(),
                        http_port,
                        "http".to_string(),
                        "/".to_string(),
                    ))
                },
            );
            match outcome {
                Ok(ServeOutcome::Continue) => {
                    served += 1;
                    eprintln!("[gw-test] served {served} request(s)");
                    // After 1 successful request, exit.
                    break;
                }
                Ok(ServeOutcome::Closed) => {
                    eprintln!("[gw-test] relay closed the connection");
                    break;
                }
                Err(e) => {
                    eprintln!("[gw-test] serve error: {e}");
                    break;
                }
            }
        }
        eprintln!("[gw-test] gateway thread exiting (listener dropped, port released)");
        served
    });
    // Give the gateway a moment to start.
    thread::sleep(Duration::from_millis(100));

    // ─── 3. Start the Relay ──────────────────────────────────────────────
    //
    // The relay plays TWO roles:
    // - "Relay A" role for the client connection (responder of the
    //   Client↔RelayA link, using `relay_a_client_link_keys`).
    // - "Relay B" role for the gateway connection (initiator of the
    //   RelayB↔GatewayA link, using `relay_b_gateway_a_link_keys`).
    //
    // This is fine — a relay just needs two sets of hop keys (one per
    // link). The N2.0 multi-hop test in n20_multihop.rs uses two separate
    // relays (Relay A and Relay B); this single-relay topology is the
    // minimal end-to-end test for Gate K.
    let relay_listener = TcpListener::bind("127.0.0.1:0").expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay local_addr");
    let relay_addr_str = relay_addr.to_string();
    drop(relay_listener);
    println!("[test] relay at {relay_addr_str}");

    let (relay_handle, _relay_counter) = spawn_relay_persistent_with_counter(
        &relay_addr_str,
        &gw_addr_str,
        relay_a_client_link_keys(),    // prev hop (client → relay)
        relay_b_gateway_a_link_keys(), // next hop (relay → gateway)
    );
    // Give the relay a moment to start.
    thread::sleep(Duration::from_millis(100));

    // ─── 4. Start the Client ─────────────────────────────────────────────
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![Capability::Client],
        relay_addr_str.clone(),
    );
    // Pre-populate the client's circuit table. In production, the circuit
    // keys come from the SNP-IK/0.1 handshake + the client↔gateway X25519
    // circuit DH. For this test, we use the deterministic N2.0 test seed
    // (CIRCUIT_SEED_A) — the same seed the gateway uses
    // (gateway_a_circuit_keys).
    {
        let mut circuits = client_node.circuits.lock().unwrap();
        circuits.insert(
            gateway_node_id,
            Circuit::new(gateway_node_id, gateway_pk, client_circuit_keys_a()),
        );
    }

    // ─── 5. Client sends request 1 (should succeed) ──────────────────────
    println!();
    println!("=== Request 1: Client → Relay → Gateway → local HTTP server ===");
    let url = "http://test.local/";
    let transit_resp = client_node
        .send_request_via_gateway_full(url, &gateway_node_id)
        .expect("Request 1 should succeed (gateway is alive)");
    println!(
        "[test] Request 1 OK: status={} object_id={} gateway_sig_verified",
        transit_resp.status,
        hex_short(&transit_resp.object_id)
    );

    // ─── 6. Verify the response ──────────────────────────────────────────
    assert_eq!(transit_resp.status, 200, "Request 1 status must be 200");
    assert_eq!(
        transit_resp.object_id,
        expected_object_id(),
        "Request 1 object_id must equal SHA-256(\"{}\") — proves the gateway fetched the body byte-for-byte from the local HTTP server (no tampering at the relay)",
        HTTP_BODY,
    );
    // `send_request_via_gateway_full` already verifies the gateway signature
    // (it returns NodeError::GatewaySignatureFailed on mismatch), so reaching
    // this point means the signature verified. We re-verify here for
    // explicitness and to document the invariant.
    assert!(
        snp_gateway::verify_transit_response(&transit_resp, &gateway_pk),
        "Request 1 gateway signature MUST verify (re-check)"
    );
    println!(
        "[test] Request 1 verified: status=200, body object_id matches SHA-256(\"{HTTP_BODY}\"), gateway signature OK"
    );

    // Verify the HTTP server actually got hit exactly once.
    let http_hits = http_request_counter.load(Ordering::SeqCst);
    assert_eq!(
        http_hits, 1,
        "HTTP server should have been hit exactly once, got {http_hits}"
    );

    // ─── 7. Wait for the gateway thread to exit ──────────────────────────
    println!();
    println!("=== Waiting for gateway thread to exit (simulating gateway death) ===");
    // The gateway thread exits after serving 1 request. We use a channel
    // to detect completion with a timeout.
    let (gw_done_tx, gw_done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let served_count = gw_handle.join().unwrap_or(0);
        let _ = gw_done_tx.send(served_count);
    });
    let gw_exit_result = gw_done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("gateway thread should exit within 3 seconds (not hang)");
    assert_eq!(
        gw_exit_result, 1,
        "gateway should have served exactly 1 request before exiting, got {gw_exit_result}"
    );
    println!(
        "[test] gateway thread exited cleanly after serving {gw_exit_result} request(s)"
    );

    // ─── 8. Client sends request 2 (should FAIL — gateway is dead) ───────
    println!();
    println!("=== Request 2: gateway is DEAD — client MUST fail (not hang) ===");
    let start = std::time::Instant::now();
    // Mark the circuit inactive-failover path: send_request_via_gateway_full
    // marks the circuit inactive on UpstreamFailure. But the circuit may
    // still be marked active from request 1. We forcibly re-activate it
    // here so the second request actually tries the gateway (instead of
    // short-circuiting with "circuit is inactive"). This simulates a client
    // that doesn't yet know the gateway is dead.
    {
        let mut circuits = client_node.circuits.lock().unwrap();
        if let Some(c) = circuits.get_mut(&gateway_node_id) {
            c.active = true;
        }
    }
    let result2 = client_node.send_request_via_gateway_full(url, &gateway_node_id);
    let elapsed = start.elapsed();
    assert!(
        result2.is_err(),
        "Request 2 MUST fail (gateway is dead). Got Ok: {result2:?}",
    );
    let err = result2.unwrap_err();
    println!(
        "[test] Request 2 failed as expected after {:.2}s: {err}",
        elapsed.as_secs_f64()
    );
    assert!(
        elapsed < FAILURE_TIMEOUT,
        "Request 2 must fail within {:?} (not hang). Took {:.2}s.",
        FAILURE_TIMEOUT,
        elapsed.as_secs_f64(),
    );

    // ─── Clean up ────────────────────────────────────────────────────────
    println!();
    println!("=== N2.0.3 Gate K PASSED ===");
    println!("  - End-to-end transit through a real relay: OK");
    println!("  - Body integrity (object_id == SHA-256(\"{HTTP_BODY}\")): OK");
    println!("  - Gateway signature verification: OK");
    println!(
        "  - Gateway death → client failure (not hang, <{:.2}s): OK",
        elapsed.as_secs_f64()
    );

    // Detach the relay and HTTP server threads (they're infinite loops).
    std::mem::forget(relay_handle);
    std::mem::forget(http_handle);
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Format the first 8 bytes of a byte slice as hex (for logging).
fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}

// Silence unused-import warnings for imports that are used only in
// conditional paths or for type inference.
#[allow(dead_code)]
fn _silence_unused_imports() {
    let _ = gateway_a_node_id();
}

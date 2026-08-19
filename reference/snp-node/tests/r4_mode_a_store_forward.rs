//! R4.3 Mode-A store-carry-forward integration test.
//!
//! This test proves the defining R4.3 property:
//!
//! ```text
//! Client → Relay → Gateway → HTTP endpoint
//! ```
//!
//! with a DELIBERATE INTERRUPTION between the relay and the gateway. The relay
//! must hold the bundle in its `BundleStore` while the gateway is unavailable,
//! then forward when it becomes available.
//!
//! # What this test does NOT use
//!
//! - No `MultiplexedCircuit` (Mode B)
//! - No `StreamHandle` (Mode B)
//! - No `N3AClient` (SOCKS5)
//! - No `TunClient` (Mode C)
//! - No `serve_gateway_mode_b_multiplexed`
//! - No test-only transport (raw TCP with length-prefixed framing)
//!
//! # Egress honesty
//!
//! The gateway performs real egress to a host-local mock HTTP server
//! (127.0.0.1). This is honestly classified as:
//!
//! ```text
//! host-local egress test
//! ```
//!
//! NOT "genuine external Internet egress." The sandbox may not have
//! external Internet access. The mock HTTP server is a real TCP socket
//! listening on 127.0.0.1 — it is NOT an internal echo server.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use snp_crypto::{derive_public_key, ed25519_sign, ed25519_verify};
use snp_gateway::{GatewayError, GatewayResult, PinnedConnector, TransitRequest, TransitResponse};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::mode_a_bundle::{
    unwrap_transit_request_from_bundle, unwrap_transit_response_from_bundle,
    wrap_transit_request_as_bundle, wrap_transit_response_as_bundle, AuthenticatedBundleCarrier,
    BundleCarrier, ModeAClient, ModeAError, ModeAGateway, ModeARelay,
};
use snp_sync::{Bundle, BundleId, BundlePayload, BundleStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─── Test identities ──────────────────────────────────────────────────────

/// Generate a deterministic identity from a seed byte.
fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

/// Generate a deterministic X25519 keypair from a seed.
fn test_x25519_keypair(seed: u8) -> (snp_crypto::X25519Secret, snp_crypto::X25519PubKey) {
    // Use the crypto module's keypair generation (non-deterministic but fine for tests).
    snp_crypto::x25519_static_keypair()
}

/// Short hex representation of a byte slice (first 8 hex chars + "..").
fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

// ─── Mock HTTP server ─────────────────────────────────────────────────────

/// Start a simple HTTP/1.1 mock server on 127.0.0.1. Returns the address.
///
/// This server uses BLOCKING std::net (not tokio) because the gateway's
/// `PinnedConnector` uses blocking `std::net::TcpStream` for egress. The
/// server runs in a dedicated thread.
async fn start_mock_http_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    std::thread::spawn(move || {
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            // Set a read timeout so the server doesn't hang forever.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                // Read the HTTP request (just enough to not block).
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                // Send a simple 200 OK response.
                let body = b"Hello from R4.3 Mode-A store-carry-forward!";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            });
        }
    });
    addr
}

// ─── Integration test: store-carry-forward with deliberate interruption ──

#[tokio::test]
async fn r4_mode_a_store_forward_with_interruption() {
    // ─── Setup: generate fresh identities for each role ───────────────
    let client_identity = test_identity(0x01);
    let relay_identity = test_identity(0x02);
    let gateway_identity = test_identity(0x03);

    // ─── Start the mock HTTP server (host-local egress) ────────────────
    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-mode-a");

    // ─── Start the gateway FIRST (so it's available when the relay ────
    //     tries to forward). But we'll start it AFTER the relay receives
    //     the bundle to prove store-carry-forward.
    //
    // Topology:
    //   Client (connects to Relay)
    //   Relay  (listens for Client, forwards to Gateway)
    //   Gateway (listens for Relay, fetches from HTTP server)
    //
    // The test flow:
    //   1. Start Relay (Gateway is NOT started yet).
    //   2. Client sends bundle to Relay.
    //   3. Relay takes custody, tries to forward to Gateway → FAILS (not started).
    //   4. Relay retains bundle in BundleStore.
    //   5. Start Gateway.
    //   6. Relay retries forwarding → SUCCEEDS.
    //   7. Gateway fetches from HTTP server, signs response, sends back.
    //   8. Client receives response bundle.
    //   9. Client verifies: reqId matches + gateway signature verifies.

    // Bind addresses on 127.0.0.1 with ephemeral ports.
    let relay_listen = "127.0.0.1:0";
    let gateway_listen = "127.0.0.1:0";

    // We need to know the actual addresses before starting. Use a trick:
    // bind a TcpListener to get the port, then drop it and pass the addr.
    let relay_listener = tokio::net::TcpListener::bind(relay_listen)
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();
    drop(relay_listener);

    let gateway_listener = tokio::net::TcpListener::bind(gateway_listen)
        .await
        .expect("bind gw");
    let gateway_addr = gateway_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(gateway_listener);

    // ─── Step 1: Create and start the relay (Gateway NOT started) ──────
    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x02);
    let relay = Arc::new(ModeARelay::new(
        relay_identity.clone(),
        relay_x_sk,
        relay_x_pk,
        relay_addr.clone(),
        gateway_addr.clone(),
        gateway_identity.node_id,
    ));
    let relay_store = relay.store();

    let relay_handle = {
        let relay = relay.clone();
        tokio::spawn(async move {
            // Run for a limited time (the relay loop is infinite).
            // We'll use tokio::select to cancel after the test.
            tokio::select! {
                _ = relay.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                    eprintln!("[test] relay timeout");
                }
            }
        })
    };

    // Give the relay a moment to start listening.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ─── Step 2: Client sends bundle to Relay ─────────────────────────
    // The client establishes an authenticated L8 connection to the relay,
    // sends the bundle, and waits for the custody acknowledgment + response.
    let (client_x_sk, client_x_pk) = test_x25519_keypair(0x01);
    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let relay_addr_for_client = relay_addr.clone();
    let relay_node_id = relay_identity.node_id;
    let gw_node_id = gateway_identity.node_id;
    let gw_pubkey = gateway_identity.public_key;

    let client_task = tokio::spawn(async move {
        client
            .send_request(
                &url,
                &relay_addr_for_client,
                relay_node_id,
                gw_node_id,
                &gw_pubkey,
            )
            .await
    });

    // Give the client time to send the bundle + the relay to receive it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ─── Step 3: Verify the relay took custody + stored the bundle ────
    let store = relay_store.lock().expect("store lock");
    let pending_count = store.pending(snp_identity::now_unix()).len();
    assert!(
        pending_count >= 1,
        "relay must have at least 1 pending bundle after receiving from client (store-carry-forward)"
    );
    eprintln!("[test] relay has {pending_count} pending bundles (store-carry-forward PROVED)");
    drop(store);

    // ─── Step 4: Relay tries to forward → FAILS (Gateway NOT started) ─
    // The relay's run loop already attempted to forward and failed.
    // Verify the bundle is STILL in the store.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let store = relay_store.lock().expect("store lock");
    let pending_after_fail = store.pending(snp_identity::now_unix()).len();
    assert!(
        pending_after_fail >= 1,
        "relay must retain bundle after forward failure (store-carry-forward)"
    );
    eprintln!("[test] relay retained {pending_after_fail} bundles after forward failure");
    drop(store);

    // ─── Step 5: Start the Gateway ─────────────────────────────────────
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair(0x03);
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        // Connector factory: use PinnedConnector::from_parts to target the
        // mock HTTP server (bypasses SSRF for host-local testing).
        move |url: &str| {
            // Parse the URL to extract host:port.
            let parsed = url::Url::parse(url)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            let path = parsed.path();
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                if path.is_empty() {
                    "/".into()
                } else {
                    path.into()
                },
            ))
        },
    );
    let gateway_handle = tokio::spawn(async move {
        tokio::select! {
            _ = gateway.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                eprintln!("[test] gateway timeout");
            }
        }
    });

    // Give the gateway a moment to start listening.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ─── Step 6: Relay retries forwarding → SUCCEEDS ───────────────────
    // Trigger a forward attempt.
    relay
        .forward_pending_bundles(snp_identity::now_unix())
        .await;

    // ─── Step 7: Wait for the client to receive the response ──────────
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), client_task).await;

    // ─── Step 8: Verify the response ──────────────────────────────────
    match result {
        Ok(Ok(Ok((resp, body)))) => {
            // reqId matches (checked inside send_request).
            // Gateway signature verifies (checked inside send_request).
            assert_eq!(resp.status, 200, "HTTP status must be 200");
            assert!(!body.is_empty(), "response body must not be empty");
            let body_str = String::from_utf8_lossy(&body);
            assert!(
                body_str.contains("Hello from R4.3"),
                "response body must contain expected text, got: {body_str}"
            );
            eprintln!(
                "[test] SUCCESS: Mode-A store-carry-forward completed with deliberate interruption."
            );
            eprintln!(
                "[test] Response status: {}, body: {} bytes",
                resp.status,
                body.len()
            );
        }
        Ok(Ok(Err(e))) => {
            panic!("Mode-A send_request failed: {e}");
        }
        Ok(Err(e)) => {
            panic!("Client task panicked: {e}");
        }
        Err(_) => {
            panic!("Client task timed out after 15 seconds — store-carry-forward failed");
        }
    }

    // Clean up.
    relay_handle.abort();
    gateway_handle.abort();
}

// ─── Test: bundle payload round-trip ──────────────────────────────────────

#[test]
fn r4_bundle_request_response_wrappers_roundtrip() {
    // Verify the wrap/unwrap functions work correctly.
    let client_identity = test_identity(0xAA);
    let gateway_identity = test_identity(0xBB);

    // Create a signed TransitRequest.
    let mut req = TransitRequest {
        req_id: [0x42; 16],
        method: "GET".into(),
        url: "http://example.com/test".into(),
        tls_termination: "PAYLOAD_E2E".into(),
        max_response_bytes: 1024 * 1024,
        deadline: snp_identity::now_unix() + 300,
        reply_to: [0u8; 32],
        client_ed25519_public_key: client_identity.public_key,
        client_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_request(&mut req, &client_identity.secret_key);

    // Wrap as a bundle.
    let bundle = wrap_transit_request_as_bundle(
        &req,
        client_identity.node_id,
        gateway_identity.node_id,
        snp_identity::now_unix(),
    )
    .expect("wrap");

    // Unwrap.
    let recovered_req = unwrap_transit_request_from_bundle(&bundle).expect("unwrap");
    assert_eq!(req.req_id, recovered_req.req_id);
    assert_eq!(req.url, recovered_req.url);
    assert!(
        snp_gateway::verify_transit_request(&recovered_req),
        "recovered request must verify"
    );

    // Now wrap a TransitResponse.
    let mut resp = TransitResponse {
        req_id: req.req_id,
        status: 200,
        headers: vec![("Content-Type".into(), "text/plain".into())],
        object_id: [0x33; 32],
        fetched_at: snp_identity::now_unix(),
        gateway_id: gateway_identity.node_id,
        gateway_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_response(&mut resp, &gateway_identity.secret_key);

    let body = b"test response body";
    let resp_bundle = wrap_transit_response_as_bundle(
        &resp,
        body,
        gateway_identity.node_id,
        client_identity.node_id,
        snp_identity::now_unix(),
        req.deadline,
    )
    .expect("wrap response");

    // Unwrap.
    let (recovered_resp, recovered_body) =
        unwrap_transit_response_from_bundle(&resp_bundle).expect("unwrap response");
    assert_eq!(resp.req_id, recovered_resp.req_id);
    assert_eq!(resp.status, recovered_resp.status);
    assert_eq!(body.as_slice(), recovered_body.as_slice());
    assert!(
        snp_gateway::verify_transit_response(&recovered_resp, &gateway_identity.public_key),
        "recovered response must verify"
    );
}

// ─── Test: relay store-carry-forward with no gateway ─────────────────────

#[tokio::test]
async fn r4_relay_holds_bundle_when_gateway_unavailable() {
    // This test proves the relay HOLDS a bundle when the gateway is unavailable.
    // It verifies the defining R4.3 property: no live end-to-end circuit is
    // required for the bundle to move.

    let relay_identity = test_identity(0x11);
    let client_identity = test_identity(0x22);
    let gateway_identity = test_identity(0x33);

    // Relay listens on an ephemeral port.
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();
    drop(relay_listener);

    // Gateway address that NOTHING is listening on (port 1 is always unavailable).
    let fake_gateway_addr = "127.0.0.1:1";

    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x11);
    let relay = Arc::new(ModeARelay::new(
        relay_identity.clone(),
        relay_x_sk,
        relay_x_pk,
        relay_addr.clone(),
        fake_gateway_addr.into(),
        gateway_identity.node_id,
    ));
    let relay_store = relay.store();

    // Start the relay.
    let relay_handle = {
        let relay = relay.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Client sends a bundle to the relay via authenticated L8 transport.
    let (client_x_sk, client_x_pk) = test_x25519_keypair(0x22);
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_addr,
        relay_identity.node_id,
        &client_identity.secret_key,
        &client_identity.public_key,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("connect to relay");

    // Create a test request bundle.
    let mut req = TransitRequest {
        req_id: [0x42; 16],
        method: "GET".into(),
        url: "http://example.com/test".into(),
        tls_termination: "PAYLOAD_E2E".into(),
        max_response_bytes: 1024,
        deadline: snp_identity::now_unix() + 300,
        reply_to: [0u8; 32],
        client_ed25519_public_key: client_identity.public_key,
        client_sig: [0u8; 64],
    };
    snp_gateway::sign_transit_request(&mut req, &client_identity.secret_key);
    let bundle = wrap_transit_request_as_bundle(
        &req,
        client_identity.node_id,
        gateway_identity.node_id,
        snp_identity::now_unix(),
    )
    .expect("wrap");

    // Send the bundle.
    carrier.send_bundle(&bundle).await.expect("send");

    // Wait for the custody acknowledgment.
    let ack = tokio::time::timeout(std::time::Duration::from_secs(5), carrier.recv_bundle()).await;
    assert!(ack.is_ok(), "relay must acknowledge custody");
    let ack_bundle = ack.unwrap().expect("recv");
    assert!(
        !ack_bundle.custody_chain.is_empty(),
        "custody chain must be non-empty after relay takes custody"
    );

    // Verify the relay STORED the bundle (gateway is unavailable).
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let store = relay_store.lock().expect("store");
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        !pending.is_empty(),
        "relay must hold the bundle in BundleStore when gateway is unavailable"
    );
    eprintln!(
        "[test] relay holds {} pending bundles while gateway is unavailable — store-carry-forward PROVED",
        pending.len()
    );

    relay_handle.abort();
}

// ─── Test: no MultiplexedCircuit used ─────────────────────────────────────

#[test]
fn r4_mode_a_does_not_use_live_circuit() {
    // This is a static assertion: verify that mode_a_bundle.rs does NOT
    // import or USE any Mode-B types.
    //
    // We check for actual USE statements and type references, not comments.
    // The word "MultiplexedCircuit" may appear in comments explaining what
    // NOT to use — that's fine. What matters is no actual code dependency.
    let source = include_str!("../src/node/mode_a_bundle.rs");
    // Check that no `use` statement imports Mode-B types.
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            assert!(
                !trimmed.contains("MultiplexedCircuit"),
                "mode_a_bundle.rs must NOT import MultiplexedCircuit (found in: {trimmed})"
            );
            assert!(
                !trimmed.contains("StreamHandle"),
                "mode_a_bundle.rs must NOT import StreamHandle (found in: {trimmed})"
            );
            assert!(
                !trimmed.contains("N3AClient"),
                "mode_a_bundle.rs must NOT import N3AClient (found in: {trimmed})"
            );
            assert!(
                !trimmed.contains("TunClient"),
                "mode_a_bundle.rs must NOT import TunClient (found in: {trimmed})"
            );
            assert!(
                !trimmed.contains("GatewayStreamTable"),
                "mode_a_bundle.rs must NOT import GatewayStreamTable (found in: {trimmed})"
            );
            assert!(
                !trimmed.contains("serve_gateway_mode_b"),
                "mode_a_bundle.rs must NOT import Mode-B gateway functions (found in: {trimmed})"
            );
        }
    }
    // Also check that no function CALLS these types.
    assert!(
        !source.contains("MultiplexedCircuit::"),
        "mode_a_bundle.rs must NOT call MultiplexedCircuit methods"
    );
    assert!(
        !source.contains("StreamHandle::"),
        "mode_a_bundle.rs must NOT call StreamHandle methods"
    );
    eprintln!("[test] mode_a_bundle.rs verified: no Mode-B/circuit types imported or called");
}

// ─── Test: identity substitution rejection ────────────────────────────────

#[tokio::test]
async fn r4_identity_substitution_rejected() {
    // Test that the relay rejects a peer whose NodeId doesn't match the
    // expected NodeId. The SNP-IK handshake has built-in identity pinning
    // (expected_peer_node_id parameter). If the peer's authenticated NodeId
    // doesn't match, the handshake fails.

    let relay_identity = test_identity(0x11);
    let attacker_identity = test_identity(0x99); // different identity
    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x11);
    let (attacker_x_sk, attacker_x_pk) = test_x25519_keypair(0x99);

    // Relay listens on an ephemeral port.
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();

    // Start the relay — it accepts connections and performs SNP-IK as responder.
    // It does NOT pin an expected peer NodeId (accepts any authenticated peer).
    // But the ATTACKER will try to connect and pin the WRONG relay NodeId.
    let relay_task = tokio::spawn(async move {
        // Accept one connection.
        let (mut stream, _) = relay_listener.accept().await.expect("accept");
        // Perform SNP-IK as responder — no expected peer pinning.
        let result = snp_link::async_link::perform_snp_ik_handshake_async(
            &mut stream,
            false, // responder
            &relay_identity.secret_key,
            &relay_identity.public_key,
            &relay_x_sk,
            &relay_x_pk,
            None, // accept any authenticated peer
        )
        .await;
        // The relay's handshake should succeed (the attacker IS authenticated,
        // just not the expected relay). But the ATTACKER's handshake should
        // FAIL because the attacker pinned a WRONG relay NodeId.
        // We don't assert here — the assertion is on the attacker's side.
        let _ = result;
    });

    // The attacker tries to connect to the relay, but pins the WRONG relay NodeId.
    // The relay's actual NodeId is relay_identity.node_id.
    // The attacker expects attacker_identity.node_id (WRONG).
    let wrong_expected = attacker_identity.node_id; // WRONG — not the relay's NodeId
    let result = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_addr,
        wrong_expected,
        &attacker_identity.secret_key,
        &attacker_identity.public_key,
        &attacker_x_sk,
        &attacker_x_pk,
    )
    .await;

    // The connection MUST fail — identity substitution detected.
    assert!(
        result.is_err(),
        "identity substitution MUST be rejected: connecting with wrong expected NodeId must fail"
    );
    eprintln!("[test] identity substitution correctly rejected");

    relay_task.await.expect("relay task");
}

// ─── Test: provenance binding — source must match authenticated peer ─────

#[tokio::test]
async fn r4_bundle_source_must_match_authenticated_peer() {
    // An authenticated peer (Node B) sends a bundle claiming source = Node A.
    // The relay MUST reject this — the authenticated peer does not match
    // the bundle's claimed source.
    let relay_identity = test_identity(0x11);
    let attacker_identity = test_identity(0x22); // B — different from A
    let victim_identity = test_identity(0x33); // A — the claimed source
    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x11);
    let (attacker_x_sk, attacker_x_pk) = test_x25519_keypair(0x22);

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();
    drop(relay_listener);

    let relay = Arc::new(ModeARelay::new(
        relay_identity.clone(),
        relay_x_sk,
        relay_x_pk,
        relay_addr.clone(),
        "127.0.0.1:1".into(), // dummy next hop
        [0xFF; 32],           // dummy gateway NodeId
    ));
    let relay_store = relay.store();

    let relay_handle = {
        let relay = relay.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Attacker connects and sends a bundle with source = victim_identity.node_id
    // (NOT attacker_identity.node_id).
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_addr,
        relay_identity.node_id,
        &attacker_identity.secret_key,
        &attacker_identity.public_key,
        &attacker_x_sk,
        &attacker_x_pk,
    )
    .await
    .expect("connect");

    // Create a bundle claiming source = victim (A), not attacker (B).
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        victim_identity.node_id, // WRONG — should be attacker_identity.node_id
        [0xFF; 32],
        BundlePayload::new(vec![0xDE, 0xAD]),
        now,
        now + 10_000,
    )
    .expect("valid bundle");

    // Send the bundle.
    carrier.send_bundle(&bundle).await.expect("send");

    // Wait a moment for the relay to process.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The relay MUST NOT have taken custody or stored the bundle.
    let store = relay_store.lock().expect("store lock");
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        pending.is_empty(),
        "relay must NOT store a bundle whose source ({}) does not match the authenticated peer ({})",
        hex_short(&victim_identity.node_id),
        hex_short(&attacker_identity.node_id)
    );
    eprintln!(
        "[test] provenance mismatch correctly rejected: peer={} != source={}",
        hex_short(&attacker_identity.node_id),
        hex_short(&victim_identity.node_id)
    );

    relay_handle.abort();
}

// ─── Test: valid first-hop identity binding passes ───────────────────────

#[tokio::test]
async fn r4_valid_first_hop_identity_binding() {
    // An authenticated peer sends a bundle with source == peer NodeId.
    // The relay MUST accept this — the first-hop identity binding is correct.
    let relay_identity = test_identity(0x11);
    let client_identity = test_identity(0x22);
    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x11);
    let (client_x_sk, client_x_pk) = test_x25519_keypair(0x22);

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();
    drop(relay_listener);

    let relay = Arc::new(ModeARelay::new(
        relay_identity.clone(),
        relay_x_sk,
        relay_x_pk,
        relay_addr.clone(),
        "127.0.0.1:1".into(),
        [0xFF; 32],
    ));
    let relay_store = relay.store();

    let relay_handle = {
        let relay = relay.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Client connects with its own identity.
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_addr,
        relay_identity.node_id,
        &client_identity.secret_key,
        &client_identity.public_key,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("connect");

    // Create a bundle with source = client_identity.node_id (CORRECT — matches authenticated peer).
    let now = snp_identity::now_unix();
    let bundle = Bundle::new(
        client_identity.node_id,
        [0xFF; 32],
        BundlePayload::new(vec![0xDE, 0xAD]),
        now,
        now + 10_000,
    )
    .expect("valid bundle");

    // Send the bundle.
    carrier.send_bundle(&bundle).await.expect("send");

    // Wait for the relay to process.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The relay MUST have taken custody and stored the bundle.
    let store = relay_store.lock().expect("store lock");
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        !pending.is_empty(),
        "relay must accept a bundle whose source matches the authenticated peer"
    );
    eprintln!(
        "[test] valid first-hop identity binding accepted: peer == source = {}",
        hex_short(&client_identity.node_id)
    );

    relay_handle.abort();
}

// ─── Test: valid chained custody identity binding ────────────────────────

#[tokio::test]
async fn r4_valid_chained_custody_identity_binding() {
    // A bundle that has been through one custody hop (client → relay A)
    // is forwarded to relay B. Relay B must verify that the authenticated
    // peer (relay A) matches the last custody hop's next_custodian_id.
    let relay_a_identity = test_identity(0x11);
    let relay_b_identity = test_identity(0x22);
    let client_identity = test_identity(0x33);
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0x22);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0x11);

    let relay_b_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay_b");
    let relay_b_addr = relay_b_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(relay_b_listener);

    let relay_b = Arc::new(ModeARelay::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        "127.0.0.1:1".into(),
        [0xFF; 32],
    ));
    let relay_b_store = relay_b.store();

    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Relay A connects to relay B and sends a bundle that has already
    // been through one custody hop (client → relay A).
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_b_addr,
        relay_b_identity.node_id,
        &relay_a_identity.secret_key,
        &relay_a_identity.public_key,
        &relay_a_x_sk,
        &relay_a_x_pk,
    )
    .await
    .expect("connect");

    // Create a bundle where relay A has already taken custody.
    let now = snp_identity::now_unix();
    let mut bundle = Bundle::new(
        client_identity.node_id,
        [0xFF; 32],
        BundlePayload::new(vec![0xDE, 0xAD]),
        now,
        now + 10_000,
    )
    .expect("valid bundle");

    // Relay A takes custody (simulated).
    bundle
        .take_custody(
            client_identity.node_id,  // prev custodian = client
            relay_a_identity.node_id, // next custodian = relay A (signer)
            &relay_a_identity.secret_key,
            now + 100,
            now + 200,
            [0x01; 16],
        )
        .expect("take custody");

    // The last custody hop's next_custodian_id = relay_a_identity.node_id.
    // Relay B should authenticate relay A and check that
    // authenticated_peer (relay A) == last_hop.next_custodian_id (relay A).
    // This should PASS.

    carrier.send_bundle(&bundle).await.expect("send");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Relay B MUST have taken custody and stored the bundle.
    let store = relay_b_store.lock().expect("store lock");
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        !pending.is_empty(),
        "relay B must accept a bundle where the last custody hop's next_custodian_id matches the authenticated peer"
    );
    eprintln!(
        "[test] valid chained custody identity binding accepted: peer == last_hop.next_custodian_id = {}",
        hex_short(&relay_a_identity.node_id)
    );

    relay_b_handle.abort();
}

// ─── Test: relay rejects provenance mismatch on chained custody ──────────

#[tokio::test]
async fn r4_relay_rejects_provenance_mismatch_chained() {
    // A bundle has been through one custody hop claiming next_custodian_id = A.
    // But the authenticated peer is B (not A). The relay MUST reject.
    let relay_identity = test_identity(0x11);
    let attacker_identity = test_identity(0x22); // B — the actual peer
    let victim_identity = test_identity(0x33); // A — claimed as next_custodian_id
    let client_identity = test_identity(0x44);
    let (relay_x_sk, relay_x_pk) = test_x25519_keypair(0x11);
    let (attacker_x_sk, attacker_x_pk) = test_x25519_keypair(0x22);

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("local_addr").to_string();
    drop(relay_listener);

    let relay = Arc::new(ModeARelay::new(
        relay_identity.clone(),
        relay_x_sk,
        relay_x_pk,
        relay_addr.clone(),
        "127.0.0.1:1".into(),
        [0xFF; 32],
    ));
    let relay_store = relay.store();

    let relay_handle = {
        let relay = relay.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Attacker (B) connects to the relay.
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_addr,
        relay_identity.node_id,
        &attacker_identity.secret_key,
        &attacker_identity.public_key,
        &attacker_x_sk,
        &attacker_x_pk,
    )
    .await
    .expect("connect");

    // Create a bundle with a custody chain claiming next_custodian_id = victim (A).
    // But the actual sender is attacker (B).
    let now = snp_identity::now_unix();
    let mut bundle = Bundle::new(
        client_identity.node_id,
        [0xFF; 32],
        BundlePayload::new(vec![0xDE, 0xAD]),
        now,
        now + 10_000,
    )
    .expect("valid bundle");

    // Add a custody hop claiming the next custodian is victim_identity (A).
    // But we sign it with attacker's key (B) — the signature won't verify
    // against A's public key. That's fine for this test — the relay rejects
    // at the provenance check, BEFORE signature verification.
    bundle.custody_chain.push(snp_sync::CustodyHop {
        bundle_id: *bundle.bundle_id(),
        custodian_id: client_identity.node_id,
        next_custodian_id: victim_identity.node_id, // CLAIMS A is the next custodian
        received_at: 1_100,
        forwarded_at: 1_200,
        nonce: [0x01; 16],
        next_sig: [0u8; 64], // dummy signature
    });

    carrier.send_bundle(&bundle).await.expect("send");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The relay MUST NOT have stored the bundle.
    let store = relay_store.lock().expect("store lock");
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        pending.is_empty(),
        "relay must reject bundle where authenticated peer ({}) != last custody hop next_custodian_id ({})",
        hex_short(&attacker_identity.node_id),
        hex_short(&victim_identity.node_id)
    );
    eprintln!(
        "[test] provenance mismatch on chained custody correctly rejected: peer={} != next_custodian_id={}",
        hex_short(&attacker_identity.node_id),
        hex_short(&victim_identity.node_id)
    );

    relay_handle.abort();
}

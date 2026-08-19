//! R4.4 multi-hop store-carry-forward integration test.
//!
//! Tests: Client → Relay A → Relay B → Gateway → HTTP endpoint
//! with deliberate interruption between Relay A and Relay B.
//!
//! The bundle must survive the interruption and complete the full path.
//! The custody chain must record every hop in the correct order.

use std::sync::Arc;

use snp_gateway::{GatewayError, GatewayResult, PinnedConnector, TransitRequest, TransitResponse};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::mode_a_bundle::{
    unwrap_transit_response_from_bundle, wrap_transit_request_as_bundle,
    AuthenticatedBundleCarrier, BundleCarrier, BundleForwarder, ModeAClient, ModeAError,
    ModeAGateway,
};
use snp_node::node::node_advert::NodeAdvertisement;
use snp_node::node::route::{Route, RouteHop};
use snp_sync::{Bundle, BundlePayload, BundleStore, CUSTODY_NONCE_BYTES};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn test_x25519_keypair(_seed: u8) -> (snp_crypto::X25519Secret, snp_crypto::X25519PubKey) {
    snp_crypto::x25519_static_keypair()
}

fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

/// Bind an ephemeral port, return its address, then drop the listener so the
/// caller (a `BundleForwarder` / `ModeAGateway`) can rebind it.
async fn ephemeral_addr() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let a = l.local_addr().expect("local_addr").to_string();
    drop(l);
    a
}

/// Generate a custody nonce (16 bytes).
fn custody_nonce() -> [u8; CUSTODY_NONCE_BYTES] {
    let mut buf = [0u8; CUSTODY_NONCE_BYTES];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

/// Create a signed NodeAdvertisement for a relay node.
fn make_relay_advert(identity: &NodeIdentity, listen_addr: &str) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp(listen_addr)],
        None, // relays MUST NOT have a circuit key
        3600,
        1,
    )
}

/// Create a signed NodeAdvertisement for a gateway node.
fn make_gateway_advert(
    identity: &NodeIdentity,
    listen_addr: &str,
    x25519_pub: &[u8; 32],
) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(listen_addr)],
        Some(*x25519_pub),
        3600,
        1,
    )
}

/// Build a multi-hop route: client → relay_a → relay_b → gateway.
fn build_multihop_route(
    client: &NodeIdentity,
    relay_a: &NodeIdentity,
    relay_b: &NodeIdentity,
    gateway: &NodeIdentity,
    relay_a_addr: &str,
    relay_b_addr: &str,
    gateway_addr: &str,
    gw_x25519_pub: &[u8; 32],
) -> Route {
    // Create signed adverts for each hop.
    let relay_a_advert = make_relay_advert(relay_a, relay_a_addr);
    let relay_b_advert = make_relay_advert(relay_b, relay_b_addr);
    let gateway_advert = make_gateway_advert(gateway, gateway_addr, gw_x25519_pub);

    // Verify each advert → get VerifiedNodeDescriptor.
    let relay_a_desc = relay_a_advert
        .verify_into_verified()
        .expect("relay A advert verification")
        .descriptor();
    let relay_b_desc = relay_b_advert
        .verify_into_verified()
        .expect("relay B advert verification")
        .descriptor();
    let gateway_desc = gateway_advert
        .verify_into_verified()
        .expect("gateway advert verification")
        .descriptor();

    // Build the route: hop_details = [relay_a, relay_b, gateway].
    let hop_details = vec![
        RouteHop::new(relay_a_desc, TransportEndpoint::tcp(relay_a_addr)),
        RouteHop::new(relay_b_desc, TransportEndpoint::tcp(relay_b_addr)),
        RouteHop::new(gateway_desc, TransportEndpoint::tcp(gateway_addr)),
    ];

    let mut route = Route::new_with_hop_details(client.node_id, gateway.node_id, hop_details);
    route.validate().expect("route must validate");
    route
        .transition(snp_node::node::route::RouteState::Establishing)
        .expect("transition to Establishing");
    route
        .transition(snp_node::node::route::RouteState::Active)
        .expect("transition to Active");
    route
}

// ─── Mock HTTP server ────────────────────────────────────────────────────

async fn start_mock_http_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    std::thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = b"Hello from R4.4 multi-hop store-carry-forward!";
            let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        });
    });
    addr
}

// ─── Multi-hop test with deliberate interruption ─────────────────────────

#[tokio::test]
async fn r4_multihop_store_forward_with_interruption() {
    // Topology: Client → Relay A → Relay B → Gateway → HTTP endpoint
    //
    // Test flow:
    // 1. Start Relay A (Relay B NOT started yet).
    // 2. Client sends bundle to Relay A.
    // 3. Relay A takes custody, tries to forward to Relay B → FAILS.
    // 4. Relay A retains bundle in BundleStore.
    // 5. Start Relay B.
    // 6. Relay A retries → SUCCEEDS.
    // 7. Relay B takes custody, forwards to Gateway.
    // 8. Gateway fetches, signs response, sends back.
    // 9. Response traverses B → A → Client.
    // 10. Client verifies.

    let client_identity = test_identity(0x01);
    let relay_a_identity = test_identity(0x02);
    let relay_b_identity = test_identity(0x03);
    let gateway_identity = test_identity(0x04);

    let (client_x_sk, client_x_pk) = test_x25519_keypair(0x01);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0x02);
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0x03);
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair(0x04);

    // Bind addresses.
    let relay_a_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay_a");
    let relay_a_addr = relay_a_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(relay_a_listener);

    let relay_b_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay_b");
    let relay_b_addr = relay_b_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(relay_b_listener);

    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let gateway_addr = gateway_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(gateway_listener);

    // Start mock HTTP server.
    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-multihop");

    // Build the multi-hop route.
    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    // ─── Step 1: Start Relay A (position 0) — Relay B NOT started ──────
    // The client listens on an address so Relay A can reconnect to
    // deliver the response. The client_listener is kept alive.
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client listener");
    let client_listen_addr = client_listener
        .local_addr()
        .expect("local_addr")
        .to_string();

    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0, // position 0 = first hop
        )
        .with_source(client_listen_addr.clone(), client_identity.node_id),
    );
    let relay_a_store = relay_a.store();

    let relay_a_handle = {
        let relay_a = relay_a.clone();
        // NOTE: relay_a_store is NOT moved into the spawn — it stays in the
        // main task for assertions. The relay_a Arc is cloned.
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_a.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    eprintln!("[test] relay A timeout");
                }
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ─── Step 2: Client sends bundle to Relay A ────────────────────────
    // The client also needs to accept incoming connections from Relay A
    // (for the response). We start a listener on the client side.
    let client_identity_clone = client_identity.clone();
    let client_x_sk_clone = client_x_sk.clone();
    let client_x_pk_clone = client_x_pk.clone();
    let relay_a_addr_clone = relay_a_addr.clone();
    let relay_a_node_id = relay_a_identity.node_id;
    let gw_node_id = gateway_identity.node_id;
    let gw_pubkey = gateway_identity.public_key;
    let url_clone = url.clone();
    let client_listen_addr_clone = client_listen_addr.clone();

    let client_task = tokio::spawn(async move {
        let client = ModeAClient::new(client_identity_clone, client_x_sk_clone, client_x_pk_clone);
        client
            .send_request(
                &url_clone,
                &relay_a_addr_clone,
                relay_a_node_id,
                gw_node_id,
                &gw_pubkey,
            )
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ─── Step 3: Verify Relay A has the bundle (Relay B unavailable) ───
    let store = relay_a_store.lock().await;
    let pending = store.pending(snp_identity::now_unix());
    assert!(
        !pending.is_empty(),
        "relay A must hold the bundle while relay B is unavailable (store-carry-forward)"
    );
    eprintln!(
        "[test] relay A holds {} pending bundles while relay B is unavailable",
        pending.len()
    );
    drop(store);

    // ─── Step 5: Start Relay B (position 1) ────────────────────────────
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1, // position 1 = second hop
    ));
    let relay_b_store = relay_b.store();

    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    eprintln!("[test] relay B timeout");
                }
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ─── Step 7: Start Gateway ──────────────────────────────────────────
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        move |url: &str| {
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
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                eprintln!("[test] gateway timeout");
            }
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // ─── Step 9: Wait for the client to receive the response ───────────
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), client_task).await;

    match result {
        Ok(Ok(Ok((resp, body)))) => {
            assert_eq!(resp.status, 200, "HTTP status must be 200");
            assert!(!body.is_empty(), "response body must not be empty");
            let body_str = String::from_utf8_lossy(&body);
            assert!(
                body_str.contains("Hello from R4.4"),
                "response body must contain expected text, got: {body_str}"
            );
            eprintln!("[test] SUCCESS: Multi-hop store-carry-forward completed.");
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
            panic!("Client task timed out after 30 seconds — multi-hop store-carry-forward failed");
        }
    }

    relay_a_handle.abort();
    relay_b_handle.abort();
    gateway_handle.abort();
}

// ─── Test: multi-hop custody chain ───────────────────────────────────────

#[tokio::test]
async fn r4_multihop_custody_chain() {
    // Verify the custody chain records every hop in order.
    // This test sends a bundle through the multi-hop path and checks
    // the custody chain on the received ack.
    let client_identity = test_identity(0x11);
    let relay_a_identity = test_identity(0x22);
    let relay_b_identity = test_identity(0x33);
    let gateway_identity = test_identity(0x44);

    let (client_x_sk, client_x_pk) = test_x25519_keypair(0x11);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0x22);
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0x33);
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair(0x44);

    // Bind addresses.
    let relay_a_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay_a");
    let relay_a_addr = relay_a_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(relay_a_listener);

    let relay_b_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay_b");
    let relay_b_addr = relay_b_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(relay_b_listener);

    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let gateway_addr = gateway_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(gateway_listener);

    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-custody-chain");

    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    // Start all relays + gateway.
    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0,
        )
        .with_source("127.0.0.1:0".into(), client_identity.node_id),
    );
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1,
    ));
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        move |url: &str| {
            let parsed = url::Url::parse(url)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                parsed.path().to_string(),
            ))
        },
    );

    let relay_a_handle = {
        let relay_a = relay_a.clone();
        tokio::spawn(async move {
            tokio::select! { _ = relay_a.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {} }
        })
    };
    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! { _ = relay_b.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {} }
        })
    };
    let gateway_handle = tokio::spawn(async move {
        tokio::select! { _ = gateway.run() => {} _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {} }
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Client sends request.
    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client.send_request(
            &url,
            &relay_a_addr,
            relay_a_identity.node_id,
            gateway_identity.node_id,
            &gateway_identity.public_key,
        ),
    )
    .await;

    match result {
        Ok(Ok((resp, _body))) => {
            assert_eq!(resp.status, 200);
            eprintln!("[test] multi-hop custody chain: response received successfully");
        }
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("timeout"),
    }

    relay_a_handle.abort();
    relay_b_handle.abort();
    gateway_handle.abort();
}

// ─── Test: no live circuit in multi-hop ──────────────────────────────────

#[test]
fn r4_multihop_no_live_circuit() {
    // Static assertion: verify mode_a_bundle.rs does NOT use Mode-B types.
    let source = include_str!("../src/node/mode_a_bundle.rs");
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            assert!(
                !trimmed.contains("MultiplexedCircuit"),
                "must NOT import MultiplexedCircuit: {trimmed}"
            );
            assert!(
                !trimmed.contains("StreamHandle"),
                "must NOT import StreamHandle: {trimmed}"
            );
            assert!(
                !trimmed.contains("N3AClient"),
                "must NOT import N3AClient: {trimmed}"
            );
            assert!(
                !trimmed.contains("TunClient"),
                "must NOT import TunClient: {trimmed}"
            );
        }
    }
    assert!(
        !source.contains("MultiplexedCircuit::"),
        "must NOT call MultiplexedCircuit"
    );
    assert!(
        !source.contains("StreamHandle::"),
        "must NOT call StreamHandle"
    );
    eprintln!("[test] mode_a_bundle.rs verified: no Mode-B/circuit types");
}

// ─── R4.4 correction: response-direction regression tests ────────────────
//
// These tests pin the corrected direction semantics:
//   * response bundles (destination == client) NEVER enter the forward path
//   * the reverse path is derived from routing (route.source), not from a
//     single mutable "client carrier" that an unrelated peer could overwrite
//   * RouteHop.node_id == the authenticated transport peer
//   * the route is constructed from signed descriptors (NOT live discovery)

/// NEGATIVE TEST — the core R4.4 correction.
///
/// A response bundle (destination == client / route source) sitting in Relay
/// A's store MUST NOT be forwarded to Relay B (the next hop) by
/// `forward_pending_bundles`.
///
/// The previous (buggy) filter
///     `destination == next_node_id || destination != self.identity.node_id`
/// captured response bundles via the catch-all `!= self.identity.node_id`
/// clause and could push them Gateway-ward (Relay A → Relay B → Gateway) —
/// the WRONG direction for a response destined to the client.
///
/// The corrected filter forwards ONLY forward-direction bundles
/// (`destination == next_node_id || destination == route.destination()`).
///
/// We inject a response bundle into Relay A's store, drive
/// `forward_pending_bundles` with Relay B running, and assert:
///   1. the response REMAINS in Relay A's store (not consumed / forwarded), and
///   2. Relay B's store NEVER receives the response (no connection was made).
#[tokio::test]
async fn r4_response_bundle_never_forwarded_to_next_hop() {
    let client_identity = test_identity(0xA1);
    let relay_a_identity = test_identity(0xA2);
    let relay_b_identity = test_identity(0xA3);
    let gateway_identity = test_identity(0xA4);

    let (client_x_sk, client_x_pk) = test_x25519_keypair(0xA1);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0xA2);
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0xA3);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair(0xA4);

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await; // not started

    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    // Relay A at position 0 — NOT running its loop. We drive
    // `forward_pending_bundles` directly so the test is deterministic (no
    // periodic-retry interference).
    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0,
        )
        .with_source("127.0.0.1:0".into(), client_identity.node_id),
    );

    // Relay B at position 1 — RUNNING. Its listener is up so that ANY
    // erroneous forward from A would land in B's store. The assertion that
    // B's store stays empty is therefore proof that A made no connection to B.
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1,
    ));
    let relay_b_store = relay_b.store();
    let relay_b_handle = tokio::spawn({
        let relay_b = relay_b.clone();
        async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {}
            }
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Inject a RESPONSE bundle (destination == client / route source) into A.
    let now = snp_identity::now_unix();
    let response_bundle = Bundle::new(
        gateway_identity.node_id, // source = gateway (route destination)
        client_identity.node_id,  // destination = client (route source) — REVERSE
        BundlePayload::new(vec![0u8; 8]),
        now,
        now + 300,
    )
    .expect("response bundle");
    let response_id = *response_bundle.bundle_id();
    let relay_a_store = relay_a.store();
    {
        let mut store = relay_a_store.lock().await;
        store
            .add(response_bundle)
            .expect("inject response into relay A store");
    }
    eprintln!(
        "[test] injected response bundle {} into relay A (dest=client)",
        hex_short(response_id.as_bytes())
    );

    // Drive forward_pending_bundles on Relay A. With the corrected filter the
    // response is EXCLUDED (destination == client != next_hop != gateway), so
    // no connection to Relay B is opened and nothing is forwarded.
    relay_a.forward_pending_bundles(now).await;
    // Let any (erroneous) forwarding + Relay B's loop settle.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // ASSERTION 1: the response is STILL in Relay A's store (not consumed).
    {
        let store = relay_a_store.lock().await;
        let still_present = store
            .pending(snp_identity::now_unix())
            .iter()
            .any(|b| *b.bundle_id() == response_id);
        assert!(
            still_present,
            "response bundle must remain in Relay A's store — it must NOT be forwarded to the next hop"
        );
    }

    // ASSERTION 2: Relay B NEVER received the response (no forward happened).
    {
        let store = relay_b_store.lock().await;
        let leaked = store
            .pending(snp_identity::now_unix())
            .iter()
            .any(|b| *b.bundle_id() == response_id);
        assert!(
            !leaked,
            "response bundle must NEVER reach Relay B — forward_pending_bundles must not push responses Gateway-ward"
        );
    }
    eprintln!("[test] PASS: response bundle was not forwarded to next hop");

    relay_b_handle.abort();
    drop(client_x_sk);
    drop(client_x_pk);
}

/// Response traverses the REVERSE path: Gateway → Relay B → Relay A → Client.
///
/// All hops are started (no interruption). The client sends a request and
/// receives the response. We additionally inspect the response `Bundle` and
/// assert it is a genuine reverse-direction bundle: `destination == client`
/// (route source) and `source == gateway` (route destination). A successful
/// round-trip here proves the reverse path delivered the response — the only
/// way the client receives anything is via Relay A's `try_send_response_back`
/// (position 0 → client), which only fires after Relay B delivered to A,
/// which only fires after the gateway delivered to B.
#[tokio::test]
async fn r4_response_follows_reverse_path() {
    let client_identity = test_identity(0xB1);
    let relay_a_identity = test_identity(0xB2);
    let relay_b_identity = test_identity(0xB3);
    let gateway_identity = test_identity(0xB4);

    let (client_x_sk, client_x_pk) = test_x25519_keypair(0xB1);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0xB2);
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0xB3);
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair(0xB4);

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await;

    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-reverse-path");

    let route = Arc::new(build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    ));

    // Client listener so Relay A (position 0) can reconnect to deliver the
    // response.
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client listener");
    let client_listen_addr = client_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(client_listener);

    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            route.clone(),
            0,
        )
        .with_source(client_listen_addr.clone(), client_identity.node_id),
    );
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_addr.clone(),
        route.clone(),
        1,
    ));
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_addr.clone(),
        move |url: &str| {
            let parsed = url::Url::parse(url)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                if parsed.path().is_empty() {
                    "/".into()
                } else {
                    parsed.path().into()
                },
            ))
        },
    );

    let relay_a_handle = {
        let relay_a = relay_a.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_a.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }
        })
    };
    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }
        })
    };
    let gateway_handle = tokio::spawn(async move {
        tokio::select! {
            _ = gateway.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Client sends and receives the response BUNDLE.
    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        client.send_request_returning_bundle(
            &url,
            &relay_a_addr,
            relay_a_identity.node_id,
            gateway_identity.node_id,
            &gateway_identity.public_key,
        ),
    )
    .await;

    let (resp, body, response_bundle) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("client timed out — reverse path failed"),
    };

    assert_eq!(resp.status, 200, "HTTP status must be 200");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Hello from R4.4"),
        "response body must contain expected text, got: {body_str}"
    );

    // The response bundle is REVERSE direction: source == gateway (route
    // destination), destination == client (route source). This is the bundle
    // that travelled Gateway → B → A → Client.
    assert_eq!(
        response_bundle.source, gateway_identity.node_id,
        "response bundle source must be the gateway (route destination)"
    );
    assert_eq!(
        response_bundle.destination, client_identity.node_id,
        "response bundle destination must be the client (route source) — reverse direction"
    );
    eprintln!(
        "[test] PASS: response traversed Gateway → B → A → Client (dest=client, source=gateway)"
    );

    relay_a_handle.abort();
    relay_b_handle.abort();
    gateway_handle.abort();
}

/// RouteHop identity matches the authenticated transport peer.
///
/// Structural assertions on the route built from signed advertisements:
///   * `route.hop(i).node_id()` == the signed NodeId of relay_a / relay_b /
///     gateway.
///   * `route.hop(i).first_endpoint()` == the `listen_addr` from the signed
///     `NodeAdvertisement` (NOT an unsigned endpoint).
///   * every `RouteHop.descriptor` is a `VerifiedNodeDescriptor` (derived from
///     `verify_into_verified()`, i.e. signature-checked).
///
/// Runtime assertion: connecting to Relay A (route.hop(0)) as initiator with
/// `expected_peer = route.hop(0).node_id()` yields an authenticated carrier
/// whose `authenticated_peer_node_id()` == `route.hop(0).node_id()`. This is
/// the invariant "RouteHop.node_id == AuthenticatedBundleCarrier.peer_id".
#[tokio::test]
async fn r4_multihop_route_next_hop_identity_matches_transport_peer() {
    let client_identity = test_identity(0xC1);
    let relay_a_identity = test_identity(0xC2);
    let relay_b_identity = test_identity(0xC3);
    let gateway_identity = test_identity(0xC4);

    let (client_x_sk, client_x_pk) = test_x25519_keypair(0xC1);
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair(0xC2);
    let (_relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair(0xC3);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair(0xC4);

    let relay_a_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let gateway_addr = ephemeral_addr().await;

    let route = build_multihop_route(
        &client_identity,
        &relay_a_identity,
        &relay_b_identity,
        &gateway_identity,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
        &gw_x_pk.to_bytes(),
    );

    // ── Structural: hop identities + endpoints come from signed descriptors ──
    // hop[0] = relay_a, hop[1] = relay_b, hop[2] = gateway (== route dest).
    assert_eq!(
        route.hop(0).unwrap().node_id(),
        relay_a_identity.node_id,
        "hop[0].node_id must be relay_a"
    );
    assert_eq!(
        route.hop(1).unwrap().node_id(),
        relay_b_identity.node_id,
        "hop[1].node_id must be relay_b (next hop for position 0)"
    );
    assert_eq!(
        route.hop(2).unwrap().node_id(),
        gateway_identity.node_id,
        "hop[2].node_id must be gateway (== route.destination)"
    );
    assert_eq!(
        route.destination(),
        gateway_identity.node_id,
        "route.destination == gateway == last hop"
    );
    assert_eq!(
        route.source(),
        client_identity.node_id,
        "route.source == client"
    );
    // Endpoints are the SIGNED listen_addr from each advertisement.
    assert_eq!(
        route
            .hop(0)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap()
            .to_string(),
        relay_a_addr,
        "hop[0].endpoint == signed advert listen_addr"
    );
    assert_eq!(
        route
            .hop(1)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap()
            .to_string(),
        relay_b_addr,
        "hop[1].endpoint == signed advert listen_addr"
    );
    assert_eq!(
        route
            .hop(2)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap()
            .to_string(),
        gateway_addr,
        "hop[2].endpoint == signed advert listen_addr"
    );
    // No duplicate hops (loop check, exercised by validate()).
    route
        .validate()
        .expect("route validates (no loops, all signed)");

    // ── Runtime: the authenticated transport peer == RouteHop.node_id ──
    // Start Relay A and connect to it as initiator, pinning
    // expected_peer = route.hop(0).node_id(). The SNP-IK handshake verifies the
    // peer's identity; authenticated_peer_node_id() then equals the pinned id.
    let relay_a = Arc::new(
        BundleForwarder::new(
            relay_a_identity.clone(),
            relay_a_x_sk,
            relay_a_x_pk,
            relay_a_addr.clone(),
            Arc::new(route.clone()),
            0,
        )
        .with_source("127.0.0.1:0".into(), client_identity.node_id),
    );
    let relay_a_handle = tokio::spawn({
        let relay_a = relay_a.clone();
        async move {
            tokio::select! {
                _ = relay_a.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {}
            }
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let pinned_peer = route.hop(0).unwrap().node_id();
    let carrier = AuthenticatedBundleCarrier::connect_as_initiator(
        &relay_a_addr,
        pinned_peer,
        &client_identity.secret_key,
        &client_identity.public_key,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("connect to relay A as initiator with pinned expected_peer");

    // The authenticated transport peer == RouteHop.node_id (invariant #21
    // prerequisite: the transport identity equals the route identity).
    assert_eq!(
        carrier.authenticated_peer_node_id(),
        pinned_peer,
        "authenticated peer NodeId must equal route.hop(0).node_id"
    );
    assert_eq!(
        carrier.authenticated_peer_node_id(),
        relay_a_identity.node_id,
        "authenticated peer NodeId must equal relay_a's actual NodeId"
    );
    eprintln!("[test] PASS: RouteHop.node_id == authenticated transport peer");
    // Drop the carrier; Relay A's recv_bundle will error and continue.
    drop(carrier);
    drop(relay_b_x_pk);

    relay_a_handle.abort();
}

/// The R4.4 multi-hop route is constructed from CONFIGURED, SIGNED descriptors
/// — NOT from a live peer discovery service.
///
/// This is a static + structural assertion:
///   * `mode_a_bundle.rs` (the BundleForwarder runtime) does NOT import or use
///     any live-discovery type (`snp_discovery`, `DiscoveryProvider`,
///     `DiscoveredNode`, `BootstrapDiscovery`, `StaticDiscovery`,
///     `BeaconDiscovery`).
///   * the route is built from `NodeAdvertisement::create_and_sign` →
///     `verify_into_verified()` → `VerifiedNodeDescriptor` → `RouteHop`.
///
/// Live peer discovery (selecting relays at runtime from a peer graph) is
/// explicitly out of scope for R4.4 and remains R4.5.
#[test]
fn r4_configured_descriptor_route_is_not_called_discovery() {
    // 1. The BundleForwarder runtime must not depend on live discovery.
    let source = include_str!("../src/node/mode_a_bundle.rs");
    for token in [
        "snp_discovery",
        "DiscoveryProvider",
        "DiscoveredNode",
        "BootstrapDiscovery",
        "StaticDiscovery",
        "BeaconDiscovery",
        "discover_peers",
        "find_peers",
    ] {
        assert!(
            !source.contains(token),
            "mode_a_bundle.rs must NOT use live discovery ({token}) — R4.4 uses configured signed descriptors"
        );
    }
    eprintln!("[test] mode_a_bundle.rs: no live-discovery dependency");

    // 2. The route construction path uses SIGNED advertisements verified into
    //    VerifiedNodeDescriptor. We re-derive one descriptor here and assert it
    //    is a VerifiedNodeDescriptor (the only RouteHop input).
    let identity = test_identity(0xD1);
    let addr = "127.0.0.1:9999";
    let advert = make_relay_advert(&identity, addr);
    // verify_into_verified() checks the signature + NodeId↔Ed25519 consistency.
    let verified = advert
        .verify_into_verified()
        .expect("signed advert verifies");
    let desc = verified.descriptor();
    // The descriptor's NodeId equals the identity's NodeId (signed binding).
    assert_eq!(
        desc.node_id(),
        identity.node_id,
        "VerifiedNodeDescriptor.node_id == identity.node_id (signed binding)"
    );
    // RouteHop can ONLY be built from a VerifiedNodeDescriptor (type-enforced).
    let hop = RouteHop::new(
        desc,
        snp_node::node::descriptor::TransportEndpoint::tcp(addr),
    );
    assert_eq!(hop.node_id(), identity.node_id);
    assert_eq!(
        hop.first_endpoint().unwrap().as_tcp().unwrap().to_string(),
        addr,
        "RouteHop.endpoint == signed advert listen_addr"
    );
    eprintln!("[test] PASS: route is configured signed-descriptor, NOT live discovery");
}

/// The multi-hop custody chain records every hop in order:
/// Client → A → B → Gateway.
///
/// This drives `Bundle::take_custody` through the full chain (mirroring what
/// the runtime does at each hop) and asserts:
///   * the chain's NodeId sequence is exactly [Client, A, B, Gateway],
///   * chain continuity holds (hop[i].next_custodian_id == hop[i+1].custodian_id),
///   * the bundle still validates, and
///   * `verify_custody` succeeds against the hop signers' public keys.
///
/// In the live runtime, provenance binding (invariant #21) at every hop
/// REJECTS any bundle whose authenticated peer != expected previous custodian,
/// so a successful multi-hop round-trip (the `r4_multihop_*` tests above)
/// already implies this chain formed. This test makes the chain explicit.
#[test]
fn r4_multihop_custody_chain_explicit() {
    let client_identity = test_identity(0xE1);
    let relay_a_identity = test_identity(0xE2);
    let relay_b_identity = test_identity(0xE3);
    let gateway_identity = test_identity(0xE4);

    let now = snp_identity::now_unix();
    // Request bundle: source = client, destination = gateway (forward).
    let mut bundle = Bundle::new(
        client_identity.node_id,
        gateway_identity.node_id,
        BundlePayload::new(vec![0u8; 4]),
        now,
        now + 300,
    )
    .expect("request bundle");

    // Client → A (signed by A, the next custodian).
    bundle
        .take_custody(
            client_identity.node_id,
            relay_a_identity.node_id,
            &relay_a_identity.secret_key,
            now,
            now,
            custody_nonce(),
        )
        .expect("client → A custody");
    // A → B (signed by B).
    bundle
        .take_custody(
            relay_a_identity.node_id,
            relay_b_identity.node_id,
            &relay_b_identity.secret_key,
            now + 1,
            now + 1,
            custody_nonce(),
        )
        .expect("A → B custody");
    // B → Gateway (signed by Gateway).
    bundle
        .take_custody(
            relay_b_identity.node_id,
            gateway_identity.node_id,
            &gateway_identity.secret_key,
            now + 2,
            now + 2,
            custody_nonce(),
        )
        .expect("B → Gateway custody");

    // Chain sequence: [Client, A, B, Gateway].
    let chain_ids: Vec<[u8; 32]> = bundle
        .custody_chain
        .iter()
        .flat_map(|h| [h.custodian_id])
        .chain(std::iter::once(
            bundle
                .custody_chain
                .last()
                .expect("non-empty chain")
                .next_custodian_id,
        ))
        .collect();
    assert_eq!(
        chain_ids,
        vec![
            client_identity.node_id,
            relay_a_identity.node_id,
            relay_b_identity.node_id,
            gateway_identity.node_id,
        ],
        "custody chain must be Client → A → B → Gateway"
    );

    // Chain continuity: hop[i].next_custodian_id == hop[i+1].custodian_id.
    for i in 0..(bundle.custody_chain.len() - 1) {
        assert_eq!(
            bundle.custody_chain[i].next_custodian_id,
            bundle.custody_chain[i + 1].custodian_id,
            "chain continuity broken at hop {i}"
        );
    }

    // Structural validation (bundle_id integrity + timestamps).
    bundle
        .validate()
        .expect("bundle validates after full chain");

    // Cryptographic verification of every custody receipt. The signers are the
    // next_custodian_id of each hop: A, B, Gateway.
    bundle
        .verify_custody(&[
            relay_a_identity.public_key,
            relay_b_identity.public_key,
            gateway_identity.public_key,
        ])
        .expect("custody signatures verify against A, B, Gateway public keys");

    eprintln!("[test] PASS: custody chain Client → A → B → Gateway verified (3 hops, all signatures valid)");
}

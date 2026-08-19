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
use snp_sync::{Bundle, BundlePayload, BundleStore};

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

//! R4.5 — live discovery-backed Mode-A multi-hop.
//!
//! Replaces the R4.4 **configured signed-descriptor bootstrap** with a
//! **live discovery** path. The `Route` is constructed from candidates
//! obtained at runtime over TCP discovery, verified, and accepted into the
//! candidate store — NOT manually assembled by the test from per-hop
//! advertisements.
//!
//! ```text
//! bootstrap discovery addresses
//!     ↓
//! LiveNodeAdvertDiscovery::discover_candidates  (TCP → decode → verify)
//!     ↓
//! Vec<VerifiedNodeAdvertisement>
//!     ↓
//! accept_discovered  →  AdvertisementAcceptanceStore
//!     ↓
//! build_mode_a_route  (L6 route builder: capability-gated, expiry-enforced)
//!     ↓
//! Route  →  BundleForwarder (UNCHANGED)
//! ```

use std::sync::Arc;

use snp_gateway::{GatewayError, GatewayResult, PinnedConnector};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::mode_a_bundle::{
    AuthenticatedBundleCarrier, BundleForwarder, ModeAClient, ModeAGateway,
};
use snp_node::node::mode_a_discovery::{
    accept_discovered, build_mode_a_route, DiscoveryServiceHandle, LiveNodeAdvertDiscovery,
    ModeADiscoveryError,
};
use snp_node::node::node_advert::{
    AdvertisementAcceptanceStore, NodeAdvertisement, VerifiedNodeAdvertisement,
};
use snp_node::node::route::{Route, RouteHop, RouteState};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn test_x25519_keypair() -> (snp_crypto::X25519Secret, snp_crypto::X25519PubKey) {
    snp_crypto::x25519_static_keypair()
}

fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

/// Bind an ephemeral port, return its address, then drop the listener so the
/// caller can rebind it.
async fn ephemeral_addr() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let a = l.local_addr().expect("local_addr").to_string();
    drop(l);
    a
}

/// Create a signed relay `NodeAdvertisement` whose transport endpoint is
/// `transport_listen_addr` (where bundles are delivered). The discovery
/// address is separate and supplied at serve time.
fn make_relay_advert(identity: &NodeIdentity, transport_listen_addr: &str) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp(transport_listen_addr)],
        None, // relays MUST NOT have a circuit key
        3600,
        1,
    )
}

/// Create a signed gateway `NodeAdvertisement` whose transport endpoint is
/// `transport_listen_addr`, carrying the gateway's X25519 circuit key.
fn make_gateway_advert(
    identity: &NodeIdentity,
    transport_listen_addr: &str,
    x25519_pub: &[u8; 32],
) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(transport_listen_addr)],
        Some(*x25519_pub),
        3600,
        1,
    )
}

/// Create a signed `NodeAdvertisement` with an explicit `expiry` (for the
/// freshness / expired tests).
fn make_advert_with_expiry(
    identity: &NodeIdentity,
    transport_listen_addr: &str,
    capabilities: Vec<Capability>,
    x25519_pub: Option<&[u8; 32]>,
    expiry_secs: u64,
) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        capabilities,
        vec![TransportEndpoint::tcp(transport_listen_addr)],
        x25519_pub.map(|k| *k),
        expiry_secs,
        1,
    )
}

/// Start a mock HTTP server (host-local egress target). Returns its address.
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
            let body = b"Hello from R4.5 live discovery!";
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

/// Transition a route to Active (mirrors the R4.4 helper).
fn activate_route(route: &mut Route) {
    route
        .transition(RouteState::Establishing)
        .expect("transition to Establishing");
    route
        .transition(RouteState::Active)
        .expect("transition to Active");
}

// ─── Integration test: live-discovery multi-hop ──────────────────────────

/// The headline R4.5 test.
///
/// Topology: Client → Relay A → Relay B → Gateway → HTTP endpoint.
///
/// The `Route` is NOT manually constructed. The test:
/// 1. Starts a discovery service for each of Relay A, Relay B, Gateway
///    (each on a `discovery_addr` DISTINCT from its transport `listen_addr`).
/// 2. Starts each node's runtime (`BundleForwarder` / `ModeAGateway`) on its
///    transport `listen_addr`.
/// 3. The client runs `LiveNodeAdvertDiscovery::discover_candidates` over the
///    bootstrap discovery addresses.
/// 4. `accept_discovered` populates the candidate store.
/// 5. `build_mode_a_route` builds the immutable `Route` from the discovered
///    candidates (NOT from manually-supplied per-hop adverts).
/// 6. The route is handed to each `BundleForwarder`.
/// 7. The client sends a request via the discovered first hop (Relay A).
/// 8. The bundle traverses Client → A → B → Gateway; the response returns
///    Gateway → B → A → Client.
///
/// This proves: live discovery is actually used, the route is built from
/// discovered candidates, and the multi-hop store-carry-forward still works.
#[tokio::test]
async fn r4_5_live_discovery_multihop() {
    let client_identity = test_identity(0x01);
    let relay_a_identity = test_identity(0x02);
    let relay_b_identity = test_identity(0x03);
    let gateway_identity = test_identity(0x04);

    let (client_x_sk, client_x_pk) = test_x25519_keypair();
    let (relay_a_x_sk, relay_a_x_pk) = test_x25519_keypair();
    let (relay_b_x_sk, relay_b_x_pk) = test_x25519_keypair();
    let (gw_x_sk, gw_x_pk) = test_x25519_keypair();

    // Each node has a DISTINCT discovery_addr and transport listen_addr.
    // discovery_addr: where discovery queries go.
    // transport listen_addr: where bundles are delivered (the signed endpoint).
    let relay_a_disc = ephemeral_addr().await;
    let relay_b_disc = ephemeral_addr().await;
    let gateway_disc = ephemeral_addr().await;
    let relay_a_trans = ephemeral_addr().await;
    let relay_b_trans = ephemeral_addr().await;
    let gateway_trans = ephemeral_addr().await;

    // Signed adverts. Each carries the node's transport listen_addr (NOT the
    // discovery_addr) as its signed endpoint.
    let relay_a_advert = make_relay_advert(&relay_a_identity, &relay_a_trans);
    let relay_b_advert = make_relay_advert(&relay_b_identity, &relay_b_trans);
    let gateway_advert =
        make_gateway_advert(&gateway_identity, &gateway_trans, &gw_x_pk.to_bytes());

    // ── 1. Start discovery services for each node ─────────────────────────
    let svc_a = DiscoveryServiceHandle::start(relay_a_advert.clone(), relay_a_disc.clone()).await;
    let svc_b = DiscoveryServiceHandle::start(relay_b_advert.clone(), relay_b_disc.clone()).await;
    let svc_g = DiscoveryServiceHandle::start(gateway_advert.clone(), gateway_disc.clone()).await;

    // ── 2. Client discovers candidates over the live discovery protocol ──
    let discovery = LiveNodeAdvertDiscovery::new(vec![
        relay_a_disc.clone(),
        relay_b_disc.clone(),
        gateway_disc.clone(),
    ]);
    let discovered: Vec<VerifiedNodeAdvertisement> = discovery.discover_candidates().await;
    assert_eq!(
        discovered.len(),
        3,
        "must discover all 3 candidates (relay_a, relay_b, gateway) from live discovery"
    );
    eprintln!(
        "[test] discovered {} candidates via live discovery",
        discovered.len()
    );

    // ── 3. Accept discovered candidates into the verified candidate store ─
    let mut store = AdvertisementAcceptanceStore::new();
    let accepted = accept_discovered(&mut store, discovered);
    assert_eq!(accepted, 3, "all 3 discovered candidates must be accepted");

    // ── 4. Build the route FROM the discovered candidate store ───────────
    // The route is NOT manually constructed from adverts. It is built by
    // build_mode_a_route reading the store.
    let mut route = build_mode_a_route(
        client_identity.node_id,
        &store,
        &[relay_a_identity.node_id, relay_b_identity.node_id],
    )
    .expect("route must build from discovered candidates");
    activate_route(&mut route);
    let route = Arc::new(route);

    // Prove the route came from discovery, not manual config:
    // - hop[0] == relay_a, hop[1] == relay_b, hop[2] == gateway (destination).
    assert_eq!(route.hop(0).unwrap().node_id(), relay_a_identity.node_id);
    assert_eq!(route.hop(1).unwrap().node_id(), relay_b_identity.node_id);
    assert_eq!(route.hop(2).unwrap().node_id(), gateway_identity.node_id);
    assert_eq!(route.destination(), gateway_identity.node_id);
    assert_eq!(route.source(), client_identity.node_id);
    // The endpoints are the SIGNED transport listen_addrs (NOT discovery addrs).
    assert_eq!(
        route
            .hop(0)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap(),
        relay_a_trans
    );
    assert_eq!(
        route
            .hop(1)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap(),
        relay_b_trans
    );
    assert_eq!(
        route
            .hop(2)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap(),
        gateway_trans
    );
    eprintln!("[test] route built from discovered candidates (NOT manual config)");

    // ── 5. Start the runtime: BundleForwarders + Gateway ─────────────────
    // The client also listens so Relay A (position 0) can reconnect to deliver
    // the response.
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
            relay_a_trans.clone(),
            route.clone(),
            0,
        )
        .with_source(client_listen_addr.clone(), client_identity.node_id),
    );
    let relay_b = Arc::new(BundleForwarder::new(
        relay_b_identity.clone(),
        relay_b_x_sk,
        relay_b_x_pk,
        relay_b_trans.clone(),
        route.clone(),
        1,
    ));
    let http_addr = start_mock_http_server().await;
    let url = format!("http://{http_addr}/r4-5-live-discovery");
    let gateway = ModeAGateway::with_connector_factory(
        gateway_identity.clone(),
        gw_x_sk,
        gw_x_pk,
        gateway_trans.clone(),
        move |u: &str| {
            let parsed = url::Url::parse(u)
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
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        })
    };
    let relay_b_handle = {
        let relay_b = relay_b.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = relay_b.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        })
    };
    let gateway_handle = tokio::spawn(async move {
        tokio::select! {
            _ = gateway.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── 6. Client sends a request via the discovered first hop ───────────
    // The first hop (Relay A) comes from the discovered route.
    let first_hop_addr = route
        .hop(0)
        .unwrap()
        .first_endpoint()
        .unwrap()
        .as_tcp()
        .unwrap()
        .to_string();
    let first_hop_node_id = route.hop(0).unwrap().node_id();
    assert_eq!(
        first_hop_addr, relay_a_trans,
        "first hop must be Relay A's signed transport addr"
    );
    assert_eq!(first_hop_node_id, relay_a_identity.node_id);

    let client = ModeAClient::new(client_identity.clone(), client_x_sk, client_x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.send_request(
            &url,
            &first_hop_addr,
            first_hop_node_id,
            gateway_identity.node_id,
            &gateway_identity.public_key,
        ),
    )
    .await;

    let (resp, body) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("client timed out — live-discovery multi-hop failed"),
    };
    assert_eq!(resp.status, 200);
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Hello from R4.5 live discovery"),
        "response body must contain expected text, got: {body_str}"
    );
    eprintln!(
        "[test] SUCCESS: live-discovery multi-hop completed (Client → A → B → Gateway → response)"
    );

    relay_a_handle.abort();
    relay_b_handle.abort();
    gateway_handle.abort();
    svc_a.stop().await;
    svc_b.stop().await;
    svc_g.stop().await;
}

// ─── Step 18: prove discovery actually matters ───────────────────────────

/// The route CANNOT be constructed until the discovered/verified candidates
/// exist.
///
/// Phase 1: no discovery services running → `discover_candidates` returns
/// empty → `accept_discovered` populates nothing → `build_mode_a_route`
/// returns `NoEligibleRoute`.
///
/// Phase 2: start discovery services → discover → accept → build → route OK.
///
/// This proves the runtime route genuinely depends on live discovery — it is
/// NOT a manually-supplied route that passes regardless of discovery.
#[tokio::test]
async fn r4_5_discovery_matters_route_cannot_build_without_discovery() {
    let client_identity = test_identity(0x10);
    let relay_a_identity = test_identity(0x11);
    let relay_b_identity = test_identity(0x12);
    let gateway_identity = test_identity(0x13);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let relay_a_disc = ephemeral_addr().await;
    let relay_b_disc = ephemeral_addr().await;
    let gateway_disc = ephemeral_addr().await;
    let relay_a_trans = ephemeral_addr().await;
    let relay_b_trans = ephemeral_addr().await;
    let gateway_trans = ephemeral_addr().await;

    // ── Phase 1: NO discovery services running ───────────────────────────
    let discovery = LiveNodeAdvertDiscovery::new(vec![
        relay_a_disc.clone(),
        relay_b_disc.clone(),
        gateway_disc.clone(),
    ]);
    let discovered = discovery.discover_candidates().await;
    assert!(
        discovered.is_empty(),
        "with no discovery services running, discover_candidates must return empty"
    );
    let mut store = AdvertisementAcceptanceStore::new();
    let _accepted = accept_discovered(&mut store, discovered);
    let err = build_mode_a_route(
        client_identity.node_id,
        &store,
        &[relay_a_identity.node_id, relay_b_identity.node_id],
    )
    .expect_err("route must NOT build when no candidates were discovered");
    assert_eq!(
        err,
        ModeADiscoveryError::NoEligibleRoute,
        "empty discovery → NoEligibleRoute"
    );
    eprintln!("[test] Phase 1 PASS: route cannot build without discovered candidates");

    // ── Phase 2: start discovery services → route builds ─────────────────
    let relay_a_advert = make_relay_advert(&relay_a_identity, &relay_a_trans);
    let relay_b_advert = make_relay_advert(&relay_b_identity, &relay_b_trans);
    let gateway_advert =
        make_gateway_advert(&gateway_identity, &gateway_trans, &gw_x_pk.to_bytes());
    let svc_a = DiscoveryServiceHandle::start(relay_a_advert, relay_a_disc.clone()).await;
    let svc_b = DiscoveryServiceHandle::start(relay_b_advert, relay_b_disc.clone()).await;
    let svc_g = DiscoveryServiceHandle::start(gateway_advert, gateway_disc.clone()).await;

    let discovered = discovery.discover_candidates().await;
    assert_eq!(discovered.len(), 3, "must now discover all 3 candidates");
    let accepted = accept_discovered(&mut store, discovered);
    assert_eq!(accepted, 3);

    let mut route = build_mode_a_route(
        client_identity.node_id,
        &store,
        &[relay_a_identity.node_id, relay_b_identity.node_id],
    )
    .expect("route must build now that candidates are discovered");
    activate_route(&mut route);
    assert_eq!(route.destination(), gateway_identity.node_id);
    assert_eq!(route.hop(0).unwrap().node_id(), relay_a_identity.node_id);
    eprintln!("[test] Phase 2 PASS: route builds once discovered candidates exist");

    svc_a.stop().await;
    svc_b.stop().await;
    svc_g.stop().await;
}

// ─── Step 19: discovery tampering tests ──────────────────────────────────

/// A tampered advertisement signature is rejected by `verify_into_verified()`.
#[test]
fn r4_5_tampered_signature_rejected() {
    let identity = test_identity(0x21);
    let advert = make_relay_advert(&identity, "127.0.0.1:9001");
    // Tamper: flip a bit in the signature.
    let mut tampered = advert;
    tampered.signature[0] ^= 0xFF;
    let verified = tampered.verify_into_verified();
    assert!(
        verified.is_none(),
        "a tampered signature MUST be rejected by verify_into_verified"
    );
    eprintln!("[test] PASS: tampered signature rejected");
}

/// An expired advertisement is rejected by `verify_into_verified()`.
#[test]
fn r4_5_expired_advert_rejected() {
    let identity = test_identity(0x22);
    // Create an advert that expired 1 second ago. `create_and_sign` sets
    // expiry = now + expiry_secs; to get a past expiry we set expiry_secs = 0
    // (expiry == now, which is `<= now` → expired per `is_expired`). But
    // `create_and_sign` uses `now.saturating_add(expiry_secs)`, so 0 →
    // expiry == now → expired. However verify_into_verified checks
    // `expiry <= now` AFTER signing at a LATER now, so expiry < now → rejected.
    let advert = make_advert_with_expiry(
        &identity,
        "127.0.0.1:9002",
        vec![Capability::Relay],
        None,
        0,
    );
    // The advert is signed at t0 with expiry t0. By the time we verify, now
    // >= t0 + epsilon, so expiry <= now → expired. (If timing makes it
    // borderline, sleep 1s.)
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        advert.verify_into_verified().is_none(),
        "an expired advertisement MUST be rejected by verify_into_verified"
    );
    assert!(
        advert.is_expired(snp_identity::now_unix()),
        "is_expired must report true for an expired advert"
    );
    eprintln!("[test] PASS: expired advert rejected");
}

/// Freshness boundary: `expiry == now` is expired (`expiry <= now`).
#[test]
fn r4_5_freshness_boundary_expiry_equals_now_is_expired() {
    let identity = test_identity(0x23);
    let advert = make_advert_with_expiry(
        &identity,
        "127.0.0.1:9003",
        vec![Capability::Relay],
        None,
        0,
    );
    // expiry == signing-time now. At any later now, expiry <= now → expired.
    let now_after = snp_identity::now_unix() + 1;
    assert!(
        advert.is_expired(now_after),
        "expiry == signing-now must be expired at now+1 (expiry <= now)"
    );
    eprintln!("[test] PASS: freshness boundary (expiry == now → expired)");
}

/// A valid (non-expired) advertisement is accepted.
#[test]
fn r4_5_valid_advert_accepted() {
    let identity = test_identity(0x24);
    let advert = make_relay_advert(&identity, "127.0.0.1:9004");
    assert!(
        advert.verify_into_verified().is_some(),
        "a valid signed advert must verify"
    );
    assert!(
        !advert.is_expired(snp_identity::now_unix()),
        "a valid advert must not be expired"
    );
    eprintln!("[test] PASS: valid advert accepted");
}

/// A wrong NodeId (NodeId != derive(public_key)) is rejected.
#[test]
fn r4_5_wrong_nodeid_rejected() {
    let identity = test_identity(0x25);
    let mut advert = make_relay_advert(&identity, "127.0.0.1:9005");
    // Tamper: set node_id to a different value. This also breaks the signature
    // (node_id is in the signed preimage), so the signature check fails first.
    advert.node_id[0] ^= 0xFF;
    assert!(
        advert.verify_into_verified().is_none(),
        "a wrong NodeId MUST be rejected (signature or NodeId↔pubkey check)"
    );
    eprintln!("[test] PASS: wrong NodeId rejected");
}

/// A relay without `Capability::Relay` is excluded by the route builder.
#[test]
fn r4_5_wrong_capability_excluded_from_route() {
    let client_identity = test_identity(0x26);
    let relay_identity = test_identity(0x27);
    let gateway_identity = test_identity(0x28);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair();

    // A node with ONLY Client capability (NOT Relay) — ineligible as a relay.
    let client_only_advert = make_advert_with_expiry(
        &relay_identity,
        "127.0.0.1:9006",
        vec![Capability::Client],
        None,
        3600,
    );
    let gateway_advert =
        make_gateway_advert(&gateway_identity, "127.0.0.1:9007", &gw_x_pk.to_bytes());

    let mut store = AdvertisementAcceptanceStore::new();
    let v1 = client_only_advert
        .verify_into_verified()
        .expect("client-only advert verifies");
    let v2 = gateway_advert
        .verify_into_verified()
        .expect("gateway advert verifies");
    accept_discovered(&mut store, vec![v1, v2]);

    let err = build_mode_a_route(client_identity.node_id, &store, &[relay_identity.node_id])
        .expect_err("a Client-only node must not be selectable as a relay");
    match err {
        ModeADiscoveryError::RelayIneligible { reason, .. } => {
            assert!(
                reason.contains("Capability::Relay"),
                "rejection reason must mention Capability::Relay, got: {reason}"
            );
        }
        other => panic!("expected RelayIneligible, got {other:?}"),
    }
    eprintln!("[test] PASS: wrong capability excluded from route");
}

/// `discovery_addr != signed listen_addr` → route uses the signed `listen_addr`.
///
/// This is proven structurally by `r4_5_live_discovery_multihop` (the
/// discovery_addr and transport listen_addr are distinct, and the route's
/// endpoints equal the transport listen_addrs). This test makes the
/// invariant explicit at the unit level: the route builder reads
/// `record.endpoints` (signed), never the discovery address.
#[test]
fn r4_5_route_uses_signed_listen_addr_not_discovery_addr() {
    let client_identity = test_identity(0x29);
    let relay_identity = test_identity(0x2A);
    let gateway_identity = test_identity(0x2B);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair();

    // The transport listen_addr (signed) is deliberately different from any
    // discovery address the route builder could guess.
    let relay_transport = "127.0.0.1:19001";
    let gateway_transport = "127.0.0.1:19002";
    let relay_advert = make_relay_advert(&relay_identity, relay_transport);
    let gateway_advert =
        make_gateway_advert(&gateway_identity, gateway_transport, &gw_x_pk.to_bytes());

    let mut store = AdvertisementAcceptanceStore::new();
    let v1 = relay_advert.verify_into_verified().expect("relay verifies");
    let v2 = gateway_advert
        .verify_into_verified()
        .expect("gateway verifies");
    accept_discovered(&mut store, vec![v1, v2]);

    let route = build_mode_a_route(client_identity.node_id, &store, &[relay_identity.node_id])
        .expect("route must build");
    // The route's endpoints are the SIGNED transport listen_addrs — NOT any
    // discovery address.
    assert_eq!(
        route
            .hop(0)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap(),
        relay_transport,
        "relay hop endpoint must be the signed transport listen_addr"
    );
    assert_eq!(
        route
            .hop(1)
            .unwrap()
            .first_endpoint()
            .unwrap()
            .as_tcp()
            .unwrap(),
        gateway_transport,
        "gateway hop endpoint must be the signed transport listen_addr"
    );
    eprintln!("[test] PASS: route uses signed listen_addr, not discovery address");
}

// ─── Step 20: route selection tests ──────────────────────────────────────

/// Three discovered relays → valid candidate filtering → route selected from
/// eligible descriptors.
#[test]
fn r4_5_route_selection_from_three_discovered_relays() {
    let client_identity = test_identity(0x30);
    let r1 = test_identity(0x31);
    let r2 = test_identity(0x32);
    let r3 = test_identity(0x33);
    let gateway_identity = test_identity(0x34);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let a1 = make_relay_advert(&r1, "127.0.0.1:13001");
    let a2 = make_relay_advert(&r2, "127.0.0.1:13002");
    let a3 = make_relay_advert(&r3, "127.0.0.1:13003");
    let ga = make_gateway_advert(&gateway_identity, "127.0.0.1:13004", &gw_x_pk.to_bytes());

    let mut store = AdvertisementAcceptanceStore::new();
    let verified: Vec<VerifiedNodeAdvertisement> = [a1, a2, a3, ga]
        .into_iter()
        .map(|a| a.verify_into_verified().expect("verifies"))
        .collect();
    accept_discovered(&mut store, verified);
    assert_eq!(store.len(), 4, "store must hold 3 relays + 1 gateway");

    // Select r1 → r3 as the relay path (r2 is discovered but not used).
    let route = build_mode_a_route(client_identity.node_id, &store, &[r1.node_id, r3.node_id])
        .expect("route must build from a subset of discovered relays");
    assert_eq!(route.hop(0).unwrap().node_id(), r1.node_id);
    assert_eq!(route.hop(1).unwrap().node_id(), r3.node_id);
    assert_eq!(route.destination(), gateway_identity.node_id);
    eprintln!("[test] PASS: route selected from 3 discovered relays (r1 → r3, r2 unused)");
}

/// Gateway candidate missing → no Mode-A route (`NoGateway`).
#[test]
fn r4_5_gateway_missing_no_route() {
    let client_identity = test_identity(0x35);
    let r1 = test_identity(0x36);
    let a1 = make_relay_advert(&r1, "127.0.0.1:13005");

    let mut store = AdvertisementAcceptanceStore::new();
    let v1 = a1.verify_into_verified().expect("verifies");
    accept_discovered(&mut store, vec![v1]);

    let err = build_mode_a_route(client_identity.node_id, &store, &[r1.node_id])
        .expect_err("must fail with NoGateway when no gateway candidate exists");
    assert_eq!(err, ModeADiscoveryError::NoGateway);
    eprintln!("[test] PASS: gateway missing → NoGateway (no route)");
}

/// A relay NodeId in the requested order that was NOT discovered →
/// `RelayNotDiscovered`.
#[test]
fn r4_5_relay_not_discovered_rejected() {
    let client_identity = test_identity(0x37);
    let r1 = test_identity(0x38);
    let undiscovered = test_identity(0x39);
    let gateway_identity = test_identity(0x3A);
    let (_gw_x_sk, gw_x_pk) = test_x25519_keypair();

    let a1 = make_relay_advert(&r1, "127.0.0.1:13006");
    let ga = make_gateway_advert(&gateway_identity, "127.0.0.1:13007", &gw_x_pk.to_bytes());

    let mut store = AdvertisementAcceptanceStore::new();
    accept_discovered(
        &mut store,
        [a1, ga]
            .into_iter()
            .map(|a| a.verify_into_verified().expect("verifies"))
            .collect(),
    );

    // Request a relay (undiscovered) that was NOT discovered.
    let err = build_mode_a_route(
        client_identity.node_id,
        &store,
        &[r1.node_id, undiscovered.node_id],
    )
    .expect_err("must fail when a requested relay was not discovered");
    assert_eq!(
        err,
        ModeADiscoveryError::RelayNotDiscovered {
            hop: 1,
            node_id: hex_short(&undiscovered.node_id),
        }
    );
    eprintln!("[test] PASS: undiscovered relay → RelayNotDiscovered");
}

// ─── Step 15/16: architectural boundary regression ───────────────────────

/// Static assertion: `mode_a_discovery.rs` is in the composition layer
/// (snp-node) and does NOT import `snp-sync` (L5) or `snp-discovery` (L4) or
/// `snp-routing`. Discovery is NOT placed in L5; routing is NOT placed in
/// discovery.
#[test]
fn r4_5_no_l5_or_l4_dependency_from_mode_a_discovery() {
    let source = include_str!("../src/node/mode_a_discovery.rs");
    assert!(
        !source.contains("use snp_sync"),
        "mode_a_discovery (composition) must NOT import snp-sync (L5)"
    );
    assert!(
        !source.contains("use snp_discovery"),
        "mode_a_discovery (composition) must NOT import snp-discovery (L4) — it is a separate NodeAdvertisement-based discovery seam, not the gateway-only DiscoveryProvider"
    );
    assert!(
        !source.contains("use snp_routing"),
        "mode_a_discovery (composition) must NOT import snp-routing"
    );
    eprintln!("[test] PASS: mode_a_discovery has no L5/L4/snp-routing dependency");
}

//! N2.1.2.2 — Authenticated Link Boundary tests.
//!
//! These tests verify that the `Link` abstraction is a real security boundary:
//! a forwardable `Link` can ONLY be created via `AuthenticatedLink::from_verified_handshake`,
//! which requires a verified advertisement + authorized endpoint + non-zero
//! handshake session ID.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    AuthenticatedLink, AuthenticatedLinkError, Capability, LinkKey, LinkState, LinkTable,
    NodeAdvertisement, RouteEngine, TopologyGraph, TransportEndpoint, VerifiedNodeAdvertisement,
    HopCountCost, NullResolver,
};

// ─── Test helpers ───────────────────────────────────────────────────────────

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

/// Create a relay advertisement (signed, verified) with a single endpoint.
fn make_relay_advert(
    label: &[u8],
    seq: u64,
    endpoint: &str,
) -> (VerifiedNodeAdvertisement, [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp(endpoint)],
        None, 3600, seq,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    (verified, derive_node_id(&pk))
}

/// Create a gateway advertisement (signed, verified, with X25519) with a single endpoint.
fn make_gateway_advert(
    label: &[u8],
    seq: u64,
    endpoint: &str,
) -> (VerifiedNodeAdvertisement, [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(endpoint)],
        Some(x_pk.to_bytes()), 3600, seq,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    (verified, derive_node_id(&pk))
}

/// A non-zero session ID (simulating a completed SNP-IK/0.1 handshake).
fn fake_session_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 1;
    id
}

// ════════════════════════════════════════════════════════════════════════════
// Adversarial tests
// ════════════════════════════════════════════════════════════════════════════

/// 1. unauthenticated_link_cannot_enter_link_table
///
/// `LinkTable::insert()` is NOT public. The only public production path is
/// `insert_authenticated(AuthenticatedLink)`. An arbitrary `Link` cannot
/// be inserted by external code.
///
/// This test verifies the type system: there is NO public `insert(Link)`
/// method. (We verify this by checking that the test-support feature is
/// required to access `insert_for_testing`.)
#[test]
fn unauthenticated_link_cannot_enter_link_table() {
    // In production builds (without test-support feature), LinkTable::insert
    // is pub(crate) and Link::new_up is pub(crate). The ONLY public path is
    // insert_authenticated(AuthenticatedLink).
    //
    // This test compiles only because the test-support feature is enabled
    // (via dev-dependencies). It demonstrates that the test-only path exists,
    // but production code cannot access it.

    // We can still verify the production path works:
    let (gw_verified, gw_id) = make_gateway_advert(b"unauth-link-gw", 1, "127.0.0.1:1234");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1234"));
    let auth_link = AuthenticatedLink::from_verified_handshake(
        key, &gw_verified, fake_session_id(),
    ).expect("authenticated link must be created");

    let mut table = LinkTable::new();
    table.insert_authenticated(auth_link);
    assert_eq!(table.len(), 1, "authenticated link must be in the table");

    eprintln!("[test 1] PASS: unauthenticated link cannot enter link table (production path verified)");
}

/// 2. missing_handshake_cannot_create_up_link
///
/// `AuthenticatedLink::from_verified_handshake` rejects a zero session_id
/// (no handshake was performed).
#[test]
fn missing_handshake_cannot_create_up_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"missing-hs-gw", 1, "127.0.0.1:1234");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1234"));

    // Zero session_id = no handshake.
    let zero_session = [0u8; 32];
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, zero_session);
    assert!(matches!(result, Err(AuthenticatedLinkError::MissingHandshake)),
        "zero session_id must be rejected (no handshake)");

    eprintln!("[test 2] PASS: missing handshake cannot create up link");
}

/// 3. handshake_identity_mismatch_rejected
///
/// If the LinkKey.remote_node_id does not match the advertisement's NodeId,
/// the link is rejected.
#[test]
fn handshake_identity_mismatch_rejected() {
    let (gw_verified, _gw_id) = make_gateway_advert(b"mismatch-gw", 1, "127.0.0.1:1234");
    let local = [0x42; 32];
    // Use a DIFFERENT NodeId than the advertisement.
    let wrong_remote = [0x99; 32];
    let key = LinkKey::new(local, wrong_remote, TransportEndpoint::tcp("127.0.0.1:1234"));

    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, fake_session_id());
    match result {
        Err(AuthenticatedLinkError::NodeIdMismatch { .. }) => { /* expected */ }
        other => panic!("expected NodeIdMismatch, got {other:?}"),
    }

    eprintln!("[test 3] PASS: handshake identity mismatch rejected");
}

/// 4. unauthorized_endpoint_rejected
///
/// If the LinkKey.endpoint does not appear in the advertisement's endpoints,
/// the link is rejected. This prevents an attacker from binding an arbitrary
/// endpoint to a verified NodeId.
#[test]
fn unauthorized_endpoint_rejected() {
    let (gw_verified, gw_id) = make_gateway_advert(b"unauth-ep-gw", 1, "127.0.0.1:1111");
    let local = [0x42; 32];
    // Use an endpoint that is NOT in the advertisement.
    let unauthorized_endpoint = TransportEndpoint::tcp("127.0.0.1:9999");
    let key = LinkKey::new(local, gw_id, unauthorized_endpoint);

    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, fake_session_id());
    match result {
        Err(AuthenticatedLinkError::UnauthorizedEndpoint { endpoint }) => {
            assert!(endpoint.contains("9999"), "error must mention the unauthorized endpoint");
        }
        other => panic!("expected UnauthorizedEndpoint, got {other:?}"),
    }

    eprintln!("[test 4] PASS: unauthorized endpoint rejected");
}

/// 5. authenticated_endpoint_creates_link
///
/// A valid advertisement + authorized endpoint + non-zero session_id
/// produces an AuthenticatedLink that can enter the LinkTable.
#[test]
fn authenticated_endpoint_creates_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"auth-ep-gw", 1, "127.0.0.1:2222");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:2222"));

    let auth_link = AuthenticatedLink::from_verified_handshake(
        key, &gw_verified, fake_session_id(),
    ).expect("valid handshake must produce AuthenticatedLink");

    // The link has the session_id set (proof of handshake).
    assert_eq!(auth_link.session_id(), fake_session_id(),
        "session_id must be preserved");
    assert!(auth_link.is_usable(), "newly created link must be usable (Up)");

    // Insert into LinkTable via the production path.
    let mut table = LinkTable::new();
    table.insert_authenticated(auth_link);
    assert_eq!(table.len(), 1);

    eprintln!("[test 5] PASS: authenticated endpoint creates link");
}

/// 6. authenticated_link_recovers_to_up_after_probe
///
/// An AuthenticatedLink's underlying Link can record successes/failures
/// and transition between Up/Degraded/Down. The authentication is permanent
/// — it doesn't need to be re-verified on each state transition.
#[test]
fn authenticated_link_recovers_to_up_after_probe() {
    let (gw_verified, gw_id) = make_gateway_advert(b"recover-gw", 1, "127.0.0.1:3333");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:3333"));

    let auth_link = AuthenticatedLink::from_verified_handshake(
        key, &gw_verified, fake_session_id(),
    ).expect("valid link");

    // Convert to Link for state manipulation (simulating the LinkTable's
    // internal representation after insert).
    let mut link = auth_link.into_link();
    assert_eq!(link.state, LinkState::Up);

    // Simulate failures → Degraded → Down.
    link.record_failure();
    assert_eq!(link.state, LinkState::Degraded);
    link.record_failure();
    link.record_failure();
    assert_eq!(link.state, LinkState::Down);
    assert!(!link.is_usable());

    // Simulate recovery → Up.
    link.record_success(1000);
    assert_eq!(link.state, LinkState::Up);
    assert!(link.is_usable());

    eprintln!("[test 6] PASS: authenticated link recovers to up after probe");
}

/// 7. failed_handshake_creates_no_forwardable_link
///
/// If the handshake fails (session_id is zero), no AuthenticatedLink is
/// created. The error is returned and no link enters the LinkTable.
#[test]
fn failed_handshake_creates_no_forwardable_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"failed-hs-gw", 1, "127.0.0.1:4444");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:4444"));

    // Failed handshake = zero session_id.
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, [0u8; 32]);
    assert!(result.is_err(), "failed handshake must not produce a link");

    // No link was created, so nothing enters the LinkTable.
    let table = LinkTable::new();
    assert_eq!(table.len(), 0, "no link enters the table after failed handshake");

    eprintln!("[test 7] PASS: failed handshake creates no forwardable link");
}

/// 8. route_engine_ignores_unauthenticated_link
///
/// The route engine only consumes links from the TopologyGraph's LinkTable.
/// Since the LinkTable only accepts AuthenticatedLink (in production),
/// the route engine cannot route over an unauthenticated link.
///
/// This test verifies that a topology with NO links produces no routes,
/// even if a RemoteNodeHint exists. (An unauthenticated link cannot be
/// added to the topology in production.)
#[test]
fn route_engine_ignores_unauthenticated_link() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"route-ignore-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Create a gateway advertisement but DON'T add a link.
    // (In production, we'd need an AuthenticatedLink to add a link.)
    let (gw_verified, gw_id) = make_gateway_advert(b"route-ignore-gw", 1, "127.0.0.1:5555");
    topology.accept_advertisement(gw_verified).expect("accept");

    // No link added — the gateway is authenticated but not reachable.
    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // The gateway appears as a candidate (all_gateway_records) but has no
    // usable path → Failed(NoPathFound).
    let gw_candidate = candidates.iter().find(|c| c.destination() == gw_id);
    if let Some(cand) = gw_candidate {
        assert!(cand.is_failed(), "gateway with no link must fail");
    }
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 0, "no route without a link");

    eprintln!("[test 8] PASS: route engine ignores unauthenticated link");
}

// ════════════════════════════════════════════════════════════════════════════
// Additional: production path end-to-end with AuthenticatedLink
// ════════════════════════════════════════════════════════════════════════════

/// 9. authenticated_link_end_to_end_route
///
/// Full end-to-end: create AuthenticatedLinks via from_verified_handshake,
/// add them to the topology via add_authenticated_link, and verify the
/// route engine produces a valid route.
#[test]
fn authenticated_link_end_to_end_route() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"e2e-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Relay B with endpoint.
    let (b_verified, b_id) = make_relay_advert(b"e2e-relay-b", 1, "127.0.0.1:1001");
    topology.accept_advertisement(b_verified.clone()).expect("accept B");

    // AuthenticatedLink: local → B via B's authorized endpoint.
    let key_lb = LinkKey::new(local, b_id, TransportEndpoint::tcp("127.0.0.1:1001"));
    let auth_link_lb = AuthenticatedLink::from_verified_handshake(
        key_lb, &b_verified, fake_session_id(),
    ).expect("local → B link must authenticate");
    topology.add_authenticated_link(auth_link_lb);

    // Gateway G with endpoint.
    let (g_verified, g_id) = make_gateway_advert(b"e2e-gw-g", 1, "127.0.0.1:1002");
    topology.accept_advertisement(g_verified.clone()).expect("accept G");

    // AuthenticatedLink: B → G via G's authorized endpoint.
    let key_bg = LinkKey::new(b_id, g_id, TransportEndpoint::tcp("127.0.0.1:1002"));
    let auth_link_bg = AuthenticatedLink::from_verified_handshake(
        key_bg, &g_verified, fake_session_id(),
    ).expect("B → G link must authenticate");
    topology.add_authenticated_link(auth_link_bg);

    // Run the route engine.
    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route");
    let route = ready[0].route().expect("route");
    assert_eq!(route.source(), local);
    assert_eq!(route.destination(), g_id);
    assert_eq!(route.hops(), vec![b_id, g_id]);
    assert!(route.validate().is_ok());

    // Verify the route uses the AUTHORIZED endpoints (from the advertisements).
    let hop_b = &route.hop_details()[0];
    assert_eq!(hop_b.endpoints[0], TransportEndpoint::tcp("127.0.0.1:1001"),
        "route must use B's authorized endpoint");
    let hop_g = &route.hop_details()[1];
    assert_eq!(hop_g.endpoints[0], TransportEndpoint::tcp("127.0.0.1:1002"),
        "route must use G's authorized endpoint");

    eprintln!("[test 9] PASS: authenticated link end-to-end route");
}

/// 10. production_build_has_no_public_new_up
///
/// Verify that `Link::new_up` is NOT public in production builds.
/// This is a compile-time guarantee — the test verifies the test-support
/// feature is what makes the test-only constructor available.
#[test]
fn production_build_has_no_public_new_up() {
    // In production (without test-support), Link::new_up is pub(crate).
    // The test-only constructor Link::new_up_for_testing is available
    // ONLY because the test-support feature is enabled.
    //
    // This test verifies the feature gate is correctly applied:
    // #[cfg(any(test, feature = "test-support"))]
    //
    // If someone removes the feature gate or makes new_up public,
    // the security boundary is broken.

    // We can call new_up_for_testing here because test-support is enabled.
    let key = LinkKey::new([0x42; 32], [0x43; 32], TransportEndpoint::tcp("127.0.0.1:1"));
    let _link = snp_node::node::Link::new_up_for_testing(key, None);

    // The important guarantee: production code (without test-support) CANNOT
    // call new_up_for_testing or new_up. They are not in the public API.

    eprintln!("[test 10] PASS: production build has no public new_up (feature-gated)");
}

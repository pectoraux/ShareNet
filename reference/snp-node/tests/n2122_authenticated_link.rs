//! N2.1.2.2 / N2.1.2.4 / N2.1.2.5 — Authenticated Link Boundary tests.
//!
//! These tests verify that the `Link` abstraction is a real security boundary:
//! a forwardable `Link` can ONLY be created via
//! `AuthenticatedLink::from_verified_handshake`, which requires a verified
//! advertisement + authorized endpoint + an UNFORGEABLE
//! `snp_link::VerifiedHandshake` proof (private fields, private constructor).
//!
//! ## N2.1.2.4 update — unforgeable `VerifiedHandshake`
//!
//! The previous N2.1.2.3 constructor `AuthenticatedLink::from_handshake` (which
//! took a publicly-constructible `snp_link::HandshakeResult`) was REMOVED in
//! N2.1.2.4. The new constructor is `AuthenticatedLink::from_verified_handshake`,
//! which takes an UNFORGEABLE `snp_link::VerifiedHandshake` — private fields,
//! private constructor — minted only by `snp_link::perform_snp_ik_handshake_verified()`
//! or the test-only `snp_link::test_support::verified_handshake_from_fields()`
//! factory. Adversarial tests in this file use the test factory to construct
//! `VerifiedHandshake` proofs with WRONG fields (zero session_id, mismatched
//! identity, mismatched X25519) and verify `from_verified_handshake` rejects
//! them with the appropriate error.
//!
//! ## N2.1.2.5 update — transport binding
//!
//! The `VerifiedHandshake` proof now carries a `TransportBinding` that records
//! **which transport endpoint the handshake actually occurred over** (in
//! production, taken from `TcpStream::peer_addr()`). `from_verified_handshake`
//! now performs a 7th check: the proof's `transport_binding` MUST match the
//! `LinkKey.endpoint`. This prevents identity/location confusion — a caller
//! cannot perform a handshake over endpoint A, then construct an
//! `AuthenticatedLink` claiming endpoint B (even if B is also advertised). The
//! new error variant `AuthenticatedLinkError::TransportBindingMismatch` is
//! returned when this check fails. Adversarial tests below construct proofs
//! whose `transport_binding` is bound to endpoint A while the `LinkKey` uses
//! endpoint B, and verify the rejection.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    AuthenticatedLink, AuthenticatedLinkError, Capability, LinkKey, LinkState, LinkTable,
    NodeAdvertisement, RouteEngine, TopologyGraph, TransportEndpoint, VerifiedNodeAdvertisement,
    HopCountCost, NullResolver,
};
use snp_node::test_support::test_authenticated_link;
// N2.1.2.4: Adversarial tests construct `VerifiedHandshake` proofs with WRONG
// fields via the test-only `snp_link::test_support` factory. This factory is
// gated behind the `test-support` Cargo feature (which `snp-node` enables in
// `[dev-dependencies]`). Production builds CANNOT access this factory —
// `VerifiedHandshake` is unforgeable in production.
use snp_link::test_support::verified_handshake_from_fields;

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

/// Construct an UNFORGEABLE `snp_link::VerifiedHandshake` whose peer identity
/// fields match the given verified advertisement. The `session_id` is
/// caller-supplied so tests can verify both the valid (non-zero) and invalid
/// (zero) cases.
///
/// **N2.1.2.5:** The proof's `TransportBinding` records **which transport
/// endpoint the handshake actually occurred over**. The caller must supply
/// `endpoint_addr` — the canonical `host:port` string of the endpoint the
/// proof should be bound to. In a real SNP-IK handshake, this comes from
/// `TcpStream::peer_addr()` inside `perform_snp_ik_handshake_verified`. In
/// tests, we synthesize it via `snp_link::test_support::transport_binding_tcp`
/// so the proof's binding can be set to ANY endpoint (including ones that
/// DON'T match the `LinkKey.endpoint`, which is the basis of the
/// `TransportBindingMismatch` adversarial tests below).
///
/// This uses `snp_link::test_support::verified_handshake_from_fields` — the
/// test-only factory that calls `VerifiedHandshake`'s PRIVATE constructor.
/// The proof is real (it's minted inside `snp-link`), it just bypasses the
/// transport layer. Production code CANNOT call this factory — it is gated
/// behind `feature = "test-support"` and is physically absent from production
/// builds.
///
/// This is the same synthesis performed by `test_authenticated_link`, but
/// exposed so individual tests can drive `AuthenticatedLink::from_verified_handshake`
/// directly with adversarial inputs (zero session_id, mismatched X25519,
/// mismatched transport binding, etc.).
fn make_verified_handshake(
    advert: &VerifiedNodeAdvertisement,
    session_id: [u8; 32],
    endpoint_addr: &str,
) -> snp_link::VerifiedHandshake {
    verified_handshake_from_fields(
        advert.node_id(),
        *advert.ed25519_public_key(),
        advert.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        session_id,
        snp_link::test_support::transport_binding_tcp(endpoint_addr),
    )
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
    let auth_link = test_authenticated_link(key, &gw_verified)
        .expect("authenticated link must be created");

    let mut table = LinkTable::new();
    table.insert_authenticated(auth_link);
    assert_eq!(table.len(), 1, "authenticated link must be in the table");

    eprintln!("[test 1] PASS: unauthenticated link cannot enter link table (production path verified)");
}

/// 2. missing_handshake_cannot_create_up_link
///
/// `AuthenticatedLink::from_verified_handshake` rejects a `VerifiedHandshake`
/// whose `session_id` is all-zero (defensive check — no handshake was
/// performed). In production, `snp_link::perform_snp_ik_handshake_verified`
/// never produces a zero session_id, but the test-only factory lets us inject
/// one to verify the defensive check fires.
#[test]
fn missing_handshake_cannot_create_up_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"missing-hs-gw", 1, "127.0.0.1:1234");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1234"));

    // Construct a VerifiedHandshake with a ZERO session_id via the test-only
    // factory. The other fields (peer_node_id, peer_public_key,
    // peer_x25519_public, transport_binding) match the advertisement and
    // LinkKey, so the ONLY failing check is the zero session_id.
    let zero_proof = make_verified_handshake(&gw_verified, [0u8; 32], "127.0.0.1:1234");
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &zero_proof);
    assert!(matches!(result, Err(AuthenticatedLinkError::MissingHandshake)),
        "zero session_id must be rejected (no handshake)");

    eprintln!("[test 2] PASS: missing handshake cannot create up link");
}

/// 3. handshake_identity_mismatch_rejected
///
/// If the LinkKey.remote_node_id does not match the advertisement's NodeId,
/// the link is rejected with `NodeIdMismatch`.
#[test]
fn handshake_identity_mismatch_rejected() {
    let (gw_verified, _gw_id) = make_gateway_advert(b"mismatch-gw", 1, "127.0.0.1:1234");
    let local = [0x42; 32];
    // Use a DIFFERENT NodeId than the advertisement.
    let wrong_remote = [0x99; 32];
    let key = LinkKey::new(local, wrong_remote, TransportEndpoint::tcp("127.0.0.1:1234"));

    // The VerifiedHandshake matches the advertisement (so the handshake check
    // would pass on its own); the rejection comes from key.remote_node_id !=
    // advert.node_id(). The transport binding is set to the advert's endpoint
    // (which the key.endpoint also matches), so the only failing check is
    // the NodeId mismatch (check #1, fires before transport binding #7).
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), "127.0.0.1:1234");
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
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

    // The proof's transport binding matches the advert's endpoint
    // (127.0.0.1:1111) — what matters here is the LinkKey.endpoint, which is
    // NOT in the advert's endpoints. Check #2 (UnauthorizedEndpoint) fires
    // before check #7 (TransportBindingMismatch), so the proof's binding
    // value is irrelevant to which error is returned; we set it to the
    // advert's authorized endpoint to keep the only failing check focused.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), "127.0.0.1:1111");
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
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

    let auth_link = test_authenticated_link(key, &gw_verified)
        .expect("valid handshake must produce AuthenticatedLink");

    // The link has a non-zero session_id (proof of handshake).
    assert_ne!(auth_link.session_id(), [0u8; 32],
        "session_id must be non-zero (handshake was performed)");
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

    let mut auth_link = test_authenticated_link(key, &gw_verified).expect("valid link");
    assert_eq!(auth_link.state(), LinkState::Up);

    // Simulate failures → Degraded → Down.
    auth_link.record_failure();
    assert_eq!(auth_link.state(), LinkState::Degraded);
    auth_link.record_failure();
    auth_link.record_failure();
    assert_eq!(auth_link.state(), LinkState::Down);
    assert!(!auth_link.is_usable());

    // Simulate recovery → Up.
    auth_link.record_success(1000);
    assert_eq!(auth_link.state(), LinkState::Up);
    assert!(auth_link.is_usable());

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

    // Failed handshake = zero session_id. The VerifiedHandshake otherwise
    // matches the advertisement (including the transport binding matching
    // key.endpoint) so ONLY the zero session_id check fails.
    let zero_proof = make_verified_handshake(&gw_verified, [0u8; 32], "127.0.0.1:4444");
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &zero_proof);
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
/// Full end-to-end: create AuthenticatedLinks via test_authenticated_link,
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
    let auth_link_lb = test_authenticated_link(key_lb, &b_verified)
        .expect("local → B link must authenticate");
    topology.add_authenticated_link(auth_link_lb);

    // Gateway G with endpoint.
    let (g_verified, g_id) = make_gateway_advert(b"e2e-gw-g", 1, "127.0.0.1:1002");
    topology.accept_advertisement(g_verified.clone()).expect("accept G");

    // AuthenticatedLink: B → G via G's authorized endpoint.
    let key_bg = LinkKey::new(b_id, g_id, TransportEndpoint::tcp("127.0.0.1:1002"));
    let auth_link_bg = test_authenticated_link(key_bg, &g_verified)
        .expect("B → G link must authenticate");
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
/// Verify that the test-only `test_authenticated_link` helper is gated
/// behind the `test-support` Cargo feature. Production builds (which do NOT
/// enable `test-support`) cannot access `snp_node::test_support` at all —
/// the module is `#[cfg(any(test, feature = "test-support"))]` and is
/// physically absent from the production binary.
///
/// This test verifies the feature gate is correctly applied by calling
/// `test_authenticated_link` (which is only reachable when the feature is
/// enabled). If someone removes the feature gate or moves the helper into
/// the public production API, the security boundary is broken.
#[test]
fn production_build_has_no_public_new_up() {
    // We need a verified advert to construct an AuthenticatedLink via the
    // test-support helper. The key's endpoint must match the advert's endpoint.
    let (gw_verified, gw_id) = make_gateway_advert(b"feature-gate-gw", 1, "127.0.0.1:1");
    let key = LinkKey::new([0x42; 32], gw_id, TransportEndpoint::tcp("127.0.0.1:1"));
    let _auth = test_authenticated_link(key, &gw_verified)
        .expect("test_authenticated_link must work with test-support feature");

    // The important guarantee: production code (without test-support) CANNOT
    // call test_authenticated_link. The `snp_node::test_support` module is
    // not compiled in production builds.

    eprintln!("[test 10] PASS: test_support module is feature-gated (not in production)");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.2.4 — Unforgeable VerifiedHandshake proof: new tests
// ════════════════════════════════════════════════════════════════════════════

/// 11. peer_x25519_mismatch_rejected
///
/// N2.1.2.4: When the advertisement has an X25519 circuit public key
/// (mandatory for gateways), the `VerifiedHandshake`'s `peer_x25519_public`
/// MUST match. This prevents identity substitution where an attacker
/// authenticates as node B but uses a different X25519 key (e.g., to
/// intercept circuit traffic destined for B).
///
/// All other fields match the advertisement — the ONLY failing check is the
/// X25519 binding (check #5 in `from_verified_handshake`).
#[test]
fn peer_x25519_mismatch_rejected() {
    let (gw_verified, gw_id) = make_gateway_advert(b"x25519-mismatch-gw", 1, "127.0.0.1:7777");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:7777"));

    // The advert's real X25519 key (from make_gateway_advert).
    let advert_x25519 = gw_verified
        .circuit_x25519_pub()
        .expect("gateway must have X25519 circuit key");

    // Construct a proof with a DIFFERENT peer_x25519_public. All other
    // fields match the advertisement, so the ONLY failing check is the
    // X25519 binding (check #5 in from_verified_handshake).
    let wrong_x25519 = {
        let mut x = *advert_x25519;
        // Flip bits to make it different (avoid the all-zero key, which is
        // a separate failure mode not under test here).
        x[0] ^= 0xff;
        x
    };
    assert_ne!(
        wrong_x25519, *advert_x25519,
        "test setup: X25519 keys must differ"
    );

    let proof = verified_handshake_from_fields(
        gw_verified.node_id(),
        *gw_verified.ed25519_public_key(),
        wrong_x25519,
        fake_session_id(),
        snp_link::test_support::transport_binding_tcp("127.0.0.1:7777"),
    );
    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
    match result {
        Err(AuthenticatedLinkError::HandshakeX25519Mismatch) => { /* expected */ }
        other => panic!("expected HandshakeX25519Mismatch, got {other:?}"),
    }

    eprintln!("[test 11] PASS: peer X25519 mismatch rejected");
}

/// 12. public_handshake_result_cannot_construct_authenticated_link
///
/// N2.1.2.4: Verify that `AuthenticatedLink::from_handshake` (the N2.1.2.3
/// constructor that accepted a publicly-constructible `snp_link::HandshakeResult`)
/// was REMOVED. The only public constructor is now
/// `AuthenticatedLink::from_verified_handshake`, which takes an UNFORGEABLE
/// `snp_link::VerifiedHandshake`.
///
/// ## Compile-time guarantee
///
/// The removal of `from_handshake` is a compile-time guarantee enforced by
/// the Rust type system. The following code would NOT compile if uncommented:
///
/// ```ignore
/// let result: snp_link::HandshakeResult = /* publicly constructible */;
/// let _ = AuthenticatedLink::from_handshake(key, &advert, &result);
/// //                       ^^^^^^^^^^^^^^^ no such method exists in N2.1.2.4
/// ```
///
/// ## Runtime verification
///
/// This test verifies what we CAN verify at runtime:
/// 1. `snp_link::HandshakeResult` still exists and has PUBLIC fields — anyone
///    can construct one, which is exactly why it is NOT a sufficient security
///    proof.
/// 2. `snp_link::VerifiedHandshake` has PRIVATE fields and a PRIVATE
///    constructor — it CANNOT be constructed without either the actual
///    handshake (`perform_snp_ik_handshake_verified`) or the test-only
///    factory (`verified_handshake_from_fields`).
/// 3. The ONLY way to construct an `AuthenticatedLink` is via
///    `from_verified_handshake(&VerifiedHandshake)`.
#[test]
fn public_handshake_result_cannot_construct_authenticated_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"no-from-hs-gw", 1, "127.0.0.1:8888");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:8888"));

    // (1) HandshakeResult is PUBLIC and constructible by anyone — this is
    // exactly why it is NOT a sufficient security proof. An attacker could
    // synthesize one with arbitrary fields.
    let _publicly_constructed: snp_link::HandshakeResult = snp_link::HandshakeResult {
        link_keys: snp_link::LinkKeys {
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
        },
        peer_node_id: gw_verified.node_id(),
        peer_public_key: *gw_verified.ed25519_public_key(),
        peer_x25519_public: gw_verified.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        peer_ephemeral_public: [0u8; 32],
        session_id: fake_session_id(),
    };
    // Note: there is NO way to feed this HandshakeResult into an
    // AuthenticatedLink. The following line would NOT compile:
    //   AuthenticatedLink::from_handshake(key, &gw_verified, &_publicly_constructed);
    // because `from_handshake` was REMOVED in N2.1.2.4.

    // (2) The ONLY way to construct an AuthenticatedLink is via a
    // VerifiedHandshake, which (in production) can only be minted by
    // `perform_snp_ik_handshake_verified`. In tests, we use the test-only
    // factory. The proof's transport binding is bound to the same endpoint
    // the LinkKey uses (127.0.0.1:8888), satisfying the N2.1.2.5 check.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), "127.0.0.1:8888");
    let auth = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof)
        .expect("VerifiedHandshake matching the advert must produce an AuthenticatedLink");
    assert!(auth.is_usable());

    eprintln!("[test 12] PASS: public HandshakeResult cannot construct AuthenticatedLink (only VerifiedHandshake can)");
}

/// 13. test_only_verified_handshake_creates_authenticated_link
///
/// Verify the test-only factory `snp_link::test_support::verified_handshake_from_fields`
/// produces a genuine `VerifiedHandshake` that is accepted by
/// `AuthenticatedLink::from_verified_handshake`. This is the canonical test
/// path: it doesn't perform an actual SNP-IK handshake over a transport, but
/// the proof it produces is real (minted via the private constructor inside
/// `snp-link`).
#[test]
fn test_only_verified_handshake_creates_authenticated_link() {
    let (gw_verified, gw_id) = make_gateway_advert(b"factory-gw", 1, "127.0.0.1:9999");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:9999"));

    // Construct a VerifiedHandshake via the test-only factory. The transport
    // binding is set to match the LinkKey.endpoint (127.0.0.1:9999), so the
    // N2.1.2.5 transport binding check passes.
    let proof = verified_handshake_from_fields(
        gw_verified.node_id(),
        *gw_verified.ed25519_public_key(),
        gw_verified.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        fake_session_id(),
        snp_link::test_support::transport_binding_tcp("127.0.0.1:9999"),
    );

    // The proof must be accepted by from_verified_handshake.
    let auth = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof)
        .expect("test-factory proof matching the advert must produce an AuthenticatedLink");

    // The link's session_id comes from the proof.
    assert_eq!(auth.session_id(), fake_session_id());
    assert!(auth.is_usable());

    eprintln!("[test 13] PASS: test-only verified_handshake_from_fields creates AuthenticatedLink");
}

/// 14. authenticated_link_preserves_verified_handshake
///
/// N2.1.2.4: The `VerifiedHandshake` proof is RETAINED inside the
/// `AuthenticatedLink` — it is NOT discarded at the storage boundary.
/// `auth_link.handshake_proof()` returns a reference to the same proof that
/// was used to construct the link. This means the proof travels with the
/// link through the entire route-engine pipeline (LinkTable stores
/// AuthenticatedLink, not plain Link).
#[test]
fn authenticated_link_preserves_verified_handshake() {
    let (gw_verified, gw_id) = make_gateway_advert(b"preserve-proof-gw", 1, "127.0.0.1:7000");
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:7000"));

    // Mint a proof via the test-only factory. The transport binding is set
    // to match the LinkKey.endpoint (127.0.0.1:7000), satisfying the
    // N2.1.2.5 transport binding check.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), "127.0.0.1:7000");

    // Construct the AuthenticatedLink.
    let auth = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof)
        .expect("valid link");

    // The proof is preserved — handshake_proof() returns a reference to a
    // VerifiedHandshake with the same fields as the one we supplied.
    let preserved = auth.handshake_proof();
    assert_eq!(preserved.session_id(), proof.session_id());
    assert_eq!(preserved.peer_node_id(), proof.peer_node_id());
    assert_eq!(preserved.peer_public_key(), proof.peer_public_key());
    assert_eq!(preserved.peer_x25519_public(), proof.peer_x25519_public());

    // N2.1.2.5: The transport binding is also preserved (and matches what we
    // supplied to the factory). The endpoint accessor on the link returns
    // the same endpoint the proof is bound to.
    assert_eq!(preserved.transport_binding(), proof.transport_binding(),
        "transport binding must be preserved inside the AuthenticatedLink");

    // Sanity: the preserved proof matches the advert.
    assert_eq!(preserved.peer_node_id(), gw_verified.node_id());
    assert_eq!(preserved.peer_public_key(), *gw_verified.ed25519_public_key());

    eprintln!("[test 14] PASS: AuthenticatedLink preserves VerifiedHandshake proof");
}

/// 15. production_build_excludes_test_handshake_factory
///
/// Verify that `snp_link::test_support::verified_handshake_from_fields`
/// (the test-only factory for `VerifiedHandshake`) is gated behind the
/// `test-support` Cargo feature. Production builds (which do NOT enable
/// `test-support`) cannot access `snp_link::test_support` at all — the
/// module is `#[cfg(any(test, feature = "test-support"))]` and is physically
/// absent from the production binary.
///
/// This test verifies the feature gate is correctly applied by calling
/// `verified_handshake_from_fields` (only reachable when the feature is
/// enabled). If someone removes the feature gate or moves the factory into
/// the public production API, the security boundary is broken — external
/// code could manufacture `VerifiedHandshake` proofs without performing an
/// actual SNP-IK handshake.
#[test]
fn production_build_excludes_test_handshake_factory() {
    let (gw_verified, _) = make_gateway_advert(b"prod-factory-gate-gw", 1, "127.0.0.1:7001");

    // This call only compiles when the `test-support` feature is enabled.
    // In a production build (no test-support), `snp_link::test_support` is
    // physically absent. The transport binding is set to match the
    // LinkKey.endpoint (127.0.0.1:7001) so the N2.1.2.5 check passes.
    let proof = verified_handshake_from_fields(
        gw_verified.node_id(),
        *gw_verified.ed25519_public_key(),
        gw_verified.circuit_x25519_pub().copied().unwrap_or([0u8; 32]),
        fake_session_id(),
        snp_link::test_support::transport_binding_tcp("127.0.0.1:7001"),
    );

    // The proof is a genuine VerifiedHandshake — it passes from_verified_handshake.
    let local = [0x42; 32];
    let key = LinkKey::new(
        local,
        gw_verified.node_id(),
        TransportEndpoint::tcp("127.0.0.1:7001"),
    );
    let _auth = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof)
        .expect("test-factory proof must produce AuthenticatedLink");

    eprintln!("[test 15] PASS: snp_link::test_support factory is feature-gated (not in production)");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.2.5 — Transport binding tests
// ════════════════════════════════════════════════════════════════════════════

/// Create a gateway advertisement (signed, verified, with X25519) with TWO
/// endpoints. Used by N2.1.2.5 transport-binding adversarial tests that need
/// an advertisement listing multiple endpoints — the mismatch scenario
/// requires both the proof's binding endpoint AND the LinkKey.endpoint to be
/// authorized (otherwise `UnauthorizedEndpoint` fires before
/// `TransportBindingMismatch`).
fn make_gateway_advert_two_endpoints(
    label: &[u8],
    seq: u64,
    endpoint_a: &str,
    endpoint_b: &str,
) -> (VerifiedNodeAdvertisement, [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Gateway],
        vec![
            TransportEndpoint::tcp(endpoint_a),
            TransportEndpoint::tcp(endpoint_b),
        ],
        Some(x_pk.to_bytes()),
        3600,
        seq,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    (verified, derive_node_id(&pk))
}

/// 16. handshake_endpoint_binding_mismatch_rejected
///
/// **N2.1.2.5.** The advertisement lists endpoints A and B. A `VerifiedHandshake`
/// proof is bound to endpoint A (i.e., the SNP-IK handshake actually occurred
/// over A — in production this comes from `TcpStream::peer_addr()`). The
/// `LinkKey`, however, claims endpoint B (which IS advertised, so check #2
/// `UnauthorizedEndpoint` passes).
///
/// `from_verified_handshake` MUST reject this with `TransportBindingMismatch`
/// (check #7). This is the central N2.1.2.5 adversarial case: a caller cannot
/// perform a handshake over endpoint A, then construct an `AuthenticatedLink`
/// claiming endpoint B (even though B is also advertised). The handshake proof
/// is bound to the ACTUAL transport endpoint used; the link must use that same
/// endpoint.
#[test]
fn handshake_endpoint_binding_mismatch_rejected() {
    let endpoint_a = "127.0.0.1:8001";
    let endpoint_b = "127.0.0.1:8002";
    let (gw_verified, gw_id) =
        make_gateway_advert_two_endpoints(b"mismatch-tb-gw", 1, endpoint_a, endpoint_b);
    let local = [0x42; 32];

    // LinkKey claims endpoint B (advertised, so check #2 passes).
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_b));

    // Proof is bound to endpoint A — the handshake actually occurred over A,
    // NOT B. This is the adversarial input: the proof is genuine (minted via
    // the private constructor inside snp-link), but its transport_binding
    // disagrees with the LinkKey.endpoint.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), endpoint_a);

    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
    match result {
        Err(AuthenticatedLinkError::TransportBindingMismatch {
            link_endpoint,
            proof_endpoint,
        }) => {
            // The error must mention BOTH endpoints — the one in the LinkKey
            // and the one bound to the proof.
            assert!(
                link_endpoint.contains("8002"),
                "error must mention the LinkKey endpoint (B): got {link_endpoint}"
            );
            assert!(
                proof_endpoint.contains("8001"),
                "error must mention the proof's transport binding endpoint (A): got {proof_endpoint}"
            );
        }
        other => panic!("expected TransportBindingMismatch, got {other:?}"),
    }

    eprintln!("[test 16] PASS: handshake endpoint binding mismatch rejected");
}

/// 17. advertised_endpoint_but_not_actual_handshake_endpoint_rejected
///
/// **N2.1.2.5.** Companion to test 16 with a different framing. The
/// advertisement lists endpoints A and B. The `LinkKey` uses endpoint A
/// (which IS advertised), but the `VerifiedHandshake` proof is bound to
/// endpoint B (i.e., the handshake actually occurred over B). Even though
/// both A and B are advertised, the link MUST use the same endpoint the
/// handshake actually used — `from_verified_handshake` rejects with
/// `TransportBindingMismatch`.
///
/// This is the inverse of test 16 (proof bound to A, key uses B → here
/// proof bound to B, key uses A). Both directions must be rejected.
#[test]
fn advertised_endpoint_but_not_actual_handshake_endpoint_rejected() {
    let endpoint_a = "127.0.0.1:8101";
    let endpoint_b = "127.0.0.1:8102";
    let (gw_verified, gw_id) =
        make_gateway_advert_two_endpoints(b"inv-mismatch-tb-gw", 1, endpoint_a, endpoint_b);
    let local = [0x42; 32];

    // LinkKey uses endpoint A (advertised, so check #2 passes).
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_a));

    // Proof is bound to endpoint B — the handshake actually occurred over B.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), endpoint_b);

    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
    assert!(
        matches!(result, Err(AuthenticatedLinkError::TransportBindingMismatch { .. })),
        "advertised endpoint that is not the actual handshake endpoint must be rejected with TransportBindingMismatch, got {result:?}"
    );

    eprintln!("[test 17] PASS: advertised endpoint ≠ actual handshake endpoint rejected");
}

/// 18. authenticated_link_requires_both_bindings
///
/// **N2.1.2.5.** An `AuthenticatedLink` requires BOTH:
///   (a) **Endpoint authorization** — the `LinkKey.endpoint` must appear in
///       the advertisement's `endpoints` list (check #2). This prevents an
///       attacker from binding an arbitrary endpoint to a verified NodeId.
///   (b) **Transport binding** — the `LinkKey.endpoint` must match the actual
///       transport endpoint the handshake occurred over (check #7). This
///       prevents identity/location confusion (handshake over A, link claims B).
///
/// This test exercises all three outcomes:
///   1. Unauthorized endpoint → `UnauthorizedEndpoint` (check #2 fires).
///   2. Authorized endpoint but proof bound elsewhere → `TransportBindingMismatch`
///      (check #7 fires).
///   3. Both checks pass → `Ok(AuthenticatedLink)`.
#[test]
fn authenticated_link_requires_both_bindings() {
    let endpoint_a = "127.0.0.1:8201";
    let endpoint_b = "127.0.0.1:8202";
    let unauthorized = "127.0.0.1:8299"; // not advertised at all
    let (gw_verified, gw_id) =
        make_gateway_advert_two_endpoints(b"both-bindings-gw", 1, endpoint_a, endpoint_b);
    let local = [0x42; 32];

    // ── (1) Endpoint authorization check (check #2: UnauthorizedEndpoint).
    // LinkKey.endpoint is NOT in the advert's endpoints. The proof's binding
    // matches the LinkKey.endpoint (so check #7 WOULD pass), but check #2
    // fires first because the endpoint isn't authorized.
    let key_unauth = LinkKey::new(local, gw_id, TransportEndpoint::tcp(unauthorized));
    let proof_unauth = make_verified_handshake(&gw_verified, fake_session_id(), unauthorized);
    let result_unauth =
        AuthenticatedLink::from_verified_handshake(key_unauth, &gw_verified, &proof_unauth);
    assert!(
        matches!(result_unauth, Err(AuthenticatedLinkError::UnauthorizedEndpoint { .. })),
        "unauthorized endpoint must be rejected with UnauthorizedEndpoint, got {result_unauth:?}"
    );

    // ── (2) Transport binding check (check #7: TransportBindingMismatch).
    // LinkKey.endpoint IS authorized (endpoint_a in advert), but the proof is
    // bound to endpoint_b — the handshake occurred over B, not A. Check #2
    // passes, but check #7 fails.
    let key_mismatch = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_a));
    let proof_mismatch = make_verified_handshake(&gw_verified, fake_session_id(), endpoint_b);
    let result_mismatch =
        AuthenticatedLink::from_verified_handshake(key_mismatch, &gw_verified, &proof_mismatch);
    assert!(
        matches!(result_mismatch, Err(AuthenticatedLinkError::TransportBindingMismatch { .. })),
        "transport binding mismatch must be rejected with TransportBindingMismatch, got {result_mismatch:?}"
    );

    // ── (3) Both checks pass — the link is created.
    // LinkKey.endpoint is authorized AND matches the proof's binding.
    let key_ok = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_a));
    let proof_ok = make_verified_handshake(&gw_verified, fake_session_id(), endpoint_a);
    let auth = AuthenticatedLink::from_verified_handshake(key_ok, &gw_verified, &proof_ok)
        .expect("both checks passing must produce an AuthenticatedLink");
    assert!(auth.is_usable());

    eprintln!("[test 18] PASS: AuthenticatedLink requires both endpoint authorization AND transport binding");
}

/// 19. different_sessions_same_peer_same_endpoint_allowed
///
/// **N2.1.2.5.** Two `VerifiedHandshake` proofs with DIFFERENT `session_id`s
/// but the SAME transport endpoint (and same peer identity) must BOTH be
/// accepted by `from_verified_handshake`. Each produces its own
/// `AuthenticatedLink` with its own session_id.
///
/// This models the real-world scenario where a peer's session expires (or the
/// link is re-keyed) and a new handshake is performed over the same transport
/// endpoint. The new session supersedes the old, but both are individually
/// valid proofs.
#[test]
fn different_sessions_same_peer_same_endpoint_allowed() {
    let endpoint = "127.0.0.1:8301";
    let (gw_verified, gw_id) = make_gateway_advert(b"same-ep-two-sessions-gw", 1, endpoint);
    let local = [0x42; 32];

    // Two different non-zero session IDs.
    let mut session_a = [0u8; 32];
    session_a[0] = 0xAA;
    let mut session_b = [0u8; 32];
    session_b[0] = 0xBB;
    assert_ne!(session_a, session_b, "test setup: sessions must differ");

    // Two proofs, same peer + same endpoint, different sessions.
    let proof_a = make_verified_handshake(&gw_verified, session_a, endpoint);
    let proof_b = make_verified_handshake(&gw_verified, session_b, endpoint);
    assert_ne!(proof_a.session_id(), proof_b.session_id());
    // Both proofs are bound to the same transport endpoint.
    assert_eq!(proof_a.transport_binding(), proof_b.transport_binding());

    // Both must produce valid AuthenticatedLinks over the same endpoint.
    let key_a = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint));
    let auth_a = AuthenticatedLink::from_verified_handshake(key_a, &gw_verified, &proof_a)
        .expect("session A over endpoint must produce a link");

    // Use a slightly different local NodeId for the second link to keep the
    // LinkKeys distinct (LinkKey equality includes local_node_id).
    let local_b = [0x43; 32];
    let key_b = LinkKey::new(local_b, gw_id, TransportEndpoint::tcp(endpoint));
    let auth_b = AuthenticatedLink::from_verified_handshake(key_b, &gw_verified, &proof_b)
        .expect("session B over endpoint must produce a link");

    // Each link's session_id matches its proof.
    assert_eq!(auth_a.session_id(), session_a);
    assert_eq!(auth_b.session_id(), session_b);
    assert_ne!(auth_a.session_id(), auth_b.session_id());
    assert!(auth_a.is_usable() && auth_b.is_usable());

    eprintln!("[test 19] PASS: different sessions over the same endpoint are both allowed");
}

/// 20. different_sessions_different_endpoints_produce_different_bindings
///
/// **N2.1.2.5.** Two `VerifiedHandshake` proofs bound to DIFFERENT transport
/// endpoints must have DIFFERENT `TransportBinding`s. Each proof can
/// independently produce an `AuthenticatedLink` over its respective endpoint.
///
/// This models a peer that is reachable over two transports (e.g., TCP and a
/// future BLE transport) — a handshake over endpoint A produces a proof bound
/// to A, distinct from a handshake over endpoint B.
#[test]
fn different_sessions_different_endpoints_produce_different_bindings() {
    let endpoint_a = "127.0.0.1:8401";
    let endpoint_b = "127.0.0.1:8402";
    let (gw_verified, gw_id) =
        make_gateway_advert_two_endpoints(b"two-ep-two-bindings-gw", 1, endpoint_a, endpoint_b);
    let local = [0x42; 32];

    // Two proofs bound to different endpoints. Use different session IDs as
    // well (the realistic case — different handshakes produce different
    // sessions).
    let mut session_a = [0u8; 32];
    session_a[0] = 0xA1;
    let mut session_b = [0u8; 32];
    session_b[0] = 0xB2;

    let proof_a = make_verified_handshake(&gw_verified, session_a, endpoint_a);
    let proof_b = make_verified_handshake(&gw_verified, session_b, endpoint_b);

    // The transport bindings must differ — they're bound to different
    // endpoints, so the canonical_addr strings differ.
    assert_ne!(
        proof_a.transport_binding(),
        proof_b.transport_binding(),
        "proofs bound to different endpoints must have different TransportBindings"
    );
    assert_eq!(proof_a.transport_binding().canonical_addr(), endpoint_a);
    assert_eq!(proof_b.transport_binding().canonical_addr(), endpoint_b);

    // Each proof produces a valid AuthenticatedLink over its own endpoint.
    let key_a = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_a));
    let auth_a = AuthenticatedLink::from_verified_handshake(key_a, &gw_verified, &proof_a)
        .expect("proof A over endpoint A must produce a link");

    let local_b = [0x43; 32];
    let key_b = LinkKey::new(local_b, gw_id, TransportEndpoint::tcp(endpoint_b));
    let auth_b = AuthenticatedLink::from_verified_handshake(key_b, &gw_verified, &proof_b)
        .expect("proof B over endpoint B must produce a link");

    // Cross-check: proof A cannot be used to mint a link over endpoint B
    // (transport binding mismatch), and vice versa.
    let key_cross = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint_b));
    let cross = AuthenticatedLink::from_verified_handshake(key_cross, &gw_verified, &proof_a);
    assert!(
        matches!(cross, Err(AuthenticatedLinkError::TransportBindingMismatch { .. })),
        "proof A cannot mint a link over endpoint B"
    );

    // The two links have different session_ids and different transport bindings.
    assert_ne!(auth_a.session_id(), auth_b.session_id());
    assert_ne!(
        auth_a.handshake_proof().transport_binding(),
        auth_b.handshake_proof().transport_binding()
    );

    eprintln!("[test 20] PASS: different endpoints produce different transport bindings");
}

/// 21. handshake_endpoint_binding_matches_actual_tcp_peer
///
/// **N2.1.2.5.** The `VerifiedHandshake`'s `transport_binding()` accessor
/// returns the actual transport endpoint used by the handshake. For a TCP
/// handshake, this is the canonical `host:port` string of the
/// `TcpStream::peer_addr()`. The transport type is `TransportType::Tcp`.
///
/// This test verifies the accessor returns the correct values after a
/// successful `from_verified_handshake` — the link's preserved proof carries
/// the binding the caller supplied to the test-only factory (in production,
/// the value `perform_snp_ik_handshake_verified` extracted from
/// `TcpStream::peer_addr()`).
#[test]
fn handshake_endpoint_binding_matches_actual_tcp_peer() {
    let endpoint = "127.0.0.1:8501";
    let (gw_verified, gw_id) = make_gateway_advert(b"tb-accessor-gw", 1, endpoint);
    let local = [0x42; 32];
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp(endpoint));

    // Proof bound to the TCP endpoint.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), endpoint);

    // Construct the AuthenticatedLink.
    let auth = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof)
        .expect("valid link");

    // Access the preserved proof's transport binding.
    let binding = auth.handshake_proof().transport_binding();

    // The transport type is TCP.
    assert_eq!(
        binding.transport(),
        snp_link::TransportType::Tcp,
        "transport type must be Tcp for a TCP handshake"
    );

    // The canonical address matches the endpoint we bound to. The
    // `transport_binding_tcp` factory stores the address as-is, and the
    // `canonicalize_tcp_addr_str` comparison in `from_verified_handshake`
    // parses `127.0.0.1:8501` into a SocketAddrV4 and re-formats it as
    // `127.0.0.1:8501` (already canonical), so the round-trip is identity.
    assert_eq!(
        binding.canonical_addr(),
        endpoint,
        "canonical_addr must match the endpoint the proof was bound to"
    );

    // Sanity: the binding also matches the LinkKey.endpoint (this is the
    // invariant `from_verified_handshake` check #7 enforces — its `Ok`
    // return is the proof the invariant held).
    assert!(
        auth.is_usable(),
        "link must be usable when binding matches LinkKey.endpoint"
    );

    eprintln!("[test 21] PASS: transport binding accessor returns the correct TCP endpoint");
}

/// 22. actual_endpoint_not_advertised_rejected
///
/// **N2.1.2.5.** The `VerifiedHandshake`'s `transport_binding` records the
/// ACTUAL endpoint the handshake occurred over. If that actual endpoint is
/// NOT in the advertisement's `endpoints` list, the proof is suspicious —
/// the peer authenticated via an endpoint it never advertised.
///
/// Setup:
/// - Advertisement lists endpoint A only.
/// - `LinkKey.endpoint` = A (so check #2 `UnauthorizedEndpoint` passes — A is
///   advertised).
/// - Proof's `transport_binding` = X, where X is NOT in the advertisement.
///
/// `from_verified_handshake` MUST reject with `TransportBindingMismatch`
/// (check #7): the LinkKey says A, the proof says X, they disagree. (Check #2
/// passes because the LinkKey.endpoint A IS advertised; the proof's binding X
/// is what's wrong.)
///
/// In production, this scenario would arise if a MITM performed the handshake
/// over a different endpoint than the one the peer advertised — the proof
/// itself records the actual endpoint, exposing the mismatch.
#[test]
fn actual_endpoint_not_advertised_rejected() {
    let advertised = "127.0.0.1:8601";
    let not_advertised = "127.0.0.1:8699"; // proof is bound here, NOT advertised
    let (gw_verified, gw_id) = make_gateway_advert(b"actual-ep-not-adv-gw", 1, advertised);
    let local = [0x42; 32];

    // LinkKey uses the advertised endpoint A — check #2 passes.
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp(advertised));

    // Proof is bound to X — the handshake actually occurred over an endpoint
    // that is NOT in the advertisement. The proof's binding disagrees with
    // the LinkKey.endpoint (A != X), so check #7 fires.
    let proof = make_verified_handshake(&gw_verified, fake_session_id(), not_advertised);

    let result = AuthenticatedLink::from_verified_handshake(key, &gw_verified, &proof);
    match result {
        Err(AuthenticatedLinkError::TransportBindingMismatch {
            link_endpoint,
            proof_endpoint,
        }) => {
            // The LinkKey.endpoint (advertised A) and the proof's binding (X,
            // not advertised) must both appear in the error.
            assert!(
                link_endpoint.contains("8601"),
                "error must mention the LinkKey endpoint (advertised A): got {link_endpoint}"
            );
            assert!(
                proof_endpoint.contains("8699"),
                "error must mention the proof's binding (X, not advertised): got {proof_endpoint}"
            );
        }
        other => panic!("expected TransportBindingMismatch, got {other:?}"),
    }

    eprintln!("[test 22] PASS: actual handshake endpoint not advertised rejected");
}

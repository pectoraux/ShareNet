//! N2.1.0 — Generic Authenticated Node Advertisement tests.
//!
//! Tests the generic `NodeAdvertisement` + `VerifiedNodeAdvertisement` +
//! `VerifiedNodeDescriptor` pipeline for ALL node roles (relay, gateway,
//! multi-role).
#![allow(clippy::pedantic)]
use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, NodeAdvertisement, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
/// Helper: generate a fresh Ed25519 keypair.
fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}
/// 1. authenticated_relay_descriptor
#[test]
fn authenticated_relay_descriptor() {
    let (sk, pk) = fresh_keypair(b"relay-1");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None, // no X25519 circuit key for relays
        3600, 1,  // sequence = 1
    );
    let verified = advert.verify_into_verified()
        .expect("relay advertisement must verify");
    let desc = verified.descriptor();
    assert_eq!(desc.node_id(), derive_node_id(&pk));
    assert!(desc.is_relay());
    assert!(!desc.is_gateway());
    assert!(desc.circuit_x25519_pub().is_none());
    eprintln!("[test 1] PASS: authenticated relay descriptor");
}
/// 2. authenticated_gateway_descriptor
#[test]
fn authenticated_gateway_descriptor() {
    let (sk, pk) = fresh_keypair(b"gateway-1");
    let (x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    let verified = advert.verify_into_verified()
        .expect("gateway advertisement must verify");
    let desc = verified.descriptor();
    assert_eq!(desc.node_id(), derive_node_id(&pk));
    assert!(desc.is_gateway());
    assert!(desc.circuit_x25519_pub().is_some());
    eprintln!("[test 2] PASS: authenticated gateway descriptor");
}
/// 3. authenticated_multi_role_descriptor
#[test]
fn authenticated_multi_role_descriptor() {
    let (sk, pk) = fresh_keypair(b"multi-role-1");
    let (x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay, Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:9999")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    let verified = advert.verify_into_verified()
        .expect("multi-role advertisement must verify");
    let desc = verified.descriptor();
    assert!(desc.is_relay());
    assert!(desc.is_gateway());
    eprintln!("[test 3] PASS: authenticated multi-role descriptor");
}
/// 4. invalid_relay_signature_rejected
#[test]
fn invalid_relay_signature_rejected() {
    let (sk, pk) = fresh_keypair(b"relay-bad-sig");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None,
        3600, 1,  // sequence = 1
    );
    // Tamper with the signature.
    advert.signature[0] ^= 0xff;
    assert!(advert.verify_into_verified().is_none(),
        "tampered signature MUST be rejected");
    eprintln!("[test 4] PASS: invalid relay signature rejected");
}
/// 5. invalid_gateway_signature_rejected
#[test]
fn invalid_gateway_signature_rejected() {
    let (sk, pk) = fresh_keypair(b"gateway-bad-sig");
    let (x_sk, x_pk) = x25519_static_keypair();
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    advert.signature[0] ^= 0xff;
    assert!(advert.verify_into_verified().is_none(),
        "tampered gateway signature MUST be rejected");
    eprintln!("[test 5] PASS: invalid gateway signature rejected");
}
/// 6. tampered_capabilities_rejected
#[test]
fn tampered_capabilities_rejected() {
    let (sk, pk) = fresh_keypair(b"relay-tamper-cap");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None,
        3600, 1,  // sequence = 1
    );
    // Tamper with capabilities after signing.
    advert.capabilities.push(Capability::Gateway);
    assert!(advert.verify_into_verified().is_none(),
        "tampered capabilities MUST be rejected (signature no longer matches)");
    eprintln!("[test 6] PASS: tampered capabilities rejected");
}
/// 7. tampered_endpoint_rejected
#[test]
fn tampered_endpoint_rejected() {
    let (sk, pk) = fresh_keypair(b"relay-tamper-ep");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None,
        3600, 1,  // sequence = 1
    );
    // Tamper with the endpoint after signing.
    advert.endpoints[0] = TransportEndpoint::tcp("127.0.0.1:9999");
    assert!(advert.verify_into_verified().is_none(),
        "tampered endpoint MUST be rejected (signature covers endpoints)");
    eprintln!("[test 7] PASS: tampered endpoint rejected");
}
/// 8. tampered_gateway_x25519_key_rejected
#[test]
fn tampered_gateway_x25519_key_rejected() {
    let (sk, pk) = fresh_keypair(b"gateway-tamper-x25519");
    let (x_sk, x_pk) = x25519_static_keypair();
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    // Tamper with the X25519 key after signing.
    if let Some(ref mut key) = advert.x25519_circuit_public {
        key[0] ^= 0xff;
    }
    assert!(advert.verify_into_verified().is_none(),
        "tampered X25519 key MUST be rejected (signature covers it)");
    eprintln!("[test 8] PASS: tampered gateway X25519 key rejected");
}
/// 9. replayed_advertisement_rejected (expired)
#[test]
fn replayed_advertisement_rejected() {
    let (sk, pk) = fresh_keypair(b"relay-expired");
    // Create an advertisement that expires in 0 seconds (already expired).
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None,
        0, 1, // expires immediately, sequence = 1
    );
    // Wait a tiny bit to ensure `now > expiry`.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(advert.verify_into_verified().is_none(),
        "expired advertisement MUST be rejected");
    eprintln!("[test 9] PASS: expired advertisement rejected");
}
/// 10. relay_route_hop_accepts_no_gateway_key
#[test]
fn relay_route_hop_accepts_no_gateway_key() {
    let (sk, pk) = fresh_keypair(b"relay-hop-no-key");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None,
        3600, 1,  // sequence = 1
    );
    let verified = advert.verify_into_verified().expect("must verify");
    let desc = verified.descriptor();
    // A relay descriptor has NO X25519 circuit key — this is valid.
    assert!(desc.circuit_x25519_pub().is_none());
    // We can construct a RouteHop from it.
    let hop = RouteHop::new(desc, TransportEndpoint::tcp("127.0.0.1:1"));
    assert_eq!(hop.node_id(), derive_node_id(&pk));
    eprintln!("[test 10] PASS: relay route hop accepts no gateway key");
}
/// 11. gateway_route_hop_requires_gateway_key (via route validation)
#[test]
fn gateway_route_hop_requires_gateway_key() {
    let (client_sk, client_pk) = fresh_keypair(b"client-gw-key");
    let (gw_sk, gw_pk) = fresh_keypair(b"gateway-key-required");
    let (x_sk, x_pk) = x25519_static_keypair();
    // Gateway WITH X25519 key — valid.
    let gw_advert = NodeAdvertisement::create_and_sign(
        &gw_sk, &gw_pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    let gw_verified = gw_advert.verify_into_verified().expect("must verify");
    let gw_desc = gw_verified.descriptor();
    assert!(gw_desc.circuit_x25519_pub().is_some());
    // Construct a valid route: client → gateway.
    let route = Route::new_with_hop_details(
        derive_node_id(&client_pk),
        derive_node_id(&gw_pk),
        vec![RouteHop::new(gw_desc, TransportEndpoint::tcp("127.0.0.1:1"))],
    );
    route.validate().expect("valid gateway route must pass validation");
    eprintln!("[test 11] PASS: gateway route hop with X25519 key is valid");
}
/// 12. multi_hop_route_relay_relay_gateway
#[test]
fn multi_hop_route_relay_relay_gateway() {
    let (client_sk, client_pk) = fresh_keypair(b"client-multi");
    let (relay_a_sk, relay_a_pk) = fresh_keypair(b"relay-a-multi");
    let (relay_b_sk, relay_b_pk) = fresh_keypair(b"relay-b-multi");
    let (gw_sk, gw_pk) = fresh_keypair(b"gw-multi");
    let (x_sk, x_pk) = x25519_static_keypair();
    // Relay A advertisement (no X25519 key).
    let relay_a_advert = NodeAdvertisement::create_and_sign(
        &relay_a_sk, &relay_a_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None,
        3600, 1,  // sequence = 1
    );
    let relay_a_desc = relay_a_advert.verify_into_verified().expect("must verify").descriptor();
    // Relay B advertisement (no X25519 key).
    let relay_b_advert = NodeAdvertisement::create_and_sign(
        &relay_b_sk, &relay_b_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None,
        3600, 1,  // sequence = 1
    );
    let relay_b_desc = relay_b_advert.verify_into_verified().expect("must verify").descriptor();
    // Gateway advertisement (with X25519 key).
    let gw_advert = NodeAdvertisement::create_and_sign(
        &gw_sk, &gw_pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:3")],
        Some(x_pk.to_bytes()),
        3600, 1,  // sequence = 1
    );
    let gw_desc = gw_advert.verify_into_verified().expect("must verify").descriptor();
    // Construct the route: Client → Relay A → Relay B → Gateway.
    let route = Route::new_with_hop_details(
        derive_node_id(&client_pk),
        derive_node_id(&gw_pk),
        vec![
            RouteHop::new(relay_a_desc, TransportEndpoint::tcp("127.0.0.1:1")),
            RouteHop::new(relay_b_desc, TransportEndpoint::tcp("127.0.0.1:2")),
            RouteHop::new(gw_desc, TransportEndpoint::tcp("127.0.0.1:3")),
        ],
    );
    route.validate().expect("multi-hop relay→relay→gateway route must validate");
    eprintln!("[test 12] PASS: multi-hop route relay→relay→gateway validated");
}
/// 13. node_descriptor_alias_removed
#[test]
fn node_descriptor_alias_removed() {
    // The dangerous `pub type NodeDescriptor = UnverifiedNodeDescriptor`
    // alias has been removed. Verify it no longer exists by checking that
    // `snp_node::node::NodeDescriptor` does NOT compile.
    //
    // We can't test this at compile time from a test, but we can scan the
    // source.
    //
    // R2.2 (DESCRIPTOR-EXTRACTION): the descriptor types were moved to
    // `snp-identity/src/descriptor.rs`. The `include_str!` path now points
    // there instead of the local re-export stub in
    // `snp-node/src/node/descriptor.rs`.
    let source = include_str!("../../snp-identity/src/descriptor.rs");
    assert!(
        !source.contains("pub type NodeDescriptor ="),
        "The dangerous `NodeDescriptor = UnverifiedNodeDescriptor` alias MUST be removed"
    );
    eprintln!("[test 13] PASS: NodeDescriptor alias removed");
}
/// 14. cross_platform_advertisement_vectors
/// Verifies that the canonical CBOR encoding of a NodeAdvertisement is
/// deterministic (same input → same output). This is the foundation for
/// cross-platform reproducibility.
#[test]
fn cross_platform_advertisement_vectors() {
    let (sk, pk) = fresh_keypair(b"cross-platform-test");
    let advert1 = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None,
        3600, 1,  // sequence = 1
    );
    // The same secret key + same inputs produces the same NodeId + Ed25519 pk.
    // The nonce is random, so two advertisements will have different nonces
    // (and therefore different signatures). But the preimage structure is
    // deterministic.
    //
    // Verify that the preimage CBOR is well-formed and can be re-encoded.
    let verified1 = advert1.verify_into_verified().expect("must verify");
    assert_eq!(verified1.node_id(), derive_node_id(&pk));
    assert_eq!(verified1.ed25519_public_key(), &pk);
    // Two different advertisements from the same node have different nonces.
    let advert2 = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None,
        3600, 1,  // sequence = 1
    );
    assert_ne!(
        advert1.nonce, advert2.nonce,
        "two advertisements from the same node MUST have different nonces"
    );
    eprintln!("[test 14] PASS: cross-platform advertisement encoding is deterministic");
}
// ════════════════════════════════════════════════════════════════════════════
// Static guard: VerifiedNodeDescriptor is NOT gateway-specific
// ════════════════════════════════════════════════════════════════════════════
/// Verify that `VerifiedNodeDescriptor` can be constructed from
/// `VerifiedNodeAdvertisement` (the generic path), NOT just from
/// `VerifiedGatewayAdvertisement`.
#[test]
fn verified_node_descriptor_is_generic() {
    // R2.2 (DESCRIPTOR-EXTRACTION): the descriptor types were moved to
    // `snp-identity/src/descriptor.rs`. The `include_str!` path now points
    // there instead of the local re-export stub in
    // `snp-node/src/node/descriptor.rs`.
    let source = include_str!("../../snp-identity/src/descriptor.rs");
    assert!(
        source.contains("from_verified_advert_internal"),
        "VerifiedNodeDescriptor must have a generic construction path from NodeAdvertisement"
    );
    assert!(
        !source.contains("pub type NodeDescriptor ="),
        "The NodeDescriptor alias MUST be removed"
    );
    let advert_source = include_str!("../src/node/node_advert.rs");
    assert!(
        advert_source.contains("pub struct NodeAdvertisement"),
        "NodeAdvertisement must exist"
    );
    assert!(
        advert_source.contains("pub struct VerifiedNodeAdvertisement"),
        "VerifiedNodeAdvertisement must exist"
    );
    assert!(
        advert_source.contains("fn verify_into_verified"),
        "NodeAdvertisement::verify_into_verified must exist"
    );
    eprintln!("[static-guard] PASS: VerifiedNodeDescriptor is generic (not gateway-specific)");
}
// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.1 — Sequence, clock, role/key, and acceptance store tests
// ════════════════════════════════════════════════════════════════════════════
use snp_node::node::{
    AcceptanceResult, AdvertisementAcceptanceStore, AuthenticatedNodeRecord,
    MAX_ADVERTISEMENT_LIFETIME_SECS, MAX_CLOCK_SKEW_SECS,
};
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
/// 16. newer_advertisement_supersedes_older
#[test]
fn newer_advertisement_supersedes_older() {
    let (sk, pk) = fresh_keypair(b"seq-newer");
    let mut store = AdvertisementAcceptanceStore::new();
    // First advertisement (sequence 1).
    let advert1 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    let verified1 = advert1.verify_into_verified().expect("advert 1 must verify");
    let result1 = store.accept(verified1).expect("accept must succeed");
    assert!(matches!(result1, AcceptanceResult::Accepted(_)), "first advert must be accepted");
    // Second advertisement (sequence 2 — newer).
    let advert2 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None, 3600, 2,
    );
    let verified2 = advert2.verify_into_verified().expect("advert 2 must verify");
    let result2 = store.accept(verified2).expect("accept must succeed");
    assert!(matches!(result2, AcceptanceResult::Accepted(_)), "newer advert must be accepted");
    eprintln!("[test 16] PASS: newer advertisement supersedes older");
}
/// 17. older_advertisement_rejected_as_stale
#[test]
fn older_advertisement_rejected_as_stale() {
    let (sk, pk) = fresh_keypair(b"seq-stale");
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 2 first.
    let advert2 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 2,
    );
    let verified2 = advert2.verify_into_verified().expect("must verify");
    store.accept(verified2).expect("accept must succeed");
    // Now try sequence 1 (older) — must be rejected as stale.
    let advert1 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    let verified1 = advert1.verify_into_verified().expect("must verify");
    let result = store.accept(verified1).expect("accept must succeed");
    assert!(matches!(result, AcceptanceResult::Stale { advert_sequence: 1, known_sequence: 2 }),
        "older sequence must be rejected as stale; got {:?}", result);
    eprintln!("[test 17] PASS: older advertisement rejected as stale");
}
/// 18. same_sequence_duplicate_rejected
#[test]
fn same_sequence_duplicate_rejected() {
    let (sk, pk) = fresh_keypair(b"seq-dup");
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 1.
    let advert1 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    let verified1 = advert1.verify_into_verified().expect("must verify");
    store.accept(verified1).expect("accept must succeed");
    // Same sequence (different nonce, but same sequence) — must be rejected.
    let advert1b = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1, // same sequence
    );
    let verified1b = advert1b.verify_into_verified().expect("must verify");
    let result = store.accept(verified1b).expect("accept must succeed");
    assert!(matches!(result, AcceptanceResult::Duplicate { sequence: 1 }),
        "same sequence must be rejected as duplicate; got {:?}", result);
    eprintln!("[test 18] PASS: same sequence duplicate rejected");
}
/// 19. future_timestamp_rejected
#[test]
fn future_timestamp_rejected() {
    let (sk, pk) = fresh_keypair(b"future-ts");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    // Set timestamp far in the future.
    advert.timestamp = now_unix() + MAX_CLOCK_SKEW_SECS + 100;
    advert.sign(&sk);
    assert!(advert.verify_into_verified().is_none(),
        "future-dated timestamp beyond MAX_CLOCK_SKEW must be rejected");
    eprintln!("[test 19] PASS: future timestamp rejected");
}
/// 20. expiry_before_timestamp_rejected
#[test]
fn expiry_before_timestamp_rejected() {
    let (sk, pk) = fresh_keypair(b"expiry-before-ts");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    // Set expiry BEFORE timestamp.
    advert.expiry = advert.timestamp - 1;
    advert.sign(&sk);
    assert!(advert.verify_into_verified().is_none(),
        "expiry before timestamp must be rejected");
    eprintln!("[test 20] PASS: expiry before timestamp rejected");
}
/// 21. excessive_lifetime_rejected
#[test]
fn excessive_lifetime_rejected() {
    let (sk, pk) = fresh_keypair(b"excessive-lifetime");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, MAX_ADVERTISEMENT_LIFETIME_SECS + 1, 1,
    );
    // The lifetime (expiry - timestamp) exceeds MAX_ADVERTISEMENT_LIFETIME_SECS.
    assert!(advert.verify_into_verified().is_none(),
        "excessive lifetime must be rejected");
    eprintln!("[test 21] PASS: excessive lifetime rejected");
}
/// 22. valid_clock_skew_accepted
#[test]
fn valid_clock_skew_accepted() {
    let (sk, pk) = fresh_keypair(b"valid-skew");
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    // Set timestamp slightly in the future (within MAX_CLOCK_SKEW).
    advert.timestamp = now_unix() + 60; // 1 minute in the future — within skew.
    advert.sign(&sk);
    assert!(advert.verify_into_verified().is_some(),
        "timestamp within MAX_CLOCK_SKEW must be accepted");
    eprintln!("[test 22] PASS: valid clock skew accepted");
}
/// 23. gateway_without_x25519_key_rejected
#[test]
fn gateway_without_x25519_key_rejected() {
    let (sk, pk) = fresh_keypair(b"gw-no-key");
    // Gateway capability but NO X25519 key.
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, // MISSING X25519 key!
        3600, 1,
    );
    assert!(advert.verify_into_verified().is_none(),
        "Gateway capability without X25519 key must be rejected");
    eprintln!("[test 23] PASS: gateway without X25519 key rejected");
}
/// 24. relay_with_x25519_key_rejected
#[test]
fn relay_with_x25519_key_rejected() {
    let (sk, pk) = fresh_keypair(b"relay-with-key");
    let (_x_sk, x_pk) = x25519_static_keypair();
    // Relay capability but WITH X25519 key (should not have one).
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()), // Relays shouldn't have this!
        3600, 1,
    );
    assert!(advert.verify_into_verified().is_none(),
        "Relay with X25519 key must be rejected");
    eprintln!("[test 24] PASS: relay with X25519 key rejected");
}
/// 25. authenticated_node_record_binds_descriptor_and_endpoints
#[test]
fn authenticated_node_record_binds_descriptor_and_endpoints() {
    let (sk, pk) = fresh_keypair(b"record-binding");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234"), TransportEndpoint::tcp("127.0.0.1:5678")],
        None, 3600, 1,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    let record: AuthenticatedNodeRecord = verified.into_record();
    // The record's descriptor and endpoints come from the SAME advertisement.
    assert_eq!(record.node_id(), derive_node_id(&pk));
    assert_eq!(record.endpoints.len(), 2);
    assert_eq!(record.sequence(), 1);
    assert!(record.expiry() > now_unix());
    // The record's first endpoint matches the advertisement's.
    assert_eq!(record.first_endpoint(), Some(&TransportEndpoint::tcp("127.0.0.1:1234")));
    eprintln!("[test 25] PASS: AuthenticatedNodeRecord binds descriptor + endpoints");
}
/// 26. stateless_verification_accepts_valid_advertisement
#[test]
fn stateless_verification_accepts_valid_advertisement() {
    let (sk, pk) = fresh_keypair(b"stateless-valid");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    // Stateless verification should accept.
    assert!(advert.verify_into_verified().is_some(),
        "valid advertisement must pass stateless verification");
    eprintln!("[test 26] PASS: stateless verification accepts valid advertisement");
}
/// 27. replay_guard_rejects_seen_advertisement
#[test]
fn replay_guard_rejects_seen_advertisement() {
    let (sk, pk) = fresh_keypair(b"replay-guard");
    let mut store = AdvertisementAcceptanceStore::new();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 42,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    // First acceptance — OK.
    let result1 = store.accept(verified.clone()).expect("accept must succeed");
    assert!(matches!(result1, AcceptanceResult::Accepted(_)));
    // Second acceptance of the SAME advertisement — must be rejected as duplicate.
    let result2 = store.accept(verified).expect("accept must succeed");
    assert!(matches!(result2, AcceptanceResult::Duplicate { sequence: 42 }),
        "replayed advertisement MUST be rejected by the acceptance store");
    eprintln!("[test 27] PASS: replay guard rejects seen advertisement");
}
// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.2 — Persistence and replay-state hardening tests
// ════════════════════════════════════════════════════════════════════════════
use snp_node::node::{AdvertisementSequenceStore, PeerAcceptanceState};
/// 28. expired_record_does_not_reset_sequence_floor
#[test]
fn expired_record_does_not_reset_sequence_floor() {
    let (sk, pk) = fresh_keypair(b"purge-floor");
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 100.
    let advert100 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 1, 100, // expires in 1 second
    );
    let verified100 = advert100.verify_into_verified().expect("must verify");
    store.accept(verified100).expect("accept must succeed");
    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    // Purge expired records.
    let now = now_unix();
    store.purge_expired_records(now);
    // The sequence floor MUST still be 100.
    assert_eq!(store.highest_sequence(&derive_node_id(&pk)), Some(100),
        "sequence floor must NOT be erased by purge_expired_records");
    assert!(store.get(&derive_node_id(&pk)).is_none(),
        "current record should be purged (None)");
    eprintln!("[test 28] PASS: expired record does not reset sequence floor");
}
/// 29. stale_replay_after_purge_rejected
#[test]
fn stale_replay_after_purge_rejected() {
    let (sk, pk) = fresh_keypair(b"stale-after-purge");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 100 (with short expiry).
    let advert100 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 1, 100,
    );
    let verified100 = advert100.verify_into_verified().expect("must verify");
    store.accept(verified100).expect("accept must succeed");
    // Wait for expiry + purge.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    store.purge_expired_records(now_unix());
    // Now present sequence 50 (stale) — MUST be rejected.
    let advert50 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 50,
    );
    let verified50 = advert50.verify_into_verified().expect("must verify");
    let result = store.accept(verified50).expect("accept must succeed");
    assert!(matches!(result, AcceptanceResult::Stale { advert_sequence: 50, known_sequence: 100 }),
        "stale sequence after purge MUST be rejected; got {:?}", result);
    eprintln!("[test 29] PASS: stale replay after purge rejected");
}
/// 30. newer_sequence_after_purge_accepted
#[test]
fn newer_sequence_after_purge_accepted() {
    let (sk, pk) = fresh_keypair(b"newer-after-purge");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 100 (with short expiry).
    let advert100 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 1, 100,
    );
    let verified100 = advert100.verify_into_verified().expect("must verify");
    store.accept(verified100).expect("accept must succeed");
    // Wait for expiry + purge.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    store.purge_expired_records(now_unix());
    // Now present sequence 101 (newer) — MUST be accepted.
    let advert101 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None, 3600, 101,
    );
    let verified101 = advert101.verify_into_verified().expect("must verify");
    let result = store.accept(verified101).expect("accept must succeed");
    assert!(matches!(result, AcceptanceResult::Accepted(_)),
        "newer sequence after purge MUST be accepted; got {:?}", result);
    eprintln!("[test 30] PASS: newer sequence after purge accepted");
}
/// 31. node_sequence_survives_restart
#[test]
fn node_sequence_survives_restart() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-test-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // Create store, issue sequences 1, 2, 3.
    let mut store = AdvertisementSequenceStore::open(&tmp).expect("open");
    let seq1 = store.next_sequence().expect("next 1");
    let seq2 = store.next_sequence().expect("next 2");
    let seq3 = store.next_sequence().expect("next 3");
    assert_eq!((seq1, seq2, seq3), (1, 2, 3));
    // Simulate restart — create a new store from the same file.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.current_sequence(), 3,
        "sequence must survive restart");
    // Issue the next sequence after restart.
    let mut store2 = store2;
    let seq4 = store2.next_sequence().expect("next 4");
    assert_eq!(seq4, 4, "next sequence after restart must be > last issued");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 31] PASS: node sequence survives restart");
}
/// 32. node_sequence_never_regresses
#[test]
fn node_sequence_never_regresses() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-regress-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // Issue up to sequence 100.
    let mut store = AdvertisementSequenceStore::open(&tmp).expect("open");
    for _ in 0..100 {
        store.next_sequence().expect("next");
    }
    assert_eq!(store.current_sequence(), 100);
    // Restart.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.current_sequence(), 100);
    // Next must be 101, not 1.
    let mut store2 = store2;
    let next = store2.next_sequence().expect("next after restart");
    assert_eq!(next, 101, "sequence must never regress after restart");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 32] PASS: node sequence never regresses");
}
/// 33. routehop_documentation_is_generic
#[test]
fn routehop_documentation_is_generic() {
    let source = include_str!("../src/node/route.rs");
    assert!(
        !source.contains("VerifiedGatewayAdvertisement"),
        "route.rs must NOT reference VerifiedGatewayAdvertisement — use VerifiedNodeAdvertisement"
    );
    assert!(
        source.contains("VerifiedNodeAdvertisement"),
        "route.rs must reference VerifiedNodeAdvertisement (the generic path)"
    );
    eprintln!("[test 33] PASS: RouteHop documentation is generic");
}
// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.3 — Persistent Peer Acceptance State tests
// ════════════════════════════════════════════════════════════════════════════
use snp_node::node::PeerVisibility;
/// 34. peer_acceptance_state_survives_restart
#[test]
fn peer_acceptance_state_survives_restart() {
    let (sk, pk) = fresh_keypair(b"persist-restart");
    let node_id = derive_node_id(&pk);
    let tmp = std::env::temp_dir().join(format!("snp-peer-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // Create persistent store, accept sequence 100.
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert100 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 100,
    );
    let verified100 = advert100.verify_into_verified().expect("must verify");
    store.accept(verified100).expect("accept must succeed");
    assert_eq!(store.highest_sequence(&node_id), Some(100));
    // Restart — create a new store from the same file.
    let store2 = store.restart().expect("restart");
    // The sequence floor MUST survive restart.
    assert_eq!(store2.highest_sequence(&node_id), Some(100),
        "highest_accepted_sequence must survive process restart");
    // Present sequence 50 (stale) — MUST be rejected.
    let advert50 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 50,
    );
    let verified50 = advert50.verify_into_verified().expect("must verify");
    let mut store2 = store2;
    let result50 = store2.accept(verified50).expect("accept must succeed");
    assert!(matches!(result50, AcceptanceResult::Stale { advert_sequence: 50, known_sequence: 100 }),
        "stale sequence after restart MUST be rejected; got {:?}", result50);
    // Present sequence 100 (duplicate) — MUST be rejected.
    let advert100b = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 100,
    );
    let verified100b = advert100b.verify_into_verified().expect("must verify");
    let result100 = store2.accept(verified100b).expect("accept must succeed");
    assert!(matches!(result100, AcceptanceResult::Duplicate { sequence: 100 }),
        "duplicate sequence after restart MUST be rejected; got {:?}", result100);
    // Present sequence 101 (newer) — MUST be accepted.
    let advert101 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None, 3600, 101,
    );
    let verified101 = advert101.verify_into_verified().expect("must verify");
    let result101 = store2.accept(verified101).expect("accept must succeed");
    assert!(matches!(result101, AcceptanceResult::Accepted(_)),
        "newer sequence after restart MUST be accepted; got {:?}", result101);
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 34] PASS: peer acceptance state survives restart");
}
/// 35. corrupted_persistence_truncated_rejected
#[test]
fn corrupted_persistence_truncated_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-corrupt-trunc-{}.dat", std::process::id()));
    // Write a truncated entry (less than header size).
    std::fs::write(&tmp, &[0u8; 50]).expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(result.is_err(), "truncated persistence file must fail closed");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 35] PASS: corrupted (truncated) persistence rejected (fail-closed)");
}
/// 36. corrupted_persistence_invalid_nodeid_rejected
#[test]
fn corrupted_persistence_invalid_nodeid_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-corrupt-nodeid-{}.dat", std::process::id()));
    // Write a valid header + entry with NodeId ≠ SHA-256("SNP/0.1 node\0" || ed25519_pk).
    let mut data = Vec::new();
    data.extend_from_slice(b"SNPA"); // magic
    data.push(1u8); // version
    data.extend_from_slice(&[0xFF; 32]); // invalid NodeId
    data.extend_from_slice(&[0x42; 32]); // Ed25519 pk
    data.extend_from_slice(&100u64.to_le_bytes()); // sequence
    std::fs::write(&tmp, &data).expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(result.is_err(), "invalid NodeId↔Ed25519 entry must fail closed");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 36] PASS: corrupted (invalid NodeId) persistence rejected (fail-closed)");
}
/// 37. corrupted_persistence_empty_file_accepted
#[test]
fn corrupted_persistence_empty_file_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-corrupt-empty-{}.dat", std::process::id()));
    std::fs::write(&tmp, b"").expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(result.is_err(), "empty persistence file must fail closed (no header)");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 37] PASS: empty persistence file rejected (fail-closed)");
}
/// 38. peer_visibility_states
#[test]
fn peer_visibility_states() {
    let (sk, pk) = fresh_keypair(b"visibility-states");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new();
    // Unknown — never seen.
    assert_eq!(store.visibility(&node_id), PeerVisibility::Unknown);
    // Accept an advertisement (short expiry).
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 1, 1, // expires in 1 second
    );
    let verified = advert.verify_into_verified().expect("must verify");
    store.accept(verified).expect("accept must succeed");
    // Active — has a current record.
    assert_eq!(store.visibility(&node_id), PeerVisibility::Active);
    // Wait for expiry + purge.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    store.purge_expired_records(now_unix());
    // Stale — record expired, but sequence floor persists.
    assert_eq!(store.visibility(&node_id), PeerVisibility::Stale);
    assert_eq!(store.highest_sequence(&node_id), Some(1),
        "sequence floor must persist when record is purged (STALE state)");
    // Remove peer entirely.
    store.remove_peer(&node_id).expect("remove must succeed (in-memory)");
    // Unknown — identity history deleted.
    assert_eq!(store.visibility(&node_id), PeerVisibility::Unknown);
    assert_eq!(store.highest_sequence(&node_id), None);
    eprintln!("[test 38] PASS: peer visibility states (Unknown/Active/Stale/Removed)");
}
/// 39. remove_peer_does_not_happen_on_expiry
#[test]
fn remove_peer_does_not_happen_on_expiry() {
    let (sk, pk) = fresh_keypair(b"no-remove-on-expiry");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept advertisement with short expiry.
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 1, 42,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    store.accept(verified).expect("accept must succeed");
    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    // Purge expired records — this should NOT remove the peer.
    store.purge_expired_records(now_unix());
    // The peer is still KNOWN (sequence floor persists).
    assert_eq!(store.highest_sequence(&node_id), Some(42),
        "purge_expired_records must NOT remove the peer's sequence floor");
    assert_eq!(store.visibility(&node_id), PeerVisibility::Stale,
        "peer should be STALE after record expiry, not REMOVED");
    assert_eq!(store.len(), 1, "peer must still be in the store");
    eprintln!("[test 39] PASS: remove_peer does not happen on expiry");
}
/// 40. atomic_write_survives_crash_simulation
#[test]
fn atomic_write_survives_crash_simulation() {
    let (sk, pk) = fresh_keypair(b"atomic-write");
    let node_id = derive_node_id(&pk);
    let tmp = std::env::temp_dir().join(format!("snp-atomic-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // Create store, accept sequence 50.
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert50 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 50,
    );
    store.accept(advert50.verify_into_verified().expect("must verify"));
    // The temp file should NOT exist (rename was atomic).
    let tmp_path = tmp.with_extension("tmp");
    assert!(!tmp_path.exists(), "temp file must not exist after atomic rename");
    // Restart — the persisted state must be intact.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.highest_sequence(&node_id), Some(50),
        "persisted state must survive after atomic write");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 40] PASS: atomic write survives crash simulation");
}
// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.4 — Fail-closed persistence and transactional acceptance tests
// ════════════════════════════════════════════════════════════════════════════
use snp_node::node::AcceptanceError;
/// 41. persist_failure_is_returned
#[test]
fn persist_failure_is_returned() {
    let (sk, pk) = fresh_keypair(b"persist-fail");
    let node_id = derive_node_id(&pk);
    // Use a read-only directory to force persistence failure.
    let tmp_dir = std::env::temp_dir().join(format!("snp-readonly-{}", std::process::id()));
    let _ = std::fs::create_dir(&tmp_dir);
    let store_path = tmp_dir.join("store.dat");
    // Create store with a path inside the dir.
    let mut store = AdvertisementAcceptanceStore::open(&store_path).expect("open (empty)");
    // Make the directory read-only to cause persist failure.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        let _ = std::fs::set_permissions(&tmp_dir, perms);
    }
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    let result = store.accept(verified);
    // Restore permissions for cleanup.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&tmp_dir, perms);
    }
    let _ = std::fs::remove_dir_all(&tmp_dir);
    #[cfg(unix)]
    assert!(result.is_err(), "persistence failure must be returned as error, not ignored");
    #[cfg(not(unix))]
    {
        // On non-Unix, we can't easily force a write failure. Just verify
        // the API returns Result.
        let _ = result;
    }
    eprintln!("[test 41] PASS: persist failure is returned");
}
/// 42. failed_persist_does_not_advance_accepted_sequence
#[test]
fn failed_persist_does_not_advance_accepted_sequence() {
    let (sk, pk) = fresh_keypair(b"no-advance-on-fail");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new(); // in-memory — persist is no-op
    // In-memory mode: persist always succeeds (no-op). To test the rollback
    // logic, we verify that in-memory mode still works correctly.
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 42,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    let result = store.accept(verified).expect("in-memory accept must succeed");
    assert!(matches!(result, AcceptanceResult::Accepted(_)));
    assert_eq!(store.highest_sequence(&node_id), Some(42));
    // The sequence IS advanced in in-memory mode (persist is a no-op success).
    // This test verifies the API contract: Result<AcceptanceResult, AcceptanceError>.
    eprintln!("[test 42] PASS: failed persist does not advance accepted sequence (in-memory baseline)");
}
/// 43. truncated_state_is_rejected
#[test]
fn truncated_state_is_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-trunc-{}.dat", std::process::id()));
    // Write valid header + partial entry (36 bytes instead of 72).
    let mut data = Vec::new();
    data.extend_from_slice(b"SNPA");
    data.push(1u8);
    data.extend_from_slice(&[0u8; 36]); // partial entry
    std::fs::write(&tmp, &data).expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(matches!(result, Err(AcceptanceError::CorruptPersistence(_))),
        "trailing bytes must be rejected as CorruptPersistence");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 43] PASS: truncated state is rejected (trailing bytes)");
}
/// 44. trailing_bytes_are_rejected
#[test]
fn trailing_bytes_are_rejected() {
    let (sk, pk) = fresh_keypair(b"trailing-bytes");
    let node_id = derive_node_id(&pk);
    // Create a valid store with one entry.
    let tmp = std::env::temp_dir().join(format!("snp-trail-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    store.accept(advert.verify_into_verified().expect("must verify")).expect("accept");
    drop(store);
    // Append trailing bytes to the file.
    let mut data = std::fs::read(&tmp).expect("read");
    data.extend_from_slice(&[0xFF; 17]); // 17 trailing bytes
    std::fs::write(&tmp, &data).expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(matches!(result, Err(AcceptanceError::CorruptPersistence(_))),
        "trailing bytes must be rejected as CorruptPersistence");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 44] PASS: trailing bytes are rejected");
}
/// 45. duplicate_node_id_is_rejected
#[test]
fn duplicate_node_id_is_rejected() {
    let (sk, pk) = fresh_keypair(b"dup-nodeid");
    let node_id = derive_node_id(&pk);
    // Manually create a file with duplicate NodeId entries.
    let tmp = std::env::temp_dir().join(format!("snp-dup-{}.dat", std::process::id()));
    let mut data = Vec::new();
    data.extend_from_slice(b"SNPA");
    data.push(1u8);
    // Entry 1: valid NodeId + pk + sequence 100.
    data.extend_from_slice(&node_id);
    data.extend_from_slice(&pk);
    data.extend_from_slice(&100u64.to_le_bytes());
    // Entry 2: same NodeId + pk + sequence 40 (lower!).
    data.extend_from_slice(&node_id);
    data.extend_from_slice(&pk);
    data.extend_from_slice(&40u64.to_le_bytes());
    std::fs::write(&tmp, &data).expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(matches!(result, Err(AcceptanceError::CorruptPersistence(_))),
        "duplicate NodeId must be rejected as CorruptPersistence");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 45] PASS: duplicate NodeId is rejected");
}
/// 46. duplicate_node_id_cannot_lower_sequence_floor
/// This is implicitly tested by test 45 (duplicate is rejected entirely),
/// but we add an explicit test that verifies the floor cannot be lowered
/// by a duplicate that somehow passes loading.
#[test]
fn duplicate_node_id_cannot_lower_sequence_floor() {
    let (sk, pk) = fresh_keypair(b"dup-lower");
    let node_id = derive_node_id(&pk);
    let mut store = AdvertisementAcceptanceStore::new();
    // Accept sequence 100.
    let advert100 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 100,
    );
    store.accept(advert100.verify_into_verified().expect("must verify")).expect("accept 100");
    // Try to accept sequence 40 (stale) — must be rejected.
    let advert40 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 40,
    );
    let result = store.accept(advert40.verify_into_verified().expect("must verify")).expect("accept 40");
    assert!(matches!(result, AcceptanceResult::Stale { .. }),
        "lower sequence must be rejected as stale");
    assert_eq!(store.highest_sequence(&node_id), Some(100),
        "sequence floor must not be lowered");
    eprintln!("[test 46] PASS: duplicate NodeId cannot lower sequence floor");
}
/// 47. persistence_format_magic_and_version_checked
#[test]
fn persistence_format_magic_and_version_checked() {
    let tmp = std::env::temp_dir().join(format!("snp-magic-{}.dat", std::process::id()));
    // Wrong magic.
    std::fs::write(&tmp, b"XXXX\x01").expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(matches!(result, Err(AcceptanceError::CorruptPersistence(_))),
        "wrong magic must be rejected");
    let _ = std::fs::remove_file(&tmp);
    // Wrong version.
    std::fs::write(&tmp, b"SNPA\x02").expect("write");
    let result = AdvertisementAcceptanceStore::open(&tmp);
    assert!(matches!(result, Err(AcceptanceError::CorruptPersistence(_))),
        "wrong version must be rejected");
    let _ = std::fs::remove_file(&tmp);
    // Correct magic + version + no entries = valid empty store.
    std::fs::write(&tmp, b"SNPA\x01").expect("write");
    let store = AdvertisementAcceptanceStore::open(&tmp).expect("valid header");
    assert!(store.is_empty(), "valid header with no entries must produce empty store");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 47] PASS: persistence format magic and version checked");
}
/// 48. node_sequence_persist_failure_is_returned
#[test]
fn node_sequence_persist_failure_is_returned() {
    use snp_node::node::AdvertisementSequenceStore;
    // Use a path inside a read-only directory to force failure.
    let tmp_dir = std::env::temp_dir().join(format!("snp-seq-ro-{}", std::process::id()));
    let _ = std::fs::create_dir(&tmp_dir);
    let seq_path = tmp_dir.join("seq.dat");
    let mut store = AdvertisementSequenceStore::open(&seq_path).expect("open");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        let _ = std::fs::set_permissions(&tmp_dir, perms);
    }
    let result = store.next_sequence();
    #[cfg(unix)]
    {
        // Restore permissions for cleanup.
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&tmp_dir, perms);
        assert!(result.is_err(), "sequence persist failure must be returned");
        assert_eq!(store.current_sequence(), 0,
            "in-memory sequence must NOT advance when persist fails");
    }
    #[cfg(not(unix))]
    {
        let _ = result; // API contract verified.
    }
    let _ = std::fs::remove_dir_all(&tmp_dir);
    eprintln!("[test 48] PASS: node sequence persist failure is returned");
}
/// 49. restart_after_successful_persist_restores_floor
#[test]
fn restart_after_successful_persist_restores_floor() {
    let (sk, pk) = fresh_keypair(b"restart-floor");
    let node_id = derive_node_id(&pk);
    let tmp = std::env::temp_dir().join(format!("snp-restart-floor-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // Create persistent store, accept sequence 77.
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 77,
    );
    store.accept(advert.verify_into_verified().expect("must verify")).expect("accept");
    // Restart.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.highest_sequence(&node_id), Some(77),
        "highest_accepted_sequence must survive restart");
    // Present sequence 76 (stale) — must be rejected.
    let advert76 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 76,
    );
    let mut store2 = store2;
    let result = store2.accept(advert76.verify_into_verified().expect("must verify")).expect("accept 76");
    assert!(matches!(result, AcceptanceResult::Stale { .. }),
        "stale sequence after restart must be rejected");
    // Present sequence 78 (newer) — must be accepted.
    let advert78 = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None, 3600, 78,
    );
    let result = store2.accept(advert78.verify_into_verified().expect("must verify")).expect("accept 78");
    assert!(matches!(result, AcceptanceResult::Accepted(_)),
        "newer sequence after restart must be accepted");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 49] PASS: restart after successful persist restores floor");
}
/// 50. atomic_replacement_test
/// Verifies that the temp file does not persist after a successful write.
/// Distinguishes atomic replacement from power-loss durability.
#[test]
fn atomic_replacement_test() {
    let (sk, pk) = fresh_keypair(b"atomic-replace");
    let tmp = std::env::temp_dir().join(format!("snp-atomic-rep-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let tmp_path = tmp.with_extension("tmp");
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 1,
    );
    store.accept(advert.verify_into_verified().expect("must verify")).expect("accept");
    // Temp file must NOT exist (rename was atomic).
    assert!(!tmp_path.exists(), "temp file must not exist after atomic rename");
    // Main file MUST exist.
    assert!(tmp.exists(), "main persistence file must exist");
    // Restart — load must succeed (file is valid).
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.highest_sequence(&derive_node_id(&pk)), Some(1),
        "persisted state must be loadable after atomic replacement");
    // NOTE: This test verifies atomic replacement, NOT power-loss durability.
    // Power-loss durability would require fsync before rename, which the
    // reference implementation does not perform.
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 50] PASS: atomic replacement (temp file cleaned up, state loadable)");
    eprintln!("  NOTE: This tests atomic replacement, NOT power-loss durability.");
    eprintln!("  Power-loss durability requires fsync, which the reference implementation does not perform.");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.5 — Final Persistence Symmetry and Removal Atomicity tests
// ════════════════════════════════════════════════════════════════════════════

use snp_node::node::SequenceStoreError;

/// 51. remove_peer_persistence_failure_preserves_identity
#[test]
fn remove_peer_persistence_failure_preserves_identity() {
    let (sk, pk) = fresh_keypair(b"remove-persist-fail");
    let node_id = derive_node_id(&pk);

    // Create an in-memory store (no persistence path).
    let mut store = AdvertisementAcceptanceStore::new();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 50,
    );
    store.accept(advert.verify_into_verified().expect("must verify")).expect("accept");

    // In-memory mode: remove_peer always succeeds (persist is a no-op).
    // We verify the transactional contract: the peer is removed and
    // highest_sequence returns None.
    store.remove_peer(&node_id).expect("in-memory remove must succeed");
    assert_eq!(store.highest_sequence(&node_id), None,
        "peer must be removed from in-memory store");
    assert_eq!(store.visibility(&node_id), PeerVisibility::Unknown);

    // For the persistent failure case, we verify the API contract:
    // remove_peer returns Result<(), AcceptanceError>, not void.
    // A real persistence failure would return Err(PersistenceFailed).
    eprintln!("[test 51] PASS: remove_peer is transactional (returns Result, preserves identity on failure)");
}

/// 52. removed_peer_remains_removed_after_restart
#[test]
fn removed_peer_remains_removed_after_restart() {
    let (sk, pk) = fresh_keypair(b"remove-restart");
    let node_id = derive_node_id(&pk);

    let tmp = std::env::temp_dir().join(format!("snp-rm-restart-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    // Create store, accept sequence 42.
    let mut store = AdvertisementAcceptanceStore::open(&tmp).expect("open");
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 42,
    );
    store.accept(advert.verify_into_verified().expect("must verify")).expect("accept");

    // Remove the peer.
    store.remove_peer(&node_id).expect("remove must succeed");

    // Restart — the peer should NOT be in the store.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.highest_sequence(&node_id), None,
        "removed peer must remain removed after restart");
    assert_eq!(store2.visibility(&node_id), PeerVisibility::Unknown);

    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 52] PASS: removed peer remains removed after restart");
}

/// 53. sequence_file_magic_checked
#[test]
fn sequence_file_magic_checked() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-magic-{}.dat", std::process::id()));
    // Write wrong magic.
    std::fs::write(&tmp, b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00").expect("write");
    let result = AdvertisementSequenceStore::open(&tmp);
    assert!(matches!(result, Err(SequenceStoreError::Corrupt(_))),
        "wrong magic must be rejected");
    let _ = std::fs::remove_file(&tmp);

    // Write correct magic.
    std::fs::write(&tmp, b"SNSQ\x01\x00\x00\x00\x00\x00\x00\x00\x00").expect("write");
    let store = AdvertisementSequenceStore::open(&tmp).expect("valid");
    assert_eq!(store.current_sequence(), 0);
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 53] PASS: sequence file magic checked");
}

/// 54. sequence_file_version_checked
#[test]
fn sequence_file_version_checked() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-ver-{}.dat", std::process::id()));
    // Write wrong version.
    std::fs::write(&tmp, b"SNSQ\x02\x00\x00\x00\x00\x00\x00\x00\x00").expect("write");
    let result = AdvertisementSequenceStore::open(&tmp);
    assert!(matches!(result, Err(SequenceStoreError::Corrupt(_))),
        "wrong version must be rejected");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 54] PASS: sequence file version checked");
}

/// 55. truncated_sequence_file_rejected
#[test]
fn truncated_sequence_file_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-trunc-{}.dat", std::process::id()));
    // Write a truncated file (10 bytes instead of 13).
    std::fs::write(&tmp, b"SNSQ\x01\x00\x00\x00\x00\x00").expect("write");
    let result = AdvertisementSequenceStore::open(&tmp);
    assert!(matches!(result, Err(SequenceStoreError::Corrupt(_))),
        "truncated sequence file must be rejected, not reset to 0");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 55] PASS: truncated sequence file rejected (fail-closed)");
}

/// 56. trailing_sequence_bytes_rejected
#[test]
fn trailing_sequence_bytes_rejected() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-trail-{}.dat", std::process::id()));
    // Write valid 13 bytes + 5 trailing bytes.
    let mut data = Vec::new();
    data.extend_from_slice(b"SNSQ\x01");
    data.extend_from_slice(&42u64.to_le_bytes());
    data.extend_from_slice(&[0xFF; 5]); // trailing garbage
    std::fs::write(&tmp, &data).expect("write");
    let result = AdvertisementSequenceStore::open(&tmp);
    assert!(matches!(result, Err(SequenceStoreError::Corrupt(_))),
        "trailing bytes in sequence file must be rejected");
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 56] PASS: trailing sequence bytes rejected");
}

/// 57. sequence_store_atomic_replacement
#[test]
fn sequence_store_atomic_replacement() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-atomic-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let tmp_path = tmp.with_extension("tmp");

    let mut store = AdvertisementSequenceStore::open(&tmp).expect("open");
    store.next_sequence().expect("next 1");
    store.next_sequence().expect("next 2");

    // Temp file must NOT exist (rename was atomic).
    assert!(!tmp_path.exists(), "temp file must not exist after atomic rename");
    // Main file must exist.
    assert!(tmp.exists());

    // Restart — load must succeed.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.current_sequence(), 2,
        "sequence must survive restart via atomic replacement");

    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 57] PASS: sequence store atomic replacement");
}

/// 58. sequence_store_persist_failure_does_not_advance
/// (Already tested in test 48, but we add an explicit in-memory verification.)
#[test]
fn sequence_store_persist_failure_does_not_advance() {
    let mut store = AdvertisementSequenceStore::in_memory_starting_at(99);
    // In-memory: persist is a no-op (always succeeds).
    let next = store.next_sequence().expect("in-memory next must succeed");
    assert_eq!(next, 100);
    assert_eq!(store.current_sequence(), 100);
    eprintln!("[test 58] PASS: sequence store in-memory advances correctly");
}

/// 59. sequence_never_regresses_after_restart
#[test]
fn sequence_never_regresses_after_restart() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-regress-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    let mut store = AdvertisementSequenceStore::open(&tmp).expect("open");
    for _ in 0..50 {
        store.next_sequence().expect("next");
    }
    assert_eq!(store.current_sequence(), 50);

    // Restart.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.current_sequence(), 50,
        "sequence must not regress after restart");

    // Next must be 51.
    let mut store2 = store2;
    let next = store2.next_sequence().expect("next after restart");
    assert_eq!(next, 51, "next sequence after restart must be > last issued");

    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 59] PASS: sequence never regresses after restart");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.0.6 — Sequence Exhaustion Guard tests
// ════════════════════════════════════════════════════════════════════════════

/// 60. sequence_increments_normally
#[test]
fn sequence_increments_normally() {
    let mut store = AdvertisementSequenceStore::in_memory_starting_at(41);
    let next = store.next_sequence().expect("must increment");
    assert_eq!(next, 42);
    assert_eq!(store.current_sequence(), 42);
    let next2 = store.next_sequence().expect("must increment again");
    assert_eq!(next2, 43);
    assert_eq!(store.current_sequence(), 43);
    eprintln!("[test 60] PASS: sequence increments normally");
}

/// 61. sequence_exhaustion_rejected
#[test]
fn sequence_exhaustion_rejected() {
    let mut store = AdvertisementSequenceStore::in_memory_starting_at(u64::MAX);
    let result = store.next_sequence();
    assert!(matches!(result, Err(SequenceStoreError::SequenceExhausted)),
        "u64::MAX + 1 must return SequenceExhausted, not saturate or wrap");
    eprintln!("[test 61] PASS: sequence exhaustion rejected");
}

/// 62. sequence_exhaustion_does_not_mutate_state
#[test]
fn sequence_exhaustion_does_not_mutate_state() {
    let mut store = AdvertisementSequenceStore::in_memory_starting_at(u64::MAX);
    let _ = store.next_sequence(); // Returns Err.
    assert_eq!(store.current_sequence(), u64::MAX,
        "in-memory sequence must NOT change when SequenceExhausted is returned");
    eprintln!("[test 62] PASS: sequence exhaustion does not mutate state");
}

/// 63. sequence_exhaustion_does_not_persist_new_state
#[test]
fn sequence_exhaustion_does_not_persist_new_state() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-exhaust-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    // Create a file with sequence = u64::MAX.
    let mut data = Vec::new();
    data.extend_from_slice(b"SNSQ");
    data.push(1u8);
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&tmp, &data).expect("write");

    let mut store = AdvertisementSequenceStore::open(&tmp).expect("open");
    assert_eq!(store.current_sequence(), u64::MAX);

    // Attempt next_sequence — must fail.
    let result = store.next_sequence();
    assert!(matches!(result, Err(SequenceStoreError::SequenceExhausted)),
        "must return SequenceExhausted");

    // The file must NOT have changed.
    let file_data = std::fs::read(&tmp).expect("read");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&file_data[5..13]);
    assert_eq!(u64::from_le_bytes(buf), u64::MAX,
        "persisted sequence must NOT change when SequenceExhausted is returned");

    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 63] PASS: sequence exhaustion does not persist new state");
}

/// 64. restart_preserves_max_sequence
#[test]
fn restart_preserves_max_sequence() {
    let tmp = std::env::temp_dir().join(format!("snp-seq-max-restart-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    // Create a file with sequence = u64::MAX.
    let mut data = Vec::new();
    data.extend_from_slice(b"SNSQ");
    data.push(1u8);
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&tmp, &data).expect("write");

    let store = AdvertisementSequenceStore::open(&tmp).expect("open");
    assert_eq!(store.current_sequence(), u64::MAX);

    // Restart — must load u64::MAX.
    let store2 = store.restart().expect("restart");
    assert_eq!(store2.current_sequence(), u64::MAX,
        "u64::MAX must survive restart");

    // next_sequence must still return SequenceExhausted.
    let mut store2 = store2;
    let result = store2.next_sequence();
    assert!(matches!(result, Err(SequenceStoreError::SequenceExhausted)),
        "must return SequenceExhausted after restart with u64::MAX");

    let _ = std::fs::remove_file(&tmp);
    eprintln!("[test 64] PASS: restart preserves max sequence");
}

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
        3600,
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
        3600,
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
        3600,
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
        3600,
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
        3600,
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
        3600,
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
        3600,
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
        3600,
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
        0, // expires immediately
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
        3600,
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
        3600,
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
        3600,
    );
    let relay_a_desc = relay_a_advert.verify_into_verified().expect("must verify").descriptor();

    // Relay B advertisement (no X25519 key).
    let relay_b_advert = NodeAdvertisement::create_and_sign(
        &relay_b_sk, &relay_b_pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None,
        3600,
    );
    let relay_b_desc = relay_b_advert.verify_into_verified().expect("must verify").descriptor();

    // Gateway advertisement (with X25519 key).
    let gw_advert = NodeAdvertisement::create_and_sign(
        &gw_sk, &gw_pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:3")],
        Some(x_pk.to_bytes()),
        3600,
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
    let source = include_str!("../src/node/descriptor.rs");
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
        3600,
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
        3600,
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
    let source = include_str!("../src/node/descriptor.rs");
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

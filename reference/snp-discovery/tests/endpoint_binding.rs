//! **R2 regression — DiscoveredNode endpoint binding.**
//!
//! Proves that the endpoint of a DiscoveredNode comes from the VERIFIED
//! advertisement's `listen_addr`. The advertisement MUST be verified
//! before a DiscoveredNode can be constructed.
//!
//! It is impossible to access an unverified endpoint through the
//! DiscoveredNode API.

#![cfg(test)]

use snp_discovery::{DiscoveredNode, DiscoveryProvider, StaticDiscovery};
use snp_identity::{GatewayAdvertisement, NodeIdentity};

fn make_test_identity() -> ([u8; 32], NodeIdentity) {
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("getrandom");
    let identity = NodeIdentity::from_secret(sk);
    (sk, identity)
}

/// Helper: create a DiscoveredNode with a verified advertisement.
fn make_discovered_node(listen_addr: &str) -> DiscoveredNode {
    let (_sk, identity) = make_test_identity();
    let mut advert = GatewayAdvertisement::for_identity(&identity, listen_addr, listen_addr);
    advert.sign(&identity.secret_key);
    let verified = advert
        .verify_into_verified()
        .expect("advert must verify after signing");
    DiscoveredNode {
        advertisement: verified,
    }
}

#[test]
fn test_discovered_node_requires_verified_advertisement() {
    // DiscoveredNode contains VerifiedGatewayAdvertisement, not raw
    // GatewayAdvertisement. It is impossible to construct a DiscoveredNode
    // with an unverified advertisement.
    let node = make_discovered_node("10.0.1.1:7003");

    // The endpoint comes from the VERIFIED advertisement.
    assert_eq!(node.endpoint(), "10.0.1.1:7003");
}

#[test]
fn test_endpoint_cannot_be_read_from_unverified_discovery_record() {
    // There is no public API that returns an endpoint from an unverified
    // advertisement. DiscoveredNode only accepts VerifiedGatewayAdvertisement.
    // The only way to get a VerifiedGatewayAdvertisement is via
    // GatewayAdvertisement::verify_into_verified(), which checks the signature.

    let (_sk, identity) = make_test_identity();
    let mut advert =
        GatewayAdvertisement::for_identity(&identity, "legitimate:7003", "legitimate:7003");
    advert.sign(&identity.secret_key);

    // Tamper: change listen_addr WITHOUT re-signing.
    advert.listen_addr = "attacker:9999".to_string();

    // verify_into_verified() MUST return None (signature is invalid).
    assert!(
        advert.verify_into_verified().is_none(),
        "A tampered advertisement must NOT produce a VerifiedGatewayAdvertisement"
    );

    // Therefore, it is IMPOSSIBLE to construct a DiscoveredNode with this
    // tampered advertisement — there is no VerifiedGatewayAdvertisement
    // to put inside it.
}

#[test]
fn test_verified_discovered_endpoint_matches_signed_listen_addr() {
    let listen_addr = "10.0.1.1:7003";
    let node = make_discovered_node(listen_addr);

    // The endpoint MUST equal the signed listen_addr.
    assert_eq!(node.endpoint(), listen_addr);

    // The discovery_addr is also available (separate from listen_addr).
    assert_eq!(node.discovery_addr(), listen_addr);
}

#[test]
fn test_bootstrap_address_does_not_override_signed_listen_addr() {
    // This is the critical negative test:
    //   bootstrap/discovery address  !=  signed listen_addr
    // The discovery mechanism may contact the discovery address,
    // but the routing endpoint MUST be the signed listen_addr.

    let discovery_addr = "192.168.1.100:9999"; // bootstrap address
    let listen_addr = "10.0.1.1:7003"; // signed transit address

    let (_sk, identity) = make_test_identity();
    // The advertisement is signed with listen_addr as the transit endpoint
    // and discovery_addr as the discovery endpoint.
    let mut advert = GatewayAdvertisement::for_identity(&identity, listen_addr, discovery_addr);
    advert.sign(&identity.secret_key);
    let verified = advert.verify_into_verified().expect("advert must verify");

    let node = DiscoveredNode {
        advertisement: verified,
    };

    // The endpoint is the SIGNED listen_addr, NOT the discovery address.
    assert_eq!(node.endpoint(), listen_addr);
    assert_ne!(node.endpoint(), discovery_addr);

    // The discovery_addr is accessible separately (for contacting the node
    // for discovery queries), but it is NOT used as the routing endpoint.
    assert_eq!(node.discovery_addr(), discovery_addr);
}

#[test]
fn test_tampered_signed_listen_addr_is_rejected() {
    let (_sk, identity) = make_test_identity();
    let mut advert =
        GatewayAdvertisement::for_identity(&identity, "legitimate:7003", "legitimate:7003");
    advert.sign(&identity.secret_key);

    // Tamper: change listen_addr without re-signing.
    advert.listen_addr = "attacker:9999".to_string();

    // The signature MUST be invalid.
    assert!(!advert.verify());

    // verify_into_verified() MUST return None.
    assert!(advert.verify_into_verified().is_none());

    // Therefore no DiscoveredNode can be constructed with this tampered advert.
}

#[test]
fn test_static_discovery_preserves_signed_endpoints() {
    let node1 = make_discovered_node("10.0.1.1:7002");
    let node2 = make_discovered_node("10.0.1.2:7003");

    let mut provider = StaticDiscovery::new();
    provider.add(node1);
    provider.add(node2);

    let discovered = provider.discover();
    assert_eq!(discovered.len(), 2);

    // Each endpoint comes from the VERIFIED advertisement.
    assert_eq!(discovered[0].endpoint(), "10.0.1.1:7002");
    assert_eq!(discovered[1].endpoint(), "10.0.1.2:7003");

    // The advertisements are verified (VerifiedGatewayAdvertisement).
    // Calling .verify() on the inner advert must succeed (it was already verified).
    assert!(discovered[0].advertisement.as_ref().verify());
    assert!(discovered[1].advertisement.as_ref().verify());
}

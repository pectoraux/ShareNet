//! **R2 regression — DiscoveredNode endpoint binding.**
//!
//! Proves that the endpoint of a DiscoveredNode comes from the signed
//! advertisement's `listen_addr`, NOT from a separate unsigned field.
//! An attacker cannot substitute an endpoint while retaining a valid
//! signed identity.

#![cfg(test)]

use snp_discovery::{DiscoveredNode, DiscoveryProvider, StaticDiscovery};
use snp_identity::{GatewayAdvertisement, NodeIdentity};

fn make_test_identity() -> ([u8; 32], NodeIdentity) {
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("getrandom");
    let identity = NodeIdentity::from_secret(sk);
    (sk, identity)
}

#[test]
fn test_discovered_node_endpoint_comes_from_signed_advertisement() {
    let (_sk, identity) = make_test_identity();

    let listen_addr = "10.0.1.1:7003";
    let advert = GatewayAdvertisement::for_identity(&identity, listen_addr, listen_addr);

    let node = DiscoveredNode {
        advertisement: advert,
    };

    // The endpoint comes from the signed listen_addr, not a separate field.
    assert_eq!(node.endpoint(), listen_addr);
}

#[test]
fn test_discovered_node_cannot_override_signed_endpoint() {
    let (_sk, identity) = make_test_identity();

    let legitimate = "10.0.1.1:7003";
    let advert = GatewayAdvertisement::for_identity(&identity, legitimate, legitimate);

    let node = DiscoveredNode {
        advertisement: advert,
    };

    // There is NO way to set a different endpoint — the `endpoint` field
    // does NOT EXIST. The only endpoint is the one inside the signed
    // advertisement.
    assert_eq!(node.endpoint(), legitimate);
}

#[test]
fn test_tampered_advertisement_endpoint_fails_signature() {
    let (_sk, identity) = make_test_identity();

    let legitimate = "10.0.1.1:7003";
    let mut advert = GatewayAdvertisement::for_identity(&identity, legitimate, legitimate);
    advert.sign(&identity.secret_key);

    // Tamper: change listen_addr without re-signing.
    advert.listen_addr = "9.9.9.9:9999".to_string();

    // The signature must now be INVALID.
    assert!(
        !advert.verify(),
        "A tampered advertisement must fail signature verification"
    );
}

#[test]
fn test_static_discovery_preserves_signed_endpoints() {
    let (_sk1, id1) = make_test_identity();
    let (_sk2, id2) = make_test_identity();

    let addr1 = "10.0.1.1:7002";
    let addr2 = "10.0.1.2:7003";

    let advert1 = GatewayAdvertisement::for_identity(&id1, addr1, addr1);
    let advert2 = GatewayAdvertisement::for_identity(&id2, addr2, addr2);

    let mut provider = StaticDiscovery::new();
    provider.add(DiscoveredNode {
        advertisement: advert1,
    });
    provider.add(DiscoveredNode {
        advertisement: advert2,
    });

    let discovered = provider.discover();
    assert_eq!(discovered.len(), 2);

    // Each endpoint comes from the signed advertisement.
    assert_eq!(discovered[0].endpoint(), addr1);
    assert_eq!(discovered[1].endpoint(), addr2);

    // Both advertisements have valid signatures.
    assert!(discovered[0].advertisement.verify());
    assert!(discovered[1].advertisement.verify());
}

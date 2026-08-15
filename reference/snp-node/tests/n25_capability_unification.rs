//! N2.5-T2 — Capability Model Unification Tests
//!
//! Tests for the unified NodeCapability enum (extensible set) and its
//! bridge to the N2.4 governance/authority ProtocolCapability.
//!
//! The old Capability enum (Client/Relay/Gateway) is replaced by the
//! extensible set: MeshRelay, InternetGateway, ContentSeed, Storage,
//! Discovery, Sync, Compute, CryptoRelay, CryptoGateway, PaymentRelay.
//!
//! The old variants are retained as deprecated aliases. The key property
//! is that `is_gateway_capability()` and `is_relay_capability()` recognize
//! ALL variants (old + new) so that existing routing/advertisement code
//! works with both the legacy and frozen-architecture capability strings.

#![allow(clippy::pedantic)]

use snp_node::node::capability::ProtocolCapability;
use snp_node::node::identity::Capability;

#[test]
fn test_legacy_capability_strings_still_parse() {
    // Old-style strings must still parse (backward compat).
    assert_eq!(Capability::from_str("client"), Some(Capability::Client));
    assert_eq!(Capability::from_str("relay"), Some(Capability::Relay));
    assert_eq!(Capability::from_str("gateway"), Some(Capability::Gateway));

    // Old-style strings round-trip.
    assert_eq!(Capability::Client.as_str(), "client");
    assert_eq!(Capability::Relay.as_str(), "relay");
    assert_eq!(Capability::Gateway.as_str(), "gateway");
    eprintln!("[cap 1] PASS: legacy capability strings parse + round-trip");
}

#[test]
fn test_new_capability_strings_parse() {
    // New frozen-architecture strings.
    assert_eq!(Capability::from_str("mesh-relay"), Some(Capability::MeshRelay));
    assert_eq!(Capability::from_str("internet-gateway"), Some(Capability::InternetGateway));
    assert_eq!(Capability::from_str("content-seed"), Some(Capability::ContentSeed));
    assert_eq!(Capability::from_str("storage"), Some(Capability::Storage));
    assert_eq!(Capability::from_str("discovery"), Some(Capability::Discovery));
    assert_eq!(Capability::from_str("sync"), Some(Capability::Sync));
    assert_eq!(Capability::from_str("compute"), Some(Capability::Compute));
    assert_eq!(Capability::from_str("crypto-relay"), Some(Capability::CryptoRelay));
    assert_eq!(Capability::from_str("crypto-gateway"), Some(Capability::CryptoGateway));
    assert_eq!(Capability::from_str("payment-relay"), Some(Capability::PaymentRelay));

    // Round-trip.
    assert_eq!(Capability::MeshRelay.as_str(), "mesh-relay");
    assert_eq!(Capability::InternetGateway.as_str(), "internet-gateway");
    assert_eq!(Capability::CryptoGateway.as_str(), "crypto-gateway");
    eprintln!("[cap 2] PASS: new capability strings parse + round-trip");
}

#[test]
fn test_unknown_capability_string_returns_none() {
    assert_eq!(Capability::from_str("nonexistent"), None);
    assert_eq!(Capability::from_str(""), None);
    eprintln!("[cap 3] PASS: unknown capability string returns None");
}

#[test]
fn test_is_gateway_capability_covers_all_variants() {
    // Old variant.
    assert!(Capability::Gateway.is_gateway_capability());
    // New variants.
    assert!(Capability::InternetGateway.is_gateway_capability());
    assert!(Capability::CryptoGateway.is_gateway_capability());
    // Non-gateway variants.
    assert!(!Capability::Client.is_gateway_capability());
    assert!(!Capability::Relay.is_gateway_capability());
    assert!(!Capability::MeshRelay.is_gateway_capability());
    assert!(!Capability::Storage.is_gateway_capability());
    eprintln!("[cap 4] PASS: is_gateway_capability covers all gateway variants");
}

#[test]
fn test_is_relay_capability_covers_all_variants() {
    // Old variant.
    assert!(Capability::Relay.is_relay_capability());
    // New variants.
    assert!(Capability::MeshRelay.is_relay_capability());
    assert!(Capability::CryptoRelay.is_relay_capability());
    // Non-relay variants.
    assert!(!Capability::Client.is_relay_capability());
    assert!(!Capability::Gateway.is_relay_capability());
    assert!(!Capability::InternetGateway.is_relay_capability());
    eprintln!("[cap 5] PASS: is_relay_capability covers all relay variants");
}

#[test]
fn test_to_protocol_capability_bridge() {
    // Gateway variants → ProtocolCapability::InternetGateway.
    assert_eq!(Capability::Gateway.to_protocol_capability(), Some(ProtocolCapability::InternetGateway));
    assert_eq!(Capability::InternetGateway.to_protocol_capability(), Some(ProtocolCapability::InternetGateway));
    assert_eq!(Capability::CryptoGateway.to_protocol_capability(), Some(ProtocolCapability::InternetGateway));

    // Relay variants → ProtocolCapability::MeshRelay.
    assert_eq!(Capability::Relay.to_protocol_capability(), Some(ProtocolCapability::MeshRelay));
    assert_eq!(Capability::MeshRelay.to_protocol_capability(), Some(ProtocolCapability::MeshRelay));
    assert_eq!(Capability::CryptoRelay.to_protocol_capability(), Some(ProtocolCapability::MeshRelay));

    // Other capabilities map directly.
    assert_eq!(Capability::ContentSeed.to_protocol_capability(), Some(ProtocolCapability::ContentSeed));
    assert_eq!(Capability::Storage.to_protocol_capability(), Some(ProtocolCapability::Storage));
    assert_eq!(Capability::Discovery.to_protocol_capability(), Some(ProtocolCapability::Discovery));
    assert_eq!(Capability::Sync.to_protocol_capability(), Some(ProtocolCapability::Sync));
    assert_eq!(Capability::Compute.to_protocol_capability(), Some(ProtocolCapability::Compute));

    // Client and PaymentRelay have no authority-level counterpart.
    assert_eq!(Capability::Client.to_protocol_capability(), None);
    assert_eq!(Capability::PaymentRelay.to_protocol_capability(), None);
    eprintln!("[cap 6] PASS: to_protocol_capability bridge maps correctly");
}

#[test]
fn test_node_can_advertise_multiple_capabilities() {
    // A node can hold multiple capabilities simultaneously.
    let caps = vec![
        Capability::MeshRelay,
        Capability::InternetGateway,
        Capability::Storage,
    ];

    // The node is both a relay and a gateway.
    assert!(caps.iter().any(|c| c.is_relay_capability()));
    assert!(caps.iter().any(|c| c.is_gateway_capability()));

    // The node has both ProtocolCapability::MeshRelay and InternetGateway.
    let proto_caps: Vec<_> = caps.iter().filter_map(|c| c.to_protocol_capability()).collect();
    assert!(proto_caps.contains(&ProtocolCapability::MeshRelay));
    assert!(proto_caps.contains(&ProtocolCapability::InternetGateway));
    assert!(proto_caps.contains(&ProtocolCapability::Storage));
    eprintln!("[cap 7] PASS: node can advertise multiple capabilities");
}

#[test]
fn test_remote_hint_claims_gateway_with_new_capability_string() {
    use snp_node::node::topology::RemoteNodeHint;

    fn make_hint(caps: Vec<&str>) -> RemoteNodeHint {
        RemoteNodeHint {
            target_node_id: [0xAA; 32],
            claimed_sequence: 1,
            claimed_capabilities: caps.iter().map(|s| s.to_string()).collect(),
            claimed_visibility: "active".to_string(),
            claimed_last_seen: 0,
            distance_hint: 1,
            learned_from: [0xBB; 32],
            received_at: 0,
            source_propagation_sequence: 1,
        }
    }

    // A hint using the new "internet-gateway" string should be recognized.
    assert!(make_hint(vec!["internet-gateway"]).claims_gateway(),
        "hint with 'internet-gateway' must be recognized as gateway claim");

    // A hint using the old "gateway" string should still be recognized.
    assert!(make_hint(vec!["gateway"]).claims_gateway(),
        "hint with 'gateway' must still be recognized");

    // A hint using "crypto-gateway" should also be recognized.
    assert!(make_hint(vec!["crypto-gateway"]).claims_gateway(),
        "hint with 'crypto-gateway' must be recognized as gateway claim");

    // A hint with non-gateway capabilities should not claim gateway.
    assert!(!make_hint(vec!["storage", "content-seed"]).claims_gateway(),
        "hint with non-gateway capabilities must not claim gateway");
    eprintln!("[cap 8] PASS: RemoteNodeHint.claims_gateway() recognizes all gateway variants");
}

#[test]
fn test_remote_hint_claims_relay_with_new_capability_string() {
    use snp_node::node::topology::RemoteNodeHint;

    fn make_hint(caps: Vec<&str>) -> RemoteNodeHint {
        RemoteNodeHint {
            target_node_id: [0xAA; 32],
            claimed_sequence: 1,
            claimed_capabilities: caps.iter().map(|s| s.to_string()).collect(),
            claimed_visibility: "active".to_string(),
            claimed_last_seen: 0,
            distance_hint: 1,
            learned_from: [0xBB; 32],
            received_at: 0,
            source_propagation_sequence: 1,
        }
    }

    // New "mesh-relay" string.
    assert!(make_hint(vec!["mesh-relay"]).claims_relay(),
        "hint with 'mesh-relay' must be recognized as relay claim");

    // Old "relay" string.
    assert!(make_hint(vec!["relay"]).claims_relay(),
        "hint with 'relay' must still be recognized");

    // Crypto relay.
    assert!(make_hint(vec!["crypto-relay"]).claims_relay(),
        "hint with 'crypto-relay' must be recognized as relay claim");

    // Non-relay.
    assert!(!make_hint(vec!["storage"]).claims_relay(),
        "hint with non-relay capabilities must not claim relay");
    eprintln!("[cap 9] PASS: RemoteNodeHint.claims_relay() recognizes all relay variants");
}

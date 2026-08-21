//! R4.9.3 — Peer Lifecycle Automation.
//!
//! Tests for:
//! - Peer refresh updates liveness
//! - Expired peer becomes stale
//! - Stale peer not selected
//! - Quarantined peer not selected
//! - Peer recovery after revalidation
//! - Revoked peer cannot recover through advertisement refresh
//! - Sequence floor survives stale transition
//! - Sequence floor survives quarantine

#![allow(clippy::pedantic)]

use snp_crypto::{x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_identity::{
    IdentityLifecycle, NodeIdentity, NodeId, RevocationStore,
};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::node_advert::{
    AcceptanceResult, AdvertisementAcceptanceStore, NodeAdvertisement,
};
use snp_node::node::peer_lifecycle::{
    PeerLifecycleManager, PeerOperationalState,
};

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn test_x25519_keypair() -> (X25519Secret, X25519PubKey) {
    x25519_static_keypair()
}

fn make_relay_advert(identity: &NodeIdentity, listen_addr: &str, expiry_secs: u64) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp(listen_addr)],
        None,
        expiry_secs,
        1,
    )
}

// ─── 1. Peer refresh updates liveness ──────────────────────────────────

/// A fresh valid advertisement refreshes the peer's liveness — the peer
/// transitions from STALE back to ACTIVE.
#[test]
fn r4_9_3_peer_refresh_updates_liveness() {
    let peer_identity = test_identity(0x01);
    let mut store = AdvertisementAcceptanceStore::new();
    let mut lifecycle = PeerLifecycleManager::new(store, RevocationStore::new());
    let now = snp_identity::now_unix();

    // Create an advert with short expiry.
    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9001", 1);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Initially ACTIVE.
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Active,
        "peer must be Active after accepting advertisement"
    );

    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let later = snp_identity::now_unix();
    lifecycle.maintain(later);

    // Now STALE.
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Stale,
        "peer must be Stale after advertisement expiry"
    );

    // Refresh with a new valid advertisement (sequence 2).
    let advert2 = NodeAdvertisement::create_and_sign(
        &peer_identity.secret_key,
        &peer_identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:9001")],
        None,
        3600,
        2, // higher sequence
    );
    let verified2 = advert2.verify_into_verified().expect("verify2");
    lifecycle.accept_advertisement(verified2).expect("accept2");

    // Back to ACTIVE.
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Active,
        "peer must be Active after fresh advertisement refresh"
    );
    eprintln!("[test] PASS: peer refresh updates liveness — STALE → ACTIVE");
}

// ─── 2. Expired peer becomes stale ──────────────────────────────────────

/// After advertisement expiry + maintenance, the peer transitions to STALE.
#[test]
fn r4_9_3_expired_peer_becomes_stale() {
    let peer_identity = test_identity(0x02);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9002", 1);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Active
    );

    // Wait for expiry + run maintenance.
    std::thread::sleep(std::time::Duration::from_secs(2));
    lifecycle.maintain(snp_identity::now_unix());

    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Stale,
        "peer must be Stale after expiry + maintenance"
    );
    eprintln!("[test] PASS: expired peer becomes stale");
}

// ─── 3. Stale peer not selected ─────────────────────────────────────────

/// A stale peer is NOT eligible for new forwarding/routing.
#[test]
fn r4_9_3_stale_peer_not_selected() {
    let peer_identity = test_identity(0x03);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9003", 1);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_secs(2));
    lifecycle.maintain(snp_identity::now_unix());

    // Stale → NOT eligible.
    assert!(
        !lifecycle.is_eligible_for_forwarding(&peer_identity.node_id),
        "stale peer must NOT be eligible for forwarding"
    );
    eprintln!("[test] PASS: stale peer not selected for forwarding");
}

// ─── 4. Quarantined peer not selected ───────────────────────────────────

/// A quarantined peer is NOT eligible for new forwarding.
#[test]
fn r4_9_3_quarantined_peer_not_selected() {
    let peer_identity = test_identity(0x04);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9004", 3600);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Quarantine the peer.
    lifecycle.quarantine(&peer_identity.node_id, "forwarding failure");
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Quarantined,
        "peer must be Quarantined after quarantine()"
    );
    assert!(
        !lifecycle.is_eligible_for_forwarding(&peer_identity.node_id),
        "quarantined peer must NOT be eligible for forwarding"
    );
    eprintln!("[test] PASS: quarantined peer not selected");
}

// ─── 5. Peer recovery after revalidation ───────────────────────────────

/// A quarantined peer returns to ACTIVE after receiving a fresh valid
/// advertisement (revalidation).
#[test]
fn r4_9_3_peer_recovery_after_revalidation() {
    let peer_identity = test_identity(0x05);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9005", 3600);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Quarantine.
    lifecycle.quarantine(&peer_identity.node_id, "connection failure");
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Quarantined
    );

    // Revalidate with a fresh advert (sequence 2).
    let advert2 = NodeAdvertisement::create_and_sign(
        &peer_identity.secret_key,
        &peer_identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:9005")],
        None,
        3600,
        2,
    );
    let verified2 = advert2.verify_into_verified().expect("verify2");
    lifecycle.accept_advertisement(verified2).expect("accept2");

    // Recovery → ACTIVE.
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Active,
        "peer must recover to Active after successful revalidation"
    );
    assert!(
        lifecycle.is_eligible_for_forwarding(&peer_identity.node_id),
        "recovered peer must be eligible for forwarding"
    );
    eprintln!("[test] PASS: peer recovery after revalidation");
}

// ─── 6. Revoked peer cannot recover ─────────────────────────────────────

/// A revoked peer CANNOT recover through advertisement refresh — the
/// RevocationStore blocks revalidation.
#[test]
fn r4_9_3_revoked_peer_cannot_recover_through_refresh() {
    let peer_identity = test_identity(0x06);
    let revocation = RevocationStore::new();
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        revocation,
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9006", 3600);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Quarantine.
    lifecycle.quarantine(&peer_identity.node_id, "failure");

    // Revoke the peer.
    lifecycle.revoke_peer(&peer_identity.node_id).expect("revoke");

    // Attempt revalidation with a fresh advert.
    let advert2 = NodeAdvertisement::create_and_sign(
        &peer_identity.secret_key,
        &peer_identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:9006")],
        None,
        3600,
        2,
    );
    let verified2 = advert2.verify_into_verified().expect("verify2");
    let result = lifecycle.accept_advertisement(verified2);

    // Must be rejected — revoked peers cannot recover.
    assert!(
        result.is_err(),
        "revoked peer must NOT recover through advertisement refresh"
    );
    assert!(
        !lifecycle.is_eligible_for_forwarding(&peer_identity.node_id),
        "revoked peer must NOT be eligible for forwarding"
    );
    eprintln!("[test] PASS: revoked peer cannot recover through refresh");
}

// ─── 7. Sequence floor survives stale ──────────────────────────────────

/// The `highest_accepted_sequence` survives the ACTIVE → STALE transition.
#[test]
fn r4_9_3_sequence_floor_survives_stale() {
    let peer_identity = test_identity(0x07);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9007", 1);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    // Check the sequence floor.
    let seq1 = lifecycle.highest_sequence(&peer_identity.node_id);
    assert_eq!(seq1, Some(1), "sequence floor must be 1");

    // Wait for expiry + maintain.
    std::thread::sleep(std::time::Duration::from_secs(2));
    lifecycle.maintain(snp_identity::now_unix());

    // Stale — but sequence floor must persist.
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Stale
    );
    let seq2 = lifecycle.highest_sequence(&peer_identity.node_id);
    assert_eq!(
        seq2, Some(1),
        "sequence floor must persist after STALE transition"
    );

    // An old advert (sequence 1) must be rejected as stale/duplicate.
    let old_advert = make_relay_advert(&peer_identity, "127.0.0.1:9007", 3600);
    let old_verified = old_advert.verify_into_verified().expect("verify old");
    let result = lifecycle.accept_advertisement(old_verified);
    // The result should be either Stale (sequence equal) or Duplicate.
    assert!(
        matches!(result, Ok(AcceptanceResult::Stale { .. }) | Ok(AcceptanceResult::Duplicate { .. })),
        "old sequence must be rejected as Stale or Duplicate after ACTIVE→STALE transition, got: {result:?}"
    );
    eprintln!("[test] PASS: sequence floor survives stale transition");
}

// ─── 8. Sequence floor survives quarantine ─────────────────────────────

/// The `highest_accepted_sequence` survives quarantine.
#[test]
fn r4_9_3_sequence_floor_survives_quarantine() {
    let peer_identity = test_identity(0x08);
    let mut lifecycle = PeerLifecycleManager::new(
        AdvertisementAcceptanceStore::new(),
        RevocationStore::new(),
    );

    let advert = make_relay_advert(&peer_identity, "127.0.0.1:9008", 3600);
    let verified = advert.verify_into_verified().expect("verify");
    lifecycle.accept_advertisement(verified).expect("accept");

    let seq_before = lifecycle.highest_sequence(&peer_identity.node_id);
    assert_eq!(seq_before, Some(1));

    // Quarantine.
    lifecycle.quarantine(&peer_identity.node_id, "test failure");
    assert_eq!(
        lifecycle.operational_state(&peer_identity.node_id),
        PeerOperationalState::Quarantined
    );

    // Sequence floor must persist.
    let seq_after = lifecycle.highest_sequence(&peer_identity.node_id);
    assert_eq!(
        seq_after, Some(1),
        "sequence floor must persist after quarantine"
    );
    eprintln!("[test] PASS: sequence floor survives quarantine");
}

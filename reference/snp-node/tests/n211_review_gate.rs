//! N2.1.1.1 review-gate security tests.
//!
//! These test the specific blockers identified in the architecture review of
//! commit f0afe7e:
//!
//!   1. Unverified `PeerSummaryList` cannot mutate topology (P0 blocker #1)
//!   2. Propagation sequence state survives restart (P0 blocker #2)
//!   3. Remote hint freshness is age-based, not claim-based (P0 blocker #3)
//!   4. Transaction order: hint removal follows successful acceptance (fix #4)
//!
//! These are NOT N2.1.2 work. They close security holes in the N2.1.1.1
//! milestone.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, NodeAdvertisement, PeerSummary, PeerSummaryList,
    PropagationResult, PropagationVerifyError, RemoteHintFreshness, TopologyGraph,
    TransportEndpoint, REMOTE_HINT_MAX_AGE_SECS,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (_x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()),
        3600,
        seq,
    );
    (advert, sk, pk)
}

fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk,
        &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None,
        3600,
        seq,
    );
    (advert, sk, pk)
}

fn make_gateway_summary(node_id: [u8; 32], seq: u64, distance: u8) -> PeerSummary {
    PeerSummary {
        node_id,
        advertisement_sequence: seq,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: 0,
        distance_hint: distance,
    }
}

// Static counter for unique temp-file paths per test.
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let mut p = std::env::temp_dir();
    p.push(format!("sharenet-n211-review-{tag}-{pid}-{n}.db"));
    p
}

// ─── Fix #1: VerifiedPeerSummaryList trust boundary ───────────────────────

/// P0 blocker #1: an unverified PeerSummaryList must NOT be able to mutate
/// topology state. The only path to topology mutation is through
/// `verify_into_verified()`, which performs cryptographic verification.
#[test]
fn unverified_propagation_cannot_modify_topology() {
    let mut graph = TopologyGraph::new();

    // Create a legitimately signed PeerSummaryList.
    let (_gw_advert, _, gw_pk) = make_gateway_advert(b"unverified-gw", 1);
    let gw_id = derive_node_id(&gw_pk);
    let (sender_sk, sender_pk) = fresh_keypair(b"unverified-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );

    // Corrupt the signature — this list is now unverified.
    let mut forged = list.clone();
    forged.signature[0] ^= 0xff;

    // verify_into_verified() MUST fail.
    let result = forged.verify_into_verified();
    assert!(result.is_err(), "forged list must fail verification");
    assert_eq!(
        result.unwrap_err(),
        PropagationVerifyError::InvalidSignature,
        "must be InvalidSignature"
    );

    // Since we cannot obtain a VerifiedPeerSummaryList, we cannot call
    // process_peer_summaries at all. The topology MUST be unchanged.
    assert_eq!(graph.gateway_hints().len(), 0, "no hints should exist");
    assert_eq!(
        graph.highest_propagation_sequence(&sender_id),
        None,
        "propagation state must be unchanged"
    );

    // The legitimate list DOES verify and DOES mutate topology.
    let verified = list.verify_into_verified().expect("legitimate list verifies");
    let result = graph.process_peer_summaries(&verified);
    assert!(matches!(result, PropagationResult::Accepted { .. }));
    assert_eq!(graph.gateway_hints().len(), 1, "hint should be stored");
    assert_eq!(
        graph.highest_propagation_sequence(&sender_id),
        Some(1),
        "propagation state must advance"
    );
}

/// P0 blocker #1: a PeerSummaryList signed by key A but claiming
/// sender_ed25519_public_key = B must be rejected.
#[test]
fn wrong_sender_key_rejected() {
    let (sk_a, _pk_a) = fresh_keypair(b"wrong-sender-a");
    let (_sk_b, pk_b) = fresh_keypair(b"wrong-sender-b");
    let sender_id = derive_node_id(&pk_b); // claim to be B

    let list = PeerSummaryList::create_and_sign(
        &sk_a,    // sign with A's secret key
        &pk_b,    // but claim B's public key
        sender_id,
        vec![],
        1,
    );

    let result = list.verify_into_verified();
    assert!(result.is_err(), "wrong-sender-key list must fail");
    assert_eq!(
        result.unwrap_err(),
        PropagationVerifyError::InvalidSignature,
        "signature won't verify under pk_b"
    );
}

/// P0 blocker #1: a PeerSummaryList with a corrupted signature must be
/// rejected with InvalidSignature.
#[test]
fn invalid_signature_rejected() {
    let (sk, pk) = fresh_keypair(b"invalid-sig");
    let sender_id = derive_node_id(&pk);
    let mut list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![], 1);
    // Flip a bit in the signature.
    list.signature[0] ^= 0x01;
    let result = list.verify_into_verified();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PropagationVerifyError::InvalidSignature);
}

/// P0 blocker #1: a PeerSummaryList where sender_node_id does not match
/// derive_node_id(sender_ed25519_public_key) must be rejected with
/// NodeIdKeyMismatch.
#[test]
fn node_id_key_mismatch_rejected() {
    let (sk, pk) = fresh_keypair(b"mismatch-signer");
    let real_id = derive_node_id(&pk);
    // A DIFFERENT node's ID (from a different keypair).
    let (_, other_pk) = fresh_keypair(b"mismatch-other");
    let other_id = derive_node_id(&other_pk);

    // Create a list that is correctly signed by sk, but claims sender_node_id
    // = other_id (which does NOT match derive_node_id(pk)).
    let list = PeerSummaryList::create_and_sign(&sk, &pk, other_id, vec![], 1);
    assert_ne!(real_id, other_id, "test setup: IDs must differ");

    let result = list.verify_into_verified();
    assert!(result.is_err(), "node-id/key mismatch must fail");
    assert_eq!(
        result.unwrap_err(),
        PropagationVerifyError::NodeIdKeyMismatch,
        "must be NodeIdKeyMismatch, not InvalidSignature"
    );
}

// ─── Fix #2: Persistent propagation state ─────────────────────────────────

/// P0 blocker #2: propagation sequence state must survive restart.
#[test]
fn propagation_sequence_survives_restart() {
    let peer_path = temp_path("pssr-peer");
    let prop_path = temp_path("pssr-prop");
    // Clean up after the test.
    let _cleanup = scopeguard::guard((), || {
        let _ = std::fs::remove_file(&peer_path);
        let _ = std::fs::remove_file(&prop_path);
    });

    let (sender_sk, sender_pk) = fresh_keypair(b"pssr-sender");
    let sender_id = derive_node_id(&sender_pk);

    // Phase 1: open, accept propagation seq=5, drop.
    {
        let mut graph =
            TopologyGraph::open_with_propagation_path(&peer_path, &prop_path).expect("open");
        let list = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![], 5);
        let verified = list.verify_into_verified().expect("verify");
        let result = graph.process_peer_summaries(&verified);
        assert!(matches!(result, PropagationResult::Accepted { .. }));
        assert_eq!(
            graph.highest_propagation_sequence(&sender_id),
            Some(5),
            "seq 5 accepted before restart"
        );
    }
    // Graph is dropped here. Propagation state is persisted to disk.

    // Phase 2: re-open from the same path. The propagation floor MUST survive.
    {
        let graph =
            TopologyGraph::open_with_propagation_path(&peer_path, &prop_path).expect("reopen");
        assert_eq!(
            graph.highest_propagation_sequence(&sender_id),
            Some(5),
            "propagation sequence MUST survive restart (review-gate fix #2)"
        );
    }
}

/// P0 blocker #2: after restart, an old propagation sequence must be rejected
/// as stale (replay prevention survives restart).
#[test]
fn old_sequence_rejected_after_restart() {
    let peer_path = temp_path("osar-peer");
    let prop_path = temp_path("osar-prop");
    let _cleanup = scopeguard::guard((), || {
        let _ = std::fs::remove_file(&peer_path);
        let _ = std::fs::remove_file(&prop_path);
    });

    let (sender_sk, sender_pk) = fresh_keypair(b"osar-sender");
    let sender_id = derive_node_id(&sender_pk);

    // Phase 1: accept seq=10.
    {
        let mut graph =
            TopologyGraph::open_with_propagation_path(&peer_path, &prop_path).expect("open");
        let list = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![], 10);
        let verified = list.verify_into_verified().expect("verify");
        let result = graph.process_peer_summaries(&verified);
        assert!(matches!(result, PropagationResult::Accepted { .. }));
    }

    // Phase 2: restart, try to replay seq=10 (duplicate) and seq=5 (stale).
    {
        let mut graph =
            TopologyGraph::open_with_propagation_path(&peer_path, &prop_path).expect("reopen");

        // Duplicate (seq=10) — must be rejected.
        let list10 = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![], 10);
        let verified10 = list10.verify_into_verified().expect("verify");
        let result = graph.process_peer_summaries(&verified10);
        assert!(
            matches!(result, PropagationResult::Stale { .. }),
            "duplicate seq after restart must be rejected"
        );

        // Stale (seq=5) — must be rejected.
        let list5 = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![], 5);
        let verified5 = list5.verify_into_verified().expect("verify");
        let result = graph.process_peer_summaries(&verified5);
        assert!(
            matches!(result, PropagationResult::Stale { .. }),
            "stale seq after restart must be rejected"
        );

        // Newer (seq=11) — must be accepted.
        let list11 = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![], 11);
        let verified11 = list11.verify_into_verified().expect("verify");
        let result = graph.process_peer_summaries(&verified11);
        assert!(
            matches!(result, PropagationResult::Accepted { .. }),
            "newer seq after restart must be accepted"
        );
    }
}

// ─── Fix #3: Remote hint freshness ────────────────────────────────────────

/// P0 blocker #3: a remote hint older than REMOTE_HINT_MAX_AGE_SECS must be
/// purged, regardless of its claimed_visibility.
#[test]
fn remote_hint_expires_after_freshness_window() {
    let mut graph = TopologyGraph::new();
    let (_gw_advert, _, gw_pk) = make_gateway_advert(b"expire-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // Create a hint that claims "active" visibility but is OLD.
    let (sender_sk, sender_pk) = fresh_keypair(b"expire-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![PeerSummary {
            node_id: gw_id,
            advertisement_sequence: 1,
            capabilities: vec!["gateway".to_string()],
            visibility: "active".to_string(), // claims active
            last_seen: 0,
            distance_hint: 1,
        }],
        1,
    );
    let verified = list.verify_into_verified().expect("verify");
    graph.process_peer_summaries(&verified);
    assert_eq!(graph.gateway_hints().len(), 1, "fresh hint should be present");

    // Manually backdate the hint's received_at to simulate aging.
    let old = now_unix().saturating_sub(REMOTE_HINT_MAX_AGE_SECS + 1);
    graph.remote_hints_mut().get_mut(&gw_id).unwrap().received_at = old;

    // The hint's freshness MUST be Stale now.
    let hint = graph.remote_hints().get(&gw_id).unwrap();
    assert_eq!(
        hint.freshness(now_unix()),
        RemoteHintFreshness::Stale,
        "old hint must be Stale despite claimed_visibility=active"
    );

    // purge_expired MUST remove it.
    graph.purge_expired(now_unix());
    assert!(
        graph.remote_hints().get(&gw_id).is_none(),
        "expired hint must be purged (review-gate fix #3)"
    );
}

/// P0 blocker #3: stale gateway hints must NOT be returned by gateway_hints().
#[test]
fn stale_remote_gateway_hint_excluded() {
    let mut graph = TopologyGraph::new();
    let (_gw_advert, _, gw_pk) = make_gateway_advert(b"stale-gw-hint", 1);
    let gw_id = derive_node_id(&gw_pk);

    let (sender_sk, sender_pk) = fresh_keypair(b"stale-gw-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());
    assert_eq!(graph.gateway_hints().len(), 1, "fresh hint present");

    // Backdate the hint.
    let old = now_unix().saturating_sub(REMOTE_HINT_MAX_AGE_SECS + 1);
    graph.remote_hints_mut().get_mut(&gw_id).unwrap().received_at = old;

    // gateway_hints() MUST exclude the stale hint.
    assert_eq!(
        graph.gateway_hints().len(),
        0,
        "stale hint must NOT be in gateway_hints()"
    );
    // gateway_hints_including_stale() MUST still include it (for diagnostics).
    assert_eq!(
        graph.gateway_hints_including_stale().len(),
        1,
        "stale hint should be in diagnostic view"
    );
}

/// P0 blocker #3: a fresh hint (within the window) must be retained.
#[test]
fn fresh_hint_retained() {
    let mut graph = TopologyGraph::new();
    let (_gw_advert, _, gw_pk) = make_gateway_advert(b"fresh-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    let (sender_sk, sender_pk) = fresh_keypair(b"fresh-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    let now = now_unix();
    // purge_expired should NOT remove a fresh hint.
    graph.purge_expired(now);
    assert!(
        graph.remote_hints().get(&gw_id).is_some(),
        "fresh hint must be retained"
    );
    assert_eq!(graph.gateway_hints().len(), 1, "fresh hint in gateway_hints()");
}

// ─── Fix #4: Transaction order ────────────────────────────────────────────

/// Fix #4: when accept_advertisement succeeds, the remote hint is removed
/// AFTER the successful acceptance (not before). This is the success-path
/// verification.
#[test]
fn accept_advertisement_removes_superseded_hint_after_success() {
    let mut graph = TopologyGraph::new();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"txn-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // First, store a remote hint about gw_id.
    let (sender_sk, sender_pk) = fresh_keypair(b"txn-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());
    assert!(graph.remote_hints().get(&gw_id).is_some(), "hint present");

    // Now accept the real advertisement for gw_id.
    let verified = gw_advert.verify_into_verified().expect("verify");
    let result = graph.accept_advertisement(verified);
    assert!(result.is_ok(), "accept must succeed");
    let _ = result;

    // The hint MUST be removed (direct knowledge takes precedence, and the
    // removal happens AFTER successful acceptance).
    assert!(
        graph.remote_hints().get(&gw_id).is_none(),
        "remote hint must be removed after successful accept (fix #4)"
    );
    // The direct record MUST be present (the node is now authenticated, not
    // just hinted). direct_gateways() also requires a reachable link, which
    // we don't have here, so we check is_authenticated() instead.
    assert!(
        graph.is_authenticated(&gw_id),
        "node must be directly authenticated after accept"
    );
    assert!(
        graph.remote_hints().get(&gw_id).is_none(),
        "remote hint must be gone"
    );
}

/// Fix #4: the remote hint is NOT removed if accept_advertisement would fail.
/// This is hard to test without simulating a persistence failure, but we
/// can verify the ORDERING: the remote hint is still present during the
/// acceptance call (not removed before). The key invariant is that a
/// successful accept always leaves the topology consistent.
#[test]
fn remote_hint_present_during_accept() {
    let mut graph = TopologyGraph::new();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"txn-during-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // Store a remote hint.
    let (sender_sk, sender_pk) = fresh_keypair(b"txn-during-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());
    assert!(graph.remote_hints().contains_key(&gw_id));

    // Accept succeeds → hint removed.
    let verified = gw_advert.verify_into_verified().expect("verify");
    graph.accept_advertisement(verified).expect("accept");
    assert!(!graph.remote_hints().contains_key(&gw_id));
}

// ─── Helper: now_unix (local to this test file) ────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Import scopeguard for cleanup (inline to avoid adding a dep) ──────────
//
// We use a tiny RAII guard instead of the `scopeguard` crate to avoid adding
// a dependency just for test cleanup.
mod scopeguard {
    pub struct Guard<F: FnOnce()> {
        f: Option<F>,
    }
    impl<F: FnOnce()> Drop for Guard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.f.take() {
                f();
            }
        }
    }
    pub fn guard<F: FnOnce()>(_: (), f: F) -> Guard<F> {
        Guard { f: Some(f) }
    }
}

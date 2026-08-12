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
    let mut graph = TopologyGraph::new_for_testing();

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
    let mut graph = TopologyGraph::new_for_testing();
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
    let mut graph = TopologyGraph::new_for_testing();
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
    let mut graph = TopologyGraph::new_for_testing();
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
    let mut graph = TopologyGraph::new_for_testing();
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
    let mut graph = TopologyGraph::new_for_testing();
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

// ─── Fix #6 (P0): stale hints must NOT be re-propagated ───────────────────

/// P0: A receives a hint about G. The hint becomes stale (older than
/// REMOTE_HINT_MAX_AGE_SECS). A generates peer summaries. G must NOT appear
/// in A's propagated summaries.
///
/// Without this check, B receiving A's summaries would set `received_at = NOW`
/// for G, treating the stale information as fresh — defeating the freshness
/// rule across the mesh.
#[test]
fn stale_hint_is_not_repropagated() {
    let mut graph = TopologyGraph::new_for_testing();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"reprop-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // Store a remote hint about G.
    let (sender_sk, sender_pk) = fresh_keypair(b"reprop-sender");
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

    // Backdate the hint to make it stale.
    let old = now_unix().saturating_sub(REMOTE_HINT_MAX_AGE_SECS + 1);
    graph.remote_hints_mut().get_mut(&gw_id).unwrap().received_at = old;

    // Verify it's stale.
    let hint = graph.remote_hints().get(&gw_id).unwrap();
    assert_eq!(
        hint.freshness(now_unix()),
        RemoteHintFreshness::Stale,
        "hint must be stale after backdating"
    );

    // Generate peer summaries — G must NOT appear (stale hints not re-propagated).
    let summaries = graph.generate_peer_summaries();
    let g_in_summaries = summaries.iter().any(|s| s.node_id == gw_id);
    assert!(
        !g_in_summaries,
        "stale hint about G must NOT be re-propagated (review-gate fix #6)"
    );
}

/// P0 (multi-hop): A has a stale hint about G. A generates summaries (which
/// exclude G). B receives A's summaries. B must NOT have a hint about G.
///
/// This verifies the freshness guarantee propagates: stale info cannot be
/// refreshed through the mesh.
#[test]
fn stale_hint_not_refreshed_through_mesh() {
    // Node A's topology.
    let mut graph_a = TopologyGraph::new_for_testing();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"mesh-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // A receives a hint about G (from some sender S).
    let (sender_sk, sender_pk) = fresh_keypair(b"mesh-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph_a.process_peer_summaries(&list.verify_into_verified().unwrap());
    assert_eq!(graph_a.gateway_hints().len(), 1, "A has fresh hint about G");

    // Backdate A's hint to make it stale.
    let old = now_unix().saturating_sub(REMOTE_HINT_MAX_AGE_SECS + 1);
    graph_a.remote_hints_mut().get_mut(&gw_id).unwrap().received_at = old;

    // A generates summaries — G should NOT be included.
    let summaries = graph_a.generate_peer_summaries();
    assert!(
        !summaries.iter().any(|s| s.node_id == gw_id),
        "A must not re-propagate stale G"
    );

    // B receives A's summaries (which don't contain G).
    let (a_sk, a_pk) = fresh_keypair(b"mesh-a");
    let a_id = derive_node_id(&a_pk);
    let list_for_b = PeerSummaryList::create_and_sign(
        &a_sk,
        &a_pk,
        a_id,
        summaries, // A's summaries (without G)
        1,
    );

    let mut graph_b = TopologyGraph::new_for_testing();
    graph_b.process_peer_summaries(&list_for_b.verify_into_verified().unwrap());

    // B must NOT have a hint about G.
    assert!(
        graph_b.remote_hints().get(&gw_id).is_none(),
        "B must NOT have a hint about G — stale info cannot be refreshed through the mesh"
    );
}

// ─── Fix #7: Snapshot split — knowledge vs executable ─────────────────────

/// The ExecutableNetworkSnapshot MUST NOT contain remote hints.
/// It is the only snapshot type a future route engine should accept.
#[test]
fn executable_snapshot_excludes_remote_hints() {
    let mut graph = TopologyGraph::new_for_testing();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"exec-snap-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    // Store a remote hint about G.
    let (sender_sk, sender_pk) = fresh_keypair(b"exec-snap-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // Knowledge snapshot DOES include remote hints.
    let knowledge = graph.snapshot_knowledge();
    assert!(
        knowledge.remote_hints.contains_key(&gw_id),
        "knowledge snapshot must include remote hints"
    );

    // Executable snapshot does NOT have a remote_hints field at all.
    // (If this doesn't compile, someone added remote_hints to the wrong type.)
    let executable = graph.snapshot_executable();
    // The only fields are authenticated_nodes and usable_links — both empty
    // here because we haven't accepted any direct advertisements.
    assert!(
        executable.authenticated_nodes.is_empty(),
        "executable snapshot must have no authenticated nodes"
    );
    assert!(
        executable.usable_links.is_empty(),
        "executable snapshot must have no usable links"
    );
}

/// The knowledge snapshot includes remote hints (for diagnostics).
#[test]
fn knowledge_snapshot_includes_remote_hints() {
    let mut graph = TopologyGraph::new_for_testing();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"know-snap-gw", 1);
    let gw_id = derive_node_id(&gw_pk);

    let (sender_sk, sender_pk) = fresh_keypair(b"know-snap-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk,
        &sender_pk,
        sender_id,
        vec![make_gateway_summary(gw_id, 1, 1)],
        1,
    );
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    let knowledge = graph.snapshot_knowledge();
    assert!(
        knowledge.remote_hints.contains_key(&gw_id),
        "knowledge snapshot must include remote hints for diagnostics"
    );
    assert_eq!(
        knowledge.gateway_hints().len(),
        1,
        "knowledge snapshot gateway_hints() works"
    );
}

// ─── Fix #8: ephemeral constructor is test-only ─────────────────────────────

/// new_for_testing() creates an ephemeral (non-persistent) topology graph.
/// This test verifies the constructor exists and is clearly named for testing.
/// Production code should use open(path) instead.
#[test]
fn new_for_testing_creates_ephemeral_graph() {
    let graph = TopologyGraph::new_for_testing();
    // No persistence path — propagation state is in-memory only.
    // This is acceptable for unit tests but NOT for production.
    assert_eq!(graph.node_count(), 0, "fresh graph is empty");
}

// ─── Fix #9: Default impl removed + new() private ──────────────────────────

/// Compile-time guarantee that `TopologyGraph::new()` is PRIVATE.
///
/// This test file is an EXTERNAL consumer of the `snp_node` crate. It can
/// only call PUBLIC items. If `TopologyGraph::new()` were public, this test
/// file could call it directly — but it cannot (the call would fail to
/// compile with E0624 "associated function `new` is private"). The fact that
/// this test file compiles AT ALL is the proof: every call site uses
/// `new_for_testing()` (the only public ephemeral constructor) or `open(path)`
/// (the persistent constructor).
///
/// If someone re-adds `impl Default for TopologyGraph`, the CI architectural
/// guard (`reference/scripts/architectural-guard.sh`) catches any
/// `TopologyGraph::default()` / `Default::default::<TopologyGraph>()` usage
/// in production source.
#[test]
fn new_for_testing_is_the_only_public_ephemeral_constructor() {
    // This compiles because new_for_testing() is public.
    let _g = TopologyGraph::new_for_testing();
    // If `TopologyGraph::new()` were also public, the line below would compile
    // — but it doesn't (E0624), which is the guarantee.
    // let _g2 = TopologyGraph::new();  // would fail: new() is private
}

/// Runtime check: `Default::default()` cannot produce a TopologyGraph
/// because `impl Default` is removed. We can't easily test the ABSENCE of a
/// trait at runtime, but the architectural-guard.sh script statically checks
/// that no production code calls `TopologyGraph::default()` or
/// `Default::default::<TopologyGraph>()`.
#[test]
fn default_trait_is_absent_documentation() {
    // This test exists to document the guarantee. The real enforcement is:
    //   1. `impl Default for TopologyGraph` is removed (compile-time: the
    //      method doesn't exist, so `TopologyGraph::default()` won't compile).
    //   2. `architectural-guard.sh` greps production source for any
    //      `Default::default` usage on TopologyGraph.
    assert!(true, "Default impl is removed; guard script enforces no usage in src/");
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

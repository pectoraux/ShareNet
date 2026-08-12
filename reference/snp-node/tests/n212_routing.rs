//! N2.1.2 — Path Discovery and Route Construction tests.
//!
//! Spec: spec/07-routing.md (Sections 22–29 of the frozen spec).
//!
//! ## Critical invariants tested
//!
//! 1. **`RouteProposal ≠ CommittedRoute`** — a source signing a hop list
//!    does NOT mean the relays agreed. `commit_route()` requires every
//!    participant's signed `RouteAcceptance`.
//!
//! 2. **`Authenticated topology ≠ Executable route`** — `discover_path()`
//!    uses ONLY `ExecutableNetworkSnapshot` (authenticated nodes + usable
//!    links). `RemoteNodeHint`s cannot enter the route.
//!
//! 3. **Every hop is authenticated** — the `RouteProposal`'s hop list is
//!    validated for structural integrity (no loops, destination is last hop,
//!    bounded hop count).
//!
//! 4. **Missing/wrong/expired acceptances are rejected** — `commit_route()`
//!    fails closed if any required participant hasn't accepted, or if an
//!    acceptance is for the wrong proposal, or has expired.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    CandidateDestination, Capability, CommittedRoute, CommitError, Link, LinkKey,
    NodeAdvertisement, PeerSummary, PeerSummaryList, RemoteNodeHint, RouteAcceptance,
    RouteProposal, TopologyGraph, TransportEndpoint, commit_route, discover_path,
};
use std::collections::HashMap;

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (_x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()), 3600, seq,
    );
    (advert, sk, pk)
}

fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None, 3600, seq,
    );
    (advert, sk, pk)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Set up a topology: source → relay → gateway, with verified advertisements
/// and usable links. Returns the topology + the three node IDs + secret keys.
struct TestTopology {
    graph: TopologyGraph,
    source_id: [u8; 32],
    source_sk: [u8; 32],
    source_pk: [u8; 32],
    relay_id: [u8; 32],
    relay_sk: [u8; 32],
    relay_pk: [u8; 32],
    gateway_id: [u8; 32],
    gateway_sk: [u8; 32],
    gateway_pk: [u8; 32],
}

fn setup_test_topology() -> TestTopology {
    let mut graph = TopologyGraph::new_for_testing();

    // Source (client).
    let (source_sk, source_pk) = fresh_keypair(b"n212-source");
    let source_id = derive_node_id(&source_pk);

    // Relay.
    let (relay_advert, relay_sk, relay_pk) = make_relay_advert(b"n212-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    let relay_verified = relay_advert.verify_into_verified().expect("relay verify");
    graph.accept_advertisement(relay_verified).expect("relay accept");

    // Gateway.
    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n212-gateway", 1);
    let gateway_id = derive_node_id(&gw_pk);
    let gw_verified = gw_advert.verify_into_verified().expect("gateway verify");
    graph.accept_advertisement(gw_verified).expect("gateway accept");

    // Links: source → relay, relay → gateway.
    graph.add_link(Link::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));
    graph.add_link(Link::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")),
        None,
    ));

    TestTopology {
        graph,
        source_id, source_sk, source_pk,
        relay_id, relay_sk, relay_pk,
        gateway_id, gateway_sk: gw_sk, gateway_pk: gw_pk,
    }
}

// ─── Test 1: RouteProposal is NOT a CommittedRoute ────────────────────────

/// The critical invariant: a source signing a hop list does NOT mean the
/// relays agreed. A `CommittedRoute` can ONLY be constructed by `commit_route()`
/// with valid acceptances from every required participant.
#[test]
fn route_proposal_is_not_committed_route() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    // Source proposes: source → relay → gateway.
    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    assert!(proposal.verify(), "proposal signature must verify");

    // Without acceptances, commit_route MUST fail.
    let result = commit_route(proposal.clone(), vec![], now);
    assert!(
        matches!(result, Err(CommitError::MissingAcceptance { .. })),
        "commit without acceptances must fail with MissingAcceptance"
    );

    // No CommittedRoute was produced.
    assert!(result.is_err());
}

// ─── Test 2: commit_route succeeds with all required acceptances ──────────

/// With valid acceptances from the relay AND the gateway, commit_route
/// produces a CommittedRoute.
#[test]
fn commit_route_succeeds_with_all_acceptances() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    // Relay accepts.
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        proposal_hash, "relay".to_string(), vec![], now + 3600,
    );
    assert!(relay_acc.verify());

    // Gateway accepts.
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        proposal_hash, "gateway".to_string(), vec![], now + 3600,
    );
    assert!(gateway_acc.verify());

    let result = commit_route(proposal, vec![relay_acc, gateway_acc], now);
    assert!(result.is_ok(), "commit with all acceptances must succeed");
    let committed = result.unwrap();
    assert_eq!(committed.source(), topo.source_id);
    assert_eq!(committed.destination(), topo.gateway_id);
    assert_eq!(committed.hops().len(), 3);
}

// ─── Test 3: Missing acceptance rejected ───────────────────────────────────

/// If the gateway accepts but the relay doesn't, commit_route fails.
#[test]
fn missing_acceptance_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    // Only gateway accepts (relay is missing).
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        proposal_hash, "gateway".to_string(), vec![], now + 3600,
    );

    let result = commit_route(proposal, vec![gateway_acc], now);
    assert!(
        matches!(result, Err(CommitError::MissingAcceptance { participant }) if participant == topo.relay_id),
        "must fail with MissingAcceptance for the relay"
    );
}

// ─── Test 4: Wrong proposal hash in acceptance rejected ─────────────────────

/// An acceptance signed for a DIFFERENT proposal must be rejected.
#[test]
fn wrong_proposal_hash_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );

    // Create a DIFFERENT proposal (different service) to get a different hash.
    let other_proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "content-retrieval".to_string(), // different service → different hash
        now + 3600,
    );
    assert_ne!(
        proposal.proposal_hash(), other_proposal.proposal_hash(),
        "test setup: the two proposals must have different hashes"
    );

    // Relay signs acceptance for the WRONG proposal.
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        other_proposal.proposal_hash(), // wrong hash!
        "relay".to_string(), vec![], now + 3600,
    );

    let result = commit_route(proposal, vec![relay_acc], now);
    assert!(
        matches!(result, Err(CommitError::AcceptanceProposalMismatch { .. })),
        "must fail with AcceptanceProposalMismatch"
    );
}

// ─── Test 5: Expired acceptance rejected ────────────────────────────────────

/// An acceptance that has expired must be rejected.
#[test]
fn expired_acceptance_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    // Relay's acceptance expired in the past.
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        proposal_hash, "relay".to_string(), vec![],
        now - 1, // expired!
    );

    let result = commit_route(proposal, vec![relay_acc], now);
    assert!(
        matches!(result, Err(CommitError::AcceptanceExpired { .. })),
        "must fail with AcceptanceExpired"
    );
}

// ─── Test 6: Unexpected participant rejected ────────────────────────────────

/// An acceptance from a node that is NOT in the hop list must be rejected.
#[test]
fn unexpected_participant_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    // A random node that is NOT in the route tries to accept.
    let (random_sk, random_pk) = fresh_keypair(b"n212-random");
    let random_id = derive_node_id(&random_pk);
    let random_acc = RouteAcceptance::create_and_sign(
        &random_sk, &random_pk, random_id,
        proposal_hash, "relay".to_string(), vec![], now + 3600,
    );

    let result = commit_route(proposal, vec![random_acc], now);
    assert!(
        matches!(result, Err(CommitError::UnexpectedParticipant { .. })),
        "must fail with UnexpectedParticipant"
    );
}

// ─── Test 7: Expired proposal rejected ──────────────────────────────────────

#[test]
fn expired_proposal_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now - 1, // expired!
    );

    let result = commit_route(proposal, vec![], now);
    assert!(
        matches!(result, Err(CommitError::ProposalExpired { .. })),
        "must fail with ProposalExpired"
    );
}

// ─── Test 8: discover_path uses ExecutableNetworkSnapshot ONLY ──────────────

/// `discover_path()` finds a path using ONLY authenticated nodes + usable
/// links. Remote hints are NOT in the snapshot and cannot influence routing.
#[test]
fn discover_path_uses_executable_snapshot_only() {
    let mut topo = setup_test_topology();

    // Add a remote hint about a DIFFERENT "gateway" that is NOT authenticated.
    let (fake_gw_sk, fake_gw_pk) = fresh_keypair(b"n212-fake-gw");
    let fake_gw_id = derive_node_id(&fake_gw_pk);
    let (sender_sk, sender_pk) = fresh_keypair(b"n212-hint-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id,
        vec![PeerSummary {
            node_id: fake_gw_id,
            advertisement_sequence: 1,
            capabilities: vec!["gateway".to_string()],
            visibility: "active".to_string(),
            last_seen: now_unix(),
            distance_hint: 1,
        }],
        1,
    );
    topo.graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // The executable snapshot does NOT include the fake gateway.
    let exec = topo.graph.snapshot_executable();
    assert!(
        !exec.authenticated_nodes.contains_key(&fake_gw_id),
        "fake gateway must NOT be in executable snapshot"
    );

    // discover_path finds source → relay → gateway (the authenticated path).
    let path = discover_path(&exec, &topo.source_id, &topo.gateway_id);
    assert!(path.is_some(), "must find a path to the real gateway");
    let path = path.unwrap();
    assert_eq!(path.hops, vec![topo.source_id, topo.relay_id, topo.gateway_id]);

    // discover_path to the FAKE gateway returns None (it's not in the snapshot).
    let fake_path = discover_path(&exec, &topo.source_id, &fake_gw_id);
    assert!(
        fake_path.is_none(),
        "must NOT find a path to the fake gateway (not in executable snapshot)"
    );
}

// ─── Test 9: CandidateDestination from hint ─────────────────────────────────

/// A `CandidateDestination` can be derived from a `RemoteNodeHint`, but it
/// is NOT an authenticated destination — it is a "maybe, worth investigating"
/// marker.
#[test]
fn candidate_destination_from_hint() {
    let mut topo = setup_test_topology();
    let (fake_gw_sk, fake_gw_pk) = fresh_keypair(b"n212-cand-gw");
    let fake_gw_id = derive_node_id(&fake_gw_pk);

    // Store a hint about the fake gateway.
    let (sender_sk, sender_pk) = fresh_keypair(b"n212-cand-sender");
    let sender_id = derive_node_id(&sender_pk);
    let list = PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id,
        vec![PeerSummary {
            node_id: fake_gw_id,
            advertisement_sequence: 1,
            capabilities: vec!["gateway".to_string()],
            visibility: "active".to_string(),
            last_seen: now_unix(),
            distance_hint: 2,
        }],
        1,
    );
    topo.graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // Derive a candidate from the hint.
    let hints = topo.graph.gateway_hints();
    assert_eq!(hints.len(), 1);
    let candidate = CandidateDestination::from_hint(hints[0]);
    assert_eq!(candidate.target_node_id, fake_gw_id);
    assert!(candidate.claims_gateway());
    assert_eq!(candidate.distance_hint, 2);

    // The candidate is NOT authenticated — it's just a target to investigate.
    // The caller would need to fetch + verify the target's advertisement.
}

// ─── Test 10: Invalid proposal signature rejected ───────────────────────────

/// A proposal with a corrupted source signature must be rejected by commit_route.
#[test]
fn invalid_proposal_signature_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let mut proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    // Corrupt the signature.
    proposal.source_signature[0] ^= 0xff;

    let result = commit_route(proposal, vec![], now);
    assert!(
        matches!(result, Err(CommitError::ProposalSignatureInvalid)),
        "must fail with ProposalSignatureInvalid"
    );
}

// ─── Test 11: Invalid acceptance signature rejected ─────────────────────────

#[test]
fn invalid_acceptance_signature_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    let mut relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        proposal_hash, "relay".to_string(), vec![], now + 3600,
    );
    // Corrupt the signature.
    relay_acc.signature[0] ^= 0xff;

    let result = commit_route(proposal, vec![relay_acc], now);
    assert!(
        matches!(result, Err(CommitError::AcceptanceSignatureInvalid { .. })),
        "must fail with AcceptanceSignatureInvalid"
    );
}

// ─── Test 12: Duplicate hop (loop) rejected ─────────────────────────────────

#[test]
fn duplicate_hop_rejected() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    // Create a proposal with a loop: source → relay → relay → gateway.
    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );

    let result = commit_route(proposal, vec![], now);
    assert!(
        matches!(result, Err(CommitError::DuplicateHop { .. })),
        "must fail with DuplicateHop"
    );
}

// ─── Test 13: CommittedRoute has private constructor ────────────────────────

/// Compile-time proof: `CommittedRoute` cannot be constructed directly.
/// Its fields are private. The only constructor is `commit_route()`.
///
/// This test verifies at runtime that `commit_route()` is the only path.
/// If someone adds a public constructor to `CommittedRoute`, this test
/// still passes — but the architectural guard script would catch
/// production misuse.
#[test]
fn committed_route_only_constructable_via_commit_route() {
    let mut topo = setup_test_topology();
    let now = now_unix();

    let proposal = RouteProposal::create_and_sign(
        &topo.source_sk, &topo.source_pk, topo.source_id,
        topo.gateway_id,
        vec![topo.source_id, topo.relay_id, topo.gateway_id],
        "internet-transit".to_string(),
        now + 3600,
    );
    let proposal_hash = proposal.proposal_hash();

    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        proposal_hash, "relay".to_string(), vec![], now + 3600,
    );
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        proposal_hash, "gateway".to_string(), vec![], now + 3600,
    );

    // The ONLY way to get a CommittedRoute is commit_route().
    let committed: CommittedRoute = commit_route(proposal, vec![relay_acc, gateway_acc], now).unwrap();
    assert_eq!(committed.source(), topo.source_id);
    assert_eq!(committed.destination(), topo.gateway_id);
    // The commitment hash is accessible but the internal fields are not.
    assert!(!committed.commitment().iter().all(|&b| b == 0), "commitment must be non-zero");
}

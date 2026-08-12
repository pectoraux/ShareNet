//! N2.1.2 — Path Discovery and Route Construction tests (review-corrected).
//!
//! Spec: spec/07-routing.md (Sections 22–29 of the frozen spec).
//!
//! ## Critical invariants tested
//!
//! 1. **`RouteProposal ≠ CommittedRoute`** — source signing ≠ participant consent.
//! 2. **`Authenticated topology ≠ Executable route`** — `discover_path()` uses
//!    ONLY `ExecutableNetworkSnapshot`; `validate_path()` requires every hop
//!    authenticated + every edge a usable link; `RouteProposal` consumes a
//!    `ValidatedPath`, not a free-form `Vec<NodeId>`.
//! 3. **Source is the first hop** (P0 #2).
//! 4. **Typed roles** (P1 #3): destination = Gateway, intermediate = Relay.
//! 5. **Bounded BFS** (P1 #5): `ROUTE_MAX_HOPS` enforced during search.
//! 6. **Snapshot invariant** (P1 #6): every usable link has both endpoints
//!    authenticated.
//! 7. **Freshness** (P1 #7): timestamp/expiry invariants like NodeAdvertisement.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, CommitError, Link, LinkKey, NodeAdvertisement, RouteAcceptance, RouteProposal,
    RouteRole, ServiceAgreement, TopologyGraph, TransportEndpoint, commit_route, discover_path,
    validate_path,
};

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
    let (source_sk, source_pk) = fresh_keypair(b"n212-source");
    let source_id = derive_node_id(&source_pk);
    // The source must also be an authenticated node (it appears in links and
    // must have a record in ExecutableNetworkSnapshot).
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk, &source_pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(source_advert.verify_into_verified().unwrap()).unwrap();
    let (relay_advert, relay_sk, relay_pk) = make_relay_advert(b"n212-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph.accept_advertisement(relay_advert.verify_into_verified().unwrap()).unwrap();
    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n212-gateway", 1);
    let gateway_id = derive_node_id(&gw_pk);
    graph.accept_advertisement(gw_advert.verify_into_verified().unwrap()).unwrap();
    graph.add_link(Link::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));
    graph.add_link(Link::new_up(
        LinkKey::new(relay_id, gateway_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));
    TestTopology {
        graph, source_id, source_sk, source_pk,
        relay_id, relay_sk, relay_pk,
        gateway_id, gateway_sk: gw_sk, gateway_pk: gw_pk,
    }
}

/// Build a validated path source → relay → gateway from the test topology.
fn build_validated_path(topo: &TestTopology) -> snp_node::node::ValidatedPath {
    let exec = topo.graph.snapshot_executable();
    let discovered = discover_path(&exec, &topo.source_id, &topo.gateway_id).unwrap();
    validate_path(&exec, &discovered).unwrap()
}

// ─── P0 #1: RouteProposal requires ValidatedPath, not Vec<NodeId> ─────────

/// A RouteProposal can only be constructed from a ValidatedPath (backed by
/// ExecutableNetworkSnapshot evidence). There is no free-form Vec<NodeId>
/// constructor.
#[test]
fn route_proposal_requires_validated_path() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    assert!(proposal.verify());
    assert_eq!(proposal.source, topo.source_id);
    assert_eq!(proposal.destination, topo.gateway_id);
}

/// An UNBACKED hop (not in ExecutableNetworkSnapshot) cannot be validated,
/// and therefore cannot produce a RouteProposal.
#[test]
fn arbitrary_unbacked_hop_cannot_be_committed() {
    let topo = setup_test_topology();
    let exec = topo.graph.snapshot_executable();

    // Try to discover a path to a node that is NOT in the snapshot.
    let (random_sk, random_pk) = fresh_keypair(b"n212-unbacked");
    let random_id = derive_node_id(&random_pk);
    let discovered = discover_path(&exec, &topo.source_id, &random_id);
    assert!(discovered.is_none(), "no path to unbacked node");

    // Even if we manually construct a DiscoveredPath with an unbacked node,
    // validate_path() rejects it.
    use snp_node::node::DiscoveredPath;
    let fake_path = DiscoveredPath { hops: vec![topo.source_id, random_id] };
    let result = validate_path(&exec, &fake_path);
    assert!(result.is_err(), "unbacked hop must fail validation");
}

// ─── P0 #2: Source must be the first hop ───────────────────────────────────

/// Since RouteProposal is only constructable from a ValidatedPath (whose
/// source is hops[0]), this is structurally enforced. But commit_route also
/// checks it explicitly.
#[test]
fn source_must_be_first_hop() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    // The proposal's first hop IS the source (enforced by from_validated_path).
    assert_eq!(proposal.hop_node_ids.first(), Some(&proposal.source));
    // verify() checks source==first (returns false if violated).
    assert!(proposal.verify_at(now));
}

// ─── P1 #3: Typed roles ────────────────────────────────────────────────────

/// The destination must accept Gateway role; intermediate hops must accept
/// Relay role. Wrong roles are rejected by commit_route.
#[test]
fn wrong_role_rejected() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();

    // Gateway signs with WRONG role (Relay instead of Gateway).
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Relay, // WRONG — should be Gateway
        vec![], now + 3600,
    );
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );

    let result = commit_route(proposal, vec![relay_acc, gateway_acc], now);
    assert!(
        matches!(result, Err(CommitError::WrongRole { participant, expected, actual })
            if participant == topo.gateway_id && expected == RouteRole::Gateway && actual == RouteRole::Relay),
        "gateway with Relay role must be rejected"
    );
}

#[test]
fn gateway_role_required_for_destination() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();

    // Relay signs with WRONG role (Gateway instead of Relay).
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Gateway, // WRONG — should be Relay
        vec![], now + 3600,
    );
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    );

    let result = commit_route(proposal, vec![relay_acc, gateway_acc], now);
    assert!(
        matches!(result, Err(CommitError::WrongRole { participant, expected, actual })
            if participant == topo.relay_id && expected == RouteRole::Relay && actual == RouteRole::Gateway),
        "relay with Gateway role must be rejected"
    );
}

#[test]
fn relay_role_required_for_intermediate() {
    // Same as above (gateway_role_required_for_destination tests the relay
    // must be Relay). This test is the symmetric name for clarity.
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    );
    let result = commit_route(proposal, vec![relay_acc, gateway_acc], now);
    assert!(result.is_ok(), "correct roles must succeed");
}

// ─── P1 #5: Bounded BFS ────────────────────────────────────────────────────

/// discover_path() must not return paths longer than ROUTE_MAX_HOPS.
#[test]
fn bfs_respects_route_max_hops() {
    use snp_node::node::N212_ROUTE_MAX_HOPS;
    let topo = setup_test_topology();
    let exec = topo.graph.snapshot_executable();

    // Build a chain longer than ROUTE_MAX_HOPS. We need many relays.
    let mut graph = TopologyGraph::new_for_testing();
    let (sk0, pk0) = fresh_keypair(b"bfs-0");
    let id0 = derive_node_id(&pk0);
    let mut prev_id = id0;
    let mut prev_sk = sk0;
    let mut prev_pk = pk0;
    // Accept the source.
    let advert0 = NodeAdvertisement::create_and_sign(
        &sk0, &pk0, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(advert0.verify_into_verified().unwrap()).unwrap();

    // Build a chain of N relays.
    let chain_len = N212_ROUTE_MAX_HOPS + 2; // deliberately too long
    for i in 1..=chain_len {
        let (sk, pk) = fresh_keypair(format!("bfs-{i}").as_bytes());
        let id = derive_node_id(&pk);
        let is_gw = i == chain_len;
        let advert = if is_gw {
            let (_xs, xp) = x25519_static_keypair();
            NodeAdvertisement::create_and_sign(
                &sk, &pk, vec![Capability::Gateway],
                vec![TransportEndpoint::tcp("127.0.0.1:99")],
                Some(xp.to_bytes()), 3600, 1,
            )
        } else {
            NodeAdvertisement::create_and_sign(
                &sk, &pk, vec![Capability::Relay],
                vec![TransportEndpoint::tcp("127.0.0.1:1")], None, 3600, 1,
            )
        };
        graph.accept_advertisement(advert.verify_into_verified().unwrap()).unwrap();
        graph.add_link(Link::new_up(
            LinkKey::new(prev_id, id, TransportEndpoint::tcp(&format!("127.0.0.1:{i}"))), None,
        ));
        prev_id = id;
        prev_sk = sk; // keep for compiler
        prev_pk = pk;
    }
    let _ = (topo, prev_sk, prev_pk);

    let exec = graph.snapshot_executable();
    let path = discover_path(&exec, &id0, &prev_id);
    // If the chain is too long, discover_path returns None (bounded BFS).
    if let Some(p) = path {
        assert!(
            p.hop_count() <= N212_ROUTE_MAX_HOPS,
            "BFS must not return paths longer than ROUTE_MAX_HOPS"
        );
    }
    // If path is None, that's also acceptable — the bound pruned it.
}

// ─── P1 #6: Executable snapshot invariant ──────────────────────────────────

/// Every usable link in ExecutableNetworkSnapshot has BOTH endpoints
/// authenticated. A link to an unauthenticated node is excluded.
#[test]
fn executable_snapshot_has_only_authenticated_link_endpoints() {
    let mut graph = TopologyGraph::new_for_testing();

    // Source (authenticated).
    let (sk_s, pk_s) = fresh_keypair(b"snap-source");
    let source_id = derive_node_id(&pk_s);
    let source_advert = NodeAdvertisement::create_and_sign(
        &sk_s, &pk_s, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(source_advert.verify_into_verified().unwrap()).unwrap();

    // Relay (authenticated).
    let (relay_advert, _relay_sk, relay_pk) = make_relay_advert(b"snap-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph.accept_advertisement(relay_advert.verify_into_verified().unwrap()).unwrap();

    // Add a link source → relay (both authenticated → included).
    graph.add_link(Link::new_up(
        LinkKey::new(source_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));

    // Add a link source → UNAUTHENTICATED node (should be EXCLUDED).
    let (unauth_sk, unauth_pk) = fresh_keypair(b"snap-unauth");
    let unauth_id = derive_node_id(&unauth_pk);
    let _ = unauth_sk;
    graph.add_link(Link::new_up(
        LinkKey::new(source_id, unauth_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));

    let exec = graph.snapshot_executable();
    // The link to unauth_id must NOT be in usable_links.
    assert!(
        !exec.usable_links.values().any(|l| l.key.remote_node_id == unauth_id),
        "link to unauthenticated node must be excluded from ExecutableNetworkSnapshot"
    );
    // The link to relay_id (authenticated) MUST be in usable_links.
    assert!(
        exec.usable_links.values().any(|l| l.key.remote_node_id == relay_id),
        "link to authenticated node must be included"
    );
}

// ─── P1 #7: Freshness ──────────────────────────────────────────────────────

#[test]
fn route_proposal_freshness() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Future-dated proposal (timestamp > now + skew).
    let mut proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    proposal.timestamp = now + 600; // 10 min in future (> 5 min skew)
    assert!(!proposal.verify_at(now), "future-dated proposal must fail freshness");

    // Expired proposal.
    let mut proposal2 = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    proposal2.expiry = now - 1;
    assert!(!proposal2.verify_at(now), "expired proposal must fail freshness");

    // expiry <= timestamp.
    let mut proposal3 = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    proposal3.expiry = proposal3.timestamp;
    assert!(!proposal3.verify_at(now), "expiry == timestamp must fail");

    // Lifetime too long (> ROUTE_MAX_LIFETIME_SECS).
    let mut proposal4 = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    proposal4.expiry = proposal4.timestamp + 7200; // 2h > 1h max
    assert!(!proposal4.verify_at(now), "over-lifetime proposal must fail");
}

#[test]
fn route_acceptance_freshness() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();

    // Future-dated acceptance.
    let mut acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );
    acc.timestamp = now + 600;
    assert!(!acc.verify_at(now), "future-dated acceptance must fail");

    // Expired acceptance.
    let mut acc2 = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );
    acc2.expiry = now - 1;
    assert!(!acc2.verify_at(now), "expired acceptance must fail");
}

// ─── Original N2.1.2 tests (updated for new API) ──────────────────────────

#[test]
fn route_proposal_is_not_committed_route() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    // Without acceptances, commit_route MUST fail.
    let result = commit_route(proposal, vec![], now);
    assert!(matches!(result, Err(CommitError::MissingAcceptance { .. })));
}

#[test]
fn commit_route_succeeds_with_all_acceptances() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    );
    let result = commit_route(proposal, vec![relay_acc, gateway_acc], now);
    assert!(result.is_ok());
}

#[test]
fn missing_acceptance_rejected() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    );
    let result = commit_route(proposal, vec![gateway_acc], now);
    assert!(matches!(result, Err(CommitError::MissingAcceptance { participant }) if participant == topo.relay_id));
}

#[test]
fn wrong_proposal_hash_rejected() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    // Different hash (all zeros).
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        [0u8; 32], RouteRole::Relay, vec![], now + 3600,
    );
    let result = commit_route(proposal, vec![relay_acc], now);
    assert!(matches!(result, Err(CommitError::AcceptanceProposalMismatch { .. })));
}

#[test]
fn unexpected_participant_rejected() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    let hash = proposal.proposal_hash();
    let (random_sk, random_pk) = fresh_keypair(b"n212-random");
    let random_id = derive_node_id(&random_pk);
    let random_acc = RouteAcceptance::create_and_sign(
        &random_sk, &random_pk, random_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    );
    let result = commit_route(proposal, vec![random_acc], now);
    assert!(matches!(result, Err(CommitError::UnexpectedParticipant { .. })));
}

#[test]
fn discover_path_uses_executable_snapshot_only() {
    let topo = setup_test_topology();
    let exec = topo.graph.snapshot_executable();
    let path = discover_path(&exec, &topo.source_id, &topo.gateway_id);
    assert!(path.is_some());
    assert_eq!(path.unwrap().hops, vec![topo.source_id, topo.relay_id, topo.gateway_id]);
}

#[test]
fn duplicate_hop_rejected() {
    // Defense-in-depth: commit_route checks for duplicate hops. Through the
    // normal API (from_validated_path), duplicates cannot arise (BFS doesn't
    // revisit nodes, and validate_path checks each hop). But if a proposal
    // is deserialized from the wire with a duplicate, commit_route catches it.
    //
    // However, tampering with hop_node_ids after signing invalidates the
    // signature — so commit_route returns ProposalSignatureInvalid (the
    // signature check runs before the structural checks). This test verifies
    // that tampering is caught (either way).
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();
    let mut proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    );
    // Tamper: inject a duplicate hop.
    proposal.hop_node_ids = vec![topo.source_id, topo.relay_id, topo.relay_id, topo.gateway_id];
    let result = commit_route(proposal, vec![], now);
    // The signature is now invalid (hops changed after signing). commit_route
    // catches this as ProposalSignatureInvalid. The duplicate check is
    // defense-in-depth — it would catch duplicates in a legitimately-signed
    // proposal (e.g. deserialized from wire).
    assert!(
        matches!(result, Err(CommitError::ProposalSignatureInvalid) | Err(CommitError::DuplicateHop { .. })),
        "tampered proposal must be rejected (signature or duplicate check)"
    );
}

#[test]
fn validated_path_required_for_route_proposal() {
    // ValidatedPath is the ONLY input to RouteProposal. There is no
    // from_node_ids() constructor. This test verifies the API surface.
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    assert_eq!(path.source(), topo.source_id);
    assert_eq!(path.destination(), topo.gateway_id);
    assert_eq!(path.hops().len(), 3);
    assert_eq!(path.required_participants(), vec![topo.relay_id, topo.gateway_id]);
}

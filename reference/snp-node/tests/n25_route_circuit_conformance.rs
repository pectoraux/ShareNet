//! N2.5-T7 — Route/Circuit Conformance Vectors
//!
//! Frozen behavioral conformance vectors for the route/circuit security model.
//! These verify the N2.1.2/N2.1.3/N2.2/N2.3 invariants:
//!
//! 1. RouteProposal ≠ CommittedRoute (proposal requires acceptances)
//! 2. Missing acceptance rejected
//! 3. Wrong role rejected
//! 4. Capability mismatch rejected
//! 5. Duplicate acceptance rejected
//! 6. Acceptance order independence (canonical commitment)
//! 7. Commitment sensitivity (conditions change → commitment changes)
//! 8. CommittedRoute retains hop evidence
//! 9. Proposal freshness/tamper detection

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::*;
use snp_node::node::service::{
    ServiceRequirement, CapabilityOffer, PolicyConstraint, CapacityConstraint,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (_x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()),
        3600, seq,
    );
    (advert, sk, pk)
}

fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None, 3600, seq,
    );
    (advert, sk, pk)
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
    let (source_sk, source_pk) = fresh_keypair(b"n25-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk, &source_pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(source_advert.verify_into_verified().unwrap()).unwrap();

    let (relay_advert, relay_sk, relay_pk) = make_relay_advert(b"n25-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph.accept_advertisement(relay_advert.verify_into_verified().unwrap()).unwrap();

    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n25-gateway", 1);
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

fn build_validated_path(topo: &TestTopology) -> ValidatedPath {
    let exec = topo.graph.snapshot_executable();
    let discovered = discover_path(&exec, &topo.source_id, &topo.gateway_id).unwrap();
    validate_path(&exec, &discovered).unwrap()
}

fn build_proposal_and_path(topo: &TestTopology) -> (RouteProposal, ValidatedPath) {
    let path = build_validated_path(topo);
    let now = now_unix();
    // N2.6: Gateway routes MUST carry a NegotiatedServiceAgreement.
    let negotiated = negotiate_service(
        ServiceRequirement::internet_gateway(),
        CapabilityOffer::internet_gateway(),
        PolicyConstraint::wildcard(),
        CapacityConstraint::default(),
    ).expect("negotiation must succeed for default gateway offer");
    let proposal = RouteProposal::from_validated_path_with_negotiation(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        negotiated,
        now + 3600,
    ).unwrap();
    (proposal, path)
}

fn build_acceptances(topo: &TestTopology, proposal: &RouteProposal) -> Vec<RouteAcceptance> {
    let hash = proposal.proposal_hash().unwrap();
    let now = now_unix();
    vec![
        RouteAcceptance::create_and_sign(
            &topo.relay_sk, &topo.relay_pk, topo.relay_id,
            hash, RouteRole::Relay, vec![], now + 3600,
        ).unwrap(),
        RouteAcceptance::create_and_sign(
            &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
            hash, RouteRole::Gateway, vec![], now + 3600,
        ).unwrap(),
    ]
}

// ─── Vector 1: RouteProposal ≠ CommittedRoute ───────────────────────────────

#[test]
fn conf_proposal_without_acceptances_cannot_commit() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();

    // No acceptances → cannot commit.
    let result = commit_route(proposal, vec![], &path, now);
    assert!(matches!(result, Err(CommitError::MissingAcceptance { .. })),
        "proposal without acceptances must NOT commit");
    eprintln!("[conf-t7-1] PASS: RouteProposal ≠ CommittedRoute (needs acceptances)");
}

// ─── Vector 2: Missing acceptance rejected ──────────────────────────────────

#[test]
fn conf_missing_acceptance_rejected() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let acceptances = build_acceptances(&topo, &proposal);

    // Only provide the gateway acceptance — missing the relay.
    let result = commit_route(proposal, vec![acceptances[1].clone()], &path, now);
    assert!(matches!(result, Err(CommitError::MissingAcceptance { participant }) if participant == topo.relay_id),
        "missing relay acceptance must be rejected");
    eprintln!("[conf-t7-2] PASS: missing acceptance rejected");
}

// ─── Vector 3: Wrong role rejected ───────────────────────────────────────────

#[test]
fn conf_wrong_role_rejected() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let hash = proposal.proposal_hash().unwrap();

    // Gateway signs as Relay (wrong role).
    let gateway_wrong_role = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    ).unwrap();
    let relay_acc = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec![], now + 3600,
    ).unwrap();

    let result = commit_route(proposal, vec![relay_acc, gateway_wrong_role], &path, now);
    assert!(matches!(result, Err(CommitError::WrongRole { .. })),
        "wrong role must be rejected");
    eprintln!("[conf-t7-3] PASS: wrong role rejected");
}

// ─── Vector 4: Capability mismatch rejected ──────────────────────────────────

#[test]
fn conf_capability_mismatch_rejected() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let hash = proposal.proposal_hash().unwrap();

    // Relay tries to sign as Gateway (it only has Relay capability).
    let relay_as_gateway = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    ).unwrap();
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    ).unwrap();

    // But wait — the relay IS in the path as a Relay, and we're giving it
    // a Gateway acceptance. The commit_route checks the ROLE assigned to
    // each participant, not the acceptance role. Let's instead build a
    // topology where a relay-only node is the LAST hop (destination),
    // and try to use it as a gateway.

    // Actually, the capability mismatch is detected when the hop's
    // authenticated capability doesn't match its assigned role. In the
    // standard topology, the relay has Relay capability and is assigned
    // RouteRole::Relay — that matches. The gateway has Gateway capability
    // and is assigned RouteRole::Gateway — that matches.

    // To test capability mismatch, we need a node whose authenticated
    // capabilities don't match its route role. Let's create a second
    // topology where the "gateway" is actually a relay-only node.

    let mut graph2 = TopologyGraph::new_for_testing();
    let (source_sk2, source_pk2) = fresh_keypair(b"n25-cm-source");
    let source_id2 = derive_node_id(&source_pk2);
    let source_advert2 = NodeAdvertisement::create_and_sign(
        &source_sk2, &source_pk2, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph2.accept_advertisement(source_advert2.verify_into_verified().unwrap()).unwrap();

    let (relay2_advert, relay2_sk, relay2_pk) = make_relay_advert(b"n25-cm-relay", 1);
    let relay2_id = derive_node_id(&relay2_pk);
    graph2.accept_advertisement(relay2_advert.verify_into_verified().unwrap()).unwrap();

    // "Gateway" is actually a relay-only node.
    let (relay_only_advert, relay_only_sk, relay_only_pk) = make_relay_advert(b"n25-cm-dest", 1);
    let relay_only_id = derive_node_id(&relay_only_pk);
    graph2.accept_advertisement(relay_only_advert.verify_into_verified().unwrap()).unwrap();

    graph2.add_link(Link::new_up(
        LinkKey::new(source_id2, relay2_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));
    graph2.add_link(Link::new_up(
        LinkKey::new(relay2_id, relay_only_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));

    let exec2 = graph2.snapshot_executable();
    let discovered2 = discover_path(&exec2, &source_id2, &relay_only_id).unwrap();
    let path2 = validate_path(&exec2, &discovered2).unwrap();
    let proposal2 = RouteProposal::from_validated_path(
        &path2, &source_sk2, &source_pk2,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    let hash2 = proposal2.proposal_hash().unwrap();

    // relay2 signs as Relay (correct).
    let relay2_acc = RouteAcceptance::create_and_sign(
        &relay2_sk, &relay2_pk, relay2_id,
        hash2, RouteRole::Relay, vec![], now + 3600,
    ).unwrap();
    // relay_only signs as Gateway (WRONG — it only has Relay capability).
    let relay_only_acc = RouteAcceptance::create_and_sign(
        &relay_only_sk, &relay_only_pk, relay_only_id,
        hash2, RouteRole::Gateway, vec![], now + 3600,
    ).unwrap();

    let result = commit_route(proposal2, vec![relay2_acc, relay_only_acc], &path2, now);
    assert!(matches!(result, Err(CommitError::CapabilityMismatch { participant, role, .. })
        if participant == relay_only_id && role == RouteRole::Gateway),
        "relay-only node signing Gateway role must be rejected with CapabilityMismatch");

    let _ = (topo, proposal, path, hash, relay_as_gateway, gateway_acc);
    eprintln!("[conf-t7-4] PASS: capability mismatch rejected");
}

// ─── Vector 5: Duplicate acceptance rejected ─────────────────────────────────

#[test]
fn conf_duplicate_acceptance_rejected() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let hash = proposal.proposal_hash().unwrap();

    let relay_acc1 = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec!["condition-A".to_string()], now + 3600,
    ).unwrap();
    let relay_acc2 = RouteAcceptance::create_and_sign(
        &topo.relay_sk, &topo.relay_pk, topo.relay_id,
        hash, RouteRole::Relay, vec!["condition-B".to_string()], now + 3600,
    ).unwrap();
    let gateway_acc = RouteAcceptance::create_and_sign(
        &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
        hash, RouteRole::Gateway, vec![], now + 3600,
    ).unwrap();

    let result = commit_route(proposal, vec![relay_acc1, relay_acc2, gateway_acc], &path, now);
    assert!(matches!(result, Err(CommitError::DuplicateAcceptance { participant }) if participant == topo.relay_id),
        "duplicate acceptance must be rejected");
    eprintln!("[conf-t7-5] PASS: duplicate acceptance rejected");
}

// ─── Vector 6: Acceptance order independence ─────────────────────────────────

#[test]
fn conf_acceptance_order_independence() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let acceptances = build_acceptances(&topo, &proposal);
    let relay_acc = &acceptances[0];
    let gateway_acc = &acceptances[1];

    // Commit with [relay, gateway] order.
    let c1 = *commit_route(proposal.clone(), vec![relay_acc.clone(), gateway_acc.clone()], &path, now)
        .unwrap().commitment();

    // Commit with [gateway, relay] order (reversed).
    let c2 = *commit_route(proposal, vec![gateway_acc.clone(), relay_acc.clone()], &path, now)
        .unwrap().commitment();

    assert_eq!(c1, c2, "commitment must be the same regardless of acceptance order");
    eprintln!("[conf-t7-6] PASS: acceptance order independence (canonical commitment)");
}

// ─── Vector 7: Commitment sensitivity ────────────────────────────────────────

#[test]
fn conf_commitment_sensitivity() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let hash = proposal.proposal_hash().unwrap();

    // Acceptances with condition "5Mbps".
    let acc1 = vec![
        RouteAcceptance::create_and_sign(
            &topo.relay_sk, &topo.relay_pk, topo.relay_id,
            hash, RouteRole::Relay, vec!["max-bandwidth:5Mbps".to_string()], now + 3600,
        ).unwrap(),
        RouteAcceptance::create_and_sign(
            &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
            hash, RouteRole::Gateway, vec![], now + 3600,
        ).unwrap(),
    ];

    // Acceptances with condition "10Mbps" (different condition).
    let acc2 = vec![
        RouteAcceptance::create_and_sign(
            &topo.relay_sk, &topo.relay_pk, topo.relay_id,
            hash, RouteRole::Relay, vec!["max-bandwidth:10Mbps".to_string()], now + 3600,
        ).unwrap(),
        RouteAcceptance::create_and_sign(
            &topo.gateway_sk, &topo.gateway_pk, topo.gateway_id,
            hash, RouteRole::Gateway, vec![], now + 3600,
        ).unwrap(),
    ];

    let c1 = *commit_route(proposal.clone(), acc1, &path, now).unwrap().commitment();
    let c2 = *commit_route(proposal, acc2, &path, now).unwrap().commitment();

    assert_ne!(c1, c2, "commitment must change when acceptance conditions change");
    eprintln!("[conf-t7-7] PASS: commitment sensitivity (conditions change → commitment changes)");
}

// ─── Vector 8: CommittedRoute retains hop evidence ───────────────────────────

#[test]
fn conf_committed_route_retains_hop_evidence() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let acceptances = build_acceptances(&topo, &proposal);

    let committed = commit_route(proposal, acceptances, &path, now).unwrap();

    // The committed route has 3 hops: source → relay → gateway.
    assert_eq!(committed.validated_hops().len(), 3);

    // Each hop has an AuthenticatedNodeRecord (evidence).
    assert!(committed.hop_record(0).is_some(), "source hop has record");
    assert!(committed.hop_record(1).is_some(), "relay hop has record");
    assert!(committed.hop_record(2).is_some(), "gateway hop has record");

    // The relay hop record matches the relay's NodeId.
    assert_eq!(committed.hop_record(1).unwrap().node_id(), topo.relay_id);
    // The gateway hop record matches the gateway's NodeId.
    assert_eq!(committed.hop_record(2).unwrap().node_id(), topo.gateway_id);

    // The commitment hash is 32 bytes (SHA-256).
    assert_eq!(committed.commitment().len(), 32);

    // The committed_at timestamp is set.
    assert_eq!(committed.committed_at(), now);
    eprintln!("[conf-t7-8] PASS: CommittedRoute retains hop evidence");
}

// ─── Vector 9: Proposal freshness / tamper detection ────────────────────────

#[test]
fn conf_proposal_tamper_detected() {
    let topo = setup_test_topology();
    let (mut proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();

    // Original proposal verifies.
    assert!(proposal.verify_at(now), "original proposal must verify");

    // Tamper with the timestamp → verification fails.
    proposal.timestamp = now + 600; // Future timestamp beyond clock skew
    assert!(!proposal.verify_at(now), "tampered proposal must NOT verify");

    eprintln!("[conf-t7-9] PASS: proposal tamper detected");
}

// ─── Vector 10: Full happy path commits ──────────────────────────────────────

#[test]
fn conf_full_happy_path_commits() {
    let topo = setup_test_topology();
    let (proposal, path) = build_proposal_and_path(&topo);
    let now = now_unix();
    let acceptances = build_acceptances(&topo, &proposal);

    let committed = commit_route(proposal, acceptances, &path, now);

    assert!(committed.is_ok(), "full happy path must commit: {:?}", committed.err());
    let committed = committed.unwrap();

    // Verify the committed route's structure.
    assert_eq!(committed.source(), topo.source_id);
    assert_eq!(committed.destination(), topo.gateway_id);
    assert_eq!(committed.hops().len(), 3);
    assert!(!committed.is_expired(now));
    eprintln!("[conf-t7-10] PASS: full happy path (source→relay→gateway) commits successfully");
}

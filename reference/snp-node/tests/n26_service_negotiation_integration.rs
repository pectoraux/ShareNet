//! N2.6 — Service Negotiation Integration Tests
//!
//! Tests proving that a route to an InternetGateway destination CANNOT be
//! committed without a valid NegotiatedServiceAgreement.
//!
//! The key invariant:
//!   "A route cannot be committed merely because the destination advertises
//!    Gateway — the requested service must be permitted and supported."
//!
//! This is enforced by `commit_route()` which checks `proposal.negotiated_service`
//! when the destination has `RouteRole::Gateway`.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::*;
use snp_node::node::capability::ProtocolCapability;
use snp_node::node::service::{
    ServiceRequirement, CapabilityOffer, PolicyConstraint, CapacityConstraint,
    NegotiatedServiceAgreement,
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
    let (source_sk, source_pk) = fresh_keypair(b"n26-source");
    let source_id = derive_node_id(&source_pk);
    let source_advert = NodeAdvertisement::create_and_sign(
        &source_sk, &source_pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:0")], None, 3600, 1,
    );
    graph.accept_advertisement(source_advert.verify_into_verified().unwrap()).unwrap();

    let (relay_advert, relay_sk, relay_pk) = make_relay_advert(b"n26-relay", 1);
    let relay_id = derive_node_id(&relay_pk);
    graph.accept_advertisement(relay_advert.verify_into_verified().unwrap()).unwrap();

    let (gw_advert, gw_sk, gw_pk) = make_gateway_advert(b"n26-gateway", 1);
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

// ─── N2.6: Gateway route WITHOUT negotiation is rejected ────────────────────

#[test]
fn n26_gateway_route_without_negotiation_rejected() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Build a proposal WITHOUT negotiation (legacy from_validated_path).
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    let acceptances = build_acceptances(&topo, &proposal);

    // commit_route MUST reject — gateway route without negotiation.
    let result = commit_route(proposal, acceptances, &path, now);
    assert!(matches!(result, Err(CommitError::ServiceNegotiationRequired { destination }) if destination == topo.gateway_id),
        "gateway route without NegotiatedServiceAgreement must be rejected with ServiceNegotiationRequired");
    eprintln!("[n26-1] PASS: gateway route without negotiation rejected with ServiceNegotiationRequired");
}

// ─── N2.6: Gateway route WITH negotiation commits successfully ──────────────

#[test]
fn n26_gateway_route_with_negotiation_commits() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Negotiate service.
    let negotiated = negotiate_service(
        ServiceRequirement::internet_gateway(),
        CapabilityOffer::internet_gateway(),
        PolicyConstraint::wildcard(),
        CapacityConstraint::default(),
    ).expect("negotiation must succeed");

    // Build a proposal WITH negotiation.
    let proposal = RouteProposal::from_validated_path_with_negotiation(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        negotiated,
        now + 3600,
    ).unwrap();
    let acceptances = build_acceptances(&topo, &proposal);

    // commit_route MUST succeed.
    let result = commit_route(proposal, acceptances, &path, now);
    assert!(result.is_ok(), "gateway route with valid negotiation must commit: {:?}", result.err());
    eprintln!("[n26-2] PASS: gateway route with negotiation commits successfully");
}

// ─── N2.6: Route with FAILED negotiation (policy blocks destination) ───────

#[test]
fn n26_route_with_blocked_destination_negotiation_fails() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Requirement: needs "tor" protocol.
    let req = ServiceRequirement {
        capability: ProtocolCapability::InternetGateway,
        required_destinations: vec![],
        required_protocols: vec!["tor".to_string()],
        min_bandwidth_bps: None,
        max_latency_ms: None,
    };
    // Policy: only allows "https" + "dns" (blocks "tor").
    let policy = PolicyConstraint {
        allowed_destinations: vec![],
        allowed_protocols: vec!["https".to_string(), "dns".to_string()],
        charging_only: false,
        wifi_only: false,
    };

    // Negotiation must FAIL — tor is not allowed by policy.
    let negotiation_result = negotiate_service(
        req,
        CapabilityOffer::internet_gateway(),
        policy,
        CapacityConstraint::default(),
    );
    assert!(negotiation_result.is_none(),
        "negotiation must fail when the required protocol is blocked by policy");

    // Since negotiation failed, we CANNOT build a proposal with negotiation.
    // If someone tries to commit without negotiation, it's rejected.
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    let acceptances = build_acceptances(&topo, &proposal);
    let result = commit_route(proposal, acceptances, &path, now);
    assert!(matches!(result, Err(CommitError::ServiceNegotiationRequired { .. })),
        "route without negotiation (because negotiation failed) must be rejected");
    eprintln!("[n26-3] PASS: route with blocked destination — negotiation fails, commit rejected");
}

// ─── N2.6: Route with FAILED negotiation (insufficient bandwidth) ──────────

#[test]
fn n26_route_with_insufficient_bandwidth_negotiation_fails() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Requirement: needs 10 Mbps.
    let req = ServiceRequirement {
        capability: ProtocolCapability::InternetGateway,
        required_destinations: vec![],
        required_protocols: vec![],
        min_bandwidth_bps: Some(10_000_000), // 10 Mbps
        max_latency_ms: None,
    };
    // Capacity: only 1 Mbps available.
    let capacity = CapacityConstraint::new(100, Some(1_000_000), 0, None, None);

    // Negotiation must FAIL — bandwidth insufficient.
    let negotiation_result = negotiate_service(
        req,
        CapabilityOffer::internet_gateway(),
        PolicyConstraint::wildcard(),
        capacity,
    );
    assert!(negotiation_result.is_none(),
        "negotiation must fail when bandwidth is insufficient");
    eprintln!("[n26-4] PASS: route with insufficient bandwidth — negotiation fails");
}

// ─── N2.6: Non-gateway route does NOT require negotiation ───────────────────
//
// Note: In the current route discovery model, the LAST hop (destination) is
// always assigned RouteRole::Gateway. A relay-only destination triggers
// CapabilityMismatch before the negotiation check. This test verifies that
// a route whose destination is a Gateway (but the service type is NOT
// "internet-transit") still requires negotiation — because the enforcement
// is based on RouteRole::Gateway, not on service type.
//
// The N2.6 enforcement is: if the last hop has RouteRole::Gateway, the
// proposal MUST carry a NegotiatedServiceAgreement. There is currently no
// way to build a route to a non-gateway destination (the path discovery
// always assigns RouteRole::Gateway to the last hop).

#[test]
fn n26_gateway_route_always_requires_negotiation() {
    // This test documents the current behavior: any route whose last hop
    // has RouteRole::Gateway requires a NegotiatedServiceAgreement, regardless
    // of the service type string.
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Build with a non-internet-transit service type, no negotiation.
    let proposal = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("content-seed".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    let acceptances = build_acceptances(&topo, &proposal);

    // Still rejected — the destination is a Gateway, so negotiation is required.
    let result = commit_route(proposal, acceptances, &path, now);
    assert!(matches!(result, Err(CommitError::ServiceNegotiationRequired { .. })),
        "any route to a Gateway destination requires negotiation, regardless of service type");
    eprintln!("[n26-5] PASS: gateway destination always requires negotiation (regardless of service type)");
}

// ─── N2.6: has_negotiated_service() helper ─────────────────────────────────

#[test]
fn n26_has_negotiated_service_helper() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Without negotiation.
    let proposal_no_neg = RouteProposal::from_validated_path(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        now + 3600,
    ).unwrap();
    assert!(!proposal_no_neg.has_negotiated_service(),
        "proposal built without negotiation must report has_negotiated_service() == false");

    // With negotiation.
    let negotiated = NegotiatedServiceAgreement::negotiate(
        ServiceRequirement::internet_gateway(),
        CapabilityOffer::internet_gateway(),
        PolicyConstraint::wildcard(),
        CapacityConstraint::default(),
    ).unwrap();
    let proposal_with_neg = RouteProposal::from_validated_path_with_negotiation(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        negotiated,
        now + 3600,
    ).unwrap();
    assert!(proposal_with_neg.has_negotiated_service(),
        "proposal built with negotiation must report has_negotiated_service() == true");
    eprintln!("[n26-6] PASS: has_negotiated_service() helper works correctly");
}

// ─── N2.6: Full negotiation → proposal → commit pipeline ───────────────────

#[test]
fn n26_full_negotiation_to_commit_pipeline() {
    let topo = setup_test_topology();
    let path = build_validated_path(&topo);
    let now = now_unix();

    // Step 1: Client defines what it needs.
    let requirement = ServiceRequirement::internet_gateway();

    // Step 2: Gateway offers InternetGateway transit.
    let offer = CapabilityOffer::internet_gateway();

    // Step 3: Gateway policy allows HTTPS.
    let policy = PolicyConstraint {
        allowed_destinations: vec!["*:443".to_string()],
        allowed_protocols: vec!["https".to_string()],
        charging_only: false,
        wifi_only: false,
    };

    // Step 4: Gateway reports capacity.
    let capacity = CapacityConstraint::new(100, Some(10_000_000), 0, None, None);

    // Step 5: Negotiate — requirement must be satisfied.
    let negotiated = negotiate_service(requirement, offer, policy, capacity)
        .expect("negotiation must succeed — requirement matches offer + policy + capacity");

    // Step 6: Build proposal with negotiation.
    let proposal = RouteProposal::from_validated_path_with_negotiation(
        &path, &topo.source_sk, &topo.source_pk,
        ServiceAgreement::new("internet-transit".to_string(), vec![]),
        negotiated,
        now + 3600,
    ).unwrap();

    // Step 7: Get acceptances.
    let acceptances = build_acceptances(&topo, &proposal);

    // Step 8: Commit — must succeed.
    let committed = commit_route(proposal, acceptances, &path, now)
        .expect("full pipeline must produce a CommittedRoute");

    // Verify the committed route.
    assert_eq!(committed.source(), topo.source_id);
    assert_eq!(committed.destination(), topo.gateway_id);
    assert!(!committed.is_expired(now));
    eprintln!("[n26-7] PASS: full negotiation → proposal → commit pipeline works end-to-end");
}

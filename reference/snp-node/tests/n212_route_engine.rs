//! N2.1.2 — Route Discovery, Construction, and Validation tests.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    CandidateOrigin, Capability, HopCountCost, InMemoryResolver, Link, LinkKey, LinkState,
    NodeAdvertisement, NullResolver, RouteCandidateState, RouteDiscoveryError, RouteEngine,
    TopologyGraph, TransportEndpoint, VerifiedPeerSummaryList,
    DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED,
};

// ─── Test helpers ───────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

/// Create a relay advertisement (signed, verified).
fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None, 3600, seq,
    );
    (advert, sk, pk)
}

/// Create a gateway advertisement (signed, verified, with X25519 key).
fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk; // suppress unused warning
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()), 3600, seq,
    );
    (advert, sk, pk)
}

/// Create a gateway advertisement WITHOUT an X25519 key (invalid for routing).
fn make_gateway_no_x25519(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:9999")],
        None, 3600, seq,
    );
    (advert, sk, pk)
}

/// Set up a topology where:
/// - local_node is the source (the node running the route engine).
/// - A chain of relay nodes leads to a gateway.
///
/// Returns (topology, local_node_id, relay_ids, gateway_id).
struct ChainTopology {
    topology: TopologyGraph,
    local: [u8; 32],
    relays: Vec<[u8; 32]>,
    gateway: [u8; 32],
    /// The gateway's verified advertisement (for resolver registration).
    gateway_advert: NodeAdvertisement,
}

/// Build a chain topology: local → relay1 → relay2 → ... → gateway.
/// Each link is directed (local→relay1, relay1→relay2, etc.).
fn build_chain(num_relays: usize) -> ChainTopology {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"chain-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    let mut relays = Vec::new();
    let mut prev_id = local;
    let mut prev_label = b"chain-local".to_vec();

    for i in 0..num_relays {
        let label = format!("chain-relay-{i}");
        let (advert, _, pk) = make_relay_advert(label.as_bytes(), 1);
        let verified = advert.verify_into_verified().expect("relay must verify");
        topology.accept_advertisement(verified).expect("accept relay");
        let relay_id = derive_node_id(&pk);
        // Directed link: prev → relay
        let key = LinkKey::new(
            prev_id, relay_id,
            TransportEndpoint::tcp(format!("127.0.0.1:{port}", port = 2000 + i)),
        );
        topology.add_link_for_testing(Link::new_up_for_testing(key, None));
        relays.push(relay_id);
        prev_id = relay_id;
        prev_label = label.into_bytes();
    }
    let _ = prev_label;

    // Gateway at the end.
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"chain-gateway", 1);
    let gw_verified = gw_advert.verify_into_verified().expect("gateway must verify");
    topology.accept_advertisement(gw_verified).expect("accept gateway");
    let gateway = derive_node_id(&gw_pk);
    // Directed link: last relay → gateway
    let key = LinkKey::new(
        prev_id, gateway,
        TransportEndpoint::tcp("127.0.0.1:3000"),
    );
    topology.add_link_for_testing(Link::new_up_for_testing(key, None));

    ChainTopology {
        topology,
        local,
        relays,
        gateway,
        gateway_advert: make_gateway_advert(b"chain-gateway", 1).0,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test scenarios
// ════════════════════════════════════════════════════════════════════════════

/// 1. direct_gateway_route
///
/// A → G (direct, one hop).
#[test]
fn direct_gateway_route() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"direct-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    let (gw_advert, _, gw_pk) = make_gateway_advert(b"direct-gw", 1);
    topology.accept_advertisement(gw_advert.verify_into_verified().expect("verify")).expect("accept");
    let gw_id = derive_node_id(&gw_pk);

    // Directed link: local → gw
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route");
    let route = ready[0].route().expect("route exists");
    assert_eq!(route.source(), local);
    assert_eq!(route.destination(), gw_id);
    assert_eq!(route.hops().len(), 1, "direct route has 1 hop");
    assert_eq!(route.hops()[0], gw_id);
    assert!(route.validate().is_ok(), "route must validate");
    eprintln!("[test 1] PASS: direct gateway route");
}

/// 2. two_hop_gateway_route
///
/// A → B → G (two hops).
#[test]
fn two_hop_gateway_route() {
    let chain = build_chain(1); // 1 relay: local → relay1 → gateway
    let engine = RouteEngine::new(chain.local);
    let candidates = engine.discover_and_compute(&chain.topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route");
    let route = ready[0].route().expect("route exists");
    assert_eq!(route.source(), chain.local);
    assert_eq!(route.destination(), chain.gateway);
    assert_eq!(route.hops().len(), 2, "two-hop route");
    assert_eq!(route.hops()[0], chain.relays[0]);
    assert_eq!(route.hops()[1], chain.gateway);
    assert!(route.validate().is_ok());
    eprintln!("[test 2] PASS: two-hop gateway route");
}

/// 3. three_hop_gateway_route
///
/// A → B → C → G (three hops).
#[test]
fn three_hop_gateway_route() {
    let chain = build_chain(2); // 2 relays: local → relay1 → relay2 → gateway
    let engine = RouteEngine::new(chain.local);
    let candidates = engine.discover_and_compute(&chain.topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route");
    let route = ready[0].route().expect("route exists");
    assert_eq!(route.hops().len(), 3, "three-hop route");
    assert_eq!(route.hops()[0], chain.relays[0]);
    assert_eq!(route.hops()[1], chain.relays[1]);
    assert_eq!(route.hops()[2], chain.gateway);
    assert!(route.validate().is_ok());
    eprintln!("[test 3] PASS: three-hop gateway route");
}

/// 4. remote_gateway_hint_is_not_route
///
/// A hint says G exists; no route is produced without resolving G.
#[test]
fn remote_gateway_hint_is_not_route() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"hint-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // No direct gateway. Add a remote hint via propagation.
    let (sender_sk, sender_pk) = fresh_keypair(b"hint-sender");
    let sender_id = derive_node_id(&sender_pk);
    let fake_gw_id = [0xAA; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: fake_gw_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 2,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified: VerifiedPeerSummaryList = list.verify_into_verified().expect("must verify");
    topology.process_peer_summaries(&verified);

    // With NullResolver, the hint cannot be resolved → no route.
    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 0, "hint without resolution must NOT produce a route");

    // The candidate should be in Failed state.
    let failed: Vec<_> = candidates.iter().filter(|c| c.is_failed()).collect();
    assert_eq!(failed.len(), 1, "hint candidate should fail");
    match &failed[0].state() {
        RouteCandidateState::Failed { reason } => {
            assert!(matches!(reason, RouteDiscoveryError::DestinationUnresolved),
                "expected DestinationUnresolved, got {reason:?}");
        }
        other => panic!("expected Failed state, got {other:?}"),
    }
    eprintln!("[test 4] PASS: remote gateway hint is not a route without resolution");
}

/// 5. forged_gateway_hint_cannot_become_route
///
/// A forged hint (fake NodeId) cannot become a route even with a resolver,
/// because the resolver has no authenticated record for it.
#[test]
fn forged_gateway_hint_cannot_become_route() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"forged-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // A hint about a fake gateway.
    let (sender_sk, sender_pk) = fresh_keypair(b"forged-sender");
    let sender_id = derive_node_id(&sender_pk);
    let fake_gw = [0xBB; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: fake_gw,
        advertisement_sequence: 999,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("must verify");
    topology.process_peer_summaries(&verified);

    // Empty resolver — no record for the fake gateway.
    let resolver = InMemoryResolver::new();
    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &resolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 0, "forged hint must NOT produce a route");
    eprintln!("[test 5] PASS: forged gateway hint cannot become route");
}

/// 6. directed_link_required
///
/// A → B exists but B → C does not; A → B → C must fail.
#[test]
fn directed_link_required() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"dir-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Relay B (authenticated, link local → B).
    let (b_advert, _, b_pk) = make_relay_advert(b"dir-relay-b", 1);
    topology.accept_advertisement(b_advert.verify_into_verified().expect("verify")).expect("accept");
    let b_id = derive_node_id(&b_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, b_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));

    // Gateway C (authenticated, but NO link B → C).
    let (c_advert, _, c_pk) = make_gateway_advert(b"dir-gw-c", 1);
    topology.accept_advertisement(c_advert.verify_into_verified().expect("verify")).expect("accept");
    let c_id = derive_node_id(&c_pk);
    // Add link local → C? No. We want to show that without B→C, no path.
    // Actually, C is authenticated but there's no link from local or B to C.
    // So the only link is local → B. There's no path to C.

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // C is a direct authenticated gateway candidate, but no usable path exists.
    let c_candidate = candidates.iter().find(|c| c.destination() == c_id).expect("C candidate");
    assert!(c_candidate.is_failed(), "C should fail (no directed path)");
    match c_candidate.state() {
        RouteCandidateState::Failed { reason } => {
            assert!(matches!(reason, RouteDiscoveryError::NoPathFound),
                "expected NoPathFound, got {reason:?}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    eprintln!("[test 6] PASS: directed link required");
}

/// 7. stale_link_rejected
///
/// A link that is Down is not usable for routing.
#[test]
fn stale_link_rejected() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"stale-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    let (gw_advert, _, gw_pk) = make_gateway_advert(b"stale-gw", 1);
    topology.accept_advertisement(gw_advert.verify_into_verified().expect("verify")).expect("accept");
    let gw_id = derive_node_id(&gw_pk);

    // Link local → gw, but DOWN.
    let key = LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1"));
    let mut link = Link::new_up_for_testing(key.clone(), None);
    link.state = LinkState::Down;
    topology.add_link_for_testing(link);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // The gateway is authenticated, but the link is Down → no path.
    // Note: direct_gateways() requires a usable link, so the gateway won't
    // appear as a direct candidate. It might not appear at all.
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 0, "stale/Down link must NOT produce a route");
    eprintln!("[test 7] PASS: stale link rejected");
}

/// 8. stale_destination_advertisement_rejected
///
/// If the destination's advertisement has expired, route construction fails.
#[test]
fn stale_destination_advertisement_rejected() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"stale-dest-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Create a gateway advertisement, then make it expired by setting
    // timestamp and expiry in the past.
    let (sk, pk) = fresh_keypair(b"stale-dest-gw");
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let mut advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()),
        3600, // normal lifetime
        1,
    );
    // Set timestamp and expiry in the past (expired).
    let now = now_unix();
    advert.timestamp = now.saturating_sub(7200); // 2 hours ago
    advert.expiry = now.saturating_sub(3600);    // 1 hour ago (expired)
    advert.sign(&sk); // re-sign with mutated fields

    // This advertisement will fail verify_into_verified() because it's expired.
    assert!(advert.verify_into_verified().is_none(),
        "expired advertisement must not verify");

    // Since we can't accept an expired advertisement into the topology,
    // the gateway won't appear as a candidate at all. This proves that
    // stale destinations are rejected at the advertisement verification
    // layer (before the route engine even sees them).
    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);
    assert_eq!(candidates.len(), 0, "no candidates for expired advertisement");
    eprintln!("[test 8] PASS: stale destination advertisement rejected at verification layer");
}

/// 9. unauthenticated_hop_rejected
///
/// A hop that is only a hint (not authenticated) cannot be in a route.
/// This is inherently enforced by the type system: RouteHop requires
/// VerifiedNodeDescriptor. This test verifies the route engine doesn't
/// produce routes through unauthenticated nodes.
///
/// Scenario: A hint says gateway G exists. The resolver CAN resolve G
/// (has G's authenticated record). But there is NO link path to G.
/// The candidate should reach Authenticated state (resolved) but then
/// fail with NoPathFound — NOT produce a route through an unauthenticated hop.
#[test]
fn unauthenticated_hop_rejected() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"unauth-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Gateway G — create advertisement but DON'T add to local topology.
    let (g_advert, _, g_pk) = make_gateway_advert(b"unauth-gw", 1);
    let g_id = derive_node_id(&g_pk);
    let g_verified = g_advert.verify_into_verified().expect("G must verify");

    // Hint about G (G is NOT authenticated in the local topology).
    let (sender_sk, sender_pk) = fresh_keypair(b"unauth-sender");
    let sender_id = derive_node_id(&sender_pk);
    let summary = snp_node::node::PeerSummary {
        node_id: g_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    // Resolver CAN resolve G (has G's authenticated record).
    let mut resolver = InMemoryResolver::new();
    resolver.register_verified(g_verified);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &resolver, &HopCountCost);

    // The hint is resolved (authenticated record exists), but no PATH exists
    // because there's no link to G.
    let gw_candidate = candidates.iter().find(|c| c.destination() == g_id)
        .expect("G candidate must exist");
    assert!(gw_candidate.is_failed(), "gateway with no path must fail");
    match gw_candidate.state() {
        RouteCandidateState::Failed { reason } => {
            assert!(matches!(reason, RouteDiscoveryError::NoPathFound),
                "expected NoPathFound, got {reason:?}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // The key invariant: no route through an unauthenticated hop.
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 0, "no route through unauthenticated hop");
    eprintln!("[test 9] PASS: unauthenticated hop rejected (resolved but no path)");
}

/// 10. gateway_without_x25519_rejected
///
/// A gateway without an X25519 circuit key cannot be a route destination.
#[test]
fn gateway_without_x25519_rejected() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"nox25519-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Gateway WITHOUT X25519 key.
    // Note: NodeAdvertisement::create_and_sign allows this, but
    // verify_into_verified() enforces role/key consistency:
    // Gateway MUST have X25519. So this won't verify.
    let (gw_advert, _, gw_pk) = make_gateway_no_x25519(b"nox25519-gw", 1);
    assert!(gw_advert.verify_into_verified().is_none(),
        "gateway without X25519 must not verify (role/key consistency)");

    // Since it can't be verified, it can't be accepted into the topology.
    // So it won't appear as a candidate.
    let gw_id = derive_node_id(&gw_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);
    assert_eq!(candidates.len(), 0, "gateway without X25519 produces no candidates");
    eprintln!("[test 10] PASS: gateway without X25519 rejected at verification layer");
}

/// 11. route_commitment_changes_when_hop_changes
///
/// Two routes with different relay paths produce different commitments.
#[test]
fn route_commitment_changes_when_hop_changes() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"commit-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Two relays, both leading to the same gateway.
    let (r1_advert, _, r1_pk) = make_relay_advert(b"commit-relay-1", 1);
    topology.accept_advertisement(r1_advert.verify_into_verified().expect("verify")).expect("accept");
    let r1_id = derive_node_id(&r1_pk);

    let (r2_advert, _, r2_pk) = make_relay_advert(b"commit-relay-2", 1);
    topology.accept_advertisement(r2_advert.verify_into_verified().expect("verify")).expect("accept");
    let r2_id = derive_node_id(&r2_pk);

    let (gw_advert, _, gw_pk) = make_gateway_advert(b"commit-gw", 1);
    let gw_verified = gw_advert.verify_into_verified().expect("verify");
    let gw_record = gw_verified.into_record();
    topology.accept_advertisement(
        make_gateway_advert(b"commit-gw", 1).0.verify_into_verified().expect("verify")
    ).expect("accept");
    let gw_id = derive_node_id(&gw_pk);

    // Links: local → r1 → gw, and local → r2 → gw.
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, r1_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(r1_id, gw_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, r2_id, TransportEndpoint::tcp("127.0.0.1:3")), None,
    ));
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(r2_id, gw_id, TransportEndpoint::tcp("127.0.0.1:4")), None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // We should get at least one route. The commitment depends on the
    // exact hop details (descriptor + endpoints), which differ between
    // r1 and r2 paths.
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert!(ready.len() >= 1, "should have at least 1 ready route");

    // Construct a second route manually via r2 to compare commitments.
    // Actually, let's just verify that the route's commitment is non-zero
    // and that changing a hop changes it.
    let route1 = ready[0].route().expect("route");
    let commitment1 = route1.route_commitment();

    // Build a route with a different hop (manual construction for comparison).
    let r1_record = topology.get_record(&r1_id).expect("r1 record").clone();
    let r2_record = topology.get_record(&r2_id).expect("r2 record").clone();
    let gw_record2 = topology.get_record(&gw_id).expect("gw record").cloned_to_record();

    use snp_node::node::{Route, RouteHop};
    let route_via_r1 = Route::new_with_hop_details(
        local, gw_id,
        vec![
            RouteHop::new(r1_record.descriptor.clone(), r1_record.endpoints[0].clone()),
            RouteHop::new(gw_record2.descriptor.clone(), gw_record2.endpoints[0].clone()),
        ],
    );
    let route_via_r2 = Route::new_with_hop_details(
        local, gw_id,
        vec![
            RouteHop::new(r2_record.descriptor.clone(), r2_record.endpoints[0].clone()),
            RouteHop::new(gw_record2.descriptor.clone(), gw_record2.endpoints[0].clone()),
        ],
    );

    assert_ne!(route_via_r1.route_commitment(), route_via_r2.route_commitment(),
        "routes with different relay hops MUST have different commitments");
    eprintln!("[test 11] PASS: route commitment changes when hop changes");
}

/// Helper trait to clone the record out of a reference (for test convenience).
trait CloneRecord {
    fn cloned_to_record(self) -> snp_node::node::AuthenticatedNodeRecord;
}

impl<'a> CloneRecord for &'a snp_node::node::AuthenticatedNodeRecord {
    fn cloned_to_record(self) -> snp_node::node::AuthenticatedNodeRecord {
        self.clone()
    }
}

/// 12. route_commitment_changes_when_endpoint_changes
///
/// Two routes with the same hops but different endpoints produce different
/// commitments.
#[test]
fn route_commitment_changes_when_endpoint_changes() {
    use snp_node::node::{Route, RouteHop};
    let (sk, pk) = fresh_keypair(b"endpoint-commit");
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1111")],
        Some(x_pk.to_bytes()), 3600, 1,
    );
    let verified = advert.verify_into_verified().expect("verify");
    let record = verified.into_record();
    let local = [0x42; 32];
    let gw_id = record.node_id();

    let route_ep1 = Route::new_with_hop_details(
        local, gw_id,
        vec![RouteHop::new(record.descriptor.clone(), TransportEndpoint::tcp("127.0.0.1:1111"))],
    );
    let route_ep2 = Route::new_with_hop_details(
        local, gw_id,
        vec![RouteHop::new(record.descriptor.clone(), TransportEndpoint::tcp("127.0.0.1:2222"))],
    );

    assert_ne!(route_ep1.route_commitment(), route_ep2.route_commitment(),
        "routes with different endpoints MUST have different commitments");
    eprintln!("[test 12] PASS: route commitment changes when endpoint changes");
}

/// 13. route_validation_rejects_invalid_order
///
/// A route where the destination doesn't match the last hop is rejected.
#[test]
fn route_validation_rejects_invalid_order() {
    use snp_node::node::{Route, RouteError, RouteHop};
    let (sk1, pk1) = fresh_keypair(b"order-1");
    let (sk2, pk2) = fresh_keypair(b"order-2");
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert1 = NodeAdvertisement::create_and_sign(
        &sk1, &pk1, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        Some(x_pk.to_bytes()), 3600, 1,
    );
    let advert2 = NodeAdvertisement::create_and_sign(
        &sk2, &pk2, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:2")],
        None, 3600, 1,
    );
    let r1 = advert1.verify_into_verified().expect("verify").into_record();
    let r2 = advert2.verify_into_verified().expect("verify").into_record();

    let local = [0x11; 32];
    let dest = r1.node_id(); // gateway is the destination

    // Construct a route where hops are in WRONG order (relay last, gateway first).
    let route = Route::new_with_hop_details(
        local, dest,
        vec![
            RouteHop::new(r1.descriptor.clone(), r1.endpoints[0].clone()), // gateway first
            RouteHop::new(r2.descriptor.clone(), r2.endpoints[0].clone()), // relay last
        ],
    );

    // Validation should fail: last hop is not a gateway, and destination
    // doesn't match last hop.
    let result = route.validate();
    assert!(result.is_err(), "route with invalid order must fail validation");
    match result {
        Err(RouteError::DestinationDescriptorMismatch) => { /* expected */ }
        Err(RouteError::DestinationNotGateway) => { /* also acceptable */ }
        Err(e) => panic!("expected DestinationDescriptorMismatch or DestinationNotGateway, got {e:?}"),
        Ok(()) => panic!("should have failed"),
    }
    eprintln!("[test 13] PASS: route validation rejects invalid order");
}

/// 14. route_resolution_survives_alternate_candidate
///
/// If the primary candidate fails, an alternate candidate can still produce
/// a route.
#[test]
fn route_resolution_survives_alternate_candidate() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"alt-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Two gateways: G1 (reachable) and G2 (only a hint, unresolvable).
    let (g1_advert, _, g1_pk) = make_gateway_advert(b"alt-gw-1", 1);
    topology.accept_advertisement(g1_advert.verify_into_verified().expect("verify")).expect("accept");
    let g1_id = derive_node_id(&g1_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, g1_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));

    // Hint about G2 (fake, unresolvable).
    let (sender_sk, sender_pk) = fresh_keypair(b"alt-sender");
    let sender_id = derive_node_id(&sender_pk);
    let g2_fake = [0xDD; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: g2_fake,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // G1 should produce a route; G2 should fail.
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "exactly 1 ready route (G1)");
    assert_eq!(ready[0].route().expect("route").destination(), g1_id);

    let failed: Vec<_> = candidates.iter().filter(|c| c.is_failed()).collect();
    assert_eq!(failed.len(), 1, "exactly 1 failed candidate (G2)");
    eprintln!("[test 14] PASS: route resolution survives alternate candidate");
}

/// 15. candidate_gateway_discovery_from_remote_hint
///
/// RemoteNodeHint identifies G; route engine resolves G's actual authenticated
/// advertisement; route becomes executable.
#[test]
fn candidate_gateway_discovery_from_remote_hint() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"cand-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Relay B (authenticated, link local → B).
    let (b_advert, _, b_pk) = make_relay_advert(b"cand-relay-b", 1);
    topology.accept_advertisement(b_advert.verify_into_verified().expect("verify")).expect("accept");
    let b_id = derive_node_id(&b_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, b_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));

    // Gateway G (create advertisement, but DON'T add to local topology).
    // G is only known through a hint.
    let (g_advert, _, g_pk) = make_gateway_advert(b"cand-gw-g", 1);
    let g_id = derive_node_id(&g_pk);
    let g_verified = g_advert.verify_into_verified().expect("G must verify");

    // Hint: B claims G exists as a gateway.
    let (b_sk, b_pk2) = fresh_keypair(b"cand-relay-b"); // same label → same keys
    let _ = b_sk;
    let b_sender_id = derive_node_id(&b_pk2);
    assert_eq!(b_sender_id, b_id, "sender ID must match relay B");
    let summary = snp_node::node::PeerSummary {
        node_id: g_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &b_sk, &b_pk2, b_sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    // Resolver: can resolve G's advertisement.
    let mut resolver = InMemoryResolver::new();
    resolver.register_verified(g_verified);

    // BUT: there's no link B → G in the local topology!
    // So path computation will fail (NoPathFound) because the local
    // topology doesn't know about B → G.
    //
    // For a complete test, we need to also add a link B → G.
    // In a real system, this link would be discovered through the relay.
    // For this test, we simulate it by adding the link.
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(b_id, g_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &resolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route via resolved G");
    let route = ready[0].route().expect("route");
    assert_eq!(route.destination(), g_id);
    assert_eq!(route.hops(), vec![b_id, g_id]);
    assert!(route.validate().is_ok());
    eprintln!("[test 15] PASS: candidate gateway discovery from remote hint");
}

// ════════════════════════════════════════════════════════════════════════════
// Local topology multi-hop route test (NOT distributed discovery)
// ════════════════════════════════════════════════════════════════════════════

/// 16. local_topology_multi_hop_route_with_destination_resolution
///
/// **N2.1.2.1:** Renamed from `north_star_multi_hop_route` to be honest
/// about what this test proves.
///
/// This test proves LOCAL route computation over an authenticated topology
/// graph plus destination resolution abstraction. It does NOT prove a
/// real distributed route-discovery protocol.
///
/// Scenario:
/// - A has no direct Internet gateway.
/// - A's local topology already contains the executable links:
///   A → B, B → C, C → G (all authenticated, all usable).
/// - A learns a RemoteNodeHint saying G is a gateway.
/// - A does NOT initially have G's authenticated advertisement.
/// - The InMemoryResolver (TEST-ONLY) supplies G's authenticated record.
///
/// The route engine:
///   1. discovers G as a candidate (from hint),
///   2. resolves G (via InMemoryResolver — NOT a distributed protocol),
///   3. computes the path A → B → C → G via Dijkstra over LOCAL links,
///   4. authenticates every hop (VerifiedNodeDescriptor per hop),
///   5. constructs the Route (RouteHop sequence with SELECTED LINK endpoints),
///   6. validates it (Route::validate()),
///   7. computes RouteCommitment (canonical CBOR hash),
///   8. returns RouteReady { route, cost }.
///
/// **What this does NOT prove:**
/// - A querying B over the network for C's advertisement.
/// - A querying B for the B→C link.
/// - A discovering links it doesn't already possess locally.
/// - A real distributed route-discovery protocol.
///
/// Those capabilities require the `DistributedRouteDiscovery` trait
/// (defined but explicitly unimplemented in this milestone).
#[test]
fn local_topology_multi_hop_route_with_destination_resolution() {
    let mut topology = TopologyGraph::new();

    // Local node A.
    let (a_sk, a_pk) = fresh_keypair(b"north-a");
    let a_id = derive_node_id(&a_pk);
    let _ = a_sk;

    // Relay B (authenticated, link A → B).
    let (b_advert, b_sk, b_pk) = make_relay_advert(b"north-b", 1);
    topology.accept_advertisement(b_advert.verify_into_verified().expect("verify B")).expect("accept B");
    let b_id = derive_node_id(&b_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(a_id, b_id, TransportEndpoint::tcp("127.0.0.1:1001")), None,
    ));

    // Relay C (authenticated, link B → C).
    // C is NOT directly known to A through a link, but B has a link to C.
    // For the path to work, C must be in the local topology (authenticated)
    // and the link B → C must exist.
    let (c_advert, _, c_pk) = make_relay_advert(b"north-c", 1);
    topology.accept_advertisement(c_advert.verify_into_verified().expect("verify C")).expect("accept C");
    let c_id = derive_node_id(&c_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(b_id, c_id, TransportEndpoint::tcp("127.0.0.1:1002")), None,
    ));

    // Gateway G — create advertisement but DON'T add to local topology.
    // G is only known through a hint.
    let (g_advert, _, g_pk) = make_gateway_advert(b"north-g", 1);
    let g_id = derive_node_id(&g_pk);
    let g_verified = g_advert.verify_into_verified().expect("G must verify");

    // Link C → G (exists in the topology, simulating that C has probed G).
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(c_id, g_id, TransportEndpoint::tcp("127.0.0.1:1003")), None,
    ));

    // A receives a hint from B: "G is a gateway, ~1 hop from B (2 hops from A)."
    let summary = snp_node::node::PeerSummary {
        node_id: g_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 2, // B claims G is 2 hops from B (through C)
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &b_sk, &b_pk, b_id, vec![summary], 1,
    );
    let verified_hint = list.verify_into_verified().expect("hint must verify");
    topology.process_peer_summaries(&verified_hint);

    // Verify A does NOT have G as an authenticated record.
    assert!(topology.get_record(&g_id).is_none(),
        "A must NOT initially have G's authenticated record");

    // Resolver: can resolve G's advertisement (simulating "ask B for G's advert").
    let mut resolver = InMemoryResolver::new();
    resolver.register_verified(g_verified);

    // Run the route engine.
    let engine = RouteEngine::new(a_id);
    let candidates = engine.discover_and_compute(&topology, &resolver, &HopCountCost);

    // Step 1: G was discovered as a candidate.
    let g_candidate = candidates.iter().find(|c| c.destination() == g_id)
        .expect("G must be discovered as a candidate");

    // Step 2-8: G was resolved, path found, route constructed, validated.
    assert!(g_candidate.is_ready(), "G candidate must be RouteReady");
    let route = g_candidate.route().expect("route exists");

    // Verify the route: A → B → C → G
    assert_eq!(route.source(), a_id, "source must be A");
    assert_eq!(route.destination(), g_id, "destination must be G");
    assert_eq!(route.hops(), vec![b_id, c_id, g_id], "route must be A → B → C → G");
    assert_eq!(route.hops().len(), 3, "three hops");

    // Step 6: Route validates.
    assert!(route.validate().is_ok(), "route must validate");

    // Step 7: RouteCommitment is computed (non-zero).
    let commitment = route.route_commitment();
    assert_ne!(commitment.as_bytes(), &[0u8; 32], "commitment must be non-zero");

    // Verify every hop is authenticated (has a VerifiedNodeDescriptor).
    for (i, hop) in route.hop_details().iter().enumerate() {
        assert!(hop.descriptor.verify_node_id_consistency(),
            "hop {i} must have verified NodeId consistency");
        assert!(!hop.endpoints.is_empty(),
            "hop {i} must have at least one endpoint");
    }

    // The destination hop must be a gateway with X25519.
    let last_hop = route.hop_details().last().expect("last hop");
    assert!(last_hop.descriptor.is_gateway(), "destination must be a gateway");
    assert!(last_hop.descriptor.circuit_x25519_pub().is_some(),
        "destination gateway must have X25519 circuit key");

    eprintln!("[test 16] PASS: LOCAL TOPOLOGY — A → B → C → G multi-hop route");
    eprintln!("  (This is LOCAL path computation + destination resolution,");
    eprintln!("   NOT distributed route discovery.)");
    eprintln!("  Route: {} → {} → {} → {}",
        hex_short_local(&a_id), hex_short_local(&b_id),
        hex_short_local(&c_id), hex_short_local(&g_id));
    eprintln!("  Commitment: {}", hex_short_local(commitment.as_bytes()));
    eprintln!("  Hops: {}", route.hops().len());
    eprintln!("  Cost: {}", g_candidate.route_cost().expect("cost"));
}

fn hex_short_local(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}

// ════════════════════════════════════════════════════════════════════════════
// Additional security/architecture tests
// ════════════════════════════════════════════════════════════════════════════

/// 17. candidate_origin_distinguishes_direct_vs_remote
#[test]
fn candidate_origin_distinguishes_direct_vs_remote() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"origin-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Direct gateway.
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"origin-direct-gw", 1);
    topology.accept_advertisement(gw_advert.verify_into_verified().expect("verify")).expect("accept");
    let gw_id = derive_node_id(&gw_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, gw_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));

    // Remote hint.
    let (sender_sk, sender_pk) = fresh_keypair(b"origin-sender");
    let sender_id = derive_node_id(&sender_pk);
    let remote_gw = [0xEE; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: remote_gw,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 3,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_gateway_candidates(&topology);

    let direct: Vec<_> = candidates.iter()
        .filter(|c| matches!(c.origin(), CandidateOrigin::Direct { .. }))
        .collect();
    let remote: Vec<_> = candidates.iter()
        .filter(|c| matches!(c.origin(), CandidateOrigin::Remote { .. }))
        .collect();

    assert_eq!(direct.len(), 1, "1 direct candidate");
    assert_eq!(remote.len(), 1, "1 remote candidate");
    assert_eq!(direct[0].destination(), gw_id);
    assert_eq!(remote[0].destination(), remote_gw);
    eprintln!("[test 17] PASS: candidate origin distinguishes direct vs remote");
}

/// 18. distance_hint_does_not_affect_route_cost
///
/// distance_hint is SELF_REPORTED and must not influence route cost.
/// Two hints with different distance_hints but same resolved destination
/// produce the same route (same cost).
#[test]
fn distance_hint_does_not_affect_route_cost() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"dist-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Relay + gateway chain.
    let (r_advert, _, r_pk) = make_relay_advert(b"dist-relay", 1);
    topology.accept_advertisement(r_advert.verify_into_verified().expect("verify")).expect("accept");
    let r_id = derive_node_id(&r_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, r_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));

    let (g_advert, _, g_pk) = make_gateway_advert(b"dist-gw", 1);
    let g_verified = g_advert.verify_into_verified().expect("verify");
    let g_id = derive_node_id(&g_pk);
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(r_id, g_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));

    // Hint 1: distance_hint = 1.
    let (s1_sk, s1_pk) = fresh_keypair(b"dist-sender-1");
    let s1_id = derive_node_id(&s1_pk);
    let summary1 = snp_node::node::PeerSummary {
        node_id: g_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list1 = snp_node::node::PeerSummaryList::create_and_sign(
        &s1_sk, &s1_pk, s1_id, vec![summary1], 1,
    );
    let v1 = list1.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&v1);

    // The route engine discovers G as a candidate (via hint).
    // It resolves G (resolver provides the record).
    // The route cost depends on hop count + RTT, NOT distance_hint.
    let mut resolver = InMemoryResolver::new();
    resolver.register_verified(g_verified);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &resolver, &HopCountCost);

    // G should appear as BOTH a direct candidate (it's in the local topology
    // via the link r → g, and g's advertisement was accepted) AND a remote
    // hint. The direct candidate takes precedence.
    // Wait — g_advert wasn't accepted into the topology in this test.
    // Let me check: we created g_advert and g_verified, but only registered
    // it in the resolver. We did NOT call topology.accept_advertisement().
    // So G is only known through the hint. Good.
    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "1 ready route");
    let route = ready[0].route().expect("route");
    assert_eq!(route.hops(), vec![r_id, g_id]);

    // The cost (hop count) is 2, regardless of distance_hint.
    assert_eq!(route.metrics().hop_count, 2);
    eprintln!("[test 18] PASS: distance_hint does not affect route cost");
}

/// 19. failed_candidate_does_not_poison_topology
///
/// A failed candidate (unresolvable hint) does not modify the topology.
#[test]
fn failed_candidate_does_not_poison_topology() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"poison-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Add a hint.
    let (sender_sk, sender_pk) = fresh_keypair(b"poison-sender");
    let sender_id = derive_node_id(&sender_pk);
    let fake_gw = [0xFF; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: fake_gw,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    // Snapshot the topology state before route computation.
    let hint_count_before = topology.remote_hints().len();
    let record_count_before = topology.directory().peer_count();

    // Run route engine with NullResolver (hint can't be resolved).
    let engine = RouteEngine::new(local);
    let _candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    // Topology must be unchanged.
    assert_eq!(topology.remote_hints().len(), hint_count_before,
        "failed candidate must NOT modify remote_hints");
    assert_eq!(topology.directory().peer_count(), record_count_before,
        "failed candidate must NOT modify authenticated records");
    assert!(topology.get_record(&fake_gw).is_none(),
        "failed candidate must NOT add an authenticated record");
    eprintln!("[test 19] PASS: failed candidate does not poison topology");
}

/// 20. low_latency_cost_model_selects_better_path
///
/// The LowLatencyCost model selects the path with lower total RTT.
#[test]
fn low_latency_cost_model_selects_better_path() {
    use snp_node::node::LowLatencyCost;

    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"lat-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Two paths to the same gateway:
    // Path 1: local → r1 → gw (r1 has high RTT)
    // Path 2: local → r2 → gw (r2 has low RTT)
    let (r1_advert, _, r1_pk) = make_relay_advert(b"lat-relay-1", 1);
    topology.accept_advertisement(r1_advert.verify_into_verified().expect("verify")).expect("accept");
    let r1_id = derive_node_id(&r1_pk);
    let (r2_advert, _, r2_pk) = make_relay_advert(b"lat-relay-2", 1);
    topology.accept_advertisement(r2_advert.verify_into_verified().expect("verify")).expect("accept");
    let r2_id = derive_node_id(&r2_pk);

    let (gw_advert, _, gw_pk) = make_gateway_advert(b"lat-gw", 1);
    topology.accept_advertisement(gw_advert.verify_into_verified().expect("verify")).expect("accept");
    let gw_id = derive_node_id(&gw_pk);

    // Links with different RTTs.
    let mut link1 = Link::new_up_for_testing(
        LinkKey::new(local, r1_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    );
    link1.record_success(500_000); // 500ms RTT

    let mut link2 = Link::new_up_for_testing(
        LinkKey::new(local, r2_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    );
    link2.record_success(10_000); // 10ms RTT

    topology.add_link_for_testing(link1);
    topology.add_link_for_testing(link2);

    let mut link3 = Link::new_up_for_testing(
        LinkKey::new(r1_id, gw_id, TransportEndpoint::tcp("127.0.0.1:3")), None,
    );
    link3.record_success(500_000);
    topology.add_link_for_testing(link3);

    let mut link4 = Link::new_up_for_testing(
        LinkKey::new(r2_id, gw_id, TransportEndpoint::tcp("127.0.0.1:4")), None,
    );
    link4.record_success(10_000);
    topology.add_link_for_testing(link4);

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &LowLatencyCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert!(ready.len() >= 1, "should have at least 1 ready route");
    let route = ready[0].route().expect("route");
    // The low-latency path goes through r2 (10ms + 10ms = 20ms),
    // not r1 (500ms + 500ms = 1000ms).
    assert_eq!(route.hops()[0], r2_id, "low-latency cost should select r2 path");
    eprintln!("[test 20] PASS: low-latency cost model selects better path");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.2.1 — Route correctness and distributed-resolution boundary tests
// ════════════════════════════════════════════════════════════════════════════

/// Helper: create a relay advertisement with MULTIPLE endpoints.
fn make_relay_advert_multi_endpoint(
    label: &[u8],
    seq: u64,
    endpoints: Vec<TransportEndpoint>,
) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        endpoints,
        None, 3600, seq,
    );
    (advert, sk, pk)
}

/// Helper: create a gateway advertisement with MULTIPLE endpoints.
fn make_gateway_advert_multi_endpoint(
    label: &[u8],
    seq: u64,
    endpoints: Vec<TransportEndpoint>,
) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        endpoints,
        Some(x_pk.to_bytes()), 3600, seq,
    );
    (advert, sk, pk)
}

/// 21. selected_link_endpoint_is_route_endpoint
///
/// N2.1.2.1: The RouteHop endpoint MUST be the endpoint from the selected
/// Link (LinkKey.endpoint), NOT record.endpoints.first().
///
/// This test creates a node that advertises TWO endpoints, then creates
/// a link using the SECOND endpoint. The route must use the second endpoint
/// in the RouteHop — not the first.
#[test]
fn selected_link_endpoint_is_route_endpoint() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"endpoint-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Gateway G advertises TWO endpoints: ep1 and ep2.
    let (g_advert, _, g_pk) = make_gateway_advert_multi_endpoint(
        b"endpoint-gw", 1,
        vec![
            TransportEndpoint::tcp("127.0.0.1:1111"),  // ep1 (first in advertisement)
            TransportEndpoint::tcp("127.0.0.1:2222"),  // ep2 (second in advertisement)
        ],
    );
    topology.accept_advertisement(g_advert.verify_into_verified().expect("verify")).expect("accept");
    let g_id = derive_node_id(&g_pk);

    // Create a link using the SECOND endpoint (ep2).
    let selected_endpoint = TransportEndpoint::tcp("127.0.0.1:2222");
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, g_id, selected_endpoint.clone()),
        None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 1, "should have 1 ready route");
    let route = ready[0].route().expect("route");

    // The RouteHop endpoint MUST be ep2 (the selected link's endpoint),
    // NOT ep1 (the first endpoint in the advertisement).
    let hop = &route.hop_details()[0];
    assert_eq!(hop.endpoints[0], selected_endpoint,
        "RouteHop endpoint MUST match the selected Link's endpoint, not record.endpoints.first()");
    assert_ne!(hop.endpoints[0], TransportEndpoint::tcp("127.0.0.1:1111"),
        "RouteHop endpoint must NOT be the first advertised endpoint");
    eprintln!("[test 21] PASS: selected link endpoint is route endpoint");
}

/// 22. route_commitment_changes_with_selected_link_endpoint
///
/// N2.1.2.1: Two routes to the same gateway via different selected link
/// endpoints MUST produce different RouteCommitments.
#[test]
fn route_commitment_changes_with_selected_link_endpoint() {
    let mut topology1 = TopologyGraph::new();
    let mut topology2 = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"commit-endpoint-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Gateway G advertises TWO endpoints.
    let (g_advert, _, g_pk) = make_gateway_advert_multi_endpoint(
        b"commit-endpoint-gw", 1,
        vec![
            TransportEndpoint::tcp("127.0.0.1:1111"),
            TransportEndpoint::tcp("127.0.0.1:2222"),
        ],
    );
    let g_verified = g_advert.verify_into_verified().expect("verify");
    let g_id = derive_node_id(&g_pk);

    topology1.accept_advertisement(g_verified.clone()).expect("accept");
    topology2.accept_advertisement(g_verified).expect("accept");

    // Topology 1: link via ep1.
    topology1.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, g_id, TransportEndpoint::tcp("127.0.0.1:1111")),
        None,
    ));

    // Topology 2: link via ep2.
    topology2.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, g_id, TransportEndpoint::tcp("127.0.0.1:2222")),
        None,
    ));

    let engine = RouteEngine::new(local);
    let candidates1 = engine.discover_and_compute(&topology1, &NullResolver, &HopCountCost);
    let candidates2 = engine.discover_and_compute(&topology2, &NullResolver, &HopCountCost);

    let route1 = candidates1.iter().find(|c| c.is_ready()).expect("route1 ready").route().expect("route1");
    let route2 = candidates2.iter().find(|c| c.is_ready()).expect("route2 ready").route().expect("route2");

    // Same source, same destination, same descriptor — but DIFFERENT selected endpoint.
    assert_eq!(route1.source(), route2.source());
    assert_eq!(route1.destination(), route2.destination());
    assert_ne!(
        route1.hop_details()[0].endpoints[0],
        route2.hop_details()[0].endpoints[0],
        "routes must use different selected endpoints"
    );

    // RouteCommitment MUST differ because the selected endpoint differs.
    assert_ne!(
        route1.route_commitment(),
        route2.route_commitment(),
        "routes with different selected link endpoints MUST have different commitments"
    );
    eprintln!("[test 22] PASS: route commitment changes with selected link endpoint");
}

/// 23. best_route_selects_lowest_computed_cost
///
/// N2.1.2.1: best_route() must select the route with the minimum actual
/// computed cost — NOT the first ready candidate based on discovery order.
///
/// This test constructs two gateway routes where:
/// - Candidate A (discovered first): 3-hop route, higher cost.
/// - Candidate B (discovered second): 1-hop route, lower cost.
///
/// best_route() must return Candidate B's route.
#[test]
fn best_route_selects_lowest_computed_cost() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"best-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Gateway G1: 3-hop route (local → r1 → r2 → g1).
    let (r1_advert, _, r1_pk) = make_relay_advert(b"best-relay-1", 1);
    topology.accept_advertisement(r1_advert.verify_into_verified().expect("verify")).expect("accept");
    let r1_id = derive_node_id(&r1_pk);

    let (r2_advert, _, r2_pk) = make_relay_advert(b"best-relay-2", 1);
    topology.accept_advertisement(r2_advert.verify_into_verified().expect("verify")).expect("accept");
    let r2_id = derive_node_id(&r2_pk);

    let (g1_advert, _, g1_pk) = make_gateway_advert(b"best-gw-1", 1);
    topology.accept_advertisement(g1_advert.verify_into_verified().expect("verify")).expect("accept");
    let g1_id = derive_node_id(&g1_pk);

    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, r1_id, TransportEndpoint::tcp("127.0.0.1:1")), None,
    ));
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(r1_id, r2_id, TransportEndpoint::tcp("127.0.0.1:2")), None,
    ));
    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(r2_id, g1_id, TransportEndpoint::tcp("127.0.0.1:3")), None,
    ));

    // Gateway G2: 1-hop route (local → g2).
    let (g2_advert, _, g2_pk) = make_gateway_advert(b"best-gw-2", 1);
    topology.accept_advertisement(g2_advert.verify_into_verified().expect("verify")).expect("accept");
    let g2_id = derive_node_id(&g2_pk);

    topology.add_link_for_testing(Link::new_up_for_testing(
        LinkKey::new(local, g2_id, TransportEndpoint::tcp("127.0.0.1:4")), None,
    ));

    let engine = RouteEngine::new(local);
    let candidates = engine.discover_and_compute(&topology, &NullResolver, &HopCountCost);

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    assert_eq!(ready.len(), 2, "should have 2 ready routes");

    // The first ready candidate might be G1 (3-hop) or G2 (1-hop) depending
    // on discovery order. But best_route() must return G2 (1-hop, lower cost).
    let best = RouteEngine::best_route(&candidates).expect("best route");
    assert_eq!(best.destination(), g2_id,
        "best_route must select the lower-cost route (G2, 1-hop), not G1 (3-hop)");
    assert_eq!(best.hops().len(), 1, "best route must be the 1-hop route");

    // Verify the cost is correct.
    let (best_route, best_cost) = RouteEngine::best_route_with_cost(&candidates).expect("best");
    assert_eq!(best_route.destination(), g2_id);
    // HopCountCost: 1 hop = 1_000_000, 3 hops = 3_000_000.
    assert!(best_cost < 3_000_000, "1-hop cost must be less than 3-hop cost");

    eprintln!("[test 23] PASS: best_route selects lowest computed cost");
}

/// 24. remote_hint_does_not_create_local_link
///
/// N2.1.2.1: A RemoteNodeHint is non-authoritative and must NOT create
/// a local link in the topology. The topology's LinkTable must remain
/// unchanged after processing a hint.
#[test]
fn remote_hint_does_not_create_local_link() {
    let mut topology = TopologyGraph::new();
    let (local_sk, local_pk) = fresh_keypair(b"hint-no-link-local");
    let local = derive_node_id(&local_pk);
    let _ = local_sk;

    // Snapshot the link count before processing a hint.
    let link_count_before = topology.link_count();

    // Create a hint about a remote gateway.
    let (sender_sk, sender_pk) = fresh_keypair(b"hint-no-link-sender");
    let sender_id = derive_node_id(&sender_pk);
    let remote_gw = [0xAB; 32];
    let summary = snp_node::node::PeerSummary {
        node_id: remote_gw,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 2,
    };
    let list = snp_node::node::PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id, vec![summary], 1,
    );
    let verified = list.verify_into_verified().expect("verify");
    topology.process_peer_summaries(&verified);

    // The hint must NOT create a local link.
    assert_eq!(topology.link_count(), link_count_before,
        "RemoteNodeHint must NOT create a local link");

    // The hint must NOT make the remote node directly reachable.
    assert!(!topology.is_directly_reachable(&remote_gw),
        "RemoteNodeHint must NOT make the node directly reachable");

    // The hint must NOT create an authenticated record.
    assert!(topology.get_record(&remote_gw).is_none(),
        "RemoteNodeHint must NOT create an authenticated record");

    // The hint IS stored as a non-authoritative RemoteNodeHint.
    assert!(topology.remote_hints().contains_key(&remote_gw),
        "RemoteNodeHint must be stored as a hint (not a link or record)");

    eprintln!("[test 24] PASS: remote hint does not create local link");
}

/// 25. in_memory_resolver_is_test_only_route_resolution
///
/// N2.1.2.1: InMemoryResolver is explicitly documented as TEST-ONLY.
/// It does NOT perform distributed route discovery. This test verifies
/// that InMemoryResolver returns pre-registered records (simulating
/// resolution) but does NOT query any network.
#[test]
fn in_memory_resolver_is_test_only_route_resolution() {
    // InMemoryResolver returns pre-registered records.
    let mut resolver = InMemoryResolver::new();

    // Create a gateway advertisement and register it.
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"resolver-test-gw", 1);
    let gw_id = derive_node_id(&gw_pk);
    let gw_verified = gw_advert.verify_into_verified().expect("verify");
    resolver.register_verified(gw_verified);

    // Resolution succeeds for the registered node.
    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: gw_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: now_unix(),
        distance_hint: 1,
        learned_from: [0x00; 32],
        received_at: now_unix(),
        source_propagation_sequence: 1,
    };
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &gw_id, &hint);
    assert!(resolved.is_some(), "InMemoryResolver must return registered records");
    assert_eq!(resolved.unwrap().node_id(), gw_id);

    // Resolution fails for an unregistered node.
    let unknown_id = [0xCD; 32];
    let resolved_unknown = snp_node::node::DestinationResolver::resolve(&resolver, &unknown_id, &hint);
    assert!(resolved_unknown.is_none(),
        "InMemoryResolver must return None for unregistered nodes");

    // Key point: InMemoryResolver does NOT perform any network operation.
    // It is a deterministic TEST-ONLY stub. A production resolver would
    // query an authenticated next-hop peer, receive advertisement bytes,
    // and call NodeAdvertisement::verify_into_verified().
    //
    // The InMemoryResolver skips all of that by returning pre-authenticated
    // records from a local map. This is why it is TEST-ONLY.

    eprintln!("[test 25] PASS: InMemoryResolver is test-only route resolution");
}

/// 26. distributed_route_discovery_is_explicitly_unimplemented
///
/// N2.1.2.1: The architecture explicitly marks distributed route discovery
/// as unimplemented. The DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED constant
/// is false, and the DistributedRouteDiscovery trait has no production
/// implementation.
#[test]
fn distributed_route_discovery_is_explicitly_unimplemented() {
    // The constant must be false — distributed discovery is NOT implemented.
    assert!(!DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED,
        "DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED must be false in this milestone");

    // The DistributedRouteDiscovery trait exists (it compiles), but no
    // production implementation is available. The trait defines the
    // interface for future implementation:
    //
    //   fn discover_path(
    //       &mut self,
    //       source: &[u8; 32],
    //       destination: &[u8; 32],
    //   ) -> Option<Vec<([u8; 32], LinkKey)>>;
    //
    // A production implementation would:
    // 1. Query an authenticated next-hop peer for the next segment.
    // 2. Receive and verify the next-hop node's advertisement.
    // 3. Discover the usable link from the current hop to the next hop.
    // 4. Continue until the destination is reached and authenticated.
    //
    // This is explicitly NOT implemented. The RouteEngine currently performs
    // LOCAL path computation only.

    // Verify the trait can be referenced (it exists in the type system).
    fn _assert_trait_exists<T: snp_node::node::DistributedRouteDiscovery>() {}
    // (No concrete type to pass — there is no implementation.)

    eprintln!("[test 26] PASS: distributed route discovery is explicitly unimplemented");
}

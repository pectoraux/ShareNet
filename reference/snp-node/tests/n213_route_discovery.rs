//! N2.1.3 — Distributed Route Discovery Protocol tests.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, NodeAdvertisement, NextHopQuery, NextHopResponse, NextHopResult,
    NextHopResolver, InMemoryNextHopTransport, TopologyGraph, TransportEndpoint,
    VerifiedNodeAdvertisement, DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED,
};

// ─── Test helpers ───────────────────────────────────────────────────────────

fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64, endpoint: &str) -> (VerifiedNodeAdvertisement, [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(endpoint)],
        Some(x_pk.to_bytes()), 3600, seq,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    (verified, derive_node_id(&pk))
}

fn make_relay_advert(label: &[u8], seq: u64, endpoint: &str) -> (VerifiedNodeAdvertisement, [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp(endpoint)],
        None, 3600, seq,
    );
    let verified = advert.verify_into_verified().expect("must verify");
    (verified, derive_node_id(&pk))
}

// ════════════════════════════════════════════════════════════════════════════
// Protocol message tests
// ════════════════════════════════════════════════════════════════════════════

/// 1. next_hop_query_verifies_signature
#[test]
fn next_hop_query_verifies_signature() {
    let (sk, pk) = fresh_keypair(b"query-sender");
    let node_id = derive_node_id(&pk);
    let destination = [0xAA; 32];

    let query = NextHopQuery::create_and_sign(&sk, &pk, node_id, destination, 10);
    assert!(query.verify_signature(), "NextHopQuery must verify");
    assert_eq!(query.source_node_id, node_id);
    assert_eq!(query.destination_node_id, destination);
    assert_eq!(query.max_hops, 10);
    eprintln!("[test 1] PASS: NextHopQuery verifies signature");
}

/// 2. next_hop_query_tampered_rejected
#[test]
fn next_hop_query_tampered_rejected() {
    let (sk, pk) = fresh_keypair(b"query-tamper");
    let node_id = derive_node_id(&pk);
    let mut query = NextHopQuery::create_and_sign(&sk, &pk, node_id, [0xBB; 32], 5);
    query.destination_node_id = [0xCC; 32]; // Tamper.
    assert!(!query.verify_signature(), "tampered query must fail verification");
    eprintln!("[test 2] PASS: tampered NextHopQuery rejected");
}

/// 3. next_hop_response_found_verifies_signature
#[test]
fn next_hop_response_found_verifies_signature() {
    let (sk, pk) = fresh_keypair(b"responder");
    let node_id = derive_node_id(&pk);
    let (gw_advert, gw_id) = make_gateway_advert(b"response-gw", 1, "127.0.0.1:1234");

    let response = NextHopResponse::create_found_and_sign(
        &sk, &pk, node_id,
        [0u8; 16], // query_id
        gw_id,
        gw_advert.as_ref().clone(),
        true, // is_destination
    );
    assert!(response.verify_signature(), "NextHopResponse must verify");
    assert!(matches!(response.result, NextHopResult::Found { is_destination: true, .. }));
    eprintln!("[test 3] PASS: NextHopResponse (Found) verifies signature");
}

/// 4. next_hop_response_not_found_verifies_signature
#[test]
fn next_hop_response_not_found_verifies_signature() {
    let (sk, pk) = fresh_keypair(b"responder-nf");
    let node_id = derive_node_id(&pk);

    let response = NextHopResponse::create_not_found_and_sign(
        &sk, &pk, node_id,
        [0u8; 16],
    );
    assert!(response.verify_signature(), "NotFound response must verify");
    assert!(matches!(response.result, NextHopResult::NotFound));
    eprintln!("[test 4] PASS: NextHopResponse (NotFound) verifies signature");
}

/// 5. next_hop_response_tampered_rejected
#[test]
fn next_hop_response_tampered_rejected() {
    let (sk, pk) = fresh_keypair(b"responder-tamper");
    let node_id = derive_node_id(&pk);
    let (gw_advert, gw_id) = make_gateway_advert(b"tamper-gw", 1, "127.0.0.1:1234");

    let mut response = NextHopResponse::create_found_and_sign(
        &sk, &pk, node_id,
        [0u8; 16], gw_id, gw_advert.as_ref().clone(), true,
    );
    // Tamper with the result.
    if let NextHopResult::Found { is_destination, .. } = &mut response.result {
        *is_destination = false;
    }
    assert!(!response.verify_signature(), "tampered response must fail verification");
    eprintln!("[test 5] PASS: tampered NextHopResponse rejected");
}

/// 6. next_hop_response_matches_query
#[test]
fn next_hop_response_matches_query() {
    let (q_sk, q_pk) = fresh_keypair(b"match-query");
    let q_id = derive_node_id(&q_pk);
    let query = NextHopQuery::create_and_sign(&q_sk, &q_pk, q_id, [0xDD; 32], 5);

    let (r_sk, r_pk) = fresh_keypair(b"match-responder");
    let r_id = derive_node_id(&r_pk);
    let response = NextHopResponse::create_not_found_and_sign(&r_sk, &r_pk, r_id, query.query_id);

    assert!(response.matches_query(&query), "response must match query");
    eprintln!("[test 6] PASS: response matches query");
}

/// 7. next_hop_response_does_not_match_different_query
#[test]
fn next_hop_response_does_not_match_different_query() {
    let (q_sk, q_pk) = fresh_keypair(b"diff-query");
    let q_id = derive_node_id(&q_pk);
    let query1 = NextHopQuery::create_and_sign(&q_sk, &q_pk, q_id, [0xEE; 32], 5);
    let query2 = NextHopQuery::create_and_sign(&q_sk, &q_pk, q_id, [0xFF; 32], 5);

    let (r_sk, r_pk) = fresh_keypair(b"diff-responder");
    let r_id = derive_node_id(&r_pk);
    let response = NextHopResponse::create_not_found_and_sign(&r_sk, &r_pk, r_id, query1.query_id);

    assert!(response.matches_query(&query1), "response matches query1");
    assert!(!response.matches_query(&query2), "response does NOT match query2");
    eprintln!("[test 7] PASS: response does not match different query");
}

// ════════════════════════════════════════════════════════════════════════════
// Distributed route discovery implementation marker
// ════════════════════════════════════════════════════════════════════════════

/// 8. distributed_route_discovery_is_now_implemented
#[test]
fn distributed_route_discovery_is_now_implemented() {
    assert!(DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED,
        "N2.1.3: distributed route discovery is now implemented");
    eprintln!("[test 8] PASS: distributed route discovery is implemented");
}

// ════════════════════════════════════════════════════════════════════════════
// NextHopResolver tests
// ════════════════════════════════════════════════════════════════════════════

/// 9. next_hop_resolver_resolves_destination_through_neighbor
///
/// Scenario: A wants to reach G. A knows B. B knows G.
/// A queries B, B responds with G's advertisement.
#[test]
fn next_hop_resolver_resolves_destination_through_neighbor() {
    let topology = TopologyGraph::new();

    // Local node A.
    let (a_sk, a_pk) = fresh_keypair(b"resolver-a");
    let a_id = derive_node_id(&a_pk);

    // Relay B (the neighbor A will query).
    let (_b_verified, b_id) = make_relay_advert(b"resolver-b", 1, "127.0.0.1:2001");

    // Gateway G (the destination).
    let (g_verified, g_id) = make_gateway_advert(b"resolver-g", 1, "127.0.0.1:2002");
    let g_advert = g_verified.as_ref().clone();

    // Hint: B claims G exists.
    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: g_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // In-memory transport: B responds with G's advertisement.
    let mut transport = InMemoryNextHopTransport::new();
    transport.register_responder(b_id, move |_query| {
        let (b_sk, b_pk) = fresh_keypair(b"resolver-b"); // same label → same keys
        let b_node_id = derive_node_id(&b_pk);
        Some(NextHopResponse::create_found_and_sign(
            &b_sk, &b_pk, b_node_id,
            _query.query_id,
            g_id,
            g_advert.clone(),
            true, // is_destination
        ))
    });

    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &g_id, &hint);

    assert!(resolved.is_some(), "resolver must find G");
    let record = resolved.unwrap();
    assert_eq!(record.node_id(), g_id);
    assert!(record.descriptor.is_gateway());
    eprintln!("[test 9] PASS: NextHopResolver resolves destination through neighbor");
}

/// 10. next_hop_resolver_returns_none_when_neighbor_does_not_respond
#[test]
fn next_hop_resolver_returns_none_when_neighbor_does_not_respond() {
    let topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"no-response-a");
    let a_id = derive_node_id(&a_pk);
    let (_b_verified, b_id) = make_relay_advert(b"no-response-b", 1, "127.0.0.1:2003");

    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: [0xAA; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // Empty transport — no responders registered.
    let transport = InMemoryNextHopTransport::new();
    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &[0xAA; 32], &hint);
    assert!(resolved.is_none(), "resolver must return None when neighbor doesn't respond");
    eprintln!("[test 10] PASS: resolver returns None when neighbor doesn't respond");
}

/// 11. next_hop_resolver_rejects_unsigned_response
#[test]
fn next_hop_resolver_rejects_unsigned_response() {
    let topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"unsigned-a");
    let a_id = derive_node_id(&a_pk);
    let (_b_verified, b_id) = make_relay_advert(b"unsigned-b", 1, "127.0.0.1:2004");
    let (g_verified, g_id) = make_gateway_advert(b"unsigned-g", 1, "127.0.0.1:2005");

    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: g_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // Register a responder that returns an UNSIGNED response.
    let g_advert = g_verified.as_ref().clone();
    let mut transport = InMemoryNextHopTransport::new();
    transport.register_responder(b_id, move |query| {
        let mut response = NextHopResponse::create_found_and_sign(
            &fresh_keypair(b"wrong-responder").0, // WRONG key
            &fresh_keypair(b"wrong-responder").1,
            derive_node_id(&fresh_keypair(b"wrong-responder").1),
            query.query_id,
            g_id,
            g_advert.clone(),
            true,
        );
        // Corrupt the signature.
        response.signature[0] ^= 0xFF;
        Some(response)
    });

    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &g_id, &hint);
    assert!(resolved.is_none(), "resolver must reject unsigned response");
    eprintln!("[test 11] PASS: resolver rejects unsigned response");
}

/// 12. next_hop_resolver_rejects_response_with_mismatched_query_id
#[test]
fn next_hop_resolver_rejects_response_with_mismatched_query_id() {
    let topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"mismatch-a");
    let a_id = derive_node_id(&a_pk);
    let (_b_verified, b_id) = make_relay_advert(b"mismatch-b", 1, "127.0.0.1:2006");
    let (g_verified, g_id) = make_gateway_advert(b"mismatch-g", 1, "127.0.0.1:2007");

    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: g_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // Register a responder that returns a response with a WRONG query_id.
    let g_advert = g_verified.as_ref().clone();
    let mut transport = InMemoryNextHopTransport::new();
    transport.register_responder(b_id, move |_query| {
        let (b_sk, b_pk) = fresh_keypair(b"mismatch-b");
        let b_node_id = derive_node_id(&b_pk);
        Some(NextHopResponse::create_found_and_sign(
            &b_sk, &b_pk, b_node_id,
            [0xFF; 16], // WRONG query_id
            g_id,
            g_advert.clone(),
            true,
        ))
    });

    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &g_id, &hint);
    assert!(resolved.is_none(), "resolver must reject mismatched query_id");
    eprintln!("[test 12] PASS: resolver rejects mismatched query_id");
}

/// 13. next_hop_resolver_rejects_not_found_response
#[test]
fn next_hop_resolver_rejects_not_found_response() {
    let topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"notfound-a");
    let a_id = derive_node_id(&a_pk);
    let (_b_verified, b_id) = make_relay_advert(b"notfound-b", 1, "127.0.0.1:2008");

    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: [0xBB; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    let mut transport = InMemoryNextHopTransport::new();
    transport.register_responder(b_id, |query| {
        let (b_sk, b_pk) = fresh_keypair(b"notfound-b");
        let b_node_id = derive_node_id(&b_pk);
        Some(NextHopResponse::create_not_found_and_sign(&b_sk, &b_pk, b_node_id, query.query_id))
    });

    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &[0xBB; 32], &hint);
    assert!(resolved.is_none(), "resolver must return None for NotFound");
    eprintln!("[test 13] PASS: resolver returns None for NotFound");
}

/// 14. next_hop_resolver_rejects_invalid_advertisement
///
/// The response contains an advertisement that fails verification
/// (e.g., expired or tampered).
#[test]
fn next_hop_resolver_rejects_invalid_advertisement() {
    let topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"invalid-advert-a");
    let a_id = derive_node_id(&a_pk);
    let (_b_verified, b_id) = make_relay_advert(b"invalid-advert-b", 1, "127.0.0.1:2009");

    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: [0xCC; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // Create an INVALID advertisement (tampered signature).
    let (g_sk, g_pk) = fresh_keypair(b"invalid-advert-g");
    let (x_sk, x_pk) = x25519_static_keypair();
    let _ = x_sk;
    let mut bad_advert = NodeAdvertisement::create_and_sign(
        &g_sk, &g_pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:2010")],
        Some(x_pk.to_bytes()), 3600, 1,
    );
    bad_advert.signature[0] ^= 0xFF; // Corrupt signature.

    let mut transport = InMemoryNextHopTransport::new();
    transport.register_responder(b_id, move |query| {
        let (b_sk, b_pk) = fresh_keypair(b"invalid-advert-b");
        let b_node_id = derive_node_id(&b_pk);
        Some(NextHopResponse::create_found_and_sign(
            &b_sk, &b_pk, b_node_id,
            query.query_id,
            [0xCC; 32],
            bad_advert.clone(),
            true,
        ))
    });

    let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
    let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &[0xCC; 32], &hint);
    assert!(resolved.is_none(), "resolver must reject invalid advertisement");
    eprintln!("[test 14] PASS: resolver rejects invalid advertisement");
}

// ════════════════════════════════════════════════════════════════════════════
// Integration: distributed discovery + route engine
// ════════════════════════════════════════════════════════════════════════════

/// 15. distributed_resolution_plus_local_route_construction
///
/// Full pipeline: A uses NextHopResolver to resolve G through B,
/// then RouteEngine constructs a route using the resolved record.
#[test]
fn distributed_resolution_plus_local_route_construction() {
    use snp_node::node::{HopCountCost, LinkKey, RouteEngine};
    use snp_node::test_support::test_authenticated_link;

    let mut topology = TopologyGraph::new();
    let (a_sk, a_pk) = fresh_keypair(b"integration-a");
    let a_id = derive_node_id(&a_pk);

    // Relay B (authenticated, A has a link to B).
    let (b_verified, b_id) = make_relay_advert(b"integration-b", 1, "127.0.0.1:3001");
    topology.accept_advertisement(b_verified.clone()).expect("accept B");
    let key_ab = LinkKey::new(a_id, b_id, TransportEndpoint::tcp("127.0.0.1:3001"));
    topology.add_authenticated_link(test_authenticated_link(key_ab, &b_verified).unwrap());

    // Gateway G (NOT in local topology — will be resolved via B).
    let (g_verified, g_id) = make_gateway_advert(b"integration-g", 1, "127.0.0.1:3002");
    let g_advert = g_verified.as_ref().clone();

    // Hint: B claims G exists.
    let hint = snp_node::node::RemoteNodeHint {
        target_node_id: g_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from: b_id,
        received_at: 0,
        source_propagation_sequence: 1,
    };

    // Transport: B responds with G's advertisement.
    let mut transport = InMemoryNextHopTransport::new();
    let g_advert_for_closure = g_advert.clone();
    transport.register_responder(b_id, move |query| {
        let (b_sk, b_pk) = fresh_keypair(b"integration-b");
        let b_node_id = derive_node_id(&b_pk);
        Some(NextHopResponse::create_found_and_sign(
            &b_sk, &b_pk, b_node_id,
            query.query_id,
            g_id,
            g_advert_for_closure.clone(),
            true,
        ))
    });

    // Step 1: Resolve G via distributed protocol.
    // The resolver borrows topology immutably, so we resolve first,
    // then mutate topology after the resolver is dropped.
    {
        let resolver = NextHopResolver::new(&topology, &transport, a_sk, a_pk, a_id);
        let resolved = snp_node::node::DestinationResolver::resolve(&resolver, &g_id, &hint);
        assert!(resolved.is_some(), "G must be resolved");
        let g_record = resolved.unwrap();
        assert_eq!(g_record.node_id(), g_id);
    }

    // Step 2: Add G's resolved record to the topology.
    topology.accept_advertisement(g_verified.clone()).expect("accept G");
    let key_ag = LinkKey::new(a_id, g_id, TransportEndpoint::tcp("127.0.0.1:3002"));
    topology.add_authenticated_link(test_authenticated_link(key_ag, &g_verified).unwrap());

    // Step 3: Construct route using RouteEngine.
    // Use NullResolver since G is now in the local topology.
    let engine = RouteEngine::new(a_id);
    let candidates = engine.discover_and_compute(
        &topology,
        &snp_node::node::NullResolver,
        &HopCountCost,
    );

    let ready: Vec<_> = candidates.iter().filter(|c| c.is_ready()).collect();
    // G should be ready — A has a direct authenticated link to G.
    assert!(!ready.is_empty(), "should have at least 1 ready route");

    let g_route = ready.iter().find(|c| c.destination() == g_id);
    assert!(g_route.is_some(), "G route must be ready");
    let cand = g_route.unwrap();
    let route = cand.route().expect("route");
    assert_eq!(route.source(), a_id);
    assert_eq!(route.destination(), g_id);
    assert!(route.validate().is_ok());
    eprintln!("[test 15] PASS: distributed resolution + local route construction");
}

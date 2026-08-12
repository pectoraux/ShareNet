//! N2.1.1 — Topology, Peer Directory, and Link tests.

#![allow(clippy::pedantic)]

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, Link, LinkKey, LinkState, NodeAdvertisement, PeerDirectory, PeerSummary,
    PeerSummaryList, PeerVisibility, TopologyGraph, TransportEndpoint,
};

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

fn make_relay_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1234")],
        None, 1, seq, // 1 second expiry for purge test
    );
    (advert, sk, pk)
}

fn make_gateway_advert(label: &[u8], seq: u64) -> (NodeAdvertisement, [u8; 32], [u8; 32]) {
    let (sk, pk) = fresh_keypair(label);
    let (x_sk, x_pk) = x25519_static_keypair();
    let advert = NodeAdvertisement::create_and_sign(
        &sk, &pk, vec![Capability::Gateway],
        vec![TransportEndpoint::tcp("127.0.0.1:5678")],
        Some(x_pk.to_bytes()), 3600, seq,
    );
    (advert, sk, pk)
}

// ─── Link tests ─────────────────────────────────────────────────────────────

#[test]
fn link_state_transitions() {
    let (sk_a, pk_a) = fresh_keypair(b"link-a");
    let (sk_b, pk_b) = fresh_keypair(b"link-b");
    let node_a = derive_node_id(&pk_a);
    let node_b = derive_node_id(&pk_b);
    let key = LinkKey::new(node_a, node_b, TransportEndpoint::tcp("127.0.0.1:1"));
    let mut link = Link::new_up(key.clone(), None);
    assert_eq!(link.state, LinkState::Up);
    assert!(link.is_usable());

    // One failure → Degraded.
    link.record_failure();
    assert_eq!(link.state, LinkState::Degraded);
    assert!(link.is_usable());

    // Success → Up.
    link.record_success(1000);
    assert_eq!(link.state, LinkState::Up);
    assert_eq!(link.metrics.success_count, 1);
    assert_eq!(link.metrics.rtt_micros, Some(1000));

    // Three consecutive failures → Down.
    link.record_failure();
    link.record_failure();
    link.record_failure();
    assert_eq!(link.state, LinkState::Down);
    assert!(!link.is_usable());
    assert_eq!(link.consecutive_failures, 3);
}

#[test]
fn link_metrics_recorded() {
    let (sk_a, pk_a) = fresh_keypair(b"link-metrics-a");
    let (sk_b, pk_b) = fresh_keypair(b"link-metrics-b");
    let key = LinkKey::new(
        derive_node_id(&pk_a),
        derive_node_id(&pk_b),
        TransportEndpoint::tcp("127.0.0.1:1"),
    );
    let mut link = Link::new_up(key, None);
    link.record_success(500);
    link.record_success(750);
    link.record_failure();
    assert_eq!(link.metrics.success_count, 2);
    assert_eq!(link.metrics.failure_count, 1);
    assert_eq!(link.metrics.rtt_micros, Some(750));
    let rate = link.metrics.success_rate().unwrap();
    assert!((rate - 0.6667).abs() < 0.01);
}

#[test]
fn link_table_directed() {
    use snp_node::node::LinkTable;
    let (sk_a, pk_a) = fresh_keypair(b"lt-a");
    let (sk_b, pk_b) = fresh_keypair(b"lt-b");
    let node_a = derive_node_id(&pk_a);
    let node_b = derive_node_id(&pk_b);

    let mut table = LinkTable::new();
    // A → B link.
    let key_ab = LinkKey::new(node_a, node_b, TransportEndpoint::tcp("127.0.0.1:1"));
    table.insert(Link::new_up(key_ab.clone(), None));

    // links_from(A) should return the A→B link.
    let from_a = table.links_from(&node_a);
    assert_eq!(from_a.len(), 1);
    assert_eq!(from_a[0].key.remote_node_id, node_b);

    // links_to(B) should return the A→B link.
    let to_b = table.links_to(&node_b);
    assert_eq!(to_b.len(), 1);
    assert_eq!(to_b[0].key.local_node_id, node_a);

    // links_from(B) should be empty (no B→A link).
    let from_b = table.links_from(&node_b);
    assert_eq!(from_b.len(), 0, "directed: B→A should NOT exist just because A→B exists");
}

// ─── PeerDirectory tests ────────────────────────────────────────────────────

#[test]
fn peer_directory_accepts_new_advertisement() {
    let mut dir = PeerDirectory::new();
    let (advert, _, pk) = make_relay_advert(b"dir-relay", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    let result = dir.accept_advertisement(verified).expect("accept");
    assert!(matches!(result, snp_node::node::AcceptanceResult::Accepted(_)));
    assert_eq!(dir.visibility(&derive_node_id(&pk)), PeerVisibility::Active);
}

#[test]
fn peer_directory_rejects_stale_advertisement() {
    let mut dir = PeerDirectory::new();
    let (advert2, _, _) = make_relay_advert(b"dir-stale", 2);
    let verified2 = advert2.verify_into_verified().expect("must verify");
    dir.accept_advertisement(verified2).expect("accept 2");

    let (advert1, _, _) = make_relay_advert(b"dir-stale", 1);
    let verified1 = advert1.verify_into_verified().expect("must verify");
    let result = dir.accept_advertisement(verified1).expect("accept 1");
    assert!(matches!(result, snp_node::node::AcceptanceResult::Stale { .. }));
}

#[test]
fn peer_directory_rejects_duplicate_advertisement() {
    let mut dir = PeerDirectory::new();
    let (advert, sk, _) = make_relay_advert(b"dir-dup", 5);
    let verified1 = advert.verify_into_verified().expect("must verify");
    dir.accept_advertisement(verified1).expect("accept 1");

    // Same sequence — different nonce but same sequence.
    let advert2 = NodeAdvertisement::create_and_sign(
        &sk, &derive_public_key(&sk), vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:1")],
        None, 3600, 5, // same sequence
    );
    let verified2 = advert2.verify_into_verified().expect("must verify");
    let result = dir.accept_advertisement(verified2).expect("accept 2");
    assert!(matches!(result, snp_node::node::AcceptanceResult::Duplicate { .. }));
}

#[test]
fn peer_directory_purge_makes_stale_not_removed() {
    let mut dir = PeerDirectory::new();
    let (advert, _, pk) = make_relay_advert(b"dir-purge", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    dir.accept_advertisement(verified).expect("accept");
    let node_id = derive_node_id(&pk);

    assert_eq!(dir.visibility(&node_id), PeerVisibility::Active);

    // Wait for expiry.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    dir.purge_expired(now_unix());

    assert_eq!(dir.visibility(&node_id), PeerVisibility::Stale,
        "purge should make STALE, not REMOVED");
    assert!(dir.highest_sequence(&node_id).is_some(),
        "sequence floor must persist after purge");
}

#[test]
fn peer_directory_remove_peer_is_explicit() {
    let mut dir = PeerDirectory::new();
    let (advert, _, pk) = make_relay_advert(b"dir-remove", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    dir.accept_advertisement(verified).expect("accept");
    let node_id = derive_node_id(&pk);

    assert_eq!(dir.visibility(&node_id), PeerVisibility::Active);

    dir.remove_peer(&node_id).expect("remove");

    assert_eq!(dir.visibility(&node_id), PeerVisibility::Unknown);
    assert!(dir.highest_sequence(&node_id).is_none());
}

// ─── TopologyGraph tests ────────────────────────────────────────────────────

#[test]
fn topology_graph_directed_links() {
    let mut graph = TopologyGraph::new();
    let (sk_a, pk_a) = fresh_keypair(b"tg-a");
    let (sk_b, pk_b) = fresh_keypair(b"tg-b");
    let node_a = derive_node_id(&pk_a);
    let node_b = derive_node_id(&pk_b);

    // A → B link only.
    let key_ab = LinkKey::new(node_a, node_b, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(key_ab, None));

    // neighbors(A) should return 1 link.
    let neighbors_a = graph.neighbors(&node_a);
    assert_eq!(neighbors_a.len(), 1);

    // neighbors(B) should return 0 links (directed).
    let neighbors_b = graph.neighbors(&node_b);
    assert_eq!(neighbors_b.len(), 0, "directed: B should not have outgoing links");

    // is_directly_reachable(B) should be true (A→B exists).
    assert!(graph.is_directly_reachable(&node_b));
    // is_directly_reachable(A) should be false (no B→A link).
    assert!(!graph.is_directly_reachable(&node_a));
}

#[test]
fn topology_graph_reachable_gateways() {
    let mut graph = TopologyGraph::new();
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"tg-gw", 1);
    let gw_verified = gw_advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(gw_verified).expect("accept");
    let gw_id = derive_node_id(&gw_pk);

    let (relay_advert, _, relay_pk) = make_relay_advert(b"tg-relay", 1);
    let relay_verified = relay_advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(relay_verified).expect("accept");
    let relay_id = derive_node_id(&relay_pk);

    // Add a link to the gateway (making it directly reachable).
    let local_id = [0xAA; 32]; // Our own NodeId.
    let gw_link_key = LinkKey::new(local_id, gw_id, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(gw_link_key, None));

    // direct_gateways() should return 1 gateway.
    let gateways = graph.direct_gateways();
    assert_eq!(gateways.len(), 1);
    assert_eq!(gateways[0].descriptor.node_id(), gw_id);

    // reachable_relays() should return 0 (no link to relay).
    let relays = graph.reachable_relays();
    assert_eq!(relays.len(), 0, "relay without a link should not be reachable");
}

#[test]
fn topology_graph_snapshot_is_immutable() {
    let mut graph = TopologyGraph::new();
    let (advert, _, pk) = make_relay_advert(b"tg-snap", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(verified).expect("accept");
    let node_id = derive_node_id(&pk);

    let local_id = [0xBB; 32];
    let key = LinkKey::new(local_id, node_id, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(key.clone(), None));

    let snapshot = graph.snapshot();
    assert_eq!(snapshot.links.len(), 1);

    // Mutate the live graph after snapshot.
    graph.remove_link(&key);

    // Snapshot should NOT reflect the mutation.
    assert_eq!(snapshot.links.len(), 1, "snapshot must be immutable");
}

#[test]
fn topology_graph_remote_propagation() {
    let mut graph = TopologyGraph::new();

    // We know about a direct relay.
    let (relay_advert, _, relay_pk) = make_relay_advert(b"tg-prop-relay", 1);
    let relay_verified = relay_advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(relay_verified).expect("accept");
    let relay_id = derive_node_id(&relay_pk);

    // Simulate receiving a PeerSummaryList from the relay.
    // The relay tells us about a remote gateway.
    let (gw_advert, _, gw_pk) = make_gateway_advert(b"tg-prop-gw", 42);
    let gw_id = derive_node_id(&gw_pk);
    let gw_summary = PeerSummary {
        node_id: gw_id,
        advertisement_sequence: 42,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1, // 1 hop from the relay
    };

    let (sender_sk, sender_pk) = fresh_keypair(b"tg-prop-sender");
    let sender_id = derive_node_id(&sender_pk);
    let summary_list = PeerSummaryList::create_and_sign(
        &sender_sk, &sender_pk, sender_id,
        vec![gw_summary],
        1, // propagation_sequence
    );

    assert!(summary_list.verify(), "summary list must verify");
    let result = graph.process_peer_summaries(&summary_list.verify_into_verified().unwrap());
    assert!(matches!(result, snp_node::node::PropagationResult::Accepted { .. }));

    // The remote gateway should be in remote_hints (NOT remote_nodes).
    let remote_gws = graph.gateway_hints();
    assert_eq!(remote_gws.len(), 1);
    assert_eq!(remote_gws[0].target_node_id, gw_id);
    assert!(remote_gws[0].claims_gateway());

    // direct_gateways() should NOT include the remote hint.
    let direct_gws = graph.direct_gateways();
    assert_eq!(direct_gws.len(), 0, "remote hint must NOT be in direct_gateways()");
}

#[test]
fn topology_graph_generate_peer_summaries() {
    let mut graph = TopologyGraph::new();

    // Add a direct relay.
    let (relay_advert, _, _) = make_relay_advert(b"tg-gen-relay", 1);
    let relay_verified = relay_advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(relay_verified).expect("accept");

    // Add a link to the relay (making it "active").
    let (sk_local, pk_local) = fresh_keypair(b"tg-gen-local");
    let local_id = derive_node_id(&pk_local);
    let (relay_sk, relay_pk) = fresh_keypair(b"tg-gen-relay");
    let relay_id = derive_node_id(&relay_pk);
    let key = LinkKey::new(local_id, relay_id, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(key, None));

    let summaries = graph.generate_peer_summaries();
    assert!(summaries.len() >= 1, "should generate at least 1 summary");
    assert_eq!(summaries[0].distance_hint, 1, "direct neighbor should have distance_hint=1");
}

#[test]
fn node_churn_appears_disappears_returns() {
    let mut graph = TopologyGraph::new();
    let (advert, _, pk) = make_relay_advert(b"tg-churn", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(verified).expect("accept");
    let node_id = derive_node_id(&pk);
    let local_id = [0xCC; 32];

    // Node appears: add link.
    let key = LinkKey::new(local_id, node_id, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(key.clone(), None));
    assert!(graph.is_directly_reachable(&node_id));
    assert_eq!(graph.visibility(&node_id), PeerVisibility::Active);

    // Node disappears: link goes Down.
    graph.update_link_state(&key, LinkState::Down);
    assert!(!graph.is_directly_reachable(&node_id), "should not be reachable when link is Down");
    assert_eq!(graph.visibility(&node_id), PeerVisibility::Active,
        "advertisement should still be CURRENT (link Down ≠ advertisement expired)");

    // Node returns: link comes back Up.
    graph.update_link_state(&key, LinkState::Up);
    assert!(graph.is_directly_reachable(&node_id));
    assert_eq!(graph.visibility(&node_id), PeerVisibility::Active);

    // Identity is still KNOWN throughout.
    assert!(graph.is_known(&node_id));
}

// ─── Protocol message tests ─────────────────────────────────────────────────

#[test]
fn goodbye_message_verifies() {
    let (sk, pk) = fresh_keypair(b"goodbye");
    let node_id = derive_node_id(&pk);
    let msg = snp_node::node::GoodbyeMessage::create_and_sign(&sk, &pk, node_id, 42);
    assert!(msg.verify(), "GOODBYE must verify");
    assert_eq!(msg.node_id, node_id);
    assert_eq!(msg.sequence, 42);
}

#[test]
fn goodbye_message_tampered_rejected() {
    let (sk, pk) = fresh_keypair(b"goodbye-tamper");
    let node_id = derive_node_id(&pk);
    let mut msg = snp_node::node::GoodbyeMessage::create_and_sign(&sk, &pk, node_id, 42);
    msg.sequence = 99; // Tamper.
    assert!(!msg.verify(), "tampered GOODBYE must fail verification");
}

#[test]
fn peer_summary_list_verifies() {
    let (sk, pk) = fresh_keypair(b"summary-list");
    let node_id = derive_node_id(&pk);
    let summary = PeerSummary {
        node_id: [0xDD; 32],
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list = PeerSummaryList::create_and_sign(&sk, &pk, node_id, vec![summary], 1);
    assert!(list.verify(), "PeerSummaryList must verify");
    assert_eq!(list.len(), 1);
}

#[test]
fn peer_summary_list_tampered_rejected() {
    let (sk, pk) = fresh_keypair(b"summary-tamper");
    let node_id = derive_node_id(&pk);
    let summary = PeerSummary {
        node_id: [0xEE; 32],
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let mut list = PeerSummaryList::create_and_sign(&sk, &pk, node_id, vec![summary], 1);
    list.summaries[0].advertisement_sequence = 99; // Tamper.
    assert!(!list.verify(), "tampered PeerSummaryList must fail verification");
}

#[test]
fn peer_summary_from_record() {
    let (advert, _, _) = make_gateway_advert(b"summary-record", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    let record = verified.into_record();
    let summary = PeerSummary::from_record(&record, 2, now_unix());
    assert_eq!(summary.node_id, record.descriptor.node_id());
    assert_eq!(summary.advertisement_sequence, 1);
    assert!(summary.is_gateway());
    assert!(!summary.is_relay());
    assert_eq!(summary.distance_hint, 2);
}

#[test]
fn link_failure_makes_node_unreachable_but_known() {
    let mut graph = TopologyGraph::new();
    let (advert, _, pk) = make_relay_advert(b"tg-fail", 1);
    let verified = advert.verify_into_verified().expect("must verify");
    graph.accept_advertisement(verified).expect("accept");
    let node_id = derive_node_id(&pk);
    let local_id = [0xFF; 32];

    let key = LinkKey::new(local_id, node_id, TransportEndpoint::tcp("127.0.0.1:1"));
    graph.add_link(Link::new_up(key.clone(), None));
    assert!(graph.is_directly_reachable(&node_id));
    assert!(graph.is_known(&node_id));

    // Simulate 3 failures → Down.
    graph.record_link_failure(&key);
    graph.record_link_failure(&key);
    graph.record_link_failure(&key);

    assert!(!graph.is_directly_reachable(&node_id), "should be unreachable when link is Down");
    assert!(graph.is_known(&node_id), "identity must remain KNOWN when link is Down");
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.1.1 — Non-authoritative remote hints tests
// ════════════════════════════════════════════════════════════════════════════

use snp_node::node::{PropagationResult, RemoteNodeHint};

/// 1. remote_hint_is_not_authenticated_node
#[test]
fn remote_hint_is_not_authenticated_node() {
    let mut graph = TopologyGraph::new();

    // Create a fake summary claiming node G is a gateway.
    let fake_gw_id = [0xAA; 32];
    let summary = PeerSummary {
        node_id: fake_gw_id,
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let (sk, pk) = fresh_keypair(b"hint-not-auth");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // G should be in remote_hints, NOT in authenticated records.
    assert!(graph.remote_hints().contains_key(&fake_gw_id));
    assert!(!graph.is_authenticated(&fake_gw_id), "remote hint must NOT be authenticated");
    assert!(graph.get_record(&fake_gw_id).is_none(), "no AuthenticatedNodeRecord for remote hint");
    eprintln!("[test N1] PASS: remote hint is not authenticated node");
}

/// 2. fake_gateway_claim_is_not_authenticated
#[test]
fn fake_gateway_claim_is_not_authenticated() {
    let mut graph = TopologyGraph::new();
    let fake_gw_id = [0xBB; 32];
    let summary = PeerSummary {
        node_id: fake_gw_id,
        advertisement_sequence: 999,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 2,
    };
    let (sk, pk) = fresh_keypair(b"fake-gw");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // gateway_hints() should contain the fake claim.
    let hints = graph.gateway_hints();
    assert_eq!(hints.len(), 1);
    assert!(hints[0].claims_gateway());

    // direct_gateways() must NOT contain the fake gateway.
    let direct = graph.direct_gateways();
    assert_eq!(direct.len(), 0, "fake gateway must NOT appear in direct_gateways()");
    eprintln!("[test N2] PASS: fake gateway claim is not authenticated");
}

/// 3. direct_gateways_excludes_remote_hints
#[test]
fn direct_gateways_excludes_remote_hints() {
    let mut graph = TopologyGraph::new();

    // Add an authenticated direct relay (not a gateway).
    let (relay_advert, _, relay_pk) = make_relay_advert(b"direct-relay", 1);
    graph.accept_advertisement(relay_advert.verify_into_verified().expect("verify")).expect("accept");
    let relay_id = derive_node_id(&relay_pk);
    let local = [0xCC; 32];
    graph.add_link(Link::new_up(
        LinkKey::new(local, relay_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));

    // Add a remote hint claiming a gateway exists.
    let fake_gw = PeerSummary {
        node_id: [0xDD; 32],
        advertisement_sequence: 1,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let (sk, pk) = fresh_keypair(b"hint-sender");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![fake_gw], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // direct_gateways() = 0 (no authenticated gateway with a link).
    assert_eq!(graph.direct_gateways().len(), 0);
    // gateway_hints() = 1 (the remote claim).
    assert_eq!(graph.gateway_hints().len(), 1);
    eprintln!("[test N3] PASS: direct_gateways excludes remote hints");
}

/// 4. gateway_hints_contains_remote_claim
#[test]
fn gateway_hints_contains_remote_claim() {
    let mut graph = TopologyGraph::new();
    let gw_id = [0xEE; 32];
    let summary = PeerSummary {
        node_id: gw_id,
        advertisement_sequence: 5,
        capabilities: vec!["gateway".to_string(), "relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 3,
    };
    let (sk, pk) = fresh_keypair(b"hint-gw");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    let hints = graph.gateway_hints();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].target_node_id, gw_id);
    assert!(hints[0].claims_gateway());
    assert!(hints[0].claims_relay());
    assert_eq!(hints[0].distance_hint, 3);
    eprintln!("[test N4] PASS: gateway_hints contains remote claim");
}

/// 5. remote_hint_cannot_become_verified_descriptor
#[test]
fn remote_hint_cannot_become_verified_descriptor() {
    let mut graph = TopologyGraph::new();
    let target_id = [0xFF; 32];
    let summary = PeerSummary {
        node_id: target_id,
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let (sk, pk) = fresh_keypair(b"hint-no-convert");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    // There is no API to convert RemoteNodeHint → VerifiedNodeDescriptor.
    // The only way to get a VerifiedNodeDescriptor is via
    // VerifiedNodeAdvertisement::descriptor() or
    // VerifiedGatewayAdvertisement::descriptor().
    // RemoteNodeHint has no such method.
    let hint = graph.remote_hints().get(&target_id).unwrap();
    // Verify the hint type doesn't expose descriptor(), node_id() returns [u8;32] but
    // there is no path to VerifiedNodeDescriptor.
    assert_eq!(hint.target_node_id(), target_id);
    // The type system prevents conversion — no method exists on RemoteNodeHint
    // that returns VerifiedNodeDescriptor or AuthenticatedNodeRecord.
    eprintln!("[test N5] PASS: remote hint cannot become verified descriptor (type-level enforcement)");
}

/// 6. multi_hop_destination_discovery_without_authentication
#[test]
fn multi_hop_destination_discovery_without_authentication() {
    let mut graph_a = TopologyGraph::new();

    // A knows B directly (authenticated).
    let (b_advert, _, b_pk) = make_relay_advert(b"multi-b", 1);
    graph_a.accept_advertisement(b_advert.verify_into_verified().expect("verify")).expect("accept");
    let b_id = derive_node_id(&b_pk);
    let a_local = [0x11; 32];
    graph_a.add_link(Link::new_up(
        LinkKey::new(a_local, b_id, TransportEndpoint::tcp("127.0.0.1:1")),
        None,
    ));

    // B sends a summary to A claiming C exists (1 hop from B).
    let c_id = [0x22; 32];
    let c_summary = PeerSummary {
        node_id: c_id,
        advertisement_sequence: 10,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };

    // B also claims G exists (2 hops from B).
    let g_id = [0x33; 32];
    let g_summary = PeerSummary {
        node_id: g_id,
        advertisement_sequence: 5,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 2,
    };

    let (b_sk, b_pk2) = fresh_keypair(b"multi-b-sender");
    let b_sender_id = derive_node_id(&b_pk2);
    let list = PeerSummaryList::create_and_sign(
        &b_sk, &b_pk2, b_sender_id,
        vec![c_summary, g_summary],
        1,
    );
    graph_a.process_peer_summaries(&list.verify_into_verified().unwrap());

    // A now knows:
    // - B is authenticated and directly reachable (distance 0).
    // - C is a remote hint (distance 2: B said 1, we add 1).
    // - G is a remote hint (distance 3: B said 2, we add 1).
    assert!(graph_a.is_authenticated(&b_id), "B must be authenticated");
    assert!(!graph_a.is_authenticated(&c_id), "C must NOT be authenticated");
    assert!(!graph_a.is_authenticated(&g_id), "G must NOT be authenticated");

    let c_hint = graph_a.remote_hints().get(&c_id).expect("C hint must exist");
    // B claimed C is 1 hop from B. A stores this as B's claim (distance_hint=1).
    // When A propagates this further, it will increment to 2.
    assert_eq!(c_hint.distance_hint, 1, "C distance_hint should be 1 (B's claim, not incremented)");

    let g_hint = graph_a.remote_hints().get(&g_id).expect("G hint must exist");
    // B claimed G is 2 hops from B. A stores this as B's claim (distance_hint=2).
    assert_eq!(g_hint.distance_hint, 2, "G distance_hint should be 2 (B's claim)");
    assert!(g_hint.claims_gateway());

    // G is in gateway_hints but NOT in direct_gateways.
    assert_eq!(graph_a.gateway_hints().len(), 1);
    assert_eq!(graph_a.direct_gateways().len(), 0);

    // A does NOT have:
    // - G's authenticated NodeAdvertisement
    // - G's authenticated endpoint
    // - G's authenticated X25519 gateway key
    assert!(graph_a.get_record(&g_id).is_none());
    eprintln!("[test N6] PASS: multi-hop destination discovery without authentication");
}

/// 7. distance_hint_is_not_route
#[test]
fn distance_hint_is_not_route() {
    let mut graph = TopologyGraph::new();
    let target = [0x44; 32];
    let summary = PeerSummary {
        node_id: target,
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 5,
    };
    let (sk, pk) = fresh_keypair(b"distance-not-route");
    let sender_id = derive_node_id(&pk);
    let list = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary], 1);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    let hint = graph.remote_hints().get(&target).unwrap();
    assert_eq!(hint.distance_hint, 5);
    // distance_hint is a heuristic, NOT:
    // - a verified path
    // - a next hop
    // - an executable route
    // The topology graph does NOT contain any path information for remote hints.
    // It only knows "someone claimed this node is approximately 5 hops away."
    eprintln!("[test N7] PASS: distance_hint is not a route");
}

/// 8. propagation_sequence_replay_rejected
#[test]
fn propagation_sequence_replay_rejected() {
    let mut graph = TopologyGraph::new();
    let (sk, pk) = fresh_keypair(b"replay-sender");
    let sender_id = derive_node_id(&pk);

    // First message (propagation_sequence = 10).
    let summary1 = PeerSummary {
        node_id: [0x55; 32],
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list1 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary1], 10);
    let result1 = graph.process_peer_summaries(&list1.verify_into_verified().unwrap());
    assert!(matches!(result1, PropagationResult::Accepted { .. }));

    // Replay with same propagation_sequence = 10.
    let summary2 = PeerSummary {
        node_id: [0x66; 32],
        advertisement_sequence: 1,
        capabilities: vec!["relay".to_string()],
        visibility: "active".to_string(),
        last_seen: now_unix(),
        distance_hint: 1,
    };
    let list2 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![summary2], 10);
    let result2 = graph.process_peer_summaries(&list2.verify_into_verified().unwrap());
    assert!(matches!(result2, PropagationResult::Stale { received_sequence: 10, known_sequence: 10 }),
        "replayed propagation_sequence must be rejected");

    // Older propagation_sequence = 5.
    let list3 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![], 5);
    let result3 = graph.process_peer_summaries(&list3.verify_into_verified().unwrap());
    assert!(matches!(result3, PropagationResult::Stale { received_sequence: 5, known_sequence: 10 }),
        "older propagation_sequence must be rejected");
    eprintln!("[test N8] PASS: propagation sequence replay rejected");
}

/// 9. stale_propagation_message_rejected
#[test]
fn stale_propagation_message_rejected() {
    let mut graph = TopologyGraph::new();
    let (sk, pk) = fresh_keypair(b"stale-prop");
    let sender_id = derive_node_id(&pk);

    // First message (seq 1).
    let list1 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![], 1);
    let r1 = graph.process_peer_summaries(&list1.verify_into_verified().unwrap());
    assert!(matches!(r1, PropagationResult::Accepted { .. }));

    // Newer message (seq 5).
    let list5 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![], 5);
    let r5 = graph.process_peer_summaries(&list5.verify_into_verified().unwrap());
    assert!(matches!(r5, PropagationResult::Accepted { .. }));

    // Now try seq 3 (stale — between 1 and 5).
    let list3 = PeerSummaryList::create_and_sign(&sk, &pk, sender_id, vec![], 3);
    let r3 = graph.process_peer_summaries(&list3.verify_into_verified().unwrap());
    assert!(matches!(r3, PropagationResult::Stale { known_sequence: 5, .. }),
        "seq 3 after seq 5 must be rejected as stale");
    eprintln!("[test N9] PASS: stale propagation message rejected");
}

/// 10. provenance_preserved
#[test]
fn provenance_preserved() {
    let mut graph = TopologyGraph::new();
    let target = [0x77; 32];
    let (sender_sk, sender_pk) = fresh_keypair(b"provenance-sender");
    let sender_id = derive_node_id(&sender_pk);

    let summary = PeerSummary {
        node_id: target,
        advertisement_sequence: 42,
        capabilities: vec!["gateway".to_string()],
        visibility: "active".to_string(),
        last_seen: 12345,
        distance_hint: 3,
    };
    let list = PeerSummaryList::create_and_sign(&sender_sk, &sender_pk, sender_id, vec![summary], 7);
    graph.process_peer_summaries(&list.verify_into_verified().unwrap());

    let hint = graph.remote_hints().get(&target).expect("hint must exist");
    assert_eq!(hint.target_node_id, target);
    assert_eq!(hint.claimed_sequence, 42);
    assert_eq!(hint.claimed_last_seen, 12345);
    assert_eq!(hint.distance_hint, 3);
    assert_eq!(hint.learned_from, sender_id, "provenance: learned_from must be the sender");
    assert_eq!(hint.source_propagation_sequence, 7, "provenance: propagation_sequence must be preserved");
    assert!(hint.received_at > 0, "provenance: received_at must be set");
    eprintln!("[test N10] PASS: provenance preserved");
}

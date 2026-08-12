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
    );

    assert!(summary_list.verify(), "summary list must verify");
    graph.process_peer_summaries(&summary_list);

    // The remote gateway should be in remote_nodes.
    let remote_gws = graph.remote_gateways();
    assert_eq!(remote_gws.len(), 1);
    assert_eq!(remote_gws[0].summary.node_id, gw_id);
    assert!(remote_gws[0].summary.is_gateway());

    // all_known_gateways() should include both direct and remote.
    let all_gws = graph.all_known_gateways();
    assert_eq!(all_gws.len(), 1, "should know about 1 gateway (remote)");
    assert_eq!(all_gws[0].0, gw_id);
    assert!(!all_gws[0].1, "should be remote, not direct");
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
    let list = PeerSummaryList::create_and_sign(&sk, &pk, node_id, vec![summary]);
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
    let mut list = PeerSummaryList::create_and_sign(&sk, &pk, node_id, vec![summary]);
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

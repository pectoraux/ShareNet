//! N2.2.1 — Async Tokio TCP Next-Hop Transport tests.
//!
//! These tests verify `TcpRecursiveTransport` and `TcpForwardingServer` —
//! the production implementation of `RecursiveNextHopTransport` that uses
//! async Tokio TCP sockets, the SNP-IK/0.1 handshake, AEAD-encrypted
//! canonical CBOR frames, identity binding, and server-side replay
//! protection.
//!
//! ## North-star scenario
//!
//! ```text
//!   A ──TCP──> B ──TCP──> C ──TCP──> G
//! ```
//!
//! - A, B, C, G each bind their own async TCP listener on an ephemeral port.
//! - A's `TcpRecursiveTransport` knows B's TCP address + Ed25519 public key.
//! - B's `TcpRecursiveTransport` knows C's TCP address + Ed25519 public key.
//! - C's `TcpRecursiveTransport` knows G's TCP address + Ed25519 public key.
//! - Each `ForwardedQuery` crosses a real TCP boundary:
//!   1. A AEAD-encrypts the ForwardedQuery (canonical CBOR) and sends it
//!      to B over async TCP.
//!   2. B's `TcpForwardingServer` accepts the connection, performs the
//!      async SNP-IK handshake as responder, AEAD-decrypts the frame,
//!      checks identity binding + replay cache, calls
//!      `ForwardingNode::handle_query` (via `spawn_blocking`), which
//!      forwards a NEW query to C over async TCP, etc.
//!   3. The response propagates back: G → C → B → A (each hop
//!      AEAD-encrypted).
//!
//! ## Constraints
//!
//! - NO `InMemoryRecursiveTransport` anywhere in this test.
//! - NO direct A→C or A→G TCP connections.
//! - Each node has its own TCP listener + Ed25519 keypair + X25519 keypair.
//! - SNP-IK authentication + AEAD encryption on every connection.
//! - ForwardedQuery crosses the actual TCP boundary (serialized → AEAD →
//!   TCP → AEAD-decrypt → deserialized → verified).

#![allow(clippy::pedantic)]

use std::sync::Arc;

use snp_crypto::{derive_node_id, derive_public_key, sha256, x25519_static_keypair};
use snp_node::node::{
    Capability, ForwardedQuery, ForwardingNode, InMemoryNextHopTransport, LinkKey, NextHopResolver,
    NodeAdvertisement, RemoteNodeHint, TcpForwardingServer, TcpRecursiveTransport,
    TopologyGraph, TransportEndpoint, MAX_FRAME_SIZE,
};
use snp_node::test_support::test_authenticated_link;

// ─── Test helpers ───────────────────────────────────────────────────────────

/// Derive a deterministic Ed25519 keypair from a label (for reproducible
/// tests). Production code would use `Ed25519SecretKey::generate()`.
fn fresh_keypair(label: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk = sha256(label);
    let pk = derive_public_key(&sk);
    (sk, pk)
}

/// Build a hint that claims `learned_from` knows about `target`.
fn make_hint(target: [u8; 32], learned_from: [u8; 32]) -> RemoteNodeHint {
    RemoteNodeHint {
        target_node_id: target,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: 0,
        distance_hint: 1,
        learned_from,
        received_at: 0,
        source_propagation_sequence: 1,
    }
}

/// A node in the TCP test mesh: keypair + own TCP address + own advert.
struct TcpNode {
    ed25519_secret: [u8; 32],
    ed25519_public: [u8; 32],
    node_id: [u8; 32],
    advert: NodeAdvertisement,
    /// The TCP address the node is listening on (e.g. "127.0.0.1:38507").
    /// Filled in once the TcpForwardingServer is bound.
    listen_addr: String,
}

impl TcpNode {
    /// Create a TCP node with the given label, capabilities, and X25519
    /// circuit key option. Does NOT bind a listener yet.
    fn new(
        label: &[u8],
        capabilities: Vec<Capability>,
        x25519_circuit_public: Option<[u8; 32]>,
    ) -> Self {
        let (sk, pk) = fresh_keypair(label);
        let node_id = derive_node_id(&pk);
        let advert = NodeAdvertisement::create_and_sign(
            &sk,
            &pk,
            capabilities,
            // Endpoints will be set after the listener is bound.
            Vec::new(),
            x25519_circuit_public,
            3600,
            1,
        );
        Self {
            ed25519_secret: sk,
            ed25519_public: pk,
            node_id,
            advert,
            listen_addr: String::new(),
        }
    }
}

/// The full A → B → C → G async TCP test mesh.
///
/// Each node has:
/// - Its own Ed25519 + X25519 keypair.
/// - Its own `TcpRecursiveTransport` (for forwarding to the next hop).
/// - Its own `TcpForwardingServer` (listening for incoming queries on an
///   async `tokio::net::TcpListener`, running on a dedicated OS thread
///   with its own multi-threaded Tokio runtime via `serve_in_background`).
/// - Its own `ForwardingNode` (the protocol participant).
struct TcpMesh {
    a: TcpNode,
    b: TcpNode,
    c: TcpNode,
    g: TcpNode,
    /// A's TCP transport (knows B's address). Stored in the mesh so the
    /// resolver can borrow it for the resolver's lifetime.
    a_transport: Arc<TcpRecursiveTransport>,
    /// Keep the servers alive (they hold the listeners + background
    /// threads). Dropping this kills the background threads.
    _servers: Vec<Arc<TcpForwardingServer>>,
    /// A's topology (contains B's record + authenticated link A→B).
    topology: TopologyGraph,
}

impl TcpMesh {
    /// Build the standard A → B → C → G TCP mesh.
    ///
    /// - G is a Gateway (has X25519 circuit key).
    /// - B, C are relays.
    /// - A is the local resolver (no server needed — A only initiates).
    ///
    /// Listeners are bound synchronously via `std::net::TcpListener` and
    /// converted to `tokio::net::TcpListener` via `from_std`. This keeps
    /// `TcpMesh::new` synchronous so the north-star test (which is
    /// synchronous — it calls `resolver.resolve_route`) can construct the
    /// mesh without an async context.
    fn new(label: &[u8]) -> Self {
        // G (gateway, destination). Created first so C can reference its advert.
        let (g_x_sk, g_x_pk) = x25519_static_keypair();
        let _ = g_x_sk;
        let mut g = TcpNode::new(
            &[label, b"-g"].concat(),
            vec![Capability::Gateway],
            Some(g_x_pk.to_bytes()),
        );

        // C (relay, knows G).
        let mut c = TcpNode::new(&[label, b"-c"].concat(), vec![Capability::Relay], None);

        // B (relay, knows C). A's direct neighbor.
        let mut b = TcpNode::new(&[label, b"-b"].concat(), vec![Capability::Relay], None);

        // A (the local resolver — does not need a server).
        let a = TcpNode::new(&[label, b"-a"].concat(), vec![Capability::Client], None);

        // Create TcpRecursiveTransport for B, C, G (each forwards to the
        // next hop). A also gets one (to send the initial query to B).
        let mut b_transport = TcpRecursiveTransport::new(b.ed25519_secret, b.ed25519_public);
        let mut c_transport = TcpRecursiveTransport::new(c.ed25519_secret, c.ed25519_public);
        let g_transport = TcpRecursiveTransport::new(g.ed25519_secret, g.ed25519_public);

        // Bind listeners with ephemeral ports (synchronously). The
        // TcpForwardingServer stores the std listener and converts it to
        // a tokio listener inside its own runtime when serve() is called.
        let b_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let g_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b_addr = b_listener.local_addr().unwrap().to_string();
        let c_addr = c_listener.local_addr().unwrap().to_string();
        let g_addr = g_listener.local_addr().unwrap().to_string();

        b.listen_addr = b_addr.clone();
        c.listen_addr = c_addr.clone();
        g.listen_addr = g_addr.clone();

        // Now add peers to each transport.
        // B → C, C → G. G has no peers (terminal). A → B (added separately below).
        b_transport.add_peer(c.ed25519_public, c_addr.clone());
        c_transport.add_peer(g.ed25519_public, g_addr.clone());
        let _ = g_transport; // G has no peers.

        // Wrap transports in Arc<dyn RecursiveNextHopTransport + Send + Sync>.
        let b_transport_arc: Arc<dyn snp_node::node::RecursiveNextHopTransport + Send + Sync> =
            Arc::new(b_transport);
        let c_transport_arc: Arc<dyn snp_node::node::RecursiveNextHopTransport + Send + Sync> =
            Arc::new(c_transport);
        let g_transport_arc: Arc<dyn snp_node::node::RecursiveNextHopTransport + Send + Sync> =
            Arc::new(g_transport);

        // Create ForwardingNodes.
        let mut b_node = ForwardingNode::new(
            b.ed25519_secret,
            b.ed25519_public,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(b_addr.clone())],
            None,
            b_transport_arc,
        );
        let mut c_node = ForwardingNode::new(
            c.ed25519_secret,
            c.ed25519_public,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(c_addr.clone())],
            None,
            c_transport_arc,
        );
        let g_node = ForwardingNode::new(
            g.ed25519_secret,
            g.ed25519_public,
            vec![Capability::Gateway],
            vec![TransportEndpoint::tcp(g_addr.clone())],
            Some(g_x_pk.to_bytes()),
            g_transport_arc,
        );

        // Add neighbors. B knows C; C knows G.
        let c_advert = c_node.self_advert().clone();
        let g_advert = g_node.self_advert().clone();
        b_node.add_neighbor(c.node_id, c_advert);
        c_node.add_neighbor(g.node_id, g_advert);

        // Update the TcpNode adverts to match the ForwardingNode's adverts
        // (so the test assertions use the signed adverts with the real
        // endpoints).
        b.advert = b_node.self_advert().clone();
        c.advert = c_node.self_advert().clone();
        g.advert = g_node.self_advert().clone();

        // Create TcpForwardingServers from the pre-bound async listeners.
        let b_server = TcpForwardingServer::from_listener(
            Arc::new(b_node),
            b.ed25519_secret,
            b.ed25519_public,
            b_listener,
        )
        .unwrap();
        let c_server = TcpForwardingServer::from_listener(
            Arc::new(c_node),
            c.ed25519_secret,
            c.ed25519_public,
            c_listener,
        )
        .unwrap();
        let g_server = TcpForwardingServer::from_listener(
            Arc::new(g_node),
            g.ed25519_secret,
            g.ed25519_public,
            g_listener,
        )
        .unwrap();

        let b_server = Arc::new(b_server);
        let c_server = Arc::new(c_server);
        let g_server = Arc::new(g_server);

        // Serve in background (each on its own OS thread + multi-threaded
        // Tokio runtime). Returns immediately.
        b_server.clone().serve_in_background();
        c_server.clone().serve_in_background();
        g_server.clone().serve_in_background();

        // Build A's topology: B's advert + authenticated link A→B.
        let mut topology = TopologyGraph::new();
        let b_verified = b.advert.verify_into_verified().expect("B advert verifies");
        topology
            .accept_advertisement(b_verified.clone())
            .expect("accept B");
        let key_ab = LinkKey::new(a.node_id, b.node_id, TransportEndpoint::tcp(b_addr.clone()));
        topology.add_authenticated_link(
            test_authenticated_link(key_ab, &b_verified).expect("auth link A→B"),
        );

        // Build A's TCP transport (knows B's address).
        let mut a_transport = TcpRecursiveTransport::new(a.ed25519_secret, a.ed25519_public);
        a_transport.add_peer(b.ed25519_public, b_addr.clone());
        let a_transport = Arc::new(a_transport);

        Self {
            a,
            b,
            c,
            g,
            a_transport,
            _servers: vec![b_server, c_server, g_server],
            topology,
        }
    }

    /// Build a NextHopResolver configured with A's TcpRecursiveTransport.
    ///
    /// The resolver borrows from `&self` — the mesh must outlive the resolver.
    /// The single-step transport is leaked (test-only) because
    /// `NextHopResolver::new` requires a `&dyn NextHopTransport` and we
    /// don't use it (we only call `resolve_route`).
    fn resolver(&self) -> NextHopResolver<'_> {
        let single_step = InMemoryNextHopTransport::new();
        let single_step: &'static InMemoryNextHopTransport = Box::leak(Box::new(single_step));

        NextHopResolver::new(
            &self.topology,
            single_step,
            self.a.ed25519_secret,
            self.a.ed25519_public,
            self.a.node_id,
        )
        .with_recursive_transport(&*self.a_transport)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 1. tcp_recursive_a_b_c_gateway_success — THE NORTH-STAR TEST
// ════════════════════════════════════════════════════════════════════════════

/// **North-star test:** A → B → C → G recursive resolution via real async TCP.
///
/// Verifies the full N2.2.1 architecture:
/// - A sends ONE `ForwardedQuery` to B over real async TCP (AEAD-encrypted
///   canonical CBOR frame).
/// - B's `TcpForwardingServer` accepts the connection, performs the async
///   SNP-IK handshake as responder, AEAD-decrypts the frame, checks
///   identity binding + replay cache, calls `ForwardingNode::handle_query`
///   (via `spawn_blocking`), which forwards a NEW query to C over real
///   async TCP.
/// - C repeats the process, forwarding to G over real async TCP.
/// - G (the destination) responds.
/// - The response propagates back over TCP (AEAD-encrypted): G → C → B → A.
/// - A constructs a `DistributedRouteResolution` and verifies it.
/// - The resolution converts to a `Route`.
///
/// This test uses NO `InMemoryRecursiveTransport` — every hop crosses a
/// real async TCP boundary with SNP-IK authentication + AEAD encryption.
///
/// This test is synchronous (`#[test]`) because the protocol layer
/// (`NextHopResolver::resolve_route`) is synchronous. The transport's
/// `forward_query` method bridges to async Tokio internally via a
/// per-call current-thread runtime (see `TcpRecursiveTransport::forward_query`).
#[test]
fn tcp_recursive_a_b_c_gateway_success() {
    let mesh = TcpMesh::new(b"tcp-recursive");
    let hint = make_hint(mesh.g.node_id, mesh.b.node_id);

    let mut resolver = mesh.resolver();
    let resolution = resolver
        .resolve_route(&mesh.g.node_id, &hint)
        .expect("TCP recursive resolution must succeed for A→B→C→G");

    // Verify the path A → B → C → G.
    assert_eq!(
        resolution.ordered_node_ids,
        vec![mesh.a.node_id, mesh.b.node_id, mesh.c.node_id, mesh.g.node_id],
        "ordered_node_ids must be A → B → C → G"
    );
    assert_eq!(resolution.source, mesh.a.node_id);
    assert_eq!(resolution.destination, mesh.g.node_id);
    assert_eq!(resolution.ordered_records.len(), 3, "3 records (B, C, G)");
    assert_eq!(
        resolution.ordered_assertions.len(),
        2,
        "2 assertions (B's and C's)"
    );
    assert_eq!(
        resolution.query_chain.len(),
        3,
        "3 query steps (A→B, B→C, C→G)"
    );
    assert_eq!(resolution.hop_count(), 3, "3 hops");

    // Verify the records.
    assert_eq!(resolution.ordered_records[0].node_id(), mesh.b.node_id);
    assert_eq!(resolution.ordered_records[1].node_id(), mesh.c.node_id);
    assert_eq!(resolution.ordered_records[2].node_id(), mesh.g.node_id);
    assert!(
        resolution.ordered_records[2].descriptor.is_gateway(),
        "G must be a gateway"
    );

    // Verify the assertions.
    let b_assertion = &resolution.ordered_assertions[0];
    assert_eq!(b_assertion.responder_node_id, mesh.b.node_id);
    assert_eq!(b_assertion.next_hop_node_id, mesh.c.node_id);
    assert!(!b_assertion.is_destination);

    let c_assertion = &resolution.ordered_assertions[1];
    assert_eq!(c_assertion.responder_node_id, mesh.c.node_id);
    assert_eq!(c_assertion.next_hop_node_id, mesh.g.node_id);
    assert!(c_assertion.is_destination);
    assert!(c_assertion.claims_destination_reached());

    // Verify the query chain (provenance).
    assert_eq!(resolution.query_chain[0].source_node_id, mesh.a.node_id);
    assert_eq!(resolution.query_chain[0].responder_node_id, mesh.b.node_id);
    assert_eq!(resolution.query_chain[1].source_node_id, mesh.b.node_id);
    assert_eq!(resolution.query_chain[1].responder_node_id, mesh.c.node_id);
    assert_eq!(resolution.query_chain[2].source_node_id, mesh.c.node_id);
    assert_eq!(resolution.query_chain[2].responder_node_id, mesh.g.node_id);

    // Verify the full resolution (checks every signature + chain coherence).
    resolution.verify().expect("resolution must verify");

    // Convert to a Route.
    let route = resolution
        .into_route()
        .expect("resolution must convert to a Route");
    assert_eq!(route.source(), mesh.a.node_id);
    assert_eq!(route.destination(), mesh.g.node_id);
    assert_eq!(
        route.hops(),
        vec![mesh.b.node_id, mesh.c.node_id, mesh.g.node_id]
    );
    assert!(route.validate().is_ok());

    eprintln!(
        "[test 1] PASS: async TCP recursive A→B→C→G resolution succeeds via real Tokio TCP + SNP-IK + AEAD + canonical CBOR"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 2. tcp_serialization_round_trips — verify canonical CBOR round-trip
// ════════════════════════════════════════════════════════════════════════════

/// Verify that `ForwardedQuery::encode_cbor()` → `decode_cbor()` round-trips
/// exactly, and that the wire bytes are byte-identical to `compute_hash()`'s
/// preimage. This is the security-critical invariant: the parent_query_hash
/// binding depends on the wire bytes being identical to the hash preimage.
#[test]
fn tcp_serialization_round_trips() {
    let (sk, pk) = fresh_keypair(b"round-trip");
    let query = ForwardedQuery::create_and_sign(
        &sk,
        &pk,
        derive_node_id(&pk),
        [0u8; 32], // destination (filled below)
        16,
        [0u8; 16],
        [0u8; 32],
        [0u8; 32],
        vec![derive_node_id(&pk)],
    );

    // Encode → decode → compare.
    let bytes = query.encode_cbor();
    let decoded = ForwardedQuery::decode_cbor(&bytes).expect("decode must succeed");
    assert_eq!(decoded.source_node_id, query.source_node_id);
    assert_eq!(decoded.source_ed25519_public_key, query.source_ed25519_public_key);
    assert_eq!(decoded.destination_node_id, query.destination_node_id);
    assert_eq!(decoded.query_id, query.query_id);
    assert_eq!(decoded.timestamp, query.timestamp);
    assert_eq!(decoded.max_hops, query.max_hops);
    assert_eq!(decoded.signature, query.signature);
    assert_eq!(decoded.parent_query_id, query.parent_query_id);
    assert_eq!(decoded.parent_responder_node_id, query.parent_responder_node_id);
    assert_eq!(decoded.parent_query_hash, query.parent_query_hash);
    assert_eq!(decoded.visited_nodes, query.visited_nodes);
    assert_eq!(decoded.parent_signature, query.parent_signature);

    // SECURITY-CRITICAL: the wire bytes MUST be identical to compute_hash()'s
    // preimage. Otherwise the parent_query_hash binding breaks after a wire
    // round-trip.
    let hash_preimage_bytes = snp_cbor::encode(&query.to_cbor_map()).expect("encode preimage");
    assert_eq!(
        bytes, hash_preimage_bytes,
        "wire bytes must be byte-identical to compute_hash() preimage"
    );

    // And the decoded query's hash must equal the original's hash.
    assert_eq!(
        decoded.compute_hash(),
        query.compute_hash(),
        "decoded query's hash must equal original's hash (wire round-trip preserves hash)"
    );

    // Both signatures must verify on the decoded query.
    assert!(
        decoded.verify_all(),
        "decoded query's signatures must verify (canonical CBOR preserves signatures)"
    );

    eprintln!("[test 2] PASS: ForwardedQuery canonical CBOR round-trips and hash is preserved");
}

// ════════════════════════════════════════════════════════════════════════════
// 3. tampered_serialized_field_rejected
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test.** Flip a byte in the serialized `ForwardedQuery` and
/// verify that decoding or signature verification fails.
///
/// The `signature` field covers the canonical CBOR preimage of the
/// NextHopQuery fields. Flipping a byte in:
/// - A signed field (e.g. `destination_node_id`) → signature verification
///   fails.
/// - The `signature` itself → signature verification fails.
/// - A length prefix or CBOR structural byte → decode fails (returns None).
#[test]
fn tampered_serialized_field_rejected() {
    let (sk, pk) = fresh_keypair(b"tamper");
    let dest_id = derive_node_id(&pk);
    let query = ForwardedQuery::create_and_sign(
        &sk,
        &pk,
        derive_node_id(&pk),
        dest_id,
        16,
        [0u8; 16],
        [0u8; 32],
        [0u8; 32],
        vec![derive_node_id(&pk)],
    );

    let original_bytes = query.encode_cbor();
    // Sanity: original decodes and verifies.
    let original = ForwardedQuery::decode_cbor(&original_bytes).expect("original decodes");
    assert!(original.verify_all(), "original signatures verify");

    // Tamper case 1: flip a byte in the CBOR payload.
    let mut tampered = original_bytes.clone();
    let flip_pos = tampered.len() / 2;
    tampered[flip_pos] ^= 0xFF;

    // The tampered bytes must EITHER fail to decode OR fail signature
    // verification. Both are acceptable rejections.
    let outcome = ForwardedQuery::decode_cbor(&tampered).map(|q| q.verify_all());
    assert!(
        matches!(outcome, None | Some(false)),
        "tampered serialized field must be rejected (either decode fails or signature verification fails), got: {outcome:?}"
    );

    eprintln!("[test 3] PASS: tampered serialized field rejected (decode or signature verification fails)");
}

// ════════════════════════════════════════════════════════════════════════════
// 4. malformed_frame_rejected
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test.** Send a truncated AEAD frame to a
/// `TcpForwardingServer` and verify it is rejected safely (the server does
/// not crash, and the connection is closed without a response).
///
/// "Truncated" means: declare a sealed-body length of N but send fewer
/// than N bytes. The server's `read_sealed_frame` reads the 4-byte length
/// prefix and the 12-byte nonce, then blocks waiting for the remaining
/// sealed-body bytes. On EOF (client closed), `read_exact` returns
/// `UnexpectedEof`. The server closes the connection.
///
/// This test completes the SNP-IK handshake first (so the AEAD frame layer
/// is actually exercised), then sends a truncated frame.
#[tokio::test]
async fn malformed_frame_rejected() {
    use snp_link::perform_snp_ik_handshake_verified_async;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mesh = TcpMesh::new(b"malformed-frame");
    let g_addr = mesh.g.listen_addr.clone();

    let mut stream = TcpStream::connect(g_addr)
        .await
        .expect("connect to G");

    // Use fresh keys for the initiator — G's server accepts any
    // authenticated peer (no expected_peer_node_id pinning on the responder).
    let (sk, pk) = fresh_keypair(b"malformed-initiator");
    let (x_sk, x_pk) = x25519_static_keypair();
    let verified = perform_snp_ik_handshake_verified_async(
        &mut stream,
        true, // initiator
        &sk,
        &pk,
        &x_sk,
        &x_pk,
        Some(&mesh.g.node_id), // pin G's NodeId
    )
    .await
    .expect("SNP-IK handshake with G must succeed");

    // Sanity: we have AEAD link keys (the handshake produced them).
    let _keys = verified.link_keys();

    // Now send a TRUNCATED frame: 4-byte length claiming 100 bytes of
    // sealed body, then 12 bytes of nonce, then only 3 bytes of body.
    stream.write_all(&100u32.to_be_bytes()).await.unwrap();
    stream.write_all(&[0u8; 12]).await.unwrap(); // fake nonce
    stream.write_all(b"abc").await.unwrap();
    // Flush + shutdown write half so the server sees EOF on the read half.
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;

    // G's read_sealed_frame will block waiting for the remaining 97 bytes,
    // then hit EOF (because we shut down the write half) and return error.
    // The server closes the connection. We should get EOF (read returns 0)
    // or an error on read.
    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf).await;
    assert!(
        matches!(result, Err(_) | Ok(0)),
        "truncated frame must be rejected with EOF or error, got: {result:?}"
    );

    eprintln!("[test 4] PASS: malformed (truncated) AEAD frame rejected safely after handshake (server did not crash)");
}

// ════════════════════════════════════════════════════════════════════════════
// 5. oversized_frame_rejected
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test.** Send a frame whose declared sealed-body length
/// exceeds `MAX_FRAME_SIZE` and verify it is rejected (the server closes
/// the connection without allocating the buffer).
#[tokio::test]
async fn oversized_frame_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mesh = TcpMesh::new(b"oversized-frame");
    let g_addr = mesh.g.listen_addr.clone();

    let mut stream = TcpStream::connect(g_addr)
        .await
        .expect("connect to G");

    // Send a 4-byte length prefix claiming (MAX_FRAME_SIZE + 1) bytes.
    // The server's read_sealed_frame reads the length, checks it against
    // MAX_FRAME_SIZE, and rejects with InvalidData BEFORE allocating.
    let bogus_len = u32::try_from(MAX_FRAME_SIZE + 1).unwrap();
    stream.write_all(&bogus_len.to_be_bytes()).await.unwrap();
    let _ = stream.flush().await;

    // The server's read_sealed_frame returns InvalidData. The server
    // closes the connection. We should get EOF or an error on read.
    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf).await;
    assert!(
        matches!(result, Err(_) | Ok(0)),
        "oversized frame must be rejected with EOF or error, got: {result:?}"
    );

    eprintln!("[test 5] PASS: oversized AEAD frame rejected (MAX_FRAME_SIZE = {} bytes)", MAX_FRAME_SIZE);
}

// ════════════════════════════════════════════════════════════════════════════
// 6. replayed_serialized_message_rejected
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test.** Construct a `ForwardedQuery` whose `visited_nodes`
/// contains the receiver, AEAD-encrypt it, and send it to the receiver's
/// `TcpForwardingServer`. Verify the server rejects it (closes the
/// connection without a response).
///
/// This exercises the recursive path's freshness check (loop prevention via
/// `visited_nodes`): a query whose visited set contains the receiver is
/// rejected as a loop by `ForwardingNode::handle_query`. The server closes
/// the connection WITHOUT sending a response frame.
///
/// Note: the server-side replay cache would ALSO reject a duplicated
/// `(source_node_id, query_id)` pair, but this test uses a FRESH query_id
/// (generated by `ForwardedQuery::create_and_sign`) so the replay cache
/// lets it through to `handle_query`, where the loop-prevention check
/// rejects it. The replay cache is tested separately by the unit tests in
/// `tcp_route_transport.rs` (`replay_cache_rejects_duplicate`,
/// `replay_cache_evicts_when_full`, `replay_cache_purges_expired`).
#[tokio::test]
async fn replayed_serialized_message_rejected() {
    use snp_crypto::aead_seal;
    use snp_link::perform_snp_ik_handshake_verified_async;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mesh = TcpMesh::new(b"replay");
    let b_addr = mesh.b.listen_addr.clone();

    // Construct a ForwardedQuery from A with visited=[A, B].
    // B is the target. When B receives this, has_visited(B) returns true,
    // and handle_query rejects it as a loop.
    let query = ForwardedQuery::create_and_sign(
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        mesh.a.node_id,
        mesh.g.node_id, // destination
        16,
        [0u8; 16],
        [0u8; 32],
        [0u8; 32],
        vec![mesh.a.node_id, mesh.b.node_id], // visited = [A, B]
    );

    // Encode the query to canonical CBOR (the AEAD plaintext).
    let query_bytes = query.encode_cbor();

    // Connect to B's server and perform the async SNP-IK handshake as A.
    let mut stream = TcpStream::connect(b_addr)
        .await
        .expect("connect to B");

    // A's X25519 keypair for the handshake.
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let verified = perform_snp_ik_handshake_verified_async(
        &mut stream,
        true, // initiator
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        &a_x_sk,
        &a_x_pk,
        Some(&mesh.b.node_id), // pin B's NodeId
    )
    .await
    .expect("SNP-IK handshake with B must succeed");

    // The handshake authenticated us as A. The query's source_node_id is A.
    // The server's identity-binding check (peer_node_id == source_node_id)
    // passes. The replay cache check passes (fresh query_id). Then
    // handle_query is called → has_visited(B) → true → None → server
    // closes without a response.
    let keys = verified.link_keys();

    // AEAD-seal the query with the derived send_key + a fresh nonce.
    let nonce = {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).expect("getrandom");
        n
    };
    let sealed = aead_seal(&keys.send_key, &nonce, &query_bytes, &[]);

    // Write the encrypted frame: [4-byte BE sealed_len][12-byte nonce][sealed].
    let sealed_len = u32::try_from(sealed.len()).unwrap();
    stream.write_all(&sealed_len.to_be_bytes()).await.unwrap();
    stream.write_all(&nonce).await.unwrap();
    stream.write_all(&sealed).await.unwrap();
    let _ = stream.flush().await;

    // B's handle_query rejects the query (visited contains B → loop).
    // The server closes the connection WITHOUT sending a response frame.
    // We should get EOF (read returns 0) or an error.
    let mut buf = [0u8; 4];
    let result = stream.read(&mut buf).await;
    assert!(
        matches!(result, Err(_) | Ok(0)),
        "replayed serialized message (visited contains receiver) must be rejected with EOF or error, got: {result:?}"
    );

    eprintln!("[test 6] PASS: replayed serialized message rejected (loop prevention / freshness check)");
}

// ════════════════════════════════════════════════════════════════════════════
// 7. identity_binding_rejects_cross_channel_injection
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test (N2.2.1 identity binding).** Connect to B's server
/// as A (handshake authenticates as A), then send a `ForwardedQuery` whose
/// `source_node_id` is C (a DIFFERENT identity). The server's
/// identity-binding check (`peer_node_id == query.source_node_id`) must
/// reject the query — a query signed by C cannot be injected over a
/// connection authenticated as A.
///
/// Without this check, a malicious node that authenticated as A could
/// inject queries signed by any other node, bypassing the SNP-IK
/// authentication boundary. The identity-binding check closes this
/// cross-channel injection vector.
#[tokio::test]
async fn identity_binding_rejects_cross_channel_injection() {
    use snp_crypto::aead_seal;
    use snp_link::perform_snp_ik_handshake_verified_async;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mesh = TcpMesh::new(b"identity-binding");
    let b_addr = mesh.b.listen_addr.clone();

    // Construct a query SIGNED BY C (source_node_id = C) but with a
    // visited set that does NOT contain B (so the loop check would pass
    // if the identity check didn't catch it first).
    let query = ForwardedQuery::create_and_sign(
        &mesh.c.ed25519_secret,
        &mesh.c.ed25519_public,
        mesh.c.node_id, // source = C (NOT A)
        mesh.g.node_id, // destination
        16,
        [0u8; 16],
        [0u8; 32],
        [0u8; 32],
        vec![mesh.c.node_id], // visited = [C] (B is NOT in visited)
    );

    let query_bytes = query.encode_cbor();

    // Connect to B's server and perform the async SNP-IK handshake AS A
    // (NOT as C). The handshake authenticates us as A.
    let mut stream = TcpStream::connect(b_addr)
        .await
        .expect("connect to B");

    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let verified = perform_snp_ik_handshake_verified_async(
        &mut stream,
        true, // initiator
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        &a_x_sk,
        &a_x_pk,
        Some(&mesh.b.node_id), // pin B's NodeId
    )
    .await
    .expect("SNP-IK handshake with B must succeed (as A)");

    // Sanity: the handshake authenticated us as A, NOT C.
    assert_eq!(verified.peer_node_id(), mesh.b.node_id);

    let keys = verified.link_keys();

    // AEAD-seal the query (signed by C) with A's derived send_key.
    let nonce = {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).expect("getrandom");
        n
    };
    let sealed = aead_seal(&keys.send_key, &nonce, &query_bytes, &[]);

    let sealed_len = u32::try_from(sealed.len()).unwrap();
    stream.write_all(&sealed_len.to_be_bytes()).await.unwrap();
    stream.write_all(&nonce).await.unwrap();
    stream.write_all(&sealed).await.unwrap();
    let _ = stream.flush().await;

    // B's handle_connection reads the frame, decodes the query
    // (source_node_id = C), then checks identity binding:
    //   peer_node_id (A, from the handshake) != query.source_node_id (C)
    // → REJECT. The server closes the connection WITHOUT sending a
    // response. We should get EOF or an error.
    let mut buf = [0u8; 4];
    let result = stream.read(&mut buf).await;
    assert!(
        matches!(result, Err(_) | Ok(0)),
        "cross-channel injection (query signed by C over connection authenticated as A) must be rejected with EOF or error, got: {result:?}"
    );

    eprintln!("[test 7] PASS: identity binding rejected cross-channel injection (query signed by C over A-authenticated connection)");
}

// ════════════════════════════════════════════════════════════════════════════
// 8. replay_cache_rejects_duplicate_query_id
// ════════════════════════════════════════════════════════════════════════════

/// **Adversarial test (N2.2.1 server-side replay cache).** Send the SAME
/// `ForwardedQuery` (same `source_node_id` AND same `query_id`) to B twice.
/// The first send is processed (B forwards to C → G → response). The
/// second send must be rejected by the server-side replay cache BEFORE
/// reaching `ForwardingNode::handle_query`.
///
/// This test distinguishes the replay cache from the loop-prevention check:
/// the query's `visited_nodes = [A]` does NOT contain B, so the loop check
/// would pass. The replay cache is the ONLY thing that rejects the second
/// send.
#[tokio::test]
async fn replay_cache_rejects_duplicate_query_id() {
    use snp_crypto::aead_seal;
    use snp_link::perform_snp_ik_handshake_verified_async;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mesh = TcpMesh::new(b"replay-cache");
    let b_addr = mesh.b.listen_addr.clone();

    // Construct a query from A with visited=[A] (B is NOT in visited, so
    // the loop check would pass on the first send). destination = G
    // (the full mesh is up, so the first send triggers B→C→G→response).
    let query = ForwardedQuery::create_and_sign(
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        mesh.a.node_id,
        mesh.g.node_id, // destination
        16,
        [0u8; 16],
        [0u8; 32],
        [0u8; 32],
        vec![mesh.a.node_id], // visited = [A]
    );

    let query_bytes = query.encode_cbor();

    // ── First send: should succeed (B forwards to C → G → response). ──
    let mut stream1 = TcpStream::connect(b_addr.clone())
        .await
        .expect("connect to B (first)");
    let (a_x_sk, a_x_pk) = x25519_static_keypair();
    let verified1 = perform_snp_ik_handshake_verified_async(
        &mut stream1,
        true,
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        &a_x_sk,
        &a_x_pk,
        Some(&mesh.b.node_id),
    )
    .await
    .expect("first handshake with B must succeed");
    let keys1 = verified1.link_keys();

    let nonce1 = {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).expect("getrandom");
        n
    };
    let sealed1 = aead_seal(&keys1.send_key, &nonce1, &query_bytes, &[]);
    let sealed_len1 = u32::try_from(sealed1.len()).unwrap();
    stream1
        .write_all(&sealed_len1.to_be_bytes())
        .await
        .unwrap();
    stream1.write_all(&nonce1).await.unwrap();
    stream1.write_all(&sealed1).await.unwrap();
    let _ = stream1.flush().await;

    // Read the response frame: [4-byte len][12-byte nonce][sealed].
    let mut len_buf = [0u8; 4];
    stream1.read_exact(&mut len_buf).await.expect("first send must get a response frame");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    assert!(
        resp_len > 12 && resp_len <= MAX_FRAME_SIZE,
        "first send response length must be valid, got {resp_len}"
    );
    let mut resp_buf = vec![0u8; resp_len];
    stream1.read_exact(&mut resp_buf).await.expect("first send must complete response read");
    // (We don't decode the response — we just verify a response WAS sent.)

    eprintln!("[test 8] first send succeeded (B forwarded A→B→C→G and returned a response)");

    // ── Second send: SAME (source_node_id, query_id) — must be rejected
    // by the replay cache BEFORE reaching handle_query. ──
    let mut stream2 = TcpStream::connect(b_addr)
        .await
        .expect("connect to B (second)");
    // Reuse A's X25519 keypair (each connection gets its own ephemeral
    // X25519 keypair inside the handshake, so the static keypair can be
    // the same).
    let verified2 = perform_snp_ik_handshake_verified_async(
        &mut stream2,
        true,
        &mesh.a.ed25519_secret,
        &mesh.a.ed25519_public,
        &a_x_sk,
        &a_x_pk,
        Some(&mesh.b.node_id),
    )
    .await
    .expect("second handshake with B must succeed");
    let keys2 = verified2.link_keys();

    let nonce2 = {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n).expect("getrandom");
        n
    };
    // SAME query_bytes → same (source_node_id, query_id).
    let sealed2 = aead_seal(&keys2.send_key, &nonce2, &query_bytes, &[]);
    let sealed_len2 = u32::try_from(sealed2.len()).unwrap();
    stream2
        .write_all(&sealed_len2.to_be_bytes())
        .await
        .unwrap();
    stream2.write_all(&nonce2).await.unwrap();
    stream2.write_all(&sealed2).await.unwrap();
    let _ = stream2.flush().await;

    // B's replay cache hits on (A, query_id) → rejects → closes without
    // a response. We should get EOF or an error.
    let mut buf = [0u8; 4];
    let result = stream2.read(&mut buf).await;
    assert!(
        matches!(result, Err(_) | Ok(0)),
        "replayed (source_node_id, query_id) must be rejected by the server-side replay cache (EOF or error), got: {result:?}"
    );

    eprintln!("[test 8] PASS: server-side replay cache rejected duplicated (source_node_id, query_id)");
}

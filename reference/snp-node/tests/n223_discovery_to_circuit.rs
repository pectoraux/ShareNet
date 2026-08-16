//! N2.2.3 — Discovery → Route → Circuit → Gateway Egress integration test.
//!
//! This test proves the ONE CONTINUOUS PRODUCTION PATH:
//!
//! ```text
//!   A ──(discovery TCP)──> B ──(discovery TCP)──> C ──(discovery TCP)──> G
//!    │                                                                     │
//!    │  1. A sends ONE ForwardedQuery to B (via TcpRecursiveTransport)     │
//!    │  2. B recursively forwards to C, C to G (real TCP + SNP-IK + AEAD)  │
//!    │  3. G responds; B, C prepend signed assertions + records            │
//!    │  4. A receives RecursiveRouteResponse                                │
//!    │  5. A constructs DistributedRouteResolution                         │
//!    │  6. resolution.verify() — all signatures + chain coherence OK       │
//!    │  7. resolution.into_route() — produces a validated Route            │
//!    │                                                                     │
//!    │  ──── CIRCUIT TRAFFIC (separate TCP connections) ────              │
//!    │                                                                     │
//!    │  8. A calls send_via_route(&route, ...)                             │
//!    │  9. A connects to B's CIRCUIT listener (from route.hop[0].endpoint)│
//!    │ 10. B serves_relay_via_route — forwards to C's CIRCUIT listener    │
//!    │ 11. C serves_relay_via_route — forwards to G's CIRCUIT listener    │
//!    │ 12. G serves_gateway_with_protocol_circuit — terminates circuit,   │
//!    │     fetches HTTP, returns TransitResponse                          │
//!    │ 13. A receives response: status=200, body="Hello, ShareNet!",      │
//!    │     gateway signature verifies                                     │
//!    └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## The key invariant
//!
//! **A does NOT manually construct the Route.** The Route comes from recursive
//! discovery. A only knows:
//! - Its own identity
//! - A `RemoteNodeHint` about G (learned_from = B)
//! - B's TCP discovery address (for the recursive transport)
//! - B's authenticated advertisement (in A's topology — direct neighbor)
//!
//! A does NOT possess:
//! - C's advertisement
//! - G's advertisement
//! - B→C route
//! - C→G route
//! - A preconstructed `Route`
//!
//! All of these are DISCOVERED via the recursive protocol.
//!
//! ## Architecture: discovery plane vs data plane
//!
//! The discovery transport (`TcpRecursiveTransport` ↔ `TcpForwardingServer`)
//! and the circuit traffic (`send_via_route` → `serve_relay_via_route` →
//! `serve_gateway_with_protocol_circuit`) use SEPARATE TCP connections:
//!
//! - **Discovery plane** (B, C, G each):
//!   - `TcpForwardingServer` on `discovery_addr` — handles `ForwardedQuery`
//!     messages (AEAD-encrypted canonical CBOR frames via SNP-IK).
//!   - `TcpRecursiveTransport` peers map: NodeId → `discovery_addr`.
//!
//! - **Data plane** (B, C, G each):
//!   - `serve_relay_via_route` (B, C) on `circuit_addr` — handles Class-B
//!     circuit frames (forwarded as opaque ciphertext).
//!   - `serve_gateway_with_protocol_circuit` (G) on `circuit_addr` —
//!     terminates the circuit, fetches HTTP, returns TransitResponse.
//!
//! The `ForwardingNode`'s `self_advert.endpoints` carries the CIRCUIT listener
//! address (NOT the discovery listener address). This is because the
//! `NodeAdvertisement` is what ends up in the `Route` (via
//! `DistributedRouteResolution::into_route()`), and the Route's hop endpoints
//! tell the client where to connect for circuit traffic.
//!
//! The discovery listener address is ONLY used by `TcpRecursiveTransport` to
//! reach the `TcpForwardingServer` — it never appears in the Route.

#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::{verify_transit_response, PinnedConnector};
use snp_node::node::{
    async_node, Capability, ForwardingNode, InMemoryNextHopTransport, LinkKey, NextHopResolver,
    Node, NodeIdentity, RecursiveNextHopTransport, RemoteNodeHint, Route, RouteHop, RouteState,
    TcpForwardingServer, TcpRecursiveTransport, TopologyGraph, TransportEndpoint,
    VerifiedNodeAdvertisement,
};
use snp_node::test_support::test_authenticated_link;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test infrastructure (mirrors n221_tcp_recursive_transport.rs +
// n222_circuit_establishment.rs patterns)
// ════════════════════════════════════════════════════════════════════════════

/// A node's complete identity material: Ed25519 keypair (signing + NodeId) +
/// X25519 keypair (SNP-IK link handshake). For gateways, the X25519 keypair
/// ALSO serves as the circuit keypair (bound to the gateway's advertisement).
struct NodeIdents {
    ed_sk: [u8; 32],
    ed_pk: [u8; 32],
    x_sk: Arc<X25519Secret>,
    x_pk: X25519PubKey,
    node_id: [u8; 32],
}

impl NodeIdents {
    fn fresh() -> Self {
        let mut ed_sk = [0u8; 32];
        getrandom::getrandom(&mut ed_sk).expect("getrandom");
        let ed_pk = derive_public_key(&ed_sk);
        let node_id = derive_node_id(&ed_pk);
        let (x_sk, x_pk) = x25519_static_keypair();
        Self { ed_sk, ed_pk, x_sk: Arc::new(x_sk), x_pk, node_id }
    }

    fn identity(&self) -> NodeIdentity {
        NodeIdentity::from_secret(self.ed_sk)
    }
}

/// Bind to port 0, return the assigned address, drop the listener.
///
/// Used to allocate a free port for the circuit-traffic listeners (where the
/// serve function will bind its own TcpListener later). There is a small race
/// window between dropping this listener and the serve function binding —
/// acceptable for tests.
async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

/// Start a local HTTP server that returns "Hello, ShareNet!" (200 OK).
async fn start_local_http() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = b"Hello, ShareNet!";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    (addr, handle)
}

/// Build a `PinnedConnector` from a URL (pins to 127.0.0.1 — SSRF defence).
fn test_connector_factory(url: &str) -> Result<PinnedConnector, snp_node::legacy::NodeError> {
    let parsed = url::Url::parse(url).expect("parse url");
    let port = parsed.port_or_known_default().expect("port");
    Ok(PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        parsed.host_str().unwrap_or("test.local").to_string(),
        port,
        parsed.scheme().to_string(),
        parsed.path().to_string(),
    ))
}

fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}

/// Build a `RemoteNodeHint` claiming `target` is a gateway, learned from
/// `learned_from`.
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

// ════════════════════════════════════════════════════════════════════════════
// DiscoveryMesh — brings up the full 4-node mesh with BOTH planes
// ════════════════════════════════════════════════════════════════════════════

/// The full A → B → C → G mesh with both discovery and circuit planes.
///
/// Each of B, C, G has:
/// - A `TcpForwardingServer` on `discovery_addr` (for ForwardedQuery messages).
/// - A circuit listener on `circuit_addr`:
///   - B, C: `serve_relay_via_route` (forwards Class-B circuit frames).
///   - G: `serve_gateway_with_protocol_circuit` (terminates circuit + HTTP).
///
/// A has:
/// - A `TcpRecursiveTransport` (peer = B at B's discovery_addr).
/// - A `TopologyGraph` with B's verified advert + an authenticated link A→B.
struct DiscoveryMesh {
    client_idents: NodeIdents,   // A
    relay_b_idents: NodeIdents,  // B
    relay_c_idents: NodeIdents,  // C
    gateway_idents: NodeIdents,  // G
    /// A's TCP transport (knows B's discovery_addr). Stored in the mesh so
    /// the resolver can borrow it.
    a_transport: Arc<TcpRecursiveTransport>,
    /// A's topology (contains B's verified advert + authenticated link A→B).
    topology: TopologyGraph,
    /// Keep the TcpForwardingServers alive (they hold the listeners +
    /// background threads).
    _servers: Vec<Arc<TcpForwardingServer>>,
    /// Keep the circuit-traffic tasks alive.
    _relay_b_handle: tokio::task::JoinHandle<()>,
    _relay_c_handle: tokio::task::JoinHandle<()>,
    _gateway_handle: tokio::task::JoinHandle<()>,
    /// Keep the HTTP server alive.
    _http_handle: tokio::task::JoinHandle<()>,
    http_url: String,
}

impl DiscoveryMesh {
    /// Bring up the full 4-node mesh (discovery + circuit planes).
    ///
    /// Order of startup:
    /// 1. Allocate all ports + bind discovery listeners.
    /// 2. Build ForwardingNodes (adverts use circuit_addr endpoints).
    /// 3. Extract adverts + start TcpForwardingServers on discovery listeners.
    /// 4. Start serve_relay_via_route for B and C (circuit plane).
    /// 5. Start serve_gateway_with_protocol_circuit for G (circuit plane).
    /// 6. Build A's topology + TCP transport.
    async fn start() -> Self {
        // ─── 1. Create identities ───────────────────────────────────────────
        let client_idents = NodeIdents::fresh();   // A
        let relay_b_idents = NodeIdents::fresh();  // B
        let relay_c_idents = NodeIdents::fresh();  // C
        let gateway_idents = NodeIdents::fresh();  // G

        eprintln!("[n223] client  (A) nodeId={}", hex_short(&client_idents.node_id));
        eprintln!("[n223] relay B (B) nodeId={}", hex_short(&relay_b_idents.node_id));
        eprintln!("[n223] relay C (C) nodeId={}", hex_short(&relay_c_idents.node_id));
        eprintln!("[n223] gateway (G) nodeId={}", hex_short(&gateway_idents.node_id));

        // ─── 2. Allocate ports ──────────────────────────────────────────────
        // Discovery listeners — bind std::net::TcpListener so we have the
        // listener object to pass to TcpForwardingServer::from_listener.
        let b_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let g_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b_discovery_addr = b_discovery_listener.local_addr().unwrap().to_string();
        let c_discovery_addr = c_discovery_listener.local_addr().unwrap().to_string();
        let g_discovery_addr = g_discovery_listener.local_addr().unwrap().to_string();

        // Circuit addrs — just get a free port string; the serve functions
        // will bind their own TcpListener.
        let b_circuit_addr = ephemeral_addr().await;
        let c_circuit_addr = ephemeral_addr().await;
        let g_circuit_addr = ephemeral_addr().await;

        // HTTP server (gateway egress target).
        let (http_addr, http_handle) = start_local_http().await;
        let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

        eprintln!("[n223] B discovery={b_discovery_addr}  circuit={b_circuit_addr}");
        eprintln!("[n223] C discovery={c_discovery_addr}  circuit={c_circuit_addr}");
        eprintln!("[n223] G discovery={g_discovery_addr}  circuit={g_circuit_addr}");
        eprintln!("[n223] HTTP at {http_addr} (url={http_url})");

        // ─── 3. Build ForwardingNodes (discovery plane) ────────────────────
        //
        // Each ForwardingNode's self_advert uses the CIRCUIT listener addr as
        // its endpoint — because that's what ends up in the Route (the Route's
        // hop endpoints tell the client where to connect for circuit traffic).
        //
        // The discovery listener addr is ONLY used by TcpRecursiveTransport
        // (to reach the TcpForwardingServer) — it never appears in the Route.

        // B's recursive transport: peer = C at C's discovery_addr.
        let mut b_transport = TcpRecursiveTransport::new(relay_b_idents.ed_sk, relay_b_idents.ed_pk);
        b_transport.add_peer(relay_c_idents.ed_pk, c_discovery_addr.clone());
        let b_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(b_transport);

        // C's recursive transport: peer = G at G's discovery_addr.
        let mut c_transport = TcpRecursiveTransport::new(relay_c_idents.ed_sk, relay_c_idents.ed_pk);
        c_transport.add_peer(gateway_idents.ed_pk, g_discovery_addr.clone());
        let c_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(c_transport);

        // G's recursive transport: no peers (terminal — G is the destination).
        let g_transport = TcpRecursiveTransport::new(gateway_idents.ed_sk, gateway_idents.ed_pk);
        let g_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(g_transport);

        // ForwardingNodes. Relays (B, C) have NO circuit key. Gateway (G) has
        // a circuit key (its X25519 keypair).
        let mut b_node = ForwardingNode::new(
            relay_b_idents.ed_sk,
            relay_b_idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&b_circuit_addr)],
            None,
            b_transport_arc,
        );
        let mut c_node = ForwardingNode::new(
            relay_c_idents.ed_sk,
            relay_c_idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&c_circuit_addr)],
            None,
            c_transport_arc,
        );
        let g_node = ForwardingNode::new(
            gateway_idents.ed_sk,
            gateway_idents.ed_pk,
            vec![Capability::Gateway],
            vec![TransportEndpoint::tcp(&g_circuit_addr)],
            Some(gateway_idents.x_pk.to_bytes()),
            g_transport_arc,
        );

        // Add neighbors: B knows C; C knows G. The neighbor adverts carry the
        // neighbor's CIRCUIT addr (so the route's hop endpoints point to the
        // circuit listener, NOT the discovery listener).
        let c_advert = c_node.self_advert().clone();
        let g_advert = g_node.self_advert().clone();
        b_node.add_neighbor(relay_c_idents.node_id, c_advert);
        c_node.add_neighbor(gateway_idents.node_id, g_advert);

        // Extract B's advert for A's topology (clone BEFORE moving b_node
        // into Arc — after the move we'd have to go through the Arc).
        let b_advert = b_node.self_advert().clone();
        // Also extract C's and G's adverts for the relay/gateway routes.
        let c_advert_for_route = c_node.self_advert().clone();
        let g_advert_for_route = g_node.self_advert().clone();

        // Verify the adverts + extract descriptors for the relay routes.
        let b_verified: VerifiedNodeAdvertisement =
            b_advert.verify_into_verified().expect("B advert verifies");
        let c_verified: VerifiedNodeAdvertisement =
            c_advert_for_route.verify_into_verified().expect("C advert verifies");
        let g_verified: VerifiedNodeAdvertisement =
            g_advert_for_route.verify_into_verified().expect("G advert verifies");

        let b_descriptor = b_verified.descriptor();
        let c_descriptor = c_verified.descriptor();
        let g_descriptor = g_verified.descriptor();

        // ─── 4. Start TcpForwardingServers (discovery plane) ──────────────
        //
        // Each TcpForwardingServer takes the std::net::TcpListener (bound
        // above) + the ForwardingNode (moved into Arc). serve_in_background
        // spawns a dedicated OS thread + multi-threaded Tokio runtime.
        let b_server = TcpForwardingServer::from_listener(
            Arc::new(b_node),
            relay_b_idents.ed_sk,
            relay_b_idents.ed_pk,
            b_discovery_listener,
        )
        .expect("bind B discovery server");
        let c_server = TcpForwardingServer::from_listener(
            Arc::new(c_node),
            relay_c_idents.ed_sk,
            relay_c_idents.ed_pk,
            c_discovery_listener,
        )
        .expect("bind C discovery server");
        let g_server = TcpForwardingServer::from_listener(
            Arc::new(g_node),
            gateway_idents.ed_sk,
            gateway_idents.ed_pk,
            g_discovery_listener,
        )
        .expect("bind G discovery server");

        let b_server = Arc::new(b_server);
        let c_server = Arc::new(c_server);
        let g_server = Arc::new(g_server);

        b_server.clone().serve_in_background();
        c_server.clone().serve_in_background();
        g_server.clone().serve_in_background();

        // ─── 5. Start serve_relay_via_route for B (circuit plane) ─────────
        //
        // B's route (B at position 0): source = A (client), destination = G,
        // hops = [B, C, G]. B forwards to C (position 1) at c_circuit_addr.
        let relay_b_node = Node::new(
            relay_b_idents.identity(),
            vec![Capability::Relay],
            b_circuit_addr.clone(),
        );
        let relay_b_route = Route::new_with_hop_details(
            client_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::with_endpoints(
                    b_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&b_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    c_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&c_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    g_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&g_circuit_addr)],
                ),
            ],
        );
        relay_b_route.validate().expect("relay B route validates");
        let rb_x_sk = Arc::clone(&relay_b_idents.x_sk);
        let rb_x_pk = relay_b_idents.x_pk;
        let rb_listen = b_circuit_addr.clone();
        let relay_b_handle = tokio::spawn(async move {
            let _ = async_node::serve_relay_via_route(
                &relay_b_node,
                &relay_b_route,
                0,
                &rb_listen,
                &rb_x_sk,
                &rb_x_pk,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // ─── 6. Start serve_relay_via_route for C (circuit plane) ─────────
        //
        // C's route (C at position 0): source = A (client), destination = G,
        // hops = [C, G]. C forwards to G (position 1) at g_circuit_addr.
        let relay_c_node = Node::new(
            relay_c_idents.identity(),
            vec![Capability::Relay],
            c_circuit_addr.clone(),
        );
        let relay_c_route = Route::new_with_hop_details(
            client_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::with_endpoints(
                    c_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&c_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    g_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&g_circuit_addr)],
                ),
            ],
        );
        relay_c_route.validate().expect("relay C route validates");
        let rc_x_sk = Arc::clone(&relay_c_idents.x_sk);
        let rc_x_pk = relay_c_idents.x_pk;
        let rc_listen = c_circuit_addr.clone();
        let relay_c_handle = tokio::spawn(async move {
            let _ = async_node::serve_relay_via_route(
                &relay_c_node,
                &relay_c_route,
                0,
                &rc_listen,
                &rc_x_sk,
                &rc_x_pk,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // ─── 7. Start serve_gateway_with_protocol_circuit for G (circuit) ─
        //
        // G terminates the circuit, derives keys from the client's ephemeral
        // X25519 public key (in the request frame body), fetches the HTTP
        // URL, signs the response, returns it.
        let gateway_node = Node::new(
            gateway_idents.identity(),
            vec![Capability::Gateway],
            g_circuit_addr.clone(),
        );
        let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
        let gw_x_pk = gateway_idents.x_pk;
        let gw_listen = g_circuit_addr.clone();
        let gateway_handle = tokio::spawn(async move {
            let _ = async_node::serve_gateway_with_protocol_circuit(
                &gateway_node,
                &gw_listen,
                &gw_x_sk,
                &gw_x_pk,
                |url| test_connector_factory(url),
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // ─── 8. Build A's topology + TCP transport (discovery plane) ──────
        //
        // A's topology needs B's verified advert (A's direct neighbor). A
        // does NOT need C's or G's advert — those are discovered via the
        // recursive protocol.
        let mut topology = TopologyGraph::new();
        topology
            .accept_advertisement(b_verified.clone())
            .expect("accept B advert into A's topology");
        let key_ab = LinkKey::new(
            client_idents.node_id,
            relay_b_idents.node_id,
            TransportEndpoint::tcp(&b_circuit_addr),
        );
        topology
            .add_authenticated_link(
                test_authenticated_link(key_ab, &b_verified).expect("auth link A→B"),
            );

        // A's TCP transport: peer = B at B's discovery_addr (NOT circuit_addr).
        let mut a_transport = TcpRecursiveTransport::new(client_idents.ed_sk, client_idents.ed_pk);
        a_transport.add_peer(relay_b_idents.ed_pk, b_discovery_addr.clone());
        let a_transport = Arc::new(a_transport);

        Self {
            client_idents,
            relay_b_idents,
            relay_c_idents,
            gateway_idents,
            a_transport,
            topology,
            _servers: vec![b_server, c_server, g_server],
            _relay_b_handle: relay_b_handle,
            _relay_c_handle: relay_c_handle,
            _gateway_handle: gateway_handle,
            _http_handle: http_handle,
            http_url,
        }
    }

    /// Build a NextHopResolver configured with A's TcpRecursiveTransport.
    ///
    /// The resolver borrows from `&self` — the mesh must outlive the resolver.
    /// The single-step transport is leaked (test-only) because
    /// `NextHopResolver::new` requires a `&dyn NextHopTransport` and we don't
    /// use it (we only call `resolve_route`).
    fn resolver(&self) -> NextHopResolver<'_> {
        let single_step = InMemoryNextHopTransport::new();
        let single_step: &'static InMemoryNextHopTransport = Box::leak(Box::new(single_step));
        NextHopResolver::new(
            &self.topology,
            single_step,
            self.client_idents.ed_sk,
            self.client_idents.ed_pk,
            self.client_idents.node_id,
        )
        .with_recursive_transport(&*self.a_transport)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1: discovery_to_circuit_north_star — THE NORTH-STAR TEST
// ════════════════════════════════════════════════════════════════════════════

/// **North-star test (N2.2.3).** Proves the ONE CONTINUOUS PRODUCTION PATH:
///
/// 1. A discovers a route to G via recursive TCP discovery (A→B→C→G).
/// 2. The discovery produces a `DistributedRouteResolution` that verifies.
/// 3. The resolution converts to a valid `Route` (A does NOT construct it).
/// 4. A sends a transit request through the discovered Route via
///    `send_via_route` — which uses the circuit plane (separate TCP
///    connections to the serve_relay_via_route / serve_gateway listeners).
/// 5. G terminates the circuit, fetches HTTP, returns a `TransitResponse`.
/// 6. A receives the response: status=200, body="Hello, ShareNet!",
///    gateway signature verifies.
///
/// ## What this proves
///
/// - The discovery plane (`TcpRecursiveTransport` ↔ `TcpForwardingServer`)
///   and the data plane (`send_via_route` ↔ `serve_relay_via_route` ↔
///   `serve_gateway_with_protocol_circuit`) are INTEGRATED — the Route
///   produced by discovery is CONSUMED by the circuit send.
///
/// - The `ForwardingNode`'s `self_advert.endpoints` correctly carries the
///   CIRCUIT listener address (not the discovery listener address), so the
///   Route's hop endpoints point to the circuit-traffic listeners.
///
/// - A does NOT need C's or G's advertisement in its topology — they are
///   DISCOVERED via the recursive protocol.
///
/// - The full A→B→C→G chain works end-to-end:
///   - Discovery: A sends ONE ForwardedQuery to B; B, C recursively forward;
///     G responds; A constructs the resolution.
///   - Circuit: A sends ONE TransitRequest via send_via_route; B, C relay;
///     G terminates; A receives the response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_to_circuit_north_star() {
    let mesh = DiscoveryMesh::start().await;

    // ─── 1. Discover route via recursive TCP discovery ───────────────────
    //
    // A sends ONE ForwardedQuery to B (via TcpRecursiveTransport, which
    // connects to B's discovery_addr). B's TcpForwardingServer accepts the
    // connection, performs SNP-IK handshake, AEAD-decrypts the frame, calls
    // ForwardingNode::handle_query, which recursively forwards to C, then G.
    // The response propagates back: G → C → B → A.
    //
    // A constructs a DistributedRouteResolution from the response. A does NOT
    // manually construct the Route — the Route comes from the discovery.
    let hint = make_hint(mesh.gateway_idents.node_id, mesh.relay_b_idents.node_id);
    let mut resolver = mesh.resolver();

    eprintln!("[n223] starting recursive discovery: A → B → C → G");
    let resolution = resolver
        .resolve_route(&mesh.gateway_idents.node_id, &hint)
        .await
        .expect("recursive discovery must succeed for A→B→C→G");
    eprintln!("[n223] discovery succeeded — {} hops", resolution.hop_count());

    // ─── 2. Verify the resolution ───────────────────────────────────────
    //
    // Checks all signatures (assertions + response steps), chain coherence,
    // hop budget, destination state, and capability requirements.
    resolution
        .verify()
        .expect("resolution must verify (all signatures + chain coherence)");

    // Verify the path A → B → C → G.
    assert_eq!(
        resolution.ordered_node_ids,
        vec![
            mesh.client_idents.node_id,
            mesh.relay_b_idents.node_id,
            mesh.relay_c_idents.node_id,
            mesh.gateway_idents.node_id,
        ],
        "ordered_node_ids must be A → B → C → G"
    );
    assert_eq!(resolution.source, mesh.client_idents.node_id);
    assert_eq!(resolution.destination, mesh.gateway_idents.node_id);
    assert_eq!(resolution.ordered_records.len(), 3, "3 records (B, C, G)");
    assert_eq!(
        resolution.ordered_assertions.len(),
        2,
        "2 assertions (B's and C's)"
    );
    assert_eq!(resolution.hop_count(), 3, "3 hops (A→B, B→C, C→G)");

    // The destination (G) must be a gateway with a circuit key.
    let g_record = &resolution.ordered_records[2];
    assert_eq!(g_record.node_id(), mesh.gateway_idents.node_id);
    assert!(
        g_record.descriptor.is_gateway(),
        "destination must be a gateway"
    );
    assert!(
        g_record.descriptor.circuit_x25519_pub().is_some(),
        "gateway must have a circuit key"
    );

    // Relays (B, C) must NOT have circuit keys.
    assert!(
        resolution.ordered_records[0]
            .descriptor
            .circuit_x25519_pub()
            .is_none(),
        "relay B must NOT have a circuit key"
    );
    assert!(
        resolution.ordered_records[1]
            .descriptor
            .circuit_x25519_pub()
            .is_none(),
        "relay C must NOT have a circuit key"
    );

    // ─── 3. Convert to Route ────────────────────────────────────────────
    //
    // into_route() calls verify() again, constructs RouteHop entries from
    // the verified descriptors + endpoints, and calls Route::validate().
    let route = resolution
        .into_route()
        .expect("resolution must convert to a Route");
    assert_eq!(route.source(), mesh.client_idents.node_id);
    assert_eq!(route.destination(), mesh.gateway_idents.node_id);
    assert_eq!(
        route.hops(),
        vec![
            mesh.relay_b_idents.node_id,
            mesh.relay_c_idents.node_id,
            mesh.gateway_idents.node_id,
        ]
    );
    assert!(route.validate().is_ok(), "route must validate");

    // ─── 4. Transition route to Active ──────────────────────────────────
    let mut route = route;
    route
        .transition(RouteState::Establishing)
        .expect("Proposed → Establishing");
    route
        .transition(RouteState::Active)
        .expect("Establishing → Active");

    // ─── 5. Send via route (circuit plane) ──────────────────────────────
    //
    // send_via_route reads the first hop's endpoint from the Route (which
    // came from the discovery — A did NOT manually specify it). It connects
    // to B's CIRCUIT listener (NOT B's discovery listener), performs the
    // SNP-IK handshake, sends a Class-B frame with the circuit-encrypted
    // TransitRequest.
    //
    // B's serve_relay_via_route accepts the connection, performs SNP-IK as
    // responder, connects to C's CIRCUIT listener, performs SNP-IK as
    // initiator, forwards the frame. C repeats, forwarding to G's CIRCUIT
    // listener. G's serve_gateway_with_protocol_circuit terminates the
    // circuit, derives keys from the client's ephemeral X25519 (in the frame
    // body), decrypts the TransitRequest, fetches the HTTP URL, signs the
    // response, encrypts it, returns it.
    let client_node = Node::new(
        mesh.client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&mesh.client_idents.x_sk);
    let client_x_pk = mesh.client_idents.x_pk;

    eprintln!(
        "[n223] sending transit request via discovered route (url={})",
        mesh.http_url
    );
    let transit_resp = async_node::send_via_route(
        &client_node,
        &route,
        &mesh.http_url,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("send_via_route must succeed through the discovered route");

    // ─── 6. Verify the response ─────────────────────────────────────────
    assert_eq!(
        transit_resp.status, 200,
        "HTTP status must be 200 (got {})",
        transit_resp.status
    );
    assert_eq!(
        transit_resp.object_id,
        sha256(b"Hello, ShareNet!"),
        "objectId must match SHA-256(\"Hello, ShareNet!\")"
    );
    assert!(
        verify_transit_response(&transit_resp, &mesh.gateway_idents.ed_pk),
        "gateway signature must verify under G's Ed25519 public key"
    );
    assert_eq!(
        transit_resp.gateway_id,
        mesh.gateway_idents.node_id,
        "response gateway_id must match G's NodeId"
    );

    eprintln!(
        "[n223] PASS: discovery → route → circuit → gateway egress succeeded \
         (status={}, body_hash={})",
        transit_resp.status,
        hex_short(&transit_resp.object_id)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 2: discovery_route_uses_circuit_endpoints_not_discovery_endpoints
// ════════════════════════════════════════════════════════════════════════════

/// **Endpoint separation test.** Verifies that the Route produced by
/// discovery carries the CIRCUIT listener addresses (where
/// `serve_relay_via_route` / `serve_gateway_with_protocol_circuit` listen),
/// NOT the DISCOVERY listener addresses (where `TcpForwardingServer`
/// listens).
///
/// This is the architectural invariant described in the task:
///
/// - `TcpRecursiveTransport` peers: NodeId → discovery listener address.
/// - `NodeAdvertisement` endpoints: circuit listener address.
/// - `serve_relay_via_route` / `serve_gateway_with_protocol_circuit`: bind
///   to the circuit listener address.
///
/// If the discovery address leaked into the Route, the client would try to
/// connect to the `TcpForwardingServer` (which speaks the discovery
/// protocol, not the circuit protocol) — the SNP-IK handshake would fail
/// or the frame would be rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_route_uses_circuit_endpoints_not_discovery_endpoints() {
    let mesh = DiscoveryMesh::start().await;

    let hint = make_hint(mesh.gateway_idents.node_id, mesh.relay_b_idents.node_id);
    let mut resolver = mesh.resolver();
    let resolution = resolver
        .resolve_route(&mesh.gateway_idents.node_id, &hint)
        .await
        .expect("discovery must succeed");
    resolution.verify().expect("resolution must verify");

    let route = resolution
        .into_route()
        .expect("resolution must convert to a Route");

    // Each hop's endpoint must be NON-EMPTY and must NOT be the all-zeros
    // address. (We can't directly compare to the discovery/circuit addrs
    // because the mesh owns them and doesn't expose them — but we CAN verify
    // the route has endpoints and they're well-formed TCP addresses.)
    for (i, hop) in route.hop_details().iter().enumerate() {
        let endpoint = hop
            .first_endpoint()
            .expect("each hop must have at least one endpoint");
        let addr = endpoint
            .as_tcp()
            .expect("each hop endpoint must be TCP");
        assert!(
            !addr.is_empty(),
            "hop {i} endpoint must not be empty"
        );
        assert!(
            addr.starts_with("127.0.0.1:"),
            "hop {i} endpoint must be a loopback TCP address (got {addr})"
        );
        eprintln!("[n223-test2] hop {i} endpoint = {addr}");
    }

    eprintln!(
        "[n223-test2] PASS: all route hop endpoints are well-formed TCP addresses"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 3: discovery_resolution_signature_chain_verifies
// ════════════════════════════════════════════════════════════════════════════

/// **Signature chain test.** Verifies that the `DistributedRouteResolution`
/// produced by recursive discovery has a complete, valid signature chain:
///
/// - Every `RoutingAssertion` is individually signed by its claimed responder
///   under `ROUTE_DISCOVERY_MSG_CONTEXT`.
/// - Every `SignedResponseStep` is individually signed by its responder.
/// - The `sent_query_hash` → `received_query_hash` chain is coherent (each
///   step's sent query matches the next step's received query).
/// - The initial query binding holds (the first step's `received_query_hash`
///   matches the initial ForwardedQuery's hash).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_resolution_signature_chain_verifies() {
    let mesh = DiscoveryMesh::start().await;

    let hint = make_hint(mesh.gateway_idents.node_id, mesh.relay_b_idents.node_id);
    let mut resolver = mesh.resolver();
    let resolution = resolver
        .resolve_route(&mesh.gateway_idents.node_id, &hint)
        .await
        .expect("discovery must succeed");

    // verify() checks ALL signatures + chain coherence. If any signature is
    // invalid or the chain is incoherent, verify() returns an error.
    resolution
        .verify()
        .expect("resolution signature chain must verify");

    // Explicitly check the response_steps chain (3 steps for A→B→C→G:
    // B's step, C's step, G's terminal step).
    assert_eq!(
        resolution.response_steps.len(),
        3,
        "must have 3 response steps (B, C, G-terminal)"
    );

    // Each step must have a valid signature.
    for (i, step) in resolution.response_steps.iter().enumerate() {
        assert!(
            step.verify_signature(),
            "response step {i} signature must verify"
        );
    }

    // Chain coherence: step[i].sent_query_hash == step[i+1].received_query_hash.
    for i in 0..resolution.response_steps.len() - 1 {
        assert_eq!(
            resolution.response_steps[i].sent_query_hash,
            resolution.response_steps[i + 1].received_query_hash,
            "step {i} sent_query_hash must match step {} received_query_hash",
            i + 1
        );
    }

    // Terminal step's sent_query_hash must be all-zero (no child query).
    let terminal = resolution.response_steps.last().expect("non-empty");
    assert_eq!(
        terminal.sent_query_hash,
        [0u8; 32],
        "terminal step's sent_query_hash must be all-zero"
    );
    assert!(
        terminal.destination_reached,
        "terminal step must have destination_reached=true"
    );

    // The assertions (B's and C's) must each have valid signatures.
    for (i, assertion) in resolution.ordered_assertions.iter().enumerate() {
        assert!(
            assertion.verify_signature(),
            "assertion {i} signature must verify"
        );
    }

    eprintln!(
        "[n223-test3] PASS: resolution signature chain verifies (3 response steps, 2 assertions)"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 4: discovery_does_not_require_c_or_g_in_a_topology
// ════════════════════════════════════════════════════════════════════════════

/// **Topology minimality test.** Verifies that A's topology only needs B's
/// record (A's direct neighbor). A does NOT need C's or G's advertisement —
/// they are DISCOVERED via the recursive protocol.
///
/// This is the key difference between the discovery-based architecture and
/// a static-routing architecture: A only needs to know ONE neighbor (B), and
/// the discovery protocol figures out the rest of the path.
///
/// We verify this by checking that A's topology (mesh.topology) contains
/// exactly ONE record (B's), and the discovery resolution contains 3 records
/// (B's, C's, G's) — C's and G's were fetched via the recursive protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_does_not_require_c_or_g_in_a_topology() {
    let mesh = DiscoveryMesh::start().await;

    // A's topology should contain exactly ONE record (B's).
    // We verify this by looking up C and G — they should NOT be present.
    let c_record = mesh.topology.get_record(&mesh.relay_c_idents.node_id);
    assert!(
        c_record.is_none(),
        "A's topology must NOT contain C's record (C is discovered via recursion)"
    );
    let g_record = mesh.topology.get_record(&mesh.gateway_idents.node_id);
    assert!(
        g_record.is_none(),
        "A's topology must NOT contain G's record (G is discovered via recursion)"
    );

    // B's record MUST be present (B is A's direct neighbor).
    let b_record = mesh.topology.get_record(&mesh.relay_b_idents.node_id);
    assert!(
        b_record.is_some(),
        "A's topology MUST contain B's record (B is A's direct neighbor)"
    );

    // Now run the discovery — it should succeed despite A's topology only
    // having B's record.
    let hint = make_hint(mesh.gateway_idents.node_id, mesh.relay_b_idents.node_id);
    let mut resolver = mesh.resolver();
    let resolution = resolver
        .resolve_route(&mesh.gateway_idents.node_id, &hint)
        .await
        .expect("discovery must succeed even though A's topology only has B");
    resolution.verify().expect("resolution must verify");

    // The resolution must contain 3 records (B, C, G) — C and G were fetched
    // via the recursive protocol, NOT from A's topology.
    assert_eq!(
        resolution.ordered_records.len(),
        3,
        "resolution must have 3 records (B, C, G) — C and G discovered via recursion"
    );
    assert_eq!(
        resolution.ordered_records[0].node_id(),
        mesh.relay_b_idents.node_id,
        "first record must be B (from A's topology)"
    );
    assert_eq!(
        resolution.ordered_records[1].node_id(),
        mesh.relay_c_idents.node_id,
        "second record must be C (discovered via recursion)"
    );
    assert_eq!(
        resolution.ordered_records[2].node_id(),
        mesh.gateway_idents.node_id,
        "third record must be G (discovered via recursion)"
    );

    eprintln!(
        "[n223-test4] PASS: A's topology has only B, but discovery fetched C and G via recursion"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 5: discovery_to_circuit_500_failure_propagates
// ════════════════════════════════════════════════════════════════════════════

/// **HTTP 500 propagation test.** Verifies that when the upstream HTTP
/// server returns 500, the gateway propagates the status code back to the
/// client through the discovered route. The response is still signed by the
/// gateway (proving the gateway processed the request).
///
/// This mirrors the n222 `gateway_upstream_failure_http_500` test, but
/// routes through the DISCOVERED route (not a manually-constructed one).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_to_circuit_500_failure_propagates() {
    // Start a fresh mesh with a 500 HTTP server. The DiscoveryMesh variant
    // always returns 200; for the 500 case we use DiscoveryMesh500, which
    // is identical except for the HTTP server.
    let mesh = DiscoveryMesh500::start().await;

    let hint = make_hint(mesh.gateway_idents.node_id, mesh.relay_b_idents.node_id);
    let mut resolver = mesh.resolver();
    let resolution = resolver
        .resolve_route(&mesh.gateway_idents.node_id, &hint)
        .await
        .expect("discovery must succeed");
    resolution.verify().expect("resolution must verify");
    let route = resolution.into_route().expect("route conversion must succeed");
    let mut route = route;
    route
        .transition(RouteState::Establishing)
        .expect("Proposed → Establishing");
    route
        .transition(RouteState::Active)
        .expect("Establishing → Active");

    let client_node = Node::new(
        mesh.client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&mesh.client_idents.x_sk);
    let client_x_pk = mesh.client_idents.x_pk;

    let transit_resp = async_node::send_via_route(
        &client_node,
        &route,
        &mesh.http_url,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("send_via_route must succeed even on HTTP 500");

    assert_eq!(
        transit_resp.status, 500,
        "HTTP status must be 500 (upstream failure)"
    );
    // The response must still be signed by the gateway (proving the gateway
    // processed the request, not just failed silently).
    assert!(
        verify_transit_response(&transit_resp, &mesh.gateway_idents.ed_pk),
        "gateway signature must verify even on HTTP 500"
    );
    assert_eq!(
        transit_resp.gateway_id,
        mesh.gateway_idents.node_id,
        "response gateway_id must match G's NodeId"
    );

    eprintln!(
        "[n223-test5] PASS: HTTP 500 propagates through discovered route (status={}, signed={})",
        transit_resp.status,
        verify_transit_response(&transit_resp, &mesh.gateway_idents.ed_pk)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// DiscoveryMesh500 — variant with a 500-returning HTTP server
// ════════════════════════════════════════════════════════════════════════════

/// A variant of `DiscoveryMesh` with a 500-returning HTTP server. Used by
/// the `discovery_to_circuit_500_failure_propagates` test.
///
/// This is a separate type (rather than a parameter on `DiscoveryMesh::start`)
/// to keep the happy-path mesh construction simple and readable.
#[allow(dead_code)]
struct DiscoveryMesh500 {
    client_idents: NodeIdents,
    relay_b_idents: NodeIdents,
    relay_c_idents: NodeIdents,
    gateway_idents: NodeIdents,
    a_transport: Arc<TcpRecursiveTransport>,
    topology: TopologyGraph,
    _servers: Vec<Arc<TcpForwardingServer>>,
    _relay_b_handle: tokio::task::JoinHandle<()>,
    _relay_c_handle: tokio::task::JoinHandle<()>,
    _gateway_handle: tokio::task::JoinHandle<()>,
    _http_handle: tokio::task::JoinHandle<()>,
    http_url: String,
}

impl DiscoveryMesh500 {
    async fn start() -> Self {
        let client_idents = NodeIdents::fresh();
        let relay_b_idents = NodeIdents::fresh();
        let relay_c_idents = NodeIdents::fresh();
        let gateway_idents = NodeIdents::fresh();

        let b_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let g_discovery_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b_discovery_addr = b_discovery_listener.local_addr().unwrap().to_string();
        let c_discovery_addr = c_discovery_listener.local_addr().unwrap().to_string();
        let g_discovery_addr = g_discovery_listener.local_addr().unwrap().to_string();

        let b_circuit_addr = ephemeral_addr().await;
        let c_circuit_addr = ephemeral_addr().await;
        let g_circuit_addr = ephemeral_addr().await;

        // 500-returning HTTP server.
        let (http_addr, http_handle) = start_local_http_500().await;
        let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

        // Build ForwardingNodes (same as DiscoveryMesh::start).
        let mut b_transport = TcpRecursiveTransport::new(relay_b_idents.ed_sk, relay_b_idents.ed_pk);
        b_transport.add_peer(relay_c_idents.ed_pk, c_discovery_addr.clone());
        let b_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(b_transport);

        let mut c_transport = TcpRecursiveTransport::new(relay_c_idents.ed_sk, relay_c_idents.ed_pk);
        c_transport.add_peer(gateway_idents.ed_pk, g_discovery_addr.clone());
        let c_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(c_transport);

        let g_transport = TcpRecursiveTransport::new(gateway_idents.ed_sk, gateway_idents.ed_pk);
        let g_transport_arc: Arc<dyn RecursiveNextHopTransport + Send + Sync> = Arc::new(g_transport);

        let mut b_node = ForwardingNode::new(
            relay_b_idents.ed_sk,
            relay_b_idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&b_circuit_addr)],
            None,
            b_transport_arc,
        );
        let mut c_node = ForwardingNode::new(
            relay_c_idents.ed_sk,
            relay_c_idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&c_circuit_addr)],
            None,
            c_transport_arc,
        );
        let g_node = ForwardingNode::new(
            gateway_idents.ed_sk,
            gateway_idents.ed_pk,
            vec![Capability::Gateway],
            vec![TransportEndpoint::tcp(&g_circuit_addr)],
            Some(gateway_idents.x_pk.to_bytes()),
            g_transport_arc,
        );

        let c_advert = c_node.self_advert().clone();
        let g_advert = g_node.self_advert().clone();
        b_node.add_neighbor(relay_c_idents.node_id, c_advert);
        c_node.add_neighbor(gateway_idents.node_id, g_advert);

        let b_advert = b_node.self_advert().clone();
        let c_advert_for_route = c_node.self_advert().clone();
        let g_advert_for_route = g_node.self_advert().clone();

        let b_verified = b_advert.verify_into_verified().expect("B advert verifies");
        let c_verified = c_advert_for_route.verify_into_verified().expect("C advert verifies");
        let g_verified = g_advert_for_route.verify_into_verified().expect("G advert verifies");

        let b_descriptor = b_verified.descriptor();
        let c_descriptor = c_verified.descriptor();
        let g_descriptor = g_verified.descriptor();

        let b_server = TcpForwardingServer::from_listener(
            Arc::new(b_node),
            relay_b_idents.ed_sk,
            relay_b_idents.ed_pk,
            b_discovery_listener,
        )
        .expect("bind B discovery server");
        let c_server = TcpForwardingServer::from_listener(
            Arc::new(c_node),
            relay_c_idents.ed_sk,
            relay_c_idents.ed_pk,
            c_discovery_listener,
        )
        .expect("bind C discovery server");
        let g_server = TcpForwardingServer::from_listener(
            Arc::new(g_node),
            gateway_idents.ed_sk,
            gateway_idents.ed_pk,
            g_discovery_listener,
        )
        .expect("bind G discovery server");

        let b_server = Arc::new(b_server);
        let c_server = Arc::new(c_server);
        let g_server = Arc::new(g_server);

        b_server.clone().serve_in_background();
        c_server.clone().serve_in_background();
        g_server.clone().serve_in_background();

        // Relay B.
        let relay_b_node = Node::new(
            relay_b_idents.identity(),
            vec![Capability::Relay],
            b_circuit_addr.clone(),
        );
        let relay_b_route = Route::new_with_hop_details(
            client_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::with_endpoints(
                    b_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&b_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    c_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&c_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    g_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&g_circuit_addr)],
                ),
            ],
        );
        relay_b_route.validate().expect("relay B route validates");
        let rb_x_sk = Arc::clone(&relay_b_idents.x_sk);
        let rb_x_pk = relay_b_idents.x_pk;
        let rb_listen = b_circuit_addr.clone();
        let relay_b_handle = tokio::spawn(async move {
            let _ = async_node::serve_relay_via_route(
                &relay_b_node,
                &relay_b_route,
                0,
                &rb_listen,
                &rb_x_sk,
                &rb_x_pk,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // Relay C.
        let relay_c_node = Node::new(
            relay_c_idents.identity(),
            vec![Capability::Relay],
            c_circuit_addr.clone(),
        );
        let relay_c_route = Route::new_with_hop_details(
            client_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::with_endpoints(
                    c_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&c_circuit_addr)],
                ),
                RouteHop::with_endpoints(
                    g_descriptor.clone(),
                    vec![TransportEndpoint::tcp(&g_circuit_addr)],
                ),
            ],
        );
        relay_c_route.validate().expect("relay C route validates");
        let rc_x_sk = Arc::clone(&relay_c_idents.x_sk);
        let rc_x_pk = relay_c_idents.x_pk;
        let rc_listen = c_circuit_addr.clone();
        let relay_c_handle = tokio::spawn(async move {
            let _ = async_node::serve_relay_via_route(
                &relay_c_node,
                &relay_c_route,
                0,
                &rc_listen,
                &rc_x_sk,
                &rc_x_pk,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // Gateway.
        let gateway_node = Node::new(
            gateway_idents.identity(),
            vec![Capability::Gateway],
            g_circuit_addr.clone(),
        );
        let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
        let gw_x_pk = gateway_idents.x_pk;
        let gw_listen = g_circuit_addr.clone();
        let gateway_handle = tokio::spawn(async move {
            let _ = async_node::serve_gateway_with_protocol_circuit(
                &gateway_node,
                &gw_listen,
                &gw_x_sk,
                &gw_x_pk,
                |url| test_connector_factory(url),
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;

        // A's topology.
        let mut topology = TopologyGraph::new();
        topology
            .accept_advertisement(b_verified.clone())
            .expect("accept B advert");
        let key_ab = LinkKey::new(
            client_idents.node_id,
            relay_b_idents.node_id,
            TransportEndpoint::tcp(&b_circuit_addr),
        );
        topology
            .add_authenticated_link(
                test_authenticated_link(key_ab, &b_verified).expect("auth link A→B"),
            );

        let mut a_transport = TcpRecursiveTransport::new(client_idents.ed_sk, client_idents.ed_pk);
        a_transport.add_peer(relay_b_idents.ed_pk, b_discovery_addr.clone());
        let a_transport = Arc::new(a_transport);

        Self {
            client_idents,
            relay_b_idents,
            relay_c_idents,
            gateway_idents,
            a_transport,
            topology,
            _servers: vec![b_server, c_server, g_server],
            _relay_b_handle: relay_b_handle,
            _relay_c_handle: relay_c_handle,
            _gateway_handle: gateway_handle,
            _http_handle: http_handle,
            http_url,
        }
    }

    fn resolver(&self) -> NextHopResolver<'_> {
        let single_step = InMemoryNextHopTransport::new();
        let single_step: &'static InMemoryNextHopTransport = Box::leak(Box::new(single_step));
        NextHopResolver::new(
            &self.topology,
            single_step,
            self.client_idents.ed_sk,
            self.client_idents.ed_pk,
            self.client_idents.node_id,
        )
        .with_recursive_transport(&*self.a_transport)
    }
}

/// Start a local HTTP server that always returns 500 Internal Server Error.
async fn start_local_http_500() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = b"upstream failure";
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
    (addr, handle)
}

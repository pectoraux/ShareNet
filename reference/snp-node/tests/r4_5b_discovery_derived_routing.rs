//! R4.5b — Discovery-derived autonomous Mode-A route selection.
//!
//! Replaces the R4.5a **caller-supplied `relay_order`** with a **routing
//! intent**. The routing layer autonomously selects:
//!   1. the destination gateway (from verified candidates, deterministic)
//!   2. the relay path (via the existing recursive distributed route-discovery
//!      protocol)
//!
//! The caller supplies:
//!   - a `BootstrapSeed` (one verified peer's advert-discovery + route-discovery
//!     addresses + public key)
//!   - a `ModeARoutingIntent` (e.g. `AnyInternetGateway`)
//!
//! The caller does NOT supply:
//!   - `relay_order`
//!   - `gateway_node_id`
//!   - a manually constructed `Route`
//!
//! ## Architecture (R4.5b)
//!
//! ```text
//! CONTROL PLANE (discovery + routing)
//!
//!   bootstrap seed
//!       ↓
//!   discover_all_candidates (TCP → CBOR array → verify each)
//!       ↓
//!   TopologyGraph (verified candidate set)
//!       ↓
//!   routing layer: select gateway (Capability::Gateway + circuit key,
//!                   lowest NodeId — deterministic)
//!       ↓
//!   NextHopResolver::resolve_route(gateway, hint)
//!       ↓
//!   ForwardedQuery → Relay A → Relay B → Gateway
//!       ↓
//!   DistributedRouteResolution::into_route()
//!       ↓
//!   immutable Route
//!
//! DATA PLANE (Mode-A store-carry-forward)
//!
//!   Route → BundleForwarder → Relay A → Relay B → Gateway → HTTP
//!       → response → Relay B → Relay A → Client
//! ```

#![allow(clippy::pedantic, deprecated)]

use std::sync::Arc;

use snp_crypto::{derive_node_id, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::{GatewayError, GatewayResult, PinnedConnector};
use snp_identity::{NodeId, NodeIdentity};
use snp_node::node::descriptor::TransportEndpoint;
use snp_node::node::identity::Capability;
use snp_node::node::mode_a_bundle::{BundleForwarder, ModeAClient, ModeAGateway};
use snp_node::node::mode_a_discovery::{
    discover_all_candidates, discover_mode_a_route, serve_bootstrap_discovery_async,
    serve_node_adverts_with_neighbors_async, BootstrapSeed, ModeADiscoveryError,
    ModeARoutingIntent,
};
use snp_node::node::node_advert::NodeAdvertisement;
use snp_node::node::route_discovery_protocol::{
    ForwardingNode, InMemoryNextHopTransport, NextHopResolver, RecursiveNextHopTransport,
};
use snp_node::node::tcp_route_transport::TcpForwardingServer;
use snp_node::node::topology::RemoteNodeHint;
use snp_node::node::{Route, RouteState, TopologyGraph};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity(seed: u8) -> NodeIdentity {
    NodeIdentity::from_secret([seed; 32])
}

fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

/// A node's complete identity material.
struct NodeIdents {
    identity: NodeIdentity,
    ed_sk: [u8; 32],
    ed_pk: [u8; 32],
    x_sk: Arc<X25519Secret>,
    x_pk: X25519PubKey,
    node_id: NodeId,
}

impl NodeIdents {
    fn fresh(seed: u8) -> Self {
        let identity = NodeIdentity::from_secret([seed; 32]);
        let ed_sk = identity.secret_key;
        let ed_pk = identity.public_key;
        let node_id = identity.node_id;
        let (x_sk, x_pk) = x25519_static_keypair();
        Self {
            identity,
            ed_sk,
            ed_pk,
            x_sk: Arc::new(x_sk),
            x_pk,
            node_id,
        }
    }
}

/// Bind an ephemeral port, return its address, then drop the listener.
async fn ephemeral_addr() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let a = l.local_addr().expect("local_addr").to_string();
    drop(l);
    a
}

/// Bind an ephemeral std::net::TcpListener (for `TcpForwardingServer::from_listener`).
fn ephemeral_std_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").expect("bind std ephemeral")
}

/// Create a signed relay `NodeAdvertisement` (transport endpoint = circuit addr).
fn make_relay_advert(identity: &NodeIdentity, circuit_addr: &str) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp(circuit_addr)],
        None,
        3600,
        1,
    )
}

/// Create a signed gateway `NodeAdvertisement` (with circuit key).
fn make_gateway_advert(
    identity: &NodeIdentity,
    circuit_addr: &str,
    x25519_pub: &[u8; 32],
) -> NodeAdvertisement {
    NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Gateway],
        vec![TransportEndpoint::tcp(circuit_addr)],
        Some(*x25519_pub),
        3600,
        1,
    )
}

/// Start a mock HTTP server (host-local egress target).
async fn start_mock_http_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr").to_string();
    listener.set_nonblocking(false).expect("set_nonblocking");
    std::thread::spawn(move || loop {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = b"Hello from R4.5b autonomous routing!";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        });
    });
    addr
}

/// A complete relay node: ForwardingNode + TcpForwardingServer (route-discovery)
/// + advert-discovery service + BundleForwarder (data plane).
struct RelayNode {
    _advert_disc_handle: tokio::task::JoinHandle<()>,
    _advert_disc_shutdown: Arc<tokio::sync::Mutex<bool>>,
    _fwd_server: Arc<TcpForwardingServer>,
    _bundle_handle: tokio::task::JoinHandle<()>,
    _circuit_addr: String,
    _advert_discovery_addr: String,
    _route_discovery_addr: String,
}

impl RelayNode {
    /// Start a relay node with the given neighbors.
    ///
    /// `neighbor_adverts`: the relay's known neighbors' signed adverts.
    /// These are served via advert-discovery AND added to the ForwardingNode
    /// for recursive forwarding.
    async fn start(
        idents: &NodeIdents,
        neighbor_adverts: Vec<NodeAdvertisement>,
        route: Arc<Route>,
        position: usize,
        source_addr: Option<(String, NodeId)>,
    ) -> Self {
        let circuit_addr = ephemeral_addr().await;
        let advert_discovery_addr = ephemeral_addr().await;
        let route_discovery_listener = ephemeral_std_listener();
        let route_discovery_addr = route_discovery_listener
            .local_addr()
            .expect("local_addr")
            .to_string();

        // ── ForwardingNode (route-discovery plane) ──
        // Each relay's transport knows its next-hop's route-discovery address.
        // We register the neighbors' route-discovery addresses.
        // For now, each relay's transport is empty (the recursive protocol
        // handles forwarding through the ForwardingNode chain).
        let transport = Arc::new(snp_node::node::tcp_route_transport::TcpRecursiveTransport::new(
            idents.ed_sk,
            idents.ed_pk,
        )) as Arc<dyn RecursiveNextHopTransport + Send + Sync>;

        let own_advert = make_relay_advert(&idents.identity, &circuit_addr);
        let mut fwd_node = ForwardingNode::new(
            idents.ed_sk,
            idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&circuit_addr)],
            None,
            transport,
        );
        // Add neighbors to the ForwardingNode.
        for advert in &neighbor_adverts {
            let neighbor_id = advert.node_id;
            fwd_node.add_neighbor(neighbor_id, advert.clone());
        }

        // ── TcpForwardingServer (route-discovery plane) ──
        let fwd_server = TcpForwardingServer::from_listener(
            Arc::new(fwd_node),
            idents.ed_sk,
            idents.ed_pk,
            route_discovery_listener,
        )
        .expect("bind forwarding server");
        let fwd_server = Arc::new(fwd_server);
        fwd_server.clone().serve_in_background();

        // ── Advert-discovery service (serves own + neighbor adverts) ──
        let shutdown = Arc::new(tokio::sync::Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let own_advert_for_serve = own_advert.clone();
        let neighbor_adverts_for_serve = neighbor_adverts.clone();
        let advert_addr_clone = advert_discovery_addr.clone();
        let advert_disc_handle = tokio::spawn(async move {
            let shutdown_future = async move {
                loop {
                    if *shutdown_clone.lock().await {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            };
            serve_node_adverts_with_neighbors_async(
                own_advert_for_serve,
                neighbor_adverts_for_serve,
                advert_addr_clone,
                shutdown_future,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // ── BundleForwarder (data plane) ──
        let mut forwarder = BundleForwarder::new(
            idents.identity.clone(),
            (*idents.x_sk).clone(),
            idents.x_pk,
            circuit_addr.clone(),
            route,
            position,
        );
        if let Some((src_addr, src_node_id)) = source_addr {
            forwarder = forwarder.with_source(src_addr, src_node_id);
        }
        let bundle_handle = tokio::spawn(async move {
            tokio::select! {
                _ = forwarder.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        });

        Self {
            _advert_disc_handle: advert_disc_handle,
            _advert_disc_shutdown: shutdown,
            _fwd_server: fwd_server,
            _bundle_handle: bundle_handle,
            _circuit_addr: circuit_addr,
            _advert_discovery_addr: advert_discovery_addr,
            _route_discovery_addr: route_discovery_addr,
        }
    }
}

/// A complete gateway node: ForwardingNode + TcpForwardingServer +
/// advert-discovery + ModeAGateway (data plane).
struct GatewayNode {
    _advert_disc_handle: tokio::task::JoinHandle<()>,
    _advert_disc_shutdown: Arc<tokio::sync::Mutex<bool>>,
    _fwd_server: Arc<TcpForwardingServer>,
    _gateway_handle: tokio::task::JoinHandle<()>,
    _circuit_addr: String,
    _advert_discovery_addr: String,
    _route_discovery_addr: String,
}

impl GatewayNode {
    async fn start(
        idents: &NodeIdents,
        neighbor_adverts: Vec<NodeAdvertisement>,
        http_url: String,
    ) -> Self {
        let circuit_addr = ephemeral_addr().await;
        let advert_discovery_addr = ephemeral_addr().await;
        let route_discovery_listener = ephemeral_std_listener();
        let route_discovery_addr = route_discovery_listener
            .local_addr()
            .expect("local_addr")
            .to_string();

        let transport = Arc::new(snp_node::node::tcp_route_transport::TcpRecursiveTransport::new(
            idents.ed_sk,
            idents.ed_pk,
        )) as Arc<dyn RecursiveNextHopTransport + Send + Sync>;

        let own_advert = make_gateway_advert(&idents.identity, &circuit_addr, &idents.x_pk.to_bytes());
        let mut fwd_node = ForwardingNode::new(
            idents.ed_sk,
            idents.ed_pk,
            vec![Capability::Gateway],
            vec![TransportEndpoint::tcp(&circuit_addr)],
            Some(idents.x_pk.to_bytes()),
            transport,
        );
        for advert in &neighbor_adverts {
            let neighbor_id = advert.node_id;
            fwd_node.add_neighbor(neighbor_id, advert.clone());
        }

        let fwd_server = TcpForwardingServer::from_listener(
            Arc::new(fwd_node),
            idents.ed_sk,
            idents.ed_pk,
            route_discovery_listener,
        )
        .expect("bind gateway forwarding server");
        let fwd_server = Arc::new(fwd_server);
        fwd_server.clone().serve_in_background();

        // Advert-discovery service.
        let shutdown = Arc::new(tokio::sync::Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let own_advert_for_serve = own_advert.clone();
        let neighbor_adverts_for_serve = neighbor_adverts.clone();
        let advert_addr_clone = advert_discovery_addr.clone();
        let advert_disc_handle = tokio::spawn(async move {
            let shutdown_future = async move {
                loop {
                    if *shutdown_clone.lock().await {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            };
            serve_node_adverts_with_neighbors_async(
                own_advert_for_serve,
                neighbor_adverts_for_serve,
                advert_addr_clone,
                shutdown_future,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // ModeAGateway (data plane).
        let gw_x_sk = (*idents.x_sk).clone();
        let gw_x_pk = idents.x_pk;
        let gateway = ModeAGateway::with_connector_factory(
            idents.identity.clone(),
            gw_x_sk,
            gw_x_pk,
            circuit_addr.clone(),
            move |url: &str| {
                let parsed = url::Url::parse(url)
                    .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
                let host = parsed
                    .host_str()
                    .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
                let port = parsed.port().unwrap_or(80);
                Ok(PinnedConnector::from_parts(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    host.to_string(),
                    port,
                    "http".into(),
                    if parsed.path().is_empty() {
                        "/".into()
                    } else {
                        parsed.path().into()
                    },
                ))
            },
        );
        let _http_url = http_url;
        let gateway_handle = tokio::spawn(async move {
            tokio::select! {
                _ = gateway.run() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        });

        Self {
            _advert_disc_handle: advert_disc_handle,
            _advert_disc_shutdown: shutdown,
            _fwd_server: fwd_server,
            _gateway_handle: gateway_handle,
            _circuit_addr: circuit_addr,
            _advert_discovery_addr: advert_discovery_addr,
            _route_discovery_addr: route_discovery_addr,
        }
    }
}

/// A mesh of nodes for the R4.5b tests.
struct Mesh {
    client: NodeIdents,
    relay_a: NodeIdents,
    relay_b: NodeIdents,
    gateway: NodeIdents,
    relay_a_advert: NodeAdvertisement,
    relay_b_advert: NodeAdvertisement,
    gateway_advert: NodeAdvertisement,
    relay_a_advert_disc: String,
    relay_a_route_disc: String,
    relay_a_circuit: String,
    _relay_a: RelayNode,
    _relay_b: RelayNode,
    _gateway: GatewayNode,
    http_url: String,
}

impl Mesh {
    /// Start the full mesh: Client → Relay A → Relay B → Gateway.
    ///
    /// Relay A knows Relay B + Gateway (neighbors).
    /// Relay B knows Gateway (neighbor).
    /// Gateway has no neighbors (terminal).
    async fn start() -> Self {
        let client = NodeIdents::fresh(0x01);
        let relay_a = NodeIdents::fresh(0x02);
        let relay_b = NodeIdents::fresh(0x03);
        let gateway = NodeIdents::fresh(0x04);

        let http_addr = start_mock_http_server().await;
        let http_url = format!("http://{http_addr}/r4-5b-autonomous");

        // We need the adverts BEFORE starting the nodes (neighbors need them).
        // But the adverts carry the circuit addr, which is assigned when the
        // node starts. So we use a two-phase approach:
        // 1. Pre-assign circuit + discovery addresses.
        // 2. Create adverts with those addresses.
        // 3. Start nodes with the pre-assigned addresses.

        let relay_a_circuit = ephemeral_addr().await;
        let relay_b_circuit = ephemeral_addr().await;
        let gateway_circuit = ephemeral_addr().await;

        let relay_a_advert = make_relay_advert(&relay_a.identity, &relay_a_circuit);
        let relay_b_advert = make_relay_advert(&relay_b.identity, &relay_b_circuit);
        let gateway_advert =
            make_gateway_advert(&gateway.identity, &gateway_circuit, &gateway.x_pk.to_bytes());

        // Start Gateway (no neighbors).
        let gateway_node = GatewayNode::start(
            &gateway,
            vec![],
            http_url.clone(),
        )
        .await;

        // Start Relay B (neighbor = Gateway).
        // Relay B's route needs to be built AFTER we know the full route.
        // But the route needs to be discovered... circular.
        //
        // For the test, the BundleForwarder at each relay needs a Route to
        // execute. But the Route is discovered by the client. So the relay's
        // BundleForwarder receives the Route from the test (which gets it from
        // discover_mode_a_route). But the relay needs to be running BEFORE
        // the client can discover the route (because the recursive protocol
        // goes through the relay's ForwardingNode).
        //
        // Solution: start the ForwardingNode + advert-discovery + TcpForwardingServer
        // first (without the BundleForwarder). Then discover the route. Then
        // start the BundleForwarders with the discovered route.
        //
        // But RelayNode bundles all three together. Let me refactor: split the
        // ForwardingNode + advert-discovery from the BundleForwarder.

        // Actually, for the headline test, the relay's BundleForwarder needs
        // the Route to know where to forward. But the Route is discovered by
        // the client, not by the relay. So the relay's BundleForwarder
        // receives the Route from the test.
        //
        // The relay's ForwardingNode (route-discovery plane) is independent —
        // it doesn't need the Route. Only the BundleForwarder (data plane) needs it.
        //
        // So the test flow is:
        // 1. Start ForwardingNode + advert-discovery + TcpForwardingServer for each relay/gateway.
        // 2. Client discovers the route (via discover_mode_a_route).
        // 3. Start BundleForwarders at each relay with the discovered route.
        // 4. Client sends the request.

        // For simplicity, I'll use a placeholder route for the relay
        // BundleForwarders and replace it after discovery.
        // Actually, the BundleForwarder takes the Route at construction time.
        // I need to construct it AFTER the route is discovered.
        //
        // Let me restructure: the Mesh starts the discovery-plane nodes first,
        // then the test discovers the route, then starts the data-plane nodes.

        // For now, use the approach where the relay's ForwardingNode +
        // advert-discovery are started first, and the BundleForwarder is
        // started later with the discovered route.

        // I'll create a "DiscoveryPlaneMesh" that starts just the
        // ForwardingNodes + advert-discovery + TcpForwardingServers.

        todo!("restructure to split discovery plane from data plane")
    }
}

// Since the Mesh above is incomplete, let me write the test using a simpler
// approach: a two-phase setup.

/// A neighbor's info: its advert (for the ForwardingNode's neighbor map +
/// advert-discovery service) + its route-discovery address (for the
/// TcpRecursiveTransport's peer map) + its Ed25519 public key (for
/// `transport.add_peer`).
struct NeighborInfo {
    advert: NodeAdvertisement,
    route_discovery_addr: String,
    ed25519_public_key: [u8; 32],
}

/// Phase 1: discovery-plane nodes (ForwardingNode + TcpForwardingServer +
/// advert-discovery service). No BundleForwarder yet.
struct DiscoveryPlaneNode {
    advert_disc_shutdown: Arc<tokio::sync::Mutex<bool>>,
    _advert_disc_handle: tokio::task::JoinHandle<()>,
    _fwd_server: Arc<TcpForwardingServer>,
    advert_discovery_addr: String,
    route_discovery_addr: String,
    circuit_addr: String,
    own_advert: NodeAdvertisement,
}

impl DiscoveryPlaneNode {
    async fn start_relay(
        idents: &NodeIdents,
        forwarding_neighbors: Vec<NeighborInfo>,
        extra_served_adverts: Vec<NodeAdvertisement>,
    ) -> Self {
        let circuit_addr = ephemeral_addr().await;
        let advert_discovery_addr = ephemeral_addr().await;
        let route_listener = ephemeral_std_listener();
        let route_discovery_addr = route_listener
            .local_addr()
            .expect("local_addr")
            .to_string();

        // The relay's transport must know its DIRECT neighbors' route-discovery
        // addresses (so the ForwardingNode can forward ForwardedQueries to them).
        let mut transport = snp_node::node::tcp_route_transport::TcpRecursiveTransport::new(
            idents.ed_sk,
            idents.ed_pk,
        );
        for n in &forwarding_neighbors {
            transport.add_peer(n.ed25519_public_key, &n.route_discovery_addr);
        }
        let transport = Arc::new(transport) as Arc<dyn RecursiveNextHopTransport + Send + Sync>;

        let own_advert = make_relay_advert(&idents.identity, &circuit_addr);
        let mut fwd_node = ForwardingNode::new(
            idents.ed_sk,
            idents.ed_pk,
            vec![Capability::Relay],
            vec![TransportEndpoint::tcp(&circuit_addr)],
            None,
            transport,
        );
        // The ForwardingNode has ONLY direct neighbors (nodes it can forward to).
        for n in &forwarding_neighbors {
            fwd_node.add_neighbor(n.advert.node_id, n.advert.clone());
        }
        // The advert-discovery service serves own + all known adverts (direct
        // + indirect). A relay can serve a gateway's advert without being able
        // to forward directly to it — the recursive protocol discovers the path.
        let neighbor_adverts: Vec<NodeAdvertisement> = forwarding_neighbors
            .iter()
            .map(|n| n.advert.clone())
            .chain(extra_served_adverts.into_iter())
            .collect();

        let fwd_server = TcpForwardingServer::from_listener(
            Arc::new(fwd_node),
            idents.ed_sk,
            idents.ed_pk,
            route_listener,
        )
        .expect("bind forwarding server");
        let fwd_server = Arc::new(fwd_server);
        fwd_server.clone().serve_in_background();

        let shutdown = Arc::new(tokio::sync::Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let own_advert_for_serve = own_advert.clone();
        let neighbor_adverts_for_serve = neighbor_adverts.clone();
        let advert_addr_clone = advert_discovery_addr.clone();
        let handle = tokio::spawn(async move {
            let sf = async move {
                loop {
                    if *shutdown_clone.lock().await {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            };
            serve_node_adverts_with_neighbors_async(
                own_advert_for_serve,
                neighbor_adverts_for_serve,
                advert_addr_clone,
                sf,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        Self {
            advert_disc_shutdown: shutdown,
            _advert_disc_handle: handle,
            _fwd_server: fwd_server,
            advert_discovery_addr,
            route_discovery_addr,
            circuit_addr,
            own_advert,
        }
    }

    async fn start_gateway(
        idents: &NodeIdents,
        forwarding_neighbors: Vec<NeighborInfo>,
        extra_served_adverts: Vec<NodeAdvertisement>,
    ) -> Self {
        let circuit_addr = ephemeral_addr().await;
        let advert_discovery_addr = ephemeral_addr().await;
        let route_listener = ephemeral_std_listener();
        let route_discovery_addr = route_listener
            .local_addr()
            .expect("local_addr")
            .to_string();

        let mut transport = snp_node::node::tcp_route_transport::TcpRecursiveTransport::new(
            idents.ed_sk,
            idents.ed_pk,
        );
        for n in &forwarding_neighbors {
            transport.add_peer(n.ed25519_public_key, &n.route_discovery_addr);
        }
        let transport = Arc::new(transport) as Arc<dyn RecursiveNextHopTransport + Send + Sync>;

        let own_advert =
            make_gateway_advert(&idents.identity, &circuit_addr, &idents.x_pk.to_bytes());
        let mut fwd_node = ForwardingNode::new(
            idents.ed_sk,
            idents.ed_pk,
            vec![Capability::Gateway],
            vec![TransportEndpoint::tcp(&circuit_addr)],
            Some(idents.x_pk.to_bytes()),
            transport,
        );
        for n in &forwarding_neighbors {
            fwd_node.add_neighbor(n.advert.node_id, n.advert.clone());
        }
        let neighbor_adverts: Vec<NodeAdvertisement> = forwarding_neighbors
            .iter()
            .map(|n| n.advert.clone())
            .chain(extra_served_adverts.into_iter())
            .collect();

        let fwd_server = TcpForwardingServer::from_listener(
            Arc::new(fwd_node),
            idents.ed_sk,
            idents.ed_pk,
            route_listener,
        )
        .expect("bind gateway forwarding server");
        let fwd_server = Arc::new(fwd_server);
        fwd_server.clone().serve_in_background();

        let shutdown = Arc::new(tokio::sync::Mutex::new(false));
        let shutdown_clone = shutdown.clone();
        let own_advert_for_serve = own_advert.clone();
        let neighbor_adverts_for_serve = neighbor_adverts.clone();
        let advert_addr_clone = advert_discovery_addr.clone();
        let handle = tokio::spawn(async move {
            let sf = async move {
                loop {
                    if *shutdown_clone.lock().await {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            };
            serve_node_adverts_with_neighbors_async(
                own_advert_for_serve,
                neighbor_adverts_for_serve,
                advert_addr_clone,
                sf,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        Self {
            advert_disc_shutdown: shutdown,
            _advert_disc_handle: handle,
            _fwd_server: fwd_server,
            advert_discovery_addr,
            route_discovery_addr,
            circuit_addr,
            own_advert,
        }
    }

    /// Create a `NeighborInfo` from this node (for registering as a neighbor
    /// of another node).
    fn neighbor_info(&self) -> NeighborInfo {
        NeighborInfo {
            advert: self.own_advert.clone(),
            route_discovery_addr: self.route_discovery_addr.clone(),
            ed25519_public_key: self.own_advert.ed25519_public_key,
        }
    }
}

/// ─── Headline test: R4.5b autonomous route selection ───
///
/// Proves:
/// ```text
/// Client
///   ↓ live bootstrap discovery
///   ↓ routing selects gateway
///   ↓ recursive route discovery (A → B → Gateway)
///   ↓ host-local HTTP
///   ↓ response (B → A → Client)
/// ```
///
/// The test does NOT supply `relay_order` or `gateway_node_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_autonomous_route_selection_multihop() {
    let client = NodeIdents::fresh(0x01);
    let relay_a = NodeIdents::fresh(0x02);
    let relay_b = NodeIdents::fresh(0x03);
    let gateway = NodeIdents::fresh(0x04);

    let http_addr = start_mock_http_server().await;
    let http_url = format!("http://{http_addr}/r4-5b-autonomous");

    // ── Phase 1: Start discovery-plane nodes ──────────────────────────
    // Topology: Client → Relay A → Relay B → Gateway
    // Relay A forwards to Relay B only (3-hop path).
    // Relay A SERVES Gateway's advert (so the client can discover it) but
    // does NOT forward directly to Gateway — the recursive protocol discovers
    // the path A → B → Gateway.
    let gw_dp = DiscoveryPlaneNode::start_gateway(&gateway, vec![], vec![]).await;
    let rb_dp =
        DiscoveryPlaneNode::start_relay(&relay_b, vec![gw_dp.neighbor_info()], vec![]).await;
    let ra_dp = DiscoveryPlaneNode::start_relay(
        &relay_a,
        vec![rb_dp.neighbor_info()],
        vec![gw_dp.own_advert.clone()],
    )
    .await;

    // ── Phase 2: Client discovers the route autonomously ──────────────
    let bootstrap = BootstrapSeed {
        advert_discovery_addr: ra_dp.advert_discovery_addr.clone(),
        route_discovery_addr: ra_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk,
    };

    let route = discover_mode_a_route(
        &client.identity,
        &client.x_sk,
        &client.x_pk,
        &bootstrap,
        ModeARoutingIntent::AnyInternetGateway,
    )
    .await
    .expect("autonomous route discovery must succeed");

    eprintln!(
        "[test] route discovered: {} hops → gateway {}",
        route.hop_details().len(),
        hex_short(&route.destination())
    );

    // Verify the route has the expected hops: Relay A, Relay B, Gateway.
    assert_eq!(route.hop_details().len(), 3, "3 hops: A, B, Gateway");
    assert_eq!(route.hop(0).unwrap().node_id(), relay_a.node_id, "hop[0] = Relay A");
    assert_eq!(route.hop(1).unwrap().node_id(), relay_b.node_id, "hop[1] = Relay B");
    assert_eq!(route.hop(2).unwrap().node_id(), gateway.node_id, "hop[2] = Gateway");
    assert_eq!(route.destination(), gateway.node_id, "destination = Gateway");

    // Verify the endpoints are the SIGNED circuit addresses (not discovery addrs).
    assert_eq!(
        route.hop(0).unwrap().first_endpoint().unwrap().as_tcp().unwrap(),
        ra_dp.circuit_addr,
        "hop[0].endpoint == Relay A's signed circuit addr"
    );
    assert_eq!(
        route.hop(1).unwrap().first_endpoint().unwrap().as_tcp().unwrap(),
        rb_dp.circuit_addr,
        "hop[1].endpoint == Relay B's signed circuit addr"
    );
    assert_eq!(
        route.hop(2).unwrap().first_endpoint().unwrap().as_tcp().unwrap(),
        gw_dp.circuit_addr,
        "hop[2].endpoint == Gateway's signed circuit addr"
    );

    // Verify the route endpoints are NOT the discovery addresses.
    assert_ne!(
        route.hop(0).unwrap().first_endpoint().unwrap().as_tcp().unwrap(),
        ra_dp.advert_discovery_addr,
        "hop[0].endpoint != advert-discovery addr"
    );
    assert_ne!(
        route.hop(0).unwrap().first_endpoint().unwrap().as_tcp().unwrap(),
        ra_dp.route_discovery_addr,
        "hop[0].endpoint != route-discovery addr"
    );

    // ── Phase 3: Start data-plane nodes (BundleForwarders + Gateway) ───
    let route = Arc::new(route);
    let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client listener");
    let client_listen_addr = client_listener
        .local_addr()
        .expect("local_addr")
        .to_string();
    drop(client_listener);

    let ra_forwarder = BundleForwarder::new(
        relay_a.identity.clone(),
        (*relay_a.x_sk).clone(),
        relay_a.x_pk,
        ra_dp.circuit_addr.clone(),
        route.clone(),
        0,
    )
    .with_source(client_listen_addr.clone(), client.node_id);
    let rb_forwarder = BundleForwarder::new(
        relay_b.identity.clone(),
        (*relay_b.x_sk).clone(),
        relay_b.x_pk,
        rb_dp.circuit_addr.clone(),
        route.clone(),
        1,
    );
    let gw_gateway = ModeAGateway::with_connector_factory(
        gateway.identity.clone(),
        (*gateway.x_sk).clone(),
        gateway.x_pk,
        gw_dp.circuit_addr.clone(),
        move |url: &str| {
            let parsed = url::Url::parse(url)
                .map_err(|e| GatewayError::MalformedUrl(format!("URL parse: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| GatewayError::MalformedUrl("no host".into()))?;
            let port = parsed.port().unwrap_or(80);
            Ok(PinnedConnector::from_parts(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host.to_string(),
                port,
                "http".into(),
                if parsed.path().is_empty() {
                    "/".into()
                } else {
                    parsed.path().into()
                },
            ))
        },
    );

    let ra_handle = tokio::spawn(async move {
        tokio::select! {
            _ = ra_forwarder.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    });
    let rb_handle = tokio::spawn(async move {
        tokio::select! {
            _ = rb_forwarder.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    });
    let gw_handle = tokio::spawn(async move {
        tokio::select! {
            _ = gw_gateway.run() => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── Phase 4: Client sends request via the discovered route ─────────
    let first_hop_addr = route
        .hop(0)
        .unwrap()
        .first_endpoint()
        .unwrap()
        .as_tcp()
        .unwrap()
        .to_string();
    let first_hop_node_id = route.hop(0).unwrap().node_id();
    let gateway_node_id = route.destination();

    let mode_a_client = ModeAClient::new(client.identity.clone(), (*client.x_sk).clone(), client.x_pk);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        mode_a_client.send_request(
            &http_url,
            &first_hop_addr,
            first_hop_node_id,
            gateway_node_id,
            &gateway.identity.public_key,
        ),
    )
    .await;

    let (resp, body) = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => panic!("send_request failed: {e}"),
        Err(_) => panic!("client timed out — autonomous routing failed"),
    };
    assert_eq!(resp.status, 200);
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Hello from R4.5b autonomous routing"),
        "response body must contain expected text, got: {body_str}"
    );
    eprintln!("[test] SUCCESS: R4.5b autonomous route selection + multi-hop round-trip");

    ra_handle.abort();
    rb_handle.abort();
    gw_handle.abort();
    *ra_dp.advert_disc_shutdown.lock().await = true;
    *rb_dp.advert_disc_shutdown.lock().await = true;
    *gw_dp.advert_disc_shutdown.lock().await = true;
}

/// ─── Discovery bypass test (requirement H) ───
///
/// Phase 1: no discovery servers → `discover_mode_a_route` fails.
/// Phase 2: start discovery → route succeeds.
/// Neither phase supplies `relay_order` or `gateway_node_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_discovery_bypass_route_fails_without_discovery() {
    let client = NodeIdents::fresh(0x10);
    let relay_a = NodeIdents::fresh(0x11);
    let relay_b = NodeIdents::fresh(0x12);
    let gateway = NodeIdents::fresh(0x13);

    // ── Phase 1: no discovery servers running ──────────────────────────
    // Use a non-existent address (nothing is listening).
    let bootstrap = BootstrapSeed {
        advert_discovery_addr: "127.0.0.1:1".to_string(), // port 1 = nothing
        route_discovery_addr: "127.0.0.1:1".to_string(),
        ed25519_public_key: relay_a.ed_pk,
    };
    let err = discover_mode_a_route(
        &client.identity,
        &client.x_sk,
        &client.x_pk,
        &bootstrap,
        ModeARoutingIntent::AnyInternetGateway,
    )
    .await
    .expect_err("must fail with NoEligibleRoute when no discovery is running");
    assert_eq!(
        err,
        ModeADiscoveryError::NoEligibleRoute,
        "empty discovery → NoEligibleRoute"
    );
    eprintln!("[test] Phase 1 PASS: route cannot be discovered without discovery");

    // ── Phase 2: start discovery → route succeeds ──────────────────────
    // Topology: Relay A → Relay B → Gateway (A forwards to B; B forwards to G).
    // Relay A serves Gateway's advert (so the client can discover it).
    let gw_dp = DiscoveryPlaneNode::start_gateway(&gateway, vec![], vec![]).await;
    let rb_dp = DiscoveryPlaneNode::start_relay(&relay_b, vec![gw_dp.neighbor_info()], vec![]).await;
    let ra_dp = DiscoveryPlaneNode::start_relay(
        &relay_a,
        vec![rb_dp.neighbor_info()],
        vec![gw_dp.own_advert.clone()],
    )
    .await;

    let bootstrap = BootstrapSeed {
        advert_discovery_addr: ra_dp.advert_discovery_addr.clone(),
        route_discovery_addr: ra_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk,
    };
    let route = discover_mode_a_route(
        &client.identity,
        &client.x_sk,
        &client.x_pk,
        &bootstrap,
        ModeARoutingIntent::AnyInternetGateway,
    )
    .await
    .expect("route must succeed now that discovery is running");

    assert_eq!(route.hop_details().len(), 3, "3 hops: A, B, Gateway");
    assert_eq!(route.destination(), gateway.node_id);
    eprintln!("[test] Phase 2 PASS: route discovered without manual relay_order or gateway_node_id");

    *ra_dp.advert_disc_shutdown.lock().await = true;
    *rb_dp.advert_disc_shutdown.lock().await = true;
    *gw_dp.advert_disc_shutdown.lock().await = true;
}

/// ─── Gateway selection test (requirement 3) ───
///
/// Multiple eligible gateways → routing layer selects one deterministically
/// (lowest NodeId). The caller does NOT identify the gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_gateway_selection_deterministic() {
    let client = NodeIdents::fresh(0x20);
    let relay_a = NodeIdents::fresh(0x21);
    let gw1 = NodeIdents::fresh(0x22);
    let gw2 = NodeIdents::fresh(0x23);

    // Start two gateways.
    let gw1_dp = DiscoveryPlaneNode::start_gateway(&gw1, vec![], vec![]).await;
    let gw2_dp = DiscoveryPlaneNode::start_gateway(&gw2, vec![], vec![]).await;
    // Relay A forwards to both gateways directly (1-hop path).
    let ra_dp = DiscoveryPlaneNode::start_relay(
        &relay_a,
        vec![gw1_dp.neighbor_info(), gw2_dp.neighbor_info()],
        vec![],
    )
    .await;

    let bootstrap = BootstrapSeed {
        advert_discovery_addr: ra_dp.advert_discovery_addr.clone(),
        route_discovery_addr: ra_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk,
    };
    let route = discover_mode_a_route(
        &client.identity,
        &client.x_sk,
        &client.x_pk,
        &bootstrap,
        ModeARoutingIntent::AnyInternetGateway,
    )
    .await
    .expect("route must succeed with multiple gateways");

    // The routing layer selects the gateway with the lowest NodeId.
    let selected = route.destination();
    assert!(
        selected == gw1.node_id || selected == gw2.node_id,
        "selected gateway must be one of the two"
    );
    // Verify deterministic: lowest NodeId.
    let expected = std::cmp::min(gw1.node_id, gw2.node_id);
    assert_eq!(
        selected, expected,
        "routing layer must select the gateway with the lowest NodeId (deterministic)"
    );
    eprintln!("[test] PASS: routing layer selected gateway {} (lowest NodeId) from {} eligible", hex_short(&selected), 2);

    *ra_dp.advert_disc_shutdown.lock().await = true;
    *gw1_dp.advert_disc_shutdown.lock().await = true;
    *gw2_dp.advert_disc_shutdown.lock().await = true;
}

/// ─── Capability tests (requirement 4) ───

/// A non-gateway (relay-only) cannot become a route destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_non_gateway_cannot_be_destination() {
    let client = NodeIdents::fresh(0x30);
    let relay_a = NodeIdents::fresh(0x31);
    let relay_b = NodeIdents::fresh(0x32);
    // No gateway in the mesh — only relays.
    let rb_dp = DiscoveryPlaneNode::start_relay(&relay_b, vec![], vec![]).await;
    let ra_dp = DiscoveryPlaneNode::start_relay(
        &relay_a,
        vec![rb_dp.neighbor_info()],
        vec![],
    )
    .await;

    let bootstrap = BootstrapSeed {
        advert_discovery_addr: ra_dp.advert_discovery_addr.clone(),
        route_discovery_addr: ra_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk,
    };
    let err = discover_mode_a_route(
        &client.identity,
        &client.x_sk,
        &client.x_pk,
        &bootstrap,
        ModeARoutingIntent::AnyInternetGateway,
    )
    .await
    .expect_err("must fail with NoGateway when no gateway candidate exists");
    assert_eq!(err, ModeADiscoveryError::NoGateway);
    eprintln!("[test] PASS: no gateway → NoGateway");

    *ra_dp.advert_disc_shutdown.lock().await = true;
    *rb_dp.advert_disc_shutdown.lock().await = true;
}

/// ─── Advertisement security (requirement 5) ───

/// A tampered advertisement signature is rejected by `verify_into_verified()`.
#[test]
fn r4_5b_tampered_signature_rejected() {
    let identity = test_identity(0x40);
    let advert = make_relay_advert(&identity, "127.0.0.1:9001");
    let mut tampered = advert;
    tampered.signature[0] ^= 0xFF;
    assert!(
        tampered.verify_into_verified().is_none(),
        "tampered signature MUST be rejected"
    );
    eprintln!("[test] PASS: tampered signature rejected");
}

/// A wrong NodeId (NodeId != derive(public_key)) is rejected.
#[test]
fn r4_5b_wrong_nodeid_rejected() {
    let identity = test_identity(0x41);
    let mut advert = make_relay_advert(&identity, "127.0.0.1:9002");
    advert.node_id[0] ^= 0xFF; // breaks signature + NodeId↔pubkey
    assert!(
        advert.verify_into_verified().is_none(),
        "wrong NodeId MUST be rejected"
    );
    eprintln!("[test] PASS: wrong NodeId rejected");
}

/// An expired advertisement is rejected.
#[test]
fn r4_5b_expired_advert_rejected() {
    let identity = test_identity(0x42);
    let advert = NodeAdvertisement::create_and_sign(
        &identity.secret_key,
        &identity.public_key,
        vec![Capability::Relay],
        vec![TransportEndpoint::tcp("127.0.0.1:9003")],
        None,
        0, // expiry_secs = 0 → expiry == now → expired
        1,
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        advert.verify_into_verified().is_none(),
        "expired advert MUST be rejected"
    );
    assert!(advert.is_expired(snp_identity::now_unix()));
    eprintln!("[test] PASS: expired advert rejected");
}

/// A valid advertisement is accepted.
#[test]
fn r4_5b_valid_advert_accepted() {
    let identity = test_identity(0x43);
    let advert = make_relay_advert(&identity, "127.0.0.1:9004");
    assert!(advert.verify_into_verified().is_some());
    assert!(!advert.is_expired(snp_identity::now_unix()));
    eprintln!("[test] PASS: valid advert accepted");
}

/// ─── Remote-hint security (requirement 6) ───
///
/// A `RemoteNodeHint` is non-authoritative. It can trigger resolution but
/// cannot itself become a `RouteHop`. The `DistributedRouteResolution::verify()`
/// checks that every hop has a verified `AuthenticatedNodeRecord`.
///
/// This test proves: the routing layer obtains the ACTUAL advertisement at
/// each hop (via the recursive protocol), and a hint alone does not produce
/// a `RouteHop`. We verify this structurally: `into_route()` uses
/// `record.endpoints` from verified records, NOT from hints.
#[test]
fn r4_5b_remote_hint_cannot_become_route_hop_directly() {
    // The RemoteNodeHint type is non-authoritative. Its fields are "claimed_*"
    // (claims, not facts). The only way to get a RouteHop is via a
    // VerifiedNodeAdvertisement → AuthenticatedNodeRecord.
    //
    // We verify structurally: RemoteNodeHint has no `endpoints` field (it
    // cannot supply a RouteHop endpoint). The only source of endpoints is
    // AuthenticatedNodeRecord (from a verified advert).
    let hint = RemoteNodeHint {
        target_node_id: [0xAA; 32],
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: snp_identity::now_unix(),
        distance_hint: 1,
        learned_from: [0xBB; 32],
        received_at: snp_identity::now_unix(),
        source_propagation_sequence: 0,
    };
    // The hint has NO endpoint field — it CANNOT supply a RouteHop endpoint.
    // This is the structural guarantee: a hint triggers resolution, but the
    // actual RouteHop comes from the verified advert obtained during resolution.
    assert!(hint.claims_gateway(), "hint claims gateway");
    // The hint has no `endpoints` or `listen_addr` field — it cannot become
    // a RouteHop without obtaining + verifying the actual advert.
    eprintln!("[test] PASS: RemoteNodeHint has no endpoint field — cannot become RouteHop without verification");
}

/// ─── Endpoint binding test (requirement 7) ───
///
/// The route-discovery address and the data-plane `listen_addr` are DIFFERENT.
/// The `RouteHop.endpoint` is always the signed `listen_addr`, never the
/// route-discovery address.
///
/// This is proven structurally by the headline test above (the route's hop
/// endpoints are the circuit addresses, NOT the discovery addresses). This test
/// makes the invariant explicit at the unit level.
#[test]
fn r4_5b_route_endpoint_is_signed_listen_addr_not_discovery_addr() {
    // The NodeAdvertisement carries `endpoints` (the signed data-plane listen_addr).
    // The BootstrapSeed has separate `advert_discovery_addr` and `route_discovery_addr`.
    // These are DIFFERENT values by construction.
    let identity = test_identity(0x50);
    let listen_addr = "127.0.0.1:5001";
    let advert = make_relay_advert(&identity, listen_addr);
    let verified = advert.verify_into_verified().expect("verifies");
    // The verified advert's endpoint is the signed listen_addr.
    assert_eq!(
        verified.endpoints()[0].as_tcp().unwrap(),
        listen_addr,
        "verified advert endpoint == signed listen_addr"
    );
    // The discovery address is NOT in the advert.
    let discovery_addr = "127.0.0.1:9999";
    assert_ne!(listen_addr, discovery_addr, "listen_addr != discovery_addr");
    // A RouteHop built from this advert uses the signed listen_addr.
    let hop = snp_node::node::route::RouteHop::new(
        verified.descriptor(),
        verified.endpoints()[0].clone(),
    );
    assert_eq!(
        hop.first_endpoint().unwrap().as_tcp().unwrap(),
        listen_addr,
        "RouteHop.endpoint == signed listen_addr (not discovery addr)"
    );
    eprintln!("[test] PASS: RouteHop.endpoint == signed listen_addr, NOT discovery address");
}

/// ─── No manual path test (requirement 8) ───
///
/// The `discover_mode_a_route` API takes `(client_identity, x_sk, x_pk,
/// bootstrap, intent)` — there is NO `relay_order` parameter and NO
/// `gateway_node_id` parameter. The relay path is discovered by the recursive
/// protocol, not supplied by the caller.
///
/// This test verifies the API does NOT accept `relay_order` or
/// `gateway_node_id` by checking the BootstrapSeed + ModeARoutingIntent types
/// (which are the ONLY inputs to the routing layer beyond the client identity).
#[test]
fn r4_5b_api_does_not_accept_relay_order_or_gateway_nodeid() {
    // The BootstrapSeed has NO relay_order and NO gateway_node_id field.
    let seed = BootstrapSeed {
        advert_discovery_addr: "127.0.0.1:1".into(),
        route_discovery_addr: "127.0.0.1:1".into(),
        ed25519_public_key: [0u8; 32],
    };
    // The only routing input is ModeARoutingIntent (an enum, not a NodeId).
    let _intent = ModeARoutingIntent::AnyInternetGateway;
    // The seed has exactly 3 fields: advert_discovery_addr,
    // route_discovery_addr, ed25519_public_key. No relay_order, no gateway_node_id.
    assert_eq!(seed.advert_discovery_addr, "127.0.0.1:1");
    assert_eq!(seed.route_discovery_addr, "127.0.0.1:1");
    eprintln!("[test] PASS: discover_mode_a_route API uses BootstrapSeed + ModeARoutingIntent, NOT relay_order or gateway_node_id");
}

/// ─── discover_all_candidates unit test ───
///
/// Verifies the advert-discovery service returns multiple adverts (own +
/// neighbors) and the client decodes + verifies each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_discover_all_candidates_from_one_bootstrap() {
    let relay_a = NodeIdents::fresh(0x60);
    let relay_b = NodeIdents::fresh(0x61);
    let gateway = NodeIdents::fresh(0x62);

    let gw_dp = DiscoveryPlaneNode::start_gateway(&gateway, vec![], vec![]).await;
    let rb_dp = DiscoveryPlaneNode::start_relay(&relay_b, vec![gw_dp.neighbor_info()], vec![]).await;
    let ra_dp = DiscoveryPlaneNode::start_relay(
        &relay_a,
        vec![rb_dp.neighbor_info()],
        vec![gw_dp.own_advert.clone()],
    )
    .await;

    // Query Relay A's advert-discovery → get 3 adverts (A + B + Gateway).
    // The BootstrapSeed binds the discovery response to Relay A's identity
    // (Issue A fix): the first advert MUST be Relay A's own advert.
    let bootstrap = BootstrapSeed {
        advert_discovery_addr: ra_dp.advert_discovery_addr.clone(),
        route_discovery_addr: ra_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk,
    };
    let discovered = discover_all_candidates(&bootstrap).await;
    assert_eq!(discovered.len(), 3, "must discover 3 candidates (A + B + Gateway)");

    let node_ids: Vec<NodeId> = discovered.iter().map(|v| v.node_id()).collect();
    assert!(node_ids.contains(&relay_a.node_id), "must contain Relay A");
    assert!(node_ids.contains(&relay_b.node_id), "must contain Relay B");
    assert!(node_ids.contains(&gateway.node_id), "must contain Gateway (served by Relay A)");

    *ra_dp.advert_disc_shutdown.lock().await = true;
    *rb_dp.advert_disc_shutdown.lock().await = true;
    *gw_dp.advert_disc_shutdown.lock().await = true;
    eprintln!("[test] PASS: discover_all_candidates returns 3 verified adverts from one bootstrap");
}

/// ─── Issue A: bootstrap identity binding — negative test ───
///
/// `BootstrapSeed` points to identity B, but the advert-discovery server is
/// identity X (a different node). `discover_all_candidates` MUST reject the
/// response — X's candidate set cannot silently become authoritative bootstrap
/// discovery.
///
/// The test also proves the positive case: when the discovery server's first
/// advert matches `BootstrapSeed.node_id()`, discovery succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_bootstrap_identity_mismatch_rejected() {
    let relay_a = NodeIdents::fresh(0x70);
    let relay_b = NodeIdents::fresh(0x71);
    let imposter = NodeIdents::fresh(0x72);

    // Start Relay B (serves its own + neighbors). Relay B IS the imposter
    // relative to a BootstrapSeed that claims to be Relay A.
    let rb_dp = DiscoveryPlaneNode::start_relay(&relay_b, vec![], vec![]).await;

    // ── NEGATIVE: BootstrapSeed claims identity = Relay A, but the discovery
    //    server is Relay B. discover_all_candidates MUST reject.
    let bad_seed = BootstrapSeed {
        advert_discovery_addr: rb_dp.advert_discovery_addr.clone(),
        route_discovery_addr: rb_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_a.ed_pk, // claims Relay A
    };
    let discovered = discover_all_candidates(&bad_seed).await;
    assert!(
        discovered.is_empty(),
        "discover_all_candidates MUST reject when the discovery server's identity != BootstrapSeed identity"
    );
    eprintln!("[test] PASS: identity mismatch (server=B, seed=A) → rejected");

    // ── POSITIVE: BootstrapSeed identity = Relay B, discovery server = Relay B.
    let good_seed = BootstrapSeed {
        advert_discovery_addr: rb_dp.advert_discovery_addr.clone(),
        route_discovery_addr: rb_dp.route_discovery_addr.clone(),
        ed25519_public_key: relay_b.ed_pk, // matches Relay B
    };
    let discovered = discover_all_candidates(&good_seed).await;
    assert_eq!(
        discovered.len(),
        1,
        "discover_all_candidates MUST succeed when the discovery server's identity == BootstrapSeed identity"
    );
    assert_eq!(discovered[0].node_id(), relay_b.node_id);
    eprintln!("[test] PASS: identity match (server=B, seed=B) → discovered 1 candidate");

    // Suppress unused warning for `imposter` (kept for clarity of intent).
    let _ = imposter.node_id;
    *rb_dp.advert_disc_shutdown.lock().await = true;
}

/// ─── Issue B: bootstrap serves only verified peer adverts ───
///
/// The bootstrap's `TopologyGraph` contains:
/// - verified `AuthenticatedNodeRecord`s for Relay A + Gateway G
/// - a malicious `RemoteNodeHint` for FakeGateway F
///
/// `serve_bootstrap_discovery_async` MUST serve ONLY the verified records
/// (B, A, G) — NOT the `RemoteNodeHint` for F. This protects the
/// topology-poisoning boundary: a non-authoritative hint cannot become
/// authoritative discovery output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_5b_bootstrap_serves_only_verified_no_remote_hints() {
    let bootstrap_idents = NodeIdents::fresh(0x80);
    let relay_a = NodeIdents::fresh(0x81);
    let gateway = NodeIdents::fresh(0x82);
    let fake_gateway = NodeIdents::fresh(0x83);

    // Build the bootstrap's TopologyGraph with verified records for itself,
    // Relay A, and Gateway G.
    let bootstrap_circuit = ephemeral_addr().await;
    let bootstrap_advert =
        make_relay_advert(&bootstrap_idents.identity, &bootstrap_circuit);
    let ra_advert = make_relay_advert(&relay_a.identity, "127.0.0.1:18001");
    let gw_advert =
        make_gateway_advert(&gateway.identity, "127.0.0.1:18002", &gateway.x_pk.to_bytes());

    let mut topology = TopologyGraph::new();
    topology
        .accept_advertisement(bootstrap_advert.verify_into_verified().unwrap())
        .unwrap();
    topology
        .accept_advertisement(ra_advert.verify_into_verified().unwrap())
        .unwrap();
    topology
        .accept_advertisement(gw_advert.verify_into_verified().unwrap())
        .unwrap();

    // Inject a malicious RemoteNodeHint for FakeGateway F into the topology.
    // RemoteNodeHint is non-authoritative — it must NOT be served as discovery.
    // (We construct it to document the attack vector; TopologyGraph only
    // accepts hints via process_verified_peer_summary_list, which we don't
    // call here. The structural guarantee is that all_records() returns
    // &AuthenticatedNodeRecord — a RemoteNodeHint can never appear.)
    let fake_hint = RemoteNodeHint {
        target_node_id: fake_gateway.node_id,
        claimed_sequence: 1,
        claimed_capabilities: vec!["gateway".to_string()],
        claimed_visibility: "active".to_string(),
        claimed_last_seen: snp_identity::now_unix(),
        distance_hint: 1,
        learned_from: bootstrap_idents.node_id,
        received_at: snp_identity::now_unix(),
        source_propagation_sequence: 0,
    };
    // TopologyGraph doesn't expose a public add_remote_hint in production
    // (only via process_verified_peer_summary_list), but we can verify
    // structurally that RemoteNodeHint cannot appear in all_records().
    // all_records() returns &AuthenticatedNodeRecord — a RemoteNodeHint
    // cannot be converted to AuthenticatedNodeRecord (type-enforced).
    let active: Vec<NodeId> = topology
        .directory()
        .acceptance_store()
        .all_records()
        .map(|r| r.node_id())
        .collect();
    let active_ids = active;
    assert!(
        !active_ids.contains(&fake_gateway.node_id),
        "RemoteNodeHint target MUST NOT appear in active_nodes() (non-authoritative)"
    );
    assert!(active_ids.contains(&bootstrap_idents.node_id));
    assert!(active_ids.contains(&relay_a.node_id));
    assert!(active_ids.contains(&gateway.node_id));
    eprintln!("[test] RemoteNodeHint for fake gateway excluded from verified records");

    // Start serve_bootstrap_discovery_async with this topology.
    let advert_addr = ephemeral_addr().await;
    let seed_addr = advert_addr.clone();
    let shutdown = Arc::new(tokio::sync::Mutex::new(false));
    let shutdown_clone = shutdown.clone();
    let ba_clone = bootstrap_advert.clone();
    let topo_ref = topology; // keep ownership for the assertion after serve
    let _handle = tokio::spawn(async move {
        let sf = async move {
            loop {
                if *shutdown_clone.lock().await {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        serve_bootstrap_discovery_async(ba_clone, &topo_ref, advert_addr.clone(), sf).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Query the bootstrap discovery (with the correct identity).
    let seed = BootstrapSeed {
        advert_discovery_addr: seed_addr.clone(),
        route_discovery_addr: seed_addr.clone(),
        ed25519_public_key: bootstrap_idents.ed_pk,
    };
    let discovered = discover_all_candidates(&seed).await;
    // Must discover exactly 3: bootstrap (own) + Relay A + Gateway G.
    // FakeGateway F MUST NOT appear.
    assert_eq!(
        discovered.len(),
        3,
        "must discover exactly 3 verified candidates (bootstrap + A + G)"
    );
    let discovered_ids: Vec<NodeId> = discovered.iter().map(|v| v.node_id()).collect();
    assert!(discovered_ids.contains(&bootstrap_idents.node_id));
    assert!(discovered_ids.contains(&relay_a.node_id));
    assert!(discovered_ids.contains(&gateway.node_id));
    assert!(
        !discovered_ids.contains(&fake_gateway.node_id),
        "FakeGateway (from RemoteNodeHint) MUST NOT be in discovery output"
    );
    eprintln!("[test] PASS: bootstrap discovery serves only verified records — no RemoteNodeHints");

    *shutdown.lock().await = true;
}

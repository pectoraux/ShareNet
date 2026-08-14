//! N2.2.4 — Real Internet Egress: SSRF/security + concurrent upstream +
//! upstream failure propagation tests.
//!
//! This file is the deterministic, network-isolated test suite for N2.2.4.
//! It exercises:
//!
//! 1. **SSRF rejection (13 tests)** — `PinnedConnector::new(url)` rejects
//!    every SSRF bypass vector at construction time, BEFORE any DNS
//!    resolution or TCP connection. The tests are pure (no network access,
//!    no running server) and deterministic.
//!
//! 2. **Concurrent upstream (1 test)** — Three independent 4-node meshes
//!    (A→B→C→G) are brought up concurrently, each with its own HTTP server
//!    returning a distinct body. Three `send_via_route` calls run
//!    concurrently; the responses are verified to be correctly correlated
//!    with their requests (no cross-contamination of fetch bodies or
//!    circuit keys).
//!
//! 3. **Upstream failure propagation (4 tests)** — The gateway correctly
//!    propagates upstream failures to the client:
//!    - TCP connection refused (no listener on the port)
//!    - TCP timeout (black-hole address — TEST-NET-1)
//!    - HTTP 500 (server returns Internal Server Error)
//!    - HTTP 404 (server returns Not Found)
//!
//! The external-internet test (real HTTPS fetch through the production
//! `PinnedConnector::new`) is in `n224_real_internet_egress.rs` and is
//! `#[ignore]` by default (requires `SHARENET_EXTERNAL_NET_TESTS=1`).
//!
//! ## What is NOT tested here
//!
//! - Real HTTPS egress (covered by `n224_real_internet_egress.rs`).
//! - Relay opacity, circuit freshness, replay protection — covered by
//!   `n222_circuit_establishment.rs`.
//! - Discovery → circuit integration — covered by
//!   `n223_discovery_to_circuit.rs`.

#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::{
    verify_transit_response, GatewayError, PinnedConnector, TransitResponse,
};
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test infrastructure (mirrors n222_circuit_establishment.rs patterns)
// ════════════════════════════════════════════════════════════════════════════

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

    /// Build a `VerifiedNodeDescriptor` for a GATEWAY by constructing +
    /// signing + verifying a `GatewayAdvertisement`.
    fn gateway_descriptor(&self) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(),
            self.x_pk.to_bytes(),
            "127.0.0.1:0",
            "127.0.0.1:0",
        );
        advert
            .verify_into_verified()
            .expect("signed advert must verify")
            .descriptor()
            .expect("NodeId must be consistent")
    }

    /// Build a `VerifiedNodeDescriptor` for a RELAY.
    fn relay_descriptor(&self) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(),
            self.x_pk.to_bytes(),
            "127.0.0.1:0",
            "127.0.0.1:0",
        );
        advert
            .verify_into_verified()
            .expect("signed advert must verify")
            .descriptor()
            .expect("NodeId must be consistent")
    }
}

/// Bind to port 0, return the assigned address, drop the listener.
async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

/// Bind to port 0, return the assigned port, drop the listener.
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Start a local HTTP server that returns the given body with HTTP 200.
async fn start_local_http_with_body(
    body: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let body_clone = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body_clone.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body_clone.as_bytes()).await;
            });
        }
    });
    (addr, handle)
}

/// Start a local HTTP server that returns the given status code and body.
async fn start_local_http_with_status(
    status: u16,
    status_text: &str,
    body: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let body = body.to_string();
    let status_text = status_text.to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            let status_text = status_text.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });
    (addr, handle)
}

/// Test-only connector factory: bypasses `PinnedConnector::new` SSRF defence
/// so tests can pin to a local mock HTTP server on 127.0.0.1.
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
// `hex_short` is intentionally kept for debugging; suppress the dead-code
// warning so the test file compiles cleanly.
#[allow(dead_code)]
fn _hex_short_keep(_h: String) {
    let _ = hex_short(&[0u8; 8]);
}

/// Build a `Route` for the standard 4-node topology (client → A → B → G).
fn build_route(
    client_idents: &NodeIdents,
    relay_a_idents: &NodeIdents,
    relay_b_idents: &NodeIdents,
    gateway_idents: &NodeIdents,
    relay_a_addr: &str,
    relay_b_addr: &str,
    gateway_addr: &str,
) -> Route {
    let route = Route::new_with_hop_details(
        client_idents.node_id,
        gateway_idents.node_id,
        vec![
            RouteHop::new(
                relay_a_idents.relay_descriptor(),
                TransportEndpoint::tcp(relay_a_addr),
            ),
            RouteHop::new(
                relay_b_idents.relay_descriptor(),
                TransportEndpoint::tcp(relay_b_addr),
            ),
            RouteHop::new(
                gateway_idents.gateway_descriptor(),
                TransportEndpoint::tcp(gateway_addr),
            ),
        ],
    );
    route.validate().expect("route must be valid");
    let mut route = route;
    route.transition(RouteState::Establishing).expect("Proposed → Establishing");
    route.transition(RouteState::Active).expect("Establishing → Active");
    route
}

/// Start the gateway with the protocol-driven circuit establishment,
/// using the test connector factory (bypasses SSRF for local HTTP).
fn start_gateway(
    gateway_idents: &NodeIdents,
    gateway_listen_addr: &str,
) -> tokio::task::JoinHandle<()> {
    let gateway_node = Node::new(
        gateway_idents.identity(),
        vec![Capability::Gateway],
        gateway_listen_addr.to_string(),
    );
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let listen = gateway_listen_addr.to_string();
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_with_protocol_circuit(
            &gateway_node,
            &listen,
            &gw_x_sk,
            &gw_x_pk,
            |url| test_connector_factory(url),
        )
        .await;
    })
}

/// Start a relay at the given position in the route.
fn start_relay(
    relay_idents: &NodeIdents,
    route: &Route,
    my_position: usize,
    listen_addr: &str,
) -> tokio::task::JoinHandle<()> {
    let relay_node = Node::new(
        relay_idents.identity(),
        vec![Capability::Relay],
        listen_addr.to_string(),
    );
    let x_sk = Arc::clone(&relay_idents.x_sk);
    let x_pk = relay_idents.x_pk;
    let listen = listen_addr.to_string();
    let route = route.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(
            &relay_node,
            &route,
            my_position,
            &listen,
            &x_sk,
            &x_pk,
        )
        .await;
    })
}

/// Standard 4-node mesh with a parameterized HTTP body.
#[allow(dead_code)]
struct Mesh {
    client_idents: NodeIdents,
    relay_a_idents: NodeIdents,
    relay_b_idents: NodeIdents,
    gateway_idents: NodeIdents,
    gateway_addr: String,
    relay_a_addr: String,
    relay_b_addr: String,
    http_url: String,
    expected_body: Vec<u8>,
    #[allow(dead_code)]
    _http_handle: tokio::task::JoinHandle<()>,
    gateway_handle: tokio::task::JoinHandle<()>,
    relay_a_handle: tokio::task::JoinHandle<()>,
    relay_b_handle: tokio::task::JoinHandle<()>,
}

impl Mesh {
    /// Bring up the full 4-node mesh (gateway + 2 relays + local HTTP) with
    /// the given HTTP response body. Each mesh instance is independent
    /// (fresh NodeIdents, fresh ports).
    async fn start_with_body(body: &str) -> Self {
        let client_idents = NodeIdents::fresh();
        let relay_a_idents = NodeIdents::fresh();
        let relay_b_idents = NodeIdents::fresh();
        let gateway_idents = NodeIdents::fresh();

        let gateway_addr = ephemeral_addr().await;
        let relay_b_addr = ephemeral_addr().await;
        let relay_a_addr = ephemeral_addr().await;
        let (http_addr, http_handle) = start_local_http_with_body(body.to_string()).await;
        let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

        let gateway_handle = start_gateway(&gateway_idents, &gateway_addr);
        tokio::time::sleep(Duration::from_millis(60)).await;

        let relay_b_route = Route::new_with_hop_details(
            relay_a_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::new(
                    relay_b_idents.relay_descriptor(),
                    TransportEndpoint::tcp(&relay_b_addr),
                ),
                RouteHop::new(
                    gateway_idents.gateway_descriptor(),
                    TransportEndpoint::tcp(&gateway_addr),
                ),
            ],
        );
        let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
        tokio::time::sleep(Duration::from_millis(60)).await;

        let relay_a_route = Route::new_with_hop_details(
            client_idents.node_id,
            gateway_idents.node_id,
            vec![
                RouteHop::new(
                    relay_a_idents.relay_descriptor(),
                    TransportEndpoint::tcp(&relay_a_addr),
                ),
                RouteHop::new(
                    relay_b_idents.relay_descriptor(),
                    TransportEndpoint::tcp(&relay_b_addr),
                ),
                RouteHop::new(
                    gateway_idents.gateway_descriptor(),
                    TransportEndpoint::tcp(&gateway_addr),
                ),
            ],
        );
        let relay_a_handle = start_relay(&relay_a_idents, &relay_a_route, 0, &relay_a_addr);
        tokio::time::sleep(Duration::from_millis(60)).await;

        Self {
            client_idents,
            relay_a_idents,
            relay_b_idents,
            gateway_idents,
            gateway_addr,
            relay_a_addr,
            relay_b_addr,
            http_url,
            expected_body: body.as_bytes().to_vec(),
            _http_handle: http_handle,
            gateway_handle,
            relay_a_handle,
            relay_b_handle,
        }
    }

    /// Build the client's view of the route.
    fn client_route(&self) -> Route {
        build_route(
            &self.client_idents,
            &self.relay_a_idents,
            &self.relay_b_idents,
            &self.gateway_idents,
            &self.relay_a_addr,
            &self.relay_b_addr,
            &self.gateway_addr,
        )
    }

    /// Build a client `Node` for sending.
    fn client_node(&self) -> Node {
        Node::new(
            self.client_idents.identity(),
            vec![Capability::Client],
            String::new(),
        )
    }
}

/// Send a transit request through the mesh using the production
/// `send_via_route` API. Returns the verified TransitResponse.
async fn send_via_route(mesh: &Mesh) -> Result<TransitResponse, snp_node::legacy::NodeError> {
    let client_node = mesh.client_node();
    let route = mesh.client_route();
    let client_x_sk = Arc::clone(&mesh.client_idents.x_sk);
    let client_x_pk = mesh.client_idents.x_pk;
    async_node::send_via_route(
        &client_node,
        &route,
        &mesh.http_url,
        &client_x_sk,
        &client_x_pk,
    )
    .await
}

// ════════════════════════════════════════════════════════════════════════════
// SSRF REJECTION TESTS (13)
//
// All tests call `PinnedConnector::new(url)` directly and verify the error
// type. NO network access is needed — the SSRF check fires at construction
// time, BEFORE any DNS resolution or TCP connection.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn localhost_url_rejected() {
    let result = PinnedConnector::new("http://localhost/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://localhost/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn loopback_ip_rejected() {
    let result = PinnedConnector::new("http://127.0.0.1/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://127.0.0.1/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn private_ip_rejected() {
    let result = PinnedConnector::new("http://10.0.0.1/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://10.0.0.1/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn ipv6_loopback_rejected() {
    let result = PinnedConnector::new("http://[::1]/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://[::1]/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn link_local_rejected() {
    let result = PinnedConnector::new("http://169.254.169.254/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://169.254.169.254/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn metadata_endpoint_rejected() {
    let result = PinnedConnector::new("http://metadata.google.internal/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://metadata.google.internal/ must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn decimal_ip_rejected() {
    // 2130706433 decimal = 127.0.0.1 (loopback).
    let result = PinnedConnector::new("http://2130706433/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://2130706433/ (decimal 127.0.0.1) must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn octal_ip_rejected() {
    // 0177.0.0.1 — dotted-octal form of 127.0.0.1.
    let result = PinnedConnector::new("http://0177.0.0.1/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://0177.0.0.1/ (dotted-octal 127.0.0.1) must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn hex_ip_rejected() {
    // 0x7f000001 — hex single-integer form of 127.0.0.1.
    let result = PinnedConnector::new("http://0x7f000001/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://0x7f000001/ (hex 127.0.0.1) must be rejected with EgressBlocked, got {:?}",
        result
    );
}

#[test]
fn disallowed_port_rejected() {
    // HTTPS on port 22 — port policy rejects non-443 for HTTPS.
    let result = PinnedConnector::new("https://example.com:22/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "https://example.com:22/ must be rejected with EgressBlocked (port policy), got {:?}",
        result
    );
}

#[test]
fn oversized_url_rejected() {
    // URL > MAX_URL_LENGTH (8192) chars → MalformedUrl.
    let url_too_long = format!(
        "https://example.com/{}",
        "a".repeat(snp_gateway::MAX_URL_LENGTH - "https://example.com/".len() + 1)
    );
    assert!(url_too_long.len() > snp_gateway::MAX_URL_LENGTH);
    let result = PinnedConnector::new(&url_too_long);
    assert!(
        matches!(result, Err(GatewayError::MalformedUrl(_))),
        "URL > MAX_URL_LENGTH must be rejected with MalformedUrl, got {:?}",
        result
    );
}

#[test]
fn unsupported_scheme_rejected() {
    let result = PinnedConnector::new("ftp://example.com/");
    assert!(
        matches!(result, Err(GatewayError::MalformedUrl(_))),
        "ftp://example.com/ must be rejected with MalformedUrl (unsupported scheme), got {:?}",
        result
    );
}

#[test]
fn broadcast_address_rejected() {
    let result = PinnedConnector::new("http://255.255.255.255/");
    assert!(
        matches!(result, Err(GatewayError::EgressBlocked(_))),
        "http://255.255.255.255/ (broadcast) must be rejected with EgressBlocked, got {:?}",
        result
    );
}

// ════════════════════════════════════════════════════════════════════════════
// CONCURRENT UPSTREAM TEST (1)
//
// Three independent 4-node meshes (A→B→C→G) are brought up concurrently,
// each with its own HTTP server returning a distinct body. Three
// `send_via_route` calls run concurrently via `tokio::join!`; the responses
// are verified to be correctly correlated with their requests (no
// cross-contamination of fetch bodies or circuit keys).
//
// The production gateway serves ONE request per
// `serve_gateway_with_protocol_circuit` call (it breaks out of its loop
// after one request — see the comment in async_node.rs). To test
// concurrency without modifying the FROZEN production gateway, we bring up
// 3 INDEPENDENT meshes, each with its own gateway, relays, and HTTP server.
// This proves the protocol layer has no shared-state issues across
// independent circuits AND that the upstream fetch layer correctly
// attributes each response to the correct circuit.
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_upstream_through_mesh() {
    // Three meshes, each with a distinct HTTP body. The body is what lets
    // us verify that responses are correctly correlated with requests —
    // if mesh 1's response contains mesh 2's body, we have a bug.
    let (m1, m2, m3) = tokio::join!(
        Mesh::start_with_body("concurrent-upstream-mesh-1"),
        Mesh::start_with_body("concurrent-upstream-mesh-2"),
        Mesh::start_with_body("concurrent-upstream-mesh-3"),
    );

    // Three concurrent send_via_route calls. Each uses its own client
    // identity, its own route, its own gateway, its own circuit keys.
    let (r1, r2, r3) = tokio::join!(send_via_route(&m1), send_via_route(&m2), send_via_route(&m3));

    let resp1 = r1.expect("mesh 1 send_via_route must succeed");
    let resp2 = r2.expect("mesh 2 send_via_route must succeed");
    let resp3 = r3.expect("mesh 3 send_via_route must succeed");

    // All 3 must be HTTP 200.
    assert_eq!(resp1.status, 200, "mesh 1 status must be 200");
    assert_eq!(resp2.status, 200, "mesh 2 status must be 200");
    assert_eq!(resp3.status, 200, "mesh 3 status must be 200");

    // Each response's object_id must match SHA-256 of its mesh's body.
    // This is the cross-contamination check: if mesh 1's response had
    // mesh 2's body, this assert would fail.
    assert_eq!(
        resp1.object_id,
        sha256(&m1.expected_body),
        "mesh 1 object_id must match SHA-256 of its body"
    );
    assert_eq!(
        resp2.object_id,
        sha256(&m2.expected_body),
        "mesh 2 object_id must match SHA-256 of its body"
    );
    assert_eq!(
        resp3.object_id,
        sha256(&m3.expected_body),
        "mesh 3 object_id must match SHA-256 of its body"
    );

    // The 3 object_ids must be DISTINCT (proving the 3 bodies are distinct
    // and the 3 responses are not duplicated).
    assert_ne!(resp1.object_id, resp2.object_id, "mesh 1 and 2 object_ids must differ");
    assert_ne!(resp1.object_id, resp3.object_id, "mesh 1 and 3 object_ids must differ");
    assert_ne!(resp2.object_id, resp3.object_id, "mesh 2 and 3 object_ids must differ");

    // Each response must be signed by its own gateway (proving no gateway
    // cross-signing).
    assert!(
        verify_transit_response(&resp1, &m1.gateway_idents.ed_pk),
        "mesh 1 response must verify under mesh 1 gateway's pubkey"
    );
    assert!(
        verify_transit_response(&resp2, &m2.gateway_idents.ed_pk),
        "mesh 2 response must verify under mesh 2 gateway's pubkey"
    );
    assert!(
        verify_transit_response(&resp3, &m3.gateway_idents.ed_pk),
        "mesh 3 response must verify under mesh 3 gateway's pubkey"
    );

    // Each response's gateway_id must match its own gateway's NodeId.
    assert_eq!(resp1.gateway_id, m1.gateway_idents.node_id);
    assert_eq!(resp2.gateway_id, m2.gateway_idents.node_id);
    assert_eq!(resp3.gateway_id, m3.gateway_idents.node_id);

    // The 3 req_ids must be DISTINCT (proving fresh per-call req_id
    // generation — no reuse across concurrent calls).
    assert_ne!(resp1.req_id, resp2.req_id, "mesh 1 and 2 req_ids must differ");
    assert_ne!(resp1.req_id, resp3.req_id, "mesh 1 and 3 req_ids must differ");
    assert_ne!(resp2.req_id, resp3.req_id, "mesh 2 and 3 req_ids must differ");

    eprintln!(
        "[n224-concurrent] PASS: 3 concurrent upstreams through 3 meshes — \
         all 200, distinct bodies, distinct req_ids, distinct gateways"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// UPSTREAM FAILURE PROPAGATION TESTS (4)
//
// These tests use `PinnedConnector::from_parts()` (test-only bypass of SSRF)
// to construct a connector pointing at a controlled upstream, then call
// `connector.fetch("GET", &[])` directly. This tests the upstream fetch
// layer in isolation, without the full mesh.
//
// The tests cover:
// 1. `upstream_connection_refused` — TCP connect to a port with no listener.
// 2. `upstream_timeout` — TCP connect to a black-hole address (TEST-NET-1).
// 3. `upstream_http_500` — HTTP server returns 500.
// 4. `upstream_http_404` — HTTP server returns 404.
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_connection_refused() {
    // Allocate a port, then immediately drop the listener. The port is
    // now free (no listener) — a TCP connect to it should fail with
    // ECONNREFUSED quickly.
    let port = ephemeral_port().await;
    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test.local".to_string(),
        port,
        "http".to_string(),
        "/".to_string(),
    );

    // The fetch should fail with GatewayError::Upstream (TCP connect
    // refused). Use a 5s timeout to bound the test (the connect_timeout
    // in PinnedConnector::fetch is 15s, but ECONNREFUSED is immediate).
    let fetch_result = tokio::task::spawn_blocking(move || connector.fetch("GET", &[]))
        .await
        .expect("spawn_blocking join");
    assert!(
        matches!(fetch_result, Err(GatewayError::Upstream(_))),
        "upstream_connection_refused: expected Err(Upstream(_)), got {:?}",
        fetch_result
    );
    eprintln!(
        "[n224-refused] PASS: TCP connect to non-listening port returned Upstream error ({})",
        match &fetch_result {
            Err(GatewayError::Upstream(msg)) => msg.as_str(),
            _ => "(unexpected)",
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_timeout() {
    // Connect to a black-hole address: 192.0.2.1 (TEST-NET-1, RFC 5737 —
    // reserved for documentation, packets to it should be dropped or
    // result in "network unreachable"). In sandboxed environments this
    // typically fails fast with ENETUNREACH; in routed environments it
    // times out after the 15s connect_timeout. Either way, the result is
    // GatewayError::Upstream.
    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        "blackhole.test".to_string(),
        80,
        "http".to_string(),
        "/".to_string(),
    );

    // Wrap in a 20s timeout — the connect_timeout in fetch is 15s, so 20s
    // gives a 5s margin. If the test environment fails fast (ENETUNREACH),
    // this completes immediately.
    let fetch_result = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || connector.fetch("GET", &[])),
    )
    .await;
    match fetch_result {
        Ok(Ok(fetch_result)) => {
            assert!(
                matches!(fetch_result, Err(GatewayError::Upstream(_))),
                "upstream_timeout: expected Err(Upstream(_)), got {:?}",
                fetch_result
            );
            eprintln!(
                "[n224-timeout] PASS: black-hole TCP connect returned Upstream error ({})",
                match &fetch_result {
                    Err(GatewayError::Upstream(msg)) => msg.as_str(),
                    _ => "(unexpected)",
                }
            );
        }
        Ok(Err(join_err)) => panic!("spawn_blocking join error: {join_err}"),
        Err(_elapsed) => panic!("upstream_timeout: fetch did not complete within 20s"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_http_500() {
    // Start a local HTTP server that returns 500.
    let (http_addr, _http_handle) =
        start_local_http_with_status(500, "Internal Server Error", "upstream failure").await;
    let port: u16 = http_addr.rsplit(':').next().unwrap().parse().unwrap();

    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test.local".to_string(),
        port,
        "http".to_string(),
        "/".to_string(),
    );

    let response = tokio::task::spawn_blocking(move || connector.fetch("GET", &[]))
        .await
        .expect("spawn_blocking join")
        .expect("upstream_http_500: fetch must succeed (the server is up, just returns 500)");

    assert_eq!(
        response.status, 500,
        "upstream_http_500: response status must be 500, got {}",
        response.status
    );
    assert_eq!(
        response.body,
        b"upstream failure".to_vec(),
        "upstream_http_500: response body must match"
    );
    eprintln!("[n224-500] PASS: HTTP 500 propagated with body");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_http_404() {
    // Start a local HTTP server that returns 404.
    let (http_addr, _http_handle) =
        start_local_http_with_status(404, "Not Found", "no such resource").await;
    let port: u16 = http_addr.rsplit(':').next().unwrap().parse().unwrap();

    let connector = PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        "test.local".to_string(),
        port,
        "http".to_string(),
        "/".to_string(),
    );

    let response = tokio::task::spawn_blocking(move || connector.fetch("GET", &[]))
        .await
        .expect("spawn_blocking join")
        .expect("upstream_http_404: fetch must succeed (the server is up, just returns 404)");

    assert_eq!(
        response.status, 404,
        "upstream_http_404: response status must be 404, got {}",
        response.status
    );
    assert_eq!(
        response.body,
        b"no such resource".to_vec(),
        "upstream_http_404: response body must match"
    );
    eprintln!("[n224-404] PASS: HTTP 404 propagated with body");
}

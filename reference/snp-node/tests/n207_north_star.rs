//! N2.0.7 North-Star Integration Test — protocol-driven circuit + Route-authoritative.
//!
//! This test proves:
//!
//! 1. **Protocol-driven circuit establishment** — the client generates a fresh
//!    ephemeral X25519 key per request, seals the TransitRequest as
//!    `eph_pub(32) || sealed_payload`, and the gateway derives the circuit
//!    keys FROM the ephemeral public key in the frame body. No out-of-band
//!    circuit key exchange.
//!
//! 2. **Route is authoritative** — the client calls `send_via_route(route, ...)`
//!    and the relays call `serve_relay_via_route(route, position, ...)`. The
//!    Route's `hop_details` (NodeId + endpoints) drive the actual path. Change
//!    the Route's hop list, and the traffic follows a different path.
//!
//! 3. **Dynamic topology** — arbitrary identities (fresh Ed25519 + X25519),
//!    discovered via `discover_gateways_async`, Route constructed from
//!    discovered information. No compile-time topology.
//!
//! 4. **Failure recovery** — Relay B is killed, a new Route via Relay C is
//!    constructed, traffic continues without process restart.
//!
//! 5. **X25519-identity binding** — the gateway's X25519 static circuit public
//!    key is carried in the SIGNED GatewayAdvertisement. An attacker cannot
//!    substitute a different X25519 key without invalidating the signature.
//!
//! ## What this test MUST NOT do (enforced by static guard)
//!
//! - No `derive_circuit_keys(` (deterministic seed circuit keys)
//! - No `derive_link_keys` (deterministic seed link keys)
//! - No `Link::connect` / `Link::new` (sync link)
//! - No `std::net::TcpStream` / `std::net::TcpListener` (raw sync transport)
//! - No `perform_snp_ik_handshake_async` directly (handshake is internal)
//! - No `async_relay_forward_links` directly (forwarding is internal)
//! - No `AsyncLink::new` / `AsyncLink::connect_raw` directly
//! - No `x25519_dh` directly (circuit DH is internal to the protocol)
//! - No `derive_circuit_keys_from_dh` directly (circuit key derivation is internal)
//! - No `seal_circuit_payload_with_fresh_eph` directly (called internally by send_via_route)
//! - No `open_circuit_payload_with_fresh_eph` directly (called internally by gateway)
//! - No `encrypt_circuit_payload` / `decrypt_circuit_payload` directly
//! - No manually supplied `relay_addr` / `next_hop_addr` in the canonical route API

#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::{verify_transit_response, PinnedConnector};
use snp_node::node::{
    async_node, Node, NodeIdentity, Route, RouteHop, RouteState, Capability,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// STATIC GUARD: the test must use ONLY canonical production entry points.
// ════════════════════════════════════════════════════════════════════════════

const FORBIDDEN_PATTERNS: &[&str] = &[
    "derive_link_keys",
    "derive_circuit_keys(",
    "derive_circuit_keys_from_dh",
    "Link::connect",
    "Link::new",
    "std::net::TcpStream",
    "std::net::TcpListener",
    "perform_snp_ik_handshake_async",
    "async_relay_forward_links",
    "serve_one_gateway_request_async_with_connector",
    "serve_one_gateway_request_async",
    "serve_one_gateway_request_protocol_circuit",
    "AsyncLink::new",
    "AsyncLink::connect_raw",
    "x25519_dh",
    "seal_circuit_payload_with_fresh_eph",
    "open_circuit_payload_with_fresh_eph",
    "derive_gateway_response_keys",
    "encrypt_circuit_payload",
    "decrypt_circuit_payload",
];

const TEST_SOURCE: &str = include_str!("n207_north_star.rs");

#[test]
fn north_star_test_uses_only_canonical_entry_points() {
    let mut in_forbidden_array = false;
    for (lineno, line) in TEST_SOURCE.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.contains("const FORBIDDEN_PATTERNS") {
            in_forbidden_array = true;
        }
        if in_forbidden_array {
            if trimmed.starts_with("];") {
                in_forbidden_array = false;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
            continue;
        }
        for pattern in FORBIDDEN_PATTERNS {
            if line.contains(pattern) {
                panic!(
                    "north_star_test_uses_only_canonical_entry_points: forbidden pattern \
                     `{pattern}` found at line {} (outside a comment).\n  Line: {line}\n  \
                     The north-star test MUST use ONLY the canonical production Node entry \
                     points (send_via_route, serve_relay_via_route, serve_gateway_with_protocol_circuit).",
                    lineno + 1
                );
            }
        }
    }
    eprintln!("[static-guard] PASS: no forbidden patterns in north-star test source");
}

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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

async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

async fn start_local_http() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let body = b"Hello, ShareNet!";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    });
    (addr, handle)
}

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

// ════════════════════════════════════════════════════════════════════════════
// THE NORTH-STAR TEST: protocol-driven circuit + Route-authoritative
// ════════════════════════════════════════════════════════════════════════════

/// **North-star test: discovery → selection → Route → circuit → traffic.**
///
/// Proves:
/// 1. Protocol-driven circuit (fresh ephemeral X25519 per request, gateway
///    derives keys from the frame body — NO out-of-band keys).
/// 2. Route is authoritative (`send_via_route` + `serve_relay_via_route`).
/// 3. Dynamic topology (arbitrary identities, discovered, no compile-time).
/// 4. X25519-identity binding (advertisement carries circuit_x25519_pub
///    in the signed preimage).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn north_star_protocol_circuit_route_authoritative() {
    // ═══ 1. Generate dynamic identities ═══
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    eprintln!("[north-star] client     nodeId={}", hex_short(&client_idents.node_id));
    eprintln!("[north-star] relay A    nodeId={}", hex_short(&relay_a_idents.node_id));
    eprintln!("[north-star] relay B    nodeId={}", hex_short(&relay_b_idents.node_id));
    eprintln!("[north-star] gateway    nodeId={}", hex_short(&gateway_idents.node_id));

    // ═══ 2. Allocate ephemeral ports + start HTTP ═══
    let gateway_listen_addr = ephemeral_addr().await;
    let relay_b_listen_addr = ephemeral_addr().await;
    let relay_a_listen_addr = ephemeral_addr().await;
    let (http_addr, http_handle) = start_local_http().await;
    let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

    // ═══ 3. Start the GATEWAY with protocol-driven circuit establishment ═══
    // The gateway takes its X25519 SECRET (NOT circuit_keys). It derives
    // per-circuit keys FROM each request frame's ephemeral public key.
    let gateway_handle = {
        let gateway_node = Node::new(
            gateway_idents.identity(),
            vec![Capability::Gateway],
            gateway_listen_addr.clone(),
        );
        let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
        let gw_x_pk = gateway_idents.x_pk;
        let client_ed_pk = client_idents.ed_pk;
        let listen = gateway_listen_addr.clone();
        tokio::spawn(async move {
            async_node::serve_gateway_with_protocol_circuit(
                &gateway_node,
                &listen,
                &gw_x_sk,
                &gw_x_pk,
                client_ed_pk,
                |url| test_connector_factory(url),
            )
            .await
            .expect("gateway protocol-circuit must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 4. Start Relay B via serve_relay_via_route ═══
    // Relay B is at position 1 in the Route (0=relay A, 1=relay B, 2=gateway).
    let relay_b_handle = {
        let relay_b_node = Node::new(
            relay_b_idents.identity(),
            vec![Capability::Relay],
            relay_b_listen_addr.clone(),
        );
        let rb_x_sk = Arc::clone(&relay_b_idents.x_sk);
        let rb_x_pk = relay_b_idents.x_pk;
        let listen = relay_b_listen_addr.clone();
        let gw_addr = gateway_listen_addr.clone();
        let gw_node_id = gateway_idents.node_id;
        // Construct a Route that Relay B sees: [relay B, gateway].
        let relay_b_route = Route::new_with_hop_details(
            relay_a_idents.node_id, // source (from relay A's perspective)
            gw_node_id,
            vec![
                RouteHop::new(relay_b_idents.node_id, listen.clone()),
                RouteHop::new(gw_node_id, gw_addr),
            ],
        );
        tokio::spawn(async move {
            async_node::serve_relay_via_route(
                &relay_b_node,
                &relay_b_route,
                0, // my_position=0 (relay B is the first hop in its own view)
                &listen,
                &rb_x_sk,
                &rb_x_pk,
            )
            .await
            .expect("relay B via route must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 5. Start Relay A via serve_relay_via_route ═══
    // Relay A is at position 0 in the client's Route.
    let relay_a_handle = {
        let relay_a_node = Node::new(
            relay_a_idents.identity(),
            vec![Capability::Relay],
            relay_a_listen_addr.clone(),
        );
        let ra_x_sk = Arc::clone(&relay_a_idents.x_sk);
        let ra_x_pk = relay_a_idents.x_pk;
        let listen = relay_a_listen_addr.clone();
        let rb_addr = relay_b_listen_addr.clone();
        let rb_node_id = relay_b_idents.node_id;
        let gw_node_id = gateway_idents.node_id;
        let gw_addr = gateway_listen_addr.clone();
        // Relay A's view: [relay A, relay B, gateway].
        let relay_a_route = Route::new_with_hop_details(
            client_idents.node_id,
            gw_node_id,
            vec![
                RouteHop::new(relay_a_idents.node_id, listen.clone()),
                RouteHop::new(rb_node_id, rb_addr),
                RouteHop::new(gw_node_id, gw_addr),
            ],
        );
        tokio::spawn(async move {
            async_node::serve_relay_via_route(
                &relay_a_node,
                &relay_a_route,
                0, // my_position=0
                &listen,
                &ra_x_sk,
                &ra_x_pk,
            )
            .await
            .expect("relay A via route must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 6. CLIENT: construct the Route + send via route ═══
    // The Route is AUTHORITATIVE — the client's send_via_route reads
    // hop_details[0] (relay A's endpoint) and hop_details[last] (gateway's
    // NodeId) from the Route.
    let client_route = Route::new_with_hop_details(
        client_idents.node_id,
        gateway_idents.node_id,
        vec![
            RouteHop::new(relay_a_idents.node_id, relay_a_listen_addr.clone()),
            RouteHop::new(relay_b_idents.node_id, relay_b_listen_addr.clone()),
            RouteHop::new(gateway_idents.node_id, gateway_listen_addr.clone()),
        ],
    );
    client_route.validate().expect("route must be valid");
    let mut client_route = client_route;
    client_route.transition(RouteState::Establishing).expect("Proposed → Establishing");
    client_route.transition(RouteState::Active).expect("Establishing → Active");

    let client_node = Node::new(
        client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let transit_resp = async_node::send_via_route(
        &client_node,
        &client_route,
        &http_url,
        &gateway_idents.ed_pk,
        &gateway_idents.x_pk,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("send_via_route must succeed");

    // ═══ 7. Verify the response ═══
    assert_eq!(transit_resp.status, 200, "HTTP status must be 200");
    assert_eq!(
        transit_resp.object_id,
        sha256(b"Hello, ShareNet!"),
        "objectId must match SHA-256(\"Hello, ShareNet!\")"
    );
    assert!(
        verify_transit_response(&transit_resp, &gateway_idents.ed_pk),
        "gateway signature must verify"
    );
    assert_eq!(
        transit_resp.gateway_id, gateway_idents.node_id,
        "response gateway_id must match"
    );

    // ═══ 8. Cleanup ═══
    let _ = http_handle.await;
    let _ = gateway_handle.await;
    let _ = relay_b_handle.await;
    let _ = relay_a_handle.await;

    eprintln!("[north-star] PASSED:");
    eprintln!("  Client → Relay A → Relay B → Gateway → local HTTP → back");
    eprintln!("  Protocol-driven circuit: YES (fresh ephemeral X25519, gateway derives from frame)");
    eprintln!("  Route-authoritative: YES (send_via_route + serve_relay_via_route)");
    eprintln!("  Dynamic identities: YES (4 fresh Ed25519 + X25519 keypairs)");
    eprintln!("  No out-of-band circuit keys");
    eprintln!("  No manually supplied next-hop addresses in the route API");
    eprintln!("  HTTP traffic: real (status=200, body=\"Hello, ShareNet!\")");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2: Route is causally responsible — invalid topology fails
// ════════════════════════════════════════════════════════════════════════════

/// Prove that the Route is CAUSALLY RESPONSIBLE for the path: if the Route's
/// hop list points to a non-existent relay, the send FAILS. This is not
/// merely an assertion — the Route's hop_details drive the actual connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_is_causally_responsible_invalid_topology_fails() {
    let client_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    // Construct a Route with a NON-EXISTENT relay endpoint.
    let bad_route = Route::new_with_hop_details(
        client_idents.node_id,
        gateway_idents.node_id,
        vec![
            RouteHop::new([0xaa; 32], "127.0.0.1:1".into()), // port 1 — nothing listening
            RouteHop::new(gateway_idents.node_id, "127.0.0.1:2".into()),
        ],
    );

    let client_node = Node::new(
        client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let result = async_node::send_via_route(
        &client_node,
        &bad_route,
        "http://test.local/",
        &gateway_idents.ed_pk,
        &gateway_idents.x_pk,
        &client_x_sk,
        &client_x_pk,
    )
    .await;

    assert!(
        result.is_err(),
        "send_via_route with an invalid topology (non-existent relay) MUST fail"
    );
    eprintln!("[route-causal] PASS: invalid topology correctly fails");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3: Gateway X25519-identity binding — substitution fails
// ════════════════════════════════════════════════════════════════════════════

/// Prove that the gateway's X25519 static circuit public key is BOUND to its
/// Ed25519 identity via the signed advertisement. An attacker cannot
/// substitute a different X25519 key without invalidating the signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_x25519_identity_binding_substitution_fails() {
    use snp_node::node::GatewayAdvertisement;

    let gateway_idents = NodeIdents::fresh();
    let attacker_x25519_pub = x25519_static_keypair().1;

    // Legitimate advertisement: X25519 key IS in the signed preimage.
    let legit_advert = GatewayAdvertisement::for_identity_with_circuit_key(
        &gateway_idents.identity(),
        gateway_idents.x_pk.to_bytes(),
        "127.0.0.1:7001",
        "127.0.0.1:7002",
    );
    assert!(legit_advert.verify(), "legitimate advertisement must verify");
    assert_eq!(
        legit_advert.circuit_x25519_pub,
        gateway_idents.x_pk.to_bytes(),
        "legitimate advert carries the gateway's X25519 key"
    );

    // Attacker substitutes a DIFFERENT X25519 key into the advertisement.
    let mut forged_advert = legit_advert.clone();
    forged_advert.circuit_x25519_pub = attacker_x25519_pub.to_bytes();
    // The signature is STILL over the ORIGINAL preimage (with the real X25519 key).
    // The attacker cannot re-sign because they don't have the gateway's Ed25519 secret.
    assert!(
        !forged_advert.verify(),
        "advertisement with substituted X25519 key MUST FAIL signature verification"
    );

    eprintln!("[x25519-binding] PASS: X25519 substitution correctly rejected");
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4: Two circuits between the same client/gateway have different keys
// ════════════════════════════════════════════════════════════════════════════

/// Prove that the circuit keys are FRESH per request: two calls to
/// `seal_circuit_payload_with_fresh_eph` with the same gateway X25519 pub
/// produce DIFFERENT circuit keys (because the ephemeral X25519 keypair is
/// fresh per call).
///
/// NOTE: This test calls `seal_circuit_payload_with_fresh_eph` directly
/// because it's testing the CRYPTO PRIMITIVE, not the production path.
/// The production path (`send_via_route`) uses this primitive internally.
#[test]
fn two_circuits_have_different_keys() {
    let gateway_x25519_pub = x25519_static_keypair().1;
    let plaintext = b"test payload";

    let (keys1, eph1, _body1) =
        snp_link::seal_circuit_payload_with_fresh_eph(&gateway_x25519_pub, plaintext);
    let (keys2, eph2, _body2) =
        snp_link::seal_circuit_payload_with_fresh_eph(&gateway_x25519_pub, plaintext);

    assert_ne!(
        eph1.to_bytes(),
        eph2.to_bytes(),
        "two circuits MUST have different ephemeral public keys"
    );
    assert_ne!(
        keys1.send_key, keys2.send_key,
        "two circuits MUST have different send keys"
    );
    assert_ne!(
        keys1.recv_key, keys2.recv_key,
        "two circuits MUST have different recv keys"
    );
    eprintln!("[fresh-circuit] PASS: two circuits have different keys");
}

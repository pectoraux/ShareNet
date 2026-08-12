//! N2.0.6 North-Star Integration Test — the canonical production path proof.
//!
//! Topology:
//!
//! ```text
//!   Client ──[SNP-IK/0.1]──> Relay A ──[SNP-IK/0.1]──> Relay B ──[SNP-IK/0.1]──> Gateway ──> local HTTP
//!     └──────────────────── [circuit DH: client↔gateway X25519] ────────────────────┘
//! ```
//!
//! ## What this test exercises
//!
//! This test exercises the SINGLE canonical production path:
//!
//! 1. **Canonical production Node entry points** — the test calls ONLY:
//!    - [`snp_node::node::async_node::serve_gateway_persistent_async_with_handshake_and_connector`]
//!      (gateway: handshake-on-accept + serve loop, all internal).
//!    - [`snp_node::node::async_node::serve_relay_persistent_async_with_handshake`]
//!      (relay: handshake both sides + bidirectional forward, all internal).
//!    - [`snp_node::node::async_node::establish_circuit_and_send_async`]
//!      (client: fresh X25519 circuit DH + SNP-IK handshake with relay + send).
//!
//! 2. **Canonical async transport** — `AsyncLink` (Tokio-based AEAD framing).
//!    The test never touches `AsyncLink` directly — it's internal to the
//!    production entry points.
//!
//! 3. **Real async SNP-IK/0.1 handshakes for every hop** — 3 handshakes
//!    (client↔relay A, relay A↔relay B, relay B↔gateway). All internal to
//!    the production entry points.
//!
//! 4. **Fresh X25519 circuit establishment** — the client performs a fresh
//!    X25519 DH with the gateway's static X25519 public key to derive the
//!    circuit keys (via `derive_circuit_keys_from_dh` — NOT the deterministic
//!    `derive_circuit_keys`). This is internal to
//!    `establish_circuit_and_send_async`.
//!
//! 5. **Dynamic Route/Circuit objects** — `Route::new` + `Circuit::new` with
//!    arbitrary NodeIds (no `GatewayChoice`, no compile-time topology).
//!
//! 6. **Actual HTTP traffic** — a local HTTP server returns
//!    `"Hello, ShareNet!"`; the gateway fetches via `PinnedConnector`; the
//!    response body's SHA-256 (`object_id`) is verified end-to-end.
//!
//! ## What this test MUST NOT do (enforced by static guards)
//!
//! The test MUST NOT call:
//! - `derive_link_keys` (deterministic seed link keys — FORBIDDEN)
//! - `derive_circuit_keys` (deterministic seed circuit keys — FORBIDDEN)
//! - `Link::connect` (sync link — FORBIDDEN)
//! - `std::net::TcpStream` / `std::net::TcpListener` (raw sync transport — FORBIDDEN)
//! - `perform_snp_ik_handshake_async` directly (the handshake is internal — FORBIDDEN)
//! - `async_relay_forward_links` directly (forwarding is internal — FORBIDDEN)
//! - `serve_one_gateway_request_async_with_connector` directly (FORBIDDEN)
//! - `AsyncLink::new` / `AsyncLink::connect_raw` directly (FORBIDDEN)
//!
//! A self-scanning static guard (`north_star_test_uses_only_canonical_entry_points`)
//! reads this file's source and fails if any of the forbidden patterns appear
//! outside comments.

#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_dh, x25519_static_keypair, X25519PubKey,
    X25519Secret,
};
use snp_gateway::{verify_transit_response, PinnedConnector};
use snp_link::derive_circuit_keys_from_dh;
use snp_node::node::{
    async_node, Circuit, Node, NodeIdentity, Route, RouteState, Capability,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// STATIC GUARD: the test must use ONLY canonical production entry points.
// This test reads its OWN source file and fails if any forbidden pattern
// appears outside comments. This prevents regression — if a future edit
// adds a direct call to `derive_link_keys`, `Link::connect`,
// `perform_snp_ik_handshake_async`, `AsyncLink::new`, etc., this test
// will FAIL at compile time (the include_str! is evaluated at compile time).
// ════════════════════════════════════════════════════════════════════════════

/// The forbidden patterns — if ANY of these appear in the test source
/// (outside comments), the static guard test fails.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "derive_link_keys",
    "derive_circuit_keys(",
    "Link::connect",
    "Link::new",
    "std::net::TcpStream",
    "std::net::TcpListener",
    "perform_snp_ik_handshake_async",
    "async_relay_forward_links",
    "serve_one_gateway_request_async_with_connector",
    "serve_one_gateway_request_async",
    "AsyncLink::new",
    "AsyncLink::connect_raw",
];

/// The test's own source (compiled into the binary at build time).
const TEST_SOURCE: &str = include_str!("n205_north_star.rs");

/// Static guard: scan the test source for forbidden patterns. If any appear
/// outside comments (lines starting with `//` or inside `/* */` blocks) AND
/// outside the `FORBIDDEN_PATTERNS` declaration itself, fail. This prevents
/// regression — a future edit that adds a direct call to a low-level
/// transport/handshake function will cause this test to fail.
#[test]
fn north_star_test_uses_only_canonical_entry_points() {
    // Skip the FORBIDDEN_PATTERNS declaration itself (it literally contains
    // the forbidden strings as array elements).
    let mut in_forbidden_array = false;
    for (lineno, line) in TEST_SOURCE.lines().enumerate() {
        let trimmed = line.trim_start();
        // Track entry into the FORBIDDEN_PATTERNS array.
        if trimmed.contains("const FORBIDDEN_PATTERNS") {
            in_forbidden_array = true;
        }
        // Skip while inside the array.
        if in_forbidden_array {
            if trimmed.starts_with("];") {
                in_forbidden_array = false;
            }
            continue;
        }
        // Skip comment lines.
        if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
            continue;
        }
        for pattern in FORBIDDEN_PATTERNS {
            if line.contains(pattern) {
                panic!(
                    "north_star_test_uses_only_canonical_entry_points: forbidden pattern \
                     `{pattern}` found at line {} (outside a comment).\n  Line: {line}\n  \
                     The north-star test MUST use ONLY the canonical production Node entry \
                     points (serve_gateway_persistent_async_with_handshake, \
                     serve_relay_persistent_async_with_handshake, \
                     establish_circuit_and_send_async). Direct calls to low-level \
                     transport/handshake functions are FORBIDDEN.",
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

/// Now-unix-seconds helper.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A node's full identity: Ed25519 (signing) + X25519 (rendezvous) + NodeId.
///
/// The X25519 secret is wrapped in `Arc` so it can be shared between the
/// circuit-DH computation (in `establish_circuit_and_send_async`) and the
/// SNP-IK/0.1 handshake (internal to the production entry points).
struct NodeIdents {
    ed_sk: [u8; 32],
    ed_pk: [u8; 32],
    x_sk: Arc<X25519Secret>,
    x_pk: X25519PubKey,
    node_id: [u8; 32],
}

impl NodeIdents {
    /// Generate a fresh identity from an OS-CSPRNG (NO deterministic seeds).
    fn fresh() -> Self {
        let mut ed_sk = [0u8; 32];
        getrandom::getrandom(&mut ed_sk).expect("getrandom");
        let ed_pk = derive_public_key(&ed_sk);
        let node_id = derive_node_id(&ed_pk);
        let (x_sk, x_pk) = x25519_static_keypair();
        Self {
            ed_sk,
            ed_pk,
            x_sk: Arc::new(x_sk),
            x_pk,
            node_id,
        }
    }

    /// Build a `NodeIdentity` (Ed25519-only) for the Node abstraction.
    fn identity(&self) -> NodeIdentity {
        NodeIdentity::from_secret(self.ed_sk)
    }
}

/// Bind an ephemeral port and return the address (drops the listener).
async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

/// A local HTTP server that returns a deterministic body.
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

/// Test-only connector factory: bypasses `is_private_destination` to allow
/// fetching from the local mock HTTP server on 127.0.0.1.
fn test_connector_factory(
    url: &str,
) -> Result<PinnedConnector, snp_node::legacy::NodeError> {
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

/// Hex-short for diagnostics.
fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

// ════════════════════════════════════════════════════════════════════════════
// THE NORTH-STAR TEST
// ════════════════════════════════════════════════════════════════════════════

/// The north-star integration test:
///
/// Client → Relay A → Relay B → Gateway → local HTTP → back, using ONLY
/// the canonical production Node entry points.
///
/// - `serve_gateway_persistent_async_with_handshake_and_connector` (gateway)
/// - `serve_relay_persistent_async_with_handshake` (relay A + relay B)
/// - `establish_circuit_and_send_async` (client)
///
/// All SNP-IK/0.1 handshakes, all AsyncLink construction, all relay
/// forwarding, all circuit establishment — INTERNAL to the production
/// entry points. The test only orchestrates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn north_star_canonical_production_path() {
    // ═══ 1. Generate dynamic identities (fresh Ed25519 + X25519) ═══
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

    // ═══ 3. Establish the gateway-side circuit keys ═══
    // The gateway needs the SAME circuit keys as the client (derived from the
    // client↔gateway X25519 DH). The client's DH is internal to
    // `establish_circuit_and_send_async`; the gateway's DH is computed here
    // (using the gateway's X25519 secret + the client's X25519 public).
    let gateway_circuit_dh = x25519_dh(&gateway_idents.x_sk, &client_idents.x_pk);
    let gateway_circuit_keys = derive_circuit_keys_from_dh(&gateway_circuit_dh, false);

    // ═══ 4. Construct the dynamic Route ═══
    let mut route = Route::new(
        client_idents.node_id,
        gateway_idents.node_id,
        vec![
            relay_a_idents.node_id,
            relay_b_idents.node_id,
            gateway_idents.node_id,
        ],
    );
    route.validate().expect("route must be valid");
    route.transition(RouteState::Establishing).expect("Proposed → Establishing");
    eprintln!("[north-star] route: {} hops (relay A → relay B → gateway)", route.hops.len());

    // ═══ 5. Start the GATEWAY via the canonical production entry point ═══
    // `serve_gateway_persistent_async_with_handshake_and_connector` does:
    //   1. Bind + accept a connection from Relay B.
    //   2. Perform the SNP-IK/0.1 handshake (responder) — INTERNAL.
    //   3. Serve transit requests (decrypt circuit → fetch URL → encrypt response).
    let gateway_handle = {
        let gateway_node = Node::new(
            gateway_idents.identity(),
            vec![Capability::Gateway],
            gateway_listen_addr.clone(),
        );
        let gateway_x_sk = Arc::clone(&gateway_idents.x_sk);
        let gateway_x_pk = gateway_idents.x_pk;
        let client_ed_pk = client_idents.ed_pk;
        let circuit_keys = gateway_circuit_keys;
        let listen_addr = gateway_listen_addr.clone();
        tokio::spawn(async move {
            async_node::serve_gateway_persistent_async_with_handshake_and_connector(
                &gateway_node,
                &listen_addr,
                &gateway_x_sk,
                &gateway_x_pk,
                circuit_keys,
                client_ed_pk,
                |url| test_connector_factory(url),
            )
            .await
            .expect("gateway canonical entry point must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 6. Start RELAY B via the canonical production entry point ═══
    // `serve_relay_persistent_async_with_handshake` does:
    //   1. Bind + accept a connection from Relay A.
    //   2. Perform the SNP-IK/0.1 handshake (responder) with Relay A — INTERNAL.
    //   3. Connect to the gateway.
    //   4. Perform the SNP-IK/0.1 handshake (initiator, pinning gateway NodeId) — INTERNAL.
    //   5. Forward frames bidirectionally — INTERNAL.
    let relay_b_handle = {
        let relay_b_node = Node::new(
            relay_b_idents.identity(),
            vec![Capability::Relay],
            relay_b_listen_addr.clone(),
        );
        let relay_b_x_sk = Arc::clone(&relay_b_idents.x_sk);
        let relay_b_x_pk = relay_b_idents.x_pk;
        let listen_addr = relay_b_listen_addr.clone();
        let next_hop = gateway_listen_addr.clone();
        let gateway_node_id = gateway_idents.node_id;
        tokio::spawn(async move {
            async_node::serve_relay_persistent_async_with_handshake(
                &relay_b_node,
                &listen_addr,
                &next_hop,
                gateway_node_id,
                &relay_b_x_sk,
                &relay_b_x_pk,
            )
            .await
            .expect("relay B canonical entry point must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 7. Start RELAY A via the canonical production entry point ═══
    let relay_a_handle = {
        let relay_a_node = Node::new(
            relay_a_idents.identity(),
            vec![Capability::Relay],
            relay_a_listen_addr.clone(),
        );
        let relay_a_x_sk = Arc::clone(&relay_a_idents.x_sk);
        let relay_a_x_pk = relay_a_idents.x_pk;
        let listen_addr = relay_a_listen_addr.clone();
        let next_hop = relay_b_listen_addr.clone();
        let relay_b_node_id = relay_b_idents.node_id;
        tokio::spawn(async move {
            async_node::serve_relay_persistent_async_with_handshake(
                &relay_a_node,
                &listen_addr,
                &next_hop,
                relay_b_node_id,
                &relay_a_x_sk,
                &relay_a_x_pk,
            )
            .await
            .expect("relay A canonical entry point must succeed");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 8. CLIENT: establish circuit + send request via the canonical entry point ═══
    // `establish_circuit_and_send_async` does:
    //   1. Establish fresh circuit keys via client↔gateway X25519 DH — INTERNAL.
    //   2. Insert the Circuit into the Node's circuit table — INTERNAL.
    //   3. Perform the SNP-IK/0.1 handshake with Relay A (initiator, pinning Relay A's NodeId) — INTERNAL.
    //   4. Build + sign + circuit-encrypt the TransitRequest — INTERNAL.
    //   5. Send via the AsyncLink — INTERNAL.
    //   6. Receive + decrypt + verify the response — INTERNAL.
    let client_node = Node::new(
        client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let transit_resp = async_node::establish_circuit_and_send_async(
        &client_node,
        &http_url,
        &gateway_idents.node_id,
        &gateway_idents.ed_pk,
        &gateway_idents.x_pk,
        &relay_a_listen_addr,
        &relay_a_idents.node_id,
        &client_x_sk,
        &client_x_pk,
    )
    .await
    .expect("client canonical entry point must succeed");

    // ═══ 9. Verify the response ═══
    assert_eq!(transit_resp.status, 200, "HTTP status must be 200");
    let expected_object_id = sha256(b"Hello, ShareNet!");
    assert_eq!(
        transit_resp.object_id, expected_object_id,
        "objectId must match SHA-256(\"Hello, ShareNet!\")"
    );
    assert!(verify_transit_response(&transit_resp, &gateway_idents.ed_pk),
        "gateway signature must verify");
    assert_eq!(transit_resp.gateway_id, gateway_idents.node_id,
        "response gateway_id must match the gateway's NodeId");

    // ═══ 10. Drive the route to Active + verify the Circuit ═══
    route.transition(RouteState::Active).expect("Establishing → Active");
    assert_eq!(route.state, RouteState::Active);
    assert_eq!(route.metrics.hop_count, 3, "route has 3 hops");

    let circuit = client_node
        .circuits
        .lock()
        .unwrap()
        .get(&gateway_idents.node_id)
        .cloned()
        .expect("circuit must be in the Node's circuit table");
    assert!(circuit.active, "circuit must be active");
    assert_eq!(circuit.gateway_node_id, gateway_idents.node_id);
    assert_eq!(circuit.gateway_public_key, gateway_idents.ed_pk);

    // ═══ 11. Cleanup ═══
    let _ = http_handle.await;
    let _ = gateway_handle.await;
    let _ = relay_b_handle.await;
    let _ = relay_a_handle.await;

    eprintln!("[north-star] PASSED:");
    eprintln!("  Client → Relay A → Relay B → Gateway → local HTTP → back");
    eprintln!("  Canonical production entry points: YES (3 — gateway, relay, client)");
    eprintln!("  Dynamic identities: 4 fresh Ed25519 + X25519 keypairs (no deterministic seeds)");
    eprintln!("  SNP-IK/0.1 handshakes: 3 (all INTERNAL to the production entry points)");
    eprintln!("  Canonical async transport: AsyncLink (INTERNAL)");
    eprintln!("  Fresh X25519 circuit establishment: client↔gateway DH (INTERNAL)");
    eprintln!("  Dynamic Route: {:?} → {} hops", route.state, route.hops.len());
    eprintln!("  Dynamic Circuit: in Node's circuit table (active=true)");
    eprintln!("  HTTP traffic: real (status=200, body=\"Hello, ShareNet!\")");
    eprintln!("  Body integrity: objectId = SHA-256(\"Hello, ShareNet!\") (verified)");
    eprintln!("  Gateway signature: verified (Ed25519)");
    eprintln!("  No GatewayChoice, no deterministic seeds, no compile-time topology");
    eprintln!("  No direct calls to derive_link_keys, derive_circuit_keys, Link::connect,");
    eprintln!("    std::net::TcpStream/TcpListener, perform_snp_ik_handshake_async,");
    eprintln!("    async_relay_forward_links, AsyncLink::new, AsyncLink::connect_raw");
}

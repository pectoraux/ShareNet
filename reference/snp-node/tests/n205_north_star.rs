//! N2.0.6 North-Star Integration Test — the strongest reference-level proof.
//!
//! Topology:
//!
//! ```text
//!   Client ──[SNP-IK/0.1]──> Relay A ──[SNP-IK/0.1]──> Relay B ──[SNP-IK/0.1]──> Gateway ──> local HTTP
//!     └──────────────────── [circuit DH: client↔gateway X25519] ────────────────────┘
//! ```
//!
//! This test exercises the FULL canonical production path:
//!
//! 1. **Dynamic identities** — 4 random Ed25519 + X25519 keypairs (no
//!    deterministic seeds, no `GatewayChoice`, no compile-time topology).
//! 2. **SNP-IK/0.1 handshakes** at every hop via
//!    [`perform_snp_ik_handshake_async`] — fresh directional AEAD link keys
//!    per hop, identity binding (the client pins each peer's NodeId).
//! 3. **Canonical async transport** — [`AsyncLink`] (Tokio-based AEAD
//!    framing) for all frame send/recv.
//! 4. **Dynamic Route** — [`Route::new`] with an explicit hop list, validated
//!    by [`Route::validate`], state machine driven Proposed → Establishing
//!    → Active.
//! 5. **Dynamic Circuit** — [`Circuit::new`] with the gateway's NodeId +
//!    Ed25519 public key + fresh circuit keys derived from a client↔gateway
//!    X25519 DH (NOT a deterministic seed).
//! 6. **Real HTTP traffic** — a local HTTP server returns `"Hello, ShareNet!"`;
//!    the client sends a TransitRequest through the mesh; the gateway fetches
//!    via `PinnedConnector::from_parts` (test-only SSRF bypass for 127.0.0.1);
//!    the response body's SHA-256 (`object_id`) is verified end-to-end.
//! 7. **No process restart** — relay and gateway run in tokio tasks; the
//!    client task sends the request and verifies the response.

#![allow(clippy::pedantic, deprecated)]

use std::sync::Arc;

use snp_crypto::{
    derive_node_id, derive_public_key, sha256, x25519_dh, x25519_static_keypair, X25519PubKey,
    X25519Secret,
};
use snp_frames::{Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_gateway::{
    decode_transit_response, encode_transit_request, sign_transit_request,
    verify_transit_response, PinnedConnector, TransitRequest, TransitResponse,
};
use snp_link::async_link::{
    async_relay_forward_links, perform_snp_ik_handshake_async, AsyncLink,
};
use snp_link::{
    decrypt_circuit_payload, derive_circuit_keys_from_dh, encrypt_circuit_payload, LinkKeys,
};
use snp_node::node::{
    async_node::serve_one_gateway_request_async_with_connector, Circuit, Node, NodeIdentity,
    Route, RouteState, ServeOutcome, Capability,
};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
/// circuit-DH computation (in the test thread) and the SNP-IK/0.1 handshake
/// (in a tokio task). `X25519Secret` is not `Clone`, but `Arc::clone` just
/// bumps the refcount — the underlying secret bytes are shared.
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
}

/// Bind an ephemeral port and return the address (drops the listener).
async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

/// Perform the SNP-IK/0.1 handshake as the INITIATOR (client side).
///
/// Connects to `peer_addr`, performs the handshake with `expected_peer_node_id`
/// pinning, returns the resulting `LinkKeys` + the `AsyncLink` ready for use.
async fn handshake_initiator(
    my_idents: &NodeIdents,
    peer_addr: &str,
    expected_peer_node_id: &[u8; 32],
) -> (LinkKeys, AsyncLink) {
    let mut stream = AsyncLink::connect_raw(peer_addr)
        .await
        .expect("initiator: connect");
    let result = perform_snp_ik_handshake_async(
        &mut stream,
        true, // initiator
        &my_idents.ed_sk,
        &my_idents.ed_pk,
        &my_idents.x_sk,
        &my_idents.x_pk,
        Some(expected_peer_node_id),
    )
    .await
    .expect("initiator: handshake");
    assert_eq!(
        result.peer_node_id, *expected_peer_node_id,
        "initiator: peer NodeId must match expected (identity substitution would be rejected)"
    );
    let link = AsyncLink::new(stream, result.link_keys);
    (result.link_keys, link)
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

// ─── Test 1: north-star happy path (manual client send) ─────────────────────

/// The north-star integration test:
///
/// Client → Relay A → Relay B → Gateway → local HTTP → back, with:
/// - 4 dynamic identities (fresh Ed25519 + X25519 keypairs)
/// - SNP-IK/0.1 handshakes at every hop (identity binding, fresh keys)
/// - Canonical async transport (AsyncLink / tokio)
/// - Dynamic Route (Proposed → Establishing → Active)
/// - Dynamic Circuit (fresh client↔gateway X25519 DH)
/// - Real HTTP traffic + body integrity (objectId = SHA-256(body))
/// - No GatewayChoice, no deterministic seeds, no compile-time topology
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn north_star_async_snp_ik_dynamic_mesh_with_http() {
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
    let gateway_transit_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;
    let (http_addr, http_handle) = start_local_http().await;
    // The URL the client requests — uses the local HTTP server's actual port.
    // The `test_connector_factory` bypasses SSRF to allow 127.0.0.1.
    let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

    // ═══ 3. Establish circuit keys via client↔gateway X25519 DH ═══
    // The circuit key is end-to-end (client ↔ gateway); relays NEVER possess it.
    // Both sides compute the SAME DH output (X25519 is symmetric).
    let circuit_dh_client = x25519_dh(&client_idents.x_sk, &gateway_idents.x_pk);
    let circuit_dh_gateway = x25519_dh(&gateway_idents.x_sk, &client_idents.x_pk);
    assert_eq!(
        circuit_dh_client, circuit_dh_gateway,
        "client↔gateway X25519 DH must produce the same shared secret on both sides"
    );
    let client_circuit_keys = derive_circuit_keys_from_dh(&circuit_dh_client, true);
    let gateway_circuit_keys = derive_circuit_keys_from_dh(&circuit_dh_gateway, false);

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
    eprintln!(
        "[north-star] route: {} hops (relay A → relay B → gateway)",
        route.hops.len()
    );

    // ═══ 5. Start the gateway (async, with handshake-on-accept) ═══
    let gateway_handle = {
        let gateway_sk = gateway_idents.ed_sk;
        let gateway_pk = gateway_idents.ed_pk;
        let gateway_x_sk = Arc::clone(&gateway_idents.x_sk);
        let gateway_x_pk = gateway_idents.x_pk;
        let gateway_node_id = gateway_idents.node_id;
        let client_ed_pk = client_idents.ed_pk;
        let circuit_keys = gateway_circuit_keys;
        let listen_addr = gateway_transit_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen_addr).await.expect("gateway: bind");
            eprintln!("[north-star] gateway listening on {listen_addr}");
            let (mut stream, _) = listener.accept().await.expect("gateway: accept");
            eprintln!("[north-star] gateway accepted relay connection");
            let handshake = perform_snp_ik_handshake_async(
                &mut stream,
                false, // responder
                &gateway_sk,
                &gateway_pk,
                &gateway_x_sk,
                &gateway_x_pk,
                None,
            )
            .await
            .expect("gateway: handshake");
            eprintln!(
                "[north-star] gateway handshake OK, peer (relay) nodeId={}",
                hex_short(&handshake.peer_node_id)
            );
            let link = Arc::new(AsyncLink::new(stream, handshake.link_keys));
            let mut seen_req_ids = std::collections::HashSet::new();
            // Serve loop (one request for this test).
            loop {
                let outcome = serve_one_gateway_request_async_with_connector(
                    &link,
                    gateway_node_id,
                    &gateway_sk,
                    &client_ed_pk,
                    &circuit_keys,
                    &mut seen_req_ids,
                    &|url| test_connector_factory(url),
                )
                .await;
                match outcome {
                    Ok(ServeOutcome::Continue) => {
                        eprintln!("[north-star] gateway served one request");
                        break;
                    }
                    Ok(ServeOutcome::Closed) => {
                        eprintln!("[north-star] gateway connection closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[north-star] gateway error: {e}");
                        break;
                    }
                }
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 6. Start Relay B (async, handshakes on both sides) ═══
    let relay_b_handle = {
        let relay_b_sk = relay_b_idents.ed_sk;
        let relay_b_pk = relay_b_idents.ed_pk;
        let relay_b_x_sk = Arc::clone(&relay_b_idents.x_sk);
        let relay_b_x_pk = relay_b_idents.x_pk;
        let gateway_node_id = gateway_idents.node_id;
        let listen_addr = relay_b_addr.clone();
        let gateway_addr = gateway_transit_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen_addr).await.expect("relay B: bind");
            eprintln!("[north-star] relay B listening on {listen_addr}");
            let (mut prev_stream, _) = listener.accept().await.expect("relay B: accept");
            eprintln!("[north-star] relay B accepted relay A connection");
            let prev_handshake = perform_snp_ik_handshake_async(
                &mut prev_stream,
                false, // responder (Relay A is the initiator here)
                &relay_b_sk,
                &relay_b_pk,
                &relay_b_x_sk,
                &relay_b_x_pk,
                None,
            )
            .await
            .expect("relay B: prev handshake");
            eprintln!(
                "[north-star] relay B handshake with relay A OK, peer nodeId={}",
                hex_short(&prev_handshake.peer_node_id)
            );
            let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_handshake.link_keys));
            // Connect to gateway + handshake (initiator).
            let mut next_stream = AsyncLink::connect_raw(&gateway_addr)
                .await
                .expect("relay B: connect to gateway");
            let next_handshake = perform_snp_ik_handshake_async(
                &mut next_stream,
                true, // initiator
                &relay_b_sk,
                &relay_b_pk,
                &relay_b_x_sk,
                &relay_b_x_pk,
                Some(&gateway_node_id),
            )
            .await
            .expect("relay B: next handshake");
            assert_eq!(
                next_handshake.peer_node_id, gateway_node_id,
                "relay B: gateway identity must match expected"
            );
            eprintln!("[north-star] relay B handshake with gateway OK");
            let next_link = Arc::new(AsyncLink::new(next_stream, next_handshake.link_keys));
            let _ = async_relay_forward_links(prev_link, next_link).await;
            eprintln!("[north-star] relay B forwarding complete");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 7. Start Relay A (async, handshakes on both sides) ═══
    let relay_a_handle = {
        let relay_a_sk = relay_a_idents.ed_sk;
        let relay_a_pk = relay_a_idents.ed_pk;
        let relay_a_x_sk = Arc::clone(&relay_a_idents.x_sk);
        let relay_a_x_pk = relay_a_idents.x_pk;
        let relay_b_node_id = relay_b_idents.node_id;
        let listen_addr = relay_a_addr.clone();
        let relay_b_addr_local = relay_b_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen_addr).await.expect("relay A: bind");
            eprintln!("[north-star] relay A listening on {listen_addr}");
            let (mut prev_stream, _) = listener.accept().await.expect("relay A: accept");
            eprintln!("[north-star] relay A accepted client connection");
            let prev_handshake = perform_snp_ik_handshake_async(
                &mut prev_stream,
                false, // responder (client is the initiator)
                &relay_a_sk,
                &relay_a_pk,
                &relay_a_x_sk,
                &relay_a_x_pk,
                None,
            )
            .await
            .expect("relay A: prev handshake");
            eprintln!(
                "[north-star] relay A handshake with client OK, peer nodeId={}",
                hex_short(&prev_handshake.peer_node_id)
            );
            let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_handshake.link_keys));
            // Connect to relay B + handshake (initiator).
            let mut next_stream = AsyncLink::connect_raw(&relay_b_addr_local)
                .await
                .expect("relay A: connect to relay B");
            let next_handshake = perform_snp_ik_handshake_async(
                &mut next_stream,
                true, // initiator
                &relay_a_sk,
                &relay_a_pk,
                &relay_a_x_sk,
                &relay_a_x_pk,
                Some(&relay_b_node_id),
            )
            .await
            .expect("relay A: next handshake");
            assert_eq!(
                next_handshake.peer_node_id, relay_b_node_id,
                "relay A: relay B identity must match expected"
            );
            eprintln!("[north-star] relay A handshake with relay B OK");
            let next_link = Arc::new(AsyncLink::new(next_stream, next_handshake.link_keys));
            let _ = async_relay_forward_links(prev_link, next_link).await;
            eprintln!("[north-star] relay A forwarding complete");
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ═══ 8. Client: handshake with Relay A + send request ═══
    let (_client_link_keys, client_link) =
        handshake_initiator(&client_idents, &relay_a_addr, &relay_a_idents.node_id).await;
    eprintln!("[north-star] client handshake with relay A OK");

    // Build + sign the TransitRequest.
    let mut req = TransitRequest {
        req_id: {
            let mut id = [0u8; 16];
            getrandom::getrandom(&mut id).unwrap();
            id
        },
        method: "GET".to_string(),
        url: http_url.clone(),
        tls_termination: "GATEWAY_PLAINTEXT".to_string(),
        max_response_bytes: 65536,
        deadline: now_unix() + 60,
        reply_to: [0u8; 32],
        client_sig: [0u8; 64],
    };
    sign_transit_request(&mut req, &client_idents.ed_sk);
    let req_bytes = encode_transit_request(&req).expect("encode request");

    // Circuit-encrypt the body.
    let sealed_body = encrypt_circuit_payload(&client_circuit_keys.send_key, &req_bytes);

    // Build the Class B frame addressed to the gateway.
    let req_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: gateway_idents.node_id,
        src: client_idents.node_id,
        ttl: FRAME_TTL_MAX,
        fid: {
            let mut fid = [0u8; 8];
            getrandom::getrandom(&mut fid).unwrap();
            fid
        },
        seq: 1,
        body: sealed_body,
    };

    eprintln!("[north-star] client sending request frame");
    client_link
        .send_frame(&req_frame)
        .await
        .expect("client: send request");

    // Receive the response.
    let resp_frame = client_link.recv_frame().await.expect("client: recv response");
    assert_eq!(resp_frame.cls, b'B', "response must be Class B");

    // Decrypt the circuit payload.
    let resp_bytes = decrypt_circuit_payload(&client_circuit_keys.recv_key, &resp_frame.body)
        .expect("client: circuit decrypt");
    let transit_resp: TransitResponse =
        decode_transit_response(&resp_bytes).expect("decode resp");

    // Verify the gateway's signature.
    let verified = verify_transit_response(&transit_resp, &gateway_idents.ed_pk);
    assert!(verified, "gateway signature must verify");

    // Verify the HTTP status + body integrity.
    assert_eq!(transit_resp.status, 200, "HTTP status must be 200");
    let expected_object_id = sha256(b"Hello, ShareNet!");
    assert_eq!(
        transit_resp.object_id, expected_object_id,
        "objectId must match SHA-256(\"Hello, ShareNet!\")"
    );
    assert_eq!(
        transit_resp.gateway_id, gateway_idents.node_id,
        "response gateway_id must match the gateway's NodeId"
    );

    eprintln!("[north-star] response verified: status=200, objectId matches, signature OK");

    // ═══ 9. Drive the route to Active ═══
    route.transition(RouteState::Active).expect("Establishing → Active");
    assert_eq!(route.state, RouteState::Active);
    assert_eq!(
        route.metrics.hop_count, 3,
        "route has 3 hops (relay A, relay B, gateway)"
    );

    // ═══ 10. Construct the Circuit object ═══
    let circuit = Circuit::new(
        gateway_idents.node_id,
        gateway_idents.ed_pk,
        client_circuit_keys,
    );
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
    eprintln!("  Dynamic identities: 4 fresh Ed25519 + X25519 keypairs (no deterministic seeds)");
    eprintln!("  SNP-IK/0.1 handshakes: 3 (client↔relay A, relay A↔relay B, relay B↔gateway)");
    eprintln!("  Canonical async transport: AsyncLink + tokio");
    eprintln!("  Dynamic Route: {:?} → {} hops", route.state, route.hops.len());
    eprintln!("  Dynamic Circuit: client↔gateway X25519 DH (NOT a deterministic seed)");
    eprintln!("  HTTP traffic: real (status=200, body=\"Hello, ShareNet!\")");
    eprintln!("  Body integrity: objectId = SHA-256(\"Hello, ShareNet!\") (verified)");
    eprintln!("  Gateway signature: verified (Ed25519)");
    eprintln!("  No GatewayChoice, no compile-time topology, no process restart");

    // Touch http_addr to avoid unused warning.
    let _ = http_addr;
}

// ─── Test 2: north-star with the FULL handshake-and-send convenience function ──

/// A second north-star variant that uses
/// [`send_request_with_full_snp_ik_handshake_async`] — the convenience
/// function that performs the SNP-IK/0.1 handshake AND sends the request in
/// one call. This proves the canonical client production path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn north_star_full_handshake_and_send() {
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_transit_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;
    let (http_addr, http_handle) = start_local_http().await;
    let http_url = format!("http://test.local:{}/", http_addr.rsplit(':').next().unwrap());

    let circuit_dh_client = x25519_dh(&client_idents.x_sk, &gateway_idents.x_pk);
    let circuit_dh_gateway = x25519_dh(&gateway_idents.x_sk, &client_idents.x_pk);
    assert_eq!(circuit_dh_client, circuit_dh_gateway);
    let client_circuit_keys = derive_circuit_keys_from_dh(&circuit_dh_client, true);
    let gateway_circuit_keys = derive_circuit_keys_from_dh(&circuit_dh_gateway, false);

    // Gateway task.
    let gateway_handle = {
        let sk = gateway_idents.ed_sk;
        let pk = gateway_idents.ed_pk;
        let x_sk = Arc::clone(&gateway_idents.x_sk);
        let x_pk = gateway_idents.x_pk;
        let node_id = gateway_idents.node_id;
        let client_pk = client_idents.ed_pk;
        let circuit = gateway_circuit_keys;
        let listen = gateway_transit_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen).await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let h = perform_snp_ik_handshake_async(
                &mut stream, false, &sk, &pk, &x_sk, &x_pk, None,
            )
            .await
            .unwrap();
            let link = Arc::new(AsyncLink::new(stream, h.link_keys));
            let mut seen = std::collections::HashSet::new();
            let _ = serve_one_gateway_request_async_with_connector(
                &link, node_id, &sk, &client_pk, &circuit, &mut seen,
                &|url| test_connector_factory(url),
            )
            .await;
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Relay B.
    let relay_b_handle = {
        let sk = relay_b_idents.ed_sk;
        let pk = relay_b_idents.ed_pk;
        let x_sk = Arc::clone(&relay_b_idents.x_sk);
        let x_pk = relay_b_idents.x_pk;
        let gw_node_id = gateway_idents.node_id;
        let listen = relay_b_addr.clone();
        let gw_addr = gateway_transit_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen).await.unwrap();
            let (mut prev_stream, _) = listener.accept().await.unwrap();
            let prev_h = perform_snp_ik_handshake_async(
                &mut prev_stream, false, &sk, &pk, &x_sk, &x_pk, None,
            )
            .await
            .unwrap();
            let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_h.link_keys));
            let mut next_stream = AsyncLink::connect_raw(&gw_addr).await.unwrap();
            let next_h = perform_snp_ik_handshake_async(
                &mut next_stream, true, &sk, &pk, &x_sk, &x_pk, Some(&gw_node_id),
            )
            .await
            .unwrap();
            let next_link = Arc::new(AsyncLink::new(next_stream, next_h.link_keys));
            let _ = async_relay_forward_links(prev_link, next_link).await;
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Relay A.
    let relay_a_handle = {
        let sk = relay_a_idents.ed_sk;
        let pk = relay_a_idents.ed_pk;
        let x_sk = Arc::clone(&relay_a_idents.x_sk);
        let x_pk = relay_a_idents.x_pk;
        let rb_node_id = relay_b_idents.node_id;
        let listen = relay_a_addr.clone();
        let rb_addr = relay_b_addr.clone();
        tokio::spawn(async move {
            let listener = TcpListener::bind(&listen).await.unwrap();
            let (mut prev_stream, _) = listener.accept().await.unwrap();
            let prev_h = perform_snp_ik_handshake_async(
                &mut prev_stream, false, &sk, &pk, &x_sk, &x_pk, None,
            )
            .await
            .unwrap();
            let prev_link = Arc::new(AsyncLink::new(prev_stream, prev_h.link_keys));
            let mut next_stream = AsyncLink::connect_raw(&rb_addr).await.unwrap();
            let next_h = perform_snp_ik_handshake_async(
                &mut next_stream, true, &sk, &pk, &x_sk, &x_pk, Some(&rb_node_id),
            )
            .await
            .unwrap();
            let next_link = Arc::new(AsyncLink::new(next_stream, next_h.link_keys));
            let _ = async_relay_forward_links(prev_link, next_link).await;
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Client: build Node + circuit, then call the FULL handshake-and-send.
    let client_identity = NodeIdentity::from_secret(client_idents.ed_sk);
    let client_node = Node::new(client_identity, vec![Capability::Client], String::new());
    let circuit = Circuit::new(
        gateway_idents.node_id,
        gateway_idents.ed_pk,
        client_circuit_keys,
    );
    client_node
        .circuits
        .lock()
        .unwrap()
        .insert(gateway_idents.node_id, circuit);

    let transit_resp =
        snp_node::node::async_node::send_request_with_full_snp_ik_handshake_async(
            &client_node,
            &http_url,
            &gateway_idents.node_id,
            &relay_a_addr,
            &relay_a_idents.node_id,
            &client_idents.ed_sk,
            &client_idents.ed_pk,
            &client_idents.x_sk,
            &client_idents.x_pk,
        )
        .await
        .expect("full handshake-and-send must succeed");

    assert_eq!(transit_resp.status, 200);
    assert_eq!(transit_resp.object_id, sha256(b"Hello, ShareNet!"));
    assert!(verify_transit_response(&transit_resp, &gateway_idents.ed_pk));
    assert_eq!(transit_resp.gateway_id, gateway_idents.node_id);

    eprintln!("[north-star-full] PASSED: full handshake-and-send works end-to-end");

    let _ = http_handle.await;
    let _ = gateway_handle.await;
    let _ = relay_b_handle.await;
    let _ = relay_a_handle.await;

    let _ = http_addr;
}

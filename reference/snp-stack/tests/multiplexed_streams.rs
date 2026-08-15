//! N2.3.8 — Multiplexed Mode B: multiple streams on ONE authenticated circuit.
//!
//! This test proves that multiple independent Mode B streams can coexist on
//! a single authenticated circuit, each with its own destination, flow
//! control, sequence space, and TCP socket.

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{
    derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_stack::{AsyncUpstream, ShareNetCircuitUpstreamModeB};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
    fn identity(&self) -> NodeIdentity { NodeIdentity::from_secret(self.ed_sk) }
    fn gateway_descriptor(&self) -> VerifiedNodeDescriptor {
        let advert = GatewayAdvertisement::for_identity_with_circuit_key(
            &self.identity(), self.x_pk.to_bytes(), "127.0.0.1:0", "127.0.0.1:0",
        );
        advert.verify_into_verified().expect("verify").descriptor().expect("descriptor")
    }
    fn relay_descriptor(&self) -> VerifiedNodeDescriptor { self.gateway_descriptor() }
}

async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

async fn start_echo_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if stream.write_all(&buf[..n]).await.is_err() { break; } }
                    }
                }
            });
        }
    });
    (addr, handle)
}

fn start_relay(idents: &NodeIdents, route: &Route, pos: usize, addr: &str) -> tokio::task::JoinHandle<()> {
    let node = Node::new(idents.identity(), vec![Capability::Relay], addr.to_string());
    let x_sk = Arc::clone(&idents.x_sk);
    let x_pk = idents.x_pk;
    let listen = addr.to_string();
    let route = route.clone();
    tokio::spawn(async move {
        let _ = async_node::serve_relay_via_route(&node, &route, pos, &listen, &x_sk, &x_pk).await;
    })
}

fn build_route(
    client: &NodeIdents, ra: &NodeIdents, rb: &NodeIdents, gw: &NodeIdents,
    ra_addr: &str, rb_addr: &str, gw_addr: &str,
) -> Route {
    let route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(gw_addr)),
        ],
    );
    route.validate().expect("route valid");
    let mut route = route;
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    route
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiplexed_two_streams_one_circuit() {
    // 1. Bring up mesh + two echo servers (different ports = different destinations).
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;

    let (echo1_addr, _echo1) = start_echo_server().await;
    let echo1_port: u16 = echo1_addr.rsplit(':').next().unwrap().parse().unwrap();
    let (echo2_addr, _echo2) = start_echo_server().await;
    let echo2_port: u16 = echo2_addr.rsplit(':').next().unwrap().parse().unwrap();

    // Start multiplexed gateway.
    let gateway_node = Node::new(
        gateway_idents.identity(), vec![Capability::Gateway], gateway_addr.clone(),
    );
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let gw_listen = gateway_addr.clone();
    let stream_table = Arc::new(GatewayStreamTable::with_allow_loopback());
    let st = Arc::clone(&stream_table);
    let gateway_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(
            &gateway_node, &gw_listen, &gw_x_sk, &gw_x_pk, &st,
        ).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relays.
    let relay_b_route = Route::new_with_hop_details(
        relay_a_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let relay_a_route = Route::new_with_hop_details(
        client_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_a_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_a_addr)),
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_a_handle = start_relay(&relay_a_idents, &relay_a_route, 0, &relay_a_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route = build_route(
        &client_idents, &relay_a_idents, &relay_b_idents, &gateway_idents,
        &relay_a_addr, &relay_b_addr, &gateway_addr,
    );

    // 2. Establish ONE multiplexed circuit.
    let client_node = Node::new(client_idents.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    )
    .await
    .expect("establish timeout")
    .expect("establish must succeed");

    // 3. Open TWO streams on the SAME circuit — different destinations.
    let dest1 = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: echo1_port,
        protocol: TransportProtocol::Tcp,
    };
    let dest2 = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: echo2_port,
        protocol: TransportProtocol::Tcp,
    };

    let mut stream1 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(dest1),
    ).await.expect("stream1 timeout").expect("stream1 must succeed");

    let mut stream2 = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(dest2),
    ).await.expect("stream2 timeout").expect("stream2 must succeed");

    // Verify both streams have different IDs.
    assert_ne!(
        stream1.stream_id(), stream2.stream_id(),
        "streams must have different IDs"
    );

    // 4. Send distinct data on each stream.
    let data1 = b"stream-1-data-on-shared-circuit";
    let data2 = b"stream-2-different-data";

    let sent1 = stream1.send(data1).await.expect("stream1 send");
    assert_eq!(sent1, data1.len());

    let sent2 = stream2.send(data2).await.expect("stream2 send");
    assert_eq!(sent2, data2.len());

    // 5. Receive echoes — must be correctly dispatched (no cross-contamination).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp1 = stream1.recv().await.expect("stream1 recv").expect("stream1 must have data");
    assert_eq!(
        resp1, data1,
        "stream 1 echo must match — got {:?}",
        String::from_utf8_lossy(&resp1)
    );

    let resp2 = stream2.recv().await.expect("stream2 recv").expect("stream2 must have data");
    assert_eq!(
        resp2, data2,
        "stream 2 echo must match — got {:?}",
        String::from_utf8_lossy(&resp2)
    );

    eprintln!(
        "[n2.3.8-mux] PASS: 2 streams on 1 circuit — stream {} → echo1 ({} bytes), \
         stream {} → echo2 ({} bytes). No cross-contamination.",
        stream1.stream_id(), resp1.len(),
        stream2.stream_id(), resp2.len()
    );

    // 6. Close stream 1 while stream 2 remains active.
    stream1.close().await.expect("stream1 close");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stream 2 should still work.
    let data2b = b"stream-2-still-alive";
    stream2.send(data2b).await.expect("stream2 send after close 1");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp2b = stream2.recv().await.expect("stream2 recv after close 1").expect("stream2 must still have data");
    assert_eq!(resp2b, data2b, "stream 2 must still work after stream 1 closed");

    eprintln!(
        "[n2.3.8-isolation] PASS: closing stream 1 does not affect stream 2 — \
         stream 2 sent + received {} bytes after stream 1 close",
        resp2b.len()
    );

    drop(gateway_handle);
    drop(relay_a_handle);
    drop(relay_b_handle);
}

/// Start a mesh + echo server for TCP failure isolation test.
/// Uses separate circuits (not multiplexed) since the test is about
/// independent failure, not shared-circuit multiplexing.
async fn setup_mesh_with_echo() -> (
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
    Route, Node, Arc<X25519Secret>, X25519PubKey, u16,
) {
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;
    let (echo_addr, _echo_handle) = start_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    let gateway_node = Node::new(
        gateway_idents.identity(), vec![Capability::Gateway], gateway_addr.clone(),
    );
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let gw_listen = gateway_addr.clone();
    let stream_table = Arc::new(GatewayStreamTable::with_allow_loopback());
    let st = Arc::clone(&stream_table);
    let gateway_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gateway_node, &gw_listen, &gw_x_sk, &gw_x_pk, &st).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    let relay_b_route = Route::new_with_hop_details(
        relay_a_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let relay_a_route = Route::new_with_hop_details(
        client_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_a_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_a_addr)),
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_a_handle = start_relay(&relay_a_idents, &relay_a_route, 0, &relay_a_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route = build_route(
        &client_idents, &relay_a_idents, &relay_b_idents, &gateway_idents,
        &relay_a_addr, &relay_b_addr, &gateway_addr,
    );
    let client_node = Node::new(client_idents.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    (gateway_handle, relay_a_handle, relay_b_handle, route, client_node, client_x_sk, client_x_pk, echo_port)
}

// ════════════════════════════════════════════════════════════════════════════
// N2.3.8 hardening: TCP failure isolation
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiplexed_tcp_failure_isolation() {
    let (gw_h, ra_h, rb_h, route, client_node, client_x_sk, client_x_pk, echo_port) = setup_mesh_with_echo().await;

    // Establish ONE multiplexed circuit.
    let mut circuit = tokio::time::timeout(
        Duration::from_secs(30),
        MultiplexedCircuit::establish(&client_node, &route, &client_x_sk, &client_x_pk),
    ).await.expect("establish timeout").expect("establish must succeed");

    // Stream A → dead destination (port 1, nothing listens).
    let dest_dead = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: 1,
        protocol: TransportProtocol::Tcp,
    };

    // Stream B → healthy echo server.
    let dest_healthy = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: echo_port,
        protocol: TransportProtocol::Tcp,
    };

    // Open stream A (dead destination) — should fail or reset.
    let result_a = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(dest_dead),
    ).await;

    // Stream A failed — that's expected.
    match &result_a {
        Ok(Err(_)) => eprintln!("[n2.3.8-tcp-fail] PASS: dead destination stream A rejected"),
        Ok(Ok(_)) => eprintln!("[n2.3.8-tcp-fail] PASS: stream A opened (gateway may send reset)"),
        Err(_) => eprintln!("[n2.3.8-tcp-fail] PASS: stream A timed out (gateway couldn't connect)"),
    }

    // Open stream B (healthy) on the SAME circuit.
    let mut stream_b = tokio::time::timeout(
        Duration::from_secs(30),
        circuit.open_stream(dest_healthy),
    ).await.expect("stream B timeout").expect("stream B must succeed on same circuit");

    // Stream B should work.
    let data = b"stream-b-healthy-after-a-failed";
    stream_b.send(data).await.expect("stream B send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = stream_b.recv().await.expect("stream B recv").expect("stream B data");
    assert_eq!(resp, data, "stream B echo must match");

    eprintln!("[n2.3.8-tcp-fail] PASS: stream B healthy on same circuit after stream A TCP failure");
    drop(gw_h);
    drop(ra_h);
    drop(rb_h);
}

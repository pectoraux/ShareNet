//! N2.2.5 Phase 5 — End-to-end Mode B integration test.
//!
//! This test brings up a full 4-node ShareNet mesh (A→B→C→G) with a raw TCP
//! test server, opens a Mode B stream via `ShareNetCircuitUpstreamModeB`,
//! and proves arbitrary TCP bytes cross the circuit bidirectionally.

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

async fn start_raw_tcp_echo_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
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

fn start_relay(
    idents: &NodeIdents, route: &Route, pos: usize, addr: &str,
) -> tokio::task::JoinHandle<()> {
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
async fn mode_b_end_to_end_raw_tcp_through_mesh() {
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;

    let (echo_addr, _echo_handle) = start_raw_tcp_echo_server().await;
    let echo_port: u16 = echo_addr.rsplit(':').next().unwrap().parse().unwrap();

    // Start Mode B gateway.
    let gateway_node = Node::new(
        gateway_idents.identity(), vec![Capability::Gateway], gateway_addr.clone(),
    );
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let gw_listen = gateway_addr.clone();
    let stream_table = Arc::new(GatewayStreamTable::with_allow_loopback());
    let st = Arc::clone(&stream_table);
    let gateway_handle = tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b(&gateway_node, &gw_listen, &gw_x_sk, &gw_x_pk, &st).await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relay B.
    let relay_b_route = Route::new_with_hop_details(
        relay_a_idents.node_id, gateway_idents.node_id,
        vec![
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relay A.
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

    // Open a Mode B stream to the echo server.
    let client_node = Node::new(client_idents.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let destination = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: echo_port,
        protocol: TransportProtocol::Tcp,
    };

    let mut upstream = tokio::time::timeout(
        Duration::from_secs(30),
        ShareNetCircuitUpstreamModeB::open(&client_node, &route, &client_x_sk, &client_x_pk, destination),
    )
    .await
    .expect("open did not complete within 30s")
    .expect("open must succeed");

    // Send arbitrary binary data.
    let test_data = b"Hello from Mode B - arbitrary TCP bytes!";
    let sent = upstream.send(test_data).await.expect("send must succeed");
    assert_eq!(sent, test_data.len(), "all bytes must be sent");

    // Receive the echo.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let response = upstream.recv().await.expect("recv must succeed");
    assert!(response.is_some(), "must receive echo data");

    let data = response.unwrap();
    assert_eq!(
        data, test_data,
        "echo must match sent data — got {:?}, expected {:?}",
        String::from_utf8_lossy(&data),
        String::from_utf8_lossy(test_data)
    );

    eprintln!(
        "[mode-b-e2e] PASS: sent {} bytes → A→B→C→G → echo server → G→C→B→A → received {} bytes",
        sent, data.len()
    );

    drop(gateway_handle);
    drop(relay_a_handle);
    drop(relay_b_handle);
}

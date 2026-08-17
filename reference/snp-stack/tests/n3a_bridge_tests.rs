//! **N3-A — End-to-End TCP Stream Bridge Test.**
//!
//! This test proves the core N3 invariant: an ordinary TCP application
//! can communicate with a real endpoint through ShareNet.
//!
//! ## Topology
//!
//! ```text
//! TCP Client (simulated OS app)
//!     ↓ TCP connect to 127.0.0.1:N3A_PORT
//! N3AClient (TcpListener)
//!     ↓ MultiplexedCircuit::open_stream()
//! Relay A → Relay B → Gateway
//!     ↓ TCP connect to 127.0.0.1:ECHO_PORT
//! Echo Server (simulated Internet endpoint)
//! ```
//!
//! ## What this proves
//!
//! - Real application TCP traffic enters ShareNet.
//! - The ShareNet circuit carries it through relays.
//! - The gateway opens a real TCP connection to the destination.
//! - Responses flow back through ShareNet to the application.
//! - The application receives correct data.
//!
//! ## What this does NOT prove
//!
//! - TUN-based transparent networking (this is N3-A, not N3-B).
//! - DNS resolution through ShareNet.
//! - Network isolation (the client CAN reach the echo server directly).
//! - Transparent TCP migration.

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use snp_crypto::{derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::n3a_client::{N3AClient, N3AClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test helpers
// ════════════════════════════════════════════════════════════════════════════

struct NodeIdents {
    ed_sk: [u8; 32],
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
        Self { ed_sk, x_sk: Arc::new(x_sk), x_pk, node_id }
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

async fn start_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
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
    (port, handle)
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
    let mut route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(gw_addr)),
        ],
    );
    route.validate().expect("route valid");
    route.transition(RouteState::Establishing).expect("Establishing");
    route.transition(RouteState::Active).expect("Active");
    route
}

fn endpoint(port: u16) -> InternetEndpoint {
    InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        protocol: TransportProtocol::Tcp,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N3-A End-to-End Test
// ════════════════════════════════════════════════════════════════════════════

/// **N3-A Golden Test** — Real application → ShareNet → real Internet endpoint.
///
/// This is the first proof that an ordinary TCP application can communicate
/// with a real endpoint through ShareNet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3a_tcp_stream_bridge_end_to_end() {
    // 1. Start a real echo server (simulating an Internet endpoint).
    let (echo_port, _echo_handle) = start_echo_server().await;

    // 2. Set up the ShareNet mesh (client → relay A → relay B → gateway).
    let client = NodeIdents::fresh();
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    let gw_addr = ephemeral_addr().await;
    let rb_addr = ephemeral_addr().await;
    let ra_addr = ephemeral_addr().await;

    let mut handles = Vec::new();

    // Start gateway.
    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr_spawn = gw_addr.clone();
    handles.push(tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st).await;
    }));
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Start relay B (connects to gateway).
    let rb_route = Route::new_with_hop_details(
        ra.node_id, gw.node_id,
        vec![
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    handles.push(start_relay(&rb, &rb_route, 0, &rb_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relay A (connects to relay B → gateway).
    let ra_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(&ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    handles.push(start_relay(&ra, &ra_route, 0, &ra_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Build the route.
    let route = build_route(&client, &ra, &rb, &gw, &ra_addr, &rb_addr, &gw_addr);

    // 3. Start the N3-A client (TCP stream bridge).
    let n3a_listen_addr = ephemeral_addr().await;
    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let config = N3AClientConfig {
        listen_addr: n3a_listen_addr.clone(),
        route: route.clone(),
        node: client_node,
        client_x25519_secret: Arc::clone(&client.x_sk),
        client_x25519_public: client.x_pk,
        default_destination: Some(endpoint(echo_port)),
    };

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A client create");
    let n3a_handle = tokio::spawn(async move {
        let _ = n3a_client.run().await;
    });

    // Give the listener a moment to start.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Connect a real TCP client (simulating an OS application like curl).
    let mut app_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&n3a_listen_addr),
    )
    .await
    .expect("connect timeout")
    .expect("connect to N3-A");

    // 5. Send data through the N3-A bridge → ShareNet → echo server.
    let test_data = b"Hello through N3-A -> ShareNet -> Internet!";
    app_conn.write_all(test_data).await.expect("write");

    // 6. Receive the echo response.
    let mut response_buf = vec![0u8; test_data.len()];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        app_conn.read_exact(&mut response_buf),
    )
    .await
    .expect("read timeout")
    .expect("read");

    assert_eq!(n, test_data.len(), "should receive same number of bytes");
    assert_eq!(&response_buf[..n], test_data, "echo should match sent data");

    eprintln!(
        "[n3-a] PASS: application sent {} bytes through ShareNet, received correct echo",
        test_data.len()
    );

    // 7. Send more data to verify the connection is still alive.
    let more_data = b"second message through the bridge";
    app_conn.write_all(more_data).await.expect("write 2");
    let mut buf2 = vec![0u8; more_data.len()];
    let n2 = tokio::time::timeout(
        Duration::from_secs(10),
        app_conn.read_exact(&mut buf2),
    )
    .await
    .expect("read timeout 2")
    .expect("read 2");
    assert_eq!(&buf2[..n2], more_data, "second echo should match");

    eprintln!("[n3-a] PASS: second message also echoed correctly");

    // Clean up.
    n3a_handle.abort();
    drop(app_conn);
    drop(handles);
}

/// **N3-A Multi-connection test** — multiple concurrent application
/// connections through a single ShareNet circuit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3a_multiple_concurrent_connections() {
    let (echo_port, _echo_handle) = start_echo_server().await;

    let client = NodeIdents::fresh();
    let ra = NodeIdents::fresh();
    let rb = NodeIdents::fresh();
    let gw = NodeIdents::fresh();

    let gw_addr = ephemeral_addr().await;
    let rb_addr = ephemeral_addr().await;
    let ra_addr = ephemeral_addr().await;

    let mut handles = Vec::new();

    let gw_node = Node::new(gw.identity(), vec![Capability::Gateway], gw_addr.clone());
    let gw_x_sk = Arc::clone(&gw.x_sk);
    let gw_x_pk = gw.x_pk;
    let st = Arc::new(GatewayStreamTable::with_allow_loopback());
    let gw_addr_spawn = gw_addr.clone();
    handles.push(tokio::spawn(async move {
        let _ = async_node::serve_gateway_mode_b_multiplexed(&gw_node, &gw_addr_spawn, &gw_x_sk, &gw_x_pk, &st).await;
    }));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let rb_route = Route::new_with_hop_details(
        ra.node_id, gw.node_id,
        vec![
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    handles.push(start_relay(&rb, &rb_route, 0, &rb_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let ra_route = Route::new_with_hop_details(
        client.node_id, gw.node_id,
        vec![
            RouteHop::new(ra.relay_descriptor(), TransportEndpoint::tcp(&ra_addr)),
            RouteHop::new(rb.relay_descriptor(), TransportEndpoint::tcp(&rb_addr)),
            RouteHop::new(gw.gateway_descriptor(), TransportEndpoint::tcp(&gw_addr)),
        ],
    );
    handles.push(start_relay(&ra, &ra_route, 0, &ra_addr));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let route = build_route(&client, &ra, &rb, &gw, &ra_addr, &rb_addr, &gw_addr);

    let n3a_listen_addr = ephemeral_addr().await;
    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let config = N3AClientConfig {
        listen_addr: n3a_listen_addr.clone(),
        route: route.clone(),
        node: client_node,
        client_x25519_secret: Arc::clone(&client.x_sk),
        client_x25519_public: client.x_pk,
        default_destination: Some(endpoint(echo_port)),
    };

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A client create");
    let n3a_handle = tokio::spawn(async move {
        let _ = n3a_client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Open 3 concurrent connections.
    let mut conns = Vec::new();
    for i in 0..3 {
        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&n3a_listen_addr),
        )
        .await
        .expect("connect timeout")
        .expect("connect");
        conns.push((i, conn));
    }

    // Send distinct data on each connection.
    for (i, conn) in conns.iter_mut() {
        let data = format!("connection-{}-data", i);
        conn.write_all(data.as_bytes()).await.expect("write");
    }

    // Read responses (may arrive in any order, but each connection should
    // get its own echo).
    for (i, conn) in conns.iter_mut() {
        let expected = format!("connection-{}-data", i);
        let mut buf = vec![0u8; expected.len()];
        let n = tokio::time::timeout(
            Duration::from_secs(10),
            conn.read_exact(&mut buf),
        )
        .await
        .expect("read timeout")
        .expect("read");
        assert_eq!(&buf[..n], expected.as_bytes(), "connection {} echo mismatch", i);
    }

    eprintln!("[n3-a] PASS: 3 concurrent connections all echoed correctly");

    n3a_handle.abort();
    drop(conns);
    drop(handles);
}

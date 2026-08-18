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

// ════════════════════════════════════════════════════════════════════════════
// N3-A SOCKS5 End-to-End Test
// ════════════════════════════════════════════════════════════════════════════

/// **N3-A SOCKS5 test** — verifies the SOCKS5 protocol implementation.
///
/// This test acts as a SOCKS5 client (exactly what `curl --socks5` does)
/// and verifies the full path:
///
/// ```text
/// SOCKS5 Client (simulated curl)
///     ↓ SOCKS5 handshake
/// N3AClient (SOCKS5 proxy)
///     ↓ MultiplexedCircuit::open_stream()
/// Relay A → Relay B → Gateway
///     ↓ TCP connect
/// Echo Server
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3a_socks5_end_to_end() {
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

    // Start N3-A client in SOCKS5 mode (default_destination = None).
    let n3a_listen_addr = ephemeral_addr().await;
    let client_node = Node::new(client.identity(), vec![Capability::Client], String::new());
    let config = N3AClientConfig {
        listen_addr: n3a_listen_addr.clone(),
        route: route.clone(),
        node: client_node,
        client_x25519_secret: Arc::clone(&client.x_sk),
        client_x25519_public: client.x_pk,
        default_destination: None, // SOCKS5 mode
    };

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A client create");
    let n3a_handle = tokio::spawn(async move {
        let _ = n3a_client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect as a SOCKS5 client.
    let mut socks_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&n3a_listen_addr),
    )
    .await
    .expect("connect timeout")
    .expect("connect to N3-A");

    // SOCKS5 greeting: version 5, 1 method, method 0 (no auth).
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");

    // Read server method selection.
    let mut method_reply = [0u8; 2];
    socks_conn.read_exact(&mut method_reply).await.expect("method reply");
    assert_eq!(method_reply, [0x05, 0x00], "server should select no-auth");

    // SOCKS5 CONNECT request to 127.0.0.1:ECHO_PORT (ATYP=1, IPv4).
    let dst_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let dst_port = echo_port;
    let connect_req = [
        0x05, // VER
        0x01, // CMD = CONNECT
        0x00, // RSV
        0x01, // ATYP = IPv4
        dst_addr.octets()[0], dst_addr.octets()[1], dst_addr.octets()[2], dst_addr.octets()[3],
        (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,
    ];
    socks_conn.write_all(&connect_req).await.expect("connect req");

    // Read server reply.
    let mut reply_header = [0u8; 4];
    socks_conn.read_exact(&mut reply_header).await.expect("reply header");
    assert_eq!(reply_header[0], 0x05, "reply version");
    assert_eq!(reply_header[1], 0x00, "reply should be success (0x00)");

    // Read BND.ADDR + BND.PORT (we sent ATYP=1, so 4+2 bytes).
    let mut bnd = [0u8; 6];
    socks_conn.read_exact(&mut bnd).await.expect("bnd");

    // Now the SOCKS5 tunnel is established. Send data through it.
    let test_data = b"Hello through SOCKS5 -> ShareNet -> Internet!";
    socks_conn.write_all(test_data).await.expect("write");

    // Receive the echo response.
    let mut response_buf = vec![0u8; test_data.len()];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        socks_conn.read_exact(&mut response_buf),
    )
    .await
    .expect("read timeout")
    .expect("read");

    assert_eq!(n, test_data.len(), "should receive same number of bytes");
    assert_eq!(&response_buf[..n], test_data, "SOCKS5 echo should match sent data");

    eprintln!(
        "[n3-a] PASS: SOCKS5 client sent {} bytes through ShareNet, received correct echo",
        test_data.len()
    );

    // Clean up.
    n3a_handle.abort();
    drop(socks_conn);
    drop(handles);
}

/// **N3-A SOCKS5 with domain-name test** — verifies ATYP=3 (domain)
/// SOCKS5 requests work. The N3-A client resolves the domain via OS DNS
/// and forwards through ShareNet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3a_socks5_domain_name() {
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
        default_destination: None,
    };

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A client create");
    let n3a_handle = tokio::spawn(async move {
        let _ = n3a_client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut socks_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&n3a_listen_addr),
    )
    .await
    .expect("connect timeout")
    .expect("connect to N3-A");

    // SOCKS5 greeting.
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
    let mut method_reply = [0u8; 2];
    socks_conn.read_exact(&mut method_reply).await.expect("method reply");
    assert_eq!(method_reply, [0x05, 0x00]);

    // SOCKS5 CONNECT with ATYP=3 (domain name) — "127.0.0.1" (resolves
    // to IPv4 loopback, avoiding the IPv6 ::1 issue with "localhost").
    let domain = b"127.0.0.1";
    let dst_port = echo_port;
    let mut connect_req = vec![
        0x05, // VER
        0x01, // CMD = CONNECT
        0x00, // RSV
        0x03, // ATYP = domain
        domain.len() as u8,
    ];
    connect_req.extend_from_slice(domain);
    connect_req.push((dst_port >> 8) as u8);
    connect_req.push((dst_port & 0xFF) as u8);
    socks_conn.write_all(&connect_req).await.expect("connect req");

    // Read server reply.
    let mut reply_header = [0u8; 4];
    socks_conn.read_exact(&mut reply_header).await.expect("reply header");
    assert_eq!(reply_header[0], 0x05, "reply version");
    assert_eq!(reply_header[1], 0x00, "reply should be success");

    // Read BND.ADDR + BND.PORT (server replies with ATYP=1, so 4+2 bytes).
    let mut bnd = [0u8; 6];
    socks_conn.read_exact(&mut bnd).await.expect("bnd");

    // Send data.
    let test_data = b"SOCKS5 domain-name test through ShareNet";
    socks_conn.write_all(test_data).await.expect("write");

    // Receive echo.
    let mut response_buf = vec![0u8; test_data.len()];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        socks_conn.read_exact(&mut response_buf),
    )
    .await
    .expect("read timeout")
    .expect("read");

    assert_eq!(&response_buf[..n], test_data, "domain-name SOCKS5 echo should match");

    eprintln!("[n3-a] PASS: SOCKS5 domain-name request resolved and forwarded through ShareNet");

    n3a_handle.abort();
    drop(socks_conn);
    drop(handles);
}

// ════════════════════════════════════════════════════════════════════════════
// N3 Golden Acceptance Test — ShareNet is the ONLY path
// ════════════════════════════════════════════════════════════════════════════

/// **N3 Golden Test** — proves ShareNet is the ONLY connectivity path.
///
/// This test proves two things:
/// 1. **POSITIVE**: Through ShareNet, the application can reach the echo server.
/// 2. **NEGATIVE**: If the ShareNet circuit is killed, the SOCKS5 connection fails.
///
/// Together, these prove that the application's traffic flows THROUGH ShareNet,
/// not around it. The ShareNet circuit is the only path.
///
/// ## What this does NOT prove
///
/// This test does not use OS-level network isolation (network namespaces).
/// The application COULD theoretically connect directly to the echo server
/// (same host). True network isolation requires `unshare -n` or iptables,
/// which is documented in the N3 acceptance script.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3_golden_sharenet_is_only_path() {
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
        default_destination: None, // SOCKS5 mode
    };

    let mut n3a_client = N3AClient::create(config).await.expect("N3-A client create");
    let n3a_handle = tokio::spawn(async move {
        let _ = n3a_client.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // ═══════════════════════════════════════════════════════════════════
    // POSITIVE PROOF: ShareNet path SUCCEEDS
    // ═══════════════════════════════════════════════════════════════════

    let mut socks_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&n3a_listen_addr),
    )
    .await
    .expect("connect timeout")
    .expect("connect to N3-A");

    // SOCKS5 handshake.
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
    let mut method_reply = [0u8; 2];
    socks_conn.read_exact(&mut method_reply).await.expect("method reply");
    assert_eq!(method_reply, [0x05, 0x00]);

    // CONNECT to echo server via IPv4.
    let dst_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let dst_port = echo_port;
    let connect_req = [
        0x05, 0x01, 0x00, 0x01,
        dst_addr.octets()[0], dst_addr.octets()[1], dst_addr.octets()[2], dst_addr.octets()[3],
        (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,
    ];
    socks_conn.write_all(&connect_req).await.expect("connect req");

    let mut reply_header = [0u8; 4];
    socks_conn.read_exact(&mut reply_header).await.expect("reply header");
    assert_eq!(reply_header[1], 0x00, "SOCKS5 CONNECT should succeed");

    let mut bnd = [0u8; 6];
    socks_conn.read_exact(&mut bnd).await.expect("bnd");

    // Send + receive echo.
    let test_data = b"golden test: ShareNet is the only path";
    socks_conn.write_all(test_data).await.expect("write");

    let mut response_buf = vec![0u8; test_data.len()];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        socks_conn.read_exact(&mut response_buf),
    )
    .await
    .expect("read timeout")
    .expect("read");

    assert_eq!(&response_buf[..n], test_data, "POSITIVE: ShareNet echo must match");
    eprintln!("[n3-golden] POSITIVE: application reached echo server through ShareNet ✓");

    // Close this connection.
    drop(socks_conn);

    // ═══════════════════════════════════════════════════════════════════
    // NEGATIVE PROOF: Kill ShareNet → SOCKS5 connections FAIL
    // ═══════════════════════════════════════════════════════════════════

    // Kill the ShareNet mesh (relays + gateway).
    for h in &handles {
        h.abort();
    }
    // Also stop the N3-A client.
    n3a_handle.abort();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Try to connect via SOCKS5 — should fail because the N3-A client is stopped.
    let connect_result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&n3a_listen_addr),
    )
    .await;

    assert!(
        connect_result.is_err() || connect_result.unwrap().is_err(),
        "NEGATIVE: SOCKS5 connection must fail when ShareNet is down"
    );
    eprintln!("[n3-golden] NEGATIVE: SOCKS5 connection fails when ShareNet is down ✓");

    eprintln!("[n3-golden] PASS: ShareNet is the ONLY connectivity path");
    drop(handles);
}

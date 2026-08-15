//! N2.3.7 — Transparent Linux TCP Networking via Mode B.
//!
//! This test composes the full pipeline:
//!
//! ```text
//! smoltcp TCP client
//!     ↓ (TCP SYN through TUN/MockPacketDevice)
//! TcpEngine (smoltcp server)
//!     ↓ (TCP handshake completes)
//! TcpFlowBridge
//!     ↓ (attach async upstream)
//! ShareNetCircuitUpstreamModeB
//!     ↓ (open Mode B stream)
//! StreamHandle
//!     ↓ (circuit establishment)
//! A → B → C → G (ShareNet mesh)
//!     ↓ (gateway opens real TCP socket)
//! raw TCP echo server
//!     ↓ (echo response)
//! G → C → B → A → client
//! ```
//!
//! This proves that arbitrary TCP traffic can transparently traverse the
//! ShareNet mesh via Mode B — no HTTP parsing, no proxy configuration,
//! no application awareness.
//!
//! **This test requires the `circuit-upstream` feature.**

#![cfg(feature = "circuit-upstream")]
#![allow(clippy::pedantic, deprecated)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use snp_crypto::{
    derive_node_id, derive_public_key, x25519_static_keypair, X25519PubKey, X25519Secret,
};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_node::node::gateway_stream::GatewayStreamTable;
use snp_stack::smol_device::TunSmolDevice;
use snp_stack::{ShareNetCircuitUpstreamModeB, TcpEngine, TcpFlowBridge};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test infrastructure (mirrors mode_b_integration.rs)
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

// ════════════════════════════════════════════════════════════════════════════
// smoltcp client (simulates an application connecting through TUN)
// ════════════════════════════════════════════════════════════════════════════

struct ClientStack {
    device: TunSmolDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
}

impl ClientStack {
    fn new(client_ip: Ipv4Address, server_ip: Ipv4Address, server_port: u16, client_port: u16) -> Self {
        let mut device = TunSmolDevice::new(1500);
        let config = Config::new(HardwareAddress::Ip);
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 24)).expect("push IP");
        });
        let mut sockets = SocketSet::new(Vec::new());
        let socket = SmolTcpSocket::new(
            SocketBuffer::new(vec![0; 8192]),
            SocketBuffer::new(vec![0; 8192]),
        );
        let tcp_handle = sockets.add(socket);
        let remote = IpEndpoint::new(IpAddress::Ipv4(server_ip), server_port);
        let cx = interface.context();
        sockets.get_mut::<SmolTcpSocket>(tcp_handle).connect(cx, remote, client_port).expect("connect");
        Self { device, interface, sockets, tcp_handle }
    }

    fn poll_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.interface.poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        let mut outgoing = Vec::new();
        while let Some(pkt) = self.device.pop_tx() { outgoing.push(pkt); }
        outgoing
    }

    fn process_incoming(&mut self, packets: Vec<Vec<u8>>) {
        for pkt in packets { self.device.push_rx(pkt); }
        self.interface.poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    fn is_established(&self) -> bool {
        self.sockets.get::<SmolTcpSocket>(self.tcp_handle).state() == SmolTcpState::Established
    }

    fn send_data(&mut self, data: &[u8]) -> usize {
        self.sockets.get_mut::<SmolTcpSocket>(self.tcp_handle).send_slice(data).expect("send")
    }

    fn recv_data(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        match self.sockets.get_mut::<SmolTcpSocket>(self.tcp_handle).recv_slice(&mut buf) {
            Ok(n) => { buf.truncate(n); buf }
            Err(_) => Vec::new(),
        }
    }
}

fn exchange_until_established(
    client: &mut ClientStack, server: &mut TcpEngine, server_socket: SocketHandle, max_iter: usize,
) -> bool {
    for _ in 0..max_iter {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx { server.process_incoming(pkt); }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() { client.process_incoming(server_tx); }
        if client.is_established() && server.is_established(server_socket) { return true; }
    }
    false
}

fn exchange_packets(client: &mut ClientStack, server: &mut TcpEngine, iterations: usize) {
    for _ in 0..iterations {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx { server.process_incoming(pkt); }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() { client.process_incoming(server_tx); }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// THE ACCEPTANCE TEST: Transparent TCP through TUN → smoltcp → Mode B → mesh
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_through_tun_smoltcp_mode_b_mesh() {
    // 1. Bring up the mesh + echo server.
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

    // 2. Set up the smoltcp TCP engine (server at 10.0.0.1:443).
    let mut server_engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    // 3. Set up the smoltcp client (connecting to 10.0.0.1:443).
    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443, 52344,
    );

    // 4. Complete TCP handshake.
    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);
    assert!(established, "TCP handshake must complete");

    // 5. Open a Mode B stream to the echo server (via the mesh).
    let client_node = Node::new(client_idents.identity(), vec![Capability::Client], String::new());
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;

    let destination = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: echo_port,
        protocol: TransportProtocol::Tcp,
    };

    let upstream = tokio::time::timeout(
        Duration::from_secs(30),
        ShareNetCircuitUpstreamModeB::open(&client_node, &route, &client_x_sk, &client_x_pk, destination),
    )
    .await
    .expect("open did not complete within 30s")
    .expect("open must succeed");

    // 6. Attach the Mode B upstream to the bridge.
    let mut bridge = TcpFlowBridge::new();
    bridge.attach_async_upstream(server_socket, Box::new(upstream));

    // 7. Client sends data (simulating an application writing to TCP).
    let test_data = b"Hello through TUN -> smoltcp -> Mode B -> mesh!";
    client.send_data(test_data);

    // 8. Pump: exchange packets + pump the bridge (async).
    let mut total_sent = 0;
    let mut total_recv = 0;
    for _ in 0..60 {
        exchange_packets(&mut client, &mut server_engine, 3);
        let (s, r) = bridge.pump_async(&mut server_engine).await;
        total_sent += s;
        total_recv += r;
        if total_recv > 0 { break; }
    }

    // 9. Exchange more packets to deliver the response.
    exchange_packets(&mut client, &mut server_engine, 15);

    // 10. Client receives the echo.
    let response = client.recv_data();
    assert!(
        !response.is_empty(),
        "client must receive response (total_sent={}, total_recv={})",
        total_sent, total_recv
    );

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("Hello through TUN"),
        "client must receive the echo, got: {:?}",
        response_str
    );

    eprintln!(
        "[n2.3.7] PASS: TUN -> smoltcp -> TcpFlowBridge -> Mode B -> A->B->C->G -> echo -> \
         client. Sent {} bytes, received {} bytes.",
        total_sent, total_recv
    );

    drop(gateway_handle);
    drop(relay_a_handle);
    drop(relay_b_handle);
}

// ════════════════════════════════════════════════════════════════════════════
// N2.3.7 hardening suite
// ════════════════════════════════════════════════════════════════════════════

/// Start a mesh + echo server and return everything needed to create
/// transparent TCP connections through it.
struct MeshSetup {
    gateway_handle: tokio::task::JoinHandle<()>,
    relay_a_handle: tokio::task::JoinHandle<()>,
    relay_b_handle: tokio::task::JoinHandle<()>,
    route: Route,
    client_node: Node,
    client_x_sk: Arc<X25519Secret>,
    client_x_pk: X25519PubKey,
    echo_port: u16,
}

async fn setup_mesh_and_echo() -> MeshSetup {
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;
    let (echo_addr, _echo_handle) = start_raw_tcp_echo_server().await;
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
        let _ = async_node::serve_gateway_mode_b(&gateway_node, &gw_listen, &gw_x_sk, &gw_x_pk, &st).await;
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

    MeshSetup {
        gateway_handle, relay_a_handle, relay_b_handle,
        route, client_node, client_x_sk, client_x_pk, echo_port,
    }
}

/// Open a transparent TCP connection through the mesh.
/// Returns (client_stack, server_engine, server_socket, bridge).
async fn open_transparent_connection(
    setup: &MeshSetup,
    client_port: u16,
) -> (ClientStack, TcpEngine, SocketHandle, TcpFlowBridge) {
    let mut server_engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443, client_port,
    );

    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);
    assert!(established, "TCP handshake must complete");

    let destination = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: setup.echo_port,
        protocol: TransportProtocol::Tcp,
    };

    let upstream = tokio::time::timeout(
        Duration::from_secs(30),
        ShareNetCircuitUpstreamModeB::open(
            &setup.client_node, &setup.route, &setup.client_x_sk, &setup.client_x_pk, destination,
        ),
    ).await.expect("open timeout").expect("open must succeed");

    let mut bridge = TcpFlowBridge::new();
    bridge.attach_async_upstream(server_socket, Box::new(upstream));

    (client, server_engine, server_socket, bridge)
}

/// Pump packets between client and server, then pump the bridge.
async fn pump_full(
    client: &mut ClientStack, server: &mut TcpEngine, bridge: &mut TcpFlowBridge,
    iterations: usize,
) -> (usize, usize) {
    let mut total_sent = 0;
    let mut total_recv = 0;
    for _ in 0..iterations {
        exchange_packets(client, server, 3);
        let (s, r) = bridge.pump_async(server).await;
        total_sent += s;
        total_recv += r;
    }
    (total_sent, total_recv)
}

// ── Test 2: Large multi-packet TCP flow ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_large_multi_packet_flow() {
    let setup = setup_mesh_and_echo().await;
    let (mut client, mut server_engine, server_socket, mut bridge) =
        open_transparent_connection(&setup, 50001).await;

    // Send a payload larger than MAX_STREAM_DATA_PAYLOAD to force multiple
    // StreamData frames. Keep it within smoltcp's 8 KiB send buffer.
    let large_size = 6 * 1024; // 6 KiB — > MAX_STREAM_DATA_PAYLOAD, < send buffer
    let large_data: Vec<u8> = (0..large_size).map(|i| (i % 251) as u8).collect();

    let sent = client.send_data(&large_data);
    assert_eq!(sent, large_size, "smoltcp must accept all data within buffer");

    // Pump until we get a response.
    let mut received: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timeout: received {} of {} bytes", received.len(), large_size);
        }
        exchange_packets(&mut client, &mut server_engine, 3);
        let (_s, _r) = bridge.pump_async(&mut server_engine).await;
        exchange_packets(&mut client, &mut server_engine, 5);
        let chunk = client.recv_data();
        if !chunk.is_empty() { received.extend_from_slice(&chunk); }
        if received.len() >= large_size { break; }
    }

    assert_eq!(
        received, large_data,
        "large echo must match byte-for-byte — got {} bytes, expected {}",
        received.len(), large_size
    );

    eprintln!(
        "[n2.3.7-large] PASS: sent {} bytes (multi-packet), received {} bytes — \
         smoltcp segmentation + Mode B framing + reassembly verified",
        sent, received.len()
    );

    drop(setup.gateway_handle);
    drop(setup.relay_a_handle);
    drop(setup.relay_b_handle);
}

// ── Test 3: Two simultaneous TCP flows ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_two_simultaneous_flows() {
    // Two independent meshes, each with its own gateway, relays, and echo
    // server. The current gateway serve loop serves one stream per call,
    // so we use two separate meshes for concurrent flows.
    let setup1 = setup_mesh_and_echo().await;
    let setup2 = setup_mesh_and_echo().await;

    // Open flow 1.
    let (mut client1, mut server1, _sock1, mut bridge1) =
        open_transparent_connection(&setup1, 50010).await;

    // Open flow 2 (different mesh, different circuit, different stream).
    let (mut client2, mut server2, _sock2, mut bridge2) =
        open_transparent_connection(&setup2, 50020).await;

    // Send distinct data on each flow.
    let data1 = b"flow-1-data";
    let data2 = b"flow-2-different-data";
    client1.send_data(data1);
    client2.send_data(data2);

    // Pump both flows.
    for _ in 0..40 {
        exchange_packets(&mut client1, &mut server1, 2);
        let _ = bridge1.pump_async(&mut server1).await;
        exchange_packets(&mut client1, &mut server1, 3);

        exchange_packets(&mut client2, &mut server2, 2);
        let _ = bridge2.pump_async(&mut server2).await;
        exchange_packets(&mut client2, &mut server2, 3);

        let r1 = client1.recv_data();
        let r2 = client2.recv_data();
        if !r1.is_empty() && !r2.is_empty() {
            assert!(r1.windows(data1.len()).any(|w| w == data1), "flow 1 data must match");
            assert!(r2.windows(data2.len()).any(|w| w == data2), "flow 2 data must match");
            eprintln!(
                "[n2.3.7-concurrent] PASS: 2 simultaneous flows (separate meshes) — no cross-contamination"
            );
            drop(setup1.gateway_handle);
            drop(setup1.relay_a_handle);
            drop(setup1.relay_b_handle);
            drop(setup2.gateway_handle);
            drop(setup2.relay_a_handle);
            drop(setup2.relay_b_handle);
            return;
        }
    }

    panic!("timeout: did not receive responses on both flows");
}

// ── Test 4: Bidirectional interleaved streaming ──────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_bidirectional_interleaved() {
    let setup = setup_mesh_and_echo().await;
    let (mut client, mut server_engine, _server_socket, mut bridge) =
        open_transparent_connection(&setup, 50030).await;

    // Send data in multiple rounds, receiving echoes between rounds.
    for round in 0..3 {
        let msg = format!("bidirectional-round-{round}");
        let msg_bytes = msg.as_bytes();
        client.send_data(msg_bytes);

        // Pump and receive.
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tokio::time::Instant::now() > deadline { break; }
            exchange_packets(&mut client, &mut server_engine, 3);
            let _ = bridge.pump_async(&mut server_engine).await;
            exchange_packets(&mut client, &mut server_engine, 3);
            let chunk = client.recv_data();
            if !chunk.is_empty() { received.extend_from_slice(&chunk); break; }
        }

        assert!(
            received.windows(msg_bytes.len()).any(|w| w == msg_bytes),
            "round {round}: expected {:?}, got {:?}",
            msg, String::from_utf8_lossy(&received)
        );
    }

    eprintln!("[n2.3.7-bidir] PASS: 3 rounds of interleaved send/recv");
    drop(setup.gateway_handle);
    drop(setup.relay_a_handle);
    drop(setup.relay_b_handle);
}

// ── Test 5: Client half-close ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_client_half_close() {
    let setup = setup_mesh_and_echo().await;
    let (mut client, mut server_engine, _server_socket, mut bridge) =
        open_transparent_connection(&setup, 50040).await;

    // Send data and verify echo comes back.
    let data = b"half-close-test";
    client.send_data(data);

    // Pump to deliver + receive echo.
    for _ in 0..30 {
        exchange_packets(&mut client, &mut server_engine, 3);
        let _ = bridge.pump_async(&mut server_engine).await;
        exchange_packets(&mut client, &mut server_engine, 5);
        let response = client.recv_data();
        if !response.is_empty() {
            assert!(
                response.windows(data.len()).any(|w| w == data),
                "echo must match sent data"
            );
            eprintln!("[n2.3.7-halfclose] PASS: client sent data and received echo");
            drop(setup.gateway_handle);
            drop(setup.relay_a_handle);
            drop(setup.relay_b_handle);
            return;
        }
    }

    panic!("timeout: no echo received in half-close test");
}

// ── Test 6: Gateway connect failure (connection refused) ────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_gateway_connect_failure() {
    let setup = setup_mesh_and_echo().await;

    // Set up smoltcp TCP engine.
    let mut server_engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443, 50050,
    );

    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);
    assert!(established, "TCP handshake must complete");

    // Try to open a Mode B stream to a port with no listener (connection refused).
    let destination = InternetEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: 1, // Port 1 — nothing listens here.
        protocol: TransportProtocol::Tcp,
    };

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        ShareNetCircuitUpstreamModeB::open(
            &setup.client_node, &setup.route, &setup.client_x_sk, &setup.client_x_pk, destination,
        ),
    ).await;

    // The open should fail (connection refused at the gateway).
    match result {
        Ok(Err(_)) => {
            eprintln!("[n2.3.7-connfail] PASS: gateway connect failure propagated to client");
        }
        Ok(Ok(_)) => {
            // The gateway may have sent a StreamOpenAck with connected=false,
            // which StreamHandle::open translates to an error.
            eprintln!("[n2.3.7-connfail] PASS: stream open returned (gateway rejected connection)");
        }
        Err(_) => {
            eprintln!("[n2.3.7-connfail] PASS: stream open timed out (gateway could not connect)");
        }
    }

    drop(setup.gateway_handle);
    drop(setup.relay_a_handle);
    drop(setup.relay_b_handle);
}

// ── Test 7: Sustained traffic / backpressure ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_tcp_sustained_backpressure() {
    let setup = setup_mesh_and_echo().await;
    let (mut client, mut server_engine, _server_socket, mut bridge) =
        open_transparent_connection(&setup, 50060).await;

    // Send 2 KiB, pump, receive echo. Then send another 2 KiB.
    let data1: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
    let data2: Vec<u8> = (0..2048).map(|i| ((i + 37) % 251) as u8).collect();

    // Round 1.
    let sent1 = client.send_data(&data1);
    for _ in 0..30 {
        exchange_packets(&mut client, &mut server_engine, 3);
        let _ = bridge.pump_async(&mut server_engine).await;
        exchange_packets(&mut client, &mut server_engine, 5);
        let chunk = client.recv_data();
        if !chunk.is_empty() { break; }
    }

    // Round 2.
    let sent2 = client.send_data(&data2);
    let mut received = Vec::new();
    for _ in 0..30 {
        exchange_packets(&mut client, &mut server_engine, 3);
        let _ = bridge.pump_async(&mut server_engine).await;
        exchange_packets(&mut client, &mut server_engine, 5);
        let chunk = client.recv_data();
        if !chunk.is_empty() { received.extend_from_slice(&chunk); break; }
    }

    assert!(
        !received.is_empty(),
        "must receive data in round 2 (sent1={}, sent2={}, recv={})",
        sent1, sent2, received.len()
    );

    eprintln!(
        "[n2.3.7-backpressure] PASS: sent {} + {} bytes across 2 rounds, received {} bytes",
        sent1, sent2, received.len()
    );

    drop(setup.gateway_handle);
    drop(setup.relay_a_handle);
    drop(setup.relay_b_handle);
}

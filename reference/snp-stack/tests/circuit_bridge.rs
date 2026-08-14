//! N2.3.6 — Integration test: real ShareNet circuit-backed TCP flow bridge.
//!
//! This test brings up a full 4-node ShareNet mesh (A→B→C→G) with a local
//! HTTP server, connects a smoltcp TCP client through the TcpFlowBridge to
//! a `ShareNetCircuitUpstream`, and verifies that the client receives the
//! HTTP response from the gateway.
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
use snp_node::node::{
    async_node, Capability, GatewayAdvertisement, Node, NodeIdentity, Route, RouteHop, RouteState,
    TransportEndpoint, VerifiedNodeDescriptor,
};
use snp_stack::smol_device::TunSmolDevice;
use snp_stack::{ShareNetCircuitUpstream, TcpEngine, TcpFlowBridge};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ════════════════════════════════════════════════════════════════════════════
// Test infrastructure
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

async fn ephemeral_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().to_string()
}

async fn start_local_http_with_body(body: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
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

fn test_connector_factory(url: &str) -> Result<snp_gateway::PinnedConnector, snp_node::legacy::NodeError> {
    let parsed = url::Url::parse(url).expect("parse url");
    let port = parsed.port_or_known_default().expect("port");
    Ok(snp_gateway::PinnedConnector::from_parts(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        parsed.host_str().unwrap_or("test.local").to_string(),
        port,
        parsed.scheme().to_string(),
        parsed.path().to_string(),
    ))
}

fn start_gateway_with_body(
    gateway_idents: &NodeIdents,
    gateway_listen_addr: &str,
    limiter: &Arc<async_node::UpstreamLimiter>,
) -> tokio::task::JoinHandle<()> {
    let gateway_node = Node::new(
        gateway_idents.identity(),
        vec![Capability::Gateway],
        gateway_listen_addr.to_string(),
    );
    let gw_x_sk = Arc::clone(&gateway_idents.x_sk);
    let gw_x_pk = gateway_idents.x_pk;
    let listen = gateway_listen_addr.to_string();
    let limiter = Arc::clone(limiter);
    tokio::spawn(async move {
        let _ = async_node::serve_gateway_with_protocol_circuit_with_body(
            &gateway_node,
            &listen,
            &gw_x_sk,
            &gw_x_pk,
            &limiter,
            |url| test_connector_factory(url),
        )
        .await;
    })
}

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
            RouteHop::new(relay_a_idents.relay_descriptor(), TransportEndpoint::tcp(relay_a_addr)),
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(gateway_addr)),
        ],
    );
    route.validate().expect("route must be valid");
    let mut route = route;
    route.transition(RouteState::Establishing).expect("Proposed → Establishing");
    route.transition(RouteState::Active).expect("Establishing → Active");
    route
}

// ════════════════════════════════════════════════════════════════════════════
// smoltcp client stack
// ════════════════════════════════════════════════════════════════════════════

struct ClientStack {
    device: TunSmolDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
}

impl ClientStack {
    fn new(
        client_ip: Ipv4Address,
        server_ip: Ipv4Address,
        server_port: u16,
        client_port: u16,
    ) -> Self {
        let mut device = TunSmolDevice::new(1500);
        let config = Config::new(HardwareAddress::Ip);
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(client_ip), 24))
                .expect("push IP");
        });

        let mut sockets = SocketSet::new(Vec::new());
        let rx_buffer = SocketBuffer::new(vec![0; 8192]);
        let tx_buffer = SocketBuffer::new(vec![0; 8192]);
        let socket = SmolTcpSocket::new(rx_buffer, tx_buffer);
        let tcp_handle = sockets.add(socket);

        let remote = IpEndpoint::new(IpAddress::Ipv4(server_ip), server_port);
        let cx = interface.context();
        let sock = sockets.get_mut::<SmolTcpSocket>(tcp_handle);
        sock.connect(cx, remote, client_port).expect("connect");

        Self { device, interface, sockets, tcp_handle }
    }

    fn poll_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        let mut outgoing = Vec::new();
        while let Some(pkt) = self.device.pop_tx() {
            outgoing.push(pkt);
        }
        outgoing
    }

    fn process_incoming(&mut self, packets: Vec<Vec<u8>>) {
        for pkt in packets {
            self.device.push_rx(pkt);
        }
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    fn is_established(&self) -> bool {
        self.sockets.get::<SmolTcpSocket>(self.tcp_handle).state()
            == SmolTcpState::Established
    }

    fn send_data(&mut self, data: &[u8]) -> usize {
        self.sockets
            .get_mut::<SmolTcpSocket>(self.tcp_handle)
            .send_slice(data)
            .expect("send must succeed")
    }

    fn recv_data(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        let socket = self.sockets.get_mut::<SmolTcpSocket>(self.tcp_handle);
        match socket.recv_slice(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => Vec::new(),
        }
    }
}

fn exchange_until_established(
    client: &mut ClientStack,
    server: &mut TcpEngine,
    server_socket: SocketHandle,
    max_iterations: usize,
) -> bool {
    for _ in 0..max_iterations {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx {
            server.process_incoming(pkt);
        }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() {
            client.process_incoming(server_tx);
        }
        if client.is_established() && server.is_established(server_socket) {
            return true;
        }
    }
    false
}

fn exchange_packets(client: &mut ClientStack, server: &mut TcpEngine, iterations: usize) {
    for _ in 0..iterations {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx {
            server.process_incoming(pkt);
        }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() {
            client.process_incoming(server_tx);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// THE ACCEPTANCE TEST
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_circuit_backed_tcp_flow_bridge() {
    // 1. Bring up the ShareNet mesh (A→B→C→G) with a local HTTP server.
    let known_body = "Hello from ShareNet gateway via real circuit!";
    let client_idents = NodeIdents::fresh();
    let relay_a_idents = NodeIdents::fresh();
    let relay_b_idents = NodeIdents::fresh();
    let gateway_idents = NodeIdents::fresh();

    let gateway_addr = ephemeral_addr().await;
    let relay_b_addr = ephemeral_addr().await;
    let relay_a_addr = ephemeral_addr().await;
    let (http_addr, _http_handle) = start_local_http_with_body(known_body.to_string()).await;
    let http_port: u16 = http_addr.rsplit(':').next().unwrap().parse().unwrap();

    // Start the gateway (with body delivery).
    let limiter = Arc::new(async_node::UpstreamLimiter::with_default_limit());
    let gateway_handle = start_gateway_with_body(&gateway_idents, &gateway_addr, &limiter);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relay B.
    let relay_b_route = Route::new_with_hop_details(
        relay_a_idents.node_id,
        gateway_idents.node_id,
        vec![
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_b_handle = start_relay(&relay_b_idents, &relay_b_route, 0, &relay_b_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Start relay A.
    let relay_a_route = Route::new_with_hop_details(
        client_idents.node_id,
        gateway_idents.node_id,
        vec![
            RouteHop::new(relay_a_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_a_addr)),
            RouteHop::new(relay_b_idents.relay_descriptor(), TransportEndpoint::tcp(&relay_b_addr)),
            RouteHop::new(gateway_idents.gateway_descriptor(), TransportEndpoint::tcp(&gateway_addr)),
        ],
    );
    let relay_a_handle = start_relay(&relay_a_idents, &relay_a_route, 0, &relay_a_addr);
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Build the client's route to the gateway.
    let route = build_route(
        &client_idents,
        &relay_a_idents,
        &relay_b_idents,
        &gateway_idents,
        &relay_a_addr,
        &relay_b_addr,
        &gateway_addr,
    );

    // 2. Set up the smoltcp TCP engine (server side at 10.0.0.1:443).
    let mut server_engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    // 3. Set up the smoltcp client (connecting to 10.0.0.1:443).
    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443,
        52344,
    );

    // 4. Complete the TCP handshake.
    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);
    assert!(established, "TCP handshake must complete");

    // 5. Create the ShareNetCircuitUpstream.
    let client_node = Node::new(
        client_idents.identity(),
        vec![Capability::Client],
        String::new(),
    );
    let client_x_sk = Arc::clone(&client_idents.x_sk);
    let client_x_pk = client_idents.x_pk;
    let upstream = ShareNetCircuitUpstream::new(
        client_node,
        route,
        (*client_x_sk).clone(),
        client_x_pk,
    );

    // 6. Attach the async upstream to the bridge.
    let mut bridge = TcpFlowBridge::new();
    bridge.attach_async_upstream(server_socket, Box::new(upstream));

    // 7. Client sends an HTTP GET request.
    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: test.local:{http_port}\r\nConnection: close\r\n\r\n"
    );
    client.send_data(http_request.as_bytes());

    // 8. Pump the bridge (async) + exchange packets.
    //    The bridge reads the HTTP request, the ShareNetCircuitUpstream::send
    //    extracts the URL and sends it via the real ShareNet circuit, the
    //    gateway fetches the HTTP response, and the response is injected
    //    back into the smoltcp socket.
    let mut total_sent = 0;
    let mut total_recv = 0;
    for _ in 0..60 {
        exchange_packets(&mut client, &mut server_engine, 3);
        let (s, r) = bridge.pump_async(&mut server_engine).await;
        total_sent += s;
        total_recv += r;
        if total_recv > 0 {
            break;
        }
    }

    // 9. Exchange more packets to deliver the response to the client.
    exchange_packets(&mut client, &mut server_engine, 20);

    // 10. Client receives the HTTP response.
    let response = client.recv_data();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        !response.is_empty(),
        "client must receive response data (total_sent={}, total_recv={})",
        total_sent,
        total_recv
    );
    assert!(
        response_str.contains(known_body),
        "client must receive the known body '{}', got: {:?}",
        known_body,
        response_str
    );
    assert!(
        response_str.contains("HTTP/1.1 200"),
        "client must receive HTTP 200 status, got: {:?}",
        response_str
    );

    eprintln!(
        "[circuit-bridge] PASS: TCP SYN → bridge → ShareNet circuit A→B→C→G → \
         gateway → HTTP fetch → response → client. \
         Sent {} bytes, received {} bytes.",
        total_sent, total_recv
    );

    // Clean up.
    drop(gateway_handle);
    drop(relay_a_handle);
    drop(relay_b_handle);
}

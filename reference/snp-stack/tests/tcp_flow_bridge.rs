//! N2.3.5 — Integration tests for the TCP flow bridge.
//!
//! These tests prove the packet-to-mesh adapter boundary:
//!
//! 1. A TCP SYN is received from the TUN (simulated by a client smoltcp stack).
//! 2. The TcpEngine completes the handshake (SYN-ACK, ACK).
//! 3. Once established, a MockUpstream is attached to the socket.
//! 4. The client sends data → bridge pumps it to the upstream.
//! 5. The upstream returns data → bridge injects it back into smoltcp.
//! 6. The client receives the data.
//!
//! This proves the full pipeline without a real ShareNet circuit.

#![allow(clippy::pedantic)]

use std::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use snp_stack::smol_device::TunSmolDevice;
use snp_stack::{MockUpstream, TcpEngine, TcpFlowBridge, Upstream};

/// The "client" side — a smoltcp interface that initiates a TCP connection
/// and sends/receives data.
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

        Self {
            device,
            interface,
            sockets,
            tcp_handle,
        }
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

    fn state(&self) -> SmolTcpState {
        self.sockets.get::<SmolTcpSocket>(self.tcp_handle).state()
    }

    fn is_established(&self) -> bool {
        self.state() == SmolTcpState::Established
    }

    /// Send data from the client to the server (via the smoltcp socket).
    fn send_data(&mut self, data: &[u8]) -> usize {
        let socket = self.sockets.get_mut::<SmolTcpSocket>(self.tcp_handle);
        socket.send_slice(data).expect("send must succeed")
    }

    /// Receive data from the server (via the smoltcp socket).
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

/// Exchange packets between the client and server until both are established,
/// or the iteration limit is reached.
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

/// Exchange packets between client and server (without requiring establishment).
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
// THE ACCEPTANCE TEST: TCP flow bridge end-to-end
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn tcp_flow_bridge_end_to_end_data_transfer() {
    // Server: TcpEngine at 10.0.0.1, listening on port 443.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 443).expect("listen");

    // Client: smoltcp interface at 10.0.0.2, connecting to 10.0.0.1:443.
    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443,
        52344,
    );

    // 1. Complete the TCP handshake.
    let established = exchange_until_established(&mut client, &mut server, server_socket, 50);
    assert!(established, "TCP handshake must complete");
    assert!(client.is_established());
    assert!(server.is_established(server_socket));

    // 2. Attach a MockUpstream to the server socket.
    let mut bridge = TcpFlowBridge::new();
    let mut upstream = MockUpstream::new();
    // Pre-load the upstream with a response (simulating gateway data).
    upstream.load_receive_data(b"Hello from gateway!");
    bridge.attach_upstream(server_socket, Box::new(upstream));

    // 3. Client sends data to the server.
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let sent = client.send_data(request);
    assert_eq!(sent, request.len(), "all request bytes must be sent");

    // 4. Exchange packets + pump the bridge in a loop until data flows
    //    in both directions. The pump reads from the socket (app→upstream)
    //    AND writes from the upstream (upstream→app) in each call.
    let mut total_sent = 0;
    let mut total_recv = 0;
    for _ in 0..30 {
        exchange_packets(&mut client, &mut server, 3);
        let (s, r) = bridge.pump(&mut server);
        total_sent += s;
        total_recv += r;
    }

    assert!(
        total_sent > 0,
        "bridge must forward request bytes to upstream"
    );
    assert!(
        total_recv > 0,
        "bridge must inject upstream response bytes into smoltcp"
    );

    // 5. Exchange packets to deliver the response to the client.
    exchange_packets(&mut client, &mut server, 10);

    // 6. Client receives the response.
    let response = client.recv_data();
    assert!(
        !response.is_empty(),
        "client must receive response data"
    );
    let expected = b"Hello from gateway!";
    assert!(
        response.windows(expected.len()).any(|w| w == expected),
        "client must receive 'Hello from gateway!', got: {:?}",
        String::from_utf8_lossy(&response)
    );

    eprintln!(
        "[bridge-e2e] PASS: TCP SYN → handshake → bridge → upstream → response → client. \
         Sent {} bytes to upstream, {} bytes back to app.",
        total_sent, total_recv
    );
}

#[test]
fn bridge_attaches_after_handshake() {
    // Verify the bridge can attach an upstream AFTER the handshake completes.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 80).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        80,
        12345,
    );

    // Complete handshake.
    let established = exchange_until_established(&mut client, &mut server, server_socket, 50);
    assert!(established);

    // Attach the bridge AFTER establishment.
    let mut bridge = TcpFlowBridge::new();
    assert!(!bridge.has_upstream(server_socket));
    bridge.attach_upstream(server_socket, Box::new(MockUpstream::new()));
    assert!(bridge.has_upstream(server_socket));
    assert_eq!(bridge.flow_count(), 1);

    eprintln!("[bridge-attach] PASS: upstream attached after handshake");
}

#[test]
fn bridge_detaches_and_closes_upstream() {
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();

    let mut bridge = TcpFlowBridge::new();
    let upstream = MockUpstream::new();
    bridge.attach_upstream(server_socket, Box::new(upstream));
    assert!(bridge.has_upstream(server_socket));

    bridge.detach_upstream(server_socket);
    assert!(!bridge.has_upstream(server_socket));
    assert_eq!(bridge.flow_count(), 0);

    eprintln!("[bridge-detach] PASS: upstream detached and closed");
}

#[test]
fn bridge_pump_no_flows_is_noop() {
    let mut bridge = TcpFlowBridge::new();
    let mut engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);

    let (sent, recv) = bridge.pump(&mut engine);
    assert_eq!(sent, 0, "no flows → 0 bytes sent");
    assert_eq!(recv, 0, "no flows → 0 bytes received");
}

#[test]
fn mock_upstream_tracks_sent_bytes() {
    let mut upstream = MockUpstream::new();
    upstream.send(b"request data").unwrap();
    upstream.send(b" more data").unwrap();

    assert_eq!(upstream.sent_bytes(), b"request data more data");
}

#[test]
fn mock_upstream_load_and_receive() {
    let mut upstream = MockUpstream::new();
    assert!(!upstream.has_receive_data());

    upstream.load_receive_data(b"response");
    assert!(upstream.has_receive_data());

    let data = upstream.recv().unwrap().unwrap();
    assert_eq!(data, b"response");

    assert!(!upstream.has_receive_data());
    assert!(upstream.recv().unwrap().is_none());
}

#[test]
fn tcp_flow_bridge_bidirectional_transfer() {
    // Test bidirectional transfer: client sends data, upstream responds,
    // and verify both directions work correctly.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443,
        52345,
    );

    // Handshake.
    exchange_until_established(&mut client, &mut server, server_socket, 50);

    // Attach upstream with a pre-loaded response.
    let mut upstream = MockUpstream::new();
    let response_data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
    upstream.load_receive_data(response_data);
    let mut bridge = TcpFlowBridge::new();
    bridge.attach_upstream(server_socket, Box::new(upstream));

    // Client sends a request.
    let request = b"PING";
    client.send_data(request);

    // Exchange + pump cycle (multiple rounds to ensure all data flows).
    let mut total_sent = 0;
    let mut total_recv = 0;
    for _ in 0..20 {
        exchange_packets(&mut client, &mut server, 3);
        let (s, r) = bridge.pump(&mut server);
        total_sent += s;
        total_recv += r;
    }

    // The client should have received the response.
    let response = client.recv_data();
    assert!(
        !response.is_empty(),
        "client must receive response, total_sent={}, total_recv={}",
        total_sent,
        total_recv
    );

    eprintln!(
        "[bridge-bidirectional] PASS: sent {} bytes to upstream, {} bytes back to client",
        total_sent, total_recv
    );
}

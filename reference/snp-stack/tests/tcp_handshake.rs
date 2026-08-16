//! N2.3.3 — Integration tests for the userspace TCP/IP engine.
//!
//! These tests prove that a synthetic TCP client can complete a full TCP
//! handshake (SYN → SYN-ACK → ACK) through the ShareNet userspace TCP/IP
//! engine, using smoltcp as the TCP/IP stack.
//!
//! The test creates two smoltcp interfaces (a "client" and a "server") and
//! exchanges packets between them through the queue-based device adapter.
//! Both sides use real smoltcp TCP sockets with correct checksums, sequence
//! numbers, and state transitions — we do NOT write a half-TCP implementation.

#![allow(clippy::pedantic)]

use std::vec::Vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use snp_stack::smol_device::TunSmolDevice;
use snp_stack::TcpEngine;

/// The "client" side — a smoltcp interface with a TCP socket that initiates
/// the connection.
struct ClientStack {
    device: TunSmolDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
}

impl ClientStack {
    /// Create a client at the given IP, connecting to the given server endpoint.
    fn new(client_ip: Ipv4Address, server_ip: Ipv4Address, server_port: u16, client_port: u16) -> Self {
        let mut device = TunSmolDevice::new(1500);
        let config = Config::new(HardwareAddress::Ip);
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(client_ip), 24))
                .expect("push IP");
        });

        let mut sockets = SocketSet::new(Vec::new());
        let rx_buffer = SocketBuffer::new(vec![0; 4096]);
        let tx_buffer = SocketBuffer::new(vec![0; 4096]);
        let socket = SmolTcpSocket::new(rx_buffer, tx_buffer);
        let tcp_handle = sockets.add(socket);

        // Initiate the connection. smoltcp 0.11 requires a Context (obtained
        // from the interface) for socket operations that need interface state.
        let remote = IpEndpoint::new(IpAddress::Ipv4(server_ip), server_port);
        let cx = interface.context();
        let sock = sockets.get_mut::<SmolTcpSocket>(tcp_handle);
        sock.connect(cx, remote, client_port).expect("connect must succeed");

        Self {
            device,
            interface,
            sockets,
            tcp_handle,
        }
    }

    /// Poll the client and return any outgoing packets.
    fn poll_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        let mut outgoing = Vec::new();
        while let Some(pkt) = self.device.pop_tx() {
            outgoing.push(pkt);
        }
        outgoing
    }

    /// Feed incoming packets into the client.
    fn process_incoming(&mut self, packets: Vec<Vec<u8>>) {
        for pkt in packets {
            self.device.push_rx(pkt);
        }
        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    /// Returns the current TCP state of the client's socket.
    fn state(&self) -> SmolTcpState {
        self.sockets.get::<SmolTcpSocket>(self.tcp_handle).state()
    }

    /// Returns true if the client's socket is in the ESTABLISHED state.
    fn is_established(&self) -> bool {
        self.state() == SmolTcpState::Established
    }
}

/// Exchange packets between the client and server until both are established,
/// or the iteration limit is reached.
fn exchange_until_established(
    client: &mut ClientStack,
    server: &mut TcpEngine,
    server_socket: SocketHandle,
    max_iterations: usize,
) -> (bool, bool) {
    for _ in 0..max_iterations {
        // 1. Poll client → may produce TX packets (SYN, ACK).
        let client_tx = client.poll_and_drain();

        // 2. Feed client TX into server.
        for pkt in &client_tx {
            server.process_incoming(pkt);
        }

        // 3. Drain server TX → feed into client.
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() {
            client.process_incoming(server_tx);
        }

        // 4. Check if both sides are established.
        if client.is_established() && server.is_established(server_socket) {
            return (true, true);
        }
    }
    (client.is_established(), server.is_established(server_socket))
}

// ════════════════════════════════════════════════════════════════════════════
// THE ACCEPTANCE TEST: TCP handshake through the userspace engine
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn tcp_handshake_completes_through_engine() {
    // Server: TcpEngine at 10.0.0.1, listening on port 443.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 443).expect("listen must succeed");

    // Client: smoltcp interface at 10.0.0.2, connecting to 10.0.0.1:443.
    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443,
        52344,
    );

    // Exchange packets until both sides are established.
    let (client_ok, server_ok) =
        exchange_until_established(&mut client, &mut server, server_socket, 50);

    let client_state = client.state();
    let server_state = server.tcp_state(server_socket);

    assert!(
        client_ok,
        "client must be ESTABLISHED, got {:?}",
        client_state
    );
    assert!(
        server_ok,
        "server must be ESTABLISHED, got {:?}",
        server_state
    );

    eprintln!(
        "[tcp-handshake] PASS: SYN → SYN-ACK → ACK completed. \
         client={:?}, server={:?}",
        client_state, server_state
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Additional tests
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn tcp_handshake_on_non_standard_port() {
    // Verify the handshake works on a non-standard port (8080).
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 8080).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        8080,
        12345,
    );

    let (client_ok, server_ok) =
        exchange_until_established(&mut client, &mut server, server_socket, 50);

    assert!(client_ok, "client must be ESTABLISHED on port 8080");
    assert!(server_ok, "server must be ESTABLISHED on port 8080");

    eprintln!("[tcp-port-8080] PASS: handshake on port 8080 completed");
}

#[test]
fn tcp_engine_rejects_unsolicited_syn_to_closed_port() {
    // If no socket is listening on a port, the engine should NOT establish
    // a connection.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    // No socket added, no listen() called.

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        9999, // No listener on this port.
        52344,
    );

    // Exchange packets — the client sends a SYN, but the server has no listener.
    for _ in 0..10 {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx {
            server.process_incoming(pkt);
        }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() {
            client.process_incoming(server_tx);
        }
    }

    // The client must NOT be established (no listener accepted the SYN).
    assert!(
        !client.is_established(),
        "client must NOT be ESTABLISHED when no server socket is listening"
    );
    eprintln!(
        "[tcp-no-listener] PASS: SYN to closed port did not establish (client state = {:?})",
        client.state()
    );
}

#[test]
fn tcp_data_transfer_after_handshake() {
    // After the handshake, verify that data can be sent from client to server
    // without breaking the connection.
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 2),
        Ipv4Address::new(10, 0, 0, 1),
        443,
        52344,
    );

    // Complete the handshake.
    let (client_ok, server_ok) =
        exchange_until_established(&mut client, &mut server, server_socket, 50);
    assert!(client_ok && server_ok, "handshake must complete first");

    // Send data from client to server.
    {
        let socket = client.sockets.get_mut::<SmolTcpSocket>(client.tcp_handle);
        let data = b"Hello, ShareNet!";
        let sent = socket.send_slice(data).expect("send must succeed");
        assert_eq!(sent, data.len(), "all data must be sent");
    }

    // Exchange packets to deliver the data.
    for _ in 0..10 {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx {
            server.process_incoming(pkt);
        }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() {
            client.process_incoming(server_tx);
        }
    }

    // The connection must still be established after data transfer.
    assert!(
        server.is_established(server_socket),
        "server must still be ESTABLISHED after data transfer"
    );
    assert!(
        client.is_established(),
        "client must still be ESTABLISHED after data transfer"
    );

    eprintln!("[tcp-data] PASS: data sent after handshake, connection stable");
}

#[test]
fn tcp_handshake_with_different_client_ip() {
    // Verify the handshake works with a different client IP (10.0.0.100).
    let mut server = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
    let server_socket = server.add_tcp_socket();
    server.listen(server_socket, 80).expect("listen");

    let mut client = ClientStack::new(
        Ipv4Address::new(10, 0, 0, 100),
        Ipv4Address::new(10, 0, 0, 1),
        80,
        60000,
    );

    let (client_ok, server_ok) =
        exchange_until_established(&mut client, &mut server, server_socket, 50);

    assert!(client_ok, "client must be ESTABLISHED from 10.0.0.100");
    assert!(server_ok, "server must accept connection from 10.0.0.100");

    eprintln!("[tcp-client-ip] PASS: handshake from 10.0.0.100 completed");
}

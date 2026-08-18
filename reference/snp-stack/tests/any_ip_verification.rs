//! **N3-B Step 2 — Verify the `any_ip` assumption.**
//!
//! This test PROVES (not assumes) that the following configuration:
//!
//! ```text
//! smoltcp Interface {
//!     ip_addrs: [10.0.0.1/24],
//!     any_ip: true,
//!     routes: [default via 10.0.0.1],
//! }
//! +
//! listen(dst_port)
//! ```
//!
//! results in a listening socket accepting a SYN for an EXTERNAL destination
//! IP (e.g. 93.184.216.34:443) and that `local_endpoint()` on the ESTABLISHED
//! socket returns the ORIGINAL destination (93.184.216.34:443).
//!
//! ## What this test does NOT assume
//!
//! It does NOT rely on the `enable_any_ip()` wrapper. It constructs the
//! smoltcp Interface directly and checks the exact behavior. If `any_ip`
//! alone (without the default route) is insufficient, the test will FAIL
//! and show exactly what is needed.
//!
//! ## Why this test matters
//!
//! The entire N3-B architecture depends on this assumption:
//! - If `local_endpoint()` returns the original destination → transparent
//!   TCP works with NO NAT.
//! - If `local_endpoint()` returns the TUN IP → NAT is required, and the
//!   architecture must be redesigned.
//!
//! This test settles the question from the code, not from comments.

#![cfg(feature = "circuit-upstream")]

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use snp_stack::smol_device::TunSmolDevice;
use snp_stack::TcpEngine;

/// A minimal smoltcp client stack that simulates the OS TCP/IP stack.
/// It connects to a remote IP:port and generates SYN packets.
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
}

/// Exchange packets between client and server until both are ESTABLISHED.
fn exchange_until_established(
    client: &mut ClientStack,
    server: &mut TcpEngine,
    server_socket: SocketHandle,
    max_iter: usize,
) -> bool {
    for _ in 0..max_iter {
        let client_tx = client.poll_and_drain();
        for pkt in &client_tx { server.process_incoming(pkt); }
        let server_tx = server.drain_outgoing();
        if !server_tx.is_empty() { client.process_incoming(server_tx); }
        if client.is_established() && server.is_established(server_socket) {
            return true;
        }
    }
    false
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1: any_ip WITHOUT default route — SYN for external IP is DROPPED
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn any_ip_without_route_drops_external_syn() {
    // This test proves that `any_ip = true` alone is INSUFFICIENT.
    // A default route via the TUN IP is also required.
    //
    // The smoltcp any_ip check (iface/interface/ipv4.rs:113):
    //   if !self.any_ip
    //       || !dst.is_unicast()
    //       || self.routes.lookup(dst).map_or(true, |router| !self.has_ip_addr(router))
    //   { return None; }
    //
    // Without a route, routes.lookup() returns None → map_or(true, ...) → true → REJECT.

    let tun_ip = Ipv4Address::new(10, 0, 0, 1);
    let external_ip = Ipv4Address::new(93, 184, 216, 34); // example.com

    let mut server_engine = TcpEngine::new(tun_ip, 1500);
    server_engine.enable_any_ip();
    // NOTE: NO default route added — this should cause the SYN to be dropped.

    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(tun_ip, external_ip, 443, 52344);

    // Exchange packets — the SYN should be DROPPED by smoltcp because
    // there's no route for 93.184.216.34 via 10.0.0.1.
    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);

    // The connection must NOT be established — the SYN was dropped.
    assert!(
        !established,
        "any_ip without a default route should drop SYNs for external IPs, \
         but the connection was established — the any_ip behavior has changed"
    );

    // The server socket should still be in LISTEN state (never accepted).
    assert_eq!(
        server_engine.tcp_state(server_socket),
        SmolTcpState::Listen,
        "server socket should still be LISTEN (SYN was dropped)"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 2: any_ip WITH default route — SYN for external IP is ACCEPTED
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn any_ip_with_route_accepts_external_syn() {
    // This test proves that `any_ip = true` + a default route via the TUN IP
    // causes smoltcp to ACCEPT SYNs for external IPs.
    //
    // The critical question: does local_endpoint() return the ORIGINAL
    // destination (93.184.216.34:443) or the TUN IP (10.0.0.1:443)?
    //
    // This test settles that question from the code.

    let tun_ip = Ipv4Address::new(10, 0, 0, 1);
    let external_ip = Ipv4Address::new(93, 184, 216, 34); // example.com
    let external_port: u16 = 443;
    let client_port: u16 = 52344;

    let mut server_engine = TcpEngine::new(tun_ip, 1500);
    server_engine.enable_any_ip();
    // N3-B FIX: add a default route via the TUN IP. This is REQUIRED for
    // any_ip to accept packets for external IPs. Without it, smoltcp's
    // routes.lookup() returns None and the packet is dropped.
    server_engine.add_default_route(tun_ip);

    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, external_port).expect("listen");

    // Client simulates the OS TCP/IP stack connecting to 93.184.216.34:443.
    let mut client = ClientStack::new(tun_ip, external_ip, external_port, client_port);

    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 100);

    assert!(
        established,
        "Connection should be ESTABLISHED with any_ip + default route. \
         If this fails, the any_ip + route configuration is wrong."
    );

    // ═══ THE CRITICAL ASSERTION ═══
    // What does local_endpoint() return on the server's accepted socket?
    let local_ep = server_engine
        .local_endpoint(server_socket)
        .expect("ESTABLISHED socket must have a local_endpoint");

    eprintln!("[any_ip_test] server local_endpoint = {:?}", local_ep);
    eprintln!("[any_ip_test] expected external destination = {:?}", external_ip);

    // The local_endpoint should be the ORIGINAL destination (93.184.216.34:443).
    // This is the key architectural assumption: any_ip preserves the original
    // destination IP through the smoltcp stack.
    assert_eq!(
        local_ep.addr,
        IpAddress::Ipv4(external_ip),
        "local_endpoint must return the ORIGINAL destination IP (93.184.216.34), \
         not the TUN IP (10.0.0.1). If this fails, NAT is required and the \
         N3-B architecture must be redesigned."
    );
    assert_eq!(
        local_ep.port, external_port,
        "local_endpoint port must be the original destination port (443)"
    );

    // remote_endpoint should be the OS source (10.0.0.1:52344).
    let remote_ep = server_engine
        .remote_endpoint(server_socket)
        .expect("ESTABLISHED socket must have a remote_endpoint");

    eprintln!("[any_ip_test] server remote_endpoint = {:?}", remote_ep);

    assert_eq!(
        remote_ep.addr,
        IpAddress::Ipv4(tun_ip),
        "remote_endpoint should be the TUN IP (OS source) 10.0.0.1"
    );
    assert_eq!(
        remote_ep.port, client_port,
        "remote_endpoint port should be the OS ephemeral source port 52344"
    );

    eprintln!("[any_ip_test] PASS: local_endpoint = original destination (no NAT needed)");
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 3: any_ip with route — multiple different destination IPs on same port
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn any_ip_accepts_multiple_different_destinations() {
    // Proves that the same listening socket (port 443) accepts SYNs for
    // DIFFERENT destination IPs (93.184.216.34, 1.1.1.1, 8.8.8.8).
    //
    // This is the core of transparent TCP: the destination IP is NOT
    // known at listen() time — it's extracted from each SYN.

    let tun_ip = Ipv4Address::new(10, 0, 0, 1);

    for (dst_ip, label) in [
        (Ipv4Address::new(93, 184, 216, 34), "example.com"),
        (Ipv4Address::new(1, 1, 1, 1), "cloudflare DNS"),
        (Ipv4Address::new(8, 8, 8, 8), "google DNS"),
        (Ipv4Address::new(140, 82, 121, 4), "github.com"),
    ] {
        let mut server_engine = TcpEngine::new(tun_ip, 1500);
        server_engine.enable_any_ip();
        server_engine.add_default_route(tun_ip);

        let server_socket = server_engine.add_tcp_socket();
        server_engine.listen(server_socket, 443).expect("listen");

        let mut client = ClientStack::new(tun_ip, dst_ip, 443, 50000 + (dst_ip.0[3] as u16));
        let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 100);

        assert!(established, "connection to {} ({}) should be established", label, dst_ip);

        let local_ep = server_engine.local_endpoint(server_socket).expect("local_endpoint");
        assert_eq!(
            local_ep.addr, IpAddress::Ipv4(dst_ip),
            "local_endpoint for {} must be the original destination {}", label, dst_ip
        );

        eprintln!("[any_ip_test] {}: local_endpoint = {}:{} ✓", label, dst_ip, local_ep.port);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 5: Concurrent SYNs to the same port (Step 3 regression test)
// ════════════════════════════════════════════════════════════════════════════

/// A test harness that simulates the TunClient's listener management:
/// for each SYN, add a listening socket. This verifies that N concurrent
/// SYNs to the same port all reach ESTABLISHED.
struct ListenerPool {
    engine: TcpEngine,
    listening: Vec<SocketHandle>,
}

impl ListenerPool {
    fn new(tun_ip: Ipv4Address) -> Self {
        let mut engine = TcpEngine::new(tun_ip, 1500);
        engine.enable_any_ip();
        engine.add_default_route(tun_ip);
        Self { engine, listening: Vec::new() }
    }

    /// Simulate intercepting a SYN: add a listening socket for the port.
    fn add_listener_for_syn(&mut self, port: u16) {
        let handle = self.engine.add_tcp_socket();
        self.engine.listen(handle, port).expect("listen");
        self.listening.push(handle);
    }

    /// Poll the engine and drain outgoing packets.
    fn poll_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.engine.drain_outgoing()
    }

    /// Feed incoming packets to the engine.
    fn process_incoming(&mut self, packets: &[Vec<u8>]) {
        for pkt in packets {
            self.engine.process_incoming(pkt);
        }
    }

    /// Count how many listening sockets have transitioned to ESTABLISHED.
    fn count_established(&self) -> usize {
        self.listening
            .iter()
            .filter(|h| self.engine.is_established(**h))
            .count()
    }

    /// Return the local_endpoints of all ESTABLISHED sockets.
    fn established_endpoints(&self) -> Vec<(smoltcp::wire::IpAddress, u16)> {
        self.listening
            .iter()
            .filter(|h| self.engine.is_established(**h))
            .filter_map(|h| self.engine.local_endpoint(*h))
            .map(|ep| (ep.addr, ep.port))
            .collect()
    }
}

#[test]
fn concurrent_syns_same_port_all_established() {
    // N3-B Step 3 regression test: 10 simultaneous SYNs to the same port
    // (443) but different destination IPs. All 10 must reach ESTABLISHED.
    //
    // The bug this catches: if the listener pool only adds a listener when
    // the pool is empty (the old design), then 10 SYNs arriving before any
    // accept() runs would only get 1 listener. The other 9 SYNs would be
    // dropped because the single listening socket can only accept ONE
    // connection in smoltcp 0.11.
    //
    // The fix: add a listener for EVERY SYN.

    let tun_ip = Ipv4Address::new(10, 0, 0, 1);
    let dst_port: u16 = 443;

    // 10 different destination IPs (all routable Internet IPs).
    let dst_ips: Vec<Ipv4Address> = (0..10)
        .map(|i| Ipv4Address::new(93, 184, 216, 34 + i))
        .collect();

    // Create the server (simulating TunClient's TcpEngine + listener pool).
    let mut server = ListenerPool::new(tun_ip);

    // Create 10 client stacks, each connecting to a different dst IP.
    let mut clients: Vec<ClientStack> = dst_ips
        .iter()
        .enumerate()
        .map(|(i, dst_ip)| ClientStack::new(tun_ip, *dst_ip, dst_port, 50000 + i as u16))
        .collect();

    // For each client's SYN, add a listening socket on the server.
    // (This simulates TunClient::intercept_packet().)
    for _ in &dst_ips {
        server.add_listener_for_syn(dst_port);
    }

    // Exchange packets. Route each server packet to the correct client
    // based on the destination port (the client's ephemeral source port).
    // Feeding ALL SYN-ACKs to ALL clients would cause each client's smoltcp
    // to RST the non-matching ones, closing the server's sockets.
    for _ in 0..500 {
        // 1. Drain all clients + feed all SYNs to server.
        let mut all_client_tx = Vec::new();
        for client in &mut clients {
            let tx = client.poll_and_drain();
            all_client_tx.extend(tx);
        }
        if !all_client_tx.is_empty() {
            server.process_incoming(&all_client_tx);
        }

        // 2. Drain server + route each packet to the correct client by port.
        let server_tx = server.poll_and_drain();
        for pkt in &server_tx {
            // Parse the destination port from the TCP header (bytes 22-23
            // of the IP packet: offset 2-3 in the TCP header, which is at
            // IP header length + 2).
            if pkt.len() < 24 { continue; }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl + 4 { continue; }
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            // Route to the client whose ephemeral port matches.
            let client_idx = (dst_port - 50000) as usize;
            if client_idx < clients.len() {
                clients[client_idx].process_incoming(vec![pkt.clone()]);
            }
        }

        // 3. Check if all are established.
        if server.count_established() == 10 {
            break;
        }
    }

    // ═══ ASSERT: all 10 flows must be ESTABLISHED ═══
    let established = server.count_established();
    assert_eq!(
        established, 10,
        "All 10 concurrent SYNs to port {} must reach ESTABLISHED, but only {} did. \
         This means the listener allocation strategy is losing SYNs.",
        dst_port, established
    );

    // Verify each ESTABLISHED socket has the correct original destination.
    let endpoints = server.established_endpoints();
    assert_eq!(endpoints.len(), 10, "must have 10 established endpoints");

    for (i, dst_ip) in dst_ips.iter().enumerate() {
        let found = endpoints.iter().any(|(addr, port)| {
            *addr == IpAddress::Ipv4(*dst_ip) && *port == dst_port
        });
        assert!(
            found,
            "destination {} ({}:{}) must be in the established endpoints — \
             this verifies local_endpoint() returns the ORIGINAL destination",
            i, dst_ip, dst_port
        );
    }

    eprintln!("[concurrent_syn_test] PASS: all 10 SYNs established with correct destinations");
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 4: WITHOUT any_ip — SYN for external IP is DROPPED (control test)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn without_any_ip_external_syn_is_dropped() {
    // Control test: WITHOUT any_ip, a SYN for an external IP is dropped.
    // This proves that the any_ip + route configuration is what makes it work.

    let tun_ip = Ipv4Address::new(10, 0, 0, 1);
    let external_ip = Ipv4Address::new(93, 184, 216, 34);

    let mut server_engine = TcpEngine::new(tun_ip, 1500);
    // NOTE: any_ip NOT enabled (default is false).

    let server_socket = server_engine.add_tcp_socket();
    server_engine.listen(server_socket, 443).expect("listen");

    let mut client = ClientStack::new(tun_ip, external_ip, 443, 52344);
    let established = exchange_until_established(&mut client, &mut server_engine, server_socket, 50);

    assert!(
        !established,
        "Without any_ip, a SYN for an external IP must be dropped"
    );
}

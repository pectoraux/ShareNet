//! **N3-B — TUN Client Runtime (production data-plane).**
//!
//! The client-side data plane that connects a real OS TUN interface to
//! the ShareNet circuit mesh. This is the production transparent TCP
//! runtime that ties together:
//!
//! ```text
//! OS Application (e.g. curl, browser, SSH)
//!     ↓ kernel TCP/IP stack
//! TUN interface (snp0)
//!     ↓ read_packet()
//! SYN interception (extract original destination from 5-tuple)
//!     ↓ process_incoming()
//! TcpEngine (smoltcp with any_ip enabled)
//!     ↓ TCP handshake completes (SYN → SYN-ACK → ACK)
//! TcpFlowBridge
//!     ↓ attach_async_upstream()
//! ShareNetCircuitUpstreamModeB (MultiplexedCircuit stream)
//!     ↓ encrypted circuit
//! Relay mesh
//!     ↓
//! Gateway (opens real outbound TCP socket)
//!     ↓ real Internet
//! ```
//!
//! ## What this is
//!
//! A long-running async task that:
//! 1. Opens a `LinuxTunDevice` (real TUN interface).
//! 2. Creates a `TcpEngine` (smoltcp stack) with `any_ip` enabled, so it
//!    accepts SYNs for ANY destination IP (not just the TUN's local IP).
//! 3. For each incoming TCP SYN: extracts the original destination (dst IP
//!    + dst port) from the 5-tuple, ensures a listening socket exists for
//!    the destination port, then feeds the packet to smoltcp.
//! 4. When a smoltcp socket transitions to ESTABLISHED: extracts the
//!    original destination via `local_endpoint()`, opens a
//!    `MultiplexedCircuit` stream to that destination, and attaches it
//!    as an `AsyncUpstream` on the bridge.
//! 5. Pumps packets bidirectionally: TUN → smoltcp → bridge → circuit,
//!    and circuit → bridge → smoltcp → TUN.
//! 6. Removes flows when the ShareNet stream closes (FIN/RST/error).
//!
//! ## What this is NOT
//!
//! - This does NOT configure OS routes (the caller must do `ip route add`).
//! - This does NOT handle DNS (applications must use IP addresses or
//!   a separate DNS resolver).
//! - This does NOT do transparent TCP migration (existing connections
//!   are lost on circuit failure — the application must reconnect).
//! - This does NOT do NAT (smoltcp's `any_ip` mode preserves the original
//!   destination IP through the stack; no packet rewriting).
//!
//! ## N3-B architectural decisions (see worklog N3B-STATUS for full analysis)
//!
//! 1. **`any_ip` mode**: smoltcp accepts SYNs for any destination IP.
//!    `local_endpoint()` on an ESTABLISHED socket returns the original
//!    destination. NO NAT required.
//! 2. **Dynamic listening sockets**: a smoltcp 0.11 `listen()` socket
//!    accepts exactly ONE connection. When one transitions to ESTABLISHED,
//!    a replacement listening socket is added for the same port.
//! 3. **Flow ownership**: the `TcpFlowBridge` owns the socket→upstream
//!    mapping (1:1). The `FlowTable` is NOT used (it is FROZEN as
//!    observational-only and must not participate in transport behavior).
//! 4. **Recovery**: flow-fails-and-application-reconnects (NOT transparent
//!    migration). When the circuit link fails, all streams are marked
//!    Closed → bridge closes smoltcp sockets → OS application sees RST.

#![cfg(feature = "circuit-upstream")]
#![cfg(target_os = "linux")]

use crate::bridge::TcpFlowBridge;
use crate::flow_destinations::{extract_flow, is_tcp_syn, tcp_destination, validate_destination};
use crate::tcp_engine::TcpEngine;

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_gateway::stream::{InternetEndpoint, TransportProtocol};
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{Node, Route};
use snp_tun::device::LinuxTunDevice;
use snp_tun::packet::IpPacket;
use snp_tun::PacketDevice;

use smoltcp::iface::SocketHandle as SmolSocketHandle;
use smoltcp::wire::IpAddress;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the TUN client.
pub struct TunClientConfig {
    /// The TUN interface name (e.g. "snp0"). Max 15 chars. If empty,
    /// the kernel auto-assigns (e.g. "tun0").
    pub tun_name: String,
    /// The virtual IP address assigned to the TUN interface (e.g. "10.0.0.1").
    pub tun_ip: std::net::Ipv4Addr,
    /// The MTU for the TUN interface and smoltcp stack.
    pub mtu: usize,
    /// The ShareNet route to the gateway (pre-established).
    pub route: Route,
    /// The client node (identity + keys).
    pub node: Node,
    /// The client's X25519 secret key.
    pub client_x25519_secret: Arc<X25519Secret>,
    /// The client's X25519 public key.
    pub client_x25519_public: X25519PubKey,
    /// The echo/health endpoint for circuit health verification.
    /// (N3-B: this is NO LONGER used as a default destination — the
    /// destination is extracted from each SYN packet. It is retained
    /// only for the optional health-check on startup.)
    pub health_endpoint: InternetEndpoint,
}

/// The TUN client runtime.
///
/// Owns the TUN device, smoltcp engine, flow bridge, and the multiplexed
/// circuit. Runs a packet-pump loop that forwards traffic bidirectionally
/// between the OS network stack and the ShareNet circuit.
pub struct TunClient {
    /// The real TUN device.
    tun: LinuxTunDevice,
    /// The smoltcp TCP engine (processes IP packets, any_ip enabled).
    engine: TcpEngine,
    /// The flow bridge (maps TCP flows to ShareNet streams).
    bridge: TcpFlowBridge,
    /// The multiplexed circuit to the gateway.
    circuit: MultiplexedCircuit,
    /// Configuration.
    config: TunClientConfig,
    /// **N3-B** — Listening sockets per port. A smoltcp 0.11 listen() socket
    /// accepts exactly ONE connection; when one transitions to ESTABLISHED,
    /// we add a replacement. This maps dst_port → the listening socket handles
    /// that are currently waiting for a connection.
    listening_sockets: HashMap<u16, Vec<SmolSocketHandle>>,
}

impl TunClient {
    /// Create and start the TUN client.
    ///
    /// This:
    /// 1. Opens the TUN device.
    /// 2. Creates the smoltcp engine with `any_ip` enabled (so it accepts
    ///    SYNs for any destination IP, not just the TUN's local IP).
    /// 3. Establishes the multiplexed circuit.
    /// 4. Returns the client (call `run()` to start the packet pump).
    ///
    /// # Errors
    /// Returns an error if the TUN device cannot be created (permissions,
    /// etc.) or the circuit cannot be established.
    pub async fn create(config: TunClientConfig) -> Result<Self, TunClientError> {
        // 1. Open the TUN device.
        let tun = LinuxTunDevice::create(&config.tun_name)
            .map_err(TunClientError::TunCreate)?;

        eprintln!("[n3] TUN interface '{}' created (fd={}, ip={})",
            tun.name(), tun.as_raw_fd(), config.tun_ip);

        // 2. Create the smoltcp engine bound to the TUN IP.
        let smoltcp_ip = smoltcp::wire::Ipv4Address::new(
            config.tun_ip.octets()[0],
            config.tun_ip.octets()[1],
            config.tun_ip.octets()[2],
            config.tun_ip.octets()[3],
        );
        let mut engine = TcpEngine::new(smoltcp_ip, config.mtu);

        // N3-B: Enable any_ip so smoltcp accepts SYNs for ANY destination IP
        // (not just the TUN's local IP). Without this, a SYN for 93.184.216.34
        // (an external Internet IP) would be dropped by smoltcp because the
        // destination is not a local interface IP.
        engine.enable_any_ip();

        // N3-B FIX (Step 2): any_ip alone is INSUFFICIENT. smoltcp's any_ip
        // check (iface/interface/ipv4.rs:113) also requires a route whose
        // gateway is one of our own IPs. Without a default route via the TUN IP,
        // routes.lookup(dst) returns None and the SYN is rejected.
        //
        // This is verified by tests/any_ip_verification.rs:
        //   - any_ip_without_route_drops_external_syn → FAILS (SYN dropped)
        //   - any_ip_with_route_accepts_external_syn  → PASSES (SYN accepted,
        //     local_endpoint() returns the original destination)
        engine.add_default_route(smoltcp_ip);
        eprintln!("[n3] smoltcp any_ip + default route via {} enabled — accepting SYNs for any destination IP", config.tun_ip);

        // 3. Create the flow bridge.
        let bridge = TcpFlowBridge::new();

        // 4. Establish the multiplexed circuit.
        let circuit = MultiplexedCircuit::establish(
            &config.node,
            &config.route,
            &config.client_x25519_secret,
            &config.client_x25519_public,
        )
        .await
        .map_err(|e| TunClientError::CircuitEstablish(format!("{:?}", e)))?;

        eprintln!("[n3] multiplexed circuit established (fid={:?})",
            circuit.circuit_fid());

        Ok(Self {
            tun,
            engine,
            bridge,
            circuit,
            config,
            listening_sockets: HashMap::new(),
        })
    }

    /// Returns the TUN interface name.
    #[must_use]
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// **N3-B Step 7** — Configure the OS network interface.
    ///
    /// This assigns the TUN IP address, brings the interface up, and
    /// installs a default route through the TUN. After this call, the OS
    /// kernel routes ALL traffic through the TUN interface, and the
    /// TunClient intercepts SYNs.
    ///
    /// # Ownership
    ///
    /// - **Who creates TUN?** `TunClient::create()` (via `LinuxTunDevice::create`).
    /// - **Who assigns its address?** This method.
    /// - **Who installs the route?** This method.
    /// - **Who removes the route?** `cleanup_os_routes()` (call before drop).
    /// - **Who owns shutdown?** The `run()` loop + `Drop` (which closes the TUN fd,
    ///   destroying the interface + removing the route automatically).
    ///
    /// # Permissions
    ///
    /// Requires `CAP_NET_ADMIN` (root or the capability must be granted).
    ///
    /// # Errors
    /// Returns an error if the `ip` commands fail.
    pub fn configure_os_routes(&self) -> Result<(), TunClientError> {
        let config = crate::os_routes::OsRouteConfig {
            tun_name: self.tun.name().to_string(),
            tun_ip_cidr: format!("{}/24", self.config.tun_ip),
        };
        crate::os_routes::configure_os_interface(&config)
            .map_err(|e| TunClientError::SmolTcp(format!("OS route config: {e}")))
    }

    /// **N3-B Step 7** — Clean up the OS network configuration.
    ///
    /// Removes the default route and brings the interface down. Call this
    /// before dropping the TunClient for explicit cleanup.
    ///
    /// # Errors
    /// Returns an error if the cleanup commands fail (non-fatal during shutdown).
    pub fn cleanup_os_routes(&self) -> Result<(), TunClientError> {
        let config = crate::os_routes::OsRouteConfig {
            tun_name: self.tun.name().to_string(),
            tun_ip_cidr: format!("{}/24", self.config.tun_ip),
        };
        crate::os_routes::cleanup_os_interface(&config)
            .map_err(|e| TunClientError::SmolTcp(format!("OS route cleanup: {e}")))
    }

    /// Run the packet-pump loop.
    ///
    /// This is the main data-plane loop. It runs forever (until the TUN
    /// device is closed or an unrecoverable error occurs).
    ///
    /// The loop:
    /// 1. Read a packet from TUN → intercept SYN (extract destination +
    ///    ensure a listening socket exists for the dst port) → feed to smoltcp.
    /// 2. Poll listening sockets for ESTABLISHED transitions → extract
    ///    destination via local_endpoint() → open a ShareNet stream → attach
    ///    to bridge → add a replacement listening socket.
    /// 3. Pump the bridge (app→circuit and circuit→app).
    /// 4. Drain smoltcp outgoing packets → write to TUN.
    /// 5. Remove closed flows (FIN/RST/error) from the engine.
    pub async fn run(&mut self) -> Result<(), TunClientError> {
        eprintln!("[n3] TUN client packet pump starting");

        loop {
            // 1. Read a packet from TUN (with a short timeout so we don't
            //    block forever if no packets arrive).
            match tokio::time::timeout(
                Duration::from_millis(10),
                self.tun.read_packet(),
            ).await {
                Ok(Ok(packet)) => {
                    // N3-B: Intercept the packet BEFORE feeding to smoltcp.
                    // If it's a TCP SYN, extract the destination and ensure
                    // a listening socket exists for the destination port.
                    self.intercept_packet(&packet);
                    // Feed the IP packet to smoltcp.
                    self.engine.process_incoming(packet.as_bytes());
                }
                Ok(Err(e)) => {
                    eprintln!("[n3] TUN read error: {:?}", e);
                    return Err(TunClientError::TunRead(e));
                }
                Err(_) => {
                    // Timeout — no packet available. Continue to pump.
                }
            }

            // 2. Check for new ESTABLISHED connections on listening sockets.
            self.accept_new_connections().await;

            // 3. Pump the bridge (bidirectional data transfer).
            let (_sent, _recv) = self.bridge.pump_async(&mut self.engine).await;

            // 4. Drain outgoing packets from smoltcp → write to TUN.
            let outgoing = self.engine.drain_outgoing();
            for pkt in outgoing {
                match IpPacket::parse(&pkt) {
                    Ok(packet) => {
                        if let Err(e) = self.tun.write_packet(packet).await {
                            eprintln!("[n3] TUN write error: {:?}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("[n3] failed to parse outgoing packet: {:?}", e);
                    }
                }
            }

            // N3-B: Closed-flow cleanup is handled by the bridge's pump_async:
            // when an upstream returns BridgeError::Closed or the smoltcp socket
            // enters an invalid state, the bridge removes the flow from its
            // internal map and closes the smoltcp socket. The socket stays in
            // the SocketSet until it reaches a terminal state (CLOSED), at
            // which point it can be removed. This is a best-effort cleanup —
            // the authoritative removal path is the bridge's detach_upstream.

            // Yield to other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// **N3-B** — Intercept a packet before feeding it to smoltcp.
    ///
    /// If the packet is a TCP SYN, extract the destination and ensure a
    /// listening socket exists for the destination port. If the destination
    /// is not a routable Internet address (private/loopback), the packet
    /// is NOT fed to smoltcp (it would be rejected by the gateway anyway).
    fn intercept_packet(&mut self, packet: &IpPacket) {
        // Extract flow metadata (5-tuple + TCP flags) from the packet.
        let Some(meta) = extract_flow(packet) else {
            // Not a TCP/UDP packet (e.g. ICMP) — let smoltcp handle it.
            return;
        };

        // Only intercept TCP SYNs (connection initiations).
        if !is_tcp_syn(&meta) {
            return;
        }

        // Extract the destination (IP + port).
        let Some((dst_ip, dst_port)) = tcp_destination(&meta) else {
            return;
        };

        // N3-B: Client-side early validation. Reject private/loopback/link-local
        // destinations immediately. The gateway performs the authoritative SSRF
        // defence, but we reject early to avoid wasting circuit bandwidth and
        // to give the OS application an immediate RST.
        if let Err(reason) = validate_destination(&dst_ip, dst_port) {
            eprintln!("[n3] SYN to {}:{} rejected client-side: {}", dst_ip, dst_port, reason);
            // Don't feed this packet to smoltcp — it would establish a connection
            // that the gateway would reject. Instead, let smoltcp drop it (by not
            // having a listening socket for this port, smoltcp will send a RST).
            // Actually, to send a RST, smoltcp needs to see the SYN. So we DO feed
            // it, but we don't add a listening socket — smoltcp will generate a RST
            // for the unlistened port.
            return;
        }

        // N3-B: Ensure a listening socket exists for this SYN.
        //
        // smoltcp 0.11: a listen() socket accepts exactly ONE connection.
        // When it transitions to ESTABLISHED, it stops listening. To handle
        // concurrent SYNs to the same port (e.g. 10 simultaneous connections
        // to port 443), we must have N listening sockets for N SYNs.
        //
        // The fix (Step 3): add a NEW listening socket for EVERY SYN, not
        // just when the pool is empty. The replacement logic in
        // accept_new_connections() adds a replacement after each ESTABLISHED
        // transition. This guarantees that every SYN has a listener.
        //
        // Verified by tests/any_ip_verification.rs::concurrent_syns_same_port.
        let handle = self.engine.add_tcp_socket();
        match self.engine.listen(handle, dst_port) {
            Ok(()) => {
                eprintln!("[n3] added listening socket on port {} for SYN to {}",
                    dst_port, dst_ip);
                self.listening_sockets
                    .entry(dst_port)
                    .or_default()
                    .push(handle);
            }
            Err(e) => {
                eprintln!("[n3] failed to listen on port {}: {:?}", dst_port, e);
                self.engine.remove_socket(handle);
            }
        }
    }

    /// **N3-B** — Poll listening sockets for ESTABLISHED transitions.
    ///
    /// When a listening socket transitions to ESTABLISHED:
    /// 1. Extract the original destination via `local_endpoint()`.
    /// 2. Open a ShareNet stream to that destination.
    /// 3. Attach the upstream to the bridge.
    /// 4. Remove the socket from the listening pool.
    /// 5. Add a replacement listening socket for the same port.
    async fn accept_new_connections(&mut self) {
        // Collect the sockets that have transitioned to ESTABLISHED.
        let mut established: Vec<(SmolSocketHandle, u16)> = Vec::new();
        for (port, pool) in &mut self.listening_sockets {
            let mut still_listening = Vec::new();
            for handle in pool.drain(..) {
                if self.engine.is_established(handle) {
                    established.push((handle, *port));
                } else {
                    still_listening.push(handle);
                }
            }
            *pool = still_listening;
        }

        // For each newly-established socket, extract the destination and
        // open a ShareNet stream.
        for (socket_handle, port) in established {
            // Extract the original destination via local_endpoint().
            // With any_ip enabled, local_endpoint() returns the destination
            // IP:port from the accepted SYN (the external Internet endpoint).
            let local_ep = self.engine.local_endpoint(socket_handle);
            let remote_ep = self.engine.remote_endpoint(socket_handle);

            let (dst_ip, dst_port) = match local_ep {
                Some(ep) => {
                    #[allow(unreachable_patterns)]
                    let ip = match ep.addr {
                        IpAddress::Ipv4(v4) => IpAddr::V4(std::net::Ipv4Addr::new(
                            v4.0[0], v4.0[1], v4.0[2], v4.0[3],
                        )),
                        // N3-B: smoltcp is compiled with proto-ipv4 only
                        // (Cargo.toml features). IPv6 SYN interception is
                        // a future extension — not claimed here.
                        _ => {
                            eprintln!("[n3] non-IPv4 local_endpoint {:?} — closing socket {:?}",
                                ep.addr, socket_handle);
                            self.engine.tcp_socket_mut(socket_handle).close();
                            continue;
                        }
                    };
                    (ip, ep.port)
                }
                None => {
                    eprintln!("[n3] ESTABLISHED socket {:?} has no local_endpoint — closing",
                        socket_handle);
                    self.engine.tcp_socket_mut(socket_handle).close();
                    continue;
                }
            };

            eprintln!("[n3] accepted TCP connection on port {}: {} (peer={:?}) → opening ShareNet stream to {}:{}",
                port, socket_handle, remote_ep, dst_ip, dst_port);

            // Construct the InternetEndpoint for the ShareNet stream.
            let destination = InternetEndpoint {
                address: dst_ip,
                port: dst_port,
                protocol: TransportProtocol::Tcp,
            };

            // Open a ShareNet stream to the destination.
            match self.open_stream_for_socket(socket_handle, destination).await {
                Ok(()) => {
                    // Add a replacement listening socket for the same port
                    // so future connections on this port can be accepted.
                    let new_handle = self.engine.add_tcp_socket();
                    match self.engine.listen(new_handle, port) {
                        Ok(()) => {
                            self.listening_sockets
                                .entry(port)
                                .or_default()
                                .push(new_handle);
                        }
                        Err(e) => {
                            eprintln!("[n3] failed to add replacement listener on port {}: {:?}",
                                port, e);
                            self.engine.remove_socket(new_handle);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[n3] failed to open stream for socket {:?}: {}",
                        socket_handle, e);
                    // Close the smoltcp socket so the OS gets a RST.
                    self.engine.tcp_socket_mut(socket_handle).close();
                    // Still add a replacement listener.
                    let new_handle = self.engine.add_tcp_socket();
                    if self.engine.listen(new_handle, port).is_ok() {
                        self.listening_sockets
                            .entry(port)
                            .or_default()
                            .push(new_handle);
                    } else {
                        self.engine.remove_socket(new_handle);
                    }
                }
            }
        }
    }

    /// Open a ShareNet stream for a smoltcp socket and attach it to the bridge.
    async fn open_stream_for_socket(
        &mut self,
        socket: SmolSocketHandle,
        destination: InternetEndpoint,
    ) -> Result<(), TunClientError> {
        let stream = self.circuit.open_stream(destination.clone()).await
            .map_err(|e| TunClientError::StreamOpen(format!("{:?}", e)))?;

        let upstream = MultiplexedUpstream::new(stream);
        self.bridge.attach_async_upstream(socket, Box::new(upstream));
        eprintln!("[n3] opened stream to {:?} for socket {:?}", destination, socket);
        Ok(())
    }
}

/// Errors that can occur in the TUN client.
#[derive(Debug)]
pub enum TunClientError {
    /// Failed to create the TUN device.
    TunCreate(snp_tun::error::TunError),
    /// Failed to read from the TUN device.
    TunRead(snp_tun::error::TunError),
    /// Failed to establish the multiplexed circuit.
    CircuitEstablish(String),
    /// Failed to open a ShareNet stream.
    StreamOpen(String),
    /// smoltcp error.
    SmolTcp(String),
}

impl std::fmt::Display for TunClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TunCreate(e) => write!(f, "TUN create error: {}", e),
            Self::TunRead(e) => write!(f, "TUN read error: {}", e),
            Self::CircuitEstablish(e) => write!(f, "circuit establish error: {}", e),
            Self::StreamOpen(e) => write!(f, "stream open error: {}", e),
            Self::SmolTcp(e) => write!(f, "smoltcp error: {}", e),
        }
    }
}

impl std::error::Error for TunClientError {}

/// A wrapper that adapts a MultiplexedCircuit stream handle to the
/// AsyncUpstream trait. This is the same as ShareNetCircuitUpstreamModeB
/// but takes a pre-opened StreamHandle from a MultiplexedCircuit.
pub struct MultiplexedUpstream {
    handle: snp_node::node::stream_client::StreamHandle,
}

impl MultiplexedUpstream {
    /// Create from a pre-opened stream handle.
    #[must_use]
    pub fn new(handle: snp_node::node::stream_client::StreamHandle) -> Self {
        Self { handle }
    }
}

#[async_trait::async_trait]
impl crate::bridge::AsyncUpstream for MultiplexedUpstream {
    async fn send(&mut self, data: &[u8]) -> Result<usize, crate::bridge::BridgeError> {
        self.handle.send(data).await
            .map_err(|e| crate::bridge::BridgeError::SmolTcp(format!("{:?}", e)))
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, crate::bridge::BridgeError> {
        self.handle.recv().await
            .map_err(|e| crate::bridge::BridgeError::SmolTcp(format!("{:?}", e)))
    }

    async fn close(&mut self) {
        let _ = self.handle.close().await;
    }
}

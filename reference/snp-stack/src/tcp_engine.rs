//! Userspace TCP/IP engine — wraps [`smoltcp`] to provide a real TCP/IP stack
//! behind the TUN packet boundary.
//!
//! ## N2.3.3 Scope
//!
//! The [`TcpEngine`] provides:
//!
//! - A smoltcp `Interface` configured with a local IP address (the TUN
//!   interface's IP, e.g. `10.0.0.1`).
//! - A `SocketSet` holding TCP sockets.
//! - [`TcpEngine::process_incoming`] — feeds a raw IP packet (from the TUN)
//!   into the smoltcp stack and polls for state transitions.
//! - [`TcpEngine::drain_outgoing`] — drains outgoing IP packets (SYN-ACKs,
//!   ACKs, data, FINs) that smoltcp has produced, for writing back to the TUN.
//! - [`TcpEngine::add_tcp_listener`] — creates a TCP socket in `LISTEN`
//!   state on a given port.
//! - [`TcpEngine::tcp_state`] / [`TcpEngine::is_established`] — query socket
//!   state.
//!
//! ## What this proves
//!
//! A synthetic TCP client connected to the TUN interface can complete a full
//! TCP handshake (SYN → SYN-ACK → ACK) through ShareNet userspace handling.
//! The smoltcp stack handles all TCP state transitions, checksums, and
//! sequence numbers — we do NOT write a half-TCP implementation.
//!
//! ## What this does NOT do
//!
//! - DNS interception (N2.3.4).
//! - HTTPS / HTTP proxy.
//! - Circuit creation / gateway routing.
//! - Actual Internet forwarding (packets stay within the engine).
//! - UDP sockets (can be added later via `socket-udp` smoltcp feature).

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::smol_device::TunSmolDevice;

/// Default TCP socket buffer size (8 KiB each direction).
const TCP_BUFFER_SIZE: usize = 8 * 1024;

/// Errors from the TCP engine.
#[derive(Debug, thiserror::Error)]
pub enum TcpEngineError {
    /// smoltcp returned an error (e.g. buffer full, illegal state transition).
    #[error("smoltcp error: {0}")]
    SmolTcp(String),
    /// The requested socket handle was not found in the socket set.
    #[error("socket handle not found: {0}")]
    SocketNotFound(SocketHandle),
}

/// A userspace TCP/IP engine wrapping a smoltcp `Interface`.
///
/// The engine owns:
/// - A [`TunSmolDevice`] (the queue-based smoltcp device adapter).
/// - An `Interface` (the smoltcp TCP/IP stack).
/// - A `SocketSet` (holding TCP sockets).
///
/// The engine does NOT own a `PacketDevice` — the upper layer is responsible
/// for reading packets from the TUN and calling [`TcpEngine::process_incoming`],
/// and for draining outgoing packets via [`TcpEngine::drain_outgoing`] and
/// writing them to the TUN.
pub struct TcpEngine {
    device: TunSmolDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
}

impl std::fmt::Debug for TcpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpEngine").finish_non_exhaustive()
    }
}

impl TcpEngine {
    /// Create a new TCP engine with the given local IP address and MTU.
    ///
    /// The local IP is the address the TUN interface will respond to. TCP
    /// connections to this IP will be accepted by the engine.
    ///
    /// **N3-B**: `any_ip` is NOT enabled by this constructor. Call
    /// [`Self::enable_any_ip`] after construction to accept SYNs for
    /// arbitrary external destination IPs (required for transparent TCP).
    #[must_use]
    pub fn new(local_ip: Ipv4Address, mtu: usize) -> Self {
        let mut device = TunSmolDevice::new(mtu);
        let config = Config::new(HardwareAddress::Ip);
        // Interface::new borrows the device temporarily to read its
        // capabilities. The device is NOT stored in the Interface — it's
        // passed again to each poll() call.
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        // Assign the local IP address to the interface (with a /24 subnet).
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(local_ip), 24))
                .expect("push IP address must succeed");
        });

        Self {
            device,
            interface,
            sockets: SocketSet::new(Vec::new()),
        }
    }

    /// **N3-B** — Enable `any_ip` mode on the smoltcp interface.
    ///
    /// When enabled, the interface accepts incoming IP packets addressed to
    /// ANY destination IP, not just the local interface IPs. This is REQUIRED
    /// for transparent TCP: an OS application connecting to an external
    /// Internet IP (e.g. 93.184.216.34:443) sends a SYN with that external
    /// destination. Without `any_ip`, smoltcp drops the SYN because the
    /// destination is not a local interface IP.
    ///
    /// With `any_ip` enabled:
    /// - The SYN is accepted and dispatched to a listening socket on the
    ///   destination port.
    /// - When the socket transitions to ESTABLISHED, `local_endpoint()`
    ///   returns the ORIGINAL destination (the external IP:port from the SYN),
    ///   and `remote_endpoint()` returns the OS source (src_ip:src_port).
    ///
    /// This is NOT NAT — the destination IP is preserved through the stack.
    /// No packet rewriting, no checksum recomputation.
    ///
    /// See: smoltcp 0.11.0 `Interface::set_any_ip` (iface/interface/mod.rs:369).
    pub fn enable_any_ip(&mut self) {
        self.interface.set_any_ip(true);
    }

    /// Returns true if `any_ip` mode is enabled.
    #[must_use]
    pub fn any_ip(&self) -> bool {
        self.interface.any_ip()
    }

    /// Feed an incoming raw IP packet (from the TUN) into the smoltcp stack.
    /// The engine will process the packet (TCP state transitions, ACKs, etc.)
    /// and may produce outgoing packets (available via [`Self::drain_outgoing`]).
    pub fn process_incoming(&mut self, packet: &[u8]) {
        self.device.push_rx(packet.to_vec());
        self.poll();
    }

    /// Drain outgoing IP packets that smoltcp has produced (SYN-ACKs, ACKs,
    /// data, FINs). These should be written to the TUN device.
    ///
    /// Returns the packets in FIFO order (oldest first).
    pub fn drain_outgoing(&mut self) -> Vec<Vec<u8>> {
        self.poll();
        let mut outgoing = Vec::new();
        while let Some(pkt) = self.device.pop_tx() {
            outgoing.push(pkt);
        }
        outgoing
    }

    /// Poll the smoltcp interface to advance TCP state machines. This is
    /// called automatically by [`Self::process_incoming`] and
    /// [`Self::drain_outgoing`], but can be called explicitly to advance
    /// timeouts and retransmissions.
    pub fn poll(&mut self) {
        let Self {
            device,
            interface,
            sockets,
        } = self;
        interface.poll(SmolInstant::now(), device, sockets);
    }

    /// Add a new TCP socket to the engine and return its handle. The socket
    /// starts in `CLOSED` state — call [`Self::listen`] to begin accepting
    /// connections.
    #[must_use]
    pub fn add_tcp_socket(&mut self) -> SocketHandle {
        let rx_buffer = SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
        let tx_buffer = SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
        let socket = SmolTcpSocket::new(rx_buffer, tx_buffer);
        self.sockets.add(socket)
    }

    /// Put a TCP socket into `LISTEN` state on the given port. The engine
    /// will accept incoming SYN packets to this port and complete the
    /// handshake automatically.
    ///
    /// # Errors
    /// Returns [`TcpEngineError::SmolTcp`] if the socket is not in a state
    /// that allows listening (e.g. already connected).
    pub fn listen(&mut self, handle: SocketHandle, port: u16) -> Result<(), TcpEngineError> {
        let socket = self
            .sockets
            .get_mut::<SmolTcpSocket>(handle);
        socket
            .listen(port)
            .map_err(|e| TcpEngineError::SmolTcp(format!("{e:?}")))
    }

    /// Returns the current TCP state of the given socket.
    ///
    /// # Errors
    /// Returns [`TcpEngineError`] if the handle is invalid.
    pub fn tcp_state(&self, handle: SocketHandle) -> SmolTcpState {
        self.sockets.get::<SmolTcpSocket>(handle).state()
    }

    /// Returns true if the given socket is in the `ESTABLISHED` state
    /// (handshake complete, ready for data transfer).
    #[must_use]
    pub fn is_established(&self, handle: SocketHandle) -> bool {
        self.tcp_state(handle) == SmolTcpState::Established
    }

    /// Returns a reference to the underlying smoltcp socket set (for advanced
    /// socket inspection).
    #[must_use]
    pub fn sockets(&self) -> &SocketSet<'static> {
        &self.sockets
    }

    /// Returns a reference to the underlying smoltcp interface (for advanced
    /// configuration, e.g. adding routes).
    #[must_use]
    pub fn interface(&self) -> &Interface {
        &self.interface
    }

    /// Returns a mutable reference to the underlying smoltcp interface.
    #[must_use]
    pub fn interface_mut(&mut self) -> &mut Interface {
        &mut self.interface
    }

    /// Returns a mutable reference to the underlying socket set (for advanced
    /// socket manipulation — e.g. the bridge's `recv_slice`/`send_slice`).
    #[must_use]
    pub fn sockets_mut(&mut self) -> &mut SocketSet<'static> {
        &mut self.sockets
    }

    /// Returns a mutable reference to a specific TCP socket (for the bridge
    /// to call `recv_slice`/`send_slice`).
    #[must_use]
    pub fn tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut SmolTcpSocket<'static> {
        self.sockets.get_mut::<SmolTcpSocket<'static>>(handle)
    }

    /// Returns a shared reference to a specific TCP socket (for the bridge
    /// to check `can_recv`/`can_send`).
    #[must_use]
    pub fn tcp_socket(&self, handle: SocketHandle) -> &SmolTcpSocket<'static> {
        self.sockets.get::<SmolTcpSocket<'static>>(handle)
    }

    /// **N3-B** — Returns the local endpoint of an ESTABLISHED socket.
    ///
    /// When `any_ip` is enabled and a socket has transitioned from LISTEN to
    /// ESTABLISHED, this returns the ORIGINAL destination IP:port from the
    /// accepted SYN (the external Internet endpoint the OS application was
    /// trying to reach).
    ///
    /// Returns `None` if the socket is not ESTABLISHED or has no local
    /// endpoint.
    ///
    /// See: smoltcp 0.11.0 `Socket::local_endpoint` (socket/tcp.rs:696).
    #[must_use]
    pub fn local_endpoint(&self, handle: SocketHandle) -> Option<smoltcp::wire::IpEndpoint> {
        let socket = self.sockets.get::<SmolTcpSocket<'static>>(handle);
        socket.local_endpoint()
    }

    /// **N3-B** — Returns the remote endpoint (peer) of an ESTABLISHED socket.
    ///
    /// This is the OS source IP:port of the accepted TCP connection (e.g.
    /// 10.0.0.2:52344 — the ephemeral port the OS kernel assigned).
    ///
    /// Returns `None` if the socket is not ESTABLISHED or has no remote
    /// endpoint.
    ///
    /// See: smoltcp 0.11.0 `Socket::remote_endpoint` (socket/tcp.rs:702).
    #[must_use]
    pub fn remote_endpoint(&self, handle: SocketHandle) -> Option<smoltcp::wire::IpEndpoint> {
        let socket = self.sockets.get::<SmolTcpSocket<'static>>(handle);
        socket.remote_endpoint()
    }

    /// Remove a socket from the socket set (for connection teardown).
    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::socket::tcp::State;

    #[test]
    fn engine_creates_with_local_ip() {
        let _engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
        // No sockets yet.
    }

    #[test]
    fn engine_add_tcp_socket_starts_closed() {
        let mut engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
        let handle = engine.add_tcp_socket();
        assert_eq!(engine.tcp_state(handle), State::Closed);
    }

    #[test]
    fn engine_listen_transitions_to_listen_state() {
        let mut engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
        let handle = engine.add_tcp_socket();
        engine.listen(handle, 443).expect("listen must succeed");
        assert_eq!(engine.tcp_state(handle), State::Listen);
    }

    #[test]
    fn engine_is_established_false_before_handshake() {
        let mut engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
        let handle = engine.add_tcp_socket();
        engine.listen(handle, 443).expect("listen");
        assert!(!engine.is_established(handle));
    }
}

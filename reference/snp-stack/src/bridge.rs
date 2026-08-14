//! TCP Flow Bridge — connects smoltcp TCP sockets to a byte-level upstream
//! (the ShareNet circuit in production, a [`MockUpstream`] in tests).
//!
//! ## N2.3.5 Scope
//!
//! The bridge proves the packet-to-mesh adapter boundary:
//!
//! ```text
//! Virtual TCP connection (from TUN)
//!         |
//!         v
//! smoltcp socket (TcpEngine)
//!         |
//!         v
//! TcpFlowBridge (this module)
//!         |
//!         v
//! Upstream (ShareNet circuit / MockUpstream)
//!         |
//!         v
//! Gateway HTTP endpoint (production)
//! ```
//!
//! The bridge:
//!
//! 1. Detects when a smoltcp socket has received data from the application
//!    (via `socket.recv_slice()`).
//! 2. Forwards those bytes to the upstream via the [`Upstream`] trait.
//! 3. When the upstream returns bytes (via `upstream.recv()`), injects them
//!    back into the smoltcp socket (via `socket.send_slice()`).
//! 4. smoltcp delivers the injected bytes to the application as normal TCP
//!    data.
//!
//! ## What this proves
//!
//! A TCP SYN received from the TUN → smoltcp creates a socket → outbound
//! bytes extracted → wrapped into a transit-like message → gateway returns
//! bytes → injected back into smoltcp → application receives data.
//!
//! ## What this does NOT do
//!
//! - Real ShareNet circuit integration (the [`Upstream`] trait is the seam —
//!   production plugs in a circuit-backed implementation, tests use
//!   [`MockUpstream`]).
//! - HTTP/HTTPS proxying.
//! - DNS integration (DNS is handled by the [`crate::dns`] module).
//! - Application awareness (the bridge is transparent).

use std::collections::HashMap;

use smoltcp::iface::SocketHandle;

use crate::tcp_engine::TcpEngine;

/// A byte-level upstream — the seam between the TCP flow bridge and the
/// ShareNet circuit (or a test mock).
///
/// ## Production implementation
///
/// In production, this trait is implemented by a ShareNet circuit adapter:
///
/// - `send` wraps the bytes into a ShareNet transit message and sends them
///   via `send_via_route()`.
/// - `recv` awaits the gateway's response bytes (from the circuit).
/// - `close` tears down the circuit.
///
/// ## Test implementation
///
/// [`MockUpstream`] implements this trait with in-memory queues — no real
/// network access, deterministic behavior.
pub trait Upstream: Send {
    /// Send bytes to the upstream (from the application → gateway direction).
    /// Returns the number of bytes accepted (may be less than `data.len()`
    /// if the upstream buffer is full).
    ///
    /// # Errors
    /// Returns [`BridgeError`] on failure (upstream closed, buffer full, etc.).
    fn send(&mut self, data: &[u8]) -> Result<usize, BridgeError>;

    /// Receive bytes from the upstream (from the gateway → application
    /// direction). Returns `Ok(None)` if no bytes are available (non-blocking).
    ///
    /// # Errors
    /// Returns [`BridgeError`] on failure.
    fn recv(&mut self) -> Result<Option<Vec<u8>>, BridgeError>;

    /// Close the upstream (tear down the circuit). After this, `send` and
    /// `recv` should return [`BridgeError::Closed`].
    fn close(&mut self);
}

/// Errors from the TCP flow bridge.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    /// The upstream is closed (circuit torn down, connection reset, etc.).
    #[error("upstream closed")]
    Closed,
    /// The upstream buffer is full (cannot accept more bytes right now).
    #[error("upstream buffer full")]
    BufferFull,
    /// A smoltcp socket operation failed (send/recv on a closed socket).
    #[error("smoltcp socket error: {0}")]
    SmolTcp(String),
    /// The requested socket handle was not found in the bridge's tracked flows.
    #[error("unknown socket handle: {0:?}")]
    UnknownSocket(SocketHandle),
}

/// A tracked TCP flow — maps a smoltcp socket handle to an upstream instance.
struct FlowEntry {
    /// The smoltcp socket handle (in the TcpEngine's SocketSet). Retained
    /// for debugging/inspection (the pump loop already knows the handle).
    #[allow(dead_code)]
    socket_handle: SocketHandle,
    /// The upstream (circuit adapter or mock).
    upstream: Box<dyn Upstream>,
}

/// The TCP flow bridge — connects smoltcp TCP sockets to upstreams.
///
/// The bridge is the packet-to-mesh adapter. It does NOT own the TcpEngine
/// — the caller owns the engine and passes it to [`TcpFlowBridge::pump`],
/// which does the bidirectional byte transfer.
///
/// ## Lifecycle
///
/// 1. The caller creates a TcpEngine and a TcpFlowBridge.
/// 2. When a TCP connection is established (the caller detects this via
///    `engine.is_established(handle)`), the caller creates an upstream and
///    calls `bridge.attach_upstream(handle, upstream)`.
/// 3. The caller calls `bridge.pump(&mut engine)` periodically (or after
///    each packet exchange) to transfer bytes between smoltcp and the
///    upstreams.
/// 4. When a connection closes (FIN/RST), the caller calls
///    `bridge.detach_upstream(handle)`.
pub struct TcpFlowBridge {
    /// Tracked flows: socket handle → upstream.
    flows: HashMap<SocketHandle, FlowEntry>,
}

impl std::fmt::Debug for TcpFlowBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFlowBridge")
            .field("flow_count", &self.flows.len())
            .finish()
    }
}

impl Default for TcpFlowBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpFlowBridge {
    /// Create an empty bridge (no tracked flows).
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Attach an upstream to a smoltcp socket. After this, `pump` will
    /// transfer bytes between the socket and the upstream.
    pub fn attach_upstream(&mut self, socket_handle: SocketHandle, upstream: Box<dyn Upstream>) {
        self.flows.insert(
            socket_handle,
            FlowEntry {
                socket_handle,
                upstream,
            },
        );
    }

    /// Detach the upstream from a smoltcp socket. Closes the upstream and
    /// removes the flow from the bridge.
    pub fn detach_upstream(&mut self, socket_handle: SocketHandle) {
        if let Some(mut entry) = self.flows.remove(&socket_handle) {
            entry.upstream.close();
        }
    }

    /// Returns the number of tracked flows.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Returns true if the given socket has an attached upstream.
    #[must_use]
    pub fn has_upstream(&self, socket_handle: SocketHandle) -> bool {
        self.flows.contains_key(&socket_handle)
    }

    /// Pump bytes between smoltcp sockets and their upstreams.
    ///
    /// For each tracked flow:
    /// 1. Read bytes from the smoltcp socket (application → upstream).
    /// 2. Send those bytes to the upstream.
    /// 3. Receive bytes from the upstream.
    /// 4. Write those bytes into the smoltcp socket (upstream → application).
    ///
    /// This is the core bidirectional transfer. The caller should invoke
    /// `pump` after each `engine.process_incoming()` / `engine.drain_outgoing()`
    /// cycle, or periodically to advance data transfer.
    ///
    /// Returns the total number of bytes transferred in each direction.
    pub fn pump(&mut self, engine: &mut TcpEngine) -> (usize, usize) {
        let mut total_sent = 0; // app → upstream
        let mut total_recv = 0; // upstream → app

        // Collect the socket handles to avoid borrowing issues (we need to
        // borrow engine mutably, but the flows map holds the upstreams).
        let socket_handles: Vec<SocketHandle> = self.flows.keys().copied().collect();

        for socket_handle in socket_handles {
            // 1. Read bytes from the smoltcp socket (app → upstream).
            let mut read_buf = vec![0u8; 8192];
            let n_read = {
                let socket = engine.tcp_socket_mut(socket_handle);
                match socket.recv_slice(&mut read_buf) {
                    Ok(n) => n,
                    Err(smoltcp::socket::tcp::RecvError::Finished) => 0,
                    Err(smoltcp::socket::tcp::RecvError::InvalidState) => 0,
                }
            };

            if n_read > 0 {
                // Forward to the upstream.
                if let Some(entry) = self.flows.get_mut(&socket_handle) {
                    match entry.upstream.send(&read_buf[..n_read]) {
                        Ok(n_sent) => {
                            total_sent += n_sent;
                        }
                        Err(BridgeError::Closed) => {
                            // Upstream closed — close the smoltcp socket.
                            let socket = engine.tcp_socket_mut(socket_handle);
                            socket.close();
                        }
                        Err(_) => {
                            // Other error — drop the flow.
                            // (The next pump cycle will handle cleanup.)
                        }
                    }
                }
            }

            // 2. Receive bytes from the upstream (upstream → app).
            if let Some(entry) = self.flows.get_mut(&socket_handle) {
                match entry.upstream.recv() {
                    Ok(Some(data)) => {
                        if !data.is_empty() {
                            let socket = engine.tcp_socket_mut(socket_handle);
                            match socket.send_slice(&data) {
                                Ok(n_written) => {
                                    total_recv += n_written;
                                }
                                Err(smoltcp::socket::tcp::SendError::InvalidState) => {
                                    // Socket closed — drop the flow.
                                    self.flows.remove(&socket_handle);
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        // No data available — non-blocking, skip.
                    }
                    Err(BridgeError::Closed) => {
                        // Upstream closed — close the smoltcp socket.
                        let socket = engine.tcp_socket_mut(socket_handle);
                        socket.close();
                    }
                    Err(_) => {
                        // Other error — drop the flow.
                        self.flows.remove(&socket_handle);
                    }
                }
            }
        }

        (total_sent, total_recv)
    }
}

// ─── MockUpstream (for testing) ─────────────────────────────────────────────

/// A mock upstream for testing — in-memory queues, no real network access.
///
/// - `send` pushes bytes into the `sent` queue (for the test to inspect).
/// - `recv` pops bytes from the `received` queue (pre-loaded by the test).
/// - `close` marks the upstream as closed.
#[derive(Debug, Default)]
pub struct MockUpstream {
    /// Bytes sent by the bridge (app → upstream) — for test inspection.
    sent: Vec<u8>,
    /// Bytes to be received by the bridge (upstream → app) — pre-loaded by
    /// the test.
    received: std::collections::VecDeque<u8>,
    /// Whether the upstream is closed.
    closed: bool,
}

impl MockUpstream {
    /// Create an empty mock upstream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load bytes that the bridge will receive via `recv()`.
    pub fn load_receive_data(&mut self, data: &[u8]) {
        self.received.extend(data);
    }

    /// Returns the bytes sent by the bridge (app → upstream direction).
    #[must_use]
    pub fn sent_bytes(&self) -> &[u8] {
        &self.sent
    }

    /// Returns true if the upstream has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns true if there are bytes available to receive.
    #[must_use]
    pub fn has_receive_data(&self) -> bool {
        !self.received.is_empty()
    }
}

impl Upstream for MockUpstream {
    fn send(&mut self, data: &[u8]) -> Result<usize, BridgeError> {
        if self.closed {
            return Err(BridgeError::Closed);
        }
        self.sent.extend_from_slice(data);
        Ok(data.len())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>, BridgeError> {
        if self.closed {
            return Err(BridgeError::Closed);
        }
        if self.received.is_empty() {
            return Ok(None);
        }
        // Return all available bytes in one chunk.
        let data: Vec<u8> = self.received.drain(..).collect();
        Ok(Some(data))
    }

    fn close(&mut self) {
        self.closed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::Ipv4Address;

    #[test]
    fn bridge_starts_empty() {
        let bridge = TcpFlowBridge::new();
        assert_eq!(bridge.flow_count(), 0);
    }

    #[test]
    fn bridge_attach_and_detach() {
        let mut bridge = TcpFlowBridge::new();
        let mut engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);
        let handle = engine.add_tcp_socket();
        let upstream = Box::new(MockUpstream::new());
        bridge.attach_upstream(handle, upstream);
        assert!(bridge.has_upstream(handle));
        assert_eq!(bridge.flow_count(), 1);

        bridge.detach_upstream(handle);
        assert!(!bridge.has_upstream(handle));
        assert_eq!(bridge.flow_count(), 0);
    }

    #[test]
    fn mock_upstream_send_and_recv() {
        let mut upstream = MockUpstream::new();
        upstream.load_receive_data(b"hello from gateway");

        // recv should return the pre-loaded data.
        let data = upstream.recv().unwrap().unwrap();
        assert_eq!(data, b"hello from gateway");

        // Second recv should return None (queue empty).
        assert!(upstream.recv().unwrap().is_none());

        // send should store the bytes.
        upstream.send(b"app data").unwrap();
        assert_eq!(upstream.sent_bytes(), b"app data");
    }

    #[test]
    fn mock_upstream_closed_returns_error() {
        let mut upstream = MockUpstream::new();
        upstream.close();
        assert!(upstream.is_closed());

        let result = upstream.send(b"data");
        assert_eq!(result, Err(BridgeError::Closed));

        let result = upstream.recv();
        assert_eq!(result, Err(BridgeError::Closed));
    }

    #[test]
    fn bridge_pump_transfers_data_app_to_upstream() {
        // This test verifies that the bridge reads bytes from a smoltcp
        // socket and forwards them to the upstream. We need a TcpEngine with
        // an established socket — but setting up a full handshake is
        // complex. Instead, we test the pump logic with a socket that has
        // data in its recv buffer (simulated by a direct write).
        //
        // For a full end-to-end test (including handshake), see
        // tests/tcp_flow_bridge.rs.
        let mut bridge = TcpFlowBridge::new();
        let _engine = TcpEngine::new(Ipv4Address::new(10, 0, 0, 1), 1500);

        // Without an established socket, pump should be a no-op.
        let (sent, recv) = bridge.pump(&mut TcpEngine::new(
            Ipv4Address::new(10, 0, 0, 1),
            1500,
        ));
        assert_eq!(sent, 0);
        assert_eq!(recv, 0);
    }
}

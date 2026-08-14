//! Flow table — tracks active network flows with idle expiration.
//!
//! The [`FlowTable`] maps a [`FlowKey`] (5-tuple) to a [`FlowEntry`] (state +
//! timing). It supports:
//!
//! - **Flow creation** — when a new flow is seen (e.g. a TCP SYN or the first
//!   UDP packet), a [`FlowEntry`] is inserted.
//! - **Flow lookup** — subsequent packets in the same flow look up the
//!   existing entry.
//! - **Idle expiration** — flows that have not seen traffic for a configurable
//!   duration are evicted to bound memory usage.
//! - **TCP connection tracking** — detects SYN (new connection), FIN/RST
//!   (connection teardown), and transitions the flow state accordingly.
//!
//! ## Scope (N2.3.2)
//!
//! - TCP flow state: `New` (SYN seen) → `Established` (SYN-ACK seen) →
//!   `Closing` (FIN seen) → `Closed` (RST or FIN-ACK seen).
//! - UDP flow state: `New` (first packet) → `Established` (second packet).
//! - Idle expiration via `sweep_idle(now, max_age)`.
//! - Thread-safe via `tokio::sync::Mutex` (for concurrent access from
//!   multiple packet-processing tasks).
//!
//! ## Out of scope
//!
//! - Full RFC 793 TCP state machine (no retransmission tracking, no
//!   sequence validation, no TIME_WAIT).
//! - NAT / port rewriting.
//! - Actual packet forwarding (that's N2.3.3+).
//! - Circuit creation (that's the gateway layer, unchanged).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use crate::transport::{FlowKey, TcpFlags};

/// The state of a tracked TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN sent (first packet of a new connection). Waiting for SYN-ACK.
    SynSent,
    /// SYN-ACK received (or sent, for the server side). Connection established.
    Established,
    /// FIN sent or received. Waiting for the other side to close.
    Closing,
    /// RST seen, or FIN-ACK completed. The flow is terminated.
    Closed,
}

/// The state of a tracked UDP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    /// First packet seen (unidirectional so far).
    New,
    /// Return traffic seen (bidirectional).
    Established,
}

/// The protocol-specific state of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// A TCP flow with TCP-specific state.
    Tcp(TcpState),
    /// A UDP flow with UDP-specific state.
    Udp(UdpState),
}

/// A tracked flow entry.
#[derive(Debug, Clone)]
pub struct FlowEntry {
    /// The flow's 5-tuple key.
    pub key: FlowKey,
    /// The protocol-specific state.
    pub state: FlowState,
    /// When the flow was created (first packet seen).
    pub created_at: Instant,
    /// When the flow last saw traffic (updated on every packet).
    pub last_seen: Instant,
    /// Total number of packets seen in this flow.
    pub packet_count: u64,
    /// Total bytes seen in this flow (IP-level, including headers).
    pub byte_count: u64,
}

impl FlowEntry {
    /// Create a new flow entry for a TCP SYN.
    #[must_use]
    pub fn new_tcp_syn(key: FlowKey, now: Instant, packet_len: usize) -> Self {
        Self {
            key,
            state: FlowState::Tcp(TcpState::SynSent),
            created_at: now,
            last_seen: now,
            packet_count: 1,
            byte_count: packet_len as u64,
        }
    }

    /// Create a new flow entry for a UDP packet (first packet of a flow).
    #[must_use]
    pub fn new_udp(key: FlowKey, now: Instant, packet_len: usize) -> Self {
        Self {
            key,
            state: FlowState::Udp(UdpState::New),
            created_at: now,
            last_seen: now,
            packet_count: 1,
            byte_count: packet_len as u64,
        }
    }

    /// Update the flow entry for a new packet. Advances the TCP state machine
    /// if applicable, increments counters, and updates `last_seen`.
    pub fn on_packet(&mut self, flags: Option<TcpFlags>, now: Instant, packet_len: usize) {
        self.last_seen = now;
        self.packet_count += 1;
        self.byte_count += packet_len as u64;

        if let Some(flags) = flags {
            // TCP state machine transitions.
            //
            // RST ALWAYS transitions to Closed (connection abort), regardless
            // of the current state. This must be checked BEFORE the FIN
            // (teardown) check, because is_teardown() returns true for both
            // FIN and RST — RST is a hard close, FIN is a graceful close.
            if let FlowState::Tcp(state) = &mut self.state {
                if flags.rst {
                    *state = TcpState::Closed;
                    return;
                }
                match state {
                    TcpState::SynSent => {
                        if flags.is_syn_ack() {
                            // SYN-ACK received → established (we are the
                            // server side of the handshake).
                            *state = TcpState::Established;
                        } else if !flags.syn {
                            // Any non-SYN, non-RST packet (ACK, data, FIN)
                            // received while in SynSent means the handshake
                            // completed in the reverse direction → established.
                            *state = TcpState::Established;
                        }
                        // (A pure SYN while in SynSent is a retransmission —
                        // stay in SynSent. RST was handled above.)
                    }
                    TcpState::Established => {
                        if flags.fin {
                            *state = TcpState::Closing;
                        }
                        // (RST was handled above.)
                    }
                    TcpState::Closing => {
                        if flags.fin {
                            *state = TcpState::Closed;
                        }
                        // (RST was handled above.)
                    }
                    TcpState::Closed => {
                        // Stay closed — a stray packet after close doesn't
                        // reopen the flow.
                    }
                }
            }
        } else {
            // UDP: transition New → Established on any subsequent packet.
            if let FlowState::Udp(state) = &mut self.state {
                if *state == UdpState::New {
                    *state = UdpState::Established;
                }
            }
        }
    }

    /// Returns true if this flow is closed (TCP RST/FIN-ACK completed) and
    /// can be evicted.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.state, FlowState::Tcp(TcpState::Closed))
    }
}

/// A thread-safe flow table with idle expiration.
///
/// Wraps a `HashMap<FlowKey, FlowEntry>` in `tokio::sync::Mutex` for
/// concurrent access from multiple packet-processing tasks. Clones share
/// the same underlying map (via `Arc`).
#[derive(Debug, Clone)]
pub struct FlowTable {
    inner: Arc<Mutex<HashMap<FlowKey, FlowEntry>>>,
}

impl FlowTable {
    /// Create an empty flow table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the number of currently-tracked flows.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Returns true if the table is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Look up a flow by key. Returns a clone of the entry if found.
    pub async fn get(&self, key: &FlowKey) -> Option<FlowEntry> {
        self.inner.lock().await.get(key).cloned()
    }

    /// Process a packet: look up or create the flow entry, update its state,
    /// and return the (possibly updated) entry.
    ///
    /// - For TCP SYN packets: creates a new flow in `SynSent` state.
    /// - For TCP SYN-ACK packets: creates a new flow in `Established` state
    ///   (we're the server side — the SYN was in the reverse direction).
    /// - For TCP data/FIN/RST packets: creates a new flow in `Established`
    ///   state (mid-flow traffic we didn't see the SYN for) or updates the
    ///   existing flow's state.
    /// - For UDP packets: creates a new flow in `New` state, or transitions
    ///   to `Established` on the second packet.
    ///
    /// Returns the flow entry (created or updated).
    pub async fn process_packet(
        &self,
        key: &FlowKey,
        tcp_flags: Option<TcpFlags>,
        now: Instant,
        packet_len: usize,
    ) -> FlowEntry {
        let mut table = self.inner.lock().await;
        if let Some(entry) = table.get_mut(key) {
            entry.on_packet(tcp_flags, now, packet_len);
            entry.clone()
        } else {
            // New flow — determine the initial state from the first packet.
            let entry = if let Some(flags) = tcp_flags {
                // TCP flow.
                let initial_state = if flags.is_syn_ack() {
                    // SYN-ACK as first packet → we're the server side.
                    FlowState::Tcp(TcpState::Established)
                } else if flags.syn {
                    // Pure SYN → client side starting handshake.
                    FlowState::Tcp(TcpState::SynSent)
                } else {
                    // Data/FIN/RST without prior SYN → mid-flow traffic.
                    FlowState::Tcp(TcpState::Established)
                };
                FlowEntry {
                    key: *key,
                    state: initial_state,
                    created_at: now,
                    last_seen: now,
                    packet_count: 1,
                    byte_count: packet_len as u64,
                }
            } else {
                // UDP flow — first packet is always New.
                FlowEntry::new_udp(*key, now, packet_len)
            };
            table.insert(*key, entry.clone());
            entry
        }
    }

    /// Sweep idle flows. Removes flows where `last_seen` is older than
    /// `max_age` ago (relative to `now`), AND flows that are in `Closed`
    /// state (regardless of age — closed flows should be evicted immediately).
    ///
    /// Returns the number of flows evicted.
    pub async fn sweep_idle(&self, now: Instant, max_age: std::time::Duration) -> usize {
        let mut table = self.inner.lock().await;
        let before = table.len();
        table.retain(|_, entry| {
            if entry.is_closed() {
                return false; // Evict closed flows immediately.
            }
            // Evict idle flows (last_seen older than max_age).
            now.duration_since(entry.last_seen) < max_age
        });
        before - table.len()
    }

    /// Remove a specific flow from the table. Returns the removed entry if
    /// it existed.
    pub async fn remove(&self, key: &FlowKey) -> Option<FlowEntry> {
        self.inner.lock().await.remove(key)
    }

    /// Clear all flows.
    pub async fn clear(&self) {
        self.inner.lock().await.clear();
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{FlowKey, TcpFlags, PROTO_TCP, UDP};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_tcp_flow_key(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port,
            dst_port,
            protocol: PROTO_TCP,
        }
    }

    fn make_udp_flow_key(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port,
            dst_port,
            protocol: UDP,
        }
    }

    #[tokio::test]
    async fn tcp_syn_creates_new_flow() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        let entry = table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;

        assert_eq!(entry.state, FlowState::Tcp(TcpState::SynSent));
        assert_eq!(entry.packet_count, 1);
        assert_eq!(table.len().await, 1);
    }

    #[tokio::test]
    async fn tcp_syn_ack_establishes_flow() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // SYN
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;
        // SYN-ACK (same flow key — in practice this would be the reverse key,
        // but for this test we're checking the state transition logic)
        let entry = table
            .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
            .await;

        assert_eq!(entry.state, FlowState::Tcp(TcpState::Established));
        assert_eq!(entry.packet_count, 2);
    }

    #[tokio::test]
    async fn tcp_fin_transitions_to_closing() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // SYN → Established
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
            .await;
        // FIN
        let entry = table
            .process_packet(&key, Some(TcpFlags::from_byte(0x01)), now, 60)
            .await;

        assert_eq!(entry.state, FlowState::Tcp(TcpState::Closing));
    }

    #[tokio::test]
    async fn tcp_rst_closes_flow() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // SYN → Established
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
            .await;
        // RST
        let entry = table
            .process_packet(&key, Some(TcpFlags::from_byte(0x04)), now, 60)
            .await;

        assert_eq!(entry.state, FlowState::Tcp(TcpState::Closed));
        assert!(entry.is_closed());
    }

    #[tokio::test]
    async fn udp_flow_lifecycle() {
        let table = FlowTable::new();
        let key = make_udp_flow_key(53535, 53);
        let now = Instant::now();

        // First UDP packet → New
        let entry = table.process_packet(&key, None, now, 40).await;
        assert_eq!(entry.state, FlowState::Udp(UdpState::New));

        // Second packet → Established
        let entry = table.process_packet(&key, None, now, 40).await;
        assert_eq!(entry.state, FlowState::Udp(UdpState::Established));
        assert_eq!(entry.packet_count, 2);
    }

    #[tokio::test]
    async fn idle_flow_evicted_by_sweep() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // Create a flow.
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;
        assert_eq!(table.len().await, 1);

        // Sweep with max_age = 0 (evict everything idle — our flow's
        // last_seen == now, so duration_since is ~0, which is < 0? No —
        // we need to advance time. Use a future instant.
        // Actually, Instant::now() + Duration::from_secs(100) simulates
        // "100 seconds later".)
        let future = now + std::time::Duration::from_secs(100);
        let evicted = table
            .sweep_idle(future, std::time::Duration::from_secs(10))
            .await;
        assert_eq!(evicted, 1);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn active_flow_not_evicted_by_sweep() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // Create a flow.
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;

        // Sweep with max_age = 100s. The flow's last_seen == now, so
        // duration_since(last_seen) = 0 < 100s → not evicted.
        let evicted = table
            .sweep_idle(now, std::time::Duration::from_secs(100))
            .await;
        assert_eq!(evicted, 0);
        assert_eq!(table.len().await, 1);
    }

    #[tokio::test]
    async fn closed_flow_evicted_immediately_by_sweep() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        // SYN → Established → RST (Closed)
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
            .await;
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
            .await;
        table
            .process_packet(&key, Some(TcpFlags::from_byte(0x04)), now, 60)
            .await;
        assert_eq!(table.len().await, 1);

        // Sweep — the closed flow should be evicted even though it's not idle.
        let evicted = table
            .sweep_idle(now, std::time::Duration::from_secs(3600))
            .await;
        assert_eq!(evicted, 1, "closed flow must be evicted immediately");
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn flow_lookup_returns_entry() {
        let table = FlowTable::new();
        let key = make_udp_flow_key(53535, 53);
        let now = Instant::now();

        table.process_packet(&key, None, now, 40).await;

        let found = table.get(&key).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().key, key);

        let missing = table.get(&make_tcp_flow_key(60000, 80)).await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn remove_flow() {
        let table = FlowTable::new();
        let key = make_udp_flow_key(53535, 53);
        let now = Instant::now();

        table.process_packet(&key, None, now, 40).await;
        assert_eq!(table.len().await, 1);

        let removed = table.remove(&key).await;
        assert!(removed.is_some());
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn concurrent_flow_processing_no_corruption() {
        // 10 concurrent tasks, each processing a distinct flow. Verify all
        // 10 flows are tracked correctly (no loss, no cross-contamination).
        let table = FlowTable::new();
        let now = Instant::now();

        let mut tasks = Vec::new();
        for i in 0u16..10 {
            let table = table.clone();
            tasks.push(tokio::spawn(async move {
                let key = make_tcp_flow_key(10000 + i, 443);
                // SYN
                table
                    .process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60)
                    .await;
                // SYN-ACK
                table
                    .process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60)
                    .await;
                // Data
                table
                    .process_packet(&key, Some(TcpFlags::from_byte(0x10)), now, 1400)
                    .await;
                key
            }));
        }

        let mut keys = Vec::new();
        for task in tasks {
            keys.push(task.await.expect("task join"));
        }

        assert_eq!(table.len().await, 10, "must have 10 distinct flows");

        for key in &keys {
            let entry = table.get(key).await.expect("flow must exist");
            assert_eq!(entry.state, FlowState::Tcp(TcpState::Established));
            assert_eq!(entry.packet_count, 3);
        }
    }

    #[tokio::test]
    async fn byte_count_accumulates() {
        let table = FlowTable::new();
        let key = make_tcp_flow_key(52344, 443);
        let now = Instant::now();

        table.process_packet(&key, Some(TcpFlags::from_byte(0x02)), now, 60).await;
        table.process_packet(&key, Some(TcpFlags::from_byte(0x12)), now, 60).await;
        table.process_packet(&key, Some(TcpFlags::from_byte(0x10)), now, 1400).await;
        table.process_packet(&key, Some(TcpFlags::from_byte(0x18)), now, 1400).await;

        let entry = table.get(&key).await.expect("flow must exist");
        assert_eq!(entry.packet_count, 4);
        assert_eq!(entry.byte_count, 60 + 60 + 1400 + 1400);
    }
}

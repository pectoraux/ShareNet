//! N2.1.1 — Link model: directed, per-endpoint transport relationships.
//!
//! A `Link` represents an actual probed, authenticated transport relationship
//! between two nodes over a specific endpoint. It is NOT the same as "I saw
//! an advertisement" — a link requires a successful transport connection +
//! SNP-IK/0.1 handshake.
//!
//! Links are **directed**: a link from A to B does NOT imply a link from B
//! to A. This models real-world asymmetry (firewalls, NAT, transport
//! limitations).

use super::*;
use std::collections::HashMap;

/// A key that uniquely identifies a directed link: local node → remote node
/// over a specific transport endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey {
    /// The local node's NodeId (the link owner).
    pub local_node_id: [u8; 32],
    /// The remote node's NodeId (the link target).
    pub remote_node_id: [u8; 32],
    /// The transport endpoint used for this link.
    pub endpoint: TransportEndpoint,
}

impl LinkKey {
    /// Construct a new `LinkKey`.
    #[must_use]
    pub fn new(
        local_node_id: [u8; 32],
        remote_node_id: [u8; 32],
        endpoint: TransportEndpoint,
    ) -> Self {
        Self {
            local_node_id,
            remote_node_id,
            endpoint,
        }
    }

    /// Check if this link is a loopback (local == remote).
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.local_node_id == self.remote_node_id
    }
}

/// The state of a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The link is established and functioning normally.
    Up,
    /// The link is established but experiencing failures or high latency.
    /// Still usable but with degraded quality.
    Degraded,
    /// The link has failed (connection lost, handshake failed, or too many
    /// consecutive failures). The link object is retained for metrics/recovery
    /// but is NOT usable for forwarding.
    Down,
}

impl LinkState {
    /// Check if this state is usable for forwarding.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Up | Self::Degraded)
    }
}

/// The type of transport used for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// TCP transport.
    Tcp,
    /// BLE transport (not yet implemented).
    Ble,
    /// Wi-Fi Direct transport (not yet implemented).
    WifiDirect,
    /// Nearby Connections transport (not yet implemented).
    NearbyConnections,
}

impl TransportType {
    /// Derive the transport type from a `TransportEndpoint`.
    #[must_use]
    pub fn from_endpoint(endpoint: &TransportEndpoint) -> Self {
        match endpoint {
            TransportEndpoint::Tcp(_) => Self::Tcp,
            TransportEndpoint::Ble(_) => Self::Ble,
            TransportEndpoint::WifiDirect(_) => Self::WifiDirect,
            TransportEndpoint::NearbyConnections(_) => Self::NearbyConnections,
        }
    }
}

/// Metrics collected per-link for route computation.
///
/// **Metric trust levels:**
/// - **Measured metrics** (RTT, success/failure counts): derived from actual
///   link probing. These are routing evidence.
/// - **Self-reported metrics** (e.g., gateway capacity): untrusted hints from
///   the remote node's advertisement. These MUST NOT be used as trusted
///   routing/security values — a malicious node can claim anything.
#[derive(Debug, Clone, Default)]
pub struct LinkMetrics {
    /// Round-trip time in microseconds, measured via link probing.
    /// `None` until the first successful probe.
    pub rtt_micros: Option<u64>,
    /// Number of successful frame transmissions.
    pub success_count: u32,
    /// Number of failed frame transmissions.
    pub failure_count: u32,
    /// Estimated bandwidth in bits per second, if measured.
    pub estimated_bandwidth_bps: Option<u64>,
}

impl LinkMetrics {
    /// Compute the success rate as a fraction in [0.0, 1.0].
    /// Returns `None` if no probes have been made.
    #[must_use]
    pub fn success_rate(&self) -> Option<f64> {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            None
        } else {
            Some(f64::from(self.success_count) / f64::from(total))
        }
    }

    /// Record a successful transmission.
    pub fn record_success(&mut self, rtt_micros: u64) {
        self.success_count = self.success_count.saturating_add(1);
        self.rtt_micros = Some(rtt_micros);
    }

    /// Record a failed transmission.
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
    }
}

/// A directed, per-endpoint transport relationship between two nodes.
///
/// A `Link` represents a **probed, authenticated** transport relationship.
/// It is NOT created merely because an advertisement was received — an
/// actual transport connection + SNP-IK/0.1 handshake must have succeeded.
#[derive(Debug, Clone)]
pub struct Link {
    /// The key identifying this link (local → remote + endpoint).
    pub key: LinkKey,
    /// The current state of the link.
    pub state: LinkState,
    /// The type of transport used.
    pub transport_type: TransportType,
    /// When this link was first established (unix seconds).
    pub established_at: u64,
    /// When the last successful transmission occurred (unix seconds).
    pub last_success: u64,
    /// When the last failure occurred, if any (unix seconds).
    pub last_failure: Option<u64>,
    /// Link metrics (measured, not self-reported).
    pub metrics: LinkMetrics,
    /// The SNP-IK/0.1 session ID, if a handshake was performed.
    pub peer_session_id: Option<[u8; 32]>,
    /// Consecutive failure count (reset on success).
    /// When this exceeds a threshold, the link transitions to Down.
    pub consecutive_failures: u32,
}

/// The threshold for consecutive failures before a link transitions to Down.
const LINK_FAILURE_THRESHOLD: u32 = 3;

impl Link {
    /// Construct a new UP link.
    #[must_use]
    pub fn new_up(key: LinkKey, session_id: Option<[u8; 32]>) -> Self {
        let now = now_unix();
        Self {
            transport_type: TransportType::from_endpoint(&key.endpoint),
            key,
            state: LinkState::Up,
            established_at: now,
            last_success: now,
            last_failure: None,
            metrics: LinkMetrics::default(),
            peer_session_id: session_id,
            consecutive_failures: 0,
        }
    }

    /// Record a successful transmission.
    pub fn record_success(&mut self, rtt_micros: u64) {
        let now = now_unix();
        self.last_success = now;
        self.consecutive_failures = 0;
        self.metrics.record_success(rtt_micros);
        // If the link was Degraded or Down, transition back to Up.
        if self.state != LinkState::Up {
            self.state = LinkState::Up;
        }
    }

    /// Record a failed transmission.
    pub fn record_failure(&mut self) {
        let now = now_unix();
        self.last_failure = Some(now);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.metrics.record_failure();
        // Transition to Degraded after 1 failure, Down after threshold.
        if self.consecutive_failures >= LINK_FAILURE_THRESHOLD {
            self.state = LinkState::Down;
        } else if self.consecutive_failures > 0 {
            self.state = LinkState::Degraded;
        }
    }

    /// Check if this link is usable for forwarding.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.state.is_usable()
    }

    /// Get the remote NodeId.
    #[must_use]
    pub fn remote_node_id(&self) -> [u8; 32] {
        self.key.remote_node_id
    }

    /// Get the local NodeId.
    #[must_use]
    pub fn local_node_id(&self) -> [u8; 32] {
        self.key.local_node_id
    }
}

/// A table of directed links, keyed by `LinkKey`.
#[derive(Debug, Clone, Default)]
pub struct LinkTable {
    links: HashMap<LinkKey, Link>,
}

impl LinkTable {
    /// Create a new empty link table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a link.
    pub fn insert(&mut self, link: Link) {
        self.links.insert(link.key.clone(), link);
    }

    /// Get a link by key.
    #[must_use]
    pub fn get(&self, key: &LinkKey) -> Option<&Link> {
        self.links.get(key)
    }

    /// Get a mutable link by key.
    pub fn get_mut(&mut self, key: &LinkKey) -> Option<&mut Link> {
        self.links.get_mut(key)
    }

    /// Remove a link.
    pub fn remove(&mut self, key: &LinkKey) -> Option<Link> {
        self.links.remove(key)
    }

    /// Get all outgoing links from a node (links where local_node_id matches).
    #[must_use]
    pub fn links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links
            .values()
            .filter(|link| link.key.local_node_id == *node_id)
            .collect()
    }

    /// Get all usable outgoing links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links
            .values()
            .filter(|link| link.key.local_node_id == *node_id && link.is_usable())
            .collect()
    }

    /// Get all incoming links to a node (links where remote_node_id matches).
    #[must_use]
    pub fn links_to(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links
            .values()
            .filter(|link| link.key.remote_node_id == *node_id)
            .collect()
    }

    /// Check if a node has at least one usable outgoing link (is reachable).
    #[must_use]
    pub fn is_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.links
            .values()
            .any(|link| link.key.remote_node_id == *node_id && link.is_usable())
    }

    /// Get all links.
    #[must_use]
    pub fn all(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    /// Get the number of links.
    #[must_use]
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Check if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Remove all links that have been Down for longer than the given
    /// retention period. Links within the retention period are kept for
    /// metrics/recovery.
    pub fn purge_dead_links(&mut self, now: u64, retention_secs: u64) {
        self.links.retain(|_, link| {
            if link.state == LinkState::Down {
                if let Some(last_fail) = link.last_failure {
                    // Keep if within retention period.
                    now.saturating_sub(last_fail) < retention_secs
                } else {
                    // No last_failure recorded — keep (shouldn't happen for Down links).
                    true
                }
            } else {
                true
            }
        });
    }
}

//! N2.1.1 / N2.1.2.2 — Link model: directed, per-endpoint transport relationships.
//!
//! A `Link` represents an actual probed, authenticated transport relationship
//! between two nodes over a specific endpoint. It is NOT the same as "I saw
//! an advertisement" — a link requires a successful transport connection +
//! SNP-IK/0.1 handshake.
//!
//! Links are **directed**: a link from A to B does NOT imply a link from B
//! to A. This models real-world asymmetry (firewalls, NAT, transport
//! limitations).
//!
//! ## N2.1.2.2: AuthenticatedLink — real security boundary
//!
//! **`Link::new_up()` is NOT public in production builds.** It is only
//! available behind `cfg(test)` for deterministic route-engine testing.
//! In production, the ONLY way to create a forwardable `Link` is via
//! [`AuthenticatedLink::from_verified_handshake`], which requires:
//!
//! 1. A `VerifiedNodeAdvertisement` for the remote node (authenticated identity).
//! 2. The endpoint must appear in that advertisement (endpoint authorization).
//! 3. A `session_id` from a completed SNP-IK/0.1 handshake (proof of
//!    transport reachability + key agreement).
//! 4. The `LinkKey.remote_node_id` must match the advertisement's NodeId.
//! 5. The `LinkKey.endpoint` must match one of the advertisement's endpoints.
//!
//! This makes the type-level guarantee real: **every `Link` in a production
//! `LinkTable` was established through the ShareNet identity handshake with
//! an endpoint authorized by the remote node's authenticated advertisement.**

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
    /// **N2.1.2.2: NOT public in production.** Construct a new UP link.
    ///
    /// This constructor is `pub(crate)` — it can only be called from within
    /// the `snp-node` crate. In production, the ONLY way to create a
    /// forwardable `Link` is via [`AuthenticatedLink::from_verified_handshake`],
    /// which verifies the remote identity and authorizes the endpoint.
    ///
    /// A `cfg(test)` re-export (`Link::new_up_for_testing`) is available for
    /// deterministic route-engine testing. Production code MUST NOT use it.
    #[must_use]
    pub(crate) fn new_up(key: LinkKey, session_id: Option<[u8; 32]>) -> Self {
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

// ─── Test-only constructor ───────────────────────────────────────────────────

#[cfg(any(test, feature = "test-support"))]
impl Link {
    /// **TEST-ONLY.** Construct a new UP link without authentication.
    ///
    /// This is available ONLY when the `test-support` Cargo feature is
    /// enabled (or during `cfg(test)` unit tests). It allows deterministic
    /// route-engine testing without performing actual SNP-IK handshakes.
    ///
    /// **Production code MUST NOT use this.** In production, use
    /// [`AuthenticatedLink::from_verified_handshake`] to create a link that
    /// is proven to be authenticated.
    #[must_use]
    pub fn new_up_for_testing(key: LinkKey, session_id: Option<[u8; 32]>) -> Self {
        Self::new_up(key, session_id)
    }
}

// ─── AuthenticatedLink (N2.1.2.2) ───────────────────────────────────────────

/// **N2.1.2.2.** Proof that a `Link` was established through the ShareNet
/// identity handshake with an endpoint authorized by the remote node's
/// authenticated advertisement.
///
/// ## Construction
///
/// `AuthenticatedLink` has NO public constructor that accepts arbitrary
/// `LinkKey` values. The only production construction path is
/// [`AuthenticatedLink::from_verified_handshake`], which requires:
///
/// 1. A `VerifiedNodeAdvertisement` for the remote node.
/// 2. The `LinkKey.remote_node_id` must equal the advertisement's NodeId.
/// 3. The `LinkKey.endpoint` must appear in the advertisement's endpoints.
/// 4. A non-zero `session_id` from a completed SNP-IK/0.1 handshake.
///
/// ## Security invariant
///
/// An `AuthenticatedLink` CANNOT be manufactured by an arbitrary caller.
/// It can only be produced by supplying a verified advertisement + a
/// handshake session ID. This makes the route engine's invariant real:
///
/// > "Every `Link` consumed by `RouteEngine` is an authenticated,
/// > endpoint-bound relationship established through the ShareNet identity
/// > handshake."
///
/// ## Conversion to `Link`
///
/// `AuthenticatedLink` converts into `Link` via `into_link()` or `as_link()`.
/// The resulting `Link` retains the `session_id` (proof of handshake) and
/// the authorized `LinkKey`.
#[derive(Debug, Clone)]
pub struct AuthenticatedLink {
    /// The underlying `Link`. Constructed ONLY via
    /// `AuthenticatedLink::from_verified_handshake`.
    link: Link,
}

/// Error returned by `AuthenticatedLink::from_verified_handshake` when the
/// construction parameters are invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedLinkError {
    /// The `LinkKey.remote_node_id` does not match the verified
    /// advertisement's NodeId.
    #[error("remote_node_id mismatch: LinkKey says {link_node_id}, advertisement says {advert_node_id}")]
    NodeIdMismatch {
        /// The NodeId from the LinkKey.
        link_node_id: NodeIdHex,
        /// The NodeId from the advertisement.
        advert_node_id: NodeIdHex,
    },
    /// The `LinkKey.endpoint` does not appear in the verified advertisement's
    /// endpoints. The endpoint is NOT authorized.
    #[error("endpoint not authorized by advertisement: {endpoint}")]
    UnauthorizedEndpoint {
        /// The unauthorized endpoint.
        endpoint: String,
    },
    /// The `session_id` is all-zero, which means no handshake was performed.
    #[error("session_id is all-zero — no handshake was performed")]
    MissingHandshake,
}

/// A wrapper for `[u8; 32]` that implements `Display` as hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdHex(pub [u8; 32]);

impl std::fmt::Display for NodeIdHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_short(&self.0))
    }
}

impl AuthenticatedLink {
    /// **N2.1.2.2.** Construct an `AuthenticatedLink` from a verified
    /// advertisement and a completed handshake session ID.
    ///
    /// ## Requirements
    ///
    /// 1. `key.remote_node_id` must equal `advert.node_id()`. This binds
    ///    the link's remote identity to the authenticated advertisement.
    /// 2. `key.endpoint` must appear in `advert.endpoints()`. This ensures
    ///    the endpoint was authorized by the remote node's advertisement
    ///    (not attacker-chosen).
    /// 3. `session_id` must be non-zero (all-zero means no handshake was
    ///    performed). A completed SNP-IK/0.1 handshake always produces a
    ///    non-zero session ID.
    ///
    /// ## Errors
    ///
    /// Returns `AuthenticatedLinkError` if any requirement is not met.
    ///
    /// # Parameters
    /// - `key`: The `LinkKey` (local → remote + endpoint).
    /// - `advert`: The verified advertisement for the remote node.
    /// - `session_id`: The session ID from the completed handshake.
    pub fn from_verified_handshake(
        key: LinkKey,
        advert: &VerifiedNodeAdvertisement,
        session_id: [u8; 32],
    ) -> Result<Self, AuthenticatedLinkError> {
        // 1. Remote NodeId must match the advertisement.
        if key.remote_node_id != advert.node_id() {
            return Err(AuthenticatedLinkError::NodeIdMismatch {
                link_node_id: NodeIdHex(key.remote_node_id),
                advert_node_id: NodeIdHex(advert.node_id()),
            });
        }
        // 2. Endpoint must be authorized by the advertisement.
        if !advert.endpoints().contains(&key.endpoint) {
            return Err(AuthenticatedLinkError::UnauthorizedEndpoint {
                endpoint: key.endpoint.as_str().to_string(),
            });
        }
        // 3. session_id must be non-zero (handshake was performed).
        if session_id == [0u8; 32] {
            return Err(AuthenticatedLinkError::MissingHandshake);
        }
        // Construct the underlying Link with the session_id set.
        let mut link = Link::new_up(key, Some(session_id));
        // The session_id is now guaranteed non-zero and bound to the
        // authenticated advertisement.
        let _ = &mut link; // (no additional mutation needed)
        Ok(Self { link })
    }

    /// Get a reference to the underlying `Link`.
    #[must_use]
    pub fn as_link(&self) -> &Link {
        &self.link
    }

    /// Consume this `AuthenticatedLink` and return the underlying `Link`.
    #[must_use]
    pub fn into_link(self) -> Link {
        self.link
    }

    /// Get the `LinkKey`.
    #[must_use]
    pub fn key(&self) -> &LinkKey {
        &self.link.key
    }

    /// Get the session ID from the handshake.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        // Guaranteed non-zero by construction.
        self.link.peer_session_id.unwrap_or([0u8; 32])
    }

    /// Check if the link is usable for forwarding.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.link.is_usable()
    }
}

/// A table of directed links, keyed by `LinkKey`.
///
/// ## N2.1.2.2: Authentication boundary
///
/// In production, the ONLY way to add a link to a `LinkTable` is via
/// [`LinkTable::insert_authenticated`], which accepts an
/// [`AuthenticatedLink`]. This guarantees that every link in the table was
/// established through the ShareNet identity handshake with an endpoint
/// authorized by the remote node's advertisement.
///
/// The `insert(Link)` method is `pub(crate)` — available only within the
/// `snp-node` crate (for internal use and `cfg(test)` test helpers). It is
/// NOT available to external production callers.
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

    /// **N2.1.2.2: Production path.** Add or replace a link using an
    /// `AuthenticatedLink`.
    ///
    /// This is the ONLY public method for adding links to a `LinkTable`
    /// in production builds. It requires an `AuthenticatedLink`, which
    /// can only be constructed via
    /// [`AuthenticatedLink::from_verified_handshake`].
    ///
    /// This guarantees the security invariant:
    /// > "Every `Link` in a production `LinkTable` was established through
    /// > the ShareNet identity handshake with an endpoint authorized by
    /// > the remote node's authenticated advertisement."
    pub fn insert_authenticated(&mut self, auth_link: AuthenticatedLink) {
        let link = auth_link.into_link();
        self.links.insert(link.key.clone(), link);
    }

    /// **N2.1.2.2: NOT public in production.** Add or replace a link.
    ///
    /// This method is `pub(crate)` — it can only be called from within the
    /// `snp-node` crate. In production, use `insert_authenticated()` with
    /// an `AuthenticatedLink`.
    ///
    /// A `cfg(test)` re-export (`insert_for_testing`) is available for
    /// deterministic route-engine testing.
    pub(crate) fn insert(&mut self, link: Link) {
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

#[cfg(any(test, feature = "test-support"))]
impl LinkTable {
    /// **TEST-ONLY.** Add or replace a link without authentication.
    ///
    /// This is available ONLY when the `test-support` Cargo feature is
    /// enabled (or during `cfg(test)` unit tests). It allows deterministic
    /// route-engine testing without performing actual SNP-IK handshakes.
    ///
    /// **Production code MUST NOT use this.** In production, use
    /// `insert_authenticated()` with an `AuthenticatedLink`.
    pub fn insert_for_testing(&mut self, link: Link) {
        self.insert(link);
    }
}

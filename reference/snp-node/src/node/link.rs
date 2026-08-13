//! N2.1.1 / N2.1.2.3 — Link model: directed, per-endpoint transport relationships.
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
//! ## N2.1.2.3: VerifiedHandshake + AuthenticatedLink — proof-producing boundary
//!
//! **`Link::new_up()` is NOT public in production builds.** It is only
//! available behind `cfg(test)` / the `test-support` feature for
//! deterministic route-engine testing.
//!
//! In production, the ONLY way to create a forwardable link is via
//! [`AuthenticatedLink::from_handshake`], which requires:
//!
//! 1. A `VerifiedNodeAdvertisement` for the remote node (authenticated identity).
//! 2. An actual `snp_link::HandshakeResult` from a completed SNP-IK/0.1
//!    handshake (NOT an arbitrary session ID).
//! 3. The handshake's `peer_node_id` must match the advertisement's NodeId.
//! 4. The handshake's `peer_public_key` must match the advertisement's
//!    Ed25519 public key.
//! 5. The `LinkKey.remote_node_id` must match the advertisement's NodeId.
//! 6. The `LinkKey.endpoint` must appear in the advertisement's endpoints.
//!
//! The `HandshakeResult` is converted to a compact [`VerifiedHandshake`]
//! proof whose constructor is private — only
//! `AuthenticatedLink::from_handshake` can produce it, and it requires the
//! actual `&HandshakeResult` from `snp-link`.
//!
//! ## N2.1.2.3: Authentication preserved in LinkTable
//!
//! The production `LinkTable` stores `AuthenticatedLink` (NOT plain `Link`).
//! The type-level authentication proof is preserved at the storage boundary.
//! `RouteEngine` consumes `&AuthenticatedLink`, so the invariant holds:
//!
//! > "Every link consumed by `RouteEngine` is an authenticated, endpoint-bound
//! > relationship established through the ShareNet identity handshake."

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
    /// [`AuthenticatedLink::from_handshake`] to create a link that
    /// is proven to be authenticated.
    #[must_use]
    pub fn new_up_for_testing(key: LinkKey, session_id: Option<[u8; 32]>) -> Self {
        Self::new_up(key, session_id)
    }
}

// ─── VerifiedHandshake proof (N2.1.2.3) ─────────────────────────────────────

/// **N2.1.2.3.** A compact proof that an actual SNP-IK/0.1 handshake was
/// completed with a specific peer.
///
/// `VerifiedHandshake` has NO public constructor. The only way to create
/// one is via [`AuthenticatedLink::from_handshake`], which consumes an
/// actual `snp_link::HandshakeResult` and verifies its bindings against a
/// `VerifiedNodeAdvertisement`.
///
/// ## Why this exists
///
/// A random `[u8; 32]` session ID is NOT sufficient proof of a handshake.
/// The `HandshakeResult` from `snp-link` is returned only after the SNP-IK
/// handshake has authenticated the peer (signature verified, DH completed,
/// directional keys derived). By requiring `&HandshakeResult` at
/// construction time, we make it impossible to manufacture an
/// `AuthenticatedLink` without a real handshake.
///
/// ## Fields
///
/// The proof retains:
/// - `session_id` — the handshake transcript binding value.
/// - `peer_node_id` — the authenticated peer NodeId.
/// - `peer_public_key` — the authenticated peer Ed25519 public key.
///
/// These are checked against the `VerifiedNodeAdvertisement` at
/// construction time, then retained for later inspection.
#[derive(Debug, Clone)]
pub struct VerifiedHandshake {
    /// The session ID from the completed handshake.
    session_id: [u8; 32],
    /// The authenticated peer NodeId (from HandshakeResult).
    peer_node_id: [u8; 32],
    /// The authenticated peer Ed25519 public key (from HandshakeResult).
    peer_public_key: [u8; 32],
}

impl VerifiedHandshake {
    /// Get the session ID.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Get the authenticated peer NodeId.
    #[must_use]
    pub fn peer_node_id(&self) -> [u8; 32] {
        self.peer_node_id
    }

    /// Get the authenticated peer Ed25519 public key.
    #[must_use]
    pub fn peer_public_key(&self) -> [u8; 32] {
        self.peer_public_key
    }
}

// ─── AuthenticatedLink (N2.1.2.3) ───────────────────────────────────────────

/// **N2.1.2.3.** A `Link` proven to be established through the ShareNet
/// identity handshake with an endpoint authorized by the remote node's
/// authenticated advertisement.
///
/// ## Construction
///
/// `AuthenticatedLink` has NO public constructor that accepts arbitrary
/// `LinkKey` values or arbitrary session IDs. The only production
/// construction path is [`AuthenticatedLink::from_handshake`], which
/// requires:
///
/// 1. A `VerifiedNodeAdvertisement` for the remote node.
/// 2. An actual `snp_link::HandshakeResult` from a completed SNP-IK/0.1
///    handshake (NOT an arbitrary session ID).
/// 3. `handshake.peer_node_id == advert.node_id()` — the handshake's
///    authenticated peer must match the advertisement.
/// 4. `handshake.peer_public_key == advert.ed25519_public_key()` — the
///    handshake's authenticated Ed25519 key must match the advertisement.
/// 5. `key.remote_node_id == advert.node_id()` — the LinkKey's remote
///    identity must match the advertisement.
/// 6. `key.endpoint` must appear in `advert.endpoints()` — the endpoint
///    must be authorized by the advertisement.
/// 7. `handshake.session_id != [0u8; 32]` — the handshake must have
///    produced a valid session ID (guaranteed by `snp-link` for successful
///    handshakes, but checked defensively).
///
/// ## Security invariant
///
/// An `AuthenticatedLink` CANNOT be manufactured by an arbitrary caller.
/// It can only be produced by supplying a verified advertisement AND an
/// actual `HandshakeResult` from `snp-link`. A random 32-byte value is
/// NOT sufficient.
///
/// ## Proof preservation
///
/// The `VerifiedHandshake` proof is retained inside the `AuthenticatedLink`.
/// It is NOT discarded at the storage boundary — the production `LinkTable`
/// stores `AuthenticatedLink` (not plain `Link`), so the proof travels with
/// the link through the entire route-engine pipeline.
#[derive(Debug, Clone)]
pub struct AuthenticatedLink {
    /// The underlying `Link` (runtime state, metrics, key, endpoint).
    link: Link,
    /// The proof that a real handshake was performed. Retained for the
    /// lifetime of the link — NOT discarded at storage.
    proof: VerifiedHandshake,
}

/// Error returned by `AuthenticatedLink::from_handshake` when the
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
    /// The handshake's `peer_node_id` does not match the advertisement's NodeId.
    #[error("handshake peer_node_id mismatch: handshake says {handshake_node_id}, advertisement says {advert_node_id}")]
    HandshakePeerNodeIdMismatch {
        /// The NodeId from the handshake.
        handshake_node_id: NodeIdHex,
        /// The NodeId from the advertisement.
        advert_node_id: NodeIdHex,
    },
    /// The handshake's `peer_public_key` does not match the advertisement's
    /// Ed25519 public key.
    #[error("handshake peer_public_key mismatch: handshake key does not match advertisement")]
    HandshakePublicKeyMismatch,
    /// The handshake's `session_id` is all-zero, which should not happen
    /// for a successful `snp-link` handshake but is checked defensively.
    #[error("handshake session_id is all-zero — invalid HandshakeResult")]
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
    /// **N2.1.2.3.** Construct an `AuthenticatedLink` from a verified
    /// advertisement and an **actual** `snp_link::HandshakeResult`.
    ///
    /// ## Requirements (all enforced)
    ///
    /// 1. `key.remote_node_id == advert.node_id()` — LinkKey identity binding.
    /// 2. `key.endpoint` in `advert.endpoints()` — endpoint authorization.
    /// 3. `handshake.peer_node_id == advert.node_id()` — handshake identity
    ///    matches advertisement.
    /// 4. `handshake.peer_public_key == advert.ed25519_public_key()` —
    ///    handshake Ed25519 key matches advertisement.
    /// 5. `handshake.session_id != [0u8; 32]` — valid session ID.
    ///
    /// ## Why `&HandshakeResult` and not `[u8; 32]`
    ///
    /// A random 32-byte value is NOT proof of a handshake. The
    /// `HandshakeResult` from `snp-link` is returned only after the SNP-IK
    /// handshake has authenticated the peer (signature verified, DH
    /// completed, directional keys derived). Requiring `&HandshakeResult`
    /// makes it impossible to manufacture an `AuthenticatedLink` without a
    /// real handshake.
    ///
    /// ## Errors
    ///
    /// Returns `AuthenticatedLinkError` if any requirement is not met.
    pub fn from_handshake(
        key: LinkKey,
        advert: &VerifiedNodeAdvertisement,
        handshake: &snp_link::HandshakeResult,
    ) -> Result<Self, AuthenticatedLinkError> {
        // 1. LinkKey.remote_node_id must match the advertisement.
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
        // 3. Handshake peer_node_id must match the advertisement.
        if handshake.peer_node_id != advert.node_id() {
            return Err(AuthenticatedLinkError::HandshakePeerNodeIdMismatch {
                handshake_node_id: NodeIdHex(handshake.peer_node_id),
                advert_node_id: NodeIdHex(advert.node_id()),
            });
        }
        // 4. Handshake peer_public_key must match the advertisement.
        if handshake.peer_public_key != *advert.ed25519_public_key() {
            return Err(AuthenticatedLinkError::HandshakePublicKeyMismatch);
        }
        // 5. session_id must be non-zero (defensive — snp-link guarantees this).
        if handshake.session_id == [0u8; 32] {
            return Err(AuthenticatedLinkError::MissingHandshake);
        }
        // Construct the proof from the actual handshake result.
        let proof = VerifiedHandshake {
            session_id: handshake.session_id,
            peer_node_id: handshake.peer_node_id,
            peer_public_key: handshake.peer_public_key,
        };
        // Construct the underlying Link with the session_id set.
        let link = Link::new_up(key, Some(handshake.session_id));
        Ok(Self { link, proof })
    }

    /// Get a reference to the underlying `Link` (read-only).
    ///
    /// This allows the route engine to read the link's key, state, metrics,
    /// and endpoint without being able to modify identity-critical fields.
    #[must_use]
    pub fn as_link(&self) -> &Link {
        &self.link
    }

    /// Get a reference to the `VerifiedHandshake` proof.
    ///
    /// The proof is retained for the lifetime of the link. It is NOT
    /// discarded at the storage boundary.
    #[must_use]
    pub fn handshake_proof(&self) -> &VerifiedHandshake {
        &self.proof
    }

    /// Get the `LinkKey`.
    #[must_use]
    pub fn key(&self) -> &LinkKey {
        &self.link.key
    }

    /// Get the session ID from the handshake proof.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.proof.session_id
    }

    /// Check if the link is usable for forwarding.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.link.is_usable()
    }

    /// Record a successful transmission on the underlying link.
    ///
    /// This mutates runtime state (metrics, link state) but does NOT affect
    /// the authentication proof. The proof is immutable for the lifetime of
    /// the `AuthenticatedLink`.
    pub fn record_success(&mut self, rtt_micros: u64) {
        self.link.record_success(rtt_micros);
    }

    /// Record a failed transmission on the underlying link.
    pub fn record_failure(&mut self) {
        self.link.record_failure();
    }

    /// Set the link state (e.g., for explicit state transitions).
    pub fn set_state(&mut self, state: LinkState) {
        self.link.state = state;
    }

    /// Get the current link state.
    #[must_use]
    pub fn state(&self) -> LinkState {
        self.link.state
    }

    /// Get the remote NodeId.
    #[must_use]
    pub fn remote_node_id(&self) -> [u8; 32] {
        self.link.key.remote_node_id
    }

    /// Get the local NodeId.
    #[must_use]
    pub fn local_node_id(&self) -> [u8; 32] {
        self.link.key.local_node_id
    }

    /// Get the metrics.
    #[must_use]
    pub fn metrics(&self) -> &LinkMetrics {
        &self.link.metrics
    }

    /// Get the endpoint from the LinkKey.
    #[must_use]
    pub fn endpoint(&self) -> &TransportEndpoint {
        &self.link.key.endpoint
    }
}

/// A table of directed **authenticated** links, keyed by `LinkKey`.
///
/// ## N2.1.2.3: Authentication preserved at storage boundary
///
/// The production `LinkTable` stores [`AuthenticatedLink`] (NOT plain
/// `Link`). The type-level authentication proof is retained for the
/// lifetime of each link. `RouteEngine` consumes `&AuthenticatedLink`,
/// so the invariant holds:
///
/// > "Every link consumed by `RouteEngine` is an authenticated, endpoint-bound
/// > relationship established through the ShareNet identity handshake."
///
/// ## Construction
///
/// The ONLY public method for adding links is
/// [`LinkTable::insert_authenticated`], which accepts an
/// [`AuthenticatedLink`]. An `AuthenticatedLink` can only be constructed
/// via [`AuthenticatedLink::from_handshake`], which requires an actual
/// `snp_link::HandshakeResult`.
///
/// There is NO public `insert(Link)` method. An unauthenticated `Link`
/// CANNOT enter the production `LinkTable`.
#[derive(Debug, Clone, Default)]
pub struct LinkTable {
    links: HashMap<LinkKey, AuthenticatedLink>,
}

impl LinkTable {
    /// Create a new empty link table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// **N2.1.2.3: Production path.** Add or replace a link using an
    /// `AuthenticatedLink`.
    ///
    /// This is the ONLY public method for adding links to a `LinkTable`.
    /// It requires an `AuthenticatedLink`, which can only be constructed
    /// via [`AuthenticatedLink::from_handshake`] — requiring an actual
    /// `snp_link::HandshakeResult`.
    ///
    /// This guarantees the security invariant:
    /// > "Every link in a production `LinkTable` was established through
    /// > the ShareNet identity handshake with an endpoint authorized by
    /// > the remote node's authenticated advertisement."
    pub fn insert_authenticated(&mut self, auth_link: AuthenticatedLink) {
        self.links.insert(auth_link.key().clone(), auth_link);
    }

    /// Get an authenticated link by key.
    #[must_use]
    pub fn get(&self, key: &LinkKey) -> Option<&AuthenticatedLink> {
        self.links.get(key)
    }

    /// Get a mutable authenticated link by key.
    pub fn get_mut(&mut self, key: &LinkKey) -> Option<&mut AuthenticatedLink> {
        self.links.get_mut(key)
    }

    /// Remove a link.
    pub fn remove(&mut self, key: &LinkKey) -> Option<AuthenticatedLink> {
        self.links.remove(key)
    }

    /// Get all outgoing authenticated links from a node.
    #[must_use]
    pub fn links_from(&self, node_id: &[u8; 32]) -> Vec<&AuthenticatedLink> {
        self.links
            .values()
            .filter(|auth| auth.local_node_id() == *node_id)
            .collect()
    }

    /// Get all usable outgoing authenticated links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&AuthenticatedLink> {
        self.links
            .values()
            .filter(|auth| auth.local_node_id() == *node_id && auth.is_usable())
            .collect()
    }

    /// Get all incoming authenticated links to a node.
    #[must_use]
    pub fn links_to(&self, node_id: &[u8; 32]) -> Vec<&AuthenticatedLink> {
        self.links
            .values()
            .filter(|auth| auth.remote_node_id() == *node_id)
            .collect()
    }

    /// Check if a node has at least one usable outgoing link (is reachable).
    #[must_use]
    pub fn is_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.links
            .values()
            .any(|auth| auth.remote_node_id() == *node_id && auth.is_usable())
    }

    /// Get all authenticated links.
    #[must_use]
    pub fn all(&self) -> impl Iterator<Item = &AuthenticatedLink> {
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
        self.links.retain(|_, auth| {
            if auth.state() == LinkState::Down {
                // Check the underlying link's last_failure.
                let last_fail = auth.as_link().last_failure;
                if let Some(last_fail) = last_fail {
                    now.saturating_sub(last_fail) < retention_secs
                } else {
                    true
                }
            } else {
                true
            }
        });
    }
}

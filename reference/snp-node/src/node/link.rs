//! N2.1.1 / N2.1.2.4 — Link model: directed, per-endpoint transport relationships.
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
//! ## N2.1.2.4: Unforgeable handshake proof
//!
//! **`Link::new_up()` is NOT public in production builds.** The ONLY way to
//! create a forwardable link is via [`AuthenticatedLink::from_verified_handshake`],
//! which requires:
//!
//! 1. A `VerifiedNodeAdvertisement` for the remote node.
//! 2. An **unforgeable** `snp_link::VerifiedHandshake` — minted ONLY by
//!    `snp_link::perform_snp_ik_handshake_verified()`. This proof has
//!    private fields and a private constructor; external code CANNOT
//!    manufacture it.
//! 3. The handshake's `peer_node_id` must match the advertisement's NodeId.
//! 4. The handshake's `peer_public_key` must match the advertisement's
//!    Ed25519 public key.
//! 5. The handshake's `peer_x25519_public` must match the advertisement's
//!    X25519 circuit public key (when present, e.g. for gateways).
//! 6. The `LinkKey.remote_node_id` must match the advertisement's NodeId.
//! 7. The `LinkKey.endpoint` must appear in the advertisement's endpoints.
//!
//! ## N2.1.2.4: Authentication preserved in LinkTable
//!
//! The production `LinkTable` stores `AuthenticatedLink` (NOT plain `Link`).
//! The unforgeable proof is retained for the lifetime of each link.
//! `RouteEngine` consumes `&AuthenticatedLink`, so the invariant holds:
//!
//! > "Every link consumed by `RouteEngine` is an authenticated, endpoint-bound
//! > relationship established through the ShareNet identity handshake, with
//! > an unforgeable proof that the handshake occurred."

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

// ─── AuthenticatedLink (N2.1.2.4) ───────────────────────────────────────────

/// **N2.1.2.4.** A `Link` proven to be established through the ShareNet
/// identity handshake with an endpoint authorized by the remote node's
/// authenticated advertisement.
///
/// ## Construction
///
/// `AuthenticatedLink` has NO public constructor that accepts arbitrary
/// `LinkKey` values, arbitrary session IDs, or publicly-constructible
/// `HandshakeResult` structs. The only production construction path is
/// [`AuthenticatedLink::from_verified_handshake`], which requires:
///
/// 1. A `VerifiedNodeAdvertisement` for the remote node.
/// 2. An **unforgeable** `snp_link::VerifiedHandshake` — minted ONLY by
///    `snp_link::perform_snp_ik_handshake_verified()` (or the async
///    variant). This proof has private fields and a private constructor;
///    external code CANNOT manufacture it.
/// 3. `proof.peer_node_id() == advert.node_id()` — handshake identity.
/// 4. `proof.peer_public_key() == advert.ed25519_public_key()` — Ed25519 key.
/// 5. `proof.peer_x25519_public() == advert.circuit_x25519_pub()` — X25519
///    identity binding (when the advertisement has an X25519 key, e.g.
///    gateways).
/// 6. `key.remote_node_id == advert.node_id()` — LinkKey identity.
/// 7. `key.endpoint` in `advert.endpoints()` — endpoint authorization.
///
/// ## Security invariant (N2.1.2.4 — unforgeable)
///
/// An `AuthenticatedLink` CANNOT be manufactured by an arbitrary caller.
/// It can only be produced by supplying a verified advertisement AND an
/// unforgeable `snp_link::VerifiedHandshake` proof. A random 32-byte value
/// is NOT sufficient. A publicly-constructed `HandshakeResult` is NOT
/// sufficient. The proof MUST come from the actual handshake
/// implementation.
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
    /// The unforgeable proof that a real handshake was performed. Retained
    /// for the lifetime of the link — NOT discarded at storage.
    proof: snp_link::VerifiedHandshake,
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
    /// The handshake proof's `peer_node_id` does not match the advertisement's NodeId.
    #[error("handshake peer_node_id mismatch: handshake says {handshake_node_id}, advertisement says {advert_node_id}")]
    HandshakePeerNodeIdMismatch {
        /// The NodeId from the handshake.
        handshake_node_id: NodeIdHex,
        /// The NodeId from the advertisement.
        advert_node_id: NodeIdHex,
    },
    /// The handshake proof's `peer_public_key` does not match the advertisement's
    /// Ed25519 public key.
    #[error("handshake peer_public_key mismatch: handshake key does not match advertisement")]
    HandshakePublicKeyMismatch,
    /// The handshake proof's `peer_x25519_public` does not match the
    /// advertisement's X25519 circuit public key.
    #[error("handshake peer_x25519_public mismatch: handshake X25519 key does not match advertisement")]
    HandshakeX25519Mismatch,
    /// The handshake proof's `session_id` is all-zero, which should not
    /// happen for a successful `snp-link` handshake but is checked
    /// defensively.
    #[error("handshake session_id is all-zero — invalid VerifiedHandshake")]
    MissingHandshake,
    /// **N2.1.2.5.** The transport endpoint in the `LinkKey` does not match
    /// the actual transport endpoint used by the handshake (as recorded in
    /// the `VerifiedHandshake`'s `TransportBinding`).
    ///
    /// This prevents identity/location confusion: a caller cannot perform a
    /// handshake over endpoint A, then construct an `AuthenticatedLink`
    /// claiming endpoint B.
    #[error("transport binding mismatch: LinkKey says {link_endpoint}, handshake proof says {proof_endpoint}")]
    TransportBindingMismatch {
        /// The endpoint from the LinkKey.
        link_endpoint: String,
        /// The endpoint from the handshake proof's transport binding.
        proof_endpoint: String,
    },
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
    /// **N2.1.2.4.** Construct an `AuthenticatedLink` from a verified
    /// advertisement and an **unforgeable** `snp_link::VerifiedHandshake`.
    ///
    /// ## Requirements (all enforced)
    ///
    /// 1. `key.remote_node_id == advert.node_id()` — LinkKey identity binding.
    /// 2. `key.endpoint` in `advert.endpoints()` — endpoint authorization.
    /// 3. `proof.peer_node_id() == advert.node_id()` — handshake identity.
    /// 4. `proof.peer_public_key() == advert.ed25519_public_key()` — Ed25519 key.
    /// 5. `proof.peer_x25519_public() == advert.circuit_x25519_pub()` —
    ///    X25519 identity binding (when the advertisement has an X25519 key).
    /// 6. `proof.session_id() != [0u8; 32]` — valid session.
    ///
    /// ## Why `&VerifiedHandshake` and not `&HandshakeResult`
    ///
    /// `HandshakeResult` has public fields and can be constructed by anyone.
    /// `VerifiedHandshake` has private fields and a private constructor —
    /// only `snp_link::perform_snp_ik_handshake_verified()` can create it.
    /// This makes the proof **unforgeable**.
    ///
    /// ## X25519 binding
    ///
    /// When the advertisement has an X25519 circuit public key (mandatory
    /// for gateways), the handshake's authenticated `peer_x25519_public`
    /// MUST match. This prevents identity substitution where an attacker
    /// authenticates as node B but uses a different X25519 key.
    ///
    /// ## Errors
    ///
    /// Returns `AuthenticatedLinkError` if any requirement is not met.
    pub fn from_verified_handshake(
        key: LinkKey,
        advert: &VerifiedNodeAdvertisement,
        proof: &snp_link::VerifiedHandshake,
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
        if proof.peer_node_id() != advert.node_id() {
            return Err(AuthenticatedLinkError::HandshakePeerNodeIdMismatch {
                handshake_node_id: NodeIdHex(proof.peer_node_id()),
                advert_node_id: NodeIdHex(advert.node_id()),
            });
        }
        // 4. Handshake peer_public_key must match the advertisement.
        if proof.peer_public_key() != *advert.ed25519_public_key() {
            return Err(AuthenticatedLinkError::HandshakePublicKeyMismatch);
        }
        // 5. X25519 identity binding: when the advertisement has an X25519
        //    circuit public key, the handshake's peer_x25519_public MUST match.
        //    This is mandatory for gateways (they advertise X25519 for circuit
        //    establishment). For relays without X25519, this check is skipped.
        if let Some(advert_x25519) = advert.circuit_x25519_pub() {
            if proof.peer_x25519_public() != *advert_x25519 {
                return Err(AuthenticatedLinkError::HandshakeX25519Mismatch);
            }
        }
        // 6. session_id must be non-zero (defensive — snp-link guarantees this).
        if proof.session_id() == [0u8; 32] {
            return Err(AuthenticatedLinkError::MissingHandshake);
        }
        // 7. N2.1.2.5: Transport binding — the actual endpoint used by the
        //    handshake MUST match the LinkKey.endpoint. This prevents
        //    identity/location confusion: a caller cannot perform a handshake
        //    over endpoint A, then construct an AuthenticatedLink claiming
        //    endpoint B (even if B is also advertised).
        if !transport_endpoint_matches_binding(&key.endpoint, proof.transport_binding()) {
            return Err(AuthenticatedLinkError::TransportBindingMismatch {
                link_endpoint: key.endpoint.as_str().to_string(),
                proof_endpoint: proof.transport_binding().canonical_addr().to_string(),
            });
        }
        // Construct the underlying Link with the session_id set.
        let link = Link::new_up(key, Some(proof.session_id()));
        Ok(Self { link, proof: proof.clone() })
    }

    /// Get a reference to the underlying `Link` (read-only).
    #[must_use]
    pub fn as_link(&self) -> &Link {
        &self.link
    }

    /// Get a reference to the unforgeable `VerifiedHandshake` proof.
    ///
    /// The proof is retained for the lifetime of the link. It is NOT
    /// discarded at the storage boundary.
    #[must_use]
    pub fn handshake_proof(&self) -> &snp_link::VerifiedHandshake {
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
        self.proof.session_id()
    }

    /// Check if the link is usable for forwarding.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.link.is_usable()
    }

    /// Record a successful transmission on the underlying link.
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

// ─── Transport endpoint ↔ binding comparison (N2.1.2.5) ─────────────────────

/// **N2.1.2.5.** Compare a `TransportEndpoint` (from `snp-node`) with a
/// `TransportBinding` (from `snp-link`).
///
/// Returns `true` if they represent the same transport endpoint.
///
/// For TCP, the comparison canonicalizes both sides by parsing as a
/// `SocketAddr` and re-encoding. This ensures that `"127.0.0.1:12345"` and
/// `"127.0.0.1:12345"` match, and that IPv6 addresses are normalized
/// consistently.
///
/// For non-TCP transports (BLE, Wi-Fi Direct, Nearby Connections), a simple
/// string comparison is used (these transports are not yet implemented).
fn transport_endpoint_matches_binding(
    endpoint: &TransportEndpoint,
    binding: &snp_link::TransportBinding,
) -> bool {
    match (endpoint, binding.transport()) {
        (TransportEndpoint::Tcp(addr_str), snp_link::TransportType::Tcp) => {
            // Canonicalize both sides by parsing as SocketAddr.
            let endpoint_canon = canonicalize_tcp_addr_str(addr_str);
            let binding_canon = binding.canonical_addr();
            endpoint_canon == binding_canon
        }
        (TransportEndpoint::Ble(addr_str), snp_link::TransportType::Ble) => {
            endpoint.as_str() == binding.canonical_addr()
        }
        (TransportEndpoint::WifiDirect(addr_str), snp_link::TransportType::WifiDirect) => {
            endpoint.as_str() == binding.canonical_addr()
        }
        (TransportEndpoint::NearbyConnections(addr_str), snp_link::TransportType::NearbyConnections) => {
            endpoint.as_str() == binding.canonical_addr()
        }
        _ => false, // Transport type mismatch.
    }
}

/// Canonicalize a TCP address string by parsing it as a `SocketAddr`.
///
/// If parsing fails, return the original string (the caller will see a
/// mismatch, which is the safe behavior for an unparseable address).
fn canonicalize_tcp_addr_str(addr: &str) -> String {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(socket_addr) => match socket_addr {
            std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
            std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
        },
        Err(_) => addr.to_string(),
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

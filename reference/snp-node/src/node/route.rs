//! Route — first-class route object with explicit hop list and state machine.
//!
//! Extracted from node.rs for N2.0.3 Gate J (Node decomposition).
//!
//! **N2.0.7.2:** The Route now has ONE authoritative representation
//! (`hop_details`), a `RouteCommitment` (canonical hash of the authoritative
//! route representation), and full validation of `hop_details` including
//! NodeId ↔ Ed25519 consistency. The legacy `hops` field is REMOVED — it
//! is now a derived method (`route.hops()`) computed from `hop_details`.
//! Identity-critical fields are non-mutable; controlled mutation methods
//! are provided.

use super::*;

// ─── Route (Phase 5 — N2.0.3 first-class Route object) ───────────────────────

/// The state of a [`Route`] — the lifecycle of a multi-hop path from a
/// client to a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    /// The route has been proposed (e.g. by a routing algorithm) but no
    /// SNP-IK/0.1 handshakes have been performed yet.
    Proposed,
    /// One or more hop handshakes are in progress.
    Establishing,
    /// All hop handshakes have completed; the route is carrying frames.
    Active,
    /// The route is alive but has experienced a transient failure on one
    /// hop. The route MAY recover, or it MAY transition to `Migrating`.
    Degraded,
    /// The route is being migrated to a different path (e.g. one hop has
    /// failed and a new hop is being brought up). Frames may be re-routed
    /// through the new path.
    Migrating,
    /// The route has permanently failed. A new route MUST be proposed.
    Failed,
    /// The route has been gracefully closed.
    Closed,
}

/// Observed performance characteristics of a [`Route`]. Populated as the
/// route carries frames; used by the routing algorithm to rank alternative
/// routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMetrics {
    /// Number of hops in the route (`route.hop_details.len()`).
    pub hop_count: u32,
    /// Estimated one-way latency in milliseconds, if known. `None` until
    /// the first frame round-trips the route.
    pub estimated_latency_ms: Option<u64>,
    /// Estimated bandwidth in bits per second, if known. `None` until the
    /// first frame round-trips the route.
    pub bandwidth_bps: Option<u64>,
}

/// Errors from [`Route`] validation and state-machine transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// The route has no hops (`hop_details.is_empty()`).
    #[error("route is empty (no hop_details)")]
    Empty,
    /// The `source` field is all-zero (the client NodeId must be set).
    #[error("route source is unset (all-zero NodeId)")]
    SourceMismatch,
    /// The `destination` field is all-zero.
    #[error("route destination is unset (all-zero NodeId)")]
    DestinationMismatch,
    /// The `destination` field does not match `hop_details.last().descriptor.node_id()`.
    #[error("route destination does not match last hop descriptor NodeId")]
    DestinationDescriptorMismatch,
    /// A hop NodeId appears more than once (loop).
    #[error("route has a duplicate hop (loop): {0}")]
    DuplicateHop(String),
    /// The hop count exceeds the TTL max (16).
    #[error("route has too many hops: {0} > 16")]
    ExcessiveHopCount(usize),
    /// The route has expired (`expires_at <= now`).
    #[error("route has expired (expires_at={expires_at}, now={now})")]
    Expired {
        /// The route's `expires_at` timestamp.
        expires_at: u64,
        /// The `now` timestamp the check was made against.
        now: u64,
    },
    /// The state transition is illegal.
    #[error("illegal route transition: {from:?} → {to:?}")]
    IllegalTransition {
        /// The state the route is currently in.
        from: RouteState,
        /// The state the caller attempted to transition to.
        to: RouteState,
    },
    /// **N2.0.7.2.** A hop descriptor's NodeId does not match
    /// `SHA-256("SNP/0.1 node\0" || ed25519_public_key)` (invariant I4 violation).
    #[error("hop {hop_index} descriptor NodeId does not match SHA-256 of Ed25519 public key (I4 violation)")]
    NodeIdInconsistent { hop_index: usize },
    /// **N2.0.7.2.** The destination hop does not have the Gateway capability.
    #[error("destination hop does not have the Gateway capability")]
    DestinationNotGateway,
    /// **N2.0.7.2.** The destination hop (gateway) does not have an X25519 circuit public key.
    #[error("destination gateway descriptor has no X25519 circuit public key")]
    GatewayMissingCircuitKey,
    /// **N2.0.7.2.** A relay hop incorrectly advertises an X25519 circuit public key.
    #[error("relay hop {hop_index} incorrectly advertises an X25519 circuit key (only gateways should have one)")]
    RelayHasCircuitKey { hop_index: usize },
    /// **N2.0.7.2.** A hop has no endpoints (cannot connect).
    #[error("hop {hop_index} has no endpoints (cannot connect)")]
    HopMissingEndpoint { hop_index: usize },
}

/// Default route lifetime: 1 hour (matches the advertisement TTL).
const ROUTE_DEFAULT_TTL_SECS: u64 = 3600;

/// Maximum hop count (matches `FRAME_TTL_MAX` from `snp-frames`).
const ROUTE_MAX_HOPS: usize = 16;

/// **N2.0.7.2.** A `RouteCommitment` is a canonical hash of the AUTHORITATIVE
/// route representation. It commits to:
///
/// - Protocol version
/// - Source NodeId
/// - Destination NodeId
/// - Route epoch
/// - Ordered hop identities (NodeId + Ed25519 pub + X25519 circuit pub + capabilities)
/// - Selected transport endpoints
///
/// Two routes with different relay paths, different endpoints, or different
/// identity keys produce DIFFERENT commitments. Changing a selected endpoint
/// changes the commitment.
///
/// The commitment is computed via `SHA-256(canonical_encoding)` where the
/// canonical encoding is a deterministic byte sequence (NOT arbitrary in-memory
/// serialization). This ensures that the same route produces the same
/// commitment regardless of the platform or memory layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteCommitment([u8; 32]);

impl RouteCommitment {
    /// Compute the `RouteCommitment` from the authoritative route representation.
    #[must_use]
    pub fn compute(
        source: &[u8; 32],
        destination: &[u8; 32],
        epoch: u64,
        hop_details: &[RouteHop],
    ) -> Self {
        let mut buf = Vec::new();
        // Protocol version.
        buf.extend_from_slice(b"SNP/0.1 route commitment v1\0");
        // Source NodeId.
        buf.extend_from_slice(source);
        // Destination NodeId.
        buf.extend_from_slice(destination);
        // Epoch.
        buf.extend_from_slice(&epoch.to_be_bytes());
        // Ordered hop identities + endpoints.
        for hop in hop_details {
            buf.extend_from_slice(&hop.descriptor.canonical_encoding());
            for endpoint in &hop.endpoints {
                buf.extend_from_slice(&endpoint.canonical_encoding());
            }
            // Separator between hops.
            buf.push(0xFF);
        }
        Self(snp_crypto::sha256(&buf))
    }

    /// Get the 32-byte commitment.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// **N2.0.7.** A single hop in a [`Route`]. Carries the hop's
/// [`VerifiedNodeDescriptor`] (the authenticated identity) AND its current
/// transport endpoint(s) (locators that can change over time).
///
/// **N2.0.7.2:** The `descriptor` field is now a `VerifiedNodeDescriptor`
/// (not an `UnverifiedNodeDescriptor`). This means the identity data has
/// been verified to come from a signed advertisement AND the NodeId ↔
/// Ed25519 consistency has been checked. The routing layer can trust that
/// the identity is authentic.
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// The hop's VERIFIED identity descriptor. Obtained from a VERIFIED
    /// discovery source (e.g. `GatewayAdvertisement` whose signature was
    /// checked AND whose NodeId ↔ Ed25519 consistency was verified).
    pub descriptor: VerifiedNodeDescriptor,
    /// The hop's current transport endpoint(s). Each entry is a
    /// transport-neutral [`TransportEndpoint`] (NOT an informal string).
    pub endpoints: Vec<TransportEndpoint>,
}

impl RouteHop {
    /// Construct a `RouteHop` with a `VerifiedNodeDescriptor` + a single endpoint.
    #[must_use]
    pub fn new(descriptor: VerifiedNodeDescriptor, endpoint: TransportEndpoint) -> Self {
        Self {
            descriptor,
            endpoints: vec![endpoint],
        }
    }

    /// Construct a `RouteHop` with a `VerifiedNodeDescriptor` + multiple endpoints.
    #[must_use]
    pub fn with_endpoints(
        descriptor: VerifiedNodeDescriptor,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        Self {
            descriptor,
            endpoints,
        }
    }

    /// Get the first endpoint (or `None` if empty).
    #[must_use]
    pub fn first_endpoint(&self) -> Option<&TransportEndpoint> {
        self.endpoints.first()
    }

    /// Get the NodeId (convenience — delegates to the descriptor).
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.descriptor.node_id()
    }
}

/// A multi-hop route from a client to a gateway.
///
/// **N2.0.7.2:** The Route now has ONE authoritative representation:
/// `hop_details`. The legacy `hops` field is REMOVED — it is now a derived
/// method (`route.hops()`). Identity-critical fields (`source`, `destination`,
/// `hop_details`, `epoch`, `route_commitment`) are non-mutable — they are
/// set at construction time and cannot be freely modified. Controlled
/// mutation is provided via `transition()` (state machine) and
/// `increment_epoch()` (key rotation).
///
/// The `route_commitment` is a canonical hash of the authoritative route
/// representation — it commits to the source, destination, epoch, ordered
/// hop identities, and selected endpoints. Two routes with different relay
/// paths or different endpoints produce different commitments.
#[derive(Debug, Clone)]
pub struct Route {
    /// The route commitment — `SHA-256(canonical_encoding)`. Computed at
    /// construction time; cannot be modified.
    route_commitment: RouteCommitment,
    /// The client NodeId (the route's source). Non-mutable.
    source: [u8; 32],
    /// The destination gateway NodeId. Non-mutable.
    destination: [u8; 32],
    /// The ordered list of `RouteHop` entries. This is the AUTHORITATIVE
    /// routing plan. Non-mutable. Empty for legacy routes (constructed via
    /// the deprecated `Route::new`).
    hop_details: Vec<RouteHop>,
    /// Legacy raw hop NodeIds. Only populated by the deprecated `Route::new`
    /// constructor (for backward compat with tests that don't use
    /// `VerifiedNodeDescriptor`). Empty for routes constructed via
    /// `new_with_hop_details`.
    legacy_hops: Vec<[u8; 32]>,
    /// The route epoch — incremented on every key rotation or migration.
    epoch: u64,
    /// The current state of the route (mutable via `transition()`).
    state: RouteState,
    /// When the route was created (unix seconds).
    created_at: u64,
    /// When the route expires (unix seconds).
    expires_at: u64,
    /// Observed performance characteristics (mutable).
    metrics: RouteMetrics,
    /// When the route was last validated.
    last_validated: u64,
}

impl Route {
    /// **N2.0.7.2 production constructor.** Construct a `Route` with
    /// `RouteHop` entries that carry `VerifiedNodeDescriptor` +
    /// `TransportEndpoint`s. This is the AUTHORITATIVE routing plan.
    ///
    /// The `route_commitment` is computed at construction time from the
    /// canonical encoding of the source, destination, epoch, and hop_details.
    ///
    /// The `hop_details` list MUST include the destination as the last
    /// element.
    ///
    /// # Panics
    /// Never panics for well-formed inputs.
    #[must_use]
    pub fn new_with_hop_details(
        source: [u8; 32],
        destination: [u8; 32],
        hop_details: Vec<RouteHop>,
    ) -> Self {
        let now = now_unix();
        let epoch = 0u64;
        let route_commitment =
            RouteCommitment::compute(&source, &destination, epoch, &hop_details);
        let hop_count = u32::try_from(hop_details.len()).unwrap_or(u32::MAX);
        Self {
            route_commitment,
            source,
            destination,
            hop_details,
            legacy_hops: Vec::new(),
            epoch,
            state: RouteState::Proposed,
            created_at: now,
            expires_at: now.saturating_add(ROUTE_DEFAULT_TTL_SECS),
            metrics: RouteMetrics {
                hop_count,
                estimated_latency_ms: None,
                bandwidth_bps: None,
            },
            last_validated: 0,
        }
    }

    /// **N2.0.7.2 backward-compat constructor.** Construct a `Route` from
    /// raw NodeIds (without endpoints or verified descriptors). This
    /// constructor is for legacy tests that don't use the route-authoritative
    /// path. The `hop_details` will be EMPTY — the route cannot be used
    /// with `send_via_route`.
    ///
    /// **Deprecated:** Use [`Route::new_with_hop_details`] for production.
    #[deprecated(
        since = "N2.0.7.2",
        note = "use `Route::new_with_hop_details` — routes must carry verified descriptors + endpoints"
    )]
    #[must_use]
    pub fn new(source: [u8; 32], destination: [u8; 32], hops: Vec<[u8; 32]>) -> Self {
        let now = now_unix();
        let epoch = 0u64;
        // Compute a legacy route_commitment from the raw NodeIds.
        let mut id_input = Vec::with_capacity(32 + 32 + hops.len() * 32 + 16);
        id_input.extend_from_slice(&source);
        id_input.extend_from_slice(&destination);
        for hop in &hops {
            id_input.extend_from_slice(hop);
        }
        id_input.extend_from_slice(b"legacy\0");
        let route_commitment = RouteCommitment(snp_crypto::sha256(&id_input));
        let hop_count = u32::try_from(hops.len()).unwrap_or(u32::MAX);
        let _ = epoch;
        Self {
            route_commitment,
            source,
            destination,
            hop_details: Vec::new(),
            legacy_hops: hops,
            epoch: 0,
            state: RouteState::Proposed,
            created_at: now,
            expires_at: now.saturating_add(ROUTE_DEFAULT_TTL_SECS),
            metrics: RouteMetrics {
                hop_count,
                estimated_latency_ms: None,
                bandwidth_bps: None,
            },
            last_validated: 0,
        }
    }

    // ─── Accessors (read-only — fields are non-mutable) ──────────────────

    /// Get the route commitment.
    #[must_use]
    pub fn route_commitment(&self) -> &RouteCommitment {
        &self.route_commitment
    }

    /// Get the source NodeId.
    #[must_use]
    pub fn source(&self) -> [u8; 32] {
        self.source
    }

    /// Get the destination NodeId.
    #[must_use]
    pub fn destination(&self) -> [u8; 32] {
        self.destination
    }

    /// **N2.0.7.2.** Get the ordered list of hop NodeIds, DERIVED from
    /// `hop_details` (or `legacy_hops` for legacy routes). This replaces
    /// the legacy `hops` field — it is now a computed value, not
    /// independently stored mutable state.
    #[must_use]
    pub fn hops(&self) -> Vec<[u8; 32]> {
        if !self.hop_details.is_empty() {
            self.hop_details.iter().map(|h| h.node_id()).collect()
        } else {
            self.legacy_hops.clone()
        }
    }

    /// Get the hop_details (the authoritative routing plan).
    #[must_use]
    pub fn hop_details(&self) -> &[RouteHop] {
        &self.hop_details
    }

    /// Get the epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the route state.
    #[must_use]
    pub fn state(&self) -> RouteState {
        self.state
    }

    /// Get the last_validated timestamp.
    #[must_use]
    pub fn last_validated(&self) -> u64 {
        self.last_validated
    }

    /// Get the creation time.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the expiration time.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Get the metrics.
    #[must_use]
    pub fn metrics(&self) -> &RouteMetrics {
        &self.metrics
    }

    /// Get the `RouteHop` at position `i`.
    #[must_use]
    pub fn hop(&self, i: usize) -> Option<&RouteHop> {
        self.hop_details.get(i)
    }

    /// Get the first hop's endpoint.
    #[must_use]
    pub fn first_hop_endpoint(&self) -> Option<&TransportEndpoint> {
        self.hop_details
            .first()
            .and_then(|h| h.first_endpoint())
    }

    /// Get the destination hop's `VerifiedNodeDescriptor`.
    #[must_use]
    pub fn destination_descriptor(&self) -> Option<&VerifiedNodeDescriptor> {
        self.hop_details.last().map(|h| &h.descriptor)
    }

    /// Check whether this Route has `hop_details` (i.e. was constructed via
    /// `new_with_hop_details`).
    #[must_use]
    pub fn has_endpoints(&self) -> bool {
        !self.hop_details.is_empty()
    }

    // ─── Controlled mutation ─────────────────────────────────────────────

    /// Transition the route to a new state. Returns `Ok(())` on a legal
    /// transition, `Err(RouteError::IllegalTransition)` on an illegal one.
    pub fn transition(&mut self, new_state: RouteState) -> Result<(), RouteError> {
        use RouteState::*;
        let allowed = matches!(
            (self.state, new_state),
            (Proposed, Establishing)
                | (Proposed, Closed)
                | (Proposed, Failed)
                | (Establishing, Active)
                | (Establishing, Failed)
                | (Establishing, Closed)
                | (Active, Degraded)
                | (Active, Migrating)
                | (Active, Closed)
                | (Active, Failed)
                | (Degraded, Active)
                | (Degraded, Migrating)
                | (Degraded, Failed)
                | (Degraded, Closed)
                | (Migrating, Active)
                | (Migrating, Failed)
                | (Migrating, Closed)
                | (Failed, Closed)
                | (Closed, Closed)
        );
        if !allowed {
            return Err(RouteError::IllegalTransition {
                from: self.state,
                to: new_state,
            });
        }
        self.state = new_state;
        if new_state == Active {
            self.last_validated = now_unix();
        }
        Ok(())
    }

    /// N2.0.2 backward-compat: transition the route to a new state, returning
    /// `NodeResult<()>`.
    pub fn transition_to(&mut self, new_state: RouteState) -> NodeResult<()> {
        self.transition(new_state)
            .map_err(|e| NodeError::Other(format!("Route transition error: {e}")))
    }

    /// Increment the epoch (key rotation / migration). This changes the
    /// route's identity — a new `route_commitment` is computed.
    pub fn increment_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.route_commitment = RouteCommitment::compute(
            &self.source,
            &self.destination,
            self.epoch,
            &self.hop_details,
        );
    }

    /// Update the metrics (observed performance).
    pub fn update_metrics(&mut self, metrics: RouteMetrics) {
        self.metrics = metrics;
    }

    // ─── Validation ──────────────────────────────────────────────────────

    /// Check whether this route has expired (relative to `now`).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && self.expires_at <= now
    }

    /// **N2.0.7.2.** Validate the route's structural invariants. Returns
    /// `Ok(())` if the route is well-formed, or `Err(RouteError)` describing
    /// the first violation.
    ///
    /// Checks:
    /// 1. `hop_details` is non-empty.
    /// 2. `hop_details` count ≤ `ROUTE_MAX_HOPS` (16).
    /// 3. `source` is non-zero.
    /// 4. `destination` is non-zero.
    /// 5. Last hop descriptor NodeId == `destination`.
    /// 6. Every hop descriptor NodeId is unique (no loops).
    /// 7. Every hop descriptor NodeId is internally consistent with its
    ///    Ed25519 public key (invariant I4: NodeId == SHA-256("SNP/0.1 node\0" || pub_key)).
    ///    (This is already enforced at `VerifiedNodeDescriptor` construction
    ///    time, but we check it again for defence in depth.)
    /// 8. The destination hop has the Gateway capability.
    /// 9. The destination hop (gateway) has an X25519 circuit public key.
    /// 10. Relay hops do NOT advertise an X25519 circuit public key (only
    ///     gateways should have one).
    /// 11. Every hop has at least one endpoint.
    /// 12. Not expired.
    pub fn validate(&self) -> Result<(), RouteError> {
        // If hop_details is empty, this is a legacy route (constructed via
        // the deprecated Route::new). Fall back to validating the derived
        // hops() list for backward compat.
        if self.hop_details.is_empty() {
            let hops = self.hops();
            // 1. hops non-empty.
            if hops.is_empty() {
                return Err(RouteError::Empty);
            }
            // 2. Hop count ≤ 16.
            if hops.len() > ROUTE_MAX_HOPS {
                return Err(RouteError::ExcessiveHopCount(hops.len()));
            }
            // 3. Source is set (non-zero).
            if self.source == [0u8; 32] {
                return Err(RouteError::SourceMismatch);
            }
            // 4. Destination is set (non-zero).
            if self.destination == [0u8; 32] {
                return Err(RouteError::DestinationMismatch);
            }
            // 5. Last hop NodeId == destination.
            if hops.last() != Some(&self.destination) {
                return Err(RouteError::DestinationDescriptorMismatch);
            }
            // 6. No duplicate hops.
            let mut seen = HashSet::new();
            for hop in &hops {
                if !seen.insert(*hop) {
                    return Err(RouteError::DuplicateHop(hex_short(hop)));
                }
            }
            // 12. Not expired.
            let now = now_unix();
            if self.is_expired(now) {
                return Err(RouteError::Expired {
                    expires_at: self.expires_at,
                    now,
                });
            }
            return Ok(());
        }
        // N2.0.7.2: Full validation of hop_details.
        // 1. hop_details non-empty.
        if self.hop_details.is_empty() {
            return Err(RouteError::Empty);
        }
        // 2. Hop count ≤ 16.
        if self.hop_details.len() > ROUTE_MAX_HOPS {
            return Err(RouteError::ExcessiveHopCount(self.hop_details.len()));
        }
        // 3. Source is set (non-zero).
        if self.source == [0u8; 32] {
            return Err(RouteError::SourceMismatch);
        }
        // 4. Destination is set (non-zero).
        if self.destination == [0u8; 32] {
            return Err(RouteError::DestinationMismatch);
        }
        // 5. Last hop descriptor NodeId == destination.
        let last_hop = self.hop_details.last().expect("non-empty");
        if last_hop.node_id() != self.destination {
            return Err(RouteError::DestinationDescriptorMismatch);
        }
        // 6. No duplicate hops (loop detection).
        let mut seen = HashSet::new();
        for (i, hop) in self.hop_details.iter().enumerate() {
            if !seen.insert(hop.node_id()) {
                return Err(RouteError::DuplicateHop(hex_short(&hop.node_id())));
            }
            // 7. NodeId ↔ Ed25519 consistency (defence in depth).
            if !hop.descriptor.verify_node_id_consistency() {
                return Err(RouteError::NodeIdInconsistent { hop_index: i });
            }
            // 10. Relay hops do NOT advertise an X25519 circuit key.
            if !hop.descriptor.is_gateway() && hop.descriptor.circuit_x25519_pub().is_some() {
                return Err(RouteError::RelayHasCircuitKey { hop_index: i });
            }
            // 11. Every hop has at least one endpoint.
            if hop.endpoints.is_empty() {
                return Err(RouteError::HopMissingEndpoint { hop_index: i });
            }
        }
        // 8. Destination hop has Gateway capability.
        if !last_hop.descriptor.is_gateway() {
            return Err(RouteError::DestinationNotGateway);
        }
        // 9. Destination gateway has X25519 circuit public key.
        if last_hop.descriptor.circuit_x25519_pub().is_none() {
            return Err(RouteError::GatewayMissingCircuitKey);
        }
        // 12. Not expired.
        let now = now_unix();
        if self.is_expired(now) {
            return Err(RouteError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }
}

/// Verify a `VerifiedNodeDescriptor`'s NodeId consistency. This is a method
/// on `VerifiedNodeDescriptor` that is used by `Route::validate()` for
/// defence in depth. It should always return `true` for a
/// `VerifiedNodeDescriptor` (it was checked at construction time).
impl VerifiedNodeDescriptor {
    /// Verify that the NodeId matches `SHA-256("SNP/0.1 node\0" || ed25519_public_key)`.
    #[must_use]
    pub fn verify_node_id_consistency(&self) -> bool {
        // Delegate to the descriptor module's implementation.
        super::descriptor::verify_node_id_consistency(self)
    }
}

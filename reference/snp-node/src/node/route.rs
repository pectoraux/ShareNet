//! Route — first-class route object with explicit hop list and state machine.
//!
//! Extracted from node.rs for N2.0.3 Gate J (Node decomposition).

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
    /// Number of hops in the route (`route.hops.len()`).
    pub hop_count: u32,
    /// Estimated one-way latency in milliseconds, if known. `None` until
    /// the first frame round-trips the route.
    pub estimated_latency_ms: Option<u64>,
    /// Estimated bandwidth in bits per second, if known. `None` until the
    /// first frame round-trips the route.
    pub bandwidth_bps: Option<u64>,
}

/// Errors from [`Route`] validation and state-machine transitions.
///
/// The N2.0.3 task spec ("GATE B — First-class Route object") requires the
/// `Route::validate` and `Route::transition` methods to return
/// `Result<(), RouteError>` (NOT `NodeResult<()>`). The existing
/// `Route::transition_to` method (which returns `NodeResult<()>`) is kept
/// for backward compat with the N2.0.2 tests (`tests/n202_protocol.rs`
/// test_7b, test_7c) — it is a thin wrapper that maps `RouteError` to
/// `NodeError::Other`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// The route has no hops (`hops.is_empty()`).
    #[error("route is empty (no hops)")]
    Empty,
    /// The `source` field is all-zero (the client NodeId must be set).
    #[error("route source is unset (all-zero NodeId)")]
    SourceMismatch,
    /// The `destination` field does not match `hops.last()`.
    #[error("route destination does not match last hop")]
    DestinationMismatch,
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
}

/// Default route lifetime: 1 hour (matches the advertisement TTL).
const ROUTE_DEFAULT_TTL_SECS: u64 = 3600;

/// Maximum hop count (matches `FRAME_TTL_MAX` from `snp-frames`).
const ROUTE_MAX_HOPS: usize = 16;

/// **N2.0.7.** A single hop in a [`Route`]. Carries the hop's
/// [`NodeDescriptor`] (the authenticated identity) AND its current
/// transport endpoint(s) (locators that can change over time).
///
/// This enforces the ShareNet architectural principle:
///
/// > **NodeId answers "who?" — transport endpoint answers "where can I
/// > reach them now?"**
///
/// A hop may have MULTIPLE endpoints (e.g. Wi-Fi Direct, BLE, TCP) — the
/// runtime resolves the current endpoint via the transport/discovery
/// abstraction. The Route does NOT become invalid merely because a
/// transport endpoint changes; only the NodeId (inside the
/// `NodeDescriptor`) is the stable identity.
///
/// **N2.0.7.1:** The `descriptor` field carries the FULL authenticated
/// identity (NodeId + Ed25519 public key + X25519 circuit public key +
/// capabilities). This means the Route is SELF-CONTAINED — the client
/// does NOT need to pass `gateway_ed25519_public` / `gateway_x25519_pub`
/// as separate parameters to `send_via_route`; they come from the
/// destination hop's `NodeDescriptor`.
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// The hop's authenticated identity descriptor (NodeId + Ed25519 pub +
    /// X25519 circuit pub + capabilities). Obtained from a VERIFIED
    /// discovery source (e.g. `GatewayAdvertisement`).
    pub descriptor: NodeDescriptor,
    /// The hop's current transport endpoint(s). Each entry is a
    /// transport-neutral [`TransportEndpoint`] (NOT an informal string).
    /// The runtime resolves the current endpoint via the
    /// transport/discovery abstraction.
    ///
    /// May be empty — in that case, the runtime must resolve the NodeId
    /// to an endpoint via the discovery/transport abstraction before
    /// attempting to connect.
    pub endpoints: Vec<TransportEndpoint>,
}

impl RouteHop {
    /// Construct a `RouteHop` with a `NodeDescriptor` + a single TCP endpoint.
    #[must_use]
    pub fn new(descriptor: NodeDescriptor, endpoint: TransportEndpoint) -> Self {
        Self {
            descriptor,
            endpoints: vec![endpoint],
        }
    }

    /// Construct a `RouteHop` with a `NodeDescriptor` + multiple endpoints.
    #[must_use]
    pub fn with_endpoints(
        descriptor: NodeDescriptor,
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
        self.descriptor.node_id
    }
}

/// A multi-hop route from a client to a gateway.
///
/// A `Route` is a sequence of peer NodeIds (`hops`) terminating at a
/// `destination` (a gateway NodeId). Each hop has its own SNP-IK/0.1 session
/// (a [`PeerSession`]).
///
/// The `route_id` is `SHA-256(source || destination || hops || nonce)`,
/// computed when the route is proposed. It uniquely identifies this
/// particular path (the same client↔gateway pair may have multiple routes
/// via different relay paths).
///
/// **N2.0.3 (GATE B) additions.** The struct now carries:
/// - `source` — the client NodeId (was previously only implied via the
///   `route_id` input).
/// - `epoch` — incremented on every key rotation / migration.
/// - `expires_at` — when the route expires (default `created_at + 1 hour`).
/// - `metrics` — observed performance characteristics (hop count, latency,
///   bandwidth).
/// - `last_validated` — kept for backward compat with the N2.0.2 tests.
///
/// **N2.0.7 additions.** The struct now carries:
/// - `hop_details` — a `Vec<RouteHop>` with NodeId + endpoints + capabilities
///   for each hop. This makes the Route AUTHORITATIVE — the routing runtime
///   consumes `hop_details` to determine where to connect. The legacy
///   `hops` field (Vec<[u8; 32]>) is retained for backward compat with
///   tests that don't use endpoints.
#[derive(Debug, Clone)]
pub struct Route {
    /// The route id — `SHA-256(source || destination || hops || nonce)`.
    pub route_id: [u8; 32],
    /// The client NodeId (the route's source). N2.0.3 (GATE B).
    pub source: [u8; 32],
    /// The destination gateway NodeId.
    pub destination: [u8; 32],
    /// The ordered list of peer NodeIds along the path. Per the N2.0.3
    /// spec, this list INCLUDES the destination as the last element (the
    /// `destination` field is a cache of `hops.last()` for convenience).
    /// For a direct client↔gateway route, this is `[destination]`. For a
    /// one-relay route, this is `[relay_node_id, destination]`. Etc.
    ///
    /// **Note:** the N2.0.2 implementation did NOT include the destination
    /// in `hops` (it was "intermediate relays only"). The N2.0.3
    /// `validate()` method accepts both conventions — it only checks
    /// `destination == hops.last()` IF `hops` is non-empty.
    pub hops: Vec<[u8; 32]>,
    /// **N2.0.7.** The ordered list of `RouteHop` entries (NodeId + endpoints
    /// + capabilities). This is the AUTHORITATIVE routing plan — the runtime
    /// consumes `hop_details` (NOT `hops`) to determine where to connect.
    /// `hop_details[i].node_id` == `hops[i]` for all `i` (when both are
    /// populated).
    pub hop_details: Vec<RouteHop>,
    /// The route epoch — incremented on every key rotation or migration.
    /// N2.0.3 (GATE B).
    pub epoch: u64,
    /// The current state of the route.
    pub state: RouteState,
    /// When the route was created (unix seconds).
    pub created_at: u64,
    /// When the route expires (unix seconds). N2.0.3 (GATE B). Default
    /// `created_at + ROUTE_DEFAULT_TTL_SECS` (1 hour).
    pub expires_at: u64,
    /// Observed performance characteristics. N2.0.3 (GATE B).
    pub metrics: RouteMetrics,
    /// When the route was last validated (all hops handshaked successfully).
    /// Updated when the route transitions to `Active`.
    pub last_validated: u64,
}

impl Route {
    /// Construct a new `Route` in the `Proposed` state. The `route_id` is
    /// computed from the source NodeId, destination, hops, and a fresh nonce.
    ///
    /// **N2.0.3 (GATE B).** The signature is `Route::new(source,
    /// destination, hops)` (taking `[u8; 32]` by value, per the spec). The
    /// `epoch` is initialised to 0; `expires_at` to `now + 1 hour`;
    /// `metrics.hop_count` to `hops.len()`.
    ///
    /// **N2.0.7.** The `hop_details` field is initialized as empty (no
    /// endpoints). Use [`Route::new_with_hop_details`] for production routes
    /// that carry transport endpoints.
    #[must_use]
    pub fn new(source: [u8; 32], destination: [u8; 32], hops: Vec<[u8; 32]>) -> Self {
        let now = now_unix();
        // route_id = SHA-256(source || destination || hops || nonce)
        let mut id_input = Vec::with_capacity(32 + 32 + hops.len() * 32 + 16);
        id_input.extend_from_slice(&source);
        id_input.extend_from_slice(&destination);
        for hop in &hops {
            id_input.extend_from_slice(hop);
        }
        // Include a fresh nonce (timestamp + counter) so two routes with
        // the same path get different route_ids.
        id_input.extend_from_slice(&now.to_be_bytes());
        id_input.extend_from_slice(&FID_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes());
        let route_id = snp_crypto::sha256(&id_input);
        let hop_count = u32::try_from(hops.len()).unwrap_or(u32::MAX);
        Self {
            route_id,
            source,
            destination,
            hops,
            hop_details: Vec::new(), // N2.0.7: empty — use new_with_hop_details for production
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

    /// **N2.0.7 production constructor.** Construct a `Route` with
    /// `RouteHop` entries that carry `NodeDescriptor` + `TransportEndpoint`s.
    /// This is the AUTHORITATIVE routing plan — the runtime consumes
    /// `hop_details` to determine where to connect AND the cryptographic
    /// identity of the destination.
    ///
    /// The `hop_details` list MUST include the destination as the last
    /// element (same convention as `hops`). The `hops` field is
    /// automatically populated from `hop_details[i].descriptor.node_id`.
    ///
    /// # Panics
    /// Never panics for well-formed inputs.
    #[must_use]
    pub fn new_with_hop_details(
        source: [u8; 32],
        destination: [u8; 32],
        hop_details: Vec<RouteHop>,
    ) -> Self {
        let hops: Vec<[u8; 32]> = hop_details.iter().map(|h| h.node_id()).collect();
        let mut route = Self::new(source, destination, hops);
        route.hop_details = hop_details;
        route
    }

    /// **N2.0.7.** Get the `RouteHop` at position `i`. Returns `None` if
    /// `hop_details` is empty (the route was constructed via `Route::new`
    /// without endpoints) or `i` is out of bounds.
    #[must_use]
    pub fn hop(&self, i: usize) -> Option<&RouteHop> {
        self.hop_details.get(i)
    }

    /// **N2.0.7.** Get the first hop's endpoint (the relay the client
    /// connects to). Returns `None` if `hop_details` is empty or the first
    /// hop has no endpoints.
    #[must_use]
    pub fn first_hop_endpoint(&self) -> Option<&TransportEndpoint> {
        self.hop_details
            .first()
            .and_then(|h| h.first_endpoint())
    }

    /// **N2.0.7.1.** Get the destination hop's `NodeDescriptor` (the
    /// gateway's authenticated identity). This is how `send_via_route`
    /// obtains the gateway's Ed25519 public key + X25519 circuit public
    /// key WITHOUT receiving them as separate parameters.
    #[must_use]
    pub fn destination_descriptor(&self) -> Option<&NodeDescriptor> {
        self.hop_details.last().map(|h| &h.descriptor)
    }

    /// **N2.0.7.** Check whether this Route has `hop_details` (i.e. was
    /// constructed via `new_with_hop_details`). Routes without `hop_details`
    /// cannot be used with `send_via_route` (they have no endpoints).
    #[must_use]
    pub fn has_endpoints(&self) -> bool {
        !self.hop_details.is_empty()
    }

    /// Validate the route's structural invariants. Returns `Ok(())` if the
    /// route is well-formed, or `Err(RouteError)` describing the first
    /// violation.
    ///
    /// **N2.0.3 (GATE B).** Checks:
    /// 1. Not empty — `hops` is non-empty (a route must have at least the
    ///    destination hop).
    /// 2. Source is set — `source` is not all-zero.
    /// 3. Destination matches last hop — `hops.last() == Some(&destination)`.
    /// 4. No duplicate hops — no NodeId appears twice in `hops` (loop
    ///    detection).
    /// 5. Hop count ≤ 16 — `hops.len() <= ROUTE_MAX_HOPS` (TTL max).
    /// 6. Not expired — `!self.is_expired(now)`.
    ///
    /// Note: this method does NOT check that the source is the first hop
    /// (the source is the client, which is NOT in the `hops` list — the
    /// `hops` list starts at the first relay). The "Source matches first
    /// hop or is the source field" check from the spec is interpreted as
    /// "the source field must be set" (non-zero).
    pub fn validate(&self) -> Result<(), RouteError> {
        // 1. Not empty.
        if self.hops.is_empty() {
            return Err(RouteError::Empty);
        }
        // 2. Source is set (non-zero).
        if self.source == [0u8; 32] {
            return Err(RouteError::SourceMismatch);
        }
        // 3. Destination matches last hop.
        if self.hops.last() != Some(&self.destination) {
            return Err(RouteError::DestinationMismatch);
        }
        // 4. No duplicate hops (loop detection).
        let mut seen = HashSet::new();
        for hop in &self.hops {
            if !seen.insert(*hop) {
                return Err(RouteError::DuplicateHop(hex_short(hop)));
            }
        }
        // 5. Hop count ≤ 16.
        if self.hops.len() > ROUTE_MAX_HOPS {
            return Err(RouteError::ExcessiveHopCount(self.hops.len()));
        }
        // 6. Not expired.
        let now = now_unix();
        if self.is_expired(now) {
            return Err(RouteError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// Check whether this route has expired (relative to `now`).
    ///
    /// Returns `true` if `expires_at <= now`. A route with `expires_at == 0`
    /// (the N2.0.2 default before N2.0.3 added the `expires_at` field) is
    /// treated as "never expires" for backward compat.
    ///
    /// **N2.0.3 (GATE B).**
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        // expires_at == 0 means "never expires" (backward compat with
        // N2.0.2 routes that did not set this field).
        self.expires_at != 0 && self.expires_at <= now
    }

    /// Transition the route to a new state. Returns `Ok(())` on a legal
    /// transition, `Err(RouteError::IllegalTransition)` on an illegal one.
    ///
    /// **N2.0.3 (GATE B).** This is the spec-mandated `transition` method
    /// returning `Result<(), RouteError>`. The N2.0.2 `transition_to`
    /// method (returning `NodeResult<()>`) is kept as a thin wrapper for
    /// backward compat with the existing tests.
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
    /// `NodeResult<()>` (instead of `Result<(), RouteError>`). Maps
    /// `RouteError` to `NodeError::Other`. New code should prefer
    /// [`Route::transition`].
    pub fn transition_to(&mut self, new_state: RouteState) -> NodeResult<()> {
        self.transition(new_state)
            .map_err(|e| NodeError::Other(format!("Route transition error: {e}")))
    }
}


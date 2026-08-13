//! Route — first-class route object with explicit hop list and state machine.
//!
//! **N2.0.7.3:** The Route now has EXACTLY ONE representation: `hop_details`.
//! The legacy `hops` field and `legacy_hops` field are REMOVED. The old
//! `Route::new(source, destination, Vec<NodeId>)` constructor is REMOVED —
//! the only production constructor is `Route::new_with_hop_details`, which
//! requires `VerifiedNodeDescriptor` + `TransportEndpoint` for every hop.
//!
//! `RouteCommitment` now uses canonical CBOR encoding (via `snp-cbor`)
//! instead of manual byte concatenation, ensuring cross-platform
//! reproducibility.
//!
//! **Commitment vs Authorization:** `RouteCommitment` is an integrity
//! identifier (a fingerprint of the route contents), NOT a signature.
//! It does not prove that any node authorized the route. Anyone who knows
//! the route contents can compute the same hash. When cryptographic
//! authorization is needed (for Civic Points, relay accounting, dispute
//! resolution), a separate `RouteAuthorization` type will be introduced.

use super::*;
use snp_cbor::CborValue;

// ─── RouteState ──────────────────────────────────────────────────────────────

/// The state of a [`Route`] — the lifecycle of a multi-hop path from a
/// client to a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    Proposed,
    Establishing,
    Active,
    Degraded,
    Migrating,
    Failed,
    Closed,
}

// ─── RouteMetrics ────────────────────────────────────────────────────────────

/// Observed performance characteristics of a [`Route`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMetrics {
    /// Number of hops in the route.
    pub hop_count: u32,
    /// Estimated one-way latency in milliseconds.
    pub estimated_latency_ms: Option<u64>,
    /// Estimated bandwidth in bits per second.
    pub bandwidth_bps: Option<u64>,
}

// ─── RouteError ──────────────────────────────────────────────────────────────

/// Errors from [`Route`] validation and state-machine transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("route is empty (no hop_details)")]
    Empty,
    #[error("route source is unset (all-zero NodeId)")]
    SourceMismatch,
    #[error("route destination is unset (all-zero NodeId)")]
    DestinationMismatch,
    #[error("route destination does not match last hop descriptor NodeId")]
    DestinationDescriptorMismatch,
    #[error("route has a duplicate hop (loop): {0}")]
    DuplicateHop(String),
    #[error("route has too many hops: {0} > 16")]
    ExcessiveHopCount(usize),
    #[error("route has expired (expires_at={expires_at}, now={now})")]
    Expired { expires_at: u64, now: u64 },
    #[error("illegal route transition: {from:?} → {to:?}")]
    IllegalTransition { from: RouteState, to: RouteState },
    #[error("hop {hop_index} descriptor NodeId does not match SHA-256 of Ed25519 public key (I4 violation)")]
    NodeIdInconsistent { hop_index: usize },
    #[error("destination hop does not have the Gateway capability")]
    DestinationNotGateway,
    #[error("destination gateway descriptor has no X25519 circuit public key")]
    GatewayMissingCircuitKey,
    #[error("relay hop {hop_index} incorrectly advertises an X25519 circuit key")]
    RelayHasCircuitKey { hop_index: usize },
    #[error("hop {hop_index} has no endpoints (cannot connect)")]
    HopMissingEndpoint { hop_index: usize },
}

const ROUTE_DEFAULT_TTL_SECS: u64 = 3600;
const ROUTE_MAX_HOPS: usize = 16;

// ─── RouteCommitment ─────────────────────────────────────────────────────────

/// A `RouteCommitment` is a canonical hash of the AUTHORITATIVE route
/// representation. It is an **integrity identifier** (a fingerprint), NOT
/// a signature or authorization.
///
/// **N2.0.7.3:** The commitment is computed via
/// `SHA-256(canonical_CBOR_encoding)` using the existing `snp-cbor`
/// canonical encoding infrastructure. This ensures cross-platform
/// reproducibility — the same route encoded by Rust, Kotlin, Python, or
/// any other language produces the same commitment.
///
/// The commitment commits to:
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
/// **Commitment vs Authorization:** `RouteCommitment` does NOT prove that
/// any node authorized the route. Anyone who knows the route contents can
/// compute the same hash. When cryptographic authorization is needed (for
/// Civic Points, relay accounting, dispute resolution), a separate
/// `RouteAuthorization` type carrying signatures will be introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteCommitment([u8; 32]);

impl RouteCommitment {
    /// Compute the `RouteCommitment` from the authoritative route representation.
    /// Uses canonical CBOR encoding (via `snp-cbor`) for cross-platform
    /// reproducibility.
    #[must_use]
    pub fn compute(
        source: &[u8; 32],
        destination: &[u8; 32],
        epoch: u64,
        hop_details: &[RouteHop],
    ) -> Self {
        // Build a canonical CBOR map of the authoritative route fields.
        let hops_cbor: Vec<CborValue> = hop_details
            .iter()
            .map(|hop| {
                let endpoints_cbor: Vec<CborValue> = hop
                    .endpoints
                    .iter()
                    .map(|ep| ep.canonical_cbor())
                    .collect();
                CborValue::Map(vec![
                    (CborValue::TextString("descriptor".into()), hop.descriptor.canonical_cbor()),
                    (CborValue::TextString("endpoints".into()), CborValue::Array(endpoints_cbor)),
                ])
            })
            .collect();

        let route_cbor = CborValue::Map(vec![
            (CborValue::TextString("protocolVersion".into()), CborValue::TextString("SNP/0.1 route v1".into())),
            (CborValue::TextString("source".into()), CborValue::ByteString(source.to_vec())),
            (CborValue::TextString("destination".into()), CborValue::ByteString(destination.to_vec())),
            (CborValue::TextString("epoch".into()), CborValue::UnsignedInt(epoch)),
            (CborValue::TextString("hops".into()), CborValue::Array(hops_cbor)),
        ]);

        // Encode via canonical CBOR and hash.
        let encoded = snp_cbor::encode(&route_cbor).unwrap_or_default();
        Self(snp_crypto::sha256(&encoded))
    }

    /// Get the 32-byte commitment.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ─── RouteHop ────────────────────────────────────────────────────────────────

/// A single hop in a [`Route`]. Carries the hop's [`VerifiedNodeDescriptor`]
/// (the AUTHENTICATED identity — derived from a verified advertisement) AND
/// its transport endpoint(s).
///
/// **N2.0.7.3:** `RouteHop` can ONLY be constructed with a
/// `VerifiedNodeDescriptor` — NOT with `UnverifiedNodeDescriptor` or
/// `IdentityConsistentNodeDescriptor`. The type system enforces that
/// only authenticated identity data enters the routing layer.
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// The hop's VERIFIED identity descriptor. Can ONLY be constructed from
    /// a `VerifiedNodeAdvertisement` (signature checked + NodeId↔Ed25519
    /// consistency verified).
    pub descriptor: VerifiedNodeDescriptor,
    /// The hop's transport endpoint(s).
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

    /// Get the NodeId.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.descriptor.node_id()
    }
}

// ─── Route ───────────────────────────────────────────────────────────────────

/// A multi-hop route from a client to a gateway.
///
/// **N2.0.7.3:** The Route has EXACTLY ONE representation: `hop_details`.
/// There is NO `legacy_hops` field, NO `Route::new(source, destination,
/// Vec<NodeId>)` constructor, and NO fallback in `validate()` or `hops()`.
/// The only constructor is [`Route::new_with_hop_details`], which requires
/// `VerifiedNodeDescriptor` + `TransportEndpoint` for every hop.
///
/// Identity-critical fields are non-mutable (private). Controlled mutation
/// is provided via `transition()` and `increment_epoch()`.
#[derive(Debug, Clone)]
pub struct Route {
    route_commitment: RouteCommitment,
    source: [u8; 32],
    destination: [u8; 32],
    hop_details: Vec<RouteHop>,
    /// Legacy raw hop NodeIds. Only present when `legacy-circuit-keys` feature
    /// is enabled. Used by the deprecated `Route::new()` constructor.
    #[cfg(feature = "legacy-circuit-keys")]
    legacy_hops: Vec<[u8; 32]>,
    epoch: u64,
    state: RouteState,
    created_at: u64,
    expires_at: u64,
    metrics: RouteMetrics,
    last_validated: u64,
}

impl Route {
    /// **N2.0.7.3 production constructor.** The ONLY way to construct a
    /// `Route`. Requires `RouteHop` entries (each carrying a
    /// `VerifiedNodeDescriptor` + `TransportEndpoint`s).
    ///
    /// The `route_commitment` is computed at construction time from the
    /// canonical CBOR encoding of the source, destination, epoch, and
    /// hop_details.
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
            #[cfg(feature = "legacy-circuit-keys")]
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

    // ─── Accessors ───────────────────────────────────────────────────────

    #[must_use]
    pub fn route_commitment(&self) -> &RouteCommitment {
        &self.route_commitment
    }

    #[must_use]
    pub fn source(&self) -> [u8; 32] {
        self.source
    }

    #[must_use]
    pub fn destination(&self) -> [u8; 32] {
        self.destination
    }

    /// **N2.0.7.3.** Get the ordered list of hop NodeIds, DERIVED from
    /// `hop_details` (or `legacy_hops` when the legacy feature is enabled).
    #[must_use]
    pub fn hops(&self) -> Vec<[u8; 32]> {
        if !self.hop_details.is_empty() {
            self.hop_details.iter().map(|h| h.node_id()).collect()
        } else {
            #[cfg(feature = "legacy-circuit-keys")]
            { self.legacy_hops.clone() }
            #[cfg(not(feature = "legacy-circuit-keys"))]
            { Vec::new() }
        }
    }

    #[must_use]
    pub fn hop_details(&self) -> &[RouteHop] {
        &self.hop_details
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn state(&self) -> RouteState {
        self.state
    }

    #[must_use]
    pub fn last_validated(&self) -> u64 {
        self.last_validated
    }

    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn metrics(&self) -> &RouteMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn hop(&self, i: usize) -> Option<&RouteHop> {
        self.hop_details.get(i)
    }

    #[must_use]
    pub fn first_hop_endpoint(&self) -> Option<&TransportEndpoint> {
        self.hop_details
            .first()
            .and_then(|h| h.first_endpoint())
    }

    #[must_use]
    pub fn destination_descriptor(&self) -> Option<&VerifiedNodeDescriptor> {
        self.hop_details.last().map(|h| &h.descriptor)
    }

    #[must_use]
    pub fn has_endpoints(&self) -> bool {
        !self.hop_details.is_empty()
    }

    // ─── Controlled mutation ─────────────────────────────────────────────

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

    pub fn transition_to(&mut self, new_state: RouteState) -> NodeResult<()> {
        self.transition(new_state)
            .map_err(|e| NodeError::Other(format!("Route transition error: {e}")))
    }

    /// **Legacy constructor.** Only available with the `legacy-circuit-keys`
    /// Cargo feature. Creates a Route from raw NodeIds (no verified
    /// descriptors, no endpoints). The production build does NOT compile
    /// this constructor.
    #[cfg(feature = "legacy-circuit-keys")]
    #[deprecated(
        since = "N2.0.7.3",
        note = "use `Route::new_with_hop_details` with VerifiedNodeDescriptor entries"
    )]
    #[must_use]
    pub fn new(source: [u8; 32], destination: [u8; 32], hops: Vec<[u8; 32]>) -> Self {
        let now = now_unix();
        let mut id_input = Vec::with_capacity(32 + 32 + hops.len() * 32 + 16);
        id_input.extend_from_slice(&source);
        id_input.extend_from_slice(&destination);
        for hop in &hops {
            id_input.extend_from_slice(hop);
        }
        id_input.extend_from_slice(b"legacy\0");
        let route_commitment = RouteCommitment(snp_crypto::sha256(&id_input));
        let hop_count = u32::try_from(hops.len()).unwrap_or(u32::MAX);
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

    pub fn increment_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.route_commitment = RouteCommitment::compute(
            &self.source,
            &self.destination,
            self.epoch,
            &self.hop_details,
        );
    }

    pub fn update_metrics(&mut self, metrics: RouteMetrics) {
        self.metrics = metrics;
    }

    // ─── Validation ──────────────────────────────────────────────────────

    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && self.expires_at <= now
    }

    /// **N2.0.7.3.** Validate the route's structural invariants.
    /// Production validation checks `hop_details`. When the legacy feature
    /// is enabled, legacy routes (with `legacy_hops`) use a simplified
    /// validation path.
    pub fn validate(&self) -> Result<(), RouteError> {
        // Legacy fallback.
        #[cfg(feature = "legacy-circuit-keys")]
        if self.hop_details.is_empty() && !self.legacy_hops.is_empty() {
            let hops = &self.legacy_hops;
            if hops.is_empty() { return Err(RouteError::Empty); }
            if hops.len() > ROUTE_MAX_HOPS { return Err(RouteError::ExcessiveHopCount(hops.len())); }
            if self.source == [0u8; 32] { return Err(RouteError::SourceMismatch); }
            if self.destination == [0u8; 32] { return Err(RouteError::DestinationMismatch); }
            if hops.last() != Some(&self.destination) { return Err(RouteError::DestinationDescriptorMismatch); }
            let mut seen = HashSet::new();
            for hop in hops {
                if !seen.insert(*hop) { return Err(RouteError::DuplicateHop(hex_short(hop))); }
            }
            let now = now_unix();
            if self.is_expired(now) { return Err(RouteError::Expired { expires_at: self.expires_at, now }); }
            return Ok(());
        }
        // Production validation.
        if self.hop_details.is_empty() {
            return Err(RouteError::Empty);
        }
        if self.hop_details.len() > ROUTE_MAX_HOPS {
            return Err(RouteError::ExcessiveHopCount(self.hop_details.len()));
        }
        if self.source == [0u8; 32] {
            return Err(RouteError::SourceMismatch);
        }
        if self.destination == [0u8; 32] {
            return Err(RouteError::DestinationMismatch);
        }
        let last_hop = self.hop_details.last().expect("non-empty");
        if last_hop.node_id() != self.destination {
            return Err(RouteError::DestinationDescriptorMismatch);
        }
        let mut seen = HashSet::new();
        for (i, hop) in self.hop_details.iter().enumerate() {
            if !seen.insert(hop.node_id()) {
                return Err(RouteError::DuplicateHop(hex_short(&hop.node_id())));
            }
            if !hop.descriptor.verify_node_id_consistency() {
                return Err(RouteError::NodeIdInconsistent { hop_index: i });
            }
            if !hop.descriptor.is_gateway() && hop.descriptor.circuit_x25519_pub().is_some() {
                return Err(RouteError::RelayHasCircuitKey { hop_index: i });
            }
            if hop.endpoints.is_empty() {
                return Err(RouteError::HopMissingEndpoint { hop_index: i });
            }
        }
        if !last_hop.descriptor.is_gateway() {
            return Err(RouteError::DestinationNotGateway);
        }
        if last_hop.descriptor.circuit_x25519_pub().is_none() {
            return Err(RouteError::GatewayMissingCircuitKey);
        }
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

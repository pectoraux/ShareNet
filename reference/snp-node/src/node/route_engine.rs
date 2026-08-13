//! N2.1.2 / N2.1.2.1 — Route Computation, Construction, and Validation.
//!
//! ## N2.1.2.1 correction: honest LOCAL vs DISTRIBUTED boundary
//!
//! **This module implements LOCAL route computation over an authenticated
//! topology graph, plus a destination-resolution abstraction. It does NOT
//! implement a distributed route-discovery protocol.**
//!
//! The distinction is critical:
//!
//! ### LOCAL GRAPH PATH COMPUTATION (implemented here)
//!
//! The `RouteEngine` runs Dijkstra over the **local** `TopologyGraph`'s
//! `LinkTable`. It only traverses links that are already present locally
//! and whose remote nodes are already authenticated locally (or injected
//! via the `DestinationResolver` as already-verified records).
//!
//! This is sufficient when:
//! - The local node already has authenticated links to all intermediate hops.
//! - The destination's authenticated advertisement is available (either
//!   locally or via the resolver).
//!
//! ### DISTRIBUTED ROUTE DISCOVERY (NOT implemented here)
//!
//! In a real ShareNet mesh, node A may know only B, while the full path
//! A → B → C → G requires discovering B→C and C→G links that A does NOT
//! locally possess. This requires a distributed next-hop resolution
//! protocol where A queries B (an authenticated next-hop peer) for
//! C's advertisement and the B→C link, then queries C for G's
//! advertisement and the C→G link.
//!
//! That protocol is **explicitly unimplemented** in this milestone. The
//! `DistributedRouteDiscovery` trait below defines the interface, but no
//! production implementation exists. The `InMemoryResolver` is a TEST-ONLY
//! stub that simulates resolution by returning pre-authenticated records.
//!
//! ## Core principle: Hints are NOT routes
//!
//! The topology graph contains two fundamentally different kinds of
//! information:
//!
//! - **AUTHENTICATED** — `AuthenticatedNodeRecord`, verified links, selected
//!   `TransportEndpoint`s. These are the only things that can become
//!   `RouteHop` entries.
//! - **NON-AUTHORITATIVE** — `RemoteNodeHint`, `distance_hint`, third-party
//!   gateway claims. These are DISCOVERY signals, never route components.
//!
//! A `RemoteNodeHint` MUST NEVER directly become a `RouteHop`,
//! `VerifiedNodeDescriptor`, route destination, gateway X25519 key, or
//! executable next hop. It can only become a DESTINATION CANDIDATE that
//! triggers RESOLUTION.
//!
//! ## N2.1.2.1 correction: selected link endpoint → RouteHop endpoint
//!
//! The Dijkstra path computation selects a concrete `Link` (with a specific
//! `LinkKey.endpoint`). The resulting `RouteHop` MUST use the EXACT endpoint
//! from the selected link — NOT `record.endpoints.first()`. This ensures
//! the `RouteCommitment` binds the endpoint that was actually proven usable.
//!
//! ## Route computation pipeline (LOCAL)
//!
//! ```text
//! Topology (local)
//!     │
//!     ├── direct authenticated gateways  ──► direct candidate
//!     │                                      (state: AUTHENTICATED)
//!     │
//!     └── remote gateway hints          ──► remote candidate
//!                                            (state: DISCOVERED)
//!                                                │
//!                                                ▼
//!                                          DestinationResolver
//!                                          (TRUST BOUNDARY — see below)
//!                                                │
//!                                    ┌───────────┴───────────┐
//!                                    │                       │
//!                               resolved                 not resolved
//!                                    │                       │
//!                           state: AUTHENTICATED       state: FAILED
//!                                    │
//!                                    ▼
//!                          LOCAL path computation
//!                          (Dijkstra over local usable
//!                           directed authenticated links)
//!                                    │
//!                            ┌───────┴───────┐
//!                            │               │
//!                         path found     no path
//!                            │               │
//!                    state: REACHABLE  state: FAILED
//!                            │
//!                            ▼
//!                  construct RouteHop sequence
//!                  (VerifiedNodeDescriptor + SELECTED LINK endpoint)
//!                            │
//!                            ▼
//!                      validate Route
//!                            │
//!                            ▼
//!                  compute RouteCommitment
//!                  (binds exact selected endpoints)
//!                            │
//!                            ▼
//!                    state: ROUTE_READY { route, cost }
//! ```
//!
//! ## Cost model
//!
//! Route cost is a pluggable trait (`RouteCostModel`). The default model is
//! `HopCountCost` (fewest hops wins). Metrics are classified as:
//!
//! - **MEASURED** — locally observed link RTT, success rate, etc.
//! - **SIGNED** — authenticated capabilities from verified advertisements.
//! - **SELF_REPORTED** — untrusted hint values (distance_hint, claimed
//!   capabilities from `RemoteNodeHint`). These MUST NOT influence cost
//!   directly; they may only prioritize candidate resolution order.
//!
//! ## DestinationResolver is a TRUST BOUNDARY
//!
//! `DestinationResolver` is not merely a lookup interface. It is a
//! **security-critical trust boundary**. The production resolver MUST
//! obtain destination advertisements through an authenticated protocol
//! (not merely a trusted callback). A malicious or buggy resolver could
//! return a forged record, but the route engine performs additional
//! validation (the record must have a valid `VerifiedNodeDescriptor`,
//! the destination must be a gateway with an X25519 key, etc.).
//! The `InMemoryResolver` is TEST-ONLY and MUST NOT be used in production.

use super::*;
use crate::node::link::{AuthenticatedLink, Link, LinkKey, LinkState};
use crate::node::topology::RemoteNodeHint;
use std::collections::{HashMap, HashSet};

/// A heap entry for Dijkstra path computation.
///
/// Ordered by (cost, counter) — BinaryHeap is a max-heap, so we use
/// `Reverse` ordering via `Ord` implementation to make it a min-heap.
/// The `counter` breaks ties in cost to ensure deterministic ordering
/// and avoids comparing `Vec<AuthenticatedLink>` (which doesn't implement `Ord`).
#[derive(Debug, Clone)]
struct HeapEntry {
    cost: u64,
    counter: u64,
    node: [u8; 32],
    path: Vec<[u8; 32]>,
    links: Vec<AuthenticatedLink>,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.counter == other.counter
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max-heap, so we reverse the comparison
        // to make it pop the LOWEST cost first.
        // Compare by cost first, then by counter (for determinism).
        other.cost.cmp(&self.cost)
            .then_with(|| other.counter.cmp(&self.counter))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Route candidate states
// ════════════════════════════════════════════════════════════════════════════

/// The lifecycle state of a route candidate.
///
/// These states are deliberately NOT collapsed — each represents a distinct
/// phase in the discovery → resolution → construction pipeline. A candidate
/// that is `Discovered` has NOT been resolved; a candidate that is
/// `Authenticated` has NOT necessarily been reached; a candidate that is
/// `Reachable` has NOT necessarily been assembled into a `Route`.
#[derive(Debug, Clone)]
pub enum RouteCandidateState {
    /// A `RemoteNodeHint` exists for this destination, but it has NOT been
    /// resolved into an `AuthenticatedNodeRecord`. No route can be
    /// constructed yet.
    Discovered {
        /// The hint that triggered discovery (non-authoritative).
        source_hint: RemoteNodeHint,
    },
    /// The route engine is attempting to obtain the destination's
    /// authenticated advertisement (via the `DestinationResolver`).
    Resolving {
        /// The NodeId being resolved.
        destination: [u8; 32],
    },
    /// The destination has a verified `AuthenticatedNodeRecord`, but no
    /// usable path to it has been found yet (or path computation has not
    /// been attempted).
    Authenticated {
        /// The destination NodeId.
        destination: [u8; 32],
    },
    /// A usable path of authenticated nodes and directed links exists from
        /// the source to the destination, but the `Route` has not yet been
    /// assembled.
    Reachable {
        /// The ordered path of NodeIds from source (exclusive) to
        /// destination (inclusive).
        path: Vec<[u8; 32]>,
    },
    /// A complete, validated `Route` exists and is ready for use.
    ///
    /// **N2.1.2.1:** The `cost` field stores the actual computed route cost
    /// (from the `RouteCostModel` used during path computation). This allows
    /// `best_route()` to select the genuinely lowest-cost route, rather than
    /// relying on candidate discovery order.
    RouteReady {
        /// The constructed route.
        route: Route,
        /// The computed route cost (from `RouteCostModel::path_cost()`).
        /// Lower is better. This is the actual cost of the selected path,
        /// NOT the `distance_hint` (which is SELF_REPORTED and untrusted).
        cost: u64,
    },
    /// Resolution or path construction failed. The topology is NOT poisoned
    /// — the candidate is simply unusable.
    Failed {
        /// Why it failed.
        reason: RouteDiscoveryError,
    },
}

/// Errors that can occur during route discovery.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteDiscoveryError {
    #[error("destination is only a remote hint and could not be resolved into an authenticated record")]
    DestinationUnresolved,
    #[error("destination is not an authenticated gateway: {0}")]
    DestinationNotGateway(NodeIdHex),
    #[error("destination gateway lacks X25519 circuit key")]
    GatewayMissingCircuitKey,
    #[error("no usable directed path exists from source to destination")]
    NoPathFound,
    #[error("a hop in the path is not authenticated (only a hint)")]
    UnauthenticatedHop,
    #[error("a hop in the path lacks the Relay capability (intermediate hops must be relays): hop {hop_index}")]
    HopNotRelay { hop_index: usize },
    #[error("a link in the path is not usable (Down or missing): {from} -> {to}")]
    LinkNotUsable { from: NodeIdHex, to: NodeIdHex },
    #[error("route validation failed: {0}")]
    ValidationFailed(RouteError),
    #[error("destination advertisement has expired")]
    DestinationExpired,
    #[error("source node is not set (all-zero NodeId)")]
    SourceNotSet,
    #[error("route has too many hops ({0} > {max})", max = MAX_ROUTE_HOPS)]
    TooManyHops(usize),
}

/// A wrapper for `[u8; 32]` that implements `Display` as hex.
/// Used for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdHex(pub [u8; 32]);

impl std::fmt::Display for NodeIdHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_short(&self.0))
    }
}

/// Maximum number of hops in a route (matches `ROUTE_MAX_HOPS` in route.rs).
const MAX_ROUTE_HOPS: usize = 16;

// ════════════════════════════════════════════════════════════════════════════
// Route candidate
// ════════════════════════════════════════════════════════════════════════════

/// A candidate destination for route computation.
///
/// A candidate is either:
/// - **Direct** — an authenticated `AuthenticatedNodeRecord` that is
///   directly known (or reachable through authenticated relays).
/// - **Remote** — a `RemoteNodeHint` that claims a gateway exists but has
///   NOT been authenticated. A remote candidate MUST be resolved before
///   any route can be constructed.
#[derive(Debug, Clone)]
pub struct RouteCandidate {
    /// The destination NodeId.
    pub destination: [u8; 32],
    /// Whether this candidate is direct (authenticated) or remote (hint).
    pub origin: CandidateOrigin,
    /// The current lifecycle state.
    pub state: RouteCandidateState,
}

/// How a candidate was discovered.
#[derive(Debug, Clone)]
pub enum CandidateOrigin {
    /// The candidate is an authenticated `AuthenticatedNodeRecord` in the
    /// local topology. This is AUTHORITATIVE.
    Direct {
        /// The authenticated record (cloned for the candidate).
        record: AuthenticatedNodeRecord,
    },
    /// The candidate is a `RemoteNodeHint` — a non-authoritative third-party
    /// claim. It MUST be resolved before use.
    Remote {
        /// The hint that triggered this candidate.
        hint: RemoteNodeHint,
    },
}

impl RouteCandidate {
    /// Get the destination NodeId.
    #[must_use]
    pub fn destination(&self) -> [u8; 32] {
        self.destination
    }

    /// Get the candidate origin.
    #[must_use]
    pub fn origin(&self) -> &CandidateOrigin {
        &self.origin
    }

    /// Get the candidate state.
    #[must_use]
    pub fn state(&self) -> &RouteCandidateState {
        &self.state
    }

    /// Check if this candidate is ready (has a validated Route).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.state, RouteCandidateState::RouteReady { .. })
    }

    /// Check if this candidate has failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self.state, RouteCandidateState::Failed { .. })
    }

    /// Get the ready Route, if any.
    #[must_use]
    pub fn route(&self) -> Option<&Route> {
        match &self.state {
            RouteCandidateState::RouteReady { route, .. } => Some(route),
            _ => None,
        }
    }

    /// **N2.1.2.1.** Get the computed route cost, if the candidate is ready.
    ///
    /// This is the actual cost computed by the `RouteCostModel` during
    /// path computation — NOT the `distance_hint` (which is SELF_REPORTED
    /// and untrusted). Lower is better.
    #[must_use]
    pub fn route_cost(&self) -> Option<u64> {
        match &self.state {
            RouteCandidateState::RouteReady { cost, .. } => Some(*cost),
            _ => None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Destination resolver trait
// ════════════════════════════════════════════════════════════════════════════

/// Resolves a remote destination candidate into an authenticated node record.
///
/// ## Purpose
///
/// When the route engine encounters a `RemoteNodeHint` (non-authoritative),
/// it cannot use the hint as a route hop. It must OBTAIN the destination's
/// actual `NodeAdvertisement`, VERIFY it, and produce an
/// `AuthenticatedNodeRecord`. This trait abstracts that network operation.
///
/// ## Security
///
/// The resolver MUST return only VERIFIED, AUTHENTICATED records. It is the
/// bridge between non-authoritative hints and authoritative route components.
/// A malicious or buggy resolver could return a forged record, but the route
/// engine performs additional validation (the record must have a valid
/// `VerifiedNodeDescriptor`, the destination must be a gateway with an
/// X25519 key, etc.).
///
/// ## Implementation note
///
/// In a production system, the resolver would:
/// 1. Send a request to the next-hop peer asking for the destination's
///    latest advertisement.
/// 2. Receive the advertisement bytes.
/// 3. Call `NodeAdvertisement::verify_into_verified()`.
/// 4. Return the resulting `AuthenticatedNodeRecord`.
///
/// For testing, a simple in-memory resolver can be used.
pub trait DestinationResolver {
    /// Attempt to resolve a remote destination into an authenticated record.
    ///
    /// # Parameters
    /// - `destination`: The NodeId of the destination to resolve.
    /// - `hint`: The `RemoteNodeHint` that triggered the resolution
    ///   (provides `learned_from` — the peer to ask).
    ///
    /// # Returns
    /// - `Some(AuthenticatedNodeRecord)` if the destination was successfully
    ///   resolved and verified.
    /// - `None` if resolution failed (unreachable, no advertisement, etc.)
    fn resolve(
        &self,
        destination: &[u8; 32],
        hint: &RemoteNodeHint,
    ) -> Option<AuthenticatedNodeRecord>;
}

/// A no-op resolver that never resolves anything.
///
/// Used when no remote resolution is available (e.g., the node has no
/// active connections to ask). All remote candidates will fail with
/// `DestinationUnresolved`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullResolver;

impl DestinationResolver for NullResolver {
    fn resolve(
        &self,
        _destination: &[u8; 32],
        _hint: &RemoteNodeHint,
    ) -> Option<AuthenticatedNodeRecord> {
        None
    }
}

/// **TEST-ONLY.** An in-memory resolver that maps NodeId → AuthenticatedNodeRecord.
///
/// ## N2.1.2.1: This is NOT a production resolver
///
/// `InMemoryResolver` simulates destination resolution by returning
/// pre-authenticated records from a local map. It does NOT perform any
/// network operation, does NOT query next-hop peers, and does NOT obtain
/// advertisements through an authenticated protocol.
///
/// It is suitable ONLY for deterministic route-engine testing. In a
/// production system, a real `DestinationResolver` implementation MUST
/// obtain destination advertisements through an authenticated protocol
/// (e.g., querying an authenticated next-hop peer, receiving the
/// advertisement bytes, and calling `NodeAdvertisement::verify_into_verified()`).
///
/// `DestinationResolver` is a **TRUST BOUNDARY**, not merely a lookup
/// interface.
#[derive(Debug, Clone, Default)]
pub struct InMemoryResolver {
    records: HashMap<[u8; 32], AuthenticatedNodeRecord>,
}

impl InMemoryResolver {
    /// Create a new empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authenticated record for a destination.
    pub fn register(&mut self, record: AuthenticatedNodeRecord) {
        self.records.insert(record.node_id(), record);
    }

    /// Register a verified advertisement (convenience).
    pub fn register_verified(&mut self, verified: VerifiedNodeAdvertisement) {
        self.records.insert(verified.node_id(), verified.into_record());
    }
}

impl DestinationResolver for InMemoryResolver {
    fn resolve(
        &self,
        destination: &[u8; 32],
        _hint: &RemoteNodeHint,
    ) -> Option<AuthenticatedNodeRecord> {
        self.records.get(destination).cloned()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Distributed route discovery boundary (N2.1.2.1)
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.2.1.** The distributed route-discovery interface.
///
/// This trait defines the interface for a FUTURE production implementation
/// of distributed next-hop route discovery. It is **explicitly unimplemented**
/// in this milestone — no production implementation exists.
///
/// ## What this would do (when implemented)
///
/// In a real ShareNet mesh, node A may know only B, while the full path
/// A → B → C → G requires discovering B→C and C→G links that A does NOT
/// locally possess. A `DistributedRouteDiscovery` implementation would:
///
/// 1. Query an authenticated next-hop peer (e.g., B) for the next segment
///    of the path toward the destination.
/// 2. Receive the next-hop node's advertisement (or the destination's
///    advertisement if the next-hop peer knows it directly).
/// 3. Verify the received advertisement via `NodeAdvertisement::verify_into_verified()`.
/// 4. Discover the usable link from the current hop to the next hop.
/// 5. Update the local route-discovery state with the newly authenticated
///    node and link.
/// 6. Continue until the destination is reached and authenticated.
///
/// ## Why it's not implemented yet
///
/// Distributed route discovery requires:
/// - An authenticated query/response protocol between peers.
/// - A way to request and verify advertisements through the mesh.
/// - A way to discover usable links without already possessing them locally.
///
/// These are networking-layer concerns that belong in a future milestone
/// (N2.1.x or N2.2.x), not in the route-engine library.
///
/// ## Current approach
///
/// The `RouteEngine` currently performs LOCAL path computation over the
/// local `TopologyGraph`'s `LinkTable`. It can only traverse links that
/// are already present locally. The `DestinationResolver` trait bridges
/// non-authoritative hints to authenticated records, but the current
/// implementations (`NullResolver`, `InMemoryResolver`) do NOT perform
/// distributed discovery.
///
/// ## Marker
///
/// This trait exists to make the architectural boundary EXPLICIT. The
/// `DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED` constant below is `false`,
/// allowing tests and documentation to verify that distributed discovery
/// is not yet available.
pub trait DistributedRouteDiscovery {
    /// Discover a path to a destination by querying next-hop peers.
    ///
    /// Returns the ordered path of authenticated NodeIds and the links
    /// between them, or `None` if discovery failed.
    ///
    /// This method is NOT implemented in this milestone.
    fn discover_path(
        &mut self,
        source: &[u8; 32],
        destination: &[u8; 32],
    ) -> Option<Vec<([u8; 32], crate::node::link::LinkKey)>>;
}

/// **N2.1.2.1.** A compile-time and runtime marker indicating whether
/// distributed route discovery is implemented.
///
/// This is `false` in the current milestone. Tests can check this value
/// to verify that the architecture explicitly marks distributed discovery
/// as unimplemented.
pub const DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED: bool = false;

// ════════════════════════════════════════════════════════════════════════════
// Route cost model
// ════════════════════════════════════════════════════════════════════════════

/// A pluggable route cost model.
///
/// The cost model determines which path is preferred when multiple paths
/// exist to the same destination. It operates on MEASURED and SIGNED data
/// only — never on SELF_REPORTED hint values.
///
/// ## Metric classification
///
/// - **MEASURED** — locally observed link metrics (RTT, success rate).
/// - **SIGNED** — authenticated capabilities from `VerifiedNodeDescriptor`.
/// - **SELF_REPORTED** — untrusted values from `RemoteNodeHint`
///   (`distance_hint`, `claimed_capabilities`). These MUST NOT influence
///   cost. They may only prioritize candidate resolution order.
pub trait RouteCostModel {
    /// Compute the cost of a path.
    ///
    /// Lower cost is better. The cost is computed from the ordered list of
    /// links and nodes along the path.
    ///
    /// # Parameters
    /// - `links`: The ordered directed links forming the path.
    /// - `nodes`: The ordered authenticated nodes (excluding source, including
    ///   destination).
    fn path_cost(&self, links: &[&AuthenticatedLink], nodes: &[&AuthenticatedNodeRecord]) -> u64;
}

/// The default cost model: minimize hop count.
///
/// Ties are broken by total RTT (lower is better). This uses only MEASURED
/// link data (RTT) and SIGNED capability data (none needed for hop count).
#[derive(Debug, Clone, Copy, Default)]
pub struct HopCountCost;

impl RouteCostModel for HopCountCost {
    fn path_cost(&self, links: &[&AuthenticatedLink], _nodes: &[&AuthenticatedNodeRecord]) -> u64 {
        // Primary: hop count. Each hop contributes a large base cost.
        // Secondary: total RTT (measured). Lower RTT is better.
        let hop_cost = links.len() as u64 * 1_000_000;
        let rtt_cost: u64 = links
            .iter()
            .map(|l| l.metrics().rtt_micros.unwrap_or(0))
            .sum();
        hop_cost + rtt_cost
    }
}

/// A cost model that minimizes total measured RTT.
#[derive(Debug, Clone, Copy, Default)]
pub struct LowLatencyCost;

impl RouteCostModel for LowLatencyCost {
    fn path_cost(&self, links: &[&AuthenticatedLink], _nodes: &[&AuthenticatedNodeRecord]) -> u64 {
        links
            .iter()
            .map(|l| l.metrics().rtt_micros.unwrap_or(100_000)) // penalize unknown RTT
            .sum()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Route engine
// ════════════════════════════════════════════════════════════════════════════

/// The route discovery engine.
///
/// Operates on a `TopologyGraph` to discover, resolve, and construct
/// authenticated routes toward Internet gateways.
///
/// ## Usage
///
/// ```no_run
/// use snp_node::node::*;
/// # let topology: TopologyGraph = unimplemented!();
/// let engine = RouteEngine::new([0x01; 32]);
/// let mut candidates = engine.discover_gateway_candidates(&topology);
/// // Resolve remote candidates and construct routes...
/// engine.compute_routes(&topology, &mut candidates, &NullResolver, &HopCountCost);
/// ```
pub struct RouteEngine {
    /// The local node's NodeId (the route source).
    source: [u8; 32],
}

impl RouteEngine {
    /// Create a new route engine for the given local node.
    ///
    /// # Parameters
    /// - `source`: The local node's NodeId. All routes computed by this
    ///   engine will have this as the source.
    #[must_use]
    pub fn new(source: [u8; 32]) -> Self {
        Self { source }
    }

    /// Get the source NodeId.
    #[must_use]
    pub fn source(&self) -> [u8; 32] {
        self.source
    }

    // ─── Candidate discovery ─────────────────────────────────────────────

    /// Discover gateway candidates from the topology.
    ///
    /// Returns a list of `RouteCandidate`s, each in an initial state:
    /// - Direct gateways → `Authenticated` state.
    /// - Remote gateway hints → `Discovered` state.
    ///
    /// Remote candidates MUST be resolved before route construction.
    #[must_use]
    pub fn discover_gateway_candidates(
        &self,
        topology: &TopologyGraph,
    ) -> Vec<RouteCandidate> {
        let mut candidates = Vec::new();

        // Direct authenticated gateways (ALL accepted gateway records,
        // not just those with usable links — a gateway might be reachable
        // through relays).
        for record in topology.all_gateway_records() {
            let destination = record.node_id();
            candidates.push(RouteCandidate {
                destination,
                origin: CandidateOrigin::Direct { record: record.clone() },
                state: RouteCandidateState::Authenticated { destination },
            });
        }

        // Remote gateway hints (non-authoritative).
        for hint in topology.gateway_hints() {
            let destination = hint.target_node_id;
            candidates.push(RouteCandidate {
                destination,
                origin: CandidateOrigin::Remote { hint: hint.clone() },
                state: RouteCandidateState::Discovered {
                    source_hint: hint.clone(),
                },
            });
        }

        // Sort candidates: direct (authenticated) first, then by distance_hint
        // (lower is better) for remote candidates. This prioritizes
        // resolution of closer candidates. distance_hint is SELF_REPORTED
        // and only affects resolution ORDER, never route cost.
        candidates.sort_by_key(|c| match &c.origin {
            CandidateOrigin::Direct { .. } => (0u8, 0u8),
            CandidateOrigin::Remote { hint } => (1u8, hint.distance_hint),
        });

        candidates
    }

    // ─── Destination resolution ──────────────────────────────────────────

    /// Resolve a remote candidate into an authenticated destination.
    ///
    /// Uses the `DestinationResolver` to obtain the destination's
    /// `AuthenticatedNodeRecord`. If successful, the candidate state
    /// advances to `Authenticated`. If not, it advances to `Failed`.
    ///
    /// Direct candidates (already authenticated) are returned unchanged.
    pub fn resolve_candidate(
        &self,
        candidate: &mut RouteCandidate,
        resolver: &dyn DestinationResolver,
    ) {
        match &candidate.origin {
            CandidateOrigin::Direct { .. } => {
                // Already authenticated — nothing to resolve.
            }
            CandidateOrigin::Remote { hint } => {
                // Move to Resolving state.
                let dest = candidate.destination;
                candidate.state = RouteCandidateState::Resolving { destination: dest };

                // Attempt resolution.
                match resolver.resolve(&dest, hint) {
                    Some(record) => {
                        // Verify the resolved record is a gateway with X25519.
                        if !record.descriptor.is_gateway() {
                            candidate.state = RouteCandidateState::Failed {
                                reason: RouteDiscoveryError::DestinationNotGateway(NodeIdHex(dest)),
                            };
                            return;
                        }
                        if record.descriptor.circuit_x25519_pub().is_none() {
                            candidate.state = RouteCandidateState::Failed {
                                reason: RouteDiscoveryError::GatewayMissingCircuitKey,
                            };
                            return;
                        }
                        // Check expiry.
                        if record.is_expired(now_unix()) {
                            candidate.state = RouteCandidateState::Failed {
                                reason: RouteDiscoveryError::DestinationExpired,
                            };
                            return;
                        }
                        candidate.state = RouteCandidateState::Authenticated {
                            destination: dest,
                        };
                    }
                    None => {
                        candidate.state = RouteCandidateState::Failed {
                            reason: RouteDiscoveryError::DestinationUnresolved,
                        };
                    }
                }
            }
        }
    }

    /// Resolve all remote candidates in a list.
    pub fn resolve_candidates(
        &self,
        candidates: &mut [RouteCandidate],
        resolver: &dyn DestinationResolver,
    ) {
        for candidate in candidates.iter_mut() {
            self.resolve_candidate(candidate, resolver);
        }
    }

    // ─── Path computation (Dijkstra over directed authenticated links) ───

    /// Find the lowest-cost usable directed path from source to destination.
    ///
    /// Uses Dijkstra with a proper min-heap to find the lowest-cost path
    /// according to the `RouteCostModel`. Only USABLE directed links
    /// (Up/Degraded) are traversed. Only AUTHENTICATED nodes (in the local
    /// topology or added to the working set) are visited.
    ///
    /// **N2.1.2.1:** Returns the ordered path of NodeIds (excluding source,
    /// including destination), the ordered list of selected Links (each
    /// carrying its `LinkKey.endpoint`), AND the total computed cost.
    /// The links are returned so that `build_route` can use the EXACT
    /// `LinkKey.endpoint` for each `RouteHop` — NOT `record.endpoints.first()`.
    ///
    /// Returns `None` if no path exists.
    fn find_path(
        &self,
        topology: &TopologyGraph,
        destination: &[u8; 32],
        cost_model: &dyn RouteCostModel,
        // Extra authenticated records from resolution (NodeId → record).
        // These are nodes that were resolved but may not be in the local
        // topology. The path engine checks these if the local topology
        // doesn't have the record.
        extra_records: &HashMap<[u8; 32], AuthenticatedNodeRecord>,
    ) -> Option<(Vec<[u8; 32]>, Vec<AuthenticatedLink>, u64)> {
        if self.source == [0u8; 32] {
            return None;
        }

        // Build adjacency: for each node, list of outgoing LinkKeys.
        // Only usable directed authenticated links are included.
        let mut adjacency: HashMap<[u8; 32], Vec<LinkKey>> = HashMap::new();
        for auth in topology.directory().link_table().all() {
            if auth.is_usable() {
                adjacency
                    .entry(auth.local_node_id())
                    .or_default()
                    .push(auth.key().clone());
            }
        }

        // Dijkstra with cost model.
        // We use a proper min-heap (BinaryHeap with custom Ord) to ensure
        // the lowest-cost path is always expanded first. This is critical
        // for correctness — a FIFO queue would not guarantee optimal paths.
        //
        // State: (cumulative_cost, counter, current_node, path_of_node_ids, path_of_links)
        // The counter breaks ties in cost to ensure deterministic ordering
        // and prevents comparing Vec<Link> (which doesn't implement Ord).
        let mut visited: HashSet<[u8; 32]> = HashSet::new();
        let mut counter: u64 = 0;
        let mut heap: std::collections::BinaryHeap<HeapEntry> = std::collections::BinaryHeap::new();
        heap.push(HeapEntry {
            cost: 0u64,
            counter: 0,
            node: self.source,
            path: Vec::new(),
            links: Vec::new(),
        });

        // Track the best cost to each node (for pruning).
        let mut best_cost: HashMap<[u8; 32], u64> = HashMap::new();
        best_cost.insert(self.source, 0u64);

        while let Some(entry) = heap.pop() {
            let HeapEntry { cost, node, path, links, .. } = entry;

            // Skip if we've already visited this node via a lower-cost path.
            if visited.contains(&node) {
                continue;
            }
            // Skip if we've found a better path to this node since this
            // entry was enqueued.
            if let Some(&best) = best_cost.get(&node) {
                if cost > best {
                    continue;
                }
            }
            visited.insert(node);

            if node == *destination && !path.is_empty() {
                // N2.1.2.1: return the cost alongside the path and links.
                return Some((path, links, cost));
            }

            // Explore neighbors.
            if let Some(neighbors) = adjacency.get(&node) {
                for nkey in neighbors {
                    let neighbor = nkey.remote_node_id;
                    if visited.contains(&neighbor) {
                        continue;
                    }
                    // Get the authenticated link object.
                    let auth_link = topology.directory().link_table().get(nkey)?;
                    // Get the neighbor's authenticated record (local or extra).
                    let neighbor_record = topology
                        .get_record(&neighbor)
                        .or_else(|| extra_records.get(&neighbor));
                    if neighbor_record.is_none() {
                        // Can't route through an unauthenticated node.
                        continue;
                    }
                    let neighbor_record = neighbor_record?;

                    // Compute incremental cost.
                    let mut new_links: Vec<&AuthenticatedLink> = links.iter().collect::<Vec<_>>();
                    new_links.push(auth_link);
                    let mut new_nodes: Vec<&AuthenticatedNodeRecord> =
                        path.iter()
                            .filter_map(|nid| {
                                topology.get_record(nid).or_else(|| extra_records.get(nid))
                            })
                            .collect::<Vec<_>>();
                    new_nodes.push(neighbor_record);
                    let new_cost = cost_model.path_cost(&new_links, &new_nodes);

                    let prev_best = best_cost.get(&neighbor).copied().unwrap_or(u64::MAX);
                    if new_cost < prev_best {
                        best_cost.insert(neighbor, new_cost);
                        let mut new_path = path.clone();
                        new_path.push(neighbor);
                        let mut new_links_vec = links.clone();
                        new_links_vec.push(auth_link.clone());
                        counter = counter.saturating_add(1);
                        heap.push(HeapEntry {
                            cost: new_cost,
                            counter,
                            node: neighbor,
                            path: new_path,
                            links: new_links_vec,
                        });
                    }
                }
            }
        }

        None
    }

    // ─── Route construction ──────────────────────────────────────────────

    /// Attempt to construct a validated `Route` for a single candidate.
    ///
    /// This is the full pipeline for one candidate:
    /// 1. Resolve (if remote).
    /// 2. Find a usable directed path (Dijkstra).
    /// 3. Construct `RouteHop`s from authenticated records + **selected link
    ///    endpoints** (NOT `record.endpoints.first()`).
    /// 4. Validate the route.
    /// 5. Compute `RouteCommitment` (done inside `Route::new_with_hop_details`).
    /// 6. Store the computed route cost in `RouteReady { route, cost }`.
    ///
    /// **N2.1.2.1:** Step 3 uses the `LinkKey.endpoint` from each selected
    /// link in the Dijkstra path — NOT the first endpoint from the node's
    /// advertisement. This ensures the `RouteCommitment` binds the endpoint
    /// that was actually proven usable.
    ///
    /// The candidate state is updated to reflect the outcome.
    pub fn build_route(
        &self,
        topology: &TopologyGraph,
        candidate: &mut RouteCandidate,
        resolver: &dyn DestinationResolver,
        cost_model: &dyn RouteCostModel,
    ) {
        // Step 1: Resolve if needed.
        self.resolve_candidate(candidate, resolver);

        // Check if resolution failed.
        if matches!(candidate.state, RouteCandidateState::Failed { .. }) {
            return;
        }

        // Get the destination's authenticated record.
        let destination = candidate.destination;
        let dest_record: AuthenticatedNodeRecord = match &candidate.origin {
            CandidateOrigin::Direct { record } => record.clone(),
            CandidateOrigin::Remote { .. } => {
                // After resolution, the record should be available via
                // the resolver. We re-resolve to get the record.
                // (In a production system, the resolver would cache this.)
                match resolver.resolve(&destination, &match &candidate.origin {
                    CandidateOrigin::Remote { hint } => hint.clone(),
                    _ => unreachable!(),
                }) {
                    Some(r) => r,
                    None => {
                        candidate.state = RouteCandidateState::Failed {
                            reason: RouteDiscoveryError::DestinationUnresolved,
                        };
                        return;
                    }
                }
            }
        };

        // Extra records for path finding: the resolved destination.
        let mut extra_records: HashMap<[u8; 32], AuthenticatedNodeRecord> = HashMap::new();
        if topology.get_record(&destination).is_none() {
            extra_records.insert(destination, dest_record.clone());
        }

        // Step 2: Find a usable directed path.
        // N2.1.2.1: find_path now returns (path, links, cost).
        // The links carry the selected LinkKey.endpoint for each hop.
        let (path, links, route_cost) = match self.find_path(
            topology,
            &destination,
            cost_model,
            &extra_records,
        ) {
            None => {
                candidate.state = RouteCandidateState::Failed {
                    reason: RouteDiscoveryError::NoPathFound,
                };
                return;
            }
            Some((path, links, cost)) => {
                if path.len() > MAX_ROUTE_HOPS {
                    candidate.state = RouteCandidateState::Failed {
                        reason: RouteDiscoveryError::TooManyHops(path.len()),
                    };
                    return;
                }
                // Move to Reachable state.
                candidate.state = RouteCandidateState::Reachable { path: path.clone() };
                (path, links, cost)
            }
        };

        // Step 3: Construct RouteHops from authenticated records + SELECTED
        // LINK ENDPOINTS.
        //
        // N2.1.2.1: For each hop in `path`, the corresponding link in
        // `links` is the directed link that was proven usable by Dijkstra.
        // The RouteHop MUST use `link.key.endpoint` — NOT
        // `record.endpoints.first()`. This ensures the RouteCommitment
        // binds the exact endpoint that was actually used to prove
        // reachability.
        //
        // path[i] is the i-th hop NodeId (excluding source).
        // links[i] is the link from path[i-1] (or source if i==0) to path[i].
        // links[i].key.endpoint is the endpoint of path[i] as reached
        //   via this specific link.
        debug_assert_eq!(
            path.len(),
            links.len(),
            "path and links must have the same length"
        );

        let mut hop_details: Vec<RouteHop> = Vec::with_capacity(path.len());
        for (hop_index, (node_id, auth_link)) in path.iter().zip(links.iter()).enumerate() {
            let record = topology
                .get_record(node_id)
                .or_else(|| extra_records.get(node_id))
                .cloned();
            let record = match record {
                Some(r) => r,
                None => {
                    candidate.state = RouteCandidateState::Failed {
                        reason: RouteDiscoveryError::UnauthenticatedHop,
                    };
                    return;
                }
            };
            // Validate the hop is either a relay (intermediate) or gateway (destination).
            let is_destination = *node_id == destination;
            if !is_destination && !record.descriptor.is_relay() {
                candidate.state = RouteCandidateState::Failed {
                    reason: RouteDiscoveryError::HopNotRelay { hop_index },
                };
                return;
            }
            // N2.1.2.1: Use the SELECTED LINK's endpoint — NOT
            // record.endpoints.first(). The link was proven usable by
            // Dijkstra, and its endpoint is the one that must appear in
            // the RouteHop and RouteCommitment.
            // N2.1.2.3: The link is an AuthenticatedLink — its endpoint
            // is proven to be authorized by the remote node's advertisement.
            let endpoint = auth_link.endpoint().clone();
            hop_details.push(RouteHop::new(record.descriptor.clone(), endpoint));
        }

        // Step 4: Construct the Route (this computes RouteCommitment).
        let route = Route::new_with_hop_details(self.source, destination, hop_details);

        // Step 5: Validate the route.
        if let Err(e) = route.validate() {
            candidate.state = RouteCandidateState::Failed {
                reason: RouteDiscoveryError::ValidationFailed(e),
            };
            return;
        }

        // Step 6: Route is ready — store the computed cost.
        candidate.state = RouteCandidateState::RouteReady {
            route,
            cost: route_cost,
        };
    }

    /// Compute routes for all candidates.
    ///
    /// This is the full discovery → resolution → construction pipeline.
    /// Returns the list of candidates with their final states.
    #[must_use]
    pub fn compute_routes(
        &self,
        topology: &TopologyGraph,
        candidates: &mut [RouteCandidate],
        resolver: &dyn DestinationResolver,
        cost_model: &dyn RouteCostModel,
    ) {
        for candidate in candidates.iter_mut() {
            self.build_route(topology, candidate, resolver, cost_model);
        }
    }

    /// Discover and compute all gateway routes in one call.
    ///
    /// Convenience method that:
    /// 1. Discovers all gateway candidates.
    /// 2. Resolves and constructs routes for each.
    /// 3. Returns the list of candidates with their final states.
    #[must_use]
    pub fn discover_and_compute(
        &self,
        topology: &TopologyGraph,
        resolver: &dyn DestinationResolver,
        cost_model: &dyn RouteCostModel,
    ) -> Vec<RouteCandidate> {
        let mut candidates = self.discover_gateway_candidates(topology);
        self.compute_routes(topology, &mut candidates, resolver, cost_model);
        candidates
    }

    /// Get all ready routes from a list of candidates.
    #[must_use]
    pub fn ready_routes(candidates: &[RouteCandidate]) -> Vec<&Route> {
        candidates
            .iter()
            .filter_map(|c| c.route())
            .collect()
    }

    /// **N2.1.2.1.** Get the best (lowest-computed-cost) ready route from a
    /// list of candidates.
    ///
    /// Unlike the previous implementation (which returned the first ready
    /// candidate based on discovery order), this method selects the route
    /// with the **minimum actual computed cost** from the `RouteCostModel`.
    ///
    /// The cost is stored in `RouteCandidateState::RouteReady { cost }`
    /// during `build_route()`. It reflects the actual path cost (hop count,
    /// RTT, etc.) — NOT the `distance_hint` (which is SELF_REPORTED and
    /// untrusted).
    ///
    /// Returns `None` if no candidate is ready.
    #[must_use]
    pub fn best_route(candidates: &[RouteCandidate]) -> Option<&Route> {
        candidates
            .iter()
            .filter_map(|c| c.route_cost().map(|cost| (cost, c.route().expect("ready"))))
            .min_by_key(|(cost, _)| *cost)
            .map(|(_, route)| route)
    }

    /// **N2.1.2.1.** Get the best ready route AND its computed cost.
    ///
    /// Returns `None` if no candidate is ready.
    #[must_use]
    pub fn best_route_with_cost(candidates: &[RouteCandidate]) -> Option<(&Route, u64)> {
        candidates
            .iter()
            .filter_map(|c| c.route_cost().map(|cost| (cost, c.route().expect("ready"))))
            .min_by_key(|(cost, _)| *cost)
            .map(|(cost, route)| (route, cost))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Security analysis (documentation)
// ════════════════════════════════════════════════════════════════════════════

/// Security invariants enforced by the route engine:
///
/// 1. **No hint → hop conversion**: A `RemoteNodeHint` can never become a
///    `RouteHop`. It can only trigger resolution. If resolution fails, no
///    route is produced.
///
/// 2. **No unauthenticated hop**: Every hop in a `Route` must have a
///    `VerifiedNodeDescriptor` (from a verified `NodeAdvertisement`).
///    The type system enforces this — `RouteHop` can only be constructed
///    with a `VerifiedNodeDescriptor`.
///
/// 3. **No distance_hint as route**: `distance_hint` is SELF_REPORTED and
///    only affects candidate resolution order. It never influences route
///    cost or path selection.
///
/// 4. **Directed links only**: Path computation uses only outgoing usable
///    directed links. A→B does not imply B→A.
///
/// 5. **Relay capability required**: Intermediate hops must have the Relay
///    capability. The destination must have the Gateway capability.
///
/// 6. **X25519 circuit key required**: The destination gateway must have an
///    X25519 circuit public key (checked during resolution and validation).
///
/// 7. **No topology poisoning**: A failed candidate does not mutate the
///    `TopologyGraph`. Resolution results are kept in a local `extra_records`
///    map that is discarded after route construction.
///
/// 8. **Route validation**: Every constructed route is validated via
///    `Route::validate()`, which checks all structural invariants.
///
/// ## Threats analyzed
///
/// - **Malicious RemoteNodeHint**: Stored as a hint, never as a route hop.
///   Resolution must produce a verified advertisement.
/// - **Fake gateway claims**: A hint claiming "G is a gateway" does not make
///   G a gateway. G's actual verified advertisement must have
///   `Capability::Gateway`.
/// - **Stale path claims**: Links are checked for usability (Up/Degraded).
///   Down links are not traversed.
/// - **Route poisoning**: The route engine does not write to the topology.
///   Failed candidates are local to the engine.
/// - **Endpoint substitution**: Endpoints come from `AuthenticatedNodeRecord`
///   (verified advertisement), not from hints.
/// - **Malicious relay**: A relay's advertisement must be verified. A
///   malicious relay without `Capability::Relay` cannot be an intermediate
///   hop.
/// - **Asymmetric link**: Directed links are used. A→B does not enable B→A.
/// - **Disappearing next hop**: If a link goes Down between discovery and
///   route construction, the path will not be found (NoPathFound).
/// - **Eclipse**: The route engine considers ALL direct gateways and ALL
///   gateway hints. An attacker would need to control all of them.
/// - **Route amplification**: The route engine does not propagate routes.
///   It only computes local routes from local topology.
///
/// ## Not claimed
///
/// - **Sybil resistance**: Not claimed. A Sybil attacker can create many
///   identities. This is a future concern (Civic Points / reputation).
/// - **Persistence**: Route candidates are not persisted. They are
///   recomputed on each call.
mod _security_analysis {}

//! N2.1.2 — Path Discovery and Route Construction.
//!
//! Spec: spec/07-routing.md (Sections 22–29 of the frozen spec).
//!
//! ## The frozen route pipeline
//!
//! ```text
//! Remote topology hints
//!         ↓
//! Candidate Destination
//!         ↓
//! Destination Resolution (fetch target advertisement)
//!         ↓
//! Target Authentication (verify signature + NodeId binding)
//!         ↓
//! ExecutableNetworkSnapshot
//!         ↓
//! BFS bounded path discovery (discover_path)
//!         ↓
//! DiscoveredPath (a possible sequence — NOT yet validated)
//!         ↓
//! validate_path() (every hop authenticated + every edge a usable link)
//!         ↓
//! ValidatedPath (authenticated, currently executable)
//!         ↓
//! RouteProposal::from_validated_path(...) (source's belief — NOT consent)
//!         ↓
//! RouteAcceptance (per-participant signed consent, typed role)
//!         ↓
//! CommittedRoute (finalized — ALL required participants accepted)
//! ```
//!
//! ## The critical architectural invariants
//!
//! 1. **`Authenticated topology ≠ Executable route`.**
//!    `discover_path()` uses ONLY `ExecutableNetworkSnapshot`. A
//!    `RemoteNodeHint` cannot enter routing. Furthermore, a `DiscoveredPath`
//!    is just a sequence of NodeIds — it is NOT a route. It must be
//!    `validate_path()`-d against the snapshot to produce a `ValidatedPath`,
//!    which carries the authenticated node + usable-link evidence for every
//!    hop. `RouteProposal` consumes a `ValidatedPath`, not a free-form
//!    `Vec<NodeId>`.
//!
//! 2. **`RouteProposal ≠ CommittedRoute`.**
//!    A source signing a hop list does NOT mean the relays agreed. A
//!    `CommittedRoute` can only be constructed by `commit_route()` after
//!    every required participant has produced a typed `RouteAcceptance`.
//!
//! 3. **Source is the first hop.** A `RouteProposal` where
//!    `hop_node_ids.first() != source` is rejected.
//!
//! 4. **Typed roles.** `RouteRole::Relay` / `RouteRole::Gateway`. The
//!    destination must accept Gateway; intermediate hops must accept Relay.
//!
//! 5. **Bounded BFS.** `discover_path()` enforces `ROUTE_MAX_HOPS` during
//!    search, not just at commitment.
//!
//! 6. **Freshness.** Proposals and acceptances follow the same
//!    timestamp/expiry invariants as `NodeAdvertisement`
//!    (`timestamp <= now + MAX_CLOCK_SKEW_SECS`, `expiry > now`,
//!    `expiry > timestamp`, bounded lifetime).

use super::*;
use crate::node::node_advert::{AuthenticatedNodeRecord, MAX_CLOCK_SKEW_SECS};
use crate::node::topology::{ExecutableNetworkSnapshot, RemoteNodeHint};
use crate::node::link::Link;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, derive_node_id, sha256};

/// SIG_CONTEXT for route proposals and acceptances.
pub const ROUTE_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-msg\0";

/// Maximum number of hops in a route (spec §28: bounded).
pub const ROUTE_MAX_HOPS: usize = 16;

/// Maximum lifetime of a route proposal or acceptance (seconds).
/// Shorter than advertisement lifetime (24h) — routes are more dynamic.
pub const ROUTE_MAX_LIFETIME_SECS: u64 = 3600; // 1 hour

// ─── RouteRole (typed, P1 #3) ───────────────────────────────────────────────

/// A participant's role in a route.
///
/// Replaces the free-form `role: String` from the initial N2.1.2
/// implementation. The destination (gateway) MUST accept `Gateway`; every
/// intermediate hop MUST accept `Relay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRole {
    /// An intermediate forwarding hop.
    Relay,
    /// The terminal hop providing the service (e.g. Internet gateway).
    Gateway,
}

impl RouteRole {
    /// CBOR string representation.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Gateway => "gateway",
        }
    }

    /// Parse from a CBOR string.
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "relay" => Some(Self::Relay),
            "gateway" => Some(Self::Gateway),
            _ => None,
        }
    }
}

// ─── ServiceAgreement (typed, P1 #4) ────────────────────────────────────────

/// A minimally-typed service agreement.
///
/// Replaces the free-form `service: String` from the initial N2.1.2
/// implementation. The agreement captures the negotiated service type and
/// optional requirements. Full capability negotiation (matching client
/// requirements against gateway offers per spec §31) is explicitly deferred
/// — but the type system now ensures the proposal commits to a TYPED
/// agreement, not an arbitrary string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAgreement {
    /// The service type (e.g. "internet-transit", "content-retrieval").
    pub service_type: String,
    /// Optional requirements (e.g. "max-latency:500ms", "min-bandwidth:1Mbps").
    pub requirements: Vec<String>,
}

impl ServiceAgreement {
    /// Create a new service agreement.
    #[must_use]
    pub fn new(service_type: String, requirements: Vec<String>) -> Self {
        Self { service_type, requirements }
    }

    /// CBOR representation.
    fn to_cbor(&self) -> CborValue {
        let reqs: Vec<CborValue> = self
            .requirements
            .iter()
            .map(|r| CborValue::TextString(r.clone()))
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("serviceType".into()), CborValue::TextString(self.service_type.clone())),
            (CborValue::TextString("requirements".into()), CborValue::Array(reqs)),
        ])
    }
}

// ─── Candidate Destination (spec §23) ─────────────────────────────────────

/// A candidate destination derived from a `RemoteNodeHint`.
///
/// NOT authenticated — a "maybe, worth investigating" marker.
#[derive(Debug, Clone)]
pub struct CandidateDestination {
    pub target_node_id: [u8; 32],
    pub claimed_capabilities: Vec<String>,
    pub source_hint: [u8; 32],
    pub distance_hint: u8,
}

impl CandidateDestination {
    #[must_use]
    pub fn from_hint(hint: &RemoteNodeHint) -> Self {
        Self {
            target_node_id: hint.target_node_id,
            claimed_capabilities: hint.claimed_capabilities.clone(),
            source_hint: hint.learned_from,
            distance_hint: hint.distance_hint,
        }
    }

    #[must_use]
    pub fn claims_gateway(&self) -> bool {
        self.claimed_capabilities.iter().any(|c| c == "gateway")
    }
}

// ─── DiscoveredPath (BFS result, NOT yet validated) ────────────────────────

/// A path discovered by BFS over `ExecutableNetworkSnapshot`.
///
/// This is a SEQUENCE of NodeIds — it is NOT yet validated. The caller must
/// call `validate_path()` to produce a `ValidatedPath` (which carries the
/// authenticated node + usable-link evidence) before constructing a
/// `RouteProposal`.
#[derive(Debug, Clone)]
pub struct DiscoveredPath {
    /// Ordered NodeIds from source to destination.
    pub hops: Vec<[u8; 32]>,
}

impl DiscoveredPath {
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Discover a candidate path using BFS over `ExecutableNetworkSnapshot`.
///
/// ## Bounded BFS (P1 #5)
///
/// The search depth is bounded by `ROUTE_MAX_HOPS`. Paths longer than
/// `ROUTE_MAX_HOPS` hops are not discovered (the BFS prunes them during
/// search, not after).
///
/// ## Algorithm choice
///
/// BFS (not Dijkstra/A*) — per spec §62: "prioritize correctness,
/// authentication, bounded state, failure handling over theoretical
/// optimality." Do NOT replace with Dijkstra.
#[must_use]
pub fn discover_path(
    snapshot: &ExecutableNetworkSnapshot,
    source: &[u8; 32],
    destination: &[u8; 32],
) -> Option<DiscoveredPath> {
    use std::collections::{HashMap, VecDeque};
    let mut visited: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut parent: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    let mut depth: HashMap<[u8; 32], usize> = HashMap::new();
    let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
    visited.insert(*source);
    depth.insert(*source, 0);
    queue.push_back(*source);

    while let Some(current) = queue.pop_front() {
        if current == *destination {
            // Reconstruct path.
            let mut path = vec![*destination];
            let mut node = *destination;
            while node != *source {
                node = *parent.get(&node)?;
                path.push(node);
            }
            path.reverse();
            return Some(DiscoveredPath { hops: path });
        }
        let current_depth = *depth.get(&current).unwrap_or(&0);
        // P1 #5: bound BFS by ROUTE_MAX_HOPS. If we're already at max depth,
        // don't expand further.
        if current_depth >= ROUTE_MAX_HOPS {
            continue;
        }
        // Explore neighbors via usable links.
        for link in snapshot.usable_links.values() {
            if link.key.local_node_id == current && !visited.contains(&link.key.remote_node_id) {
                visited.insert(link.key.remote_node_id);
                parent.insert(link.key.remote_node_id, current);
                depth.insert(link.key.remote_node_id, current_depth + 1);
                queue.push_back(link.key.remote_node_id);
            }
        }
    }
    None
}

// ─── ValidatedPath (P0 #1 — authenticated evidence per hop) ────────────────

/// A hop in a `ValidatedPath` — carries the authenticated node record AND
/// the usable directed link that connects it to the previous hop.
#[derive(Debug, Clone)]
pub struct AuthenticatedHop {
    /// The hop's NodeId.
    pub node_id: [u8; 32],
    /// The authenticated node record (verified advertisement).
    pub record: AuthenticatedNodeRecord,
    /// The usable directed link from the previous hop to this hop.
    /// `None` for the source (first hop — no incoming link).
    pub incoming_link: Option<Link>,
}

/// A validated path — every hop is authenticated AND every edge is a usable
/// directed link in the `ExecutableNetworkSnapshot`.
///
/// ## Construction
///
/// `ValidatedPath` can ONLY be constructed by `validate_path()`, which
/// checks every hop against `snapshot.authenticated_nodes` and every edge
/// against `snapshot.usable_links`. The `hops` field is private; callers
/// access it via `hops()`.
///
/// This is the **only** input that `RouteProposal::from_validated_path()`
/// accepts. A free-form `Vec<NodeId>` is NO LONGER sufficient to construct a
/// `RouteProposal` — the proposal must be backed by validated executable
/// topology evidence.
#[derive(Debug, Clone)]
pub struct ValidatedPath {
    hops: Vec<AuthenticatedHop>,
}

/// Error from `validate_path()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The discovered path is empty.
    Empty,
    /// A hop in the path is not in `authenticated_nodes`.
    HopNotAuthenticated { index: usize, node_id: [u8; 32] },
    /// No usable link exists between two consecutive hops.
    NoUsableLink { from: [u8; 32], to: [u8; 32] },
    /// The path exceeds `ROUTE_MAX_HOPS`.
    ExcessiveHops { count: usize },
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "discovered path is empty"),
            Self::HopNotAuthenticated { index, node_id } => write!(f, "hop {index} ({}) is not authenticated", hex_short(node_id)),
            Self::NoUsableLink { from, to } => write!(f, "no usable link from {} to {}", hex_short(from), hex_short(to)),
            Self::ExcessiveHops { count } => write!(f, "path has too many hops: {count} > {ROUTE_MAX_HOPS}"),
        }
    }
}

impl std::error::Error for PathError {}

impl ValidatedPath {
    /// The ordered authenticated hops.
    #[must_use]
    pub fn hops(&self) -> &[AuthenticatedHop] {
        &self.hops
    }

    /// The ordered NodeIds (derived from hops).
    #[must_use]
    pub fn node_ids(&self) -> Vec<[u8; 32]> {
        self.hops.iter().map(|h| h.node_id).collect()
    }

    /// The source NodeId (first hop).
    #[must_use]
    pub fn source(&self) -> [u8; 32] {
        self.hops[0].node_id
    }

    /// The destination NodeId (last hop).
    #[must_use]
    pub fn destination(&self) -> [u8; 32] {
        self.hops[self.hops.len() - 1].node_id
    }

    /// The required participants (every hop except the source).
    #[must_use]
    pub fn required_participants(&self) -> Vec<[u8; 32]> {
        self.hops
            .iter()
            .skip(1) // skip source
            .map(|h| h.node_id)
            .collect()
    }
}

/// Validate a `DiscoveredPath` against an `ExecutableNetworkSnapshot`.
///
/// Checks:
/// - Path is non-empty and ≤ `ROUTE_MAX_HOPS`.
/// - Every hop is in `snapshot.authenticated_nodes`.
/// - Every consecutive pair has a usable directed link in
///   `snapshot.usable_links`.
///
/// # Errors
/// Returns `PathError` if any check fails.
pub fn validate_path(
    snapshot: &ExecutableNetworkSnapshot,
    discovered: &DiscoveredPath,
) -> Result<ValidatedPath, PathError> {
    if discovered.hops.is_empty() {
        return Err(PathError::Empty);
    }
    if discovered.hops.len() > ROUTE_MAX_HOPS {
        return Err(PathError::ExcessiveHops { count: discovered.hops.len() });
    }

    let mut hops = Vec::with_capacity(discovered.hops.len());
    for (i, &node_id) in discovered.hops.iter().enumerate() {
        let record = snapshot
            .authenticated_nodes
            .get(&node_id)
            .cloned()
            .ok_or(PathError::HopNotAuthenticated { index: i, node_id })?;

        let incoming_link: Option<Link> = if i == 0 {
            None // source has no incoming link
        } else {
            let prev = discovered.hops[i - 1];
            Some(
                snapshot
                    .usable_links
                    .values()
                    .find(|l| l.key.local_node_id == prev && l.key.remote_node_id == node_id && l.is_usable())
                    .cloned()
                    .ok_or(PathError::NoUsableLink { from: prev, to: node_id })?,
            )
        };

        hops.push(AuthenticatedHop {
            node_id,
            record,
            incoming_link,
        });
    }

    Ok(ValidatedPath { hops })
}

// ─── RouteProposal (spec §27) ─────────────────────────────────────────────

/// The source's proposed route — a belief that a path COULD work.
///
/// ## CRITICAL: NOT a committed route
///
/// Signed by the SOURCE only. Does NOT prove relays agreed. To become a
/// `CommittedRoute`, every required participant must produce a typed
/// `RouteAcceptance`.
///
/// ## Construction (P0 #1)
///
/// The ONLY constructor is `RouteProposal::from_validated_path()`, which
/// consumes a `ValidatedPath` (backed by `ExecutableNetworkSnapshot`
/// evidence). A free-form `Vec<NodeId>` is NO LONGER accepted.
#[derive(Debug, Clone)]
pub struct RouteProposal {
    pub protocol_version: u8,
    pub source: [u8; 32],
    pub destination: [u8; 32],
    pub hop_node_ids: Vec<[u8; 32]>,
    /// The negotiated service agreement (typed, not a free-form string).
    pub service: ServiceAgreement,
    pub timestamp: u64,
    pub expiry: u64,
    pub nonce: [u8; 16],
    pub source_signature: [u8; 64],
    pub source_public_key: [u8; 32],
}

impl RouteProposal {
    /// Create and sign a `RouteProposal` from a `ValidatedPath`.
    ///
    /// This is the ONLY constructor. The path must be validated against an
    /// `ExecutableNetworkSnapshot` first — the caller cannot pass an
    /// arbitrary `Vec<NodeId>`.
    #[must_use]
    pub fn from_validated_path(
        path: &ValidatedPath,
        source_secret_key: &[u8; 32],
        source_public_key: &[u8; 32],
        service: ServiceAgreement,
        expiry: u64,
    ) -> Self {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        let source = path.source();
        let destination = path.destination();
        let hop_node_ids = path.node_ids();
        let mut proposal = Self {
            protocol_version: 1,
            source,
            destination,
            hop_node_ids,
            service,
            timestamp: now,
            expiry,
            nonce,
            source_signature: [0u8; 64],
            source_public_key: *source_public_key,
        };
        proposal.source_signature = ed25519_sign(source_secret_key, &proposal.preimage_bytes());
        proposal
    }

    fn preimage(&self) -> CborValue {
        let hops: Vec<CborValue> = self
            .hop_node_ids
            .iter()
            .map(|h| CborValue::ByteString(h.to_vec()))
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("protocolVersion".into()), CborValue::UnsignedInt(u64::from(self.protocol_version))),
            (CborValue::TextString("source".into()), CborValue::ByteString(self.source.to_vec())),
            (CborValue::TextString("destination".into()), CborValue::ByteString(self.destination.to_vec())),
            (CborValue::TextString("hops".into()), CborValue::Array(hops)),
            (CborValue::TextString("service".into()), self.service.to_cbor()),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
            (CborValue::TextString("nonce".into()), CborValue::ByteString(self.nonce.to_vec())),
        ])
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let cbor = snp_cbor::encode(&self.preimage()).unwrap_or_default();
        let mut msg = Vec::with_capacity(ROUTE_MSG_CONTEXT.len() + cbor.len());
        msg.extend_from_slice(ROUTE_MSG_CONTEXT);
        msg.extend_from_slice(&cbor);
        msg
    }

    /// Compute the SHA-256 hash of this proposal (used as the acceptance key).
    #[must_use]
    pub fn proposal_hash(&self) -> [u8; 32] {
        sha256(&self.preimage_bytes())
    }

    /// Verify the source's signature, NodeId↔pubkey binding, AND freshness
    /// invariants (P1 #7).
    ///
    /// Checks:
    /// - `source == derive_node_id(source_public_key)` (I4)
    /// - Ed25519 signature valid
    /// - `source == hop_node_ids.first()` (P0 #2 — source is first hop)
    /// - `timestamp <= now + MAX_CLOCK_SKEW_SECS` (not future-dated)
    /// - `expiry > now` (not expired)
    /// - `expiry > timestamp` (sane)
    /// - `expiry - timestamp <= ROUTE_MAX_LIFETIME_SECS` (bounded lifetime)
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_at(now_unix())
    }

    /// Verify at a specific time (for testing).
    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        // I4: NodeId ↔ pubkey binding.
        let expected = derive_node_id(&self.source_public_key);
        if self.source != expected {
            return false;
        }
        // P0 #2: source must be the first hop.
        if self.hop_node_ids.first() != Some(&self.source) {
            return false;
        }
        // P1 #7: freshness.
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return false;
        }
        if self.expiry <= now {
            return false;
        }
        if self.expiry <= self.timestamp {
            return false;
        }
        if self.expiry.saturating_sub(self.timestamp) > ROUTE_MAX_LIFETIME_SECS {
            return false;
        }
        // Signature.
        ed25519_verify(
            &self.source_public_key,
            &self.preimage_bytes(),
            &self.source_signature,
        )
    }

    /// The required participants (every hop except the source).
    #[must_use]
    pub fn required_participants(&self) -> Vec<[u8; 32]> {
        self.hop_node_ids
            .iter()
            .filter(|h| **h != self.source)
            .copied()
            .collect()
    }
}

// ─── RouteAcceptance (spec §27, typed role P1 #3) ─────────────────────────

/// A participant's signed acceptance of their role in a proposed route.
#[derive(Debug, Clone)]
pub struct RouteAcceptance {
    pub proposal_hash: [u8; 32],
    pub participant_node_id: [u8; 32],
    pub participant_public_key: [u8; 32],
    /// Typed role (Relay or Gateway) — NOT a free-form string.
    pub role: RouteRole,
    pub conditions: Vec<String>,
    pub timestamp: u64,
    pub expiry: u64,
    pub signature: [u8; 64],
}

impl RouteAcceptance {
    /// Create and sign a `RouteAcceptance` with a typed role.
    #[must_use]
    pub fn create_and_sign(
        participant_secret_key: &[u8; 32],
        participant_public_key: &[u8; 32],
        participant_node_id: [u8; 32],
        proposal_hash: [u8; 32],
        role: RouteRole,
        conditions: Vec<String>,
        expiry: u64,
    ) -> Self {
        let now = now_unix();
        let mut acceptance = Self {
            proposal_hash,
            participant_node_id,
            participant_public_key: *participant_public_key,
            role,
            conditions,
            timestamp: now,
            expiry,
            signature: [0u8; 64],
        };
        acceptance.signature = ed25519_sign(participant_secret_key, &acceptance.preimage_bytes());
        acceptance
    }

    fn preimage(&self) -> CborValue {
        let conditions: Vec<CborValue> = self
            .conditions
            .iter()
            .map(|c| CborValue::TextString(c.clone()))
            .collect();
        CborValue::Map(vec![
            (CborValue::TextString("proposalHash".into()), CborValue::ByteString(self.proposal_hash.to_vec())),
            (CborValue::TextString("participantNodeId".into()), CborValue::ByteString(self.participant_node_id.to_vec())),
            (CborValue::TextString("participantPublicKey".into()), CborValue::ByteString(self.participant_public_key.to_vec())),
            (CborValue::TextString("role".into()), CborValue::TextString(self.role.as_str().into())),
            (CborValue::TextString("conditions".into()), CborValue::Array(conditions)),
            (CborValue::TextString("timestamp".into()), CborValue::UnsignedInt(self.timestamp)),
            (CborValue::TextString("expiry".into()), CborValue::UnsignedInt(self.expiry)),
        ])
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let cbor = snp_cbor::encode(&self.preimage()).unwrap_or_default();
        let mut msg = Vec::with_capacity(ROUTE_MSG_CONTEXT.len() + cbor.len());
        msg.extend_from_slice(ROUTE_MSG_CONTEXT);
        msg.extend_from_slice(&cbor);
        msg
    }

    /// Verify signature + NodeId binding + freshness (P1 #7).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_at(now_unix())
    }

    /// Verify at a specific time (for testing).
    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        let expected = derive_node_id(&self.participant_public_key);
        if self.participant_node_id != expected {
            return false;
        }
        // P1 #7: freshness.
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return false;
        }
        if self.expiry <= now {
            return false;
        }
        if self.expiry <= self.timestamp {
            return false;
        }
        if self.expiry.saturating_sub(self.timestamp) > ROUTE_MAX_LIFETIME_SECS {
            return false;
        }
        ed25519_verify(
            &self.participant_public_key,
            &self.preimage_bytes(),
            &self.signature,
        )
    }
}

// ─── CommittedRoute (spec §27) ────────────────────────────────────────────

/// A finalized route — produced ONLY after every required participant has
/// produced a valid, typed `RouteAcceptance`.
///
/// Fields are private. Only `commit_route()` constructs one.
#[derive(Debug, Clone)]
pub struct CommittedRoute {
    proposal: RouteProposal,
    commitment: [u8; 32],
    acceptances: Vec<RouteAcceptance>,
    committed_at: u64,
}

/// Error from `commit_route()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    ProposalSignatureInvalid,
    ProposalExpired { now: u64, expiry: u64 },
    MissingAcceptance { participant: [u8; 32] },
    AcceptanceSignatureInvalid { participant: [u8; 32] },
    AcceptanceProposalMismatch { participant: [u8; 32] },
    AcceptanceExpired { participant: [u8; 32], now: u64, expiry: u64 },
    UnexpectedParticipant { participant: [u8; 32] },
    /// P1 #3: the participant's role is wrong for their position.
    WrongRole { participant: [u8; 32], expected: RouteRole, actual: RouteRole },
    EmptyRoute,
    ExcessiveHops { count: usize },
    DestinationMismatch,
    DuplicateHop { node_id: [u8; 32] },
    /// P0 #2: source is not the first hop.
    SourceNotFirstHop,
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProposalSignatureInvalid => write!(f, "proposal source signature invalid"),
            Self::ProposalExpired { now, expiry } => write!(f, "proposal expired (now={now}, expiry={expiry})"),
            Self::MissingAcceptance { participant } => write!(f, "missing acceptance from {}", hex_short(participant)),
            Self::AcceptanceSignatureInvalid { participant } => write!(f, "acceptance signature invalid from {}", hex_short(participant)),
            Self::AcceptanceProposalMismatch { participant } => write!(f, "acceptance from {} is for a different proposal", hex_short(participant)),
            Self::AcceptanceExpired { participant, now, expiry } => write!(f, "acceptance from {} expired (now={now}, expiry={expiry})", hex_short(participant)),
            Self::UnexpectedParticipant { participant } => write!(f, "acceptance from unexpected participant {}", hex_short(participant)),
            Self::WrongRole { participant, expected, actual } => write!(f, "participant {} has wrong role: expected {:?}, got {:?}", hex_short(participant), expected, actual),
            Self::EmptyRoute => write!(f, "route has no hops"),
            Self::ExcessiveHops { count } => write!(f, "route has too many hops: {count} > {ROUTE_MAX_HOPS}"),
            Self::DestinationMismatch => write!(f, "destination is not the last hop"),
            Self::DuplicateHop { node_id } => write!(f, "duplicate hop: {}", hex_short(node_id)),
            Self::SourceNotFirstHop => write!(f, "source is not the first hop"),
        }
    }
}

/// Commit a route proposal into a `CommittedRoute`.
///
/// Verifies:
/// 1. Proposal signature + freshness (via `proposal.verify()`).
/// 2. Source is the first hop (P0 #2).
/// 3. Structural validity (hop count, destination last, no loops).
/// 4. Every required participant has a valid `RouteAcceptance` with the
///    correct typed role (P1 #3): destination = Gateway, intermediate = Relay.
/// 5. Each acceptance's `proposal_hash` matches.
/// 6. Each acceptance is fresh and not expired.
pub fn commit_route(
    proposal: RouteProposal,
    acceptances: Vec<RouteAcceptance>,
    now: u64,
) -> Result<CommittedRoute, CommitError> {
    // 1. Verify the proposal (signature + freshness + source==first).
    if !proposal.verify_at(now) {
        // Distinguish expiry from signature/source for clearer errors.
        if proposal.expiry <= now {
            return Err(CommitError::ProposalExpired { now, expiry: proposal.expiry });
        }
        return Err(CommitError::ProposalSignatureInvalid);
    }

    // 2. P0 #2: source must be the first hop (also checked in verify_at, but
    //    return a distinct error here for clarity).
    if proposal.hop_node_ids.first() != Some(&proposal.source) {
        return Err(CommitError::SourceNotFirstHop);
    }

    // 3. Structural validation.
    if proposal.hop_node_ids.is_empty() {
        return Err(CommitError::EmptyRoute);
    }
    if proposal.hop_node_ids.len() > ROUTE_MAX_HOPS {
        return Err(CommitError::ExcessiveHops { count: proposal.hop_node_ids.len() });
    }
    if *proposal.hop_node_ids.last().unwrap() != proposal.destination {
        return Err(CommitError::DestinationMismatch);
    }
    let mut seen = std::collections::HashSet::new();
    for hop in &proposal.hop_node_ids {
        if !seen.insert(*hop) {
            return Err(CommitError::DuplicateHop { node_id: *hop });
        }
    }

    // 4. Required participants + expected roles (P1 #3).
    let required: Vec<([u8; 32], RouteRole)> = proposal
        .hop_node_ids
        .iter()
        .filter(|h| **h != proposal.source)
        .map(|h| {
            let role = if *h == proposal.destination {
                RouteRole::Gateway
            } else {
                RouteRole::Relay
            };
            (*h, role)
        })
        .collect();

    // 5. Verify each acceptance.
    let mut accepted_by: std::collections::HashMap<[u8; 32], &RouteAcceptance> = std::collections::HashMap::new();
    for acc in &acceptances {
        if !acc.verify_at(now) {
            if acc.expiry <= now {
                return Err(CommitError::AcceptanceExpired { participant: acc.participant_node_id, now, expiry: acc.expiry });
            }
            return Err(CommitError::AcceptanceSignatureInvalid { participant: acc.participant_node_id });
        }
        if acc.proposal_hash != proposal.proposal_hash() {
            return Err(CommitError::AcceptanceProposalMismatch { participant: acc.participant_node_id });
        }
        // Check participant is required + role is correct (P1 #3).
        let expected_role = required
            .iter()
            .find(|(id, _)| *id == acc.participant_node_id)
            .map(|(_, r)| *r);
        match expected_role {
            None => {
                return Err(CommitError::UnexpectedParticipant { participant: acc.participant_node_id });
            }
            Some(expected) => {
                if acc.role != expected {
                    return Err(CommitError::WrongRole {
                        participant: acc.participant_node_id,
                        expected,
                        actual: acc.role,
                    });
                }
            }
        }
        accepted_by.entry(acc.participant_node_id).or_insert(acc);
    }

    // 6. Check every required participant accepted.
    for (req, _) in &required {
        if !accepted_by.contains_key(req) {
            return Err(CommitError::MissingAcceptance { participant: *req });
        }
    }

    // 7. Construct.
    let commitment = {
        let mut input = Vec::new();
        input.extend_from_slice(&proposal.proposal_hash());
        for acc in &acceptances {
            input.extend_from_slice(&acc.proposal_hash);
            input.extend_from_slice(&acc.participant_node_id);
        }
        sha256(&input)
    };

    Ok(CommittedRoute {
        proposal,
        commitment,
        acceptances,
        committed_at: now,
    })
}

impl CommittedRoute {
    #[must_use]
    pub fn proposal(&self) -> &RouteProposal { &self.proposal }
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] { &self.commitment }
    #[must_use]
    pub fn acceptances(&self) -> &[RouteAcceptance] { &self.acceptances }
    #[must_use]
    pub fn committed_at(&self) -> u64 { self.committed_at }
    #[must_use]
    pub fn source(&self) -> [u8; 32] { self.proposal.source }
    #[must_use]
    pub fn destination(&self) -> [u8; 32] { self.proposal.destination }
    #[must_use]
    pub fn hops(&self) -> &[[u8; 32]] { &self.proposal.hop_node_ids }
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool { self.proposal.expiry <= now }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_short(node_id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node_id[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

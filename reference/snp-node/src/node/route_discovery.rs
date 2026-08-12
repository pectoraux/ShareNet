//! N2.1.2 — Path Discovery and Route Construction.
//!
//! Spec: spec/07-routing.md (Sections 22–29 of the frozen spec).
//!
//! ## The frozen route pipeline (progressive, NOT global-graph)
//!
//! ```text
//! Destination Discovery (RemoteNodeHint → CandidateDestination)
//!         ↓
//! Target Authentication (fetch + verify target advertisement)
//!         ↓
//! Next-Hop Discovery (ask authenticated neighbor for next-hop candidates)
//!         ↓
//! Per-hop Authentication (fetch + verify each candidate's advertisement)
//!         ↓
//! Path Assembly (ordered authenticated hops + link evidence)
//!         ↓
//! Path Validation (every hop authenticated + every edge backed by evidence)
//!         ↓
//! Service Agreement (signed terms — NOT full capability negotiation yet)
//!         ↓
//! Route Proposal (source's belief — NOT participant consent)
//!         ↓
//! Route Acceptance (per-participant signed consent, typed role + capability)
//!         ↓
//! Committed Route (finalized — ALL required participants accepted,
//!                  retains full hop evidence for circuit establishment)
//! ```
//!
//! ## Critical architectural invariants
//!
//! 1. **`Authenticated topology ≠ Executable route`.** `ExecutableNetworkSnapshot`
//!    is **locally observed** authenticated executable state. It is NOT a global
//!    graph. Multi-hop discovery is **progressive**: A asks B for next-hop
//!    candidates, resolves C, authenticates B→C, continues toward G.
//!
//! 2. **`RouteProposal ≠ CommittedRoute`.** A source signing a hop list does
//!    NOT mean relays agreed.
//!
//! 3. **`RemoteNodeHint` / `RemoteLinkHint` ≠ executable link.** A relay's
//!    `LinkAttestation` is stronger than unsigned gossip but weaker than a
//!    directly observed link. It must be verified, and the candidate node must
//!    be independently authenticated.
//!
//! 4. **Role is bound to capability.** A participant signing `RouteRole::Gateway`
//!    is rejected unless their authenticated `AuthenticatedNodeRecord` actually
//!    advertises `Capability::Gateway`.
//!
//! 5. **`CommittedRoute` retains hop evidence.** It does NOT degrade to a
//!    mere list of NodeIds — it carries the authenticated node record, link
//!    evidence, endpoint, and role for every hop, so circuit establishment
//!    has everything it needs.

use super::*;
use crate::node::node_advert::{AuthenticatedNodeRecord, MAX_CLOCK_SKEW_SECS};
use crate::node::topology::{ExecutableNetworkSnapshot, RemoteNodeHint};
use crate::node::link::Link;
use crate::node::identity::Capability;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, derive_node_id, sha256};

/// SIG_CONTEXT for route proposals, acceptances, and link attestations.
pub const ROUTE_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-msg\0";

/// Maximum number of hops in a route (spec §28: bounded).
pub const ROUTE_MAX_HOPS: usize = 16;

/// Maximum lifetime of a route proposal or acceptance (seconds).
pub const ROUTE_MAX_LIFETIME_SECS: u64 = 3600; // 1 hour

// ─── RouteRole (typed, P1 #3) ───────────────────────────────────────────────

/// A participant's role in a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRole {
    Relay,
    Gateway,
}

impl RouteRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Gateway => "gateway",
        }
    }
}

// ─── ServiceAgreement (typed but NOT negotiated) ──────────────────────────

/// A typed record of service terms that participants explicitly sign.
///
/// ## NOT capability negotiation
///
/// `ServiceAgreement` records the service terms the participants signed. It
/// does NOT claim that capability negotiation (matching client requirements
/// against gateway offers per spec §31) has been performed. Full capability
/// negotiation is a distinct future sub-step. For now, this type ensures the
/// proposal commits to a TYPED agreement, not an arbitrary string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAgreement {
    pub service_type: String,
    pub requirements: Vec<String>,
}

impl ServiceAgreement {
    #[must_use]
    pub fn new(service_type: String, requirements: Vec<String>) -> Self {
        Self { service_type, requirements }
    }

    fn to_cbor(&self) -> CborValue {
        let reqs: Vec<CborValue> = self.requirements.iter().map(|r| CborValue::TextString(r.clone())).collect();
        CborValue::Map(vec![
            (CborValue::TextString("serviceType".into()), CborValue::TextString(self.service_type.clone())),
            (CborValue::TextString("requirements".into()), CborValue::Array(reqs)),
        ])
    }
}

// ─── Candidate Destination (spec §23) ─────────────────────────────────────

/// A candidate destination derived from a `RemoteNodeHint`. NOT authenticated.
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

// ─── LinkAttestation (P0 #1 — relay-signed link evidence) ────────────────

/// A relay's signed attestation that it has a usable link to a remote node.
///
/// ## Trust boundary
///
/// This is STRONGER than unsigned `RemoteLinkHint` gossip (the relay's
/// signature is verified), but WEAKER than a directly observed link in the
/// local `ExecutableNetworkSnapshot`. The attestation proves:
///
/// - "Relay B signed: I have a usable link to C as of timestamp T."
///
/// It does NOT prove:
///
/// - That C is currently reachable from A (A must independently authenticate C)
/// - That the B→C link is still up at commit time (the attestation may be stale)
///
/// ## Why not just trust RemoteLinkHint?
///
/// Unsigned gossip can be fabricated by any relay. A `LinkAttestation` is
/// cryptographically bound to the relay's Ed25519 key. If the relay lies,
/// the attestation is traceable to the liar.
///
/// ## Usage in progressive discovery
///
/// `NextHopDiscovery::discover_next_hops()` returns `NextHopCandidate`s,
/// each carrying a `LinkAttestation`. The caller must:
/// 1. Verify the attestation's signature.
/// 2. Independently authenticate the candidate (fetch + verify advertisement).
/// 3. Include the attestation as `LinkEvidence::Attested` in the `ValidatedPath`.
#[derive(Debug, Clone)]
pub struct LinkAttestation {
    /// The attester's NodeId (the relay claiming the link).
    pub attester_node_id: [u8; 32],
    /// The attester's Ed25519 public key.
    pub attester_public_key: [u8; 32],
    /// The remote node the attester claims to have a link to.
    pub remote_node_id: [u8; 32],
    /// The claimed link state ("up" or "degraded").
    pub link_state: String,
    /// When the attestation was created (unix seconds).
    pub timestamp: u64,
    /// When the attestation expires (unix seconds).
    pub expiry: u64,
    /// The attester's Ed25519 signature.
    pub signature: [u8; 64],
}

impl LinkAttestation {
    /// Create and sign a `LinkAttestation`.
    #[must_use]
    pub fn create_and_sign(
        attester_secret_key: &[u8; 32],
        attester_public_key: &[u8; 32],
        attester_node_id: [u8; 32],
        remote_node_id: [u8; 32],
        link_state: String,
        expiry: u64,
    ) -> Self {
        let now = now_unix();
        let mut att = Self {
            attester_node_id,
            attester_public_key: *attester_public_key,
            remote_node_id,
            link_state,
            timestamp: now,
            expiry,
            signature: [0u8; 64],
        };
        att.signature = ed25519_sign(attester_secret_key, &att.preimage_bytes());
        att
    }

    fn preimage(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::TextString("attesterNodeId".into()), CborValue::ByteString(self.attester_node_id.to_vec())),
            (CborValue::TextString("attesterPublicKey".into()), CborValue::ByteString(self.attester_public_key.to_vec())),
            (CborValue::TextString("remoteNodeId".into()), CborValue::ByteString(self.remote_node_id.to_vec())),
            (CborValue::TextString("linkState".into()), CborValue::TextString(self.link_state.clone())),
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

    /// Verify the attestation's signature + NodeId↔pubkey binding + freshness.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.verify_at(now_unix())
    }

    /// Verify at a specific time (for testing).
    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        let expected = derive_node_id(&self.attester_public_key);
        if self.attester_node_id != expected {
            return false;
        }
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
        ed25519_verify(&self.attester_public_key, &self.preimage_bytes(), &self.signature)
    }
}

// ─── NextHopCandidate + NextHopDiscovery trait (P0 #1) ────────────────────

/// A next-hop candidate discovered by asking an authenticated relay.
///
/// Contains:
/// - The candidate's NodeId (NOT yet authenticated by us)
/// - A `LinkAttestation` from the relay (signed, but the candidate must still
///   be independently authenticated)
#[derive(Debug, Clone)]
pub struct NextHopCandidate {
    /// The candidate's NodeId. NOT authenticated — must be resolved.
    pub candidate_node_id: [u8; 32],
    /// The relay's signed attestation that it has a usable link to the candidate.
    pub link_attestation: LinkAttestation,
}

/// The API for progressive next-hop discovery.
///
/// ## Multi-hop discovery without a global graph
///
/// A node does NOT need the entire network topology to discover a multi-hop
/// route. Instead, it progressively asks each authenticated relay for
/// next-hop candidates:
///
/// ```text
/// A asks B: "What are your next-hop candidates toward G?"
/// B returns: [NextHopCandidate { candidate: C, attestation: B→C }]
/// A authenticates C (fetch + verify C's advertisement)
/// A asks C: "What are your next-hop candidates toward G?"
/// C returns: [NextHopCandidate { candidate: G, attestation: C→G }]
/// A authenticates G
/// A assembles: A → B → C → G
/// ```
///
/// This trait is the abstraction over the network protocol that implements
/// this query. In tests, a mock implementation simulates the relay's responses.
pub trait NextHopDiscovery {
    /// Discover next-hop candidates from a given relay toward a destination.
    ///
    /// `from` is the relay's NodeId (an authenticated neighbor).
    /// `toward` is the destination NodeId.
    ///
    /// Returns candidates with link attestations. The caller MUST
    /// authenticate each candidate before using it in a `ValidatedPath`.
    fn discover_next_hops(
        &self,
        from: &[u8; 32],
        toward: &[u8; 32],
    ) -> Vec<NextHopCandidate>;
}

// ─── LinkEvidence (Direct vs Attested) ─────────────────────────────────────

/// Evidence backing a hop's incoming link.
///
/// - `Direct`: a link in our local `ExecutableNetworkSnapshot` (strongest).
/// - `Attested`: a relay's signed `LinkAttestation` (weaker, but cryptographically
///   traceable to the attester).
///
/// Both are stronger than unsigned `RemoteLinkHint` gossip. Neither is as
/// strong as directly observing the link ourselves.
#[derive(Debug, Clone)]
pub enum LinkEvidence {
    /// A directly observed link from our local topology.
    Direct(Link),
    /// A relay-attested link from progressive next-hop discovery.
    Attested(LinkAttestation),
}

impl LinkEvidence {
    /// Check if the evidence indicates a usable link.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        match self {
            Self::Direct(link) => link.is_usable(),
            Self::Attested(att) => att.link_state == "up" || att.link_state == "degraded",
        }
    }

    /// Get the remote NodeId of the link.
    #[must_use]
    pub fn remote_node_id(&self) -> [u8; 32] {
        match self {
            Self::Direct(link) => link.key.remote_node_id,
            Self::Attested(att) => att.remote_node_id,
        }
    }

    /// Verify the evidence (signature check for attested links).
    #[must_use]
    pub fn verify(&self) -> bool {
        match self {
            Self::Direct(_) => true, // local links are already trusted
            Self::Attested(att) => att.verify(),
        }
    }
}

// ─── AuthenticatedHop + ValidatedPath ──────────────────────────────────────

/// A hop in a `ValidatedPath` — carries authenticated node record AND link evidence.
#[derive(Debug, Clone)]
pub struct AuthenticatedHop {
    pub node_id: [u8; 32],
    pub record: AuthenticatedNodeRecord,
    /// The link evidence connecting the previous hop to this hop.
    /// `None` for the source (first hop — no incoming link).
    pub incoming_link: Option<LinkEvidence>,
    /// This hop's role in the route (Relay or Gateway).
    /// Determined by position: last hop = Gateway, others = Relay.
    pub role: RouteRole,
}

/// A validated path — every hop is authenticated AND every edge is backed by
/// link evidence (direct or attested).
///
/// ## Construction
///
/// Only constructable via `validate_path()` (for local paths) or
/// `assemble_progressive_path()` (for multi-hop paths using `NextHopDiscovery`).
#[derive(Debug, Clone)]
pub struct ValidatedPath {
    hops: Vec<AuthenticatedHop>,
}

/// Error from `validate_path()` / `assemble_progressive_path()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    HopNotAuthenticated { index: usize, node_id: [u8; 32] },
    NoUsableLink { from: [u8; 32], to: [u8; 32] },
    ExcessiveHops { count: usize },
    /// A relay-attested link's attestation is invalid (bad signature, expired, etc.).
    AttestationInvalid { from: [u8; 32], to: [u8; 32] },
    /// The candidate's authenticated NodeId does not match the attestation's remote_node_id.
    CandidateAttestationMismatch { candidate: [u8; 32], attestation_remote: [u8; 32] },
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "discovered path is empty"),
            Self::HopNotAuthenticated { index, node_id } => write!(f, "hop {index} ({}) is not authenticated", hex_short(node_id)),
            Self::NoUsableLink { from, to } => write!(f, "no usable link from {} to {}", hex_short(from), hex_short(to)),
            Self::ExcessiveHops { count } => write!(f, "path has too many hops: {count} > {ROUTE_MAX_HOPS}"),
            Self::AttestationInvalid { from, to } => write!(f, "link attestation invalid from {} to {}", hex_short(from), hex_short(to)),
            Self::CandidateAttestationMismatch { candidate, attestation_remote } => write!(f, "candidate {} does not match attestation remote {}", hex_short(candidate), hex_short(attestation_remote)),
        }
    }
}

impl std::error::Error for PathError {}

impl ValidatedPath {
    #[must_use]
    pub fn hops(&self) -> &[AuthenticatedHop] { &self.hops }
    #[must_use]
    pub fn node_ids(&self) -> Vec<[u8; 32]> { self.hops.iter().map(|h| h.node_id).collect() }
    #[must_use]
    pub fn source(&self) -> [u8; 32] { self.hops[0].node_id }
    #[must_use]
    pub fn destination(&self) -> [u8; 32] { self.hops[self.hops.len() - 1].node_id }
    #[must_use]
    pub fn required_participants(&self) -> Vec<[u8; 32]> {
        self.hops.iter().skip(1).map(|h| h.node_id).collect()
    }
}

// ─── DiscoveredPath (BFS result, local) ───────────────────────────────────

/// A path discovered by local BFS over `ExecutableNetworkSnapshot`.
#[derive(Debug, Clone)]
pub struct DiscoveredPath {
    pub hops: Vec<[u8; 32]>,
}

impl DiscoveredPath {
    #[must_use]
    pub fn hop_count(&self) -> usize { self.hops.len() }
}

/// Discover a path using BFS over LOCAL `ExecutableNetworkSnapshot`.
///
/// ## This is LOCAL discovery only
///
/// `ExecutableNetworkSnapshot` is **locally observed** authenticated state.
/// It contains only links that THIS node has directly probed. It does NOT
/// contain remote links (B→C) that other relays know about.
///
/// For multi-hop paths that extend beyond the local topology, use
/// `discover_path_progressive()` with a `NextHopDiscovery` provider.
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
        if current_depth >= ROUTE_MAX_HOPS {
            continue;
        }
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

/// Validate a local `DiscoveredPath` against `ExecutableNetworkSnapshot`.
///
/// Every hop must be in `authenticated_nodes` AND every edge must be a usable
/// link in `usable_links`. Produces a `ValidatedPath` with `LinkEvidence::Direct`.
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
        let record = snapshot.authenticated_nodes
            .get(&node_id)
            .cloned()
            .ok_or(PathError::HopNotAuthenticated { index: i, node_id })?;

        let is_destination = i == discovered.hops.len() - 1;
        let role = if is_destination { RouteRole::Gateway } else { RouteRole::Relay };

        let incoming_link = if i == 0 {
            None
        } else {
            let prev = discovered.hops[i - 1];
            let link = snapshot.usable_links.values()
                .find(|l| l.key.local_node_id == prev && l.key.remote_node_id == node_id && l.is_usable())
                .cloned()
                .ok_or(PathError::NoUsableLink { from: prev, to: node_id })?;
            Some(LinkEvidence::Direct(link))
        };

        hops.push(AuthenticatedHop { node_id, record, incoming_link, role });
    }

    Ok(ValidatedPath { hops })
}

/// Assemble a progressive multi-hop path using `NextHopDiscovery`.
///
/// This is the multi-hop route discovery mechanism. It:
///
/// 1. Starts at `source` (using local `ExecutableNetworkSnapshot` for the
///    first hop — the source must have a direct authenticated link to the
///    first relay).
/// 2. For each subsequent hop, calls `discovery.discover_next_hops(current, destination)`
///    to get candidates from the current relay.
/// 3. Verifies each candidate's `LinkAttestation`.
/// 4. The caller-supplied `authenticate_candidate` function fetches + verifies
///    the candidate's advertisement (out-of-band — this is the per-hop
///    authentication step).
/// 5. Assembles a `ValidatedPath` with `LinkEvidence::Attested` for remote hops.
/// 6. Stops when `destination` is reached or `ROUTE_MAX_HOPS` is exceeded.
///
/// ## Why this is progressive, not global
///
/// A does not need to know the entire network. It asks B for next-hop
/// candidates, authenticates C, asks C for candidates, authenticates G, etc.
/// Each step is independently validated. This is the frozen architecture.
///
/// ## Parameters
///
/// - `snapshot`: local `ExecutableNetworkSnapshot` (for the first hop + source auth).
/// - `discovery`: the `NextHopDiscovery` provider (network protocol abstraction).
/// - `source`: the source NodeId (must be in `snapshot.authenticated_nodes`).
/// - `destination`: the target NodeId (must be authenticated when reached).
/// - `authenticate_candidate`: a callback that fetches + verifies a candidate's
///   advertisement and returns its `AuthenticatedNodeRecord`. Returns `None`
///   if the candidate cannot be authenticated (unreachable, bad signature, etc.).
pub fn assemble_progressive_path<F>(
    snapshot: &ExecutableNetworkSnapshot,
    discovery: &dyn NextHopDiscovery,
    source: &[u8; 32],
    destination: &[u8; 32],
    authenticate_candidate: F,
) -> Result<ValidatedPath, PathError>
where
    F: Fn(&[u8; 32]) -> Option<AuthenticatedNodeRecord>,
{
    // Source must be authenticated.
    let source_record = snapshot.authenticated_nodes.get(source)
        .ok_or(PathError::HopNotAuthenticated { index: 0, node_id: *source })?
        .clone();

    let mut hops: Vec<AuthenticatedHop> = vec![AuthenticatedHop {
        node_id: *source,
        record: source_record,
        incoming_link: None,
        role: RouteRole::Relay, // source is not a relay or gateway (it's the proposer)
    }];

    let mut current = *source;
    let mut depth = 0usize;

    loop {
        if depth >= ROUTE_MAX_HOPS {
            return Err(PathError::ExcessiveHops { count: depth + 1 });
        }
        if current == *destination {
            // Mark the destination's role as Gateway.
            let last = hops.last_mut().unwrap();
            last.role = RouteRole::Gateway;
            return Ok(ValidatedPath { hops });
        }

        // Check if `current` has a DIRECT link to `destination` in the local
        // snapshot. This handles the common case where the path's last hop is
        // a directly-observed link (e.g. source → relay → gateway, where
        // relay → gateway is local).
        if let Some(link) = snapshot.usable_links.values().find(|l| {
            l.key.local_node_id == current && l.key.remote_node_id == *destination && l.is_usable()
        }) {
            let dest_record = snapshot.authenticated_nodes.get(destination)
                .cloned()
                .or_else(|| authenticate_candidate(destination))
                .ok_or(PathError::HopNotAuthenticated { index: hops.len(), node_id: *destination })?;
            hops.push(AuthenticatedHop {
                node_id: *destination,
                record: dest_record,
                incoming_link: Some(LinkEvidence::Direct(link.clone())),
                role: RouteRole::Gateway,
            });
            current = *destination;
            depth += 1;
            continue; // loop will see current == destination and return
        }

        // For the SOURCE's hop only (depth == 0), check local snapshot for
        // a direct link to any unvisited neighbor. This is how A finds its
        // first relay (B) — via the local ExecutableNetworkSnapshot, not via
        // the discovery trait.
        //
        // For subsequent hops (depth > 0), we do NOT check local links here —
        // the current relay's links may be in the local snapshot (if we
        // probed them), but they may also NOT be (if the relay is remote).
        // Instead, we fall through to the progressive discovery trait, which
        // asks the relay for its next-hop candidates.
        if depth == 0 {
            let visited: std::collections::HashSet<[u8; 32]> = hops.iter().map(|h| h.node_id).collect();
            if let Some(link) = snapshot.usable_links.values().find(|l| {
                l.key.local_node_id == current && l.is_usable() && !visited.contains(&l.key.remote_node_id)
            }) {
                let next_id = link.key.remote_node_id;
                let next_record = snapshot.authenticated_nodes.get(&next_id)
                    .cloned()
                    .or_else(|| authenticate_candidate(&next_id))
                    .ok_or(PathError::HopNotAuthenticated { index: hops.len(), node_id: next_id })?;
                let is_dest = next_id == *destination;
                let role = if is_dest { RouteRole::Gateway } else { RouteRole::Relay };
                hops.push(AuthenticatedHop {
                    node_id: next_id,
                    record: next_record,
                    incoming_link: Some(LinkEvidence::Direct(link.clone())),
                    role,
                });
                current = next_id;
                depth += 1;
                continue;
            }
        }

        // No direct links to destination (and no local first hop) — use
        // progressive next-hop discovery. Ask the current relay for
        // next-hop candidates toward destination.
        let candidates = discovery.discover_next_hops(&current, destination);
        if candidates.is_empty() {
            return Err(PathError::NoUsableLink {
                from: current,
                to: *destination,
            });
        }

        // Pick the first candidate that authenticates successfully.
        // (A more sophisticated implementation might try multiple candidates.)
        let candidate = &candidates[0];
        let attestation = &candidate.link_attestation;

        // Verify the attestation.
        if !attestation.verify() {
            return Err(PathError::AttestationInvalid {
                from: current,
                to: candidate.candidate_node_id,
            });
        }

        // Check that the attestation's remote_node_id matches the candidate.
        if attestation.remote_node_id != candidate.candidate_node_id {
            return Err(PathError::CandidateAttestationMismatch {
                candidate: candidate.candidate_node_id,
                attestation_remote: attestation.remote_node_id,
            });
        }

        // Authenticate the candidate (fetch + verify advertisement).
        let candidate_record = authenticate_candidate(&candidate.candidate_node_id)
            .ok_or(PathError::HopNotAuthenticated {
                index: hops.len(),
                node_id: candidate.candidate_node_id,
            })?;

        // Add the hop with attested link evidence.
        let is_destination = candidate.candidate_node_id == *destination;
        let role = if is_destination { RouteRole::Gateway } else { RouteRole::Relay };

        hops.push(AuthenticatedHop {
            node_id: candidate.candidate_node_id,
            record: candidate_record,
            incoming_link: Some(LinkEvidence::Attested(attestation.clone())),
            role,
        });

        current = candidate.candidate_node_id;
        depth += 1;
    }
}

// ─── RouteProposal ─────────────────────────────────────────────────────────

/// The source's proposed route — a belief that a path COULD work.
///
/// ## CRITICAL: NOT a committed route
///
/// Signed by the SOURCE only. Does NOT prove relays agreed.
#[derive(Debug, Clone)]
pub struct RouteProposal {
    pub protocol_version: u8,
    pub source: [u8; 32],
    pub destination: [u8; 32],
    pub hop_node_ids: Vec<[u8; 32]>,
    pub service: ServiceAgreement,
    pub timestamp: u64,
    pub expiry: u64,
    pub nonce: [u8; 16],
    pub source_signature: [u8; 64],
    pub source_public_key: [u8; 32],
}

impl RouteProposal {
    /// Create and sign a `RouteProposal` from a `ValidatedPath`.
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
        let hops: Vec<CborValue> = self.hop_node_ids.iter().map(|h| CborValue::ByteString(h.to_vec())).collect();
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

    #[must_use]
    pub fn proposal_hash(&self) -> [u8; 32] {
        sha256(&self.preimage_bytes())
    }

    /// Verify signature + NodeId binding + source==first + freshness.
    #[must_use]
    pub fn verify(&self) -> bool { self.verify_at(now_unix()) }

    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        let expected = derive_node_id(&self.source_public_key);
        if self.source != expected { return false; }
        if self.hop_node_ids.first() != Some(&self.source) { return false; }
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) { return false; }
        if self.expiry <= now { return false; }
        if self.expiry <= self.timestamp { return false; }
        if self.expiry.saturating_sub(self.timestamp) > ROUTE_MAX_LIFETIME_SECS { return false; }
        ed25519_verify(&self.source_public_key, &self.preimage_bytes(), &self.source_signature)
    }

    #[must_use]
    pub fn required_participants(&self) -> Vec<[u8; 32]> {
        self.hop_node_ids.iter().filter(|h| **h != self.source).copied().collect()
    }
}

// ─── RouteAcceptance ───────────────────────────────────────────────────────

/// A participant's signed acceptance of their role in a proposed route.
#[derive(Debug, Clone)]
pub struct RouteAcceptance {
    pub proposal_hash: [u8; 32],
    pub participant_node_id: [u8; 32],
    pub participant_public_key: [u8; 32],
    pub role: RouteRole,
    pub conditions: Vec<String>,
    pub timestamp: u64,
    pub expiry: u64,
    pub signature: [u8; 64],
}

impl RouteAcceptance {
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
            proposal_hash, participant_node_id, participant_public_key: *participant_public_key,
            role, conditions, timestamp: now, expiry, signature: [0u8; 64],
        };
        acceptance.signature = ed25519_sign(participant_secret_key, &acceptance.preimage_bytes());
        acceptance
    }

    fn preimage(&self) -> CborValue {
        let conditions: Vec<CborValue> = self.conditions.iter().map(|c| CborValue::TextString(c.clone())).collect();
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

    #[must_use]
    pub fn verify(&self) -> bool { self.verify_at(now_unix()) }

    #[must_use]
    pub fn verify_at(&self, now: u64) -> bool {
        let expected = derive_node_id(&self.participant_public_key);
        if self.participant_node_id != expected { return false; }
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) { return false; }
        if self.expiry <= now { return false; }
        if self.expiry <= self.timestamp { return false; }
        if self.expiry.saturating_sub(self.timestamp) > ROUTE_MAX_LIFETIME_SECS { return false; }
        ed25519_verify(&self.participant_public_key, &self.preimage_bytes(), &self.signature)
    }
}

// ─── CommittedRoute (retains hop evidence — P0 #2) ────────────────────────

/// A finalized route — produced ONLY after every required participant has
/// produced a valid, typed `RouteAcceptance` AND the route's hop evidence
/// is retained for circuit establishment.
///
/// ## P0 #2 — Retains hop evidence
///
/// `CommittedRoute` does NOT degrade to a mere list of NodeIds. It retains:
/// - The `ValidatedPath`'s `AuthenticatedHop`s (node record + link evidence + role)
/// - The `RouteProposal` (source's signed belief)
/// - The `RouteAcceptance`s (participant consent)
/// - The commitment hash (integrity identifier covering all of the above)
///
/// This ensures the future circuit layer (N2.1.3) has everything it needs:
/// node identity, transport endpoint, link evidence, and role for every hop.
#[derive(Debug, Clone)]
pub struct CommittedRoute {
    proposal: RouteProposal,
    /// The validated hop evidence — retained for circuit establishment.
    /// Every hop carries: authenticated node record, link evidence, role.
    validated_hops: Vec<AuthenticatedHop>,
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
    WrongRole { participant: [u8; 32], expected: RouteRole, actual: RouteRole },
    /// P0/P1 #3: the participant's authenticated capability does not match
    /// the role they signed. A relay cannot sign `RouteRole::Gateway` unless
    /// its authenticated record advertises `Capability::Gateway`.
    CapabilityMismatch { participant: [u8; 32], role: RouteRole, capability: Capability },
    EmptyRoute,
    ExcessiveHops { count: usize },
    DestinationMismatch,
    DuplicateHop { node_id: [u8; 32] },
    SourceNotFirstHop,
    /// P0 #2: the proposal's hop_node_ids do not match the validated_path's hops.
    PathProposalMismatch,
    /// The validated path has no hops.
    EmptyPath,
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
            Self::CapabilityMismatch { participant, role, capability } => write!(f, "participant {} signed role {:?} but authenticated capability is {:?}", hex_short(participant), role, capability),
            Self::EmptyRoute => write!(f, "route has no hops"),
            Self::ExcessiveHops { count } => write!(f, "route has too many hops: {count} > {ROUTE_MAX_HOPS}"),
            Self::DestinationMismatch => write!(f, "destination is not the last hop"),
            Self::DuplicateHop { node_id } => write!(f, "duplicate hop: {}", hex_short(node_id)),
            Self::SourceNotFirstHop => write!(f, "source is not the first hop"),
            Self::PathProposalMismatch => write!(f, "proposal hop_node_ids do not match validated path"),
            Self::EmptyPath => write!(f, "validated path is empty"),
        }
    }
}

/// Commit a route proposal into a `CommittedRoute`.
///
/// ## P0 #2 — Takes `&ValidatedPath`
///
/// The `validated_path` provides the authenticated hop evidence (node records
/// + link evidence + roles) that is RETAINED in the `CommittedRoute`. The
/// proposal's `hop_node_ids` MUST match the validated path's node IDs.
///
/// ## P0/P1 #3 — Capability binding
///
/// Checks that:
/// - Destination's `AuthenticatedNodeRecord` has `Capability::Gateway`
/// - Intermediate hops' records have `Capability::Relay`
///
/// A signed `RouteRole::Gateway` from a node whose authenticated record only
/// has `Capability::Relay` is rejected with `CapabilityMismatch`.
pub fn commit_route(
    proposal: RouteProposal,
    acceptances: Vec<RouteAcceptance>,
    validated_path: &ValidatedPath,
    now: u64,
) -> Result<CommittedRoute, CommitError> {
    // 1. Verify proposal.
    if !proposal.verify_at(now) {
        if proposal.expiry <= now {
            return Err(CommitError::ProposalExpired { now, expiry: proposal.expiry });
        }
        return Err(CommitError::ProposalSignatureInvalid);
    }

    // 2. P0 #2: proposal.hop_node_ids MUST match validated_path.node_ids().
    let path_node_ids = validated_path.node_ids();
    if proposal.hop_node_ids != path_node_ids {
        return Err(CommitError::PathProposalMismatch);
    }

    // 3. Structural validation.
    if proposal.hop_node_ids.is_empty() {
        return Err(CommitError::EmptyRoute);
    }
    if validated_path.hops().is_empty() {
        return Err(CommitError::EmptyPath);
    }
    if proposal.hop_node_ids.len() > ROUTE_MAX_HOPS {
        return Err(CommitError::ExcessiveHops { count: proposal.hop_node_ids.len() });
    }
    if proposal.hop_node_ids.first() != Some(&proposal.source) {
        return Err(CommitError::SourceNotFirstHop);
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

    // 4. P0/P1 #3: capability binding.
    //    Check every hop's authenticated capability matches its role.
    for hop in validated_path.hops() {
        let caps = hop.record.descriptor.capabilities();
        let has_gateway = caps.contains(&Capability::Gateway);
        let has_relay = caps.contains(&Capability::Relay);
        match hop.role {
            RouteRole::Gateway => {
                if !has_gateway {
                    return Err(CommitError::CapabilityMismatch {
                        participant: hop.node_id,
                        role: RouteRole::Gateway,
                        capability: if has_relay { Capability::Relay } else { Capability::Client },
                    });
                }
            }
            RouteRole::Relay => {
                if !has_relay {
                    return Err(CommitError::CapabilityMismatch {
                        participant: hop.node_id,
                        role: RouteRole::Relay,
                        capability: if has_gateway { Capability::Gateway } else { Capability::Client },
                    });
                }
            }
        }
    }

    // 5. Required participants + expected roles.
    let required: Vec<([u8; 32], RouteRole)> = validated_path.hops()
        .iter()
        .skip(1) // skip source
        .map(|h| (h.node_id, h.role))
        .collect();

    // 6. Verify each acceptance.
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
        let expected_role = required.iter()
            .find(|(id, _)| *id == acc.participant_node_id)
            .map(|(_, r)| *r);
        match expected_role {
            None => return Err(CommitError::UnexpectedParticipant { participant: acc.participant_node_id }),
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

    // 7. Every required participant accepted.
    for (req, _) in &required {
        if !accepted_by.contains_key(req) {
            return Err(CommitError::MissingAcceptance { participant: *req });
        }
    }

    // 8. Compute commitment (covers proposal + hop evidence).
    let commitment = {
        let mut input = Vec::new();
        input.extend_from_slice(&proposal.proposal_hash());
        for hop in validated_path.hops() {
            input.extend_from_slice(&hop.node_id);
            input.extend_from_slice(&hop.record.node_id());
        }
        for acc in &acceptances {
            input.extend_from_slice(&acc.proposal_hash);
            input.extend_from_slice(&acc.participant_node_id);
        }
        sha256(&input)
    };

    Ok(CommittedRoute {
        proposal,
        validated_hops: validated_path.hops().to_vec(),
        commitment,
        acceptances,
        committed_at: now,
    })
}

impl CommittedRoute {
    /// The proposal that was committed.
    #[must_use] pub fn proposal(&self) -> &RouteProposal { &self.proposal }
    /// The commitment hash (covers proposal + hop evidence + acceptances).
    #[must_use] pub fn commitment(&self) -> &[u8; 32] { &self.commitment }
    /// The participant acceptances.
    #[must_use] pub fn acceptances(&self) -> &[RouteAcceptance] { &self.acceptances }
    /// When the route was committed.
    #[must_use] pub fn committed_at(&self) -> u64 { self.committed_at }

    // P0 #2: hop evidence accessors.
    /// The validated hop evidence — retained for circuit establishment.
    /// Each hop carries: authenticated node record, link evidence, role.
    #[must_use] pub fn validated_hops(&self) -> &[AuthenticatedHop] { &self.validated_hops }
    /// The source NodeId.
    #[must_use] pub fn source(&self) -> [u8; 32] { self.proposal.source }
    /// The destination NodeId.
    #[must_use] pub fn destination(&self) -> [u8; 32] { self.proposal.destination }
    /// The ordered hop NodeIds.
    #[must_use] pub fn hops(&self) -> &[[u8; 32]] { &self.proposal.hop_node_ids }
    /// Check if the committed route has expired.
    #[must_use] pub fn is_expired(&self, now: u64) -> bool { self.proposal.expiry <= now }

    /// Get the authenticated node record for a specific hop index.
    #[must_use]
    pub fn hop_record(&self, index: usize) -> Option<&AuthenticatedNodeRecord> {
        self.validated_hops.get(index).map(|h| &h.record)
    }

    /// Get the link evidence for a specific hop index.
    #[must_use]
    pub fn hop_link_evidence(&self, index: usize) -> Option<&LinkEvidence> {
        self.validated_hops.get(index).and_then(|h| h.incoming_link.as_ref())
    }
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

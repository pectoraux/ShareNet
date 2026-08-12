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
//! Next-Hop Discovery (from ExecutableNetworkSnapshot ONLY)
//!         ↓
//! Path Validation (every hop authenticated + usable link)
//!         ↓
//! Capability/Service Negotiation
//!         ↓
//! RouteProposal  (source's belief — NOT participant consent)
//!         ↓
//! RouteAcceptance (per-participant signed acceptance)
//!         ↓
//! CommittedRoute (finalized — ALL required participants accepted)
//! ```
//!
//! ## The two critical architectural invariants (frozen spec §27, §54 #10, #11)
//!
//! 1. **`Authenticated topology ≠ Executable route`.**
//!    An `ExecutableNetworkSnapshot` provides authenticated local network
//!    facts. It does NOT authorize the route engine to invent a path merely by
//!    seeing a sequence of nodes. Every hop must be backed by an authenticated,
//!    currently-usable link.
//!
//! 2. **`RouteProposal ≠ CommittedRoute`.**
//!    A source signing "A → B → C → G" does NOT mean B, C, and G have agreed
//!    to participate. A `RouteProposal` is the source's belief. A
//!    `CommittedRoute` can only be constructed after every required
//!    participant has produced a signed `RouteAcceptance`.
//!
//! ## What is NOT implemented (N2.1.3+)
//!
//! - Circuit establishment (session keys, forwarding state) — spec §38.
//! - Route failure / recovery — spec §39, N2.1.3.
//! - Route migration — spec §39.
//!
//! These are explicitly deferred. N2.1.2 ends at `CommittedRoute`.

use super::*;
use crate::node::topology::{ExecutableNetworkSnapshot, RemoteNodeHint};
use crate::node::node_advert::AuthenticatedNodeRecord;
use snp_cbor::CborValue;
use snp_crypto::{ed25519_sign, ed25519_verify, derive_node_id, sha256};

/// SIG_CONTEXT for route proposals and acceptances.
pub const ROUTE_MSG_CONTEXT: &[u8] = b"SNP/0.1 route-msg\0";

/// Maximum number of hops in a route (spec §28: bounded).
pub const ROUTE_MAX_HOPS: usize = 16;

// ─── Candidate Destination (spec §23) ─────────────────────────────────────

/// A candidate destination derived from a `RemoteNodeHint`.
///
/// This is the entry point to the route pipeline. A hint suggests a target
/// MIGHT exist and MIGHT have a capability (e.g. INTERNET_GATEWAY). The
/// candidate is worth investigating — but it is NOT authenticated yet.
///
/// ## CRITICAL: NOT an authenticated destination
///
/// A `CandidateDestination` cannot be used as a route destination until
/// `resolve_candidate()` fetches the target's actual advertisement and
/// verifies it. This is the same trust-boundary pattern as
/// `PeerSummaryList → VerifiedPeerSummaryList` in N2.1.1.1.
#[derive(Debug, Clone)]
pub struct CandidateDestination {
    /// The NodeId the hint claims exists.
    pub target_node_id: [u8; 32],
    /// The capabilities the hint claims the target has.
    pub claimed_capabilities: Vec<String>,
    /// The hint that produced this candidate (for provenance).
    pub source_hint: [u8; 32], // learned_from NodeId
    /// Distance hint (discovery metadata, NOT a route).
    pub distance_hint: u8,
}

impl CandidateDestination {
    /// Derive a candidate from a `RemoteNodeHint`.
    ///
    /// The hint is NOT authenticated — the candidate is a "maybe, worth
    /// investigating" marker. The caller must resolve the candidate (fetch +
    /// verify the target's advertisement) before using it as a route
    /// destination.
    #[must_use]
    pub fn from_hint(hint: &RemoteNodeHint) -> Self {
        Self {
            target_node_id: hint.target_node_id,
            claimed_capabilities: hint.claimed_capabilities.clone(),
            source_hint: hint.learned_from,
            distance_hint: hint.distance_hint,
        }
    }

    /// Check if the candidate claims the target is a gateway.
    #[must_use]
    pub fn claims_gateway(&self) -> bool {
        self.claimed_capabilities.iter().any(|c| c == "gateway")
    }
}

// ─── RouteProposal (spec §27) ─────────────────────────────────────────────

/// The source's proposed route — a belief that a path COULD work.
///
/// ## CRITICAL: NOT a committed route
///
/// A `RouteProposal` is signed by the SOURCE only. It does NOT prove that
/// any relay or gateway has agreed to participate. The source signs:
///
/// - The ordered hop list (NodeIds + verified descriptors)
/// - The destination
/// - The negotiated service
/// - An expiry
///
/// But the RELAYS and GATEWAY have NOT signed anything yet. To turn a
/// `RouteProposal` into a `CommittedRoute`, every required participant must
/// produce a signed `RouteAcceptance`.
///
/// ## Construction
///
/// `RouteProposal` can be constructed by anyone who has the source's
/// secret key. But `CommittedRoute` can ONLY be constructed by
/// `commit_route(proposal, acceptances)` — and only if every required
/// participant's acceptance is present and valid.
#[derive(Debug, Clone)]
pub struct RouteProposal {
    /// Protocol version.
    pub protocol_version: u8,
    /// The source NodeId (who proposed this route).
    pub source: [u8; 32],
    /// The destination NodeId (the gateway, typically).
    pub destination: [u8; 32],
    /// Ordered hop NodeIds (source → relay1 → ... → destination).
    /// Each hop MUST be backed by a verified descriptor in `hop_descriptors`.
    pub hop_node_ids: Vec<[u8; 32]>,
    /// The negotiated service (e.g. "internet-transit", "content-retrieval").
    pub service: String,
    /// When the proposal was created (unix seconds).
    pub timestamp: u64,
    /// When the proposal expires (unix seconds).
    pub expiry: u64,
    /// A nonce for freshness.
    pub nonce: [u8; 16],
    /// The source's Ed25519 signature over the above fields.
    pub source_signature: [u8; 64],
    /// The source's Ed25519 public key (for signature verification).
    pub source_public_key: [u8; 32],
}

impl RouteProposal {
    /// Create and sign a `RouteProposal`.
    ///
    /// The caller provides the source's secret key, the hop list (which MUST
    /// be backed by verified descriptors — validated separately), and the
    /// negotiated service.
    #[must_use]
    pub fn create_and_sign(
        source_secret_key: &[u8; 32],
        source_public_key: &[u8; 32],
        source_node_id: [u8; 32],
        destination: [u8; 32],
        hop_node_ids: Vec<[u8; 32]>,
        service: String,
        expiry: u64,
    ) -> Self {
        let now = now_unix();
        let mut nonce = [0u8; 16];
        let _ = getrandom::getrandom(&mut nonce);
        let mut proposal = Self {
            protocol_version: 1,
            source: source_node_id,
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

    /// Canonical CBOR preimage for signing/verification.
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
            (CborValue::TextString("service".into()), CborValue::TextString(self.service.clone())),
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

    /// Verify the source's signature and NodeId↔pubkey binding.
    #[must_use]
    pub fn verify(&self) -> bool {
        // Verify NodeId ↔ Ed25519 consistency (I4).
        let expected = derive_node_id(&self.source_public_key);
        if self.source != expected {
            return false;
        }
        ed25519_verify(
            &self.source_public_key,
            &self.preimage_bytes(),
            &self.source_signature,
        )
    }

    /// Get the list of participant NodeIds that MUST accept this proposal.
    ///
    /// Per spec §27: every hop EXCEPT the source must accept. The source
    /// is the proposer; the destination (gateway) and all relays must sign
    /// a `RouteAcceptance` before the route can be committed.
    #[must_use]
    pub fn required_participants(&self) -> Vec<[u8; 32]> {
        self.hop_node_ids
            .iter()
            .filter(|h| **h != self.source)
            .copied()
            .collect()
    }
}

// ─── RouteAcceptance (spec §27) ────────────────────────────────────────────

/// A single participant's signed acceptance of their role in a proposed route.
///
/// Each relay and the gateway MUST produce a `RouteAcceptance` before the
/// route can be committed. The acceptance signs:
///
/// - The proposal hash (binding it to a specific `RouteProposal`)
/// - The participant's NodeId (proving WHO is accepting)
/// - The role they accept (relay / gateway)
/// - Conditions (e.g. bandwidth, quota, time window)
/// - An expiry
///
/// ## Trust boundary
///
/// A `RouteAcceptance` is the participant's cryptographic consent. Without
/// it, the participant is NOT part of the route — regardless of what the
/// `RouteProposal` says.
#[derive(Debug, Clone)]
pub struct RouteAcceptance {
    /// The hash of the `RouteProposal` this acceptance is for.
    pub proposal_hash: [u8; 32],
    /// The accepting participant's NodeId.
    pub participant_node_id: [u8; 32],
    /// The participant's Ed25519 public key.
    pub participant_public_key: [u8; 32],
    /// The role the participant accepts ("relay" or "gateway").
    pub role: String,
    /// Conditions (e.g. "max-bandwidth:5Mbps", "quota:1GB").
    pub conditions: Vec<String>,
    /// When the acceptance was created (unix seconds).
    pub timestamp: u64,
    /// When the acceptance expires (unix seconds).
    pub expiry: u64,
    /// The participant's Ed25519 signature.
    pub signature: [u8; 64],
}

impl RouteAcceptance {
    /// Create and sign a `RouteAcceptance`.
    #[must_use]
    pub fn create_and_sign(
        participant_secret_key: &[u8; 32],
        participant_public_key: &[u8; 32],
        participant_node_id: [u8; 32],
        proposal_hash: [u8; 32],
        role: String,
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
            (CborValue::TextString("role".into()), CborValue::TextString(self.role.clone())),
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

    /// Verify the participant's signature and NodeId↔pubkey binding.
    #[must_use]
    pub fn verify(&self) -> bool {
        let expected = derive_node_id(&self.participant_public_key);
        if self.participant_node_id != expected {
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
/// produced a valid `RouteAcceptance`.
///
/// ## CRITICAL: RouteProposal ≠ CommittedRoute
///
/// A `CommittedRoute` CANNOT be constructed from a `RouteProposal` alone.
/// The ONLY constructor is `commit_route(proposal, acceptances)`, which
/// verifies:
///
/// 1. The proposal's source signature is valid.
/// 2. The proposal has not expired.
/// 3. Every required participant (every hop except the source) has a
///    `RouteAcceptance`.
/// 4. Each acceptance's signature is valid.
/// 5. Each acceptance's `participant_node_id` matches a required participant.
/// 6. Each acceptance has not expired.
/// 7. Each acceptance's `proposal_hash` matches the proposal.
///
/// If ANY of these checks fail, `commit_route` returns `Err` and NO
/// `CommittedRoute` is produced.
///
/// ## Construction is private
///
/// `CommittedRoute`'s fields are private. The only way to create one is
/// `commit_route()`. This makes it impossible to construct a committed route
/// without the required participant acceptances — the type system enforces
/// spec §27's invariant: "A source signature alone is insufficient to prove
/// that every relay agreed to participate."
#[derive(Debug, Clone)]
pub struct CommittedRoute {
    /// The proposal that was committed.
    proposal: RouteProposal,
    /// The accepted route's commitment hash (integrity identifier).
    commitment: [u8; 32],
    /// The participant acceptances, keyed by NodeId.
    acceptances: Vec<RouteAcceptance>,
    /// When the route was committed (unix seconds).
    committed_at: u64,
}

/// Error from `commit_route()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError {
    /// The proposal's source signature is invalid.
    ProposalSignatureInvalid,
    /// The proposal has expired.
    ProposalExpired { now: u64, expiry: u64 },
    /// A required participant did not produce an acceptance.
    MissingAcceptance { participant: [u8; 32] },
    /// An acceptance's signature is invalid.
    AcceptanceSignatureInvalid { participant: [u8; 32] },
    /// An acceptance is for a different proposal (hash mismatch).
    AcceptanceProposalMismatch { participant: [u8; 32] },
    /// An acceptance has expired.
    AcceptanceExpired { participant: [u8; 32], now: u64, expiry: u64 },
    /// An acceptance is from a node that is not a required participant.
    UnexpectedParticipant { participant: [u8; 32] },
    /// The proposal has no hops.
    EmptyRoute,
    /// The proposal has too many hops.
    ExcessiveHops { count: usize },
    /// The destination is not the last hop.
    DestinationMismatch,
    /// A hop appears more than once (loop).
    DuplicateHop { node_id: [u8; 32] },
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProposalSignatureInvalid => write!(f, "proposal source signature invalid"),
            Self::ProposalExpired { now, expiry } => write!(f, "proposal expired (now={now}, expiry={expiry})"),
            Self::MissingAcceptance { participant } => write!(f, "missing acceptance from participant {}", hex_short(participant)),
            Self::AcceptanceSignatureInvalid { participant } => write!(f, "acceptance signature invalid from {}", hex_short(participant)),
            Self::AcceptanceProposalMismatch { participant } => write!(f, "acceptance from {} is for a different proposal", hex_short(participant)),
            Self::AcceptanceExpired { participant, now, expiry } => write!(f, "acceptance from {} expired (now={now}, expiry={expiry})", hex_short(participant)),
            Self::UnexpectedParticipant { participant } => write!(f, "acceptance from unexpected participant {}", hex_short(participant)),
            Self::EmptyRoute => write!(f, "route has no hops"),
            Self::ExcessiveHops { count } => write!(f, "route has too many hops: {count} > {ROUTE_MAX_HOPS}"),
            Self::DestinationMismatch => write!(f, "destination is not the last hop"),
            Self::DuplicateHop { node_id } => write!(f, "duplicate hop: {}", hex_short(node_id)),
        }
    }
}

/// Commit a route proposal into a `CommittedRoute`.
///
/// This is the ONLY way to construct a `CommittedRoute`. It verifies that
/// every required participant has produced a valid `RouteAcceptance`.
///
/// # Errors
/// Returns `CommitError` if any check fails. No `CommittedRoute` is produced
/// on error — the caller must fix the issue and retry.
///
/// ## Required participants
///
/// Every hop EXCEPT the source must accept. The source is the proposer; the
/// destination (gateway) and all relays must sign.
pub fn commit_route(
    proposal: RouteProposal,
    acceptances: Vec<RouteAcceptance>,
    now: u64,
) -> Result<CommittedRoute, CommitError> {
    // 1. Verify the proposal's source signature.
    if !proposal.verify() {
        return Err(CommitError::ProposalSignatureInvalid);
    }

    // 2. Check proposal expiry.
    if proposal.expiry <= now {
        return Err(CommitError::ProposalExpired { now, expiry: proposal.expiry });
    }

    // 3. Structural validation of the hop list.
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

    // 4. Determine required participants (every hop except the source).
    let required: Vec<[u8; 32]> = proposal.required_participants();

    // 5. Verify each acceptance and match it to a required participant.
    let mut accepted_by: std::collections::HashMap<[u8; 32], &RouteAcceptance> = std::collections::HashMap::new();
    for acc in &acceptances {
        // 5a. Verify the acceptance's signature.
        if !acc.verify() {
            return Err(CommitError::AcceptanceSignatureInvalid { participant: acc.participant_node_id });
        }
        // 5b. Check acceptance expiry.
        if acc.expiry <= now {
            return Err(CommitError::AcceptanceExpired { participant: acc.participant_node_id, now, expiry: acc.expiry });
        }
        // 5c. Check the acceptance is for THIS proposal.
        if acc.proposal_hash != proposal.proposal_hash() {
            return Err(CommitError::AcceptanceProposalMismatch { participant: acc.participant_node_id });
        }
        // 5d. Check the participant is a required participant.
        if !required.contains(&acc.participant_node_id) {
            return Err(CommitError::UnexpectedParticipant { participant: acc.participant_node_id });
        }
        // 5e. Store (first acceptance per participant wins; duplicates are ignored).
        accepted_by.entry(acc.participant_node_id).or_insert(acc);
    }

    // 6. Check that EVERY required participant has accepted.
    for req in &required {
        if !accepted_by.contains_key(req) {
            return Err(CommitError::MissingAcceptance { participant: *req });
        }
    }

    // 7. All checks passed. Construct the CommittedRoute.
    let commitment = {
        // The commitment is the SHA-256 of (proposal_hash || all acceptance hashes).
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
    /// The proposal that was committed.
    #[must_use]
    pub fn proposal(&self) -> &RouteProposal {
        &self.proposal
    }

    /// The commitment hash (integrity identifier for the committed route).
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// The acceptances that authorized this route.
    #[must_use]
    pub fn acceptances(&self) -> &[RouteAcceptance] {
        &self.acceptances
    }

    /// When the route was committed.
    #[must_use]
    pub fn committed_at(&self) -> u64 {
        self.committed_at
    }

    /// The source NodeId.
    #[must_use]
    pub fn source(&self) -> [u8; 32] {
        self.proposal.source
    }

    /// The destination NodeId.
    #[must_use]
    pub fn destination(&self) -> [u8; 32] {
        self.proposal.destination
    }

    /// The ordered hop NodeIds.
    #[must_use]
    pub fn hops(&self) -> &[[u8; 32]] {
        &self.proposal.hop_node_ids
    }

    /// Check if the committed route has expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.proposal.expiry <= now
    }
}

// ─── Path discovery using ExecutableNetworkSnapshot ────────────────────────

/// Discover a candidate path from source to destination using ONLY
/// authenticated nodes and usable links from an `ExecutableNetworkSnapshot`.
///
/// ## CRITICAL: Authenticated topology ≠ Executable route
///
/// This function finds a PATH (a sequence of authenticated NodeIds connected
/// by usable links). It does NOT construct a `CommittedRoute` — it returns
/// a `DiscoveredPath` that can be used to build a `RouteProposal` (which
/// then requires participant acceptances to become a `CommittedRoute`).
///
/// The discovered path uses ONLY data from `ExecutableNetworkSnapshot`:
/// - `authenticated_nodes` (verified `AuthenticatedNodeRecord`s)
/// - `usable_links` (Up or Degraded links)
///
/// It NEVER uses `RemoteNodeHint`s (they are not in the snapshot). This is
/// the architectural guarantee from spec §18: discovery knowledge ≠
/// executable routing state.
///
/// ## Algorithm
///
/// BFS (breadth-first search) from source to destination. BFS is chosen over
/// Dijkstra/A* deliberately: the frozen spec §62 says "Do not implement
/// arbitrary global routing algorithms merely because they are well known.
/// The first route engine should prioritize correctness, authentication,
/// bounded state, failure handling over theoretical optimality. A simple
/// valid route is more important than an optimal invalid route."
///
/// BFS finds the shortest hop-count path, which is simple, correct, and
/// bounded. Optimization (latency, bandwidth) is a future concern.
#[must_use]
pub fn discover_path(
    snapshot: &ExecutableNetworkSnapshot,
    source: &[u8; 32],
    destination: &[u8; 32],
) -> Option<DiscoveredPath> {
    // BFS from source to destination.
    use std::collections::{HashMap, VecDeque};
    let mut visited: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut parent: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
    visited.insert(*source);
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
        // Explore neighbors via usable links.
        for link in snapshot.usable_links.values() {
            if link.key.local_node_id == current && !visited.contains(&link.key.remote_node_id) {
                visited.insert(link.key.remote_node_id);
                parent.insert(link.key.remote_node_id, current);
                queue.push_back(link.key.remote_node_id);
            }
        }
    }
    None
}

/// A discovered path — a sequence of authenticated NodeIds connected by
/// usable links, found by `discover_path()`.
///
/// This is NOT a route. It is the INPUT to `RouteProposal::create_and_sign()`.
/// The caller must verify each hop's descriptor, negotiate service, and
/// obtain participant acceptances before a `CommittedRoute` can be built.
#[derive(Debug, Clone)]
pub struct DiscoveredPath {
    /// Ordered NodeIds from source to destination.
    pub hops: Vec<[u8; 32]>,
}

impl DiscoveredPath {
    /// Get the hop count.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
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

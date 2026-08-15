//! N2.1.1.1 — Topology Graph: directed graph of nodes and links with
//! non-authoritative remote hints.
//!
//! ## N2.1.1.1 correction: Remote topology hints are NOT authoritative
//!
//! Remote topology knowledge (from `PeerSummary` propagation) is explicitly
//! represented as `RemoteNodeHint` — a **non-authoritative third-party claim**.
//! A `RemoteNodeHint` CANNOT be converted into `AuthenticatedNodeRecord`,
//! `VerifiedNodeDescriptor`, or any authenticated type without obtaining and
//! verifying the target node's actual `NodeAdvertisement`.
//!
//! ## Gateway queries
//!
//! - `direct_gateways()` — returns ONLY authenticated, directly reachable
//!   gateways (`AuthenticatedNodeRecord`).
//! - `gateway_hints()` — returns remote gateway claims (`RemoteNodeHint`).
//!   These are discovery hints, NOT authenticated gateway identities.
//!
//! There is NO `all_known_gateways()` that conflates the two.
//!
//! ## Propagation replay prevention
//!
//! `PeerSummaryList` messages carry a `propagation_sequence` (monotonic
//! per-sender). The `TopologyGraph` tracks the highest propagation_sequence
//! per sender and rejects stale/replayed lists.

use super::*;
use crate::node::link::{Link, LinkKey, LinkState, LinkTable, TransportType};
use crate::node::propagation_state::PropagationStateStore;
use crate::node::topology_protocol::{REMOTE_HINT_MAX_AGE_SECS, VerifiedPeerSummaryList};
use std::collections::{HashMap, HashSet};

/// Format a 32-byte NodeId as lowercase hex for diagnostic logs.
fn hex(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Helper to format a `[u8; 32]` owned value as hex (for log calls).
fn hex_owned(b: [u8; 32]) -> String {
    hex(&b)
}

/// A remote node hint — third-party topology knowledge that is NOT
/// authoritative.
///
/// A `RemoteNodeHint` represents a claim made by one node (`learned_from`)
/// about another node (`target_node_id`). The claim includes the target's
/// advertised capabilities, sequence, and a distance hint — but it is
/// signed by the **claiming node**, NOT by the **target node**.
///
/// ## CRITICAL: NOT an authenticated node identity
///
/// A `RemoteNodeHint` CANNOT be converted into:
/// - `VerifiedNodeDescriptor`
/// - `AuthenticatedNodeRecord`
/// - Any authenticated type
///
/// without obtaining and successfully verifying the target node's actual
/// `NodeAdvertisement`.
///
/// A malicious relay can claim:
/// ```text
/// "Node G is a gateway"
/// ```
/// and this will be stored as a `RemoteNodeHint`. But `direct_gateways()`
/// will NOT include G, and the future route engine MUST NOT use G as an
/// authenticated destination until G's actual advertisement is verified.
///
/// ## Provenance
///
/// The hint preserves:
/// - `learned_from` — who made this claim
/// - `received_at` — when we received it
/// - `claimed_sequence` — what advertisement sequence they claimed
/// - `distance_hint` — how many hops they claimed (heuristic, NOT a route)
#[derive(Debug, Clone)]
pub struct RemoteNodeHint {
    /// The NodeId of the node being claimed about.
    pub target_node_id: [u8; 32],
    /// The advertisement sequence claimed by the source.
    pub claimed_sequence: u64,
    /// The capabilities claimed for the target node.
    pub claimed_capabilities: Vec<String>,
    /// The visibility claimed for the target node ("active" or "stale").
    pub claimed_visibility: String,
    /// When the claiming source last had contact with the target.
    pub claimed_last_seen: u64,
    /// A hop-distance heuristic from the source to the target.
    /// 0 = self, 1 = direct neighbor, 2 = two hops, etc.
    ///
    /// **distance_hint is NOT a route.** It is a discovery heuristic.
    /// It does NOT represent a verified path, next hop, or executable
    /// forwarding chain.
    pub distance_hint: u8,
    /// The NodeId of the peer that sent us this hint.
    pub learned_from: [u8; 32],
    /// When we received this hint (unix seconds).
    pub received_at: u64,
    /// The propagation_sequence of the PeerSummaryList that carried this hint.
    pub source_propagation_sequence: u64,
}

impl RemoteNodeHint {
    /// Check if this hint claims the target is a gateway.
    ///
    /// N2.5-T2: Now checks for all gateway-capability strings (old "gateway"
    /// and new "internet-gateway" / "crypto-gateway") using the typed
    /// `Capability::from_str()` + `is_gateway_capability()` bridge.
    ///
    /// **This is a CLAIM, not an authenticated fact.**
    #[must_use]
    pub fn claims_gateway(&self) -> bool {
        self.claimed_capabilities.iter().any(|c| {
            crate::node::identity::Capability::from_str(c)
                .map(|cap| cap.is_gateway_capability())
                .unwrap_or(false)
        })
    }

    /// Check if this hint claims the target is a relay.
    ///
    /// N2.5-T2: Now checks for all relay-capability strings (old "relay"
    /// and new "mesh-relay" / "crypto-relay") using the typed
    /// `Capability::from_str()` + `is_relay_capability()` bridge.
    ///
    /// **This is a CLAIM, not an authenticated fact.**
    #[must_use]
    pub fn claims_relay(&self) -> bool {
        self.claimed_capabilities.iter().any(|c| {
            crate::node::identity::Capability::from_str(c)
                .map(|cap| cap.is_relay_capability())
                .unwrap_or(false)
        })
    }

    /// Get the target NodeId.
    #[must_use]
    pub fn target_node_id(&self) -> [u8; 32] {
        self.target_node_id
    }

    /// Compute the freshness state of this hint relative to `now`.
    ///
    /// N2.1.1.1 review-gate fix #3: freshness is determined by
    /// `now - hint.received_at`, NOT by `hint.claimed_visibility`. A
    /// third-party claim like "the target is active" is a HISTORICAL claim —
    /// it cannot mean "the target is currently active indefinitely."
    ///
    /// - `Current`: `now - received_at <= REMOTE_HINT_MAX_AGE_SECS`
    /// - `Stale`: `now - received_at > REMOTE_HINT_MAX_AGE_SECS`
    ///
    /// Stale hints are excluded from `gateway_hints()` and may be purged by
    /// `purge_expired()`.
    #[must_use]
    pub fn freshness(&self, now: u64) -> RemoteHintFreshness {
        let age = now.saturating_sub(self.received_at);
        if age <= REMOTE_HINT_MAX_AGE_SECS {
            RemoteHintFreshness::Current
        } else {
            RemoteHintFreshness::Stale
        }
    }
}

/// Freshness state of a `RemoteNodeHint`.
///
/// N2.1.1.1 review-gate fix #3: this is computed from the hint's
/// `received_at` timestamp, NOT from the third-party `claimed_visibility`.
/// A remote claim of "active" cannot grant indefinite freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteHintFreshness {
    /// `now - received_at <= REMOTE_HINT_MAX_AGE_SECS` — the hint is recent
    /// enough to be considered for discovery.
    Current,
    /// `now - received_at > REMOTE_HINT_MAX_AGE_SECS` — the hint is too old
    /// to be trusted for discovery. Excluded from `gateway_hints()`.
    Stale,
}

/// The result of processing a PeerSummaryList.
#[derive(Debug, Clone)]
pub enum PropagationResult {
    /// The summary list was accepted (newer propagation_sequence).
    Accepted { hints_added: usize, hints_updated: usize },
    /// The summary list was rejected because its propagation_sequence is
    /// older than or equal to the highest seen from this sender.
    Stale {
        received_sequence: u64,
        known_sequence: u64,
    },
}

/// The topology graph — a directed graph of authenticated nodes and links,
/// plus non-authoritative remote hints.
///
/// ## Two classes of knowledge
///
/// - **Direct knowledge** (authoritative): nodes we've directly discovered
///   via verified `NodeAdvertisement` + probed links.
/// - **Remote hints** (non-authoritative): third-party claims from
///   `PeerSummaryList` propagation. These are discovery hints only.
pub struct TopologyGraph {
    /// The local peer directory (direct, authoritative knowledge).
    directory: PeerDirectory,
    /// Remote node hints (non-authoritative third-party claims).
    remote_hints: HashMap<[u8; 32], RemoteNodeHint>,
    /// Highest propagation_sequence seen per sender NodeId.
    /// Used for stateful replay prevention of PeerSummaryList messages.
    ///
    /// N2.1.1.1 review-gate fix #2: this is now a `PropagationStateStore`,
    /// which persists across restart (when a path is configured via
    /// `TopologyGraph::open()` or `open_with_propagation_path()`).
    propagation_state: PropagationStateStore,
}

impl TopologyGraph {
    /// Create a new empty in-memory topology graph (no persistence).
    ///
    /// ## ⚠️ TESTING ONLY — do NOT use in production
    ///
    /// This constructor creates an **ephemeral** `PropagationStateStore` that
    /// does NOT persist across restart. If production networking code uses
    /// this constructor, the restart-replay protection (review-gate fix #2) is
    /// silently defeated — an old propagation message could become acceptable
    /// again after a restart.
    ///
    /// Production code MUST use `TopologyGraph::open(path)` or
    /// `TopologyGraph::open_with_propagation_path(peer_path, prop_path)`,
    /// which load persistent replay-protection state from disk.
    ///
    /// **Why not just delete this?** Unit tests need an ephemeral constructor
    /// that doesn't touch the filesystem. The name `new()` is retained for
    /// ergonomics in tests, but the documentation and `#[track_caller]`
    /// attribute (via the `new_for_testing` alias below) make the intent
    /// auditable.
    ///
    /// For new test code, prefer `TopologyGraph::new_for_testing()` which
    /// makes the testing intent explicit and is easy to grep for in production
    /// code reviews.
    #[must_use]
    fn new() -> Self {
        Self {
            directory: PeerDirectory::new(),
            remote_hints: HashMap::new(),
            propagation_state: PropagationStateStore::new(),
        }
    }

    /// Create a new empty in-memory topology graph, explicitly for testing.
    ///
    /// This is the **only** public constructor that produces an ephemeral
    /// (non-persistent) topology graph. It exists for unit tests that don't
    /// touch the filesystem.
    ///
    /// ## ⚠️ TESTING ONLY — do NOT use in production
    ///
    /// This constructor creates an ephemeral `PropagationStateStore` that
    /// does NOT persist across restart. If production networking code uses
    /// this constructor, the restart-replay protection (review-gate fix #2)
    /// is silently defeated — an old propagation message could become
    /// acceptable again after a restart.
    ///
    /// Production code MUST use `TopologyGraph::open(path)` or
    /// `TopologyGraph::open_with_propagation_path(peer_path, prop_path)`,
    /// which load persistent replay-protection state from disk.
    ///
    /// ## Why `new()` is private
    ///
    /// `TopologyGraph::new()` is private. The only public ephemeral
    /// constructor is `new_for_testing()`. This makes accidental production
    /// misuse harder — a developer must explicitly opt into "testing" mode.
    /// A CI grep for `new_for_testing` in non-test code (`src/` excluding
    /// `tests/`) catches any misuse at code review.
    ///
    /// `impl Default for TopologyGraph` is deliberately REMOVED. The
    /// `Default::default()` path would also produce ephemeral state, so it
    /// is removed to close that escape hatch entirely.
    #[must_use]
    pub fn new_for_testing() -> Self {
        Self::new()
    }

    /// Create a persistent topology graph.
    ///
    /// Loads both the peer directory AND the propagation sequence state from
    /// disk. (N2.1.1.1 review-gate fix #2: propagation state is now
    /// persistent, so replay attacks cannot succeed across restart.)
    ///
    /// The propagation state is stored in a sibling file with a `.prop`
    /// extension added to `path`.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if the peer-directory persistence file is
    /// corrupted.
    /// Returns `PropagationStateError` (wrapped in `AcceptanceError`) if the
    /// propagation-state file is corrupted.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AcceptanceError> {
        let peer_path = path.as_ref().to_path_buf();
        let mut prop_path = peer_path.clone();
        prop_path.set_extension("prop");
        Self::open_with_propagation_path(peer_path, prop_path)
    }

    /// Create a persistent topology graph with explicit paths for the peer
    /// directory and the propagation state.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if either persistence file is corrupted.
    pub fn open_with_propagation_path(
        peer_path: impl AsRef<std::path::Path>,
        propagation_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, AcceptanceError> {
        let directory = PeerDirectory::open(peer_path)?;
        let propagation_state = PropagationStateStore::open(propagation_path)
            .map_err(|e| AcceptanceError::CorruptPersistence(format!("propagation: {e}")))?;
        Ok(Self {
            directory,
            remote_hints: HashMap::new(),
            propagation_state,
        })
    }

    // ─── Advertisement operations ─────────────────────────────────────────

    /// Accept a verified advertisement from a directly discovered node.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if persistence fails.
    ///
    /// ## Transaction order (N2.1.1.1 review-gate fix #4)
    ///
    /// If a remote hint for this node exists, it is removed ONLY AFTER the
    /// directory's `accept_advertisement` succeeds. This preserves the
    /// "persist → then mutate" invariant: a persistence failure leaves the
    /// remote hint in place rather than leaving the topology in a partially
    /// mutated state.
    pub fn accept_advertisement(
        &mut self,
        verified: VerifiedNodeAdvertisement,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        // NOTE: do NOT remove the remote hint yet — wait for the directory
        // to successfully persist the authenticated record first.
        let node_id = verified.node_id();
        let result = self.directory.accept_advertisement(verified);
        // Only remove the superseded remote hint if the direct acceptance
        // succeeded. On persistence failure, the hint is retained so the
        // topology remains in its pre-call state.
        if result.is_ok() {
            self.remote_hints.remove(&node_id);
        }
        result
    }

    // ─── Link operations ──────────────────────────────────────────────────

    /// Add a link to the topology.
    pub fn add_link(&mut self, link: Link) {
        self.directory.add_link(link);
    }

    /// Update a link's state.
    pub fn update_link_state(&mut self, key: &LinkKey, state: LinkState) {
        self.directory.update_link_state(key, state);
    }

    /// Remove a link.
    pub fn remove_link(&mut self, key: &LinkKey) {
        self.directory.remove_link(key);
    }

    /// Record a successful transmission on a link.
    pub fn record_link_success(&mut self, key: &LinkKey, rtt_micros: u64) {
        self.directory.record_link_success(key, rtt_micros);
    }

    /// Record a failed transmission on a link.
    pub fn record_link_failure(&mut self, key: &LinkKey) {
        self.directory.record_link_failure(key);
    }

    // ─── Remote topology propagation ──────────────────────────────────────

    /// Process a **verified** `PeerSummaryList` received from a peer.
    ///
    /// ## Trust boundary (N2.1.1.1 review-gate fix #1 — P0 blocker)
    ///
    /// This method accepts **only** `&VerifiedPeerSummaryList`. The only way
    /// to obtain a `VerifiedPeerSummaryList` is
    /// `PeerSummaryList::verify_into_verified()`, which performs Ed25519
    /// signature verification and sender NodeId↔pubkey binding verification.
    ///
    /// An attacker who manufactures a `PeerSummaryList` with an invalid
    /// signature, or with a `sender_node_id` that does not match the
    /// `derive_node_id(sender_ed25519_public_key)`, CANNOT obtain a
    /// `VerifiedPeerSummaryList` and therefore CANNOT mutate `remote_hints`,
    /// `propagation_state`, or any other topology state.
    ///
    /// This mirrors the `NodeAdvertisement → VerifiedNodeAdvertisement →
    /// AuthenticatedNodeRecord` trust-boundary pattern: the type system makes
    /// unverified → trusted conversion impossible without cryptography.
    ///
    /// ## N2.1.1.1: Non-authoritative storage + replay prevention
    ///
    /// - The list's `propagation_sequence` is checked against the highest
    ///   seen from this sender. Stale/duplicate lists are rejected.
    /// - Remote summaries are stored as `RemoteNodeHint` — NOT as
    ///   `AuthenticatedNodeRecord`. They cannot be used as authenticated
    ///   node identities.
    /// - If a node is both directly known and remotely hinted, the direct
    ///   knowledge takes precedence (the hint is not stored).
    /// - Propagation sequence state is persisted (if a persistence path was
    ///   configured via `TopologyGraph::open()`).
    pub fn process_peer_summaries(
        &mut self,
        verified_list: &VerifiedPeerSummaryList,
    ) -> PropagationResult {
        let sender = verified_list.sender_node_id();
        let prop_seq = verified_list.propagation_sequence();

        // Stateful replay prevention: reject stale/duplicate propagation.
        match self.propagation_state.highest_sequence(&sender) {
            Some(known) if prop_seq <= known => {
                return PropagationResult::Stale {
                    received_sequence: prop_seq,
                    known_sequence: known,
                };
            }
            _ => {}
        }

        // Persist the propagation sequence floor BEFORE mutating remote_hints
        // (Section 51 critical mutation sequence: persist → verify → mutate).
        // If persistence fails, the sequence is NOT advanced and no hints are
        // stored — we return Stale so the caller can retry without corruption.
        if let Err(e) = self.propagation_state.accept_sequence(sender, prop_seq) {
            // Persistence failed — fail closed. Do NOT mutate remote_hints.
            // Return Stale so the caller sees a non-Accepted result; the
            // topology is unchanged.
            eprintln!(
                "[sharenet] propagation state persistence failed for sender \
                 {}: {} — topology NOT mutated (fail-closed)",
                hex_owned(sender),
                e
            );
            return PropagationResult::Stale {
                received_sequence: prop_seq,
                // known_sequence reflects the persisted floor (unchanged on failure)
                known_sequence: self
                    .propagation_state
                    .highest_sequence(&sender)
                    .unwrap_or(0),
            };
        }

        let now = now_unix();
        let mut hints_added = 0usize;
        let mut hints_updated = 0usize;

        for summary in verified_list.summaries() {
            // Don't store hints about nodes we already know directly
            // (direct knowledge takes precedence).
            if self.directory.get_record(&summary.node_id).is_some() {
                continue;
            }

            let hint = RemoteNodeHint {
                target_node_id: summary.node_id,
                claimed_sequence: summary.advertisement_sequence,
                claimed_capabilities: summary.capabilities.clone(),
                claimed_visibility: summary.visibility.clone(),
                claimed_last_seen: summary.last_seen,
                distance_hint: summary.distance_hint,
                learned_from: sender,
                received_at: now,
                source_propagation_sequence: prop_seq,
            };

            // Only update if the claimed sequence is newer.
            let is_new = match self.remote_hints.get(&summary.node_id) {
                None => true,
                Some(existing) => summary.advertisement_sequence > existing.claimed_sequence,
            };
            if is_new {
                if self.remote_hints.contains_key(&summary.node_id) {
                    hints_updated += 1;
                } else {
                    hints_added += 1;
                }
                self.remote_hints.insert(summary.node_id, hint);
            }
        }

        PropagationResult::Accepted { hints_added, hints_updated }
    }

    /// Generate PeerSummaries for propagation to other peers.
    ///
    /// Includes:
    /// - Direct neighbors (distance_hint = 1 from our perspective)
    /// - Remote hints (distance_hint = their distance + 1)
    ///
    /// Does NOT include endpoint data.
    ///
    /// ## N2.1.1.1 review-gate fix #6 (P0): stale hints are NOT re-propagated
    ///
    /// Only `RemoteHintFreshness::Current` hints are included. A stale hint
    /// (older than `REMOTE_HINT_MAX_AGE_SECS`) is skipped, so it cannot be
    /// refreshed downstream by a peer who would otherwise set `received_at =
    /// NOW` and treat the old information as fresh.
    ///
    /// Without this check, the freshness rule in `gateway_hints()` would be
    /// defeated by propagation: A receives a hint about G, the hint goes
    /// stale, A generates a `PeerSummaryList` containing G, B receives it and
    /// sets `received_at = NOW`, and B now treats the stale information as
    /// fresh. This could repeat through the mesh indefinitely.
    #[must_use]
    pub fn generate_peer_summaries(&self) -> Vec<PeerSummary> {
        let now = now_unix();
        let mut summaries = Vec::new();

        // Direct neighbors (distance_hint = 1).
        // Direct knowledge is authoritative and not subject to the remote-hint
        // freshness rule — it is the source of fresh propagation.
        for record in self.directory.active_nodes() {
            summaries.push(PeerSummary::from_record(record, 1, now));
        }

        // Remote hints (increment distance_hint by 1, cap at 255).
        // SKIP stale hints — re-propagating them would refresh their
        // received_at downstream and defeat the freshness rule.
        for hint in self.remote_hints.values() {
            if hint.freshness(now) != RemoteHintFreshness::Current {
                continue;
            }
            let new_distance = hint.distance_hint.saturating_add(1);
            summaries.push(PeerSummary {
                node_id: hint.target_node_id,
                advertisement_sequence: hint.claimed_sequence,
                capabilities: hint.claimed_capabilities.clone(),
                visibility: hint.claimed_visibility.clone(),
                last_seen: hint.claimed_last_seen,
                distance_hint: new_distance,
            });
        }

        // Truncate to max.
        if summaries.len() > MAX_PEER_SUMMARIES_PER_MESSAGE {
            summaries.truncate(MAX_PEER_SUMMARIES_PER_MESSAGE);
        }

        summaries
    }

    /// Get all remote hints (non-authoritative third-party claims).
    #[must_use]
    pub fn remote_hints(&self) -> &HashMap<[u8; 32], RemoteNodeHint> {
        &self.remote_hints
    }

    /// Get a mutable reference to all remote hints.
    ///
    /// Exposed for diagnostic and test purposes (e.g., backdating a hint's
    /// `received_at` to simulate aging for freshness tests). Production code
    /// should not mutate hints directly — hints are managed by
    /// `process_peer_summaries()` and `purge_expired()`.
    pub fn remote_hints_mut(&mut self) -> &mut HashMap<[u8; 32], RemoteNodeHint> {
        &mut self.remote_hints
    }

    /// Get remote hints that CLAIM the target is a gateway.
    ///
    /// **These are CLAIMS, not authenticated facts.**
    /// A malicious relay can claim anything. Use `direct_gateways()` for
    /// authenticated gateway identities.
    ///
    /// N2.1.1.1 review-gate fix #3: stale hints (older than
    /// `REMOTE_HINT_MAX_AGE_SECS`) are EXCLUDED. A third-party claim of
    /// "active" cannot grant indefinite freshness.
    #[must_use]
    pub fn gateway_hints(&self) -> Vec<&RemoteNodeHint> {
        let now = now_unix();
        self.remote_hints
            .values()
            .filter(|h| h.claims_gateway() && h.freshness(now) == RemoteHintFreshness::Current)
            .collect()
    }

    /// Get ALL remote gateway hints, including stale ones.
    ///
    /// This is for diagnostic/observability only — callers that use hints
    /// for discovery should call `gateway_hints()` (which excludes stale).
    #[must_use]
    pub fn gateway_hints_including_stale(&self) -> Vec<&RemoteNodeHint> {
        self.remote_hints.values().filter(|h| h.claims_gateway()).collect()
    }

    /// Get the highest propagation_sequence seen from a sender.
    ///
    /// N2.1.1.1 review-gate fix #2: this value is now persisted across
    /// restart when a propagation path was configured.
    #[must_use]
    pub fn highest_propagation_sequence(&self, sender: &[u8; 32]) -> Option<u64> {
        self.propagation_state.highest_sequence(sender)
    }

    // ─── Queries ──────────────────────────────────────────────────────────

    /// Get all outgoing links from a node (direct knowledge only).
    #[must_use]
    pub fn neighbors(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.directory.links_from(node_id)
    }

    /// Get all usable outgoing links from a node.
    #[must_use]
    pub fn usable_neighbors(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.directory.usable_links_from(node_id)
    }

    /// Get all **directly reachable authenticated** gateways.
    ///
    /// Returns ONLY nodes with:
    /// 1. A CURRENT advertisement (not STALE).
    /// 2. `Capability::Gateway` in their capabilities.
    /// 3. At least one usable (UP/Degraded) outgoing link.
    /// 4. An X25519 circuit public key.
    ///
    /// **Does NOT include remote gateway hints.** Use `gateway_hints()`
    /// for non-authoritative third-party gateway claims.
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.directory.direct_gateways()
    }

    /// Get all directly reachable relays.
    #[must_use]
    pub fn reachable_relays(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.directory.reachable_relays()
    }

    /// Check if a node is directly reachable (has at least one usable link).
    #[must_use]
    pub fn is_directly_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.directory.is_reachable(node_id)
    }

    /// Check if a node is known (either directly authenticated or hinted).
    #[must_use]
    pub fn is_known(&self, node_id: &[u8; 32]) -> bool {
        self.directory.get_record(node_id).is_some()
            || self.remote_hints.contains_key(node_id)
    }

    /// Check if a node is **directly authenticated** (has a verified
    /// `AuthenticatedNodeRecord`, not just a remote hint).
    #[must_use]
    pub fn is_authenticated(&self, node_id: &[u8; 32]) -> bool {
        self.directory.get_record(node_id).is_some()
    }

    /// Get the visibility state of a directly known peer.
    #[must_use]
    pub fn visibility(&self, node_id: &[u8; 32]) -> PeerVisibility {
        self.directory.visibility(node_id)
    }

    /// Get the current `AuthenticatedNodeRecord` for a directly known node.
    #[must_use]
    pub fn get_record(&self, node_id: &[u8; 32]) -> Option<&AuthenticatedNodeRecord> {
        self.directory.get_record(node_id)
    }

    /// Remove a peer entirely (including the sequence floor).
    /// Also removes all links and remote hints about this node.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if persistence fails.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Result<(), AcceptanceError> {
        self.remote_hints.remove(node_id);
        self.directory.remove_peer(node_id)
    }

    /// Purge expired records, dead links, and stale remote hints.
    ///
    /// N2.1.1.1 review-gate fix #3: remote hints are purged based on their
    /// AGE (`now - received_at > REMOTE_HINT_MAX_AGE_SECS`), NOT based on
    /// their `claimed_visibility`. A third-party claim of "active" cannot
    /// grant indefinite freshness — the previous implementation retained
    /// such hints forever, contradicting the architecture's freshness
    /// requirement.
    ///
    /// Hints that have aged past `REMOTE_HINT_MAX_AGE_SECS` are removed. If
    /// a fresher propagation message arrives later, a new hint will be
    /// stored (subject to the propagation-sequence replay check).
    pub fn purge_expired(&mut self, now: u64) {
        self.directory.purge_expired(now);
        // Purge remote hints whose AGE exceeds the freshness window.
        self.remote_hints.retain(|_, hint| {
            hint.freshness(now) == RemoteHintFreshness::Current
        });
    }

    /// Get the peer directory (for direct access).
    #[must_use]
    pub fn directory(&self) -> &PeerDirectory {
        &self.directory
    }

    /// Get a mutable peer directory.
    pub fn directory_mut(&mut self) -> &mut PeerDirectory {
        &mut self.directory
    }

    /// Produce an immutable snapshot of the topology.
    ///
    /// ## Deprecated (N2.1.1.1 review-gate fix #7)
    ///
    /// This method returns `TopologySnapshot`, which bundles
    /// non-authoritative `RemoteNodeHint`s with authoritative data — making
    /// it unsafe as a routing input. Use:
    ///   - `snapshot_knowledge()` for diagnostics (includes remote hints)
    ///   - `snapshot_executable()` for routing inputs (authenticated only)
    #[deprecated(
        since = "N2.1.1.1",
        note = "use `snapshot_knowledge()` for diagnostics or `snapshot_executable()` \
               for routing inputs"
    )]
    #[must_use]
    pub fn snapshot(&self) -> TopologySnapshot {
        TopologySnapshot::from_graph(self)
    }

    /// Produce an immutable **knowledge** snapshot — ALL topology knowledge
    /// (direct nodes + links + remote hints).
    ///
    /// For **diagnostics, inspection, logging, UI display**.
    ///
    /// NOT a routing input — contains non-authoritative `RemoteNodeHint`s.
    /// Use `snapshot_executable()` for routing.
    #[must_use]
    pub fn snapshot_knowledge(&self) -> TopologyKnowledgeSnapshot {
        TopologyKnowledgeSnapshot::from_graph(self)
    }

    /// Produce an immutable **executable** snapshot — ONLY authenticated
    /// nodes and usable links. NEVER contains `RemoteNodeHint`s.
    ///
    /// For **routing inputs** (N2.1.2 and beyond).
    ///
    /// This enforces the frozen architectural separation (spec §18):
    /// discovery knowledge ≠ executable routing state. A future route engine
    /// MUST accept this type, ensuring it cannot accidentally use
    /// non-authoritative hints as routing hops.
    #[must_use]
    pub fn snapshot_executable(&self) -> ExecutableNetworkSnapshot {
        ExecutableNetworkSnapshot::from_graph(self)
    }

    /// Get the total number of known nodes (direct + remote hints).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.directory.peer_count() + self.remote_hints.len()
    }

    /// Get the number of links.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.directory.link_count()
    }
}

// NOTE: `impl Default for TopologyGraph` is deliberately REMOVED (N2.1.1.1
// review-gate fix #9). The `Default::default()` path would produce an
// ephemeral (non-persistent) topology graph, silently defeating the
// restart-replay protection established in review-gate fix #2. Production
// code MUST use `TopologyGraph::open(path)` or
// `TopologyGraph::open_with_propagation_path(...)`. Tests use
// `TopologyGraph::new_for_testing()`.

/// An immutable point-in-time view of the topology.
///
/// ## N2.1.1.1 review-gate fix #7: split into knowledge vs executable
///
/// This type is now a **diagnostic** snapshot that includes BOTH
/// authoritative (direct nodes + links) AND non-authoritative (remote hints)
/// knowledge. It is suitable for inspection, logging, and UI display.
///
/// It is NOT suitable as a routing input. A future route engine MUST accept
/// [`ExecutableNetworkSnapshot`] (produced by [`TopologyGraph::snapshot_executable`]),
/// which contains ONLY authenticated nodes and usable links — never
/// `RemoteNodeHint`s. This enforces the frozen architectural separation:
///
/// ```text
/// Discovery knowledge  !=  Executable routing state
/// ```
///
/// `TopologySnapshot` is retained as a deprecated alias for
/// [`TopologyKnowledgeSnapshot`] so existing callers keep compiling. New code
/// should call `snapshot_knowledge()` or `snapshot_executable()` explicitly.
#[deprecated(
    since = "N2.1.1.1",
    note = "use `TopologyKnowledgeSnapshot` (via `snapshot_knowledge()`) for \
           diagnostics, or `ExecutableNetworkSnapshot` (via `snapshot_executable()`) \
           for routing inputs. This alias bundles non-authoritative remote hints \
           with authoritative data — unsafe as a routing input."
)]
#[derive(Debug, Clone)]
pub struct TopologySnapshot {
    /// Direct authenticated nodes (NodeId -> AuthenticatedNodeRecord).
    pub direct_nodes: HashMap<[u8; 32], AuthenticatedNodeRecord>,
    /// Direct links (LinkKey -> Link).
    pub links: HashMap<LinkKey, Link>,
    /// Remote hints (NodeId -> RemoteNodeHint). Non-authoritative.
    pub remote_hints: HashMap<[u8; 32], RemoteNodeHint>,
}

/// An immutable point-in-time view of ALL topology knowledge — both
/// authoritative (direct nodes + links) and non-authoritative (remote hints).
///
/// For **diagnostics, inspection, logging, and UI display**.
///
/// ## NOT a routing input
///
/// This snapshot includes `RemoteNodeHint`s, which are third-party claims —
/// NOT authenticated node identities. A future route engine MUST NOT accept
/// this type. Use [`ExecutableNetworkSnapshot`] (via
/// [`TopologyGraph::snapshot_executable`]) for routing inputs.
///
/// This enforces the frozen architectural separation (spec section 18):
/// ```text
/// Discovery Topology  ("What might exist?")
///        !=
/// Executable Network State  ("What can actually be used now?")
/// ```
#[derive(Debug, Clone)]
pub struct TopologyKnowledgeSnapshot {
    /// Direct authenticated nodes (NodeId -> AuthenticatedNodeRecord).
    pub direct_nodes: HashMap<[u8; 32], AuthenticatedNodeRecord>,
    /// Direct links (LinkKey -> Link).
    pub links: HashMap<LinkKey, Link>,
    /// Remote hints (NodeId -> RemoteNodeHint). Non-authoritative.
    pub remote_hints: HashMap<[u8; 32], RemoteNodeHint>,
}

impl TopologyKnowledgeSnapshot {
    /// Create a knowledge snapshot from a TopologyGraph.
    fn from_graph(graph: &TopologyGraph) -> Self {
        let mut direct_nodes = HashMap::new();
        for node_id in graph
            .directory
            .link_table()
            .all()
            .flat_map(|l| [l.key.local_node_id, l.key.remote_node_id])
            .collect::<HashSet<_>>()
        {
            if let Some(record) = graph.directory.get_record(&node_id) {
                direct_nodes.insert(node_id, record.clone());
            }
        }
        let mut links = HashMap::new();
        for link in graph.directory.link_table().all() {
            links.insert(link.key.clone(), link.clone());
        }
        let remote_hints = graph.remote_hints.clone();
        Self { direct_nodes, links, remote_hints }
    }

    /// Get usable outgoing links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links
            .values()
            .filter(|l| l.key.local_node_id == *node_id && l.is_usable())
            .collect()
    }

    /// Get remote gateway **hints** in the snapshot (non-authoritative).
    #[must_use]
    pub fn gateway_hints(&self) -> Vec<&RemoteNodeHint> {
        self.remote_hints
            .values()
            .filter(|h| h.claims_gateway())
            .collect()
    }

    /// Check if a node is directly reachable in this snapshot.
    #[must_use]
    pub fn is_directly_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.links
            .values()
            .any(|l| l.key.remote_node_id == *node_id && l.is_usable())
    }
}

/// An immutable point-in-time view of **executable** network state — ONLY
/// authenticated nodes and usable links. NEVER contains `RemoteNodeHint`s.
///
/// ## For routing inputs (N2.1.2 and beyond)
///
/// A future route engine MUST accept this type, NOT `TopologyKnowledgeSnapshot`.
/// This enforces the frozen architectural separation (spec section 18):
///
/// ```text
/// Discovery Topology  ("What might exist?")
///        !=
/// Executable Network State  ("What can actually be used now?")
/// ```
///
/// Remote hints are useful for DISCOVERY (candidate destination identification)
/// but MUST NOT feed ROUTING (path construction). A route built from a hint
/// would have an unauthenticated hop — violating spec section 54 #10:
/// "A Route cannot contain an unauthenticated hop."
#[derive(Debug, Clone)]
pub struct ExecutableNetworkSnapshot {
    /// Direct authenticated nodes (NodeId -> AuthenticatedNodeRecord).
    pub authenticated_nodes: HashMap<[u8; 32], AuthenticatedNodeRecord>,
    /// Usable links (LinkKey -> Link). Only `LinkState::Up` or `Degraded`.
    pub usable_links: HashMap<LinkKey, Link>,
}

impl ExecutableNetworkSnapshot {
    /// Create an executable snapshot from a TopologyGraph.
    ///
    /// ## Invariant (P1 #6 — N2.1.2 review fix)
    ///
    /// Every usable link in the snapshot has BOTH endpoints authenticated.
    /// A link whose remote endpoint is not in `authenticated_nodes` is
    /// EXCLUDED. This ensures `discover_path()` can safely rely on the
    /// snapshot — every link it iterates leads to an authenticated node.
    fn from_graph(graph: &TopologyGraph) -> Self {
        let mut authenticated_nodes = HashMap::new();
        for node_id in graph
            .directory
            .link_table()
            .all()
            .flat_map(|l| [l.key.local_node_id, l.key.remote_node_id])
            .collect::<HashSet<_>>()
        {
            if let Some(record) = graph.directory.get_record(&node_id) {
                authenticated_nodes.insert(node_id, record.clone());
            }
        }
        let mut usable_links = HashMap::new();
        for link in graph.directory.link_table().all() {
            if link.is_usable() {
                // P1 #6: only include links whose BOTH endpoints are
                // authenticated. A usable link to an unauthenticated node
                // is NOT executable routing state.
                let local_auth = authenticated_nodes.contains_key(&link.key.local_node_id);
                let remote_auth = authenticated_nodes.contains_key(&link.key.remote_node_id);
                if local_auth && remote_auth {
                    usable_links.insert(link.key.clone(), link.clone());
                }
            }
        }
        Self { authenticated_nodes, usable_links }
    }

    /// Get usable outgoing links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.usable_links
            .values()
            .filter(|l| l.key.local_node_id == *node_id)
            .collect()
    }

    /// Get all **authenticated** direct gateways in the executable snapshot.
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.authenticated_nodes
            .values()
            .filter(|r| r.descriptor.is_gateway())
            .filter(|r| r.descriptor.circuit_x25519_pub().is_some())
            .filter(|r| {
                self.usable_links
                    .values()
                    .any(|l| l.key.remote_node_id == r.descriptor.node_id())
            })
            .collect()
    }

    /// Check if a node is directly reachable in this snapshot.
    #[must_use]
    pub fn is_directly_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.usable_links
            .values()
            .any(|l| l.key.remote_node_id == *node_id)
    }
}

// --- Deprecated TopologySnapshot compatibility shim ---
//
// Retained so existing callers keep compiling. New code should use
// TopologyKnowledgeSnapshot (via snapshot_knowledge()) or
// ExecutableNetworkSnapshot (via snapshot_executable()).

#[allow(deprecated)]
impl TopologySnapshot {
    /// Create a snapshot from a TopologyGraph.
    fn from_graph(graph: &TopologyGraph) -> Self {
        let k = TopologyKnowledgeSnapshot::from_graph(graph);
        Self {
            direct_nodes: k.direct_nodes,
            links: k.links,
            remote_hints: k.remote_hints,
        }
    }

    /// Get usable outgoing links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links
            .values()
            .filter(|l| l.key.local_node_id == *node_id && l.is_usable())
            .collect()
    }

    /// Get all **authenticated** direct gateways in the snapshot.
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.direct_nodes
            .values()
            .filter(|r| r.descriptor.is_gateway())
            .filter(|r| r.descriptor.circuit_x25519_pub().is_some())
            .filter(|r| {
                self.links
                    .values()
                    .any(|l| l.key.remote_node_id == r.descriptor.node_id() && l.is_usable())
            })
            .collect()
    }

    /// Get remote gateway **hints** in the snapshot (non-authoritative).
    #[must_use]
    pub fn gateway_hints(&self) -> Vec<&RemoteNodeHint> {
        self.remote_hints
            .values()
            .filter(|h| h.claims_gateway())
            .collect()
    }

    /// Check if a node is directly reachable in this snapshot.
    #[must_use]
    pub fn is_directly_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.links
            .values()
            .any(|l| l.key.remote_node_id == *node_id && l.is_usable())
    }
}

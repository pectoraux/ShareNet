//! N2.1.1 — Topology Graph: directed graph of nodes and links.
//!
//! The `TopologyGraph` is the central data structure for ShareNet's network
//! model. It combines:
//! - Nodes (from authenticated advertisements via `PeerDirectory`)
//! - Directed links (from probed, authenticated transport connections)
//! - Remote topology knowledge (from `PeerSummary` propagation)
//!
//! The graph supports:
//! - Querying neighbors, reachable gateways, reachable relays
//! - Producing immutable snapshots for route computation
//! - Tolerating node churn (appearance, disappearance, return)
//!
//! ## Directed topology
//!
//! Links are directed: A→B does NOT imply B→A. This models real-world
//! asymmetry (firewalls, NAT, transport limitations).

use super::*;
use crate::node::link::{Link, LinkKey, LinkState, LinkTable, TransportType};
use std::collections::{HashMap, HashSet};

/// The topology graph — a directed graph of authenticated nodes and links.
///
/// ## Local vs Remote Knowledge
///
/// The graph contains two types of knowledge:
/// - **Direct knowledge**: nodes we've directly discovered + links we've
///   probed (via `PeerDirectory`).
/// - **Remote knowledge**: nodes we've learned about via `PeerSummary`
///   propagation from other peers. Remote knowledge includes identity,
///   capabilities, and distance hints — but NOT endpoint data.
///
/// Remote knowledge is marked with a `distance_hint > 0`. A node with
/// `distance_hint == 0` is a direct neighbor. A node with
/// `distance_hint == 1` is one hop away through a direct neighbor, etc.
pub struct TopologyGraph {
    /// The local peer directory (direct knowledge).
    directory: PeerDirectory,
    /// Remote node knowledge: NodeId → (PeerSummary, source NodeId).
    /// Learned via PeerSummary propagation. Does NOT include endpoint data.
    remote_nodes: HashMap<[u8; 32], RemoteNodeEntry>,
}

/// A remote node learned via topology propagation.
#[derive(Debug, Clone)]
pub struct RemoteNodeEntry {
    /// The summary received from a peer.
    pub summary: PeerSummary,
    /// The NodeId of the peer that sent us this summary.
    pub learned_from: [u8; 32],
    /// When we received this summary (unix seconds).
    pub received_at: u64,
}

impl TopologyGraph {
    /// Create a new empty topology graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            directory: PeerDirectory::new(),
            remote_nodes: HashMap::new(),
        }
    }

    /// Create a persistent topology graph.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if the persistence file is corrupted.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AcceptanceError> {
        Ok(Self {
            directory: PeerDirectory::open(path)?,
            remote_nodes: HashMap::new(),
        })
    }

    // ─── Advertisement operations ─────────────────────────────────────────

    /// Accept a verified advertisement from a directly discovered node.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if persistence fails.
    pub fn accept_advertisement(
        &mut self,
        verified: VerifiedNodeAdvertisement,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        self.directory.accept_advertisement(verified)
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

    /// Process a `PeerSummaryList` received from a peer.
    ///
    /// This updates the remote node knowledge with information from the
    /// summary. Remote nodes are NOT added to the acceptance store —
    /// they are tracked separately with distance hints.
    ///
    /// When a node is both directly known (via local discovery) and
    /// remotely known (via propagation), the direct knowledge takes
    /// precedence.
    pub fn process_peer_summaries(
        &mut self,
        summary_list: &PeerSummaryList,
    ) {
        let now = now_unix();
        let sender = summary_list.sender_node_id;
        for summary in &summary_list.summaries {
            // Don't store summaries about ourselves.
            // (The caller should filter, but we check defensively.)
            // Don't store summaries about nodes we already know directly
            // (direct knowledge takes precedence).
            if self.directory.get_record(&summary.node_id).is_some() {
                continue;
            }
            // Store or update the remote entry.
            let entry = RemoteNodeEntry {
                summary: summary.clone(),
                learned_from: sender,
                received_at: now,
            };
            // Only update if the sequence is newer than what we have.
            let should_update = match self.remote_nodes.get(&summary.node_id) {
                None => true,
                Some(existing) => summary.advertisement_sequence > existing.summary.advertisement_sequence,
            };
            if should_update {
                self.remote_nodes.insert(summary.node_id, entry);
            }
        }
    }

    /// Generate PeerSummaries for propagation to other peers.
    ///
    /// Includes:
    /// - Direct neighbors (distance_hint = 1 from our perspective)
    /// - Remote nodes we know about (distance_hint = their distance + 1)
    ///
    /// Does NOT include endpoint data.
    #[must_use]
    pub fn generate_peer_summaries(&self) -> Vec<PeerSummary> {
        let mut summaries = Vec::new();

        // Direct neighbors (distance_hint = 1).
        for record in self.directory.active_nodes() {
            summaries.push(PeerSummary::from_record(record, 1, now_unix()));
        }

        // Remote nodes (increment distance_hint by 1, cap at 255).
        for entry in self.remote_nodes.values() {
            let new_distance = entry.summary.distance_hint.saturating_add(1);
            let mut summary = entry.summary.clone();
            summary.distance_hint = new_distance;
            summaries.push(summary);
        }

        // Truncate to max.
        if summaries.len() > MAX_PEER_SUMMARIES_PER_MESSAGE {
            summaries.truncate(MAX_PEER_SUMMARIES_PER_MESSAGE);
        }

        summaries
    }

    /// Get all remote nodes (learned via propagation, not directly known).
    #[must_use]
    pub fn remote_nodes(&self) -> &HashMap<[u8; 32], RemoteNodeEntry> {
        &self.remote_nodes
    }

    /// Get remote nodes that advertise Gateway capability.
    #[must_use]
    pub fn remote_gateways(&self) -> Vec<&RemoteNodeEntry> {
        self.remote_nodes
            .values()
            .filter(|e| e.summary.is_gateway())
            .collect()
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

    /// Get all directly reachable gateways (CURRENT + Gateway + UP link + X25519).
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.directory.direct_gateways()
    }

    /// Get all directly reachable relays.
    #[must_use]
    pub fn reachable_relays(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.directory.reachable_relays()
    }

    /// Get all known gateways, including remote ones.
    /// Returns (NodeId, is_direct, distance_hint) tuples.
    #[must_use]
    pub fn all_known_gateways(&self) -> Vec<([u8; 32], bool, u8)> {
        let mut result = Vec::new();
        // Direct gateways.
        for record in self.direct_gateways() {
            result.push((record.descriptor.node_id(), true, 0));
        }
        // Remote gateways.
        for entry in self.remote_gateways() {
            result.push((entry.summary.node_id, false, entry.summary.distance_hint));
        }
        result
    }

    /// Check if a node is directly reachable (has at least one usable link).
    #[must_use]
    pub fn is_directly_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.directory.is_reachable(node_id)
    }

    /// Check if a node is known (either directly or remotely).
    #[must_use]
    pub fn is_known(&self, node_id: &[u8; 32]) -> bool {
        self.directory.get_record(node_id).is_some()
            || self.remote_nodes.contains_key(node_id)
    }

    /// Get the visibility state of a directly known peer.
    #[must_use]
    pub fn visibility(&self, node_id: &[u8; 32]) -> PeerVisibility {
        self.directory.visibility(node_id)
    }

    /// Get the current AuthenticatedNodeRecord for a directly known node.
    #[must_use]
    pub fn get_record(&self, node_id: &[u8; 32]) -> Option<&AuthenticatedNodeRecord> {
        self.directory.get_record(node_id)
    }

    /// Remove a peer entirely (including the sequence floor).
    /// Also removes all links and remote knowledge about this node.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if persistence fails.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Result<(), AcceptanceError> {
        self.remote_nodes.remove(node_id);
        self.directory.remove_peer(node_id)
    }

    /// Purge expired records and dead links.
    pub fn purge_expired(&mut self, now: u64) {
        self.directory.purge_expired(now);
        // Purge remote entries whose summaries indicate "stale" and are older
        // than the advertisement lifetime.
        let cutoff = now.saturating_sub(MAX_ADVERTISEMENT_LIFETIME_SECS);
        self.remote_nodes.retain(|_, entry| {
            entry.summary.visibility == "active" || entry.received_at > cutoff
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

    /// Produce an immutable snapshot of the topology for route computation.
    #[must_use]
    pub fn snapshot(&self) -> TopologySnapshot {
        TopologySnapshot::from_graph(self)
    }

    /// Get the total number of known nodes (direct + remote).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.directory.peer_count() + self.remote_nodes.len()
    }

    /// Get the number of links.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.directory.link_count()
    }
}

impl Default for TopologyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// An immutable point-in-time view of the topology, suitable for route
/// computation. The snapshot does NOT reflect subsequent mutations to
/// the live topology.
#[derive(Debug, Clone)]
pub struct TopologySnapshot {
    /// Direct nodes (NodeId → AuthenticatedNodeRecord).
    pub direct_nodes: HashMap<[u8; 32], AuthenticatedNodeRecord>,
    /// Direct links (LinkKey → Link).
    pub links: HashMap<LinkKey, Link>,
    /// Remote nodes (NodeId → RemoteNodeEntry).
    pub remote_nodes: HashMap<[u8; 32], RemoteNodeEntry>,
}

impl TopologySnapshot {
    /// Create a snapshot from a TopologyGraph.
    fn from_graph(graph: &TopologyGraph) -> Self {
        // Collect direct nodes.
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

        // Collect links.
        let mut links = HashMap::new();
        for link in graph.directory.link_table().all() {
            links.insert(link.key.clone(), link.clone());
        }

        // Collect remote nodes.
        let remote_nodes = graph.remote_nodes.clone();

        Self {
            direct_nodes,
            links,
            remote_nodes,
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

    /// Get all direct gateways in the snapshot.
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.direct_nodes
            .values()
            .filter(|r| r.descriptor.is_gateway())
            .filter(|r| r.descriptor.circuit_x25519_pub().is_some())
            .filter(|r| {
                // Must have at least one usable link.
                self.links
                    .values()
                    .any(|l| l.key.remote_node_id == r.descriptor.node_id() && l.is_usable())
            })
            .collect()
    }

    /// Get all remote gateways in the snapshot.
    #[must_use]
    pub fn remote_gateways(&self) -> Vec<&RemoteNodeEntry> {
        self.remote_nodes
            .values()
            .filter(|e| e.summary.is_gateway())
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

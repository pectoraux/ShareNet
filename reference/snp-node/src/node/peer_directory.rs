//! N2.1.1 — Peer Directory: wraps AdvertisementAcceptanceStore + link table.
//!
//! The `PeerDirectory` is the single source of truth for:
//! - Which nodes are known (via authenticated advertisements).
//! - Which nodes have current vs stale advertisements.
//! - Which nodes have working links (reachability).
//!
//! It does NOT duplicate advertisement validation logic — it delegates to
//! `AdvertisementAcceptanceStore` for ordering and replay prevention.

use super::*;
use crate::node::link::{Link, LinkKey, LinkState, LinkTable};

/// A directory of known peers, combining advertisement acceptance state
/// with link state.
///
/// ## Architecture
///
/// ```text
/// PeerDirectory
/// ├── AdvertisementAcceptanceStore (ordering authority — already exists)
/// └── LinkTable (new — tracks probed, authenticated transport relationships)
/// ```
///
/// The directory adds link tracking on top of the existing acceptance
/// ordering. It does NOT duplicate validation logic.
pub struct PeerDirectory {
    /// The acceptance store (ordering + replay prevention).
    acceptance: AdvertisementAcceptanceStore,
    /// The link table (directed, per-endpoint transport relationships).
    links: LinkTable,
}

impl PeerDirectory {
    /// Create a new in-memory PeerDirectory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            acceptance: AdvertisementAcceptanceStore::new(),
            links: LinkTable::new(),
        }
    }

    /// Create a persistent PeerDirectory backed by a file.
    ///
    /// # Errors
    /// Returns `AcceptanceError` if the persistence file is corrupted.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AcceptanceError> {
        Ok(Self {
            acceptance: AdvertisementAcceptanceStore::open(path)?,
            links: LinkTable::new(),
        })
    }

    /// Accept a verified advertisement.
    ///
    /// Delegates to `AdvertisementAcceptanceStore::accept()` for ordering
    /// and replay prevention.
    ///
    /// # Errors
    /// Returns `AcceptanceError::PersistenceFailed` if persistence fails.
    pub fn accept_advertisement(
        &mut self,
        verified: VerifiedNodeAdvertisement,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        self.acceptance.accept(verified)
    }

    /// Add a link to the directory.
    pub fn add_link(&mut self, link: Link) {
        self.links.insert(link);
    }

    /// Update a link's state.
    pub fn update_link_state(&mut self, key: &LinkKey, state: LinkState) {
        if let Some(link) = self.links.get_mut(key) {
            link.state = state;
        }
    }

    /// Remove a link.
    pub fn remove_link(&mut self, key: &LinkKey) {
        self.links.remove(key);
    }

    /// Record a successful transmission on a link.
    pub fn record_link_success(&mut self, key: &LinkKey, rtt_micros: u64) {
        if let Some(link) = self.links.get_mut(key) {
            link.record_success(rtt_micros);
        }
    }

    /// Record a failed transmission on a link.
    pub fn record_link_failure(&mut self, key: &LinkKey) {
        if let Some(link) = self.links.get_mut(key) {
            link.record_failure();
        }
    }

    /// Get the current `AuthenticatedNodeRecord` for a NodeId, if any
    /// (and if not expired).
    #[must_use]
    pub fn get_record(&self, node_id: &[u8; 32]) -> Option<&AuthenticatedNodeRecord> {
        self.acceptance.get(node_id)
    }

    /// Get the visibility state of a peer.
    #[must_use]
    pub fn visibility(&self, node_id: &[u8; 32]) -> PeerVisibility {
        self.acceptance.visibility(node_id)
    }

    /// Get the highest accepted sequence for a NodeId.
    #[must_use]
    pub fn highest_sequence(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.acceptance.highest_sequence(node_id)
    }

    /// Check if a node is reachable (has at least one usable outgoing link).
    #[must_use]
    pub fn is_reachable(&self, node_id: &[u8; 32]) -> bool {
        self.links.is_reachable(node_id)
    }

    /// Get all active nodes (CURRENT advertisement, not STALE).
    #[must_use]
    pub fn active_nodes(&self) -> Vec<&AuthenticatedNodeRecord> {
        // The acceptance store doesn't expose an iterator directly,
        // but we can query via known node_ids from the link table
        // and any records we've accepted.
        // For now, we collect from the acceptance store's get() for
        // all node_ids we know about (from links + records).
        // This is a simplification — a production implementation would
        // add an iterator to AdvertisementAcceptanceStore.
        self.links
            .all()
            .map(|l| l.key.remote_node_id)
            .chain(self.links.all().map(|l| l.key.local_node_id))
            .filter_map(|node_id| self.acceptance.get(&node_id))
            .collect()
    }

    /// Get all nodes that are directly reachable (have at least one UP link).
    #[must_use]
    pub fn reachable_node_ids(&self) -> Vec<[u8; 32]> {
        self.links
            .all()
            .filter(|l| l.is_usable())
            .map(|l| l.key.remote_node_id)
            .collect()
    }

    /// Get all directly reachable nodes that advertise Gateway capability.
    /// These are nodes with:
    /// 1. A CURRENT advertisement (not STALE).
    /// 2. `Capability::Gateway` in their capabilities.
    /// 3. At least one usable (UP/Degraded) outgoing link.
    /// 4. An X25519 circuit public key.
    #[must_use]
    pub fn direct_gateways(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.reachable_node_ids()
            .into_iter()
            .filter_map(|node_id| self.acceptance.get(&node_id))
            .filter(|record| record.descriptor.is_gateway())
            .filter(|record| record.descriptor.circuit_x25519_pub().is_some())
            .collect()
    }

    /// Get all directly reachable nodes that advertise Relay capability.
    #[must_use]
    pub fn reachable_relays(&self) -> Vec<&AuthenticatedNodeRecord> {
        self.reachable_node_ids()
            .into_iter()
            .filter_map(|node_id| self.acceptance.get(&node_id))
            .filter(|record| record.descriptor.is_relay())
            .collect()
    }

    /// Get all outgoing links from a node.
    #[must_use]
    pub fn links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links.links_from(node_id)
    }

    /// Get all usable outgoing links from a node.
    #[must_use]
    pub fn usable_links_from(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links.usable_links_from(node_id)
    }

    /// Get all incoming links to a node.
    #[must_use]
    pub fn links_to(&self, node_id: &[u8; 32]) -> Vec<&Link> {
        self.links.links_to(node_id)
    }

    /// Remove a peer entirely (including the sequence floor).
    /// This is the ONLY way to erase identity history.
    ///
    /// # Errors
    /// Returns `AcceptanceError::PersistenceFailed` if persistence fails.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Result<(), AcceptanceError> {
        // Remove all links to/from this peer.
        let keys_to_remove: Vec<LinkKey> = self
            .links
            .all()
            .filter(|l| l.key.local_node_id == *node_id || l.key.remote_node_id == *node_id)
            .map(|l| l.key.clone())
            .collect();
        for key in keys_to_remove {
            self.links.remove(&key);
        }
        // Remove the peer from the acceptance store (transactional).
        self.acceptance.remove_peer(node_id)
    }

    /// Purge expired records (CURRENT → STALE) and dead links.
    pub fn purge_expired(&mut self, now: u64) {
        self.acceptance.purge_expired_records(now);
        // Purge links that have been Down for > 5 minutes.
        self.links.purge_dead_links(now, 300);
    }

    /// Get the acceptance store (for direct access if needed).
    #[must_use]
    pub fn acceptance_store(&self) -> &AdvertisementAcceptanceStore {
        &self.acceptance
    }

    /// Get the link table (for direct access if needed).
    #[must_use]
    pub fn link_table(&self) -> &LinkTable {
        &self.links
    }

    /// Get the number of known peers (including stale ones).
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.acceptance.len()
    }

    /// Get the number of links.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Restart from persistence (loads acceptance state from file).
    ///
    /// # Errors
    /// Returns `AcceptanceError` if the file is corrupted.
    pub fn restart(&self) -> Result<Self, AcceptanceError> {
        Ok(Self {
            acceptance: self.acceptance.restart()?,
            links: LinkTable::new(), // Links are ephemeral — rebuilt from discovery.
        })
    }

    /// Generate PeerSummaries for all active nodes at a given distance.
    /// Used for topology propagation.
    #[must_use]
    pub fn peer_summaries(&self, distance_hint: u8) -> Vec<PeerSummary> {
        let now = now_unix();
        self.active_nodes()
            .into_iter()
            .map(|record| {
                PeerSummary::from_record(record, distance_hint, now)
            })
            .collect()
    }
}

impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

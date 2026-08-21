//! Peer Lifecycle Automation (R4.9.3).
//!
//! Provides periodic liveness maintenance, stale-peer detection,
//! quarantine, and recovery after successful revalidation.
//!
//! # Architecture
//!
//! ```text
//! AdvertisementAcceptanceStore (authoritative peer state — preserved)
//!     ↑
//!     | delegates
//!     |
//! PeerLifecycleManager (operational lifecycle — additive)
//!     |
//!     +-- maintain(now): purge expired → STALE
//!     +-- quarantine(node_id, reason): operational exclusion
//!     +-- accept_advertisement(verified): refresh liveness + revoke check
//!     +-- is_eligible_for_forwarding(node_id): selection boundary
//!     +-- revoke_peer(node_id): durable revocation via RevocationStore
//! ```

use std::collections::HashSet;

use snp_identity::{NodeId, RevocationStore};

use crate::node::node_advert::{
    AcceptanceError, AcceptanceResult, AdvertisementAcceptanceStore, VerifiedNodeAdvertisement,
};

/// The operational state of a peer. **R4.9.3.**
///
/// This is distinct from `PeerVisibility` (which tracks advertisement
/// validity). `PeerOperationalState` tracks whether the peer is
/// **usable** for new forwarding/routing decisions.
///
/// - **`Active`** — peer is known, has a valid advertisement, and is
///   not quarantined or revoked.
/// - **`Stale`** — peer's advertisement has expired. The sequence floor
///   persists. Not eligible for new forwarding.
/// - **`Quarantined`** — peer has been operationally excluded due to a
///   concrete failure. Not eligible for new forwarding. Can recover
///   after successful revalidation.
/// - **`Revoked`** — peer is in the `RevocationStore`. Permanently
///   excluded. Cannot recover.
/// - **`Unknown`** — peer has never been seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOperationalState {
    /// Peer is known, valid, and not excluded.
    Active,
    /// Peer's advertisement has expired.
    Stale,
    /// Peer is operationally excluded due to failure.
    Quarantined,
    /// Peer is permanently revoked.
    Revoked,
    /// Peer has never been seen.
    Unknown,
}

/// A peer lifecycle manager. **R4.9.3.**
///
/// Wraps the existing `AdvertisementAcceptanceStore` (authoritative peer
/// state) and adds operational lifecycle: periodic expiry maintenance,
/// quarantine, and eligibility checks.
///
/// # Quarantine
///
/// Quarantine is **in-memory only** — it does not survive restart.
/// This is intentional: quarantine is an operational exclusion, not a
/// cryptographic revocation. On restart, a quarantined peer is
/// re-evaluated from its durable advertisement state. If the advertisement
/// is still valid, the peer is ACTIVE. If expired, it is STALE.
///
/// # Revocation
///
/// Revocation is **durable** — delegated to `RevocationStore`.
/// Revocation survives restart and cannot be bypassed by advertisement
/// refresh.
pub struct PeerLifecycleManager {
    /// The authoritative advertisement acceptance store (NOT owned —
    /// the manager borrows it).
    store: AdvertisementAcceptanceStore,
    /// The set of quarantined NodeIds (in-memory, not persisted).
    quarantined: HashSet<NodeId>,
    /// The revocation store (durable, fail-closed).
    revocation: RevocationStore,
}

impl PeerLifecycleManager {
    /// Create a new `PeerLifecycleManager` with the given acceptance store
    /// and revocation store.
    #[must_use]
    pub fn new(store: AdvertisementAcceptanceStore, revocation: RevocationStore) -> Self {
        Self {
            store,
            quarantined: HashSet::new(),
            revocation,
        }
    }

    /// Accept a verified advertisement. This is the trust/refresh path:
    ///
    /// 1. Check revocation — revoked peers cannot recover.
    /// 2. Accept into the authoritative store (sequence check + persist).
    /// 3. Clear quarantine (if present) — successful revalidation.
    ///
    /// # Errors
    /// - `AcceptanceError::PersistenceFailed` if the store cannot persist.
    pub fn accept_advertisement(
        &mut self,
        verified: VerifiedNodeAdvertisement,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        let node_id = verified.node_id();
        // R4.9.2: Revoked peers cannot recover through advertisement refresh.
        if self.revocation.is_revoked(&node_id) {
            return Err(AcceptanceError::CorruptPersistence(format!(
                "peer {node_id:?} is revoked — advertisement rejected"
            )));
        }
        // Accept into the authoritative store.
        let result = self.store.accept(verified)?;
        // Successful revalidation → clear quarantine.
        if self.quarantined.remove(&node_id) {
            tracing::info!(
                peer_id = ?node_id,
                "peer recovered from quarantine after successful revalidation"
            );
        }
        Ok(result)
    }

    /// Run periodic maintenance: purge expired advertisements (ACTIVE → STALE).
    ///
    /// Does NOT remove peers or reset sequence floors.
    pub fn maintain(&mut self, now: u64) {
        self.store.purge_expired_records(now);
    }

    /// Quarantine a peer due to a concrete operational failure.
    ///
    /// The peer is excluded from new forwarding but its identity history
    /// and sequence floor are preserved. The peer can recover after
    /// successful revalidation (via `accept_advertisement`).
    pub fn quarantine(&mut self, node_id: &NodeId, reason: &str) {
        if self.quarantined.insert(*node_id) {
            tracing::warn!(
                peer_id = ?node_id,
                reason = reason,
                "peer quarantined"
            );
        }
    }

    /// Revoke a peer durably via the `RevocationStore`.
    ///
    /// # Errors
    /// - `IdentityLifecycleError` if persistence fails.
    pub fn revoke_peer(&mut self, node_id: &NodeId) -> Result<(), snp_identity::IdentityLifecycleError> {
        self.revocation.revoke(*node_id)
    }

    /// Get the operational state of a peer.
    #[must_use]
    pub fn operational_state(&self, node_id: &NodeId) -> PeerOperationalState {
        // Revocation takes priority.
        if self.revocation.is_revoked(node_id) {
            return PeerOperationalState::Revoked;
        }
        // Quarantine.
        if self.quarantined.contains(node_id) {
            return PeerOperationalState::Quarantined;
        }
        // Check advertisement store.
        match self.store.get(node_id) {
            Some(_) => PeerOperationalState::Active,
            None => {
                // Check if we know the peer at all (sequence floor).
                if self.store.highest_sequence(node_id).is_some() {
                    PeerOperationalState::Stale
                } else {
                    PeerOperationalState::Unknown
                }
            }
        }
    }

    /// Returns `true` if the peer is eligible for new forwarding/routing.
    ///
    /// Only `Active` peers are eligible. `Stale`, `Quarantined`, `Revoked`,
    /// and `Unknown` peers are NOT eligible.
    #[must_use]
    pub fn is_eligible_for_forwarding(&self, node_id: &NodeId) -> bool {
        self.operational_state(node_id) == PeerOperationalState::Active
    }

    /// Get the highest accepted sequence for a peer (delegates to the
    /// acceptance store). This survives expiry and quarantine.
    #[must_use]
    pub fn highest_sequence(&self, node_id: &NodeId) -> Option<u64> {
        self.store.highest_sequence(node_id)
    }

    /// Get a reference to the underlying acceptance store.
    #[must_use]
    pub fn store(&self) -> &AdvertisementAcceptanceStore {
        &self.store
    }

    /// Get a reference to the revocation store.
    #[must_use]
    pub fn revocation_store(&self) -> &RevocationStore {
        &self.revocation
    }

    /// Get the number of quarantined peers.
    #[must_use]
    pub fn quarantined_count(&self) -> usize {
        self.quarantined.len()
    }

    /// Check if a peer is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, node_id: &NodeId) -> bool {
        self.quarantined.contains(node_id)
    }
}

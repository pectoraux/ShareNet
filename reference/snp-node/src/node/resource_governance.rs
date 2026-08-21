//! Resource Governance (R4.9.5).
//!
//! Operational resource governance that prevents a single peer, request
//! stream, or workload from exhausting the node's finite runtime resources
//! while preserving the existing protocol semantics and R4.9.1–R4.9.4
//! behavior.
//!
//! # Architectural boundary
//!
//! Resource governance is an **operational layer** around the existing
//! protocol. It does NOT alter `Bundle`/`Route`/`custody` semantics, does NOT
//! select routes, and does NOT rank peers. It enforces:
//!
//! ```text
//! finite local resources
//!     |
//!     +--> global connection ceiling
//!     +--> per-peer connection ceiling
//!     +--> global concurrency cap (composed with existing gateway egress)
//!     +--> per-peer concurrency cap
//!     +--> bounded in-flight work (no unbounded JoinSet growth)
//! ```
//!
//! # State lifetime
//!
//! All counters and semaphores are **ephemeral** (in-memory). They are NOT
//! persisted — on restart, all runtime capacity starts fresh. Durable
//! protocol state (R4.6 custody, R4.9.1–R4.9.3 identity/revocation/lifecycle)
//! remains authoritative. This mirrors the R4.9.3 quarantine and R4.9.4
//! retry-state design (operational state is not persisted unless it is
//! protocol truth).
//!
//! # Release guarantees
//!
//! Every admission is represented by an RAII guard (`ConnectionGuard`,
//! `OperationGuard`) that releases the resource on `Drop` — covering success,
//! error, panic, cancellation (task drop), and shutdown. No explicit release
//! call is required; a guard that goes out of scope releases its resource.
//!
//! # Interaction with R4.9.3 / R4.9.4
//!
//! A resource-limit rejection is a **local admission decision**, NOT a peer
//! failure. It does NOT increment `RetryScheduler::failure_count`, does NOT
//! quarantine the peer, and does NOT alter peer trust state. The rejected
//! connection is dropped; the previous hop retains the bundle durably and
//! re-sends on its existing retry schedule (invariant #24 preserved).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use snp_identity::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// R4.9.5: Default global ceiling on simultaneously-active authenticated
/// peer connections per listener. Protects against connection flood — a peer
/// (or set of peers) cannot open unlimited connections that each hold a
/// carrier + handshake state in memory. Exceeded → the new connection is
/// dropped (the peer re-tries via its existing schedule).
pub const DEFAULT_MAX_GLOBAL_CONNECTIONS: usize = 64;

/// R4.9.5: Default per-peer ceiling on simultaneously-active authenticated
/// connections. Protects against one peer monopolising the global connection
/// budget. Exceeded → the new connection is dropped (the peer's existing
/// connections continue).
pub const DEFAULT_MAX_PEER_CONNECTIONS: usize = 4;

/// R4.9.5: Default per-peer cap on concurrent governed operations (gateway
/// egress tasks / forwarding cycles). Protects against one peer occupying
/// all global capacity. Must be `< MAX_CONCURRENT_EGRESS` so that a single
/// peer cannot consume the entire global egress pool.
pub const DEFAULT_MAX_PEER_CONCURRENT_OPS: usize = 2;

/// R4.9.5: Default global cap on concurrently-active governed operations
/// (independent of the existing R4.8 `MAX_CONCURRENT_EGRESS = 8` egress
/// semaphore). This bounds the total in-flight work the node admits — it is
/// the admission gate; the R4.8 semaphore bounds the expensive egress
/// itself. Set equal to the egress cap so admission does not reduce the
/// existing egress throughput.
pub const DEFAULT_MAX_GLOBAL_CONCURRENT_OPS: usize = 8;

/// Admission decision for a governed resource.
#[derive(Debug)]
pub enum AdmissionError {
    /// The global connection ceiling would be exceeded.
    GlobalConnectionLimit {
        /// The configured ceiling.
        limit: usize,
        /// The current count (at rejection time).
        current: usize,
    },
    /// The per-peer connection ceiling would be exceeded.
    PeerConnectionLimit {
        /// The peer whose limit was reached.
        peer_id: NodeId,
        /// The configured per-peer ceiling.
        limit: usize,
        /// The peer's current connection count.
        current: usize,
    },
    /// The global operation ceiling would be exceeded.
    GlobalOperationLimit {
        /// The configured ceiling.
        limit: usize,
        /// The current in-flight count (at rejection time).
        current: usize,
    },
    /// The per-peer operation ceiling would be exceeded.
    PeerOperationLimit {
        /// The peer whose limit was reached.
        peer_id: NodeId,
        /// The configured per-peer ceiling.
        limit: usize,
        /// The peer's current in-flight count.
        current: usize,
    },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GlobalConnectionLimit { limit, current } => {
                write!(f, "global connection limit reached ({current}/{limit})")
            }
            Self::PeerConnectionLimit {
                peer_id,
                limit,
                current,
            } => write!(
                f,
                "per-peer connection limit reached for peer {:?} ({current}/{limit})",
                peer_id
            ),
            Self::GlobalOperationLimit { limit, current } => {
                write!(f, "global operation limit reached ({current}/{limit})")
            }
            Self::PeerOperationLimit {
                peer_id,
                limit,
                current,
            } => write!(
                f,
                "per-peer operation limit reached for peer {:?} ({current}/{limit})",
                peer_id
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Configuration for a `ResourceGovernor`.
#[derive(Debug, Clone, Copy)]
pub struct GovernorConfig {
    /// Global ceiling on simultaneously-active authenticated peer connections.
    pub max_global_connections: usize,
    /// Per-peer ceiling on simultaneously-active authenticated connections.
    pub max_peer_connections: usize,
    /// Global cap on concurrently-active governed operations.
    pub max_global_concurrent_ops: usize,
    /// Per-peer cap on concurrently-active governed operations.
    pub max_peer_concurrent_ops: usize,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            max_global_connections: DEFAULT_MAX_GLOBAL_CONNECTIONS,
            max_peer_connections: DEFAULT_MAX_PEER_CONNECTIONS,
            max_global_concurrent_ops: DEFAULT_MAX_GLOBAL_CONCURRENT_OPS,
            max_peer_concurrent_ops: DEFAULT_MAX_PEER_CONCURRENT_OPS,
        }
    }
}

/// Per-peer accounting state (held under the governor's lock).
#[derive(Debug, Default, Clone, Copy)]
struct PeerAccount {
    /// Active authenticated connections for this peer.
    connections: u32,
    /// In-flight governed operations for this peer.
    operations: u32,
}

/// Internal mutable state of a `ResourceGovernor`.
#[derive(Default)]
struct GovernorState {
    /// Total active authenticated connections across all peers.
    global_connections: u32,
    /// Total in-flight governed operations across all peers.
    global_operations: u32,
    /// Per-peer accounting.
    peers: HashMap<NodeId, PeerAccount>,
}

/// RAII guard for an admitted connection. Releases the global + per-peer
/// connection counters on `Drop`.
pub struct ConnectionGuard {
    peer: NodeId,
    state: Arc<Mutex<GovernorState>>,
}

impl std::fmt::Debug for ConnectionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionGuard")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Release on every exit path: success, error, panic, cancellation
        // (task drop), shutdown. Synchronous + non-async — safe to call in
        // a destructor. `std::sync::Mutex` is used (not `tokio::sync::Mutex`)
        // so Drop is fully sync and never panics under a single-threaded
        // runtime. The critical section is trivial (no await).
        let mut s = self.state.lock().expect("governor state poisoned");
        s.global_connections = s.global_connections.saturating_sub(1);
        if let Some(acct) = s.peers.get_mut(&self.peer) {
            acct.connections = acct.connections.saturating_sub(1);
            if acct.connections == 0 && acct.operations == 0 {
                s.peers.remove(&self.peer);
            }
        }
    }
}

/// RAII guard for an admitted governed operation. Releases the global +
/// per-peer operation counters on `Drop`.
pub struct OperationGuard {
    peer: NodeId,
    state: Arc<Mutex<GovernorState>>,
}

impl std::fmt::Debug for OperationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationGuard")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut s = self.state.lock().expect("governor state poisoned");
        s.global_operations = s.global_operations.saturating_sub(1);
        if let Some(acct) = s.peers.get_mut(&self.peer) {
            acct.operations = acct.operations.saturating_sub(1);
            if acct.connections == 0 && acct.operations == 0 {
                s.peers.remove(&self.peer);
            }
        }
    }
}

/// Resource governor enforcing global + per-peer connection and concurrency
/// limits. Ephemeral — all state is in-memory and resets on restart.
///
/// Cloning a governor shares the underlying counters (cheap `Arc` clone).
/// A governor is intended to be created once per node (or per listener) and
/// cloned into spawned tasks.
#[derive(Clone)]
pub struct ResourceGovernor {
    config: GovernorConfig,
    state: Arc<Mutex<GovernorState>>,
}

impl ResourceGovernor {
    /// Create a governor with the default conservative configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(GovernorConfig::default())
    }

    /// Create a governor with an explicit configuration (for tests / tuned
    /// deployments).
    #[must_use]
    pub fn with_config(config: GovernorConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(GovernorState::default())),
        }
    }

    /// The configured limits (read-only, for diagnostics / tests).
    #[must_use]
    pub fn config(&self) -> GovernorConfig {
        self.config
    }

    /// Admit a new authenticated peer connection. On success returns a guard
    /// that releases the counters on drop. On failure returns the reason —
    /// the caller MUST drop the connection without taking custody.
    ///
    /// # Errors
    /// - [`AdmissionError::GlobalConnectionLimit`] if the global ceiling is
    ///   reached.
    /// - [`AdmissionError::PeerConnectionLimit`] if the peer's ceiling is
    ///   reached.
    pub async fn admit_connection(&self, peer: NodeId) -> Result<ConnectionGuard, AdmissionError> {
        let mut s = self.state.lock().expect("governor state poisoned");
        let current_global = s.global_connections;
        if current_global >= u32::try_from(self.config.max_global_connections).unwrap_or(u32::MAX) {
            tracing::warn!(
                peer_id = ?peer,
                resource = "global_connections",
                limit = self.config.max_global_connections,
                current = current_global,
                "resource admission rejected — global connection limit reached"
            );
            return Err(AdmissionError::GlobalConnectionLimit {
                limit: self.config.max_global_connections,
                current: current_global as usize,
            });
        }
        let acct = s.peers.entry(peer).or_default();
        let peer_current = acct.connections;
        if peer_current >= u32::try_from(self.config.max_peer_connections).unwrap_or(u32::MAX) {
            tracing::warn!(
                peer_id = ?peer,
                resource = "peer_connections",
                limit = self.config.max_peer_connections,
                current = peer_current,
                "resource admission rejected — per-peer connection limit reached"
            );
            return Err(AdmissionError::PeerConnectionLimit {
                peer_id: peer,
                limit: self.config.max_peer_connections,
                current: peer_current as usize,
            });
        }
        acct.connections += 1;
        s.global_connections += 1;
        tracing::debug!(
            peer_id = ?peer,
            resource = "connection",
            "resource admission accepted"
        );
        Ok(ConnectionGuard {
            peer,
            state: self.state.clone(),
        })
    }

    /// Admit a governed operation for a peer. On success returns a guard that
    /// releases the counters on drop. On failure returns the reason — the
    /// caller MUST NOT perform the expensive operation.
    ///
    /// # Errors
    /// - [`AdmissionError::GlobalOperationLimit`] if the global operation
    ///   ceiling is reached.
    /// - [`AdmissionError::PeerOperationLimit`] if the peer's operation
    ///   ceiling is reached.
    pub async fn admit_operation(&self, peer: NodeId) -> Result<OperationGuard, AdmissionError> {
        let mut s = self.state.lock().expect("governor state poisoned");
        let current_global = s.global_operations;
        if current_global
            >= u32::try_from(self.config.max_global_concurrent_ops).unwrap_or(u32::MAX)
        {
            tracing::warn!(
                peer_id = ?peer,
                resource = "global_operations",
                limit = self.config.max_global_concurrent_ops,
                current = current_global,
                "resource admission rejected — global operation limit reached"
            );
            return Err(AdmissionError::GlobalOperationLimit {
                limit: self.config.max_global_concurrent_ops,
                current: current_global as usize,
            });
        }
        let acct = s.peers.entry(peer).or_default();
        let peer_current = acct.operations;
        if peer_current >= u32::try_from(self.config.max_peer_concurrent_ops).unwrap_or(u32::MAX) {
            tracing::warn!(
                peer_id = ?peer,
                resource = "peer_operations",
                limit = self.config.max_peer_concurrent_ops,
                current = peer_current,
                "resource admission rejected — per-peer operation limit reached"
            );
            return Err(AdmissionError::PeerOperationLimit {
                peer_id: peer,
                limit: self.config.max_peer_concurrent_ops,
                current: peer_current as usize,
            });
        }
        acct.operations += 1;
        s.global_operations += 1;
        tracing::debug!(
            peer_id = ?peer,
            resource = "operation",
            "resource admission accepted"
        );
        Ok(OperationGuard {
            peer,
            state: self.state.clone(),
        })
    }

    /// Snapshot the current global connection count (for tests / diagnostics).
    #[must_use]
    pub async fn global_connections(&self) -> u32 {
        self.state
            .lock()
            .expect("governor state poisoned")
            .global_connections
    }

    /// Snapshot the current global operation count (for tests / diagnostics).
    #[must_use]
    pub async fn global_operations(&self) -> u32 {
        self.state
            .lock()
            .expect("governor state poisoned")
            .global_operations
    }

    /// Snapshot a peer's current connection count (for tests / diagnostics).
    #[must_use]
    pub async fn peer_connections(&self, peer: &NodeId) -> u32 {
        self.state
            .lock()
            .expect("governor state poisoned")
            .peers
            .get(peer)
            .map_or(0, |a| a.connections)
    }

    /// Snapshot a peer's current operation count (for tests / diagnostics).
    #[must_use]
    pub async fn peer_operations(&self, peer: &NodeId) -> u32 {
        self.state
            .lock()
            .expect("governor state poisoned")
            .peers
            .get(peer)
            .map_or(0, |a| a.operations)
    }
}

impl Default for ResourceGovernor {
    fn default() -> Self {
        Self::new()
    }
}

/// R4.9.5: A per-peer gateway quota composed with the existing R4.8
/// `MAX_CONCURRENT_EGRESS` semaphore.
///
/// The admission order is:
/// 1. per-peer permit (bounds one peer to `max_peer_concurrent_ops`)
/// 2. global egress permit (the existing R4.8 8-permit semaphore)
///
/// Both are RAII — dropped on every exit path. The global cap is NOT
/// increased; the per-peer cap is layered on top so one peer cannot
/// monopolise the global pool.
pub struct GatewayQuota {
    per_peer: Arc<Semaphore>,
    global: Arc<Semaphore>,
    max_peer: usize,
}

impl GatewayQuota {
    /// Create a gateway quota composing a per-peer semaphore (`max_peer`
    /// permits) with the existing global egress semaphore (`global`).
    #[must_use]
    pub fn new(max_peer: usize, global: Arc<Semaphore>) -> Self {
        assert!(max_peer > 0, "per-peer gateway quota must be > 0");
        Self {
            per_peer: Arc::new(Semaphore::new(max_peer)),
            global,
            max_peer,
        }
    }

    /// The configured per-peer cap.
    #[must_use]
    pub fn max_peer(&self) -> usize {
        self.max_peer
    }

    /// Acquire a per-peer permit (does NOT touch the global semaphore).
    /// Used to bound the number of concurrent in-flight tasks a single peer
    /// may have admitted, BEFORE the global egress permit is sought.
    ///
    /// # Errors
    /// Returns the semaphore error if the per-peer semaphore is closed.
    pub async fn acquire_peer_permit(
        &self,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        self.per_peer.clone().acquire_owned().await
    }

    /// Clone the global egress semaphore handle (the caller acquires a
    /// permit from it separately, preserving the R4.8 deadline-aware
    /// acquisition path).
    #[must_use]
    pub fn global_semaphore(&self) -> Arc<Semaphore> {
        self.global.clone()
    }

    /// The number of available per-peer permits right now (for tests).
    #[must_use]
    pub fn available_peer_permits(&self) -> usize {
        self.per_peer.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: u8) -> NodeId {
        [id; 32]
    }

    #[tokio::test]
    async fn global_connection_limit_rejects() {
        let gov = ResourceGovernor::with_config(GovernorConfig {
            max_global_connections: 2,
            max_peer_connections: 4,
            max_global_concurrent_ops: 8,
            max_peer_concurrent_ops: 2,
        });
        let p = peer(1);
        let _g1 = gov.admit_connection(p).await.unwrap();
        let _g2 = gov.admit_connection(p).await.unwrap();
        let r = gov.admit_connection(p).await;
        assert!(matches!(
            r,
            Err(AdmissionError::GlobalConnectionLimit { .. })
        ));
    }

    #[tokio::test]
    async fn per_peer_connection_limit_rejects() {
        let gov = ResourceGovernor::with_config(GovernorConfig {
            max_global_connections: 64,
            max_peer_connections: 2,
            max_global_concurrent_ops: 8,
            max_peer_concurrent_ops: 2,
        });
        let p = peer(1);
        let _g1 = gov.admit_connection(p).await.unwrap();
        let _g2 = gov.admit_connection(p).await.unwrap();
        let r = gov.admit_connection(p).await;
        assert!(matches!(r, Err(AdmissionError::PeerConnectionLimit { .. })));
        // A different peer can still connect.
        let q = peer(2);
        let _g3 = gov.admit_connection(q).await.unwrap();
    }

    #[tokio::test]
    async fn connection_guard_releases_on_drop() {
        let gov = ResourceGovernor::with_config(GovernorConfig {
            max_global_connections: 1,
            max_peer_connections: 1,
            max_global_concurrent_ops: 8,
            max_peer_concurrent_ops: 2,
        });
        let p = peer(1);
        {
            let _g = gov.admit_connection(p).await.unwrap();
            assert_eq!(gov.global_connections().await, 1);
        }
        assert_eq!(
            gov.global_connections().await,
            0,
            "guard must release on drop"
        );
        // Re-admit succeeds after release.
        let _g2 = gov.admit_connection(p).await.unwrap();
    }

    #[tokio::test]
    async fn operation_guard_releases_on_drop() {
        let gov = ResourceGovernor::with_config(GovernorConfig {
            max_global_connections: 64,
            max_peer_connections: 4,
            max_global_concurrent_ops: 1,
            max_peer_concurrent_ops: 1,
        });
        let p = peer(1);
        {
            let _g = gov.admit_operation(p).await.unwrap();
            assert_eq!(gov.global_operations().await, 1);
        }
        assert_eq!(gov.global_operations().await, 0);
        let _g2 = gov.admit_operation(p).await.unwrap();
    }
}

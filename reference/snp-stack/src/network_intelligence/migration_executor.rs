//! **N2.5-R.2 — Migration Executor.**
//!
//! Connects the [`AdaptiveRouteOptimizer`] to real ShareNet circuit
//! establishment. The executor performs the full migration transaction:
//!
//! ```text
//! 1. optimizer.check() → MigrationDecision
//! 2. establish candidate circuit (real SNP-IK handshake)
//! 3. on success: construct EstablishedRoute from establishment result
//! 4. commit_migration_with_evidence(decision, evidence)
//! 5. on failure: invalidate decision, record failure, preserve old route
//! ```
//!
//! ## Atomic migration semantics
//!
//! The active route remains unchanged until the new route has passed
//! establishment AND the commit has succeeded. If establishment fails,
//! the old route remains active and no cooldown is started.

#![cfg(feature = "circuit-upstream")]

use super::observations::PeerId;
use super::route_observation::{RouteObservationStore, route_id_from_hops};
use super::route_optimizer::{
    AdaptiveRouteOptimizer, EstablishedRoute, MigrationDecision, OptimizationResult,
};
use super::feedback::{CircuitFailureReason, CircuitOutcome, CircuitResult};

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{Node, Route};
use std::sync::Arc;
use std::time::Duration;

/// The result of a migration attempt.
#[derive(Debug)]
pub enum MigrationOutcome {
    /// The migration succeeded — the new route is now active.
    Success {
        /// The established circuit (can be used for streams).
        circuit: MultiplexedCircuit,
        /// The evidence proving establishment.
        evidence: EstablishedRoute,
    },
    /// The migration failed — the old route remains active.
    Failed {
        /// Why the migration failed.
        reason: MigrationFailureReason,
    },
    /// No migration was needed (optimizer returned NoMigration).
    NotNeeded,
    /// The optimizer is on cooldown.
    Cooldown {
        /// Time remaining.
        remaining: Duration,
    },
    /// No routes are available.
    NoRoutes,
}

/// Why a migration attempt failed.
#[derive(Debug, Clone)]
pub enum MigrationFailureReason {
    /// Circuit establishment failed (relay unreachable, handshake failed, etc.).
    EstablishmentFailed(String),
    /// The established circuit's route_id didn't match the decision.
    RouteIdMismatch,
    /// The decision was stale (replaced by a newer check()).
    StaleDecision,
    /// The commit was rejected by the optimizer.
    CommitRejected(String),
}

/// The migration executor.
///
/// Connects the [`AdaptiveRouteOptimizer`] to real circuit establishment.
/// The executor is the ONLY production path for route migration.
///
/// ## Authoritative active-route owner
///
/// The optimizer's `current_route` is the authoritative active-route state.
/// The executor does NOT maintain a separate current-route cache.
pub struct MigrationExecutor {
    /// The optimizer (authoritative active-route owner).
    optimizer: AdaptiveRouteOptimizer,
    /// The route observation store (shared with optimizer).
    route_observations: Arc<std::sync::RwLock<RouteObservationStore>>,
}

impl MigrationExecutor {
    /// Create a new migration executor.
    #[must_use]
    pub fn new(
        optimizer: AdaptiveRouteOptimizer,
        route_observations: Arc<std::sync::RwLock<RouteObservationStore>>,
    ) -> Self {
        Self {
            optimizer,
            route_observations,
        }
    }

    /// Attempt a route migration.
    ///
    /// This is the full migration transaction:
    ///
    /// 1. `optimizer.check()` — get a migration decision.
    /// 2. If `Migrate`: establish the candidate circuit via real SNP-IK.
    /// 3. On success: construct `EstablishedRoute` evidence.
    /// 4. `commit_migration_with_evidence()` — validate + commit.
    /// 5. On failure: record failure, preserve old route, no cooldown.
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (hop sequences).
    /// * `node` — The client node (identity + keys).
    /// * `routes` — Map from hop sequence to `Route` object (for establishment).
    /// * `client_x25519_secret` — The client's X25519 secret.
    /// * `client_x25519_public` — The client's X25519 public key.
    pub async fn attempt_migration(
        &mut self,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
    ) -> MigrationOutcome {
        // 1. Check if migration is recommended.
        let decision = match self.optimizer.check(candidates) {
            OptimizationResult::Migrate(d) => d,
            OptimizationResult::NoMigration { .. } => return MigrationOutcome::NotNeeded,
            OptimizationResult::NoRoutes => return MigrationOutcome::NoRoutes,
            OptimizationResult::Cooldown { remaining } => {
                return MigrationOutcome::Cooldown { remaining };
            }
        };

        let target_hops = decision.target_route().to_vec();
        let to_route_id = route_id_from_hops(&target_hops);

        // 2. Find the Route object for the target hops.
        let route = match routes.iter().find(|(hops, _)| hops.as_slice() == target_hops.as_slice())
        {
            Some((_, route)) => route.clone(),
            None => {
                return MigrationOutcome::Failed {
                    reason: MigrationFailureReason::EstablishmentFailed(
                        "target route not found in routes map".into(),
                    ),
                };
            }
        };

        // 3. Attempt real circuit establishment.
        let circuit = match MultiplexedCircuit::establish(
            node,
            &route,
            client_x25519_secret,
            client_x25519_public,
        )
        .await
        {
            Ok(circuit) => circuit,
            Err(e) => {
                // Establishment failed. Record failure in route observations.
                // Do NOT start cooldown. Do NOT change current route.
                let failure_reason = format!("{:?}", e);
                self.record_route_failure(&target_hops, &failure_reason);
                return MigrationOutcome::Failed {
                    reason: MigrationFailureReason::EstablishmentFailed(failure_reason),
                };
            }
        };

        // 4. Construct EstablishedRoute evidence from the establishment result.
        // The circuit's fid is the circuit_id. The route hops are the target_hops.
        // The gateway_node_id and client_node_id come from the route/circuit.
        let gateway_node_id = route.destination();
        let client_node_id = node.identity.node_id;
        let fid = circuit.circuit_fid();

        let evidence = EstablishedRoute::from_establishment(
            target_hops.clone(),
            fid,
            gateway_node_id,
            client_node_id,
        );

        // 5. Verify evidence route_id matches decision.
        if evidence.route_id() != to_route_id {
            // This should never happen if the code is correct, but we check
            // defensively.
            self.record_route_failure(&target_hops, "route_id mismatch after establishment");
            return MigrationOutcome::Failed {
                reason: MigrationFailureReason::RouteIdMismatch,
            };
        }

        // 6. Commit the migration with evidence.
        match self
            .optimizer
            .commit_migration_with_evidence(decision, &evidence)
        {
            Ok(()) => {
                // Success! Record success in route observations.
                self.record_route_success(&target_hops);
                MigrationOutcome::Success { circuit, evidence }
            }
            Err(e) => {
                // Commit rejected — stale decision, wrong epoch, etc.
                // The old route remains active (commit_migration didn't change state).
                self.record_route_failure(&target_hops, &format!("commit rejected: {}", e));
                MigrationOutcome::Failed {
                    reason: MigrationFailureReason::CommitRejected(e),
                }
            }
        }
    }

    /// Record a successful circuit establishment on a route.
    fn record_route_success(&self, hops: &[PeerId]) {
        let mut store = self.route_observations.write().unwrap();
        store.record_success(hops);
    }

    /// Record a failed circuit establishment on a route.
    fn record_route_failure(&self, hops: &[PeerId], _reason: &str) {
        let mut store = self.route_observations.write().unwrap();
        store.record_failure(hops);
    }

    /// Returns the current active route (authoritative).
    #[must_use]
    pub fn current_route(&self) -> Option<&[PeerId]> {
        self.optimizer.current_route()
    }

    /// Returns the optimizer epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.optimizer.epoch()
    }

    /// Returns when the last successful migration occurred.
    #[must_use]
    pub fn last_migration(&self) -> Option<std::time::Instant> {
        self.optimizer.last_migration()
    }

    /// Get a reference to the optimizer (for check/classify without migration).
    #[must_use]
    pub fn optimizer(&self) -> &AdaptiveRouteOptimizer {
        &self.optimizer
    }

    /// Get a mutable reference to the optimizer.
    pub fn optimizer_mut(&mut self) -> &mut AdaptiveRouteOptimizer {
        &mut self.optimizer
    }
}

impl std::fmt::Debug for MigrationExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationExecutor")
            .field("optimizer", &self.optimizer)
            .finish_non_exhaustive()
    }
}

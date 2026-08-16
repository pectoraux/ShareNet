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
use super::circuit_lifecycle::{CircuitId, CircuitRegistry, CircuitState};

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{Node, Route};
use std::sync::Arc;
use std::time::Duration;

/// The result of a migration attempt.
#[derive(Debug)]
pub enum MigrationOutcome {
    /// The migration succeeded — the new route is now active.
    /// The active circuit is available via `executor.active_circuit()`.
    Success {
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
/// ## Authoritative owners
///
/// - **Active route**: `AdaptiveRouteOptimizer.current_route`
/// - **Circuit lifecycle**: `CircuitRegistry`
///
/// The executor does NOT maintain a separate current-route or current-circuit
/// cache — it delegates to these two authoritative owners.
pub struct MigrationExecutor {
    /// The optimizer (authoritative active-route owner).
    optimizer: AdaptiveRouteOptimizer,
    /// The route observation store (shared with optimizer).
    route_observations: Arc<std::sync::RwLock<RouteObservationStore>>,
    /// The circuit registry (authoritative circuit lifecycle owner).
    /// Owns the live MultiplexedCircuit handles for Active and Draining circuits.
    circuit_registry: CircuitRegistry,
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
            circuit_registry: CircuitRegistry::new(),
        }
    }

    /// Create with a custom drain timeout for the circuit registry.
    #[must_use]
    pub fn with_drain_timeout(
        optimizer: AdaptiveRouteOptimizer,
        route_observations: Arc<std::sync::RwLock<RouteObservationStore>>,
        drain_timeout: std::time::Duration,
    ) -> Self {
        Self {
            optimizer,
            route_observations,
            circuit_registry: CircuitRegistry::with_drain_timeout(drain_timeout),
        }
    }

    /// Returns a reference to the circuit registry.
    #[must_use]
    pub fn circuit_registry(&self) -> &CircuitRegistry {
        &self.circuit_registry
    }

    /// Returns a mutable reference to the active circuit (for opening streams).
    ///
    /// New streams MUST be opened on the active circuit. Existing streams
    /// on draining circuits remain bound to their original circuit.
    pub fn active_circuit(&mut self) -> Option<&mut MultiplexedCircuit> {
        self.circuit_registry.active_circuit_mut()
    }

    /// **Production migration method.** Health verification is MANDATORY.
    ///
    /// This is the full migration transaction:
    ///
    /// 1. `optimizer.check()` — get a migration decision.
    /// 2. If `Migrate`: establish the candidate circuit via real SNP-IK.
    /// 3. On establishment success: perform mandatory health verification
    ///    (open a stream + send/recv a test exchange through the candidate
    ///    circuit to the health endpoint).
    /// 4. On health success: construct `EstablishedRoute` evidence.
    /// 5. `commit_migration_with_evidence()` — validate + commit.
    /// 6. On any failure: invalidate decision, record failure, preserve
    ///    old route, no cooldown.
    ///
    /// **N2.5-R.2.1.1:** Health verification is NOT optional. The
    /// `health_check_endpoint` parameter is required. A separate
    /// `attempt_migration_no_health()` method exists for test-only
    /// low-level establishment verification.
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (hop sequences).
    /// * `node` — The client node (identity + keys).
    /// * `routes` — Map from hop sequence to `Route` object (for establishment).
    /// * `client_x25519_secret` — The client's X25519 secret.
    /// * `client_x25519_public` — The client's X25519 public key.
    /// * `health_check_endpoint` — The endpoint to connect to for health
    ///   verification. This endpoint must be reachable through the candidate
    ///   circuit (typically an echo server).
    pub async fn attempt_migration(
        &mut self,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
        health_check_endpoint: snp_gateway::stream::InternetEndpoint,
    ) -> MigrationOutcome {
        self.attempt_migration_inner(
            candidates,
            node,
            routes,
            client_x25519_secret,
            client_x25519_public,
            Some(health_check_endpoint),
        )
        .await
    }

    /// **TEST ONLY.** Attempt migration without health verification.
    ///
    /// This method bypasses the mandatory health check. It is intended
    /// ONLY for low-level establishment tests that do not have an echo
    /// server available. Production code MUST use `attempt_migration()`
    /// with a health endpoint.
    ///
    /// **Do NOT use this in production.** The resulting `EstablishedRoute`
    /// does not prove circuit usability — only handshake completion.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn attempt_migration_no_health(
        &mut self,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
    ) -> MigrationOutcome {
        self.attempt_migration_inner(
            candidates,
            node,
            routes,
            client_x25519_secret,
            client_x25519_public,
            None,
        )
        .await
    }

    /// Internal migration implementation. Shared by `attempt_migration`
    /// (mandatory health) and `attempt_migration_no_health` (test-only).
    async fn attempt_migration_inner(
        &mut self,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
        health_check_endpoint: Option<snp_gateway::stream::InternetEndpoint>,
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
                // Invalidate the decision — it can't be committed later.
                self.optimizer.fail_establishment();
                return MigrationOutcome::Failed {
                    reason: MigrationFailureReason::EstablishmentFailed(
                        "target route not found in routes map".into(),
                    ),
                };
            }
        };

        // 3. Attempt real circuit establishment.
        let mut circuit = match MultiplexedCircuit::establish(
            node,
            &route,
            client_x25519_secret,
            client_x25519_public,
        )
        .await
        {
            Ok(circuit) => circuit,
            Err(e) => {
                // Establishment failed. Invalidate the decision, record failure.
                self.optimizer.fail_establishment();
                let failure_reason = format!("{:?}", e);
                self.record_route_failure(&target_hops, &failure_reason);
                return MigrationOutcome::Failed {
                    reason: MigrationFailureReason::EstablishmentFailed(failure_reason),
                };
            }
        };

        // 4. N2.5-R.2.1 — Minimal health verification.
        // Performed on the circuit before it enters the registry.
        // The health check opens a stream, sends data, and receives a response.
        if let Some(endpoint) = health_check_endpoint {
            match self.health_check(&mut circuit, endpoint).await {
                Ok(()) => { /* Health check passed. */ }
                Err(e) => {
                    self.optimizer.fail_establishment();
                    self.record_route_failure(&target_hops, &format!("health check failed: {}", e));
                    // The circuit is dropped (disposed).
                    drop(circuit);
                    return MigrationOutcome::Failed {
                        reason: MigrationFailureReason::EstablishmentFailed(format!(
                            "health check failed: {}", e
                        )),
                    };
                }
            }
        }

        // 5. N2.5-R.3.1: Register the circuit in the registry.
        // The registry takes ownership of the MultiplexedCircuit.
        // The circuit enters as Candidate (established + health-checked).
        let fid = self.circuit_registry.register_candidate(
            circuit,
            to_route_id,
            target_hops.clone(),
        );

        // 6. Construct EstablishedRoute evidence.
        let gateway_node_id = route.destination();
        let client_node_id = node.identity.node_id;

        let evidence = EstablishedRoute::from_establishment(
            target_hops.clone(),
            fid,
            gateway_node_id,
            client_node_id,
        );

        // 7. Verify evidence route_id matches decision.
        if evidence.route_id() != to_route_id {
            self.optimizer.fail_establishment();
            self.circuit_registry.mark_failed(&fid).ok();
            self.record_route_failure(&target_hops, "route_id mismatch after establishment");
            return MigrationOutcome::Failed {
                reason: MigrationFailureReason::RouteIdMismatch,
            };
        }

        // 8. Mark the candidate as healthy (established + health-checked).
        self.circuit_registry.mark_healthy(&fid).ok();

        // 9. Commit the migration with evidence.
        match self
            .optimizer
            .commit_migration_with_evidence(decision, &evidence)
        {
            Ok(()) => {
                // N2.5-R.3.1: Promote the new circuit to active.
                // This transitions the old active circuit (if any) to Draining.
                // The old circuit REMAINS ALIVE in the registry — its
                // MultiplexedCircuit is retained, existing streams continue.
                self.circuit_registry.promote_to_active(&fid).ok();

                // Record success in route observations.
                self.record_route_success(&target_hops);

                // Return success. The active circuit is available via
                // `executor.active_circuit()`. The old circuit is alive
                // in the registry in Draining state.
                MigrationOutcome::Success { evidence }
            }
            Err(e) => {
                // Commit rejected — stale decision, wrong epoch, etc.
                // N2.5-R.3.1: Mark the candidate as failed and dispose it.
                // This drops the MultiplexedCircuit (disposing the circuit).
                self.circuit_registry.mark_failed(&fid).ok();
                self.record_route_failure(&target_hops, &format!("commit rejected: {}", e));
                MigrationOutcome::Failed {
                    reason: MigrationFailureReason::CommitRejected(e),
                }
            }
        }
    }

    /// **N2.5-R.2.1** — Perform a minimal health check on the candidate circuit.
    ///
    /// Opens a stream to the given endpoint and sends/receives a small
    /// test exchange. This proves the circuit is usable end-to-end, not
    /// just that the SNP-IK handshake completed.
    ///
    /// # Errors
    /// Returns an error message if the health check fails (stream open
    /// failure, send failure, recv failure, or timeout).
    async fn health_check(
        &self,
        circuit: &mut MultiplexedCircuit,
        endpoint: snp_gateway::stream::InternetEndpoint,
    ) -> Result<(), String> {
        // Open a stream through the candidate circuit (with timeout).
        // The gateway may take up to 15s to fail a TCP connect to a dead
        // endpoint, so we wrap it in a 20s timeout.
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            circuit.open_stream(endpoint),
        )
        .await
        .map_err(|_| "health check: stream open timed out (20s)".to_string())?
        .map_err(|e| format!("stream open failed: {:?}", e))?;

        // Send a small test message.
        let test_data = b"health-check-ping";
        stream
            .send(test_data)
            .await
            .map_err(|e| format!("send failed: {:?}", e))?;

        // Wait for echo response (with timeout).
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.recv(),
        )
        .await;

        match recv_result {
            Ok(Ok(Some(data))) => {
                // Verify we got data back (don't check content — echo server
                // may coalesce or split).
                if data.is_empty() {
                    return Err("health check received empty response".into());
                }
                // Close the health-check stream.
                let _ = stream.close().await;
                Ok(())
            }
            Ok(Ok(None)) => Err("health check: stream closed before response".into()),
            Ok(Err(e)) => Err(format!("health check recv failed: {:?}", e)),
            Err(_) => Err("health check timed out (10s)".into()),
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

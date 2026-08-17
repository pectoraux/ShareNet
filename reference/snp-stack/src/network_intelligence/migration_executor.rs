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
use super::route_observation::{route_id_from_hops, RouteId, RouteObservationStore};
use super::route_optimizer::{AdaptiveRouteOptimizer, EstablishedRoute, MigrationDecision, OptimizationResult};
use super::circuit_lifecycle::{CircuitHandle, CircuitId, CircuitRegistry};

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_node::node::stream_client::MultiplexedCircuit;
use snp_node::node::{Node, Route};
use std::sync::{Arc, Mutex};
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
    /// **N2.5-R.6** — The circuit was established but the health check failed.
    /// The SNP-IK handshake completed, but opening a stream / sending /
    /// receiving through the circuit failed. This is distinct from
    /// `EstablishmentFailed` (which means the handshake itself failed).
    HealthCheckFailed(String),
}

/// **N2.5-R.6** — A migration plan produced by `begin_migration()` (Phase 1).
///
/// Contains the decision and route information needed to establish a
/// candidate circuit. The `MigrationDecision` inside is move-only — it
/// is consumed by `commit_established()` (Phase 3).
///
/// This type exists so that the `RecoveryController` can split migration
/// into three phases that each hold the executor lock only briefly:
///
/// ```text
/// Phase 1 (short lock): begin_migration() → MigrationBegin
/// Phase 2 (NO lock):    establish_candidate(plan) → EstablishedCandidate
/// Phase 3 (short lock): commit_established(plan, candidate) → MigrationOutcome
/// ```
#[derive(Debug)]
pub struct MigrationPlan {
    /// The move-only migration decision from the optimizer.
    pub decision: MigrationDecision,
    /// The resolved Route object for establishment.
    pub route: Route,
    /// The target hop sequence.
    pub target_hops: Vec<PeerId>,
    /// The target route_id (SHA-256 of target_hops).
    pub to_route_id: RouteId,
}

/// **N2.5-R.6** — Result of Phase 1 (`begin_migration()`).
#[derive(Debug)]
pub enum MigrationBegin {
    /// A migration is recommended; establish this plan.
    Migrate(MigrationPlan),
    /// No migration needed (optimizer returned NoMigration).
    NotNeeded,
    /// The optimizer is on cooldown.
    Cooldown {
        /// Time remaining.
        remaining: Duration,
    },
    /// No routes are available (all quarantined or none provided).
    NoRoutes,
}

/// **N2.5-R.6** — A candidate circuit that has been established AND
/// health-checked (Phase 2 result). Ready to be committed (Phase 3).
#[derive(Debug)]
pub struct EstablishedCandidate {
    /// The live, health-checked circuit.
    pub circuit: MultiplexedCircuit,
    /// The target hop sequence.
    pub target_hops: Vec<PeerId>,
    /// The target route_id.
    pub to_route_id: RouteId,
    /// The gateway's NodeId (for evidence).
    pub gateway_node_id: [u8; 32],
    /// The client's NodeId (for evidence).
    pub client_node_id: [u8; 32],
}

/// **N2.5-R.6** — Phase 2: Establish + health-check a candidate circuit.
///
/// This is a **free function** — it does NOT touch the `MigrationExecutor`
/// or `CircuitRegistry`. It can be called WITHOUT holding the executor
/// lock, which is the key to the R.5.1/R.6 invariant: the executor-wide
/// mutex is never held over network I/O.
///
/// Performs:
/// 1. `MultiplexedCircuit::establish()` — real SNP-IK handshake (slow).
/// 2. `probe_circuit_health()` — open stream + send/recv (slow).
///
/// # Arguments
/// * `plan` — The migration plan from `begin_migration()`.
/// * `node` — The client node.
/// * `client_x25519_secret` / `client_x25519_public` — Client keys.
/// * `health_check_endpoint` — Endpoint for health verification.
///   Pass `None` for test-only establishment without health check.
///
/// # Errors
/// Returns `MigrationFailureReason::EstablishmentFailed` if the SNP-IK
/// handshake fails, or `MigrationFailureReason::HealthCheckFailed` if
/// the circuit was established but the health check failed.
pub async fn establish_candidate(
    plan: &MigrationPlan,
    node: &Node,
    client_x25519_secret: &X25519Secret,
    client_x25519_public: &X25519PubKey,
    health_check_endpoint: Option<snp_gateway::stream::InternetEndpoint>,
) -> Result<EstablishedCandidate, MigrationFailureReason> {
    // 1. Establish the circuit (real SNP-IK handshake).
    let mut circuit = match MultiplexedCircuit::establish(
        node,
        &plan.route,
        client_x25519_secret,
        client_x25519_public,
    )
    .await
    {
        Ok(circuit) => circuit,
        Err(e) => {
            return Err(MigrationFailureReason::EstablishmentFailed(format!("{:?}", e)));
        }
    };

    // 2. Health check (if endpoint provided).
    if let Some(endpoint) = health_check_endpoint {
        let failed = probe_circuit_health(&mut circuit, endpoint, Duration::from_secs(20)).await;
        if failed {
            // Circuit established but health check failed — dispose it.
            drop(circuit);
            return Err(MigrationFailureReason::HealthCheckFailed(
                "health check failed (stream open/send/recv or timeout)".into(),
            ));
        }
    }

    // 3. Construct the established candidate.
    Ok(EstablishedCandidate {
        circuit,
        target_hops: plan.target_hops.clone(),
        to_route_id: plan.to_route_id,
        gateway_node_id: plan.route.destination(),
        client_node_id: node.identity.node_id,
    })
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

    /// Returns a shared, lockable handle to the active circuit.
    ///
    /// **N2.5-R.5.1** — Returns a *cloned* `CircuitHandle`
    /// (`Arc<tokio::sync::Mutex<MultiplexedCircuit>>`) and does NOT hold any
    /// lock. Callers lock the inner mutex only for as long as they need
    /// `&mut` access (e.g. to `open_stream`):
    ///
    /// ```ignore
    /// let handle = executor.active_circuit().unwrap();
    /// let mut guard = handle.lock().await;
    /// guard.open_stream(endpoint).await?;
    /// ```
    ///
    /// New streams MUST be opened on the active circuit. Existing streams
    /// on draining circuits remain bound to their original circuit.
    #[must_use]
    pub fn active_circuit(&self) -> Option<CircuitHandle> {
        self.circuit_registry.active_circuit()
    }

    /// **N2.5-R.3.2** — Reap draining circuits.
    ///
    /// Lifecycle maintenance method. Closes draining circuits that have
    /// zero active streams or whose drain timeout has expired.
    ///
    /// Should be called periodically by the runtime (e.g., after stream
    /// operations or on a timer).
    ///
    /// Returns the circuit IDs that were closed.
    pub async fn reap_draining(&mut self) -> Vec<CircuitId> {
        self.circuit_registry.reap_draining().await
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

    // ───────────────────────────────────────────────────────────────────────
    // N2.5-R.6 — Phased Migration API
    // ───────────────────────────────────────────────────────────────────────
    //
    // The RecoveryController needs to perform migration WITHOUT holding the
    // executor-wide mutex over the slow network I/O (establishment + health
    // check can take seconds). These methods split the migration into three
    // phases:
    //
    //   Phase 1 (short lock): begin_migration() → MigrationBegin
    //   Phase 2 (NO lock):    establish_candidate(plan) → EstablishedCandidate
    //   Phase 3 (short lock): commit_established(plan, candidate) → MigrationOutcome
    //
    // `attempt_migration()` (above) remains as a convenience wrapper that
    // calls all three phases with `&mut self` held throughout — suitable
    // for callers that already own the executor directly.

    /// **N2.5-R.6** — Phase 1: Get a migration decision + resolve the route.
    ///
    /// This is the fast, synchronous phase: it calls `optimizer.check()`,
    /// resolves the `Route` object, and returns a `MigrationPlan` that
    /// can be established without touching the executor.
    ///
    /// **No network I/O occurs here.** The caller should release the
    /// executor lock immediately after this call.
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (hop sequences).
    /// * `routes` — Map from hop sequence to `Route` object.
    #[must_use]
    pub fn begin_migration(
        &mut self,
        candidates: &[Vec<PeerId>],
        routes: &[(Vec<PeerId>, Route)],
    ) -> MigrationBegin {
        let decision = match self.optimizer.check(candidates) {
            OptimizationResult::Migrate(d) => d,
            OptimizationResult::NoMigration { .. } => return MigrationBegin::NotNeeded,
            OptimizationResult::NoRoutes => return MigrationBegin::NoRoutes,
            OptimizationResult::Cooldown { remaining } => {
                return MigrationBegin::Cooldown { remaining };
            }
        };

        let target_hops = decision.target_route().to_vec();
        let to_route_id = route_id_from_hops(&target_hops);

        let route = match routes.iter().find(|(hops, _)| hops.as_slice() == target_hops.as_slice())
        {
            Some((_, route)) => route.clone(),
            None => {
                self.optimizer.fail_establishment();
                return MigrationBegin::NotNeeded;
            }
        };

        MigrationBegin::Migrate(MigrationPlan {
            decision,
            route,
            target_hops,
            to_route_id,
        })
    }

    /// **N2.5-R.6** — Phase 3: Register + commit + promote an established
    /// candidate circuit.
    ///
    /// This is the fast, synchronous phase: it registers the circuit in
    /// the `CircuitRegistry`, constructs `EstablishedRoute` evidence,
    /// commits the migration via `commit_migration_with_evidence()`, and
    /// promotes the new circuit to Active.
    ///
    /// **No network I/O occurs here.** The caller should release the
    /// executor lock immediately after this call.
    ///
    /// If `candidate_result` is `Err`, this method records the failure
    /// (invalidates the decision, records route failure) and returns
    /// `MigrationOutcome::Failed` — the caller does NOT need to separately
    /// call `fail_establishment()`.
    ///
    /// # Arguments
    /// * `plan` — The migration plan from `begin_migration()` (consumed).
    /// * `candidate_result` — The result of `establish_candidate()` (Phase 2).
    pub fn commit_established(
        &mut self,
        plan: MigrationPlan,
        candidate_result: Result<EstablishedCandidate, MigrationFailureReason>,
    ) -> MigrationOutcome {
        let candidate = match candidate_result {
            Ok(c) => c,
            Err(reason) => {
                self.optimizer.fail_establishment();
                self.record_route_failure(&plan.target_hops, &format!("{:?}", reason));
                return MigrationOutcome::Failed { reason };
            }
        };

        // Register the circuit in the registry.
        let fid = self.circuit_registry.register_candidate(
            candidate.circuit,
            candidate.to_route_id,
            candidate.target_hops.clone(),
        );

        // Construct EstablishedRoute evidence.
        let evidence = EstablishedRoute::from_establishment(
            candidate.target_hops.clone(),
            fid,
            candidate.gateway_node_id,
            candidate.client_node_id,
        );

        // Verify evidence route_id matches the plan.
        if evidence.route_id() != plan.to_route_id {
            self.optimizer.fail_establishment();
            self.circuit_registry.mark_failed(&fid).ok();
            self.record_route_failure(&candidate.target_hops, "route_id mismatch after establishment");
            return MigrationOutcome::Failed {
                reason: MigrationFailureReason::RouteIdMismatch,
            };
        }

        // Mark the candidate as healthy.
        self.circuit_registry.mark_healthy(&fid).ok();

        // Commit the migration with evidence.
        match self
            .optimizer
            .commit_migration_with_evidence(plan.decision, &evidence)
        {
            Ok(()) => {
                self.circuit_registry.promote_to_active(&fid).ok();
                self.record_route_success(&candidate.target_hops);
                MigrationOutcome::Success { evidence }
            }
            Err(e) => {
                self.circuit_registry.mark_failed(&fid).ok();
                self.record_route_failure(&candidate.target_hops, &format!("commit rejected: {}", e));
                MigrationOutcome::Failed {
                    reason: MigrationFailureReason::CommitRejected(e),
                }
            }
        }
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

    /// **N2.5-R.4 / N2.5-R.5.1** — Detect whether the active circuit has
    /// failed.
    ///
    /// This is a synchronous, caller-invoked health probe used by
    /// `recover_from_failure()`. It locks ONLY the per-circuit
    /// `tokio::sync::Mutex` (via the `CircuitHandle`) for the duration of
    /// the probe — it does NOT require `&mut self` and does NOT hold any
    /// executor-wide state across the network I/O.
    ///
    /// Detection is based on attempting to open a stream to the given
    /// health endpoint. If the stream open fails or times out, the
    /// circuit is considered failed.
    ///
    /// # Arguments
    /// * `health_check_endpoint` — The endpoint to probe.
    /// * `timeout` — How long to wait before declaring failure.
    ///
    /// Returns `true` if the active circuit has failed, `false` if it is
    /// still healthy. Returns `false` if there is no active circuit
    /// (nothing to detect), and `true` if there is an active circuit ID but
    /// no live circuit handle (the registry is inconsistent).
    pub async fn detect_active_circuit_failure(
        &self,
        health_check_endpoint: snp_gateway::stream::InternetEndpoint,
        timeout: Duration,
    ) -> bool {
        let active_id = match self.circuit_registry.active_circuit_id() {
            Some(id) => id,
            None => return false,
        };

        // Clone the handle (cheap Arc clone — NO lock held by the registry).
        let handle = match self.circuit_registry.active_circuit() {
            Some(h) => h,
            None => return true,
        };

        // Probe the circuit. Only the per-circuit mutex is held over the I/O.
        let failed = {
            let mut guard = handle.lock().await;
            probe_circuit_health(&mut guard, health_check_endpoint, timeout).await
        };

        if failed {
            eprintln!("[n2.5-r.4] active circuit {:?} failure detected", active_id);
        }
        failed
    }

    /// **N2.5-R.5.1** — Capture the probe context for the currently-active
    /// circuit, together with a cloned `CircuitHandle` that can be probed
    /// **without** holding the executor-wide mutex.
    ///
    /// This is the short-lock capture step of the failure monitor:
    ///
    /// ```text
    /// monitor:
    ///   let (ctx, handle) = executor.lock().await.prepare_probe()?;
    ///   // executor lock released here
    ///   probe(handle)  // no executor lock held over the network I/O
    /// ```
    ///
    /// Returns `None` if there is no active circuit to probe.
    #[must_use]
    pub fn prepare_probe(&self) -> Option<(ProbeContext, CircuitHandle)> {
        let circuit_id = self.circuit_registry.active_circuit_id()?;
        let route_id = self.circuit_registry.circuit_route_id(&circuit_id)?;
        let handle = self.circuit_registry.active_circuit()?;
        let epoch = self.epoch();
        Some((
            ProbeContext {
                circuit_id,
                route_id,
                epoch,
            },
            handle,
        ))
    }

    /// **N2.5-R.5.1** — Verify that a `RecoveryRequest` still matches the
    /// currently-active circuit and the current optimizer epoch.
    ///
    /// This is the stale-signal guard. The failure monitor captures a
    /// `ProbeContext` (circuit_id, route_id, epoch) at probe-start. If a
    /// migration or a recovery completes between probe-start and the
    /// runtime acting on the request, the active circuit and/or epoch will
    /// have changed, and this method returns `false` — the request is stale
    /// and MUST be discarded rather than acted upon.
    ///
    /// Returns `true` only if ALL of the following hold:
    /// - There is an active circuit.
    /// - `request.circuit_id` equals the active circuit's id.
    /// - `request.route_id` equals the active circuit's route_id.
    /// - `request.epoch` equals the current optimizer epoch.
    #[must_use]
    pub fn verify_recovery_request(&self, request: &RecoveryRequest) -> bool {
        let Some(active_id) = self.circuit_registry.active_circuit_id() else {
            return false;
        };
        let Some(active_route_id) = self.circuit_registry.circuit_route_id(&active_id) else {
            return false;
        };
        active_id == request.circuit_id
            && active_route_id == request.route_id
            && self.epoch() == request.epoch
    }

    /// **N2.5-R.5.1** — Act on a `RecoveryRequest` emitted by the failure
    /// monitor.
    ///
    /// This is the runtime side of the monitor→runtime contract:
    ///
    /// ```text
    /// RecoveryRequest { circuit_id, route_id, epoch }
    ///     ↓
    /// runtime verifies it still matches ACTIVE (verify_recovery_request)
    ///     ↓ match: fail_active_circuit() + attempt_migration()
    ///     ↓ mismatch: stale — discard, no recovery
    /// ```
    ///
    /// If the request is stale (the active circuit or epoch has changed
    /// since the probe — e.g. a migration A→B completed while the monitor
    /// was probing A), this returns `MigrationOutcome::NotNeeded` WITHOUT
    /// touching the active circuit. The probed circuit is no longer active,
    /// so its failure is not actionable.
    ///
    /// If the request is current, this performs the full recovery
    /// transaction: mark the active circuit failed + quarantine its route +
    /// attempt migration to a new (non-quarantined) route.
    ///
    /// # Arguments
    /// * `request` — The recovery request from the monitor (provenance-bound).
    /// * `candidates` — All candidate routes (hop sequences).
    /// * `node` — The client node (identity + keys).
    /// * `routes` — Map from hop sequence to `Route` object.
    /// * `client_x25519_secret` / `client_x25519_public` — Client keys.
    /// * `health_check_endpoint` — Endpoint for verifying the NEW circuit.
    pub async fn handle_recovery_request(
        &mut self,
        request: &RecoveryRequest,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
        health_check_endpoint: snp_gateway::stream::InternetEndpoint,
    ) -> MigrationOutcome {
        // 1. Verify the request still matches the active circuit + epoch.
        if !self.verify_recovery_request(request) {
            eprintln!(
                "[n2.5-r.5.1] stale recovery request discarded \
                 (request circuit={:?} epoch={}, active circuit={:?} epoch={})",
                request.circuit_id,
                request.epoch,
                self.circuit_registry.active_circuit_id(),
                self.epoch()
            );
            return MigrationOutcome::NotNeeded;
        }

        // 2. The probed circuit is still active and failed. Fail it.
        if let Err(e) = self.fail_active_circuit() {
            eprintln!("[n2.5-r.5.1] failed to mark active circuit as failed: {}", e);
            // Continue anyway — try to establish a new circuit.
        }

        // 3. Attempt migration to a new route. The failed route is excluded
        //    by quarantine (set in fail_active_circuit).
        self.attempt_migration(
            candidates,
            node,
            routes,
            client_x25519_secret,
            client_x25519_public,
            health_check_endpoint,
        )
        .await
    }

    /// **N2.5-R.4** — Mark the active circuit as failed and trigger
    /// recovery.
    ///
    /// This should be called after `detect_active_circuit_failure()`
    /// returns `true`. It:
    ///
    /// 1. Marks the active circuit as Failed in the registry (closes it).
    /// 2. Records a failure in route observations.
    /// 3. Resets the optimizer's current route (so it will recommend
    ///    a new route on the next `check()`).
    ///
    /// After this call, the runtime should call `attempt_migration()`
    /// with the available candidate routes to establish a new active
    /// circuit.
    ///
    /// # Errors
    /// Returns `Err` if there is no active circuit to fail.
    pub fn fail_active_circuit(&mut self) -> Result<(), String> {
        let active_id = self.circuit_registry.active_circuit_id()
            .ok_or_else(|| "no active circuit to fail".to_string())?;

        // Get the route_id and hops BEFORE marking failed (they remain in the registry).
        let route_id = self.circuit_registry.circuit_route_id(&active_id);
        let hops = self.circuit_registry.circuit_hops(&active_id).map(|h| h.to_vec());

        // Mark the circuit as failed (closes and drops the MultiplexedCircuit).
        self.circuit_registry.mark_failed(&active_id)
            .map_err(|e| format!("failed to mark circuit {:?} as failed: {}", active_id, e))?;

        // Record failure in route observations for the failed route.
        if let Some(ref hops) = hops {
            self.record_route_failure(hops, "active circuit failure detected");
        }

        // N2.5-R.4.1: Quarantine the failed route so it cannot be immediately
        // reselected for recovery. Default quarantine: 60 seconds.
        if let Some(rid) = route_id {
            self.optimizer.quarantine_route(rid, Duration::from_secs(60));
        }

        // Reset the optimizer's current route and increment epoch.
        // N2.5-R.4.1: clear_current_route now increments epoch.
        self.optimizer.clear_current_route();
        self.optimizer.fail_establishment();

        eprintln!(
            "[n2.5-r.4] active circuit {:?} marked as failed, optimizer reset, route quarantined",
            active_id
        );
        Ok(())
    }

    /// **N2.5-R.4** — Recovery from active-circuit failure.
    ///
    /// **This is a caller-invoked recovery transaction, NOT an automatic
    /// background monitor.** The runtime must call this method (or call
    /// `detect_active_circuit_failure()` + `fail_active_circuit()` +
    /// `attempt_migration()` manually) to initiate recovery.
    ///
    /// This is the full recovery transaction:
    ///
    /// 1. Detect active circuit failure (health probe).
    /// 2. If failed: mark active circuit as Failed + quarantine route.
    /// 3. Attempt migration to a new route (establish + health check + commit).
    ///    The failed route is excluded from candidates by quarantine.
    ///
    /// If the active circuit is healthy, returns `NotNeeded`.
    /// If recovery succeeds, returns `Success`.
    /// If recovery fails, returns `Failed` (old circuit is already Failed).
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (hop sequences).
    /// * `node` — The client node (identity + keys).
    /// * `routes` — Map from hop sequence to `Route` object.
    /// * `client_x25519_secret` — The client's X25519 secret.
    /// * `client_x25519_public` — The client's X25519 public key.
    /// * `health_check_endpoint` — Endpoint for health verification of
    ///   both the old circuit (detection) and the new circuit (verification).
    /// * `detection_timeout` — How long to wait before declaring the
    ///   active circuit failed.
    pub async fn recover_from_failure(
        &mut self,
        candidates: &[Vec<PeerId>],
        node: &Node,
        routes: &[(Vec<PeerId>, Route)],
        client_x25519_secret: &X25519Secret,
        client_x25519_public: &X25519PubKey,
        health_check_endpoint: snp_gateway::stream::InternetEndpoint,
        detection_timeout: Duration,
    ) -> MigrationOutcome {
        // 1. Detect active circuit failure.
        let failed = self.detect_active_circuit_failure(
            health_check_endpoint.clone(),
            detection_timeout,
        ).await;

        if !failed {
            return MigrationOutcome::NotNeeded;
        }

        // 2. Mark the active circuit as failed.
        if let Err(e) = self.fail_active_circuit() {
            eprintln!("[n2.5-r.4] failed to mark active circuit as failed: {}", e);
            // Continue anyway — try to establish a new circuit.
        }

        // 3. Attempt migration to a new route.
        // The optimizer's current_route has been reset, so check() will
        // recommend the best available route as a cold-start (exploration).
        self.attempt_migration(
            candidates,
            node,
            routes,
            client_x25519_secret,
            client_x25519_public,
            health_check_endpoint,
        ).await
    }
}

impl std::fmt::Debug for MigrationExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationExecutor")
            .field("optimizer", &self.optimizer)
            .finish_non_exhaustive()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.5-R.5 / N2.5-R.5.1 — Failure Detection Integration / Recovery Triggering
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.5.1** — Probe a circuit's health by opening a stream, sending a
/// small test exchange, and waiting for the echo response.
///
/// This is the shared probe routine used by BOTH:
/// - `MigrationExecutor::detect_active_circuit_failure()` (caller-invoked),
/// - the background `FailureMonitor` task.
///
/// It takes `&mut MultiplexedCircuit` (the locked guard) and performs the
/// network I/O. It does NOT touch the `MigrationExecutor` or
/// `CircuitRegistry` — the caller is responsible for obtaining the
/// `CircuitHandle` and locking it.
///
/// Returns `true` if the circuit has FAILED (probe error or timeout),
/// `false` if it is still healthy.
async fn probe_circuit_health(
    circuit: &mut MultiplexedCircuit,
    health_check_endpoint: snp_gateway::stream::InternetEndpoint,
    timeout: Duration,
) -> bool {
    let probe_result = tokio::time::timeout(
        timeout,
        async {
            // Open a stream through the circuit.
            let mut stream = circuit
                .open_stream(health_check_endpoint)
                .await
                .map_err(|e| format!("stream open failed: {:?}", e))?;

            let test_data = b"health-check-ping";
            stream
                .send(test_data)
                .await
                .map_err(|e| format!("send failed: {:?}", e))?;

            let recv_result = tokio::time::timeout(
                Duration::from_secs(10),
                stream.recv(),
            )
            .await;

            match recv_result {
                Ok(Ok(Some(data))) => {
                    if data.is_empty() {
                        return Err("empty response".into());
                    }
                    let _ = stream.close().await;
                    Ok(())
                }
                Ok(Ok(None)) => Err("stream closed".into()),
                Ok(Err(e)) => Err(format!("recv failed: {:?}", e)),
                Err(_) => Err("timeout".into()),
            }
        },
    )
    .await;

    match probe_result {
        Ok(Ok(())) => false,
        Ok(Err(_)) | Err(_) => true,
    }
}

/// **N2.5-R.5.1** — Configuration for the background failure monitor.
#[derive(Debug, Clone)]
pub struct FailureMonitorConfig {
    /// How often to probe the active circuit (default: 30 seconds).
    pub probe_interval: Duration,
    /// How long to wait for a health probe before declaring failure
    /// (default: 20 seconds).
    pub probe_timeout: Duration,
}

impl Default for FailureMonitorConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(20),
        }
    }
}

/// **N2.5-R.5.1** — The identity of the circuit being probed, captured at
/// probe-start.
///
/// This binds a probe (and its result) to a SPECIFIC circuit instance, a
/// SPECIFIC route, and a SPECIFIC optimizer epoch. Without this binding, a
/// probe started against circuit A could be misattributed to circuit B if a
/// migration A→B completes while the probe is in flight — exactly the
/// stale-signal race that N2.5-R.5.1 fixes.
///
/// The `ProbeContext` is captured under a SHORT executor lock (no I/O) by
/// `MigrationExecutor::prepare_probe()`. The probe itself then runs WITHOUT
/// the executor lock. On failure, the context is promoted into a
/// [`RecoveryRequest`] and handed to the runtime, which verifies it still
/// matches the active circuit before recovering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeContext {
    /// The circuit id (fid) of the circuit being probed.
    pub circuit_id: CircuitId,
    /// The route id of the circuit being probed.
    pub route_id: RouteId,
    /// The optimizer epoch at probe-start.
    pub epoch: u64,
}

/// **N2.5-R.5.1** — A recovery request carrying full failure provenance.
///
/// Emitted by the failure monitor when a probe fails. Unlike the previous
/// boolean `RecoverySignal`, this carries the `circuit_id`, `route_id`, and
/// `epoch` of the circuit that was actually probed. The runtime verifies
/// (via `MigrationExecutor::verify_recovery_request()`) that this still
/// matches the currently-active circuit before acting on it.
///
/// This eliminates the stale-signal race:
///
/// ```text
/// A active (epoch N)
///   ↓ monitor probes A (captures ProbeContext { A, route_A, N })
/// A → B migration completes (epoch N+1, B active)
///   ↓ probe of A fails
/// RecoveryRequest { circuit_id: A, route_id: route_A, epoch: N }
///   ↓ runtime: verify_recovery_request → A != active(B) → STALE → discard
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// The circuit id that was probed and found failed.
    pub circuit_id: CircuitId,
    /// The route id of the failed circuit.
    pub route_id: RouteId,
    /// The optimizer epoch at probe-start.
    pub epoch: u64,
}

impl From<ProbeContext> for RecoveryRequest {
    fn from(ctx: ProbeContext) -> Self {
        Self {
            circuit_id: ctx.circuit_id,
            route_id: ctx.route_id,
            epoch: ctx.epoch,
        }
    }
}

/// **N2.5-R.5.1** — The shared channel through which the failure monitor
/// delivers a `RecoveryRequest` to the runtime.
///
/// Replaces the boolean `RecoverySignal`: instead of a bare `needs_recovery`
/// flag, the monitor deposits a provenance-bound `RecoveryRequest`. The
/// runtime reads it with `take()` (or `take_async()` for the
/// `RecoveryController`) and verifies it against the active circuit
/// before recovering.
///
/// This is NOT a callback — it is a simple shared cell that avoids complex
/// async callback lifetimes. The runtime polls `take()` (or `peek()`) and
/// calls `MigrationExecutor::handle_recovery_request()` when a request is
/// present.
///
/// **N2.5-R.6** — `take_async()` uses `tokio::sync::Notify` so the
/// `RecoveryController` can wait without busy-polling (requirement: no
/// 100% CPU polling).
pub struct RecoveryChannel {
    /// The pending recovery request, or `None` if no failure has been
    /// detected since the last `take()`.
    pending: Mutex<Option<RecoveryRequest>>,
    /// Notified when a request is deposited (for `take_async()`).
    notify: tokio::sync::Notify,
}

impl std::fmt::Debug for RecoveryChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryChannel")
            .field("has_pending", &self.peek())
            .finish_non_exhaustive()
    }
}

impl Default for RecoveryChannel {
    fn default() -> Self {
        Self {
            pending: Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }
}

impl RecoveryChannel {
    /// Create a new (empty) recovery channel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read and clear the pending recovery request.
    ///
    /// Returns `Some(request)` if the monitor has detected a failure since
    /// the last call, or `None` otherwise.
    pub fn take(&self) -> Option<RecoveryRequest> {
        self.pending.lock().unwrap().take()
    }

    /// **N2.5-R.6** — Asynchronously wait for and consume a recovery request.
    ///
    /// If a request is pending, returns it immediately. Otherwise, waits
    /// until the monitor deposits one (via `emit()`). Uses
    /// `tokio::sync::Notify` internally — no busy-polling.
    ///
    /// This is the method the `RecoveryController` uses in its RUNNING
    /// state to wait for failure detection without consuming CPU.
    pub async fn take_async(&self) -> RecoveryRequest {
        loop {
            if let Some(req) = self.take() {
                return req;
            }
            self.notify.notified().await;
        }
    }

    /// Returns `true` if a recovery request is pending, WITHOUT clearing it.
    #[must_use]
    pub fn peek(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }

    /// Returns a clone of the pending request without clearing it, if any.
    /// Used by tests and diagnostics.
    #[must_use]
    pub fn peek_request(&self) -> Option<RecoveryRequest> {
        *self.pending.lock().unwrap()
    }

    /// Deposit a recovery request (called by the failure monitor).
    /// If a request is already pending, it is overwritten — the most recent
    /// failure takes precedence.
    fn emit(&self, request: RecoveryRequest) {
        *self.pending.lock().unwrap() = Some(request);
        self.notify.notify_one();
    }

    /// **Test-only.** Deposit a recovery request directly, bypassing the
    /// failure monitor. Used by unit tests to exercise
    /// `verify_recovery_request` / `handle_recovery_request` against a
    /// synthesized request.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn emit_for_test(&self, request: RecoveryRequest) {
        self.emit(request);
    }
}

/// **N2.5-R.5 / N2.5-R.5.1** — Background failure monitor.
///
/// Spawns a tokio task that periodically probes the active circuit. When a
/// probe fails, it deposits a [`RecoveryRequest`] (carrying the
/// `circuit_id`/`route_id`/`epoch` of the probed circuit) into the
/// [`RecoveryChannel`] and exits. The runtime verifies the request still
/// matches the active circuit before recovering.
///
/// ## Architecture (N2.5-R.5.1)
///
/// ```text
/// Background task:
///   loop {
///     sleep(probe_interval)
///
///     // 1. SHORT executor lock: capture ProbeContext + CircuitHandle.
///     let probe = executor.lock().await.prepare_probe();
///     // executor lock RELEASED here.
///
///     let Some((ctx, handle)) = probe else { continue };
///
///     // 2. Probe WITHOUT the executor lock — only the per-circuit
///     //    tokio::sync::Mutex is held over the network I/O.
///     let failed = {
///       let mut guard = handle.lock().await;
///       probe_circuit_health(&mut guard, endpoint, timeout).await
///     };
///
///     // 3. On failure, deposit a provenance-bound RecoveryRequest.
///     if failed {
///       channel.emit(RecoveryRequest::from(ctx));
///       break;  // exit — runtime restarts after recovery
///     }
///   }
///
/// Runtime:
///   loop {
///     if let Some(req) = channel.take() {
///       executor.handle_recovery_request(&req, ...).await  // verifies ACTIVE
///       monitor.start(...)  // restart
///     }
///   }
/// ```
///
/// ## Invariants (N2.5-R.5.1)
///
/// - The monitor NEVER holds the `MigrationExecutor`-wide mutex over the
///   network I/O. The executor lock is held only for the brief
///   `prepare_probe()` capture.
/// - The probe result is bound to the `ProbeContext` (circuit_id, route_id,
///   epoch) captured at probe-start, so it cannot be misattributed to a
///   different circuit after a migration.
/// - `start()` is idempotent: at most one monitor task exists at any time.
///
/// ## What this is NOT
///
/// - This is NOT transport-level failure detection. It is a periodic
///   health probe.
/// - This is NOT a callback system. The runtime must poll the channel.
/// - The monitor does NOT perform recovery itself. It only requests it.
pub struct FailureMonitor {
    /// Handle to the background probe task.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shared recovery channel (carries provenance-bound requests).
    channel: Arc<RecoveryChannel>,
}

impl FailureMonitor {
    /// Create a new failure monitor (not yet started).
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_handle: None,
            channel: Arc::new(RecoveryChannel::new()),
        }
    }

    /// Returns a reference to the recovery channel.
    #[must_use]
    pub fn channel(&self) -> &Arc<RecoveryChannel> {
        &self.channel
    }

    /// **N2.5-R.5.1** — Start the background failure monitor (idempotent).
    ///
    /// If a monitor task is already running, this is a no-op — there is at
    /// most one monitor task at any time. This prevents the race where a
    /// second `start()` overwrites `task_handle` while the first task is
    /// still alive (leaving an orphaned task probing in the background).
    ///
    /// If the previous task has finished (e.g. it detected a failure and
    /// exited), it is cleaned up and a new task is spawned.
    ///
    /// # Arguments
    /// * `executor` — The migration executor (shared via `Arc<Mutex>`).
    /// * `health_endpoint` — The endpoint to probe.
    /// * `config` — Monitor configuration.
    pub fn start(
        &mut self,
        executor: Arc<tokio::sync::Mutex<MigrationExecutor>>,
        health_endpoint: snp_gateway::stream::InternetEndpoint,
        config: FailureMonitorConfig,
    ) {
        // Idempotent: if a task is still running, do nothing.
        if self.is_running() {
            return;
        }
        // Clean up any finished handle before spawning a new one.
        if let Some(handle) = self.task_handle.take() {
            handle.abort(); // no-op if already finished
        }

        let channel = Arc::clone(&self.channel);

        self.task_handle = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(config.probe_interval).await;

                // 1. SHORT executor lock: capture ProbeContext + CircuitHandle.
                //    No network I/O happens under this lock.
                let probe = {
                    let exec = executor.lock().await;
                    exec.prepare_probe()
                }; // executor lock RELEASED here.

                let Some((ctx, handle)) = probe else {
                    // No active circuit to probe — nothing to do this cycle.
                    continue;
                };

                // 2. Probe WITHOUT the executor lock. Only the per-circuit
                //    tokio::sync::Mutex is held over the network I/O.
                let failed = {
                    let mut guard = handle.lock().await;
                    probe_circuit_health(&mut guard, health_endpoint.clone(), config.probe_timeout)
                        .await
                };

                // 3. On failure, deposit a provenance-bound RecoveryRequest.
                if failed {
                    eprintln!(
                        "[n2.5-r.5.1] failure monitor: active circuit {:?} (route {:?}, epoch {}) failure detected",
                        ctx.circuit_id, ctx.route_id, ctx.epoch
                    );
                    channel.emit(RecoveryRequest::from(ctx));
                    break; // exit — runtime will restart after recovery
                }
            }
        }));
    }

    /// Stop the background failure monitor.
    pub fn stop(&mut self) {
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }

    /// Returns `true` if the monitor is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.task_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

impl Default for FailureMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FailureMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for FailureMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureMonitor")
            .field("is_running", &self.is_running())
            .field("has_pending_request", &self.channel.peek())
            .finish_non_exhaustive()
    }
}

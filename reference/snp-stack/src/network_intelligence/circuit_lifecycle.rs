//! **N2.5-R.3.1 — Circuit Lifecycle Management with Real Circuit Ownership.**
//!
//! Manages the lifecycle of circuits during route migration:
//!
//! ```text
//! CANDIDATE → HEALTHY → ACTIVE → DRAINING → CLOSED
//!                                      ↘ FAILED
//! ```
//!
//! ## Key invariants
//!
//! - At most one ACTIVE circuit at any time.
//! - After migration commit, the old circuit enters DRAINING.
//! - A DRAINING circuit **remains alive** — its `MultiplexedCircuit` is
//!   retained by the registry. Existing streams continue to function.
//! - When a draining circuit's stream count reaches zero (or drain timeout
//!   expires), it is closed via `MultiplexedCircuit::close()` and
//!   transitions to CLOSED.
//! - Existing streams remain bound to their original circuit — no transparent
//!   stream migration.
//!
//! ## What this module does NOT do
//!
//! - It does NOT migrate existing streams to the new circuit.
//! - It does NOT provide transparent TCP connection migration.
//! - It does NOT automatically reconnect failed streams.
//!
//! Existing streams remain bound to their original circuit until completion,
//! failure, or drain timeout.

#![cfg(feature = "circuit-upstream")]

use super::observations::PeerId;
use super::route_observation::RouteId;
use snp_node::node::stream_client::MultiplexedCircuit;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A unique identifier for a circuit instance.
///
/// This is the circuit's frame ID (`fid`), a randomly-generated 8-byte value
/// assigned at circuit establishment. It is unique within a client's session
/// (collision probability is negligible with 8 random bytes). It is NOT
/// globally unique across different clients — it is scoped to the client's
/// local circuit registry.
///
/// This is distinct from `RouteId` (which identifies a hop sequence). Multiple
/// circuits may use the same route.
pub type CircuitId = [u8; 8];

/// The lifecycle state of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitState {
    /// The circuit is established and health-verified, owned by the registry,
    /// but has not yet been promoted to Active. The `MultiplexedCircuit`
    /// is alive in the registry.
    ///
    /// In the current executor flow, `Candidate` is a brief transitional
    /// state: the circuit is registered as Candidate immediately after
    /// health check passes, then quickly promoted to Healthy and Active.
    /// It exists to represent the window between "circuit is ready" and
    /// "circuit is committed as active."
    Candidate,
    /// The circuit is established and health-verified, but not yet active.
    Healthy,
    /// The circuit is the active circuit for new streams.
    Active,
    /// The circuit is draining — no new streams, existing streams continue.
    /// The `MultiplexedCircuit` is still alive.
    Draining,
    /// The circuit is fully closed — `MultiplexedCircuit::close()` was called.
    Closed,
    /// The circuit failed during establishment or health check.
    Failed,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Candidate => write!(f, "Candidate"),
            CircuitState::Healthy => write!(f, "Healthy"),
            CircuitState::Active => write!(f, "Active"),
            CircuitState::Draining => write!(f, "Draining"),
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Failed => write!(f, "Failed"),
        }
    }
}

/// A tracked circuit in the registry, owning the live `MultiplexedCircuit`.
#[derive(Debug)]
struct TrackedCircuit {
    /// The circuit's unique ID (fid).
    circuit_id: CircuitId,
    /// The route ID this circuit was established on.
    route_id: RouteId,
    /// The hop sequence.
    hops: Vec<PeerId>,
    /// Current lifecycle state.
    state: CircuitState,
    /// When the circuit was created.
    created_at: Instant,
    /// When the circuit entered its current state.
    state_changed_at: Instant,
    /// When the circuit entered DRAINING (if applicable).
    draining_since: Option<Instant>,
    /// The drain timeout for this circuit.
    drain_timeout: Duration,
    /// **N2.5-R.3.1** — The live `MultiplexedCircuit`, owned by the registry.
    /// Present when the circuit is Candidate, Healthy, Active, or Draining.
    /// `None` when the circuit is Closed or Failed (the circuit has been
    /// closed/dropped).
    circuit: Option<MultiplexedCircuit>,
}

impl TrackedCircuit {
    fn new(circuit_id: CircuitId, route_id: RouteId, hops: Vec<PeerId>, drain_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            circuit_id,
            route_id,
            hops,
            state: CircuitState::Candidate,
            created_at: now,
            state_changed_at: now,
            draining_since: None,
            drain_timeout,
            circuit: None,
        }
    }

    fn transition(&mut self, new_state: CircuitState) {
        if self.state != new_state {
            self.state = new_state;
            self.state_changed_at = Instant::now();
            if new_state == CircuitState::Draining {
                self.draining_since = Some(Instant::now());
            }
        }
    }

    fn is_drain_timeout_expired(&self) -> bool {
        match self.draining_since {
            Some(since) => Instant::now().duration_since(since) >= self.drain_timeout,
            None => false,
        }
    }
}

/// The authoritative circuit lifecycle registry.
///
/// This is the single source of truth for circuit state AND circuit ownership.
/// The registry owns the live `MultiplexedCircuit` handles for Active and
/// Draining circuits. When a circuit is closed, its `MultiplexedCircuit` is
/// closed via `close()` and dropped.
///
/// ## Invariants
///
/// - At most one circuit in `Active` state at any time.
/// - When a new circuit becomes `Active`, the previous active circuit
///   transitions to `Draining` and **remains alive**.
/// - A `Draining` circuit accepts no new streams but its existing streams
///   continue to function (the background reader is still running).
/// - When `drain_timeout` expires, the draining circuit is closed via
///   `MultiplexedCircuit::close()` and transitions to `Closed`.
pub struct CircuitRegistry {
    /// All tracked circuits, keyed by CircuitId.
    circuits: HashMap<CircuitId, TrackedCircuit>,
    /// The currently active circuit ID (if any).
    active_circuit_id: Option<CircuitId>,
    /// Default drain timeout for new circuits.
    default_drain_timeout: Duration,
}

impl CircuitRegistry {
    /// Create a new registry with the default drain timeout (60 seconds).
    #[must_use]
    pub fn new() -> Self {
        Self::with_drain_timeout(Duration::from_secs(60))
    }

    /// Create a new registry with a custom drain timeout.
    #[must_use]
    pub fn with_drain_timeout(drain_timeout: Duration) -> Self {
        Self {
            circuits: HashMap::new(),
            active_circuit_id: None,
            default_drain_timeout: drain_timeout,
        }
    }

    /// Register a new candidate circuit with its live `MultiplexedCircuit`.
    ///
    /// Called immediately after `MultiplexedCircuit::establish()` succeeds,
    /// BEFORE health check. The registry takes ownership of the circuit.
    ///
    /// Returns the `CircuitId` for future reference.
    pub fn register_candidate(
        &mut self,
        circuit: MultiplexedCircuit,
        route_id: RouteId,
        hops: Vec<PeerId>,
    ) -> CircuitId {
        let circuit_id = circuit.circuit_fid();
        let mut tracked = TrackedCircuit::new(circuit_id, route_id, hops, self.default_drain_timeout);
        tracked.circuit = Some(circuit);
        self.circuits.insert(circuit_id, tracked);
        circuit_id
    }

    /// Mark a candidate circuit as healthy (health check passed).
    ///
    /// # Errors
    /// Returns `Err` if the circuit is not found or not in `Candidate` state.
    pub fn mark_healthy(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
        if circuit.state != CircuitState::Candidate {
            return Err(format!("circuit {:?} is {:?}, not Candidate", circuit_id, circuit.state));
        }
        circuit.transition(CircuitState::Healthy);
        Ok(())
    }

    /// Promote a healthy circuit to active.
    ///
    /// The previous active circuit (if any) transitions to `Draining`
    /// and **remains alive** — its `MultiplexedCircuit` is retained.
    ///
    /// # Errors
    /// Returns `Err` if the circuit is not found or not in `Healthy` state.
    pub fn promote_to_active(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        // Check the circuit exists and is Healthy.
        {
            let circuit = self.circuits.get(circuit_id)
                .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
            if circuit.state != CircuitState::Healthy {
                return Err(format!("circuit {:?} is {:?}, not Healthy", circuit_id, circuit.state));
            }
        }

        // Transition the previous active circuit to Draining.
        // The old circuit's MultiplexedCircuit is NOT dropped — it stays
        // in the registry as a Draining circuit.
        if let Some(old_id) = self.active_circuit_id.take() {
            if let Some(old_circuit) = self.circuits.get_mut(&old_id) {
                old_circuit.transition(CircuitState::Draining);
            }
        }

        // Promote the new circuit.
        if let Some(circuit) = self.circuits.get_mut(circuit_id) {
            circuit.transition(CircuitState::Active);
        }
        self.active_circuit_id = Some(*circuit_id);
        Ok(())
    }

    /// Mark a circuit as failed (establishment or health check failed).
    ///
    /// The circuit's `MultiplexedCircuit` is closed and dropped.
    ///
    /// # Errors
    /// Returns `Err` if the circuit is not found.
    pub fn mark_failed(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
        // Close and drop the circuit if it's still alive.
        if let Some(mut c) = circuit.circuit.take() {
            // Use tokio::block_on or spawn — actually, close() is async.
            // For now, we just drop the circuit. Its Drop impl aborts the
            // background reader, which marks all streams as closed.
            drop(c);
        }
        circuit.transition(CircuitState::Failed);
        Ok(())
    }

    /// Mark a circuit as closed.
    ///
    /// The circuit's `MultiplexedCircuit` is closed via `close()` and dropped.
    /// This should be called when the circuit's stream count reaches zero
    /// or the drain timeout expires.
    ///
    /// # Errors
    /// Returns `Err` if the circuit is not found.
    pub async fn mark_closed(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
        // Close the circuit properly (marks all streams closed, aborts reader).
        if let Some(mut c) = circuit.circuit.take() {
            c.close().await;
        }
        circuit.transition(CircuitState::Closed);
        Ok(())
    }

    /// Returns the active circuit ID (if any).
    #[must_use]
    pub fn active_circuit_id(&self) -> Option<CircuitId> {
        self.active_circuit_id
    }

    /// Returns a mutable reference to the active circuit's `MultiplexedCircuit`.
    ///
    /// New streams MUST be opened on the active circuit. Returns `None` if
    /// there is no active circuit.
    pub fn active_circuit_mut(&mut self) -> Option<&mut MultiplexedCircuit> {
        let active_id = self.active_circuit_id?;
        self.circuits.get_mut(&active_id).and_then(|c| c.circuit.as_mut())
    }

    /// Returns the state of a circuit.
    #[must_use]
    pub fn circuit_state(&self, circuit_id: &CircuitId) -> Option<CircuitState> {
        self.circuits.get(circuit_id).map(|c| c.state)
    }

    /// Returns the route_id of a circuit.
    #[must_use]
    pub fn circuit_route_id(&self, circuit_id: &CircuitId) -> Option<RouteId> {
        self.circuits.get(circuit_id).map(|c| c.route_id)
    }

    /// Returns the hops of a circuit.
    #[must_use]
    pub fn circuit_hops(&self, circuit_id: &CircuitId) -> Option<&[PeerId]> {
        self.circuits.get(circuit_id).map(|c| c.hops.as_slice())
    }

    /// Returns all circuit IDs in a given state.
    pub fn circuits_in_state(&self, state: CircuitState) -> Vec<CircuitId> {
        self.circuits
            .iter()
            .filter(|(_, c)| c.state == state)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns the number of draining circuits.
    #[must_use]
    pub fn draining_count(&self) -> usize {
        self.circuits_in_state(CircuitState::Draining).len()
    }

    /// Check for drain timeouts and close expired circuits.
    ///
    /// Returns the circuit IDs that were force-closed. This method
    /// actually calls `MultiplexedCircuit::close()` on expired circuits.
    pub async fn check_drain_timeouts(&mut self) -> Vec<CircuitId> {
        let mut expired = Vec::new();
        for (id, circuit) in &self.circuits {
            if circuit.state == CircuitState::Draining && circuit.is_drain_timeout_expired() {
                expired.push(*id);
            }
        }
        for id in &expired {
            // Actually close the circuit.
            self.mark_closed(id).await.ok();
        }
        expired
    }

    /// **N2.5-R.3.2** — Reap draining circuits.
    ///
    /// This is the lifecycle maintenance method. It should be called
    /// periodically by the runtime (e.g., after stream operations or
    /// on a timer).
    ///
    /// For each `Draining` circuit:
    /// 1. Inspect its actual `MultiplexedCircuit::stream_count()`.
    /// 2. If stream_count == 0: close the circuit and transition to `Closed`.
    /// 3. If drain timeout has expired: close the circuit (terminating
    ///    any remaining streams) and transition to `Closed`.
    /// 4. Otherwise: leave it alive (existing streams continue).
    ///
    /// Returns the circuit IDs that were closed.
    ///
    /// ## Invariants
    ///
    /// - Only `Draining` circuits are eligible for closure.
    /// - `Active` circuits are never closed by this method.
    /// - `Candidate` circuits are never closed by this method.
    /// - A draining circuit with active streams remains alive unless
    ///   the drain timeout has expired.
    pub async fn reap_draining(&mut self) -> Vec<CircuitId> {
        let mut to_close = Vec::new();

        // Collect IDs of circuits that need closing.
        for (id, tracked) in &self.circuits {
            if tracked.state != CircuitState::Draining {
                continue;
            }

            // Check drain timeout first.
            if tracked.is_drain_timeout_expired() {
                to_close.push(*id);
                continue;
            }

            // Check actual stream count.
            if let Some(circuit) = &tracked.circuit {
                let count = circuit.stream_count().await;
                if count == 0 {
                    to_close.push(*id);
                }
            } else {
                // No circuit handle — shouldn't happen for Draining, but
                // if it does, mark as closed.
                to_close.push(*id);
            }
        }

        // Actually close the circuits.
        for id in &to_close {
            self.mark_closed(id).await.ok();
        }

        to_close
    }

    /// Returns the number of tracked circuits (all states).
    #[must_use]
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Returns the drain timeout for the registry.
    #[must_use]
    pub fn drain_timeout(&self) -> Duration {
        self.default_drain_timeout
    }
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CircuitRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitRegistry")
            .field("circuit_count", &self.circuits.len())
            .field("active_circuit_id", &self.active_circuit_id)
            .field("draining_count", &self.draining_count())
            .field("drain_timeout", &self.default_drain_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_candidate_creates_entry() {
        let mut reg = CircuitRegistry::new();
        // Can't easily create a real MultiplexedCircuit in a unit test,
        // so we test the metadata-only paths.
        let mut tracked = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![[3u8; 32]], Duration::from_secs(60));
        tracked.circuit = None; // Simulate no circuit for unit test.
        reg.circuits.insert([1u8; 8], tracked);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Candidate));
    }

    #[test]
    fn mark_healthy_transitions() {
        let mut reg = CircuitRegistry::new();
        let mut tracked = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_secs(60));
        tracked.circuit = None;
        reg.circuits.insert([1u8; 8], tracked);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Healthy));
    }

    #[test]
    fn promote_to_active_transitions_old_to_draining() {
        let mut reg = CircuitRegistry::new();
        let mut tracked1 = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_secs(60));
        tracked1.circuit = None;
        reg.circuits.insert([1u8; 8], tracked1);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();
        assert_eq!(reg.active_circuit_id(), Some([1u8; 8]));
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Active));

        // Register a second circuit.
        let mut tracked2 = TrackedCircuit::new([2u8; 8], [3u8; 32], vec![], Duration::from_secs(60));
        tracked2.circuit = None;
        reg.circuits.insert([2u8; 8], tracked2);
        reg.mark_healthy(&[2u8; 8]).unwrap();
        reg.promote_to_active(&[2u8; 8]).unwrap();

        // Old circuit is now Draining.
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Draining));
        assert_eq!(reg.active_circuit_id(), Some([2u8; 8]));
        assert_eq!(reg.draining_count(), 1);
    }

    #[test]
    fn mark_failed_transitions() {
        let mut reg = CircuitRegistry::new();
        let mut tracked = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_secs(60));
        tracked.circuit = None;
        reg.circuits.insert([1u8; 8], tracked);
        reg.mark_failed(&[1u8; 8]).unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Failed));
    }

    #[tokio::test]
    async fn mark_closed_transitions() {
        let mut reg = CircuitRegistry::new();
        let mut tracked = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_secs(60));
        tracked.circuit = None;
        reg.circuits.insert([1u8; 8], tracked);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();
        reg.mark_closed(&[1u8; 8]).await.unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Closed));
    }

    #[tokio::test]
    async fn drain_timeout_expires() {
        let mut reg = CircuitRegistry::with_drain_timeout(Duration::from_millis(10));
        let mut tracked1 = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_millis(10));
        tracked1.circuit = None;
        reg.circuits.insert([1u8; 8], tracked1);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();

        // Register second circuit and promote.
        let mut tracked2 = TrackedCircuit::new([2u8; 8], [3u8; 32], vec![], Duration::from_millis(10));
        tracked2.circuit = None;
        reg.circuits.insert([2u8; 8], tracked2);
        reg.mark_healthy(&[2u8; 8]).unwrap();
        reg.promote_to_active(&[2u8; 8]).unwrap();

        // First circuit is draining.
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Draining));

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(15));

        // Check timeouts — actually closes the circuit.
        let expired = reg.check_drain_timeouts().await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], [1u8; 8]);
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Closed));
    }

    #[test]
    fn at_most_one_active_circuit() {
        let mut reg = CircuitRegistry::new();
        let mut tracked1 = TrackedCircuit::new([1u8; 8], [2u8; 32], vec![], Duration::from_secs(60));
        tracked1.circuit = None;
        reg.circuits.insert([1u8; 8], tracked1);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();

        let mut tracked2 = TrackedCircuit::new([2u8; 8], [3u8; 32], vec![], Duration::from_secs(60));
        tracked2.circuit = None;
        reg.circuits.insert([2u8; 8], tracked2);
        reg.mark_healthy(&[2u8; 8]).unwrap();
        reg.promote_to_active(&[2u8; 8]).unwrap();

        // Only circuit 2 is active.
        let active = reg.circuits_in_state(CircuitState::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], [2u8; 8]);
    }

    #[test]
    fn circuit_route_id_and_hops() {
        let mut reg = CircuitRegistry::new();
        let route_id = [42u8; 32];
        let hops = vec![[1u8; 32], [2u8; 32]];
        let mut tracked = TrackedCircuit::new([1u8; 8], route_id, hops.clone(), Duration::from_secs(60));
        tracked.circuit = None;
        reg.circuits.insert([1u8; 8], tracked);

        assert_eq!(reg.circuit_route_id(&[1u8; 8]), Some(route_id));
        assert_eq!(reg.circuit_hops(&[1u8; 8]), Some(hops.as_slice()));
    }

    #[test]
    fn route_id_and_circuit_id_are_distinct() {
        let mut reg = CircuitRegistry::new();
        let route_id = [42u8; 32];
        let circuit_id = [99u8; 8];
        let mut tracked = TrackedCircuit::new(circuit_id, route_id, vec![], Duration::from_secs(60));
        tracked.circuit = None;
        reg.circuits.insert(circuit_id, tracked);

        // CircuitId != RouteId (different types, different values).
        assert_ne!(circuit_id, [route_id[0]; 8]);
        assert_eq!(reg.circuit_route_id(&circuit_id), Some(route_id));
    }
}

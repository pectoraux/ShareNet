//! **N2.5-R.3 — Circuit Lifecycle Management.**
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
//! - A DRAINING circuit accepts no new streams but existing streams remain valid.
//! - When a draining circuit's stream count reaches zero (or drain timeout
//!   expires), it transitions to CLOSED.
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
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A unique identifier for a circuit instance.
///
/// This is NOT the same as `RouteId` — multiple circuits may use the same
/// route. The CircuitId combines the route's `fid` (frame ID) with the
/// client's NodeId to create a scoped unique identifier.
pub type CircuitId = [u8; 8];

/// The lifecycle state of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitState {
    /// The circuit is being established (SNP-IK handshake in progress).
    Candidate,
    /// The circuit is established and health-verified, but not yet active.
    Healthy,
    /// The circuit is the active circuit for new streams.
    Active,
    /// The circuit is draining — no new streams, existing streams continue.
    Draining,
    /// The circuit is fully closed — no streams remain.
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

/// A tracked circuit in the registry.
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
    /// Whether the circuit has been disposed (MultiplexedCircuit dropped).
    disposed: bool,
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
            disposed: false,
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
/// This is the single source of truth for circuit state. The optimizer's
/// `current_route` tracks which *route* is active; the registry tracks which
/// *circuit* is active and the lifecycle of all circuits (including draining
/// ones from prior migrations).
///
/// ## Invariants
///
/// - At most one circuit in `Active` state at any time.
/// - When a new circuit becomes `Active`, the previous active circuit
///   transitions to `Draining`.
/// - A `Draining` circuit accepts no new streams.
/// - When `drain_timeout` expires, remaining streams are terminated and the
///   circuit transitions to `Closed`.
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

    /// Register a new candidate circuit.
    ///
    /// Called when a circuit is established but not yet committed as active.
    pub fn register_candidate(
        &mut self,
        circuit_id: CircuitId,
        route_id: RouteId,
        hops: Vec<PeerId>,
    ) {
        let tracked = TrackedCircuit::new(circuit_id, route_id, hops, self.default_drain_timeout);
        self.circuits.insert(circuit_id, tracked);
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
    /// The previous active circuit (if any) transitions to `Draining`.
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
    /// # Errors
    /// Returns `Err` if the circuit is not found.
    pub fn mark_failed(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
        circuit.transition(CircuitState::Failed);
        Ok(())
    }

    /// Mark a circuit as closed (all streams gone or drain timeout expired).
    ///
    /// # Errors
    /// Returns `Err` if the circuit is not found.
    pub fn mark_closed(&mut self, circuit_id: &CircuitId) -> Result<(), String> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or_else(|| format!("circuit {:?} not found", circuit_id))?;
        circuit.transition(CircuitState::Closed);
        circuit.disposed = true;
        Ok(())
    }

    /// Returns the active circuit ID (if any).
    #[must_use]
    pub fn active_circuit_id(&self) -> Option<CircuitId> {
        self.active_circuit_id
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

    /// Returns true if any circuit's drain timeout has expired.
    /// Returns the circuit IDs that need to be force-closed.
    pub fn check_drain_timeouts(&mut self) -> Vec<CircuitId> {
        let mut expired = Vec::new();
        for (id, circuit) in &self.circuits {
            if circuit.state == CircuitState::Draining && circuit.is_drain_timeout_expired() {
                expired.push(*id);
            }
        }
        for id in &expired {
            if let Some(circuit) = self.circuits.get_mut(id) {
                circuit.transition(CircuitState::Closed);
                circuit.disposed = true;
            }
        }
        expired
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
        reg.register_candidate([1u8; 8], [2u8; 32], vec![[3u8; 32]]);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Candidate));
    }

    #[test]
    fn mark_healthy_transitions() {
        let mut reg = CircuitRegistry::new();
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Healthy));
    }

    #[test]
    fn promote_to_active_transitions_old_to_draining() {
        let mut reg = CircuitRegistry::new();
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();
        assert_eq!(reg.active_circuit_id(), Some([1u8; 8]));
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Active));

        // Register a second circuit.
        reg.register_candidate([2u8; 8], [3u8; 32], vec![]);
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
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_failed(&[1u8; 8]).unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Failed));
    }

    #[test]
    fn mark_closed_transitions() {
        let mut reg = CircuitRegistry::new();
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();
        reg.mark_closed(&[1u8; 8]).unwrap();
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Closed));
    }

    #[test]
    fn drain_timeout_expires() {
        let mut reg = CircuitRegistry::with_drain_timeout(Duration::from_millis(10));
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();

        // Register second circuit and promote.
        reg.register_candidate([2u8; 8], [3u8; 32], vec![]);
        reg.mark_healthy(&[2u8; 8]).unwrap();
        reg.promote_to_active(&[2u8; 8]).unwrap();

        // First circuit is draining.
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Draining));

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(15));

        // Check timeouts.
        let expired = reg.check_drain_timeouts();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], [1u8; 8]);
        assert_eq!(reg.circuit_state(&[1u8; 8]), Some(CircuitState::Closed));
    }

    #[test]
    fn at_most_one_active_circuit() {
        let mut reg = CircuitRegistry::new();
        reg.register_candidate([1u8; 8], [2u8; 32], vec![]);
        reg.mark_healthy(&[1u8; 8]).unwrap();
        reg.promote_to_active(&[1u8; 8]).unwrap();

        reg.register_candidate([2u8; 8], [3u8; 32], vec![]);
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
        reg.register_candidate([1u8; 8], route_id, hops.clone());

        assert_eq!(reg.circuit_route_id(&[1u8; 8]), Some(route_id));
        assert_eq!(reg.circuit_hops(&[1u8; 8]), Some(hops.as_slice()));
    }

    #[test]
    fn route_id_and_circuit_id_are_distinct() {
        let mut reg = CircuitRegistry::new();
        let route_id = [42u8; 32];
        let circuit_id = [99u8; 8];
        reg.register_candidate(circuit_id, route_id, vec![]);

        // CircuitId != RouteId (different types, different values).
        assert_ne!(circuit_id, [route_id[0]; 8]);
        assert_eq!(reg.circuit_route_id(&circuit_id), Some(route_id));
    }
}

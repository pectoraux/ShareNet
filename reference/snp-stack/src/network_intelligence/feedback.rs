//! **N2.4.4 — Route Quality Feedback.**
//!
//! Every circuit completion produces a [`CircuitResult`] that is fed back
//! into the [`ObservationStore`], updating the peer's observations.
//!
//! ## Feedback loop
//!
//! ```text
//! Circuit established
//!         ↓
//! Data flows (bytes, latency samples)
//!         ↓
//! Circuit completes (success or failure)
//!         ↓
//! CircuitResult
//!         ↓
//! ObservationStore.update()
//!         ↓
//! PeerObservation updated
//!         ↓
//! BestScoreSelector picks better gateway next time
//! ```

use super::observations::{ObservationStore, PeerId};
use std::time::Duration;

/// The outcome of a circuit — success or failure with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitOutcome {
    /// The circuit was established and used successfully.
    Success,
    /// The circuit failed to establish or failed during use.
    Failed(CircuitFailureReason),
}

/// Why a circuit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitFailureReason {
    /// The relay was unreachable (TCP connect failed, SNP-IK handshake failed).
    RelayUnreachable,
    /// The gateway was unreachable.
    GatewayUnreachable,
    /// The circuit link broke mid-transfer.
    LinkError,
    /// The gateway rejected the stream (e.g., SSRF, port policy).
    StreamRejected,
    /// The TCP connection to the destination failed.
    TcpConnectFailed,
    /// A protocol violation occurred (bad sequence, wrong frame, etc.).
    ProtocolViolation,
    /// The circuit timed out.
    Timeout,
    /// An unknown error.
    Unknown,
}

/// The result of a completed circuit. Fed back into the observation store.
#[derive(Debug, Clone)]
pub struct CircuitResult {
    /// The gateway's NodeId.
    pub gateway_id: PeerId,
    /// The relay NodeIds in the route (first hop, second hop, etc.).
    pub relay_ids: Vec<PeerId>,
    /// The outcome (success or failure + reason).
    pub outcome: CircuitOutcome,
    /// The total duration the circuit was active.
    pub duration: Duration,
    /// Total bytes sent through the circuit.
    pub bytes_sent: u64,
    /// Total bytes received through the circuit.
    pub bytes_received: u64,
    /// The last measured latency (milliseconds), if any.
    pub latency_ms: Option<f64>,
}

impl CircuitResult {
    /// Create a successful circuit result.
    #[must_use]
    pub fn success(gateway_id: PeerId) -> Self {
        Self {
            gateway_id,
            relay_ids: Vec::new(),
            outcome: CircuitOutcome::Success,
            duration: Duration::ZERO,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
        }
    }

    /// Create a failed circuit result.
    #[must_use]
    pub fn failed(gateway_id: PeerId, reason: CircuitFailureReason) -> Self {
        Self {
            gateway_id,
            relay_ids: Vec::new(),
            outcome: CircuitOutcome::Failed(reason),
            duration: Duration::ZERO,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
        }
    }

    /// Set the relay IDs.
    #[must_use]
    pub fn with_relays(mut self, relay_ids: Vec<PeerId>) -> Self {
        self.relay_ids = relay_ids;
        self
    }

    /// Set the duration.
    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set the byte counts.
    #[must_use]
    pub fn with_bytes(mut self, sent: u64, received: u64) -> Self {
        self.bytes_sent = sent;
        self.bytes_received = received;
        self
    }

    /// Set the latency.
    #[must_use]
    pub fn with_latency(mut self, latency_ms: f64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Returns `true` if the circuit was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, CircuitOutcome::Success)
    }

    /// Apply this result to an observation store, updating the observations
    /// for the gateway and all relays in the route.
    ///
    /// This is the feedback entry point — call this when a circuit completes.
    pub fn apply_to(&self, store: &mut ObservationStore) {
        // Update the gateway's observation.
        match &self.outcome {
            CircuitOutcome::Success => {
                store.record_circuit_success(&self.gateway_id);
                store.record_bytes(&self.gateway_id, self.bytes_sent + self.bytes_received);
                if let Some(latency) = self.latency_ms {
                    store.record_latency(&self.gateway_id, latency);
                }
                store.record_seen(&self.gateway_id);
            }
            CircuitOutcome::Failed(_) => {
                store.record_circuit_failure(&self.gateway_id);
            }
        }

        // Update relay observations.
        for relay_id in &self.relay_ids {
            match &self.outcome {
                CircuitOutcome::Success => {
                    store.record_seen(relay_id);
                    store.record_bytes(relay_id, self.bytes_sent + self.bytes_received);
                    if let Some(latency) = self.latency_ms {
                        store.record_latency(relay_id, latency);
                    }
                }
                CircuitOutcome::Failed(reason) => {
                    // Only record relay failure if the relay was the cause.
                    match reason {
                        CircuitFailureReason::RelayUnreachable => {
                            store.record_circuit_failure(relay_id);
                        }
                        _ => {
                            // The relay might be fine — the failure was elsewhere.
                            // Still record that we saw it.
                            store.record_seen(relay_id);
                        }
                    }
                }
            }
        }

        // Close the circuit (decrement active count) for the gateway.
        if matches!(self.outcome, CircuitOutcome::Success) {
            store.record_circuit_closed(&self.gateway_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_result_is_success() {
        let r = CircuitResult::success([1u8; 32]);
        assert!(r.is_success());
    }

    #[test]
    fn failed_result_is_not_success() {
        let r = CircuitResult::failed([1u8; 32], CircuitFailureReason::Timeout);
        assert!(!r.is_success());
    }

    #[test]
    fn apply_success_updates_observations() {
        let mut store = ObservationStore::new();
        let result = CircuitResult::success([1u8; 32])
            .with_bytes(1000, 2000)
            .with_latency(50.0);

        result.apply_to(&mut store);

        let obs = store.get(&[1u8; 32]).unwrap();
        assert_eq!(obs.successful_circuits, 1);
        assert_eq!(obs.bytes_forwarded, 3000);
        assert_eq!(obs.latency(), Some(50.0));
        assert_eq!(obs.active_circuits, 0); // closed after success
    }

    #[test]
    fn apply_failure_updates_observations() {
        let mut store = ObservationStore::new();
        let result = CircuitResult::failed([1u8; 32], CircuitFailureReason::Timeout);

        result.apply_to(&mut store);

        let obs = store.get(&[1u8; 32]).unwrap();
        assert_eq!(obs.failed_circuits, 1);
        assert_eq!(obs.successful_circuits, 0);
    }

    #[test]
    fn apply_failure_with_relay_blame() {
        let mut store = ObservationStore::new();
        let result = CircuitResult::failed([1u8; 32], CircuitFailureReason::RelayUnreachable)
            .with_relays(vec![[2u8; 32]]);

        result.apply_to(&mut store);

        // Relay should be blamed.
        let relay_obs = store.get(&[2u8; 32]).unwrap();
        assert_eq!(relay_obs.failed_circuits, 1);
    }

    #[test]
    fn apply_success_updates_relays() {
        let mut store = ObservationStore::new();
        let result = CircuitResult::success([1u8; 32])
            .with_relays(vec![[2u8; 32], [3u8; 32]])
            .with_bytes(500, 500)
            .with_latency(30.0);

        result.apply_to(&mut store);

        for relay_id in &[[2u8; 32], [3u8; 32]] {
            let obs = store.get(relay_id).unwrap();
            assert_eq!(obs.bytes_forwarded, 1000);
            assert_eq!(obs.latency(), Some(30.0));
            assert!(obs.last_seen.is_some());
        }
    }

    #[test]
    fn builder_chains() {
        let r = CircuitResult::success([1u8; 32])
            .with_relays(vec![[2u8; 32]])
            .with_duration(Duration::from_secs(10))
            .with_bytes(100, 200)
            .with_latency(25.0);

        assert_eq!(r.relay_ids, vec![[2u8; 32]]);
        assert_eq!(r.duration, Duration::from_secs(10));
        assert_eq!(r.bytes_sent, 100);
        assert_eq!(r.bytes_received, 200);
        assert_eq!(r.latency_ms, Some(25.0));
    }
}

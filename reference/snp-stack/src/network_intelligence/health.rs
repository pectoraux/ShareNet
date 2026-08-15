//! **N2.4.5 — Circuit Health Monitoring.**
//!
//! [`CircuitMonitor`] tracks the health of an active circuit and transitions
//! between [`CircuitHealth`] states based on observed conditions.
//!
//! ## State machine
//!
//! ```text
//! Healthy
//!    │
//!    │ latency increases / packet loss rises
//!    ↓
//! Degraded
//!    │
//!    │ failure threshold reached / link error
//!    ↓
//! Failed
//! ```
//!
//! The monitor is per-circuit. The caller polls [`CircuitMonitor::check`]
//! periodically (e.g., every 5 seconds) with the latest latency/loss
//! measurements, and the monitor returns the current health state.

use std::time::{Duration, Instant};

/// The health state of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitHealth {
    /// The circuit is healthy — latency is low, no packet loss, no errors.
    Healthy,
    /// The circuit is degraded — latency is elevated or some packet loss,
    /// but the circuit is still functional. The client should consider
    /// migrating soon.
    Degraded,
    /// The circuit has failed — the link is broken or conditions are
    /// unacceptable. The client must migrate immediately.
    Failed,
}

impl CircuitHealth {
    /// Returns `true` if the circuit is usable (Healthy or Degraded).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, CircuitHealth::Healthy | CircuitHealth::Degraded)
    }

    /// Returns `true` if the circuit has failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, CircuitHealth::Failed)
    }
}

impl std::fmt::Display for CircuitHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitHealth::Healthy => write!(f, "Healthy"),
            CircuitHealth::Degraded => write!(f, "Degraded"),
            CircuitHealth::Failed => write!(f, "Failed"),
        }
    }
}

/// Configuration thresholds for circuit health monitoring.
#[derive(Debug, Clone)]
pub struct HealthThresholds {
    /// Latency above this (milliseconds) triggers Degraded.
    pub latency_degraded_ms: f64,
    /// Latency above this (milliseconds) triggers Failed.
    pub latency_failed_ms: f64,
    /// Packet loss above this fraction triggers Degraded.
    pub loss_degraded: f64,
    /// Packet loss above this fraction triggers Failed.
    pub loss_failed: f64,
    /// How long the circuit can be idle (no data) before being considered Failed.
    pub idle_timeout: Duration,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            latency_degraded_ms: 200.0,
            latency_failed_ms: 1000.0,
            loss_degraded: 0.05,  // 5%
            loss_failed: 0.20,    // 20%
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// A monitor for a single circuit's health.
///
/// The monitor tracks:
/// - The current health state.
/// - The last time data was received (for idle detection).
/// - Consecutive error count (for failure detection).
///
/// The caller calls [`check`] periodically with the latest measurements.
pub struct CircuitMonitor {
    /// The current health state.
    health: CircuitHealth,
    /// When the monitor was created.
    started_at: Instant,
    /// When data was last received.
    last_data_at: Instant,
    /// Number of consecutive errors since the last success.
    consecutive_errors: u32,
    /// The thresholds.
    thresholds: HealthThresholds,
}

impl CircuitMonitor {
    /// Create a new monitor for a circuit that just started.
    #[must_use]
    pub fn new(thresholds: HealthThresholds) -> Self {
        let now = Instant::now();
        Self {
            health: CircuitHealth::Healthy,
            started_at: now,
            last_data_at: now,
            consecutive_errors: 0,
            thresholds,
        }
    }

    /// Create a new monitor with default thresholds.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(HealthThresholds::default())
    }

    /// Record that data was received (resets idle timer and error count).
    pub fn record_data(&mut self) {
        self.last_data_at = Instant::now();
        self.consecutive_errors = 0;
        if self.health == CircuitHealth::Degraded {
            // Recovery from degraded → healthy.
            self.health = CircuitHealth::Healthy;
        }
    }

    /// Record a latency sample and packet loss fraction. Returns the new
    /// health state.
    pub fn record_sample(&mut self, latency_ms: f64, packet_loss: f64) -> CircuitHealth {
        self.last_data_at = Instant::now();

        // Determine the health based on the current sample.
        let new_health = if latency_ms >= self.thresholds.latency_failed_ms
            || packet_loss >= self.thresholds.loss_failed
        {
            CircuitHealth::Failed
        } else if latency_ms >= self.thresholds.latency_degraded_ms
            || packet_loss >= self.thresholds.loss_degraded
        {
            CircuitHealth::Degraded
        } else {
            CircuitHealth::Healthy
        };

        // Health can only worsen monotonically unless recovery is detected.
        // (Recovery is handled in record_data.)
        if new_health as u8 > self.health as u8 {
            self.health = new_health;
        }

        self.health
    }

    /// Record an error (e.g., a dropped frame, a timeout). Returns the new
    /// health state.
    pub fn record_error(&mut self) -> CircuitHealth {
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);

        // After 3 consecutive errors, degrade.
        if self.consecutive_errors >= 3 && self.health == CircuitHealth::Healthy {
            self.health = CircuitHealth::Degraded;
        }
        // After 5 consecutive errors, fail.
        if self.consecutive_errors >= 5 {
            self.health = CircuitHealth::Failed;
        }

        self.health
    }

    /// Check the current health state, accounting for idle timeout.
    /// Call this periodically (e.g., every 5 seconds).
    pub fn check(&mut self) -> CircuitHealth {
        // If already failed, stay failed.
        if self.health == CircuitHealth::Failed {
            return CircuitHealth::Failed;
        }

        // Check idle timeout.
        let idle = Instant::now().duration_since(self.last_data_at);
        if idle >= self.thresholds.idle_timeout {
            self.health = CircuitHealth::Failed;
        }

        self.health
    }

    /// Returns the current health state without modifying it.
    #[must_use]
    pub fn health(&self) -> CircuitHealth {
        self.health
    }

    /// Returns how long the circuit has been active.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        Instant::now().duration_since(self.started_at)
    }

    /// Returns the number of consecutive errors.
    #[must_use]
    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors
    }

    /// Reset the monitor to Healthy (e.g., after a successful migration).
    pub fn reset(&mut self) {
        self.health = CircuitHealth::Healthy;
        self.consecutive_errors = 0;
        let now = Instant::now();
        self.last_data_at = now;
        self.started_at = now;
    }
}

impl std::fmt::Debug for CircuitMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitMonitor")
            .field("health", &self.health)
            .field("consecutive_errors", &self.consecutive_errors)
            .field("uptime", &self.uptime())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy() {
        let monitor = CircuitMonitor::with_defaults();
        assert_eq!(monitor.health(), CircuitHealth::Healthy);
    }

    #[test]
    fn high_latency_degrades() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(50.0, 0.0); // healthy
        assert_eq!(monitor.health(), CircuitHealth::Healthy);
        monitor.record_sample(250.0, 0.0); // degraded
        assert_eq!(monitor.health(), CircuitHealth::Degraded);
    }

    #[test]
    fn very_high_latency_fails() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(1500.0, 0.0); // failed
        assert_eq!(monitor.health(), CircuitHealth::Failed);
    }

    #[test]
    fn high_packet_loss_fails() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(50.0, 0.25); // 25% loss → failed
        assert_eq!(monitor.health(), CircuitHealth::Failed);
    }

    #[test]
    fn errors_degrade_then_fail() {
        let mut monitor = CircuitMonitor::with_defaults();
        for _ in 0..3 {
            monitor.record_error();
        }
        assert_eq!(monitor.health(), CircuitHealth::Degraded);
        for _ in 0..2 {
            monitor.record_error();
        }
        assert_eq!(monitor.health(), CircuitHealth::Failed);
    }

    #[test]
    fn data_recovers_from_degraded() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(250.0, 0.0); // degraded
        assert_eq!(monitor.health(), CircuitHealth::Degraded);
        monitor.record_data(); // recovery
        assert_eq!(monitor.health(), CircuitHealth::Healthy);
    }

    #[test]
    fn data_does_not_recover_from_failed() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(1500.0, 0.0); // failed
        assert_eq!(monitor.health(), CircuitHealth::Failed);
        monitor.record_data(); // no recovery from failed
        assert_eq!(monitor.health(), CircuitHealth::Failed);
    }

    #[test]
    fn check_detects_idle_timeout() {
        let mut thresholds = HealthThresholds::default();
        thresholds.idle_timeout = Duration::from_millis(10);
        let mut monitor = CircuitMonitor::new(thresholds);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(monitor.check(), CircuitHealth::Failed);
    }

    #[test]
    fn reset_restores_healthy() {
        let mut monitor = CircuitMonitor::with_defaults();
        monitor.record_sample(1500.0, 0.0); // failed
        assert_eq!(monitor.health(), CircuitHealth::Failed);
        monitor.reset();
        assert_eq!(monitor.health(), CircuitHealth::Healthy);
    }

    #[test]
    fn health_is_usable() {
        assert!(CircuitHealth::Healthy.is_usable());
        assert!(CircuitHealth::Degraded.is_usable());
        assert!(!CircuitHealth::Failed.is_usable());
    }
}

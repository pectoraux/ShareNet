//! **N2.3.9 — Transport Metrics.**
//!
//! Lock-free atomic counters for observability of the Mode B transport layer.
//!
//! ## Design
//!
//! All counters use `AtomicU64` — no locks, no allocation, no blocking.
//! A single `Arc<TransportMetrics>` can be shared between the circuit,
//! streams, gateway, and background tasks.
//!
//! ## Metric Categories
//!
//! ### Circuit
//! - `circuits_active` — currently open circuits
//! - `circuits_created_total` — total circuits ever created
//! - `circuits_closed_total` — total circuits ever closed
//! - `circuit_bytes_sent` — total bytes sent through circuits
//! - `circuit_bytes_received` — total bytes received through circuits
//!
//! ### Streams
//! - `streams_active` — currently open streams
//! - `streams_opened_total` — total streams ever opened
//! - `streams_reset_total` — total streams reset (by either side)
//! - `streams_closed_total` — total streams cleanly closed
//!
//! ### Flow control
//! - `window_block_events` — times a send() blocked on credit exhaustion
//! - `credit_updates_sent` — WindowUpdate messages sent
//! - `credit_updates_received` — WindowUpdate messages received
//!
//! ### Failures
//! - `tcp_connect_failures` — gateway TCP connect failures
//! - `protocol_resets` — protocol violation resets
//! - `circuit_teardowns` — circuit teardowns (link errors, etc.)
//!
//! ## Usage
//!
//! ```ignore
//! let metrics = Arc::new(TransportMetrics::new());
//! metrics.circuit_created();
//! metrics.stream_opened();
//! metrics.bytes_sent(1024);
//! println!("{}", metrics.snapshot());
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Transport-level metrics with lock-free atomic counters.
///
/// All methods are `&self` — safe to call from multiple tasks concurrently.
#[derive(Debug)]
pub struct TransportMetrics {
    // ── Circuit ──────────────────────────────────────────────────────────
    circuits_active: AtomicU64,
    circuits_created_total: AtomicU64,
    circuits_closed_total: AtomicU64,
    circuit_bytes_sent: AtomicU64,
    circuit_bytes_received: AtomicU64,

    // ── Streams ──────────────────────────────────────────────────────────
    streams_active: AtomicU64,
    streams_opened_total: AtomicU64,
    streams_reset_total: AtomicU64,
    streams_closed_total: AtomicU64,

    // ── Flow control ─────────────────────────────────────────────────────
    window_block_events: AtomicU64,
    credit_updates_sent: AtomicU64,
    credit_updates_received: AtomicU64,

    // ── Failures ─────────────────────────────────────────────────────────
    tcp_connect_failures: AtomicU64,
    protocol_resets: AtomicU64,
    circuit_teardowns: AtomicU64,

    // ── Latency ──────────────────────────────────────────────────────────
    /// Total duration of all completed streams (in microseconds).
    /// Divided by `streams_closed_total` + `streams_reset_total` gives
    /// the average stream lifetime.
    stream_duration_micros_total: AtomicU64,
    /// Total time spent blocked on send credit exhaustion (in microseconds).
    /// Measures how long send() calls waited for WindowUpdate.
    send_blocked_micros_total: AtomicU64,
}

impl Default for TransportMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportMetrics {
    /// Create a new metrics instance with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            circuits_active: AtomicU64::new(0),
            circuits_created_total: AtomicU64::new(0),
            circuits_closed_total: AtomicU64::new(0),
            circuit_bytes_sent: AtomicU64::new(0),
            circuit_bytes_received: AtomicU64::new(0),
            streams_active: AtomicU64::new(0),
            streams_opened_total: AtomicU64::new(0),
            streams_reset_total: AtomicU64::new(0),
            streams_closed_total: AtomicU64::new(0),
            window_block_events: AtomicU64::new(0),
            credit_updates_sent: AtomicU64::new(0),
            credit_updates_received: AtomicU64::new(0),
            tcp_connect_failures: AtomicU64::new(0),
            protocol_resets: AtomicU64::new(0),
            circuit_teardowns: AtomicU64::new(0),
            stream_duration_micros_total: AtomicU64::new(0),
            send_blocked_micros_total: AtomicU64::new(0),
        }
    }

    // ── Circuit metrics ──────────────────────────────────────────────────

    /// Record a circuit creation.
    pub fn circuit_created(&self) {
        self.circuits_created_total.fetch_add(1, Ordering::Relaxed);
        self.circuits_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a circuit closure.
    pub fn circuit_closed(&self) {
        self.circuits_closed_total.fetch_add(1, Ordering::Relaxed);
        self.circuits_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes sent through a circuit.
    pub fn bytes_sent(&self, n: u64) {
        self.circuit_bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Record bytes received through a circuit.
    pub fn bytes_received(&self, n: u64) {
        self.circuit_bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Record a circuit teardown (link error, etc.).
    pub fn circuit_teardown(&self) {
        self.circuit_teardowns.fetch_add(1, Ordering::Relaxed);
    }

    // ── Stream metrics ───────────────────────────────────────────────────

    /// Record a stream opening.
    pub fn stream_opened(&self) {
        self.streams_opened_total.fetch_add(1, Ordering::Relaxed);
        self.streams_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a stream reset.
    pub fn stream_reset(&self) {
        self.streams_reset_total.fetch_add(1, Ordering::Relaxed);
        self.streams_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a stream clean close.
    pub fn stream_closed(&self) {
        self.streams_closed_total.fetch_add(1, Ordering::Relaxed);
        self.streams_active.fetch_sub(1, Ordering::Relaxed);
    }

    // ── Flow control metrics ─────────────────────────────────────────────

    /// Record a window block event (send() blocked on credit exhaustion).
    pub fn window_block(&self) {
        self.window_block_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a credit update sent (WindowUpdate message).
    pub fn credit_update_sent(&self) {
        self.credit_updates_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a credit update received (WindowUpdate message).
    pub fn credit_update_received(&self) {
        self.credit_updates_received.fetch_add(1, Ordering::Relaxed);
    }

    // ── Failure metrics ──────────────────────────────────────────────────

    /// Record a TCP connect failure at the gateway.
    pub fn tcp_connect_failure(&self) {
        self.tcp_connect_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a protocol violation reset.
    pub fn protocol_reset(&self) {
        self.protocol_resets.fetch_add(1, Ordering::Relaxed);
    }

    // ── Latency metrics ──────────────────────────────────────────────────

    /// Record the duration of a completed stream (in microseconds).
    /// Called when a stream is closed or reset.
    pub fn record_stream_duration(&self, duration: std::time::Duration) {
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;
        self.stream_duration_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    /// Record time spent blocked on send credit exhaustion.
    /// Called when send() wakes up after waiting for a WindowUpdate.
    pub fn record_send_blocked(&self, duration: std::time::Duration) {
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;
        self.send_blocked_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    // ── Snapshot ─────────────────────────────────────────────────────────

    /// Get the number of active circuits.
    #[must_use]
    pub fn circuits_active(&self) -> u64 {
        self.circuits_active.load(Ordering::Relaxed)
    }

    /// Get the total number of circuits created.
    #[must_use]
    pub fn circuits_created_total(&self) -> u64 {
        self.circuits_created_total.load(Ordering::Relaxed)
    }

    /// Get the total number of circuits closed.
    #[must_use]
    pub fn circuits_closed_total(&self) -> u64 {
        self.circuits_closed_total.load(Ordering::Relaxed)
    }

    /// Get the total bytes sent through circuits.
    #[must_use]
    pub fn circuit_bytes_sent(&self) -> u64 {
        self.circuit_bytes_sent.load(Ordering::Relaxed)
    }

    /// Get the total bytes received through circuits.
    #[must_use]
    pub fn circuit_bytes_received(&self) -> u64 {
        self.circuit_bytes_received.load(Ordering::Relaxed)
    }

    /// Get the number of active streams.
    #[must_use]
    pub fn streams_active(&self) -> u64 {
        self.streams_active.load(Ordering::Relaxed)
    }

    /// Get the total number of streams opened.
    #[must_use]
    pub fn streams_opened_total(&self) -> u64 {
        self.streams_opened_total.load(Ordering::Relaxed)
    }

    /// Get the total number of streams reset.
    #[must_use]
    pub fn streams_reset_total(&self) -> u64 {
        self.streams_reset_total.load(Ordering::Relaxed)
    }

    /// Get the total number of streams cleanly closed.
    #[must_use]
    pub fn streams_closed_total(&self) -> u64 {
        self.streams_closed_total.load(Ordering::Relaxed)
    }

    /// Get the number of window block events.
    #[must_use]
    pub fn window_block_events(&self) -> u64 {
        self.window_block_events.load(Ordering::Relaxed)
    }

    /// Get the total number of credit updates sent.
    #[must_use]
    pub fn credit_updates_sent(&self) -> u64 {
        self.credit_updates_sent.load(Ordering::Relaxed)
    }

    /// Get the total number of credit updates received.
    #[must_use]
    pub fn credit_updates_received(&self) -> u64 {
        self.credit_updates_received.load(Ordering::Relaxed)
    }

    /// Get the number of TCP connect failures.
    #[must_use]
    pub fn tcp_connect_failures(&self) -> u64 {
        self.tcp_connect_failures.load(Ordering::Relaxed)
    }

    /// Get the number of protocol resets.
    #[must_use]
    pub fn protocol_resets(&self) -> u64 {
        self.protocol_resets.load(Ordering::Relaxed)
    }

    /// Get the number of circuit teardowns.
    #[must_use]
    pub fn circuit_teardowns(&self) -> u64 {
        self.circuit_teardowns.load(Ordering::Relaxed)
    }

    /// Get total stream duration in microseconds (all completed streams).
    #[must_use]
    pub fn stream_duration_micros_total(&self) -> u64 {
        self.stream_duration_micros_total.load(Ordering::Relaxed)
    }

    /// Get the average stream duration in microseconds.
    /// Returns 0 if no streams have completed.
    #[must_use]
    pub fn avg_stream_duration_micros(&self) -> u64 {
        let completed = self.streams_closed_total() + self.streams_reset_total();
        if completed == 0 {
            return 0;
        }
        self.stream_duration_micros_total() / completed
    }

    /// Get total time spent blocked on send credit (in microseconds).
    #[must_use]
    pub fn send_blocked_micros_total(&self) -> u64 {
        self.send_blocked_micros_total.load(Ordering::Relaxed)
    }

    /// Take a human-readable snapshot of all metrics.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            circuits_active: self.circuits_active(),
            circuits_created_total: self.circuits_created_total(),
            circuits_closed_total: self.circuits_closed_total(),
            circuit_bytes_sent: self.circuit_bytes_sent(),
            circuit_bytes_received: self.circuit_bytes_received(),
            streams_active: self.streams_active(),
            streams_opened_total: self.streams_opened_total(),
            streams_reset_total: self.streams_reset_total(),
            streams_closed_total: self.streams_closed_total(),
            window_block_events: self.window_block_events(),
            credit_updates_sent: self.credit_updates_sent(),
            credit_updates_received: self.credit_updates_received(),
            tcp_connect_failures: self.tcp_connect_failures(),
            protocol_resets: self.protocol_resets(),
            circuit_teardowns: self.circuit_teardowns(),
            stream_duration_micros_total: self.stream_duration_micros_total(),
            avg_stream_duration_micros: self.avg_stream_duration_micros(),
            send_blocked_micros_total: self.send_blocked_micros_total(),
        }
    }
}

/// A point-in-time snapshot of all transport metrics.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub circuits_active: u64,
    pub circuits_created_total: u64,
    pub circuits_closed_total: u64,
    pub circuit_bytes_sent: u64,
    pub circuit_bytes_received: u64,
    pub streams_active: u64,
    pub streams_opened_total: u64,
    pub streams_reset_total: u64,
    pub streams_closed_total: u64,
    pub window_block_events: u64,
    pub credit_updates_sent: u64,
    pub credit_updates_received: u64,
    pub tcp_connect_failures: u64,
    pub protocol_resets: u64,
    pub circuit_teardowns: u64,
    pub stream_duration_micros_total: u64,
    pub avg_stream_duration_micros: u64,
    pub send_blocked_micros_total: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Transport Metrics ===")?;
        writeln!(f, "Circuit:")?;
        writeln!(f, "  circuits_active:         {}", self.circuits_active)?;
        writeln!(
            f,
            "  circuits_created_total:  {}",
            self.circuits_created_total
        )?;
        writeln!(
            f,
            "  circuits_closed_total:   {}",
            self.circuits_closed_total
        )?;
        writeln!(
            f,
            "  circuit_bytes_sent:      {} ({:.2} MB)",
            self.circuit_bytes_sent,
            self.circuit_bytes_sent as f64 / (1024.0 * 1024.0)
        )?;
        writeln!(
            f,
            "  circuit_bytes_received:  {} ({:.2} MB)",
            self.circuit_bytes_received,
            self.circuit_bytes_received as f64 / (1024.0 * 1024.0)
        )?;
        writeln!(f, "Streams:")?;
        writeln!(f, "  streams_active:          {}", self.streams_active)?;
        writeln!(
            f,
            "  streams_opened_total:    {}",
            self.streams_opened_total
        )?;
        writeln!(f, "  streams_reset_total:     {}", self.streams_reset_total)?;
        writeln!(
            f,
            "  streams_closed_total:    {}",
            self.streams_closed_total
        )?;
        writeln!(f, "Flow control:")?;
        writeln!(f, "  window_block_events:     {}", self.window_block_events)?;
        writeln!(f, "  credit_updates_sent:     {}", self.credit_updates_sent)?;
        writeln!(
            f,
            "  credit_updates_received: {}",
            self.credit_updates_received
        )?;
        writeln!(f, "Failures:")?;
        writeln!(
            f,
            "  tcp_connect_failures:    {}",
            self.tcp_connect_failures
        )?;
        writeln!(f, "  protocol_resets:         {}", self.protocol_resets)?;
        writeln!(f, "  circuit_teardowns:       {}", self.circuit_teardowns)?;
        writeln!(f, "Latency:")?;
        writeln!(
            f,
            "  stream_duration_total:   {} ({:.3}s)",
            self.stream_duration_micros_total,
            self.stream_duration_micros_total as f64 / 1_000_000.0
        )?;
        writeln!(
            f,
            "  avg_stream_duration:     {} ({:.3}ms)",
            self.avg_stream_duration_micros,
            self.avg_stream_duration_micros as f64 / 1000.0
        )?;
        writeln!(
            f,
            "  send_blocked_total:      {} ({:.3}s)",
            self.send_blocked_micros_total,
            self.send_blocked_micros_total as f64 / 1_000_000.0
        )?;
        Ok(())
    }
}

/// Helper to create an `Arc<TransportMetrics>` for sharing between tasks.
#[must_use]
pub fn shared_metrics() -> Arc<TransportMetrics> {
    Arc::new(TransportMetrics::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_start_at_zero() {
        let m = TransportMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.circuits_active, 0);
        assert_eq!(s.streams_active, 0);
        assert_eq!(s.circuit_bytes_sent, 0);
        assert_eq!(s.credit_updates_sent, 0);
    }

    #[test]
    fn circuit_lifecycle_tracked() {
        let m = TransportMetrics::new();
        m.circuit_created();
        assert_eq!(m.circuits_active(), 1);
        assert_eq!(m.circuits_created_total(), 1);
        m.circuit_closed();
        assert_eq!(m.circuits_active(), 0);
        assert_eq!(m.circuits_closed_total(), 1);
    }

    #[test]
    fn stream_lifecycle_tracked() {
        let m = TransportMetrics::new();
        m.stream_opened();
        m.stream_opened();
        assert_eq!(m.streams_active(), 2);
        assert_eq!(m.streams_opened_total(), 2);
        m.stream_reset();
        assert_eq!(m.streams_active(), 1);
        assert_eq!(m.streams_reset_total(), 1);
        m.stream_closed();
        assert_eq!(m.streams_active(), 0);
        assert_eq!(m.streams_closed_total(), 1);
    }

    #[test]
    fn bytes_tracked() {
        let m = TransportMetrics::new();
        m.bytes_sent(1024);
        m.bytes_sent(2048);
        m.bytes_received(4096);
        assert_eq!(m.circuit_bytes_sent(), 3072);
        assert_eq!(m.circuit_bytes_received(), 4096);
    }

    #[test]
    fn flow_control_tracked() {
        let m = TransportMetrics::new();
        m.window_block();
        m.window_block();
        m.credit_update_sent();
        m.credit_update_received();
        m.credit_update_received();
        assert_eq!(m.window_block_events(), 2);
        assert_eq!(m.credit_updates_sent(), 1);
        assert_eq!(m.credit_updates_received(), 2);
    }

    #[test]
    fn failures_tracked() {
        let m = TransportMetrics::new();
        m.tcp_connect_failure();
        m.protocol_reset();
        m.protocol_reset();
        m.circuit_teardown();
        assert_eq!(m.tcp_connect_failures(), 1);
        assert_eq!(m.protocol_resets(), 2);
        assert_eq!(m.circuit_teardowns(), 1);
    }

    #[test]
    fn snapshot_display_readable() {
        let m = TransportMetrics::new();
        m.circuit_created();
        m.stream_opened();
        m.bytes_sent(1024 * 1024);
        let s = m.snapshot();
        let display = format!("{s}");
        assert!(display.contains("circuits_active:         1"));
        assert!(display.contains("streams_active:          1"));
        assert!(display.contains("circuit_bytes_sent:"));
        assert!(display.contains("1.00 MB"));
    }

    #[test]
    fn concurrent_access_safe() {
        use std::thread;
        let m = Arc::new(TransportMetrics::new());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    m.stream_opened();
                    m.bytes_sent(100);
                    m.credit_update_sent();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.streams_opened_total(), 4000);
        assert_eq!(m.circuit_bytes_sent(), 400_000);
        assert_eq!(m.credit_updates_sent(), 4000);
    }
}

//! **N2.5-R.6 — Recovery Controller, Retry Backoff, and Monitor Runtime Ownership.**
//!
//! The `RecoveryController` is the single authoritative owner of the
//! failure-detection → recovery lifecycle. It owns:
//!
//! - A `FailureMonitor` (background health probing)
//! - A `RecoveryChannel` (provenance-bound failure signals)
//! - Retry / backoff state (failure streak, attempt count, delays)
//! - Controller state machine (RUNNING → RECOVERING → BACKOFF → …)
//!
//! ## Architecture
//!
//! ```text
//! Runtime
//!    ↓
//! RecoveryController (background task)
//!    ├── FailureMonitor (probes active circuit)
//!    ├── RecoveryChannel (carries RecoveryRequest)
//!    ├── RetryPolicy (exponential backoff + jitter)
//!    └── MigrationExecutor (phased: begin → establish → commit)
//!           ↓
//!      AdaptiveRouteOptimizer
//!           ↓
//!      CircuitRegistry
//! ```
//!
//! ## State machine
//!
//! ```text
//!          ┌──────────┐
//!     ┌───→│ RUNNING  │←─── successful recovery
//!     │    └────┬─────┘
//!     │         │ RecoveryRequest (verified)
//!     │         ↓
//!     │    ┌──────────────────┐
//!     │    │ RECOVERY_REQUEST │
//!     │    └────┬─────────────┘
//!     │         │
//!     │         ↓
//!     │    ┌────────────┐     failure
//!     │    │ RECOVERING │─────────────┐
//!     │    └────┬───────┘             │
//!     │         │ success             │
//!     │         ↓                     ↓
//!     │    (reset streak)        ┌──────────┐
//!     │         │                │ BACKOFF  │
//!     └─────────┘                └────┬─────┘
//!                                     │ backoff expires
//!                                     ↓
//!                                ┌──────────┐
//!                           ┌───→│ DEGRADED │ (no routes)
//!                           │    └──────────┘
//!                           │         │ routes available
//!                           └─────────┘
//! ```
//!
//! ## Key invariants
//!
//! - At most ONE `FailureMonitor` task exists at any time.
//! - At most ONE recovery attempt runs at any time.
//! - The executor-wide mutex is NEVER held over network I/O (phased API).
//! - Stale recovery requests are discarded without incrementing failure streak.
//! - Successful recovery resets the failure streak to 0.
//! - DEGRADED state does not busy-loop (bounded retry delay).
//! - Quarantine and backoff are independent concepts.

#![cfg(feature = "circuit-upstream")]

use super::circuit_lifecycle::{CircuitId, CircuitState};
use super::migration_executor::{
    establish_candidate, FailureMonitor, FailureMonitorConfig, MigrationBegin, MigrationExecutor,
    MigrationFailureReason, MigrationOutcome, ProbeContext, RecoveryChannel, RecoveryRequest,
};
use super::observations::PeerId;
use super::route_observation::{route_id_from_hops, RouteId};

use snp_crypto::{X25519PubKey, X25519Secret};
use snp_node::node::{Node, Route};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ════════════════════════════════════════════════════════════════════════════
// Recovery Attempt Identity
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — A unique, monotonically increasing identifier for a single
/// recovery attempt.
///
/// This is distinct from:
/// - `MigrationDecisionId` (optimizer-level decision identity)
/// - `CircuitId` (circuit instance identity)
/// - `RouteId` (route hash)
///
/// A recovery attempt may produce a migration decision, which may establish
/// a circuit, which has a circuit id. The `RecoveryAttemptId` ties together
/// the full recovery transaction for observability.
pub type RecoveryAttemptId = u64;

// ════════════════════════════════════════════════════════════════════════════
// Failure Classification
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — Classification of a recovery failure.
///
/// Distinguishes between different failure modes so the controller can
/// make appropriate policy decisions (e.g. a stale request is NOT a
/// circuit failure and should not increment the failure streak).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClassification {
    /// Circuit establishment failed (SNP-IK handshake, relay unreachable).
    EstablishmentFailure,
    /// The circuit was established but the health check failed.
    HealthCheckFailure,
    /// The recovery request was stale (active circuit/epoch changed
    /// between probe-start and recovery). This is NOT a circuit failure.
    StaleRequest,
    /// No eligible routes available (all quarantined or none provided).
    NoRoutes,
    /// The optimizer returned Cooldown.
    Cooldown,
    /// An internal state error (e.g. no active circuit when one was expected).
    InternalStateError,
}

impl From<&MigrationOutcome> for FailureClassification {
    fn from(outcome: &MigrationOutcome) -> Self {
        match outcome {
            MigrationOutcome::Failed { reason } => match reason {
                MigrationFailureReason::EstablishmentFailed(_) => {
                    FailureClassification::EstablishmentFailure
                }
                MigrationFailureReason::HealthCheckFailed(_) => {
                    FailureClassification::HealthCheckFailure
                }
                MigrationFailureReason::RouteIdMismatch => {
                    FailureClassification::InternalStateError
                }
                MigrationFailureReason::StaleDecision => {
                    FailureClassification::InternalStateError
                }
                MigrationFailureReason::CommitRejected(_) => {
                    FailureClassification::InternalStateError
                }
            },
            MigrationOutcome::NoRoutes => FailureClassification::NoRoutes,
            MigrationOutcome::Cooldown { .. } => FailureClassification::Cooldown,
            MigrationOutcome::NotNeeded => FailureClassification::StaleRequest,
            MigrationOutcome::Success { .. } => {
                FailureClassification::InternalStateError // shouldn't happen
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Controller State
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — The state of the recovery controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryControllerState {
    /// Active circuit healthy; monitor running.
    Running,
    /// Valid recovery request received; about to start recovery.
    RecoveryRequested,
    /// Recovery attempt in progress (establishment + health check + commit).
    Recovering {
        /// The unique id of this recovery attempt.
        attempt_id: RecoveryAttemptId,
        /// The attempt number (1-based; increments each retry).
        attempt_number: u32,
    },
    /// Recovery attempt failed; waiting before retry.
    Backoff {
        /// When the backoff expires and the next attempt may begin.
        until: Instant,
        /// Current failure streak (resets on success).
        failure_streak: u32,
    },
    /// No active circuit; no eligible routes available.
    Degraded {
        /// When the controller entered DEGRADED.
        since: Instant,
        /// When the last recovery attempt was made (if any).
        last_attempt: Option<Instant>,
    },
    /// Controller intentionally shut down.
    Stopped,
}

impl std::fmt::Display for RecoveryControllerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::RecoveryRequested => write!(f, "RecoveryRequested"),
            Self::Recovering { attempt_id, attempt_number } => {
                write!(f, "Recovering(attempt={} id={})", attempt_number, attempt_id)
            }
            Self::Backoff { failure_streak, .. } => {
                write!(f, "Backoff(streak={})", failure_streak)
            }
            Self::Degraded { .. } => write!(f, "Degraded"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}

impl RecoveryControllerState {
    /// Returns `true` if the controller is in a state where a recovery
    /// attempt is in progress.
    #[must_use]
    pub fn is_recovering(&self) -> bool {
        matches!(self, Self::Recovering { .. } | Self::RecoveryRequested)
    }

    /// Returns `true` if the controller is stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Retry Policy
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — Retry policy for the recovery controller.
///
/// Uses exponential backoff with optional bounded jitter:
///
/// ```text
/// raw_delay = base_delay * 2^(failure_streak - 1)
/// bounded   = min(raw_delay, max_delay)
/// actual    = bounded                    (if jitter disabled)
/// actual    = [bounded/2, bounded]       (if jitter enabled)
/// ```
///
/// After `max_attempts_before_degraded` consecutive failures, the
/// controller enters `DEGRADED` state (rather than continuing to retry
/// indefinitely).
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// The base delay for the first retry (failure_streak = 1).
    pub base_delay: Duration,
    /// The maximum delay between retries (caps the exponential growth).
    pub max_delay: Duration,
    /// After this many consecutive failures, enter DEGRADED.
    pub max_attempts_before_degraded: u32,
    /// Whether to apply bounded random jitter to delays.
    /// When `true`, the delay is in `[bounded/2, bounded]`.
    /// When `false`, the delay is exactly `bounded` (for deterministic tests).
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(60),
            max_attempts_before_degraded: 5,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff delay for a given failure streak.
    ///
    /// **N2.5-R.6.1** — Canonical contract:
    ///
    /// - `failure_streak = 0` → `base_delay` (no multiplication).
    /// - `failure_streak = N` → `min(base_delay * 2^N, max_delay)`.
    ///
    /// The controller calls `delay_for(inner.failure_streak)` AFTER
    /// incrementing the streak, so:
    /// - First failure: streak becomes 1 → `base_delay * 2`.
    /// - Second failure: streak becomes 2 → `base_delay * 4`.
    ///
    /// If `jitter` is enabled, the result is in `[bounded/2, bounded]`,
    /// using `getrandom` for real entropy (not `Instant::now().elapsed()`
    /// which was near-zero and effectively deterministic).
    ///
    /// For deterministic test behavior, set `jitter: false`.
    #[must_use]
    pub fn delay_for(&self, failure_streak: u32) -> Duration {
        // Exponential: base * 2^streak (streak=0 → base, no multiplication)
        let exp_delay = if failure_streak == 0 {
            self.base_delay
        } else {
            let exp = 2u32.saturating_pow(failure_streak);
            self.base_delay
                .checked_mul(exp)
                .unwrap_or(self.max_delay)
        };

        let bounded = exp_delay.min(self.max_delay);

        if !self.jitter {
            return bounded;
        }

        // N2.5-R.6.1: Use getrandom for real entropy.
        // This prevents synchronized retry storms across independent
        // controllers that might fail at the same time.
        let mut rand_bytes = [0u8; 8];
        // getrandom should never fail on a properly seeded system, but
        // if it does, fall back to the non-jittered delay.
        if getrandom::getrandom(&mut rand_bytes).is_err() {
            return bounded;
        }
        let rand_u64 = u64::from_le_bytes(rand_bytes);

        // Bounded jitter: [bounded/2, bounded]
        let half = bounded / 2;
        let half_nanos = half.as_nanos().max(1) as u64;
        let jitter_nanos = rand_u64 % half_nanos;
        half + Duration::from_nanos(jitter_nanos)
    }

    /// **N2.5-R.6.1** — Compute the backoff delay deterministically (no jitter).
    ///
    /// This is the canonical non-jittered delay: `min(base * 2^streak, max)`.
    /// Used by tests that need deterministic timing, and available as a
    /// fallback when jitter is disabled.
    #[must_use]
    pub fn delay_for_deterministic(&self, failure_streak: u32) -> Duration {
        let exp_delay = if failure_streak == 0 {
            self.base_delay
        } else {
            let exp = 2u32.saturating_pow(failure_streak);
            self.base_delay
                .checked_mul(exp)
                .unwrap_or(self.max_delay)
        };
        exp_delay.min(self.max_delay)
    }

    /// Returns `true` if the given failure streak warrants entering DEGRADED.
    #[must_use]
    pub fn should_degrade(&self, failure_streak: u32) -> bool {
        failure_streak >= self.max_attempts_before_degraded
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Recovery Events (Telemetry)
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — Structured telemetry events emitted by the controller.
///
/// Each event records what happened and when, carrying provenance where
/// applicable. These are stored in a ring buffer for inspection without
/// relying on log output.
#[derive(Debug, Clone)]
pub struct RecoveryEvent {
    /// When the event occurred.
    pub timestamp: Instant,
    /// The type of event.
    pub kind: RecoveryEventKind,
}

/// **N2.5-R.6** — Kinds of recovery events.
#[derive(Debug, Clone)]
pub enum RecoveryEventKind {
    /// The monitor detected a failure and a recovery request was received.
    RecoveryDetected {
        /// The circuit that was probed and found failed.
        circuit_id: CircuitId,
        /// The route of the failed circuit.
        route_id: RouteId,
        /// The epoch at probe-start.
        epoch: u64,
    },
    /// A recovery attempt has started.
    RecoveryStarted {
        /// The unique attempt id.
        attempt_id: RecoveryAttemptId,
        /// The attempt number (1-based).
        attempt_number: u32,
    },
    /// A recovery attempt failed.
    RecoveryAttemptFailed {
        /// The attempt id.
        attempt_id: RecoveryAttemptId,
        /// The attempt number.
        attempt_number: u32,
        /// Why it failed.
        classification: FailureClassification,
        /// The failure streak after this failure.
        failure_streak: u32,
    },
    /// The controller entered backoff after a failed attempt.
    RecoveryBackoffStarted {
        /// The failure streak.
        failure_streak: u32,
        /// How long to wait before retrying.
        delay: Duration,
    },
    /// Recovery succeeded — a new active circuit was established.
    RecoverySucceeded {
        /// The attempt id that succeeded.
        attempt_id: RecoveryAttemptId,
        /// The attempt number.
        attempt_number: u32,
    },
    /// The controller entered DEGRADED (no eligible routes).
    RecoveryDegraded,
    /// The controller was stopped.
    RecoveryStopped,
    /// A stale recovery request was discarded (no failure streak change).
    StaleRequestDiscarded {
        /// The circuit id in the stale request.
        circuit_id: CircuitId,
        /// The epoch in the stale request.
        epoch: u64,
    },
}

// ════════════════════════════════════════════════════════════════════════════
// Controller Snapshot (for external inspection)
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — A read-only snapshot of the controller's internal state.
///
/// Allows tests and diagnostics to inspect the controller without holding
/// the controller's internal mutex for long.
#[derive(Debug, Clone)]
pub struct ControllerSnapshot {
    /// The current controller state.
    pub state: RecoveryControllerState,
    /// The total number of recovery attempts (cumulative, never reset).
    pub recovery_attempts: u32,
    /// The current failure streak (resets on success).
    pub failure_streak: u32,
    /// When the last failure occurred (if any).
    pub last_failure: Option<Instant>,
    /// When the last successful recovery occurred (if any).
    pub last_successful_recovery: Option<Instant>,
    /// When the current backoff expires (if in BACKOFF state).
    pub backoff_until: Option<Instant>,
    /// The active recovery attempt id (if in RECOVERING state).
    pub active_recovery_attempt: Option<RecoveryAttemptId>,
}

// ════════════════════════════════════════════════════════════════════════════
// Controller Configuration
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — Configuration for the recovery controller.
#[derive(Debug, Clone)]
pub struct RecoveryControllerConfig {
    /// The failure monitor configuration (probe interval/timeout).
    pub monitor_config: FailureMonitorConfig,
    /// The retry policy (backoff, jitter, max attempts).
    pub retry_policy: RetryPolicy,
    /// The health endpoint for probing the active circuit AND for
    /// health-checking new candidate circuits.
    pub health_check_endpoint: snp_gateway::stream::InternetEndpoint,
    /// How often to retry when in DEGRADED state (no routes available).
    /// This is a fixed delay, not exponential — DEGRADED means "wait for
    /// external conditions to change."
    pub degraded_retry_interval: Duration,
}

impl Default for RecoveryControllerConfig {
    fn default() -> Self {
        Self {
            monitor_config: FailureMonitorConfig::default(),
            retry_policy: RetryPolicy::default(),
            health_check_endpoint: snp_gateway::stream::InternetEndpoint {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                protocol: snp_gateway::stream::TransportProtocol::Tcp,
            },
            degraded_retry_interval: Duration::from_secs(30),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Internal Controller State
// ════════════════════════════════════════════════════════════════════════════

/// Internal mutable state shared between the controller task and external
/// inspectors.
struct ControllerInner {
    state: RecoveryControllerState,
    recovery_attempts: u32,
    failure_streak: u32,
    last_failure: Option<Instant>,
    last_successful_recovery: Option<Instant>,
    /// Monotonic counter for generating RecoveryAttemptIds.
    next_attempt_id: RecoveryAttemptId,
    /// Ring buffer of recent events.
    events: Vec<RecoveryEvent>,
    /// Whether the controller should stop (no new recovery attempts).
    shutdown: bool,
    /// **N2.5-R.6.1** — Notify used to wake up the controller task when
    /// `shutdown` is set. The task races `take_async()` against
    /// `shutdown_notify.notified()` in its RUNNING state so that `stop()`
    /// can break it out of the wait without aborting the task.
    ///
    /// This is `Arc<Notify>` (not bare `Notify`) so that the controller
    /// task can hold its own clone and call `.notified().await` on it
    /// without locking `inner`.
    shutdown_notify: Arc<tokio::sync::Notify>,
}

impl ControllerInner {
    fn new() -> Self {
        Self {
            state: RecoveryControllerState::Running,
            recovery_attempts: 0,
            failure_streak: 0,
            last_failure: None,
            last_successful_recovery: None,
            next_attempt_id: 1,
            events: Vec::new(),
            shutdown: false,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn snapshot(&self) -> ControllerSnapshot {
        let backoff_until = match &self.state {
            RecoveryControllerState::Backoff { until, .. } => Some(*until),
            _ => None,
        };
        let active_recovery_attempt = match &self.state {
            RecoveryControllerState::Recovering { attempt_id, .. } => Some(*attempt_id),
            _ => None,
        };
        ControllerSnapshot {
            state: self.state.clone(),
            recovery_attempts: self.recovery_attempts,
            failure_streak: self.failure_streak,
            last_failure: self.last_failure,
            last_successful_recovery: self.last_successful_recovery,
            backoff_until,
            active_recovery_attempt,
        }
    }

    fn record_event(&mut self, kind: RecoveryEventKind) {
        let event = RecoveryEvent {
            timestamp: Instant::now(),
            kind,
        };
        self.events.push(event);
        // Keep only the last 100 events.
        if self.events.len() > 100 {
            self.events.drain(..self.events.len() - 100);
        }
    }

    fn next_attempt(&mut self) -> (RecoveryAttemptId, u32) {
        let id = self.next_attempt_id;
        self.next_attempt_id += 1;
        self.recovery_attempts += 1;
        let attempt_number = self.recovery_attempts;
        (id, attempt_number)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Recovery Controller
// ════════════════════════════════════════════════════════════════════════════

/// **N2.5-R.6** — The recovery controller.
///
/// Owns the failure-detection → recovery lifecycle. Runs as a background
/// tokio task that:
///
/// 1. When `Running`: starts a `FailureMonitor` for the active circuit,
///    waits for a `RecoveryRequest`.
/// 2. When `RecoveryRequested`: verifies the request against the current
///    active circuit/epoch (discards stale requests).
/// 3. When `Recovering`: runs phased migration (`begin_migration` →
///    `establish_candidate` → `commit_established`) without holding the
///    executor-wide mutex over I/O.
/// 4. On success: resets failure streak, restarts monitor → `Running`.
/// 5. On failure: increments failure streak, enters `Backoff`.
/// 6. After backoff: retries (or enters `Degraded` if max attempts reached).
/// 7. When `Degraded`: waits `degraded_retry_interval`, then retries.
/// 8. When `Stopped`: exits.
///
/// ## Shutdown semantics
///
/// `stop()` sets a shutdown flag and aborts the monitor. The controller
/// task will exit after its current iteration. An in-progress recovery
/// attempt is **allowed to finish** (not cancelled) — `stop()` prevents
/// NEW recovery attempts but does not abort one already in flight.
pub struct RecoveryController {
    /// Shared executor (also used by the monitor and external callers).
    executor: Arc<tokio::sync::Mutex<MigrationExecutor>>,
    /// The failure monitor (owned by the controller).
    monitor: Mutex<FailureMonitor>,
    /// Cached clone of the monitor's `Arc<RecoveryChannel>`.
    ///
    /// `start()` moves the monitor into the background task via
    /// `std::mem::take`, which leaves `self.monitor` holding a freshly
    /// `Default`-constructed monitor (with a **different** `Arc<RecoveryChannel>`).
    /// Without this cached clone, `channel()` would return the wrong channel
    /// after `start()` — callers depositing via `emit_for_test()` would never
    /// reach the task. We refresh this cached clone in `new()` and `start()`
    /// so it always aliases the monitor the task is actually listening on.
    channel: Arc<RecoveryChannel>,
    /// Internal state (state machine, counters, events).
    inner: Arc<Mutex<ControllerInner>>,
    /// Handle to the background controller task.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Configuration.
    config: RecoveryControllerConfig,
}

impl RecoveryController {
    /// Create a new recovery controller.
    ///
    /// The controller does NOT start running until `start()` is called.
    ///
    /// # Arguments
    /// * `executor` — The migration executor (shared via `Arc<Mutex>`).
    ///   The controller is the authoritative owner of recovery — external
    ///   callers should NOT call `attempt_migration()` or
    ///   `recover_from_failure()` on this executor while the controller
    ///   is running.
    /// * `config` — Controller configuration.
    #[must_use]
    pub fn new(
        executor: Arc<tokio::sync::Mutex<MigrationExecutor>>,
        config: RecoveryControllerConfig,
    ) -> Self {
        let monitor = FailureMonitor::new();
        let channel = Arc::clone(monitor.channel());
        Self {
            executor,
            monitor: Mutex::new(monitor),
            channel,
            inner: Arc::new(Mutex::new(ControllerInner::new())),
            task_handle: None,
            config,
        }
    }

    /// Returns a snapshot of the controller's current state.
    ///
    /// This is the primary way for tests and diagnostics to inspect the
    /// controller without blocking the controller task.
    #[must_use]
    pub fn snapshot(&self) -> ControllerSnapshot {
        self.inner.lock().unwrap().snapshot()
    }

    /// Returns the current controller state.
    #[must_use]
    pub fn state(&self) -> RecoveryControllerState {
        self.inner.lock().unwrap().state.clone()
    }

    /// Returns a clone of the recent events (telemetry).
    #[must_use]
    pub fn events(&self) -> Vec<RecoveryEvent> {
        self.inner.lock().unwrap().events.clone()
    }

    /// Returns a reference to the recovery channel (for testing).
    ///
    /// Returns the same `Arc<RecoveryChannel>` that the background task's
    /// `FailureMonitor` is listening on (via `take_async()`), even after
    /// `start()` has moved the monitor into the task. This is achieved by
    /// caching the channel in `new()` / `start()`.
    #[must_use]
    pub fn channel(&self) -> Arc<RecoveryChannel> {
        Arc::clone(&self.channel)
    }

    /// Returns `true` if the controller task is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.task_handle
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// **N2.5-R.6** — Start the recovery controller background task.
    ///
    /// The controller will:
    /// 1. Start a `FailureMonitor` for the active circuit (if one exists).
    /// 2. Wait for recovery requests.
    /// 3. On failure: verify, recover, backoff/retry.
    ///
    /// If there is no active circuit when `start()` is called, the
    /// controller immediately enters `Degraded` and attempts initial
    /// establishment.
    ///
    /// # Arguments
    /// * `candidates` — All candidate routes (cloned into the task).
    /// * `node` — The client node (cloned into the task).
    /// * `routes` — Map from hop sequence to Route (cloned into the task).
    /// * `client_x25519_secret` / `client_x25519_public` — Client keys.
    pub fn start(
        &mut self,
        candidates: Vec<Vec<PeerId>>,
        node: Node,
        routes: Vec<(Vec<PeerId>, Route)>,
        client_x25519_secret: Arc<X25519Secret>,
        client_x25519_public: X25519PubKey,
    ) {
        if self.is_running() {
            return;
        }

        let executor = Arc::clone(&self.executor);
        let inner = Arc::clone(&self.inner);
        let config = self.config.clone();
        // N2.5-R.6.1: Clone the shutdown_notify so the task can race
        // `take_async()` against `notified()` in `handle_running()` and
        // `tokio::time::sleep` against `notified()` in `handle_backoff()` /
        // `handle_degraded()`. This lets `stop()` wake the task without
        // aborting it.
        let shutdown_notify = Arc::clone(&inner.lock().unwrap().shutdown_notify);

        // Move the monitor out of self — the task owns it.
        let monitor = {
            let mut m = self.monitor.lock().unwrap();
            // Cache the channel BEFORE taking the monitor so that `channel()`
            // continues to return the same `Arc<RecoveryChannel>` the task is
            // listening on. After `take`, `self.monitor` holds a default
            // monitor with a different (unshared) channel.
            self.channel = Arc::clone(m.channel());
            std::mem::take(&mut *m)
        };

        self.task_handle = Some(tokio::spawn(async move {
            controller_task(
                executor,
                monitor,
                inner,
                shutdown_notify,
                config,
                candidates,
                node,
                routes,
                client_x25519_secret,
                client_x25519_public,
            )
            .await;
        }));
    }

    /// **N2.5-R.6** — Stop the controller.
    ///
    /// **N2.5-R.6.1** — Graceful shutdown: `stop()` sets a shutdown flag
    /// and notifies the controller task via `shutdown_notify`. The task
    /// will exit at the next state transition (or immediately if it is
    /// blocked in `take_async()`).
    ///
    /// In-progress recovery (establishment I/O) is **allowed to complete** —
    /// `stop()` does NOT abort the task. After the in-progress recovery
    /// finishes, the task checks the shutdown flag and exits without
    /// starting a new cycle.
    ///
    /// To wait for the task to finish, call `join()` after `stop()`.
    ///
    /// After `stop()`, the controller enters `Stopped` state.
    pub fn stop(&mut self) {
        let shutdown_notify = {
            let mut inner = self.inner.lock().unwrap();
            inner.shutdown = true;
            inner.state = RecoveryControllerState::Stopped;
            inner.record_event(RecoveryEventKind::RecoveryStopped);
            Arc::clone(&inner.shutdown_notify)
        };
        // Stop the monitor (if any is held in self.monitor — the task's
        // monitor is owned by the task and will be dropped when the task
        // exits gracefully).
        if let Ok(mut monitor) = self.monitor.try_lock() {
            monitor.stop();
        }
        // N2.5-R.6.1: Wake up the controller task if it is blocked in
        // `take_async()` (RUNNING state) so it can observe the shutdown
        // flag and exit. We use `notify_one()` on the shutdown_notify
        // AND `wake()` on the recovery channel — both are necessary
        // because the task might be waiting on either, depending on the
        // state.
        shutdown_notify.notify_one();
        // Wake up `take_async()` in case the task is blocked there.
        // The channel is shared between the monitor and the task — calling
        // `wake()` does NOT deposit a request, it just notifies the wait.
        self.channel.wake();
    }

    /// **N2.5-R.6.1** — Wait for the controller task to finish (graceful
    /// shutdown).
    ///
    /// After calling `stop()`, call `join()` to block until the controller
    /// task has exited. This is useful for tests that need to assert the
    /// task has fully terminated.
    ///
    /// If the task is in the middle of recovery (establishment I/O),
    /// `join()` will block until that recovery completes (success or
    /// failure) and the task exits.
    ///
    /// This is a no-op if the task has already exited or was never started.
    pub async fn join(&mut self) {
        if let Some(handle) = self.task_handle.take() {
            // Wait for the task to finish. Ignore join errors (panics are
            // already logged by tokio).
            let _ = handle.await;
        }
    }
}

impl Drop for RecoveryController {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for RecoveryController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snap = self.snapshot();
        f.debug_struct("RecoveryController")
            .field("state", &snap.state)
            .field("is_running", &self.is_running())
            .field("recovery_attempts", &snap.recovery_attempts)
            .field("failure_streak", &snap.failure_streak)
            .finish_non_exhaustive()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Controller Task (the background state machine)
// ════════════════════════════════════════════════════════════════════════════

/// The background controller task. Owns the `FailureMonitor` and runs the
/// state machine loop.
async fn controller_task(
    executor: Arc<tokio::sync::Mutex<MigrationExecutor>>,
    mut monitor: FailureMonitor,
    inner: Arc<Mutex<ControllerInner>>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    config: RecoveryControllerConfig,
    candidates: Vec<Vec<PeerId>>,
    node: Node,
    routes: Vec<(Vec<PeerId>, Route)>,
    client_x25519_secret: Arc<X25519Secret>,
    client_x25519_public: X25519PubKey,
) {
    eprintln!("[n2.5-r.6] recovery controller task started");

    loop {
        // Check shutdown.
        if inner.lock().unwrap().shutdown {
            break;
        }

        let state = inner.lock().unwrap().state.clone();

        match state {
            RecoveryControllerState::Running => {
                handle_running(
                    &executor,
                    &mut monitor,
                    &inner,
                    &shutdown_notify,
                    &config,
                    &candidates,
                    &node,
                    &routes,
                    &client_x25519_secret,
                    &client_x25519_public,
                )
                .await;
            }

            RecoveryControllerState::RecoveryRequested => {
                // Transition to Recovering (the request was already verified
                // when we entered RecoveryRequested).
                let (attempt_id, attempt_number) = {
                    let mut inner = inner.lock().unwrap();
                    inner.next_attempt()
                };
                {
                    let mut inner = inner.lock().unwrap();
                    inner.state = RecoveryControllerState::Recovering {
                        attempt_id,
                        attempt_number,
                    };
                    inner.record_event(RecoveryEventKind::RecoveryStarted {
                        attempt_id,
                        attempt_number,
                    });
                }
                eprintln!(
                    "[n2.5-r.6] recovery attempt #{} (id={}) started",
                    attempt_number, attempt_id
                );
            }

            RecoveryControllerState::Recovering { attempt_id, attempt_number } => {
                handle_recovering(
                    &executor,
                    &inner,
                    &config,
                    &candidates,
                    &node,
                    &routes,
                    &client_x25519_secret,
                    &client_x25519_public,
                    attempt_id,
                    attempt_number,
                )
                .await;
            }

            RecoveryControllerState::Backoff { until, failure_streak } => {
                handle_backoff(&inner, &shutdown_notify, until, failure_streak, &config).await;
            }

            RecoveryControllerState::Degraded { since, last_attempt } => {
                handle_degraded(
                    &executor,
                    &inner,
                    &shutdown_notify,
                    &config,
                    &candidates,
                    &node,
                    &routes,
                    &client_x25519_secret,
                    &client_x25519_public,
                    since,
                    last_attempt,
                )
                .await;
            }

            RecoveryControllerState::Stopped => {
                break;
            }
        }
    }

    // Clean up: stop the monitor.
    monitor.stop();
    eprintln!("[n2.5-r.6] recovery controller task exited");
}

// ───────────────────────────────────────────────────────────────────────────
// State handlers
// ───────────────────────────────────────────────────────────────────────────

/// **RUNNING** — Start monitor for the active circuit, wait for a recovery
/// request.
async fn handle_running(
    executor: &Arc<tokio::sync::Mutex<MigrationExecutor>>,
    monitor: &mut FailureMonitor,
    inner: &Arc<Mutex<ControllerInner>>,
    shutdown_notify: &Arc<tokio::sync::Notify>,
    config: &RecoveryControllerConfig,
    candidates: &[Vec<PeerId>],
    node: &Node,
    routes: &[(Vec<PeerId>, Route)],
    client_x25519_secret: &Arc<X25519Secret>,
    client_x25519_public: &X25519PubKey,
) {
    // Check if there's an active circuit to monitor.
    let probe = {
        let exec = executor.lock().await;
        exec.prepare_probe()
    };

    match probe {
        Some((ctx, handle)) => {
            // Start (or restart) the monitor for the active circuit.
            if !monitor.is_running() {
                monitor.start(
                    Arc::clone(executor),
                    config.health_check_endpoint.clone(),
                    config.monitor_config.clone(),
                );
                eprintln!(
                    "[n2.5-r.6] monitor started for circuit {:?} (epoch {})",
                    ctx.circuit_id, ctx.epoch
                );
            }

            // N2.5-R.6.1: Wait for a recovery request OR a shutdown signal.
            // We use `biased` so that if `stop()` is called while a request
            // is also pending, we prefer to exit (don't start a new recovery).
            // The `shutdown_notify.notified()` future is stored as a permit
            // by `stop()`, so even if the task is currently blocked in
            // `take_async()`, the `select!` will be re-polled and pick the
            // shutdown branch.
            let request = tokio::select! {
                biased;
                _ = shutdown_notify.notified() => {
                    // Shutdown signaled — exit gracefully without starting
                    // a new recovery. The monitor will be stopped by the
                    // outer task cleanup.
                    monitor.stop();
                    return;
                }
                req = monitor.channel().take_async() => req,
            };

            // Stop the monitor — it has exited or we need to stop it.
            monitor.stop();

            // Check shutdown (in case stop() was called during processing).
            if inner.lock().unwrap().shutdown {
                return;
            }

            // Record the detection.
            {
                let mut inner = inner.lock().unwrap();
                inner.record_event(RecoveryEventKind::RecoveryDetected {
                    circuit_id: request.circuit_id,
                    route_id: request.route_id,
                    epoch: request.epoch,
                });
            }

            // Verify the request is current (not stale).
            let is_current = {
                let exec = executor.lock().await;
                exec.verify_recovery_request(&request)
            };

            if !is_current {
                // Stale request — discard without incrementing failure streak.
                eprintln!(
                    "[n2.5-r.6] stale recovery request discarded (circuit={:?} epoch={})",
                    request.circuit_id, request.epoch
                );
                {
                    let mut inner = inner.lock().unwrap();
                    inner.record_event(RecoveryEventKind::StaleRequestDiscarded {
                        circuit_id: request.circuit_id,
                        epoch: request.epoch,
                    });
                }
                // Stay in Running — the active circuit is still healthy.
                // The monitor will be restarted on the next loop iteration.
                return;
            }

            // The request is current. Transition to RecoveryRequested.
            // First, fail the active circuit (it's been probed as failed).
            {
                let mut exec = executor.lock().await;
                if let Err(e) = exec.fail_active_circuit() {
                    eprintln!("[n2.5-r.6] failed to mark active circuit as failed: {}", e);
                }
            }

            // Transition to RecoveryRequested.
            {
                let mut inner = inner.lock().unwrap();
                inner.state = RecoveryControllerState::RecoveryRequested;
            }
        }

        None => {
            // No active circuit — try initial establishment, or enter Degraded.
            eprintln!("[n2.5-r.6] no active circuit — attempting initial establishment");
            // N2.5-R.6.1: Check shutdown before starting initial establishment.
            if inner.lock().unwrap().shutdown {
                return;
            }
            let (attempt_id, attempt_number) = {
                let mut inner = inner.lock().unwrap();
                inner.next_attempt()
            };
            {
                let mut inner = inner.lock().unwrap();
                inner.record_event(RecoveryEventKind::RecoveryStarted {
                    attempt_id,
                    attempt_number,
                });
            }
            let outcome = do_phased_migration(
                executor,
                config,
                candidates,
                node,
                routes,
                client_x25519_secret,
                client_x25519_public,
            )
            .await;

            match outcome {
                MigrationOutcome::Success { .. } => {
                    eprintln!("[n2.5-r.6] initial establishment succeeded");
                    // Stay in Running — the monitor will be started next iteration.
                    let mut inner = inner.lock().unwrap();
                    inner.failure_streak = 0;
                    inner.last_successful_recovery = Some(Instant::now());
                }
                MigrationOutcome::NoRoutes => {
                    eprintln!("[n2.5-r.6] no routes — entering Degraded");
                    let mut inner = inner.lock().unwrap();
                    inner.state = RecoveryControllerState::Degraded {
                        since: Instant::now(),
                        last_attempt: Some(Instant::now()),
                    };
                    inner.record_event(RecoveryEventKind::RecoveryDegraded);
                }
                _ => {
                    eprintln!("[n2.5-r.6] initial establishment failed — entering Degraded");
                    let mut inner = inner.lock().unwrap();
                    inner.failure_streak += 1;
                    inner.last_failure = Some(Instant::now());
                    inner.state = RecoveryControllerState::Degraded {
                        since: Instant::now(),
                        last_attempt: Some(Instant::now()),
                    };
                    inner.record_event(RecoveryEventKind::RecoveryDegraded);
                }
            }
        }
    }
}

/// **RECOVERING** — Run a phased migration attempt.
async fn handle_recovering(
    executor: &Arc<tokio::sync::Mutex<MigrationExecutor>>,
    inner: &Arc<Mutex<ControllerInner>>,
    config: &RecoveryControllerConfig,
    candidates: &[Vec<PeerId>],
    node: &Node,
    routes: &[(Vec<PeerId>, Route)],
    client_x25519_secret: &Arc<X25519Secret>,
    client_x25519_public: &X25519PubKey,
    attempt_id: RecoveryAttemptId,
    attempt_number: u32,
) {
    let outcome = do_phased_migration(
        executor,
        config,
        candidates,
        node,
        routes,
        client_x25519_secret,
        client_x25519_public,
    )
    .await;

    match outcome {
        MigrationOutcome::Success { .. } => {
            // Recovery succeeded! Reset streak, restart monitor.
            eprintln!(
                "[n2.5-r.6] recovery attempt #{} (id={}) succeeded",
                attempt_number, attempt_id
            );
            let mut inner = inner.lock().unwrap();
            inner.failure_streak = 0;
            inner.last_successful_recovery = Some(Instant::now());
            inner.state = RecoveryControllerState::Running;
            inner.record_event(RecoveryEventKind::RecoverySucceeded {
                attempt_id,
                attempt_number,
            });
        }

        MigrationOutcome::NoRoutes => {
            // No eligible routes — enter Degraded.
            eprintln!(
                "[n2.5-r.6] recovery attempt #{} (id={}) → NoRoutes → Degraded",
                attempt_number, attempt_id
            );
            let mut inner = inner.lock().unwrap();
            inner.state = RecoveryControllerState::Degraded {
                since: Instant::now(),
                last_attempt: Some(Instant::now()),
            };
            inner.record_event(RecoveryEventKind::RecoveryDegraded);
        }

        MigrationOutcome::Failed { reason } => {
            // Recovery attempt failed.
            let classification = FailureClassification::from(&MigrationOutcome::Failed {
                reason: reason.clone(),
            });
            eprintln!(
                "[n2.5-r.6] recovery attempt #{} (id={}) failed: {:?}",
                attempt_number, attempt_id, classification
            );

            let mut inner = inner.lock().unwrap();
            inner.failure_streak += 1;
            inner.last_failure = Some(Instant::now());
            let streak_after_failure = inner.failure_streak;

            inner.record_event(RecoveryEventKind::RecoveryAttemptFailed {
                attempt_id,
                attempt_number,
                classification: classification.clone(),
                failure_streak: streak_after_failure,
            });

            // Check if we should enter Degraded.
            if config.retry_policy.should_degrade(streak_after_failure) {
                eprintln!(
                    "[n2.5-r.6] failure streak {} >= max_attempts {} → Degraded",
                    streak_after_failure, config.retry_policy.max_attempts_before_degraded
                );
                inner.state = RecoveryControllerState::Degraded {
                    since: Instant::now(),
                    last_attempt: Some(Instant::now()),
                };
                inner.record_event(RecoveryEventKind::RecoveryDegraded);
            } else {
                // Enter Backoff.
                let delay = config.retry_policy.delay_for(streak_after_failure);
                let until = Instant::now() + delay;
                eprintln!(
                    "[n2.5-r.6] entering backoff (streak={}, delay={:?})",
                    streak_after_failure, delay
                );
                inner.state = RecoveryControllerState::Backoff {
                    until,
                    failure_streak: streak_after_failure,
                };
                inner.record_event(RecoveryEventKind::RecoveryBackoffStarted {
                    failure_streak: streak_after_failure,
                    delay,
                });
            }
        }

        MigrationOutcome::NotNeeded => {
            // The optimizer didn't recommend migration. This can happen if
            // the active circuit is still the best route. Since we got here
            // from a verified failure, the circuit IS failed — but the
            // optimizer might not have enough data. Enter Backoff.
            eprintln!(
                "[n2.5-r.6] recovery attempt #{} (id={}) → NotNeeded (optimizer stale?)",
                attempt_number, attempt_id
            );
            let mut inner = inner.lock().unwrap();
            inner.failure_streak += 1;
            inner.last_failure = Some(Instant::now());
            let delay = config.retry_policy.delay_for(inner.failure_streak);
            inner.state = RecoveryControllerState::Backoff {
                until: Instant::now() + delay,
                failure_streak: inner.failure_streak,
            };
        }

        MigrationOutcome::Cooldown { remaining } => {
            // The optimizer is on cooldown. Wait for the cooldown, then retry.
            eprintln!(
                "[n2.5-r.6] recovery attempt #{} (id={}) → Cooldown ({:?})",
                attempt_number, attempt_id, remaining
            );
            let mut inner = inner.lock().unwrap();
            // Don't increment failure_streak for cooldown — it's not a failure.
            let delay = remaining.max(config.retry_policy.base_delay);
            inner.state = RecoveryControllerState::Backoff {
                until: Instant::now() + delay,
                failure_streak: inner.failure_streak,
            };
        }
    }
}

/// **BACKOFF** — Wait until the backoff expires, then retry.
async fn handle_backoff(
    inner: &Arc<Mutex<ControllerInner>>,
    shutdown_notify: &Arc<tokio::sync::Notify>,
    until: Instant,
    failure_streak: u32,
    config: &RecoveryControllerConfig,
) {
    let now = Instant::now();
    if until > now {
        let remaining = until - now;
        eprintln!(
            "[n2.5-r.6] backoff: waiting {:?} (streak={})",
            remaining, failure_streak
        );
        // N2.5-R.6.1: Race the sleep against shutdown_notify so that
        // `stop()` during backoff wakes us up immediately rather than
        // waiting for the full backoff to expire.
        tokio::select! {
            biased;
            _ = shutdown_notify.notified() => {
                // Shutdown signaled — exit gracefully.
                return;
            }
            _ = tokio::time::sleep(remaining) => {}
        }
    }

    // Check shutdown.
    if inner.lock().unwrap().shutdown {
        return;
    }

    // Transition to RecoveryRequested to start a new attempt.
    let (attempt_id, attempt_number) = {
        let mut inner = inner.lock().unwrap();
        let (id, num) = inner.next_attempt();
        inner.state = RecoveryControllerState::Recovering {
            attempt_id: id,
            attempt_number: num,
        };
        inner.record_event(RecoveryEventKind::RecoveryStarted {
            attempt_id: id,
            attempt_number: num,
        });
        (id, num)
    };
    eprintln!(
        "[n2.5-r.6] backoff expired — starting recovery attempt #{} (id={})",
        attempt_number, attempt_id
    );
}

/// **DEGRADED** — No active circuit, no eligible routes. Wait and retry.
async fn handle_degraded(
    executor: &Arc<tokio::sync::Mutex<MigrationExecutor>>,
    inner: &Arc<Mutex<ControllerInner>>,
    shutdown_notify: &Arc<tokio::sync::Notify>,
    config: &RecoveryControllerConfig,
    candidates: &[Vec<PeerId>],
    node: &Node,
    routes: &[(Vec<PeerId>, Route)],
    client_x25519_secret: &Arc<X25519Secret>,
    client_x25519_public: &X25519PubKey,
    _since: Instant,
    _last_attempt: Option<Instant>,
) {
    eprintln!(
        "[n2.5-r.6] degraded: waiting {:?} before retry",
        config.degraded_retry_interval
    );
    // N2.5-R.6.1: Race the sleep against shutdown_notify so that `stop()`
    // during DEGRADED wakes us up immediately.
    tokio::select! {
        biased;
        _ = shutdown_notify.notified() => {
            // Shutdown signaled — exit gracefully.
            return;
        }
        _ = tokio::time::sleep(config.degraded_retry_interval) => {}
    }

    // Check shutdown.
    if inner.lock().unwrap().shutdown {
        return;
    }

    // Try to establish a circuit.
    eprintln!("[n2.5-r.6] degraded: attempting recovery");
    // Count this as a recovery attempt (for telemetry / testability).
    let (attempt_id, attempt_number) = {
        let mut inner = inner.lock().unwrap();
        inner.next_attempt()
    };
    {
        let mut inner = inner.lock().unwrap();
        inner.record_event(RecoveryEventKind::RecoveryStarted {
            attempt_id,
            attempt_number,
        });
    }
    let outcome = do_phased_migration(
        executor,
        config,
        candidates,
        node,
        routes,
        client_x25519_secret,
        client_x25519_public,
    )
    .await;

    match outcome {
        MigrationOutcome::Success { .. } => {
            eprintln!("[n2.5-r.6] degraded → recovery succeeded → Running");
            let mut inner = inner.lock().unwrap();
            inner.failure_streak = 0;
            inner.last_successful_recovery = Some(Instant::now());
            inner.state = RecoveryControllerState::Running;
        }
        MigrationOutcome::NoRoutes => {
            // Still no routes — stay in Degraded.
            eprintln!("[n2.5-r.6] degraded: still NoRoutes");
            let mut inner = inner.lock().unwrap();
            inner.state = RecoveryControllerState::Degraded {
                since: Instant::now(),
                last_attempt: Some(Instant::now()),
            };
        }
        _ => {
            // Attempt failed — stay in Degraded (don't enter Backoff from Degraded).
            eprintln!("[n2.5-r.6] degraded: recovery attempt failed, staying Degraded");
            let mut inner = inner.lock().unwrap();
            inner.failure_streak += 1;
            inner.last_failure = Some(Instant::now());
            inner.state = RecoveryControllerState::Degraded {
                since: Instant::now(),
                last_attempt: Some(Instant::now()),
            };
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Phased Migration (no executor lock over I/O)
// ───────────────────────────────────────────────────────────────────────────

/// Run a phased migration without holding the executor-wide mutex over I/O.
///
/// Phase 1 (short lock): `begin_migration()` → `MigrationBegin`
/// Phase 2 (NO lock):    `establish_candidate(plan)` → `Result<EstablishedCandidate, _>`
/// Phase 3 (short lock): `commit_established(plan, result)` → `MigrationOutcome`
async fn do_phased_migration(
    executor: &Arc<tokio::sync::Mutex<MigrationExecutor>>,
    config: &RecoveryControllerConfig,
    candidates: &[Vec<PeerId>],
    node: &Node,
    routes: &[(Vec<PeerId>, Route)],
    client_x25519_secret: &Arc<X25519Secret>,
    client_x25519_public: &X25519PubKey,
) -> MigrationOutcome {
    // Phase 1: begin_migration (short executor lock).
    let begin = {
        let mut exec = executor.lock().await;
        exec.begin_migration(candidates, routes)
    }; // executor lock RELEASED.

    let MigrationBegin::Migrate(plan) = begin else {
        return match begin {
            MigrationBegin::NotNeeded => MigrationOutcome::NotNeeded,
            MigrationBegin::Cooldown { remaining } => MigrationOutcome::Cooldown { remaining },
            MigrationBegin::NoRoutes => MigrationOutcome::NoRoutes,
            MigrationBegin::Migrate(_) => unreachable!(),
        };
    };

    // Phase 2: establish_candidate (NO executor lock — slow I/O).
    let candidate_result = establish_candidate(
        &plan,
        node,
        client_x25519_secret,
        &client_x25519_public,
        Some(config.health_check_endpoint.clone()),
    )
    .await;

    // Phase 3: commit_established (short executor lock).
    let outcome = {
        let mut exec = executor.lock().await;
        exec.commit_established(plan, candidate_result)
    }; // executor lock RELEASED.

    outcome
}

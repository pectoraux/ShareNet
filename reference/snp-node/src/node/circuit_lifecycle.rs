//! N3.1 — Circuit Lifecycle + Key Rotation
//!
//! Manages the full lifecycle of a circuit:
//!
//! ```text
//! CircuitSetup → Active → (key rotation) → Active → ... → Expired/Teardown
//!                                                      ↓
//!                                              Resource cleanup (zero keys)
//! ```
//!
//! ## Key properties
//!
//! 1. **No sequence reuse** — the circuit's sequence counter is monotonic;
//!    it NEVER resets or rolls back, even across key rotation.
//! 2. **No stale circuit reuse** — an expired/torn-down circuit CANNOT be
//!    re-activated; a new circuit must be established.
//! 3. **No forwarding state survives its circuit** — when a circuit is
//!    torn down, all forwarding state (keys, replay windows) is zeroed
//!    and removed.
//! 4. **Key rotation** — keys can be rotated (new epoch) without changing
//!    the circuit_id. The sequence counter continues from where it left off
//!    (no reset).
//!
//! ## Key rotation model
//!
//! ```text
//! Epoch 0: keys_0, seq [0..N)
//!     ↓ (rotate)
//! Epoch 1: keys_1, seq [N..M)  ← seq continues, NOT reset
//!     ↓ (rotate)
//! Epoch 2: keys_2, seq [M..P)
//!     ↓ (teardown)
//! Keys zeroed, state removed
//! ```

use crate::node::evidence::{EvidenceLevel, ObservedMetric};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── CircuitLifecycleState ───────────────────────────────────────────────────

/// The lifecycle state of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitLifecycleState {
    /// Circuit has been set up but not yet activated.
    Setup,
    /// Circuit is active and can carry traffic.
    Active,
    /// Circuit is being rotated (new keys being derived).
    Rotating,
    /// Circuit has expired (lifetime reached).
    Expired,
    /// Circuit has been torn down (explicit close).
    TornDown,
}

impl fmt::Display for CircuitLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup => write!(f, "setup"),
            Self::Active => write!(f, "active"),
            Self::Rotating => write!(f, "rotating"),
            Self::Expired => write!(f, "expired"),
            Self::TornDown => write!(f, "torn-down"),
        }
    }
}

// ─── CircuitEpoch ────────────────────────────────────────────────────────────

/// A key epoch within a circuit.
///
/// Each epoch has its own set of forwarding keys, but the circuit_id and
/// sequence counter are shared across epochs. The sequence counter NEVER
/// resets — it continues monotonically across key rotations.
#[derive(Debug, Clone)]
pub struct CircuitEpoch {
    /// The epoch number (0 for the initial epoch, 1 after first rotation, etc.).
    pub epoch: u32,
    /// The forwarding keys for this epoch (opaque bytes — in production these
    /// would be AEAD keys derived via HKDF).
    pub keys: Vec<u8>,
    /// The sequence counter at the START of this epoch.
    pub start_seq: u64,
    /// The current sequence counter (monotonic, never resets).
    pub current_seq: u64,
    /// When this epoch was established.
    pub established_at: u64,
}

impl CircuitEpoch {
    /// Create a new epoch with fresh keys.
    fn new(epoch: u32, keys: Vec<u8>, start_seq: u64, now: u64) -> Self {
        Self {
            epoch,
            keys,
            start_seq,
            current_seq: start_seq,
            established_at: now,
        }
    }

    /// Advance the sequence counter. Returns the new sequence number.
    /// This is monotonic — it NEVER resets.
    pub fn advance_seq(&mut self) -> u64 {
        self.current_seq = self.current_seq.saturating_add(1);
        self.current_seq
    }

    /// Zero the keys (for resource cleanup).
    fn zero_keys(&mut self) {
        for b in &mut self.keys {
            *b = 0;
        }
    }
}

// ─── CircuitLifecycleManager ─────────────────────────────────────────────────

/// Manages the full lifecycle of a circuit.
///
/// ## Properties enforced
///
/// 1. **No sequence reuse** — `current_seq()` is monotonic across epochs.
/// 2. **No stale circuit reuse** — an Expired/TornDown circuit cannot be
///    re-activated.
/// 3. **No forwarding state survives its circuit** — `teardown()` zeros
///    all keys and clears all state.
/// 4. **Key rotation** — `rotate_keys()` creates a new epoch with fresh
///    keys, but the sequence counter continues from where it left off.
#[derive(Debug)]
pub struct CircuitLifecycleManager {
    /// The circuit's unique ID.
    circuit_id: [u8; 32],
    /// The current lifecycle state.
    state: CircuitLifecycleState,
    /// The current epoch (keys + sequence counter).
    current_epoch: CircuitEpoch,
    /// All past epochs (for audit — keys are zeroed).
    past_epochs: Vec<CircuitEpoch>,
    /// When the circuit was created.
    created_at: u64,
    /// When the circuit expires.
    expires_at: u64,
    /// The replay window (set of seen sequence numbers — prevents replay).
    replay_window: HashMap<u64, bool>,
    /// Maximum replay window size (old entries are evicted).
    max_replay_window: usize,
}

impl CircuitLifecycleManager {
    /// Create a new circuit lifecycle manager.
    ///
    /// # Arguments
    /// * `circuit_id` — The unique 32-byte circuit ID.
    /// * `initial_keys` — The initial forwarding keys.
    /// * `created_at` — When the circuit was created (unix seconds).
    /// * `lifetime_secs` — The circuit's lifetime (seconds).
    #[must_use]
    pub fn new(circuit_id: [u8; 32], initial_keys: Vec<u8>, created_at: u64, lifetime_secs: u64) -> Self {
        let expires_at = created_at.saturating_add(lifetime_secs);
        Self {
            circuit_id,
            state: CircuitLifecycleState::Setup,
            current_epoch: CircuitEpoch::new(0, initial_keys, 0, created_at),
            past_epochs: Vec::new(),
            created_at,
            expires_at,
            replay_window: HashMap::new(),
            max_replay_window: 1024,
        }
    }

    /// Activate the circuit (transition Setup → Active).
    ///
    /// # Errors
    /// Returns `CircuitLifecycleError` if the circuit is not in Setup state.
    pub fn activate(&mut self, now: u64) -> Result<(), CircuitLifecycleError> {
        if self.state != CircuitLifecycleState::Setup {
            return Err(CircuitLifecycleError::InvalidTransition {
                from: self.state,
                to: CircuitLifecycleState::Active,
            });
        }
        if self.is_expired(now) {
            self.state = CircuitLifecycleState::Expired;
            return Err(CircuitLifecycleError::ExpiredBeforeActivation);
        }
        self.state = CircuitLifecycleState::Active;
        Ok(())
    }

    /// Get the circuit ID.
    #[must_use]
    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }

    /// Get the current lifecycle state.
    #[must_use]
    pub fn state(&self) -> CircuitLifecycleState {
        self.state
    }

    /// Get the current epoch number.
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch.epoch
    }

    /// Get the current sequence counter (monotonic across epochs).
    #[must_use]
    pub fn current_seq(&self) -> u64 {
        self.current_epoch.current_seq
    }

    /// Get the current keys.
    #[must_use]
    pub fn current_keys(&self) -> &[u8] {
        &self.current_epoch.keys
    }

    /// Check if the circuit has expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Get the expiry timestamp.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Advance the sequence counter (allocates a new sequence number).
    ///
    /// # Errors
    /// Returns `CircuitLifecycleError` if the circuit is not Active.
    pub fn next_seq(&mut self, now: u64) -> Result<u64, CircuitLifecycleError> {
        if self.state != CircuitLifecycleState::Active {
            return Err(CircuitLifecycleError::NotActive { state: self.state });
        }
        if self.is_expired(now) {
            self.state = CircuitLifecycleState::Expired;
            return Err(CircuitLifecycleError::ExpiredAtSeq);
        }
        let seq = self.current_epoch.advance_seq();
        // Add to replay window.
        self.replay_window.insert(seq, true);
        // Evict old entries if window is too large.
        if self.replay_window.len() > self.max_replay_window {
            // Evict the oldest entries (lowest seq numbers).
            let to_remove: Vec<u64> = self.replay_window.keys()
                .filter(|&&s| s < seq - self.max_replay_window as u64 / 2)
                .copied()
                .collect();
            for s in to_remove {
                self.replay_window.remove(&s);
            }
        }
        Ok(seq)
    }

    /// Check if a sequence number has been seen (replay detection).
    #[must_use]
    pub fn is_replay(&self, seq: u64) -> bool {
        self.replay_window.contains_key(&seq)
    }

    /// Rotate the keys (create a new epoch).
    ///
    /// The sequence counter CONTINUES from where it left off — it does NOT
    /// reset. The old epoch's keys are zeroed and moved to `past_epochs`.
    ///
    /// # Errors
    /// Returns `CircuitLifecycleError` if the circuit is not Active.
    pub fn rotate_keys(&mut self, new_keys: Vec<u8>, now: u64) -> Result<(), CircuitLifecycleError> {
        if self.state != CircuitLifecycleState::Active {
            return Err(CircuitLifecycleError::NotActive { state: self.state });
        }
        if self.is_expired(now) {
            self.state = CircuitLifecycleState::Expired;
            return Err(CircuitLifecycleError::ExpiredDuringRotation);
        }

        // Transition to Rotating.
        self.state = CircuitLifecycleState::Rotating;

        // Capture the current epoch number + seq before replacing.
        let new_epoch_num = self.current_epoch.epoch + 1;
        let continuation_seq = self.current_epoch.current_seq;

        // Move the current epoch to past_epochs (zero its keys).
        let mut old_epoch = std::mem::replace(
            &mut self.current_epoch,
            CircuitEpoch::new(
                new_epoch_num,
                new_keys,
                continuation_seq, // seq continues!
                now,
            ),
        );
        old_epoch.zero_keys();
        self.past_epochs.push(old_epoch);

        // Transition back to Active.
        self.state = CircuitLifecycleState::Active;
        Ok(())
    }

    /// Tear down the circuit (explicit close).
    ///
    /// ALL keys are zeroed, ALL state is cleared. The circuit CANNOT be
    /// re-activated after teardown.
    ///
    /// # Errors
    /// Returns `CircuitLifecycleError` if the circuit is already TornDown.
    pub fn teardown(&mut self) -> Result<(), CircuitLifecycleError> {
        if self.state == CircuitLifecycleState::TornDown {
            return Err(CircuitLifecycleError::AlreadyTornDown);
        }

        // Zero the current epoch's keys.
        self.current_epoch.zero_keys();

        // Zero all past epochs' keys (they should already be zeroed, but
        // this is defence in depth).
        for epoch in &mut self.past_epochs {
            epoch.zero_keys();
        }

        // Clear the replay window.
        self.replay_window.clear();

        // Transition to TornDown.
        self.state = CircuitLifecycleState::TornDown;
        Ok(())
    }

    /// Check if the circuit is active (can carry traffic).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == CircuitLifecycleState::Active
    }

    /// Check if the circuit has been torn down.
    #[must_use]
    pub fn is_torn_down(&self) -> bool {
        self.state == CircuitLifecycleState::TornDown
    }

    /// Get the number of past epochs (for audit).
    #[must_use]
    pub fn past_epoch_count(&self) -> usize {
        self.past_epochs.len()
    }

    /// Get the replay window size (for monitoring).
    #[must_use]
    pub fn replay_window_size(&self) -> usize {
        self.replay_window.len()
    }

    /// Evidence level for the lifecycle state: Observed.
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Observed
    }

    /// Check if the circuit should be expired (and expire it if so).
    pub fn check_expiry(&mut self, now: u64) -> bool {
        if self.is_expired(now) && self.state == CircuitLifecycleState::Active {
            self.state = CircuitLifecycleState::Expired;
            // Zero keys on expiry (resource cleanup).
            self.current_epoch.zero_keys();
            self.replay_window.clear();
            true
        } else {
            false
        }
    }
}

impl Drop for CircuitLifecycleManager {
    fn drop(&mut self) {
        // Defence in depth: zero all keys when the manager is dropped.
        self.current_epoch.zero_keys();
        for epoch in &mut self.past_epochs {
            epoch.zero_keys();
        }
        self.replay_window.clear();
    }
}

// ─── CircuitLifecycleError ──────────────────────────────────────────────────

/// Errors from the CircuitLifecycleManager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitLifecycleError {
    /// Invalid state transition.
    InvalidTransition { from: CircuitLifecycleState, to: CircuitLifecycleState },
    /// The circuit expired before it could be activated.
    ExpiredBeforeActivation,
    /// The circuit is not Active (needed for seq/rotation).
    NotActive { state: CircuitLifecycleState },
    /// The circuit expired while allocating a sequence number.
    ExpiredAtSeq,
    /// The circuit expired during key rotation.
    ExpiredDuringRotation,
    /// The circuit has already been torn down.
    AlreadyTornDown,
}

impl fmt::Display for CircuitLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} → {to}")
            }
            Self::ExpiredBeforeActivation => write!(f, "circuit expired before activation"),
            Self::NotActive { state } => write!(f, "circuit is not active (state: {state})"),
            Self::ExpiredAtSeq => write!(f, "circuit expired while allocating sequence number"),
            Self::ExpiredDuringRotation => write!(f, "circuit expired during key rotation"),
            Self::AlreadyTornDown => write!(f, "circuit has already been torn down"),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

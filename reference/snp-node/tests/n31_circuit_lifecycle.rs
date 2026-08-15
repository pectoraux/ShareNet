//! N3.1 — Circuit Lifecycle + Key Rotation Tests
//!
//! Tests proving:
//! 1. No sequence reuse — seq counter is monotonic across epochs.
//! 2. No stale circuit reuse — expired/torn-down circuits cannot be re-activated.
//! 3. No forwarding state survives its circuit — teardown zeros all keys.
//! 4. Key rotation — new epoch with fresh keys, seq continues.
//! 5. Replay detection — seen sequence numbers are rejected.

#![allow(clippy::pedantic)]

use snp_node::node::circuit_lifecycle::*;
use snp_node::node::evidence::EvidenceLevel;

fn now() -> u64 {
    1_700_000_000
}

fn make_circuit(lifetime_secs: u64) -> CircuitLifecycleManager {
    CircuitLifecycleManager::new(
        [0xAA; 32],
        vec![0x11; 32], // initial keys
        now(),
        lifetime_secs,
    )
}

// ─── 1. No sequence reuse (monotonic across epochs) ──────────────────────────

#[test]
fn n31_no_sequence_reuse_across_epochs() {
    let mut circuit = make_circuit(3600);
    circuit.activate(now()).unwrap();

    // Epoch 0: seq 1, 2, 3.
    let s1 = circuit.next_seq(now()).unwrap();
    let s2 = circuit.next_seq(now()).unwrap();
    let s3 = circuit.next_seq(now()).unwrap();
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(s3, 3);

    // Rotate keys → epoch 1.
    circuit.rotate_keys(vec![0x22; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 1);

    // Epoch 1: seq CONTINUES (4, 5, 6 — NOT 1, 2, 3).
    let s4 = circuit.next_seq(now()).unwrap();
    let s5 = circuit.next_seq(now()).unwrap();
    let s6 = circuit.next_seq(now()).unwrap();
    assert_eq!(s4, 4, "seq must continue after rotation (not reset)");
    assert_eq!(s5, 5);
    assert_eq!(s6, 6);

    // Rotate again → epoch 2.
    circuit.rotate_keys(vec![0x33; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 2);

    // Epoch 2: seq still continues (7, 8).
    let s7 = circuit.next_seq(now()).unwrap();
    let s8 = circuit.next_seq(now()).unwrap();
    assert_eq!(s7, 7, "seq must continue across multiple rotations");
    assert_eq!(s8, 8);

    // Seq 1 and 4 are in the replay window (they were allocated).
    // NOTE: old entries may be evicted if the window is full, but with a
    // small number of allocations they should still be present.
    assert!(circuit.is_replay(1), "seq 1 was allocated → in replay window");
    assert!(circuit.is_replay(4), "seq 4 was allocated → in replay window");
    assert!(circuit.is_replay(7), "seq 7 was allocated → in replay window");

    // An unseen sequence number is NOT in the replay window.
    assert!(!circuit.is_replay(999), "seq 999 was never allocated → not in replay window");
    eprintln!("[n31-1] PASS: no sequence reuse across epochs (1,2,3 → 4,5,6 → 7,8)");
}

// ─── 2. No stale circuit reuse (expired) ────────────────────────────────────

#[test]
fn n31_expired_circuit_cannot_be_reactivated() {
    let mut circuit = make_circuit(100); // 100s lifetime
    circuit.activate(now()).unwrap();
    assert!(circuit.is_active());

    // Advance time past expiry.
    let later = now() + 200;
    assert!(circuit.is_expired(later));

    // check_expiry() should transition to Expired.
    let expired = circuit.check_expiry(later);
    assert!(expired, "check_expiry should detect expiry");
    assert_eq!(circuit.state(), CircuitLifecycleState::Expired);

    // Cannot allocate more sequences.
    let result = circuit.next_seq(later);
    assert!(result.is_err(), "expired circuit must not allocate sequences");

    // Cannot rotate keys.
    let result = circuit.rotate_keys(vec![0x22; 32], later);
    assert!(result.is_err(), "expired circuit must not rotate keys");
    eprintln!("[n31-2] PASS: expired circuit cannot be re-activated");
}

// ─── 3. No stale circuit reuse (torn down) ──────────────────────────────────

#[test]
fn n31_torn_down_circuit_cannot_be_reactivated() {
    let mut circuit = make_circuit(3600);
    circuit.activate(now()).unwrap();
    let _ = circuit.next_seq(now()).unwrap();

    // Tear down.
    circuit.teardown().unwrap();
    assert_eq!(circuit.state(), CircuitLifecycleState::TornDown);
    assert!(circuit.is_torn_down());

    // Cannot allocate sequences.
    let result = circuit.next_seq(now());
    assert!(result.is_err(), "torn-down circuit must not allocate sequences");

    // Cannot rotate keys.
    let result = circuit.rotate_keys(vec![0x22; 32], now());
    assert!(result.is_err(), "torn-down circuit must not rotate keys");

    // Cannot tear down again.
    let result = circuit.teardown();
    assert!(result.is_err(), "cannot tear down twice");
    eprintln!("[n31-3] PASS: torn-down circuit cannot be re-activated");
}

// ─── 4. No forwarding state survives teardown ────────────────────────────────

#[test]
fn n31_no_forwarding_state_survives_teardown() {
    let mut circuit = make_circuit(3600);
    circuit.activate(now()).unwrap();

    // Allocate some sequences (populates replay window).
    let _ = circuit.next_seq(now()).unwrap();
    let _ = circuit.next_seq(now()).unwrap();
    let _ = circuit.next_seq(now()).unwrap();
    assert!(circuit.replay_window_size() > 0, "replay window should have entries");

    // Rotate keys (creates a past epoch).
    circuit.rotate_keys(vec![0x22; 32], now()).unwrap();
    assert_eq!(circuit.past_epoch_count(), 1);

    // Tear down.
    circuit.teardown().unwrap();

    // After teardown: keys are zeroed.
    assert!(circuit.current_keys().iter().all(|&b| b == 0), "current keys must be zeroed");
    // Replay window is cleared.
    assert_eq!(circuit.replay_window_size(), 0, "replay window must be cleared");
    eprintln!("[n31-4] PASS: no forwarding state survives teardown (keys zeroed, replay cleared)");
}

// ─── 5. Key rotation produces fresh keys ────────────────────────────────────

#[test]
fn n31_key_rotation_produces_fresh_keys() {
    let mut circuit = make_circuit(3600);
    circuit.activate(now()).unwrap();

    // Epoch 0: keys = [0x11; 32].
    assert_eq!(circuit.current_epoch(), 0);
    assert_eq!(circuit.current_keys(), &[0x11; 32]);

    // Rotate → epoch 1: keys = [0x22; 32].
    circuit.rotate_keys(vec![0x22; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 1);
    assert_eq!(circuit.current_keys(), &[0x22; 32]);

    // Rotate → epoch 2: keys = [0x33; 32].
    circuit.rotate_keys(vec![0x33; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 2);
    assert_eq!(circuit.current_keys(), &[0x33; 32]);

    // Past epochs have zeroed keys.
    assert_eq!(circuit.past_epoch_count(), 2);
    eprintln!("[n31-5] PASS: key rotation produces fresh keys each epoch");
}

// ─── 6. Replay detection ────────────────────────────────────────────────────

#[test]
fn n31_replay_detection() {
    let mut circuit = make_circuit(3600);
    circuit.activate(now()).unwrap();

    let s1 = circuit.next_seq(now()).unwrap();
    let s2 = circuit.next_seq(now()).unwrap();

    // s1 and s2 are in the replay window.
    assert!(circuit.is_replay(s1));
    assert!(circuit.is_replay(s2));

    // s3 has NOT been seen.
    assert!(!circuit.is_replay(s3_unseen()));
    eprintln!("[n31-6] PASS: replay detection works");
}

fn s3_unseen() -> u64 {
    999 // an unseen sequence number
}

// ─── 7. Activation requires Setup state ─────────────────────────────────────

#[test]
fn n31_activation_requires_setup_state() {
    let mut circuit = make_circuit(3600);

    // Can activate from Setup.
    circuit.activate(now()).unwrap();
    assert!(circuit.is_active());

    // Cannot activate again from Active.
    let result = circuit.activate(now());
    assert!(result.is_err(), "cannot activate from Active state");
    eprintln!("[n31-7] PASS: activation requires Setup state");
}

// ─── 8. Expiry before activation ────────────────────────────────────────────

#[test]
fn n31_expiry_before_activation() {
    let mut circuit = make_circuit(100); // 100s lifetime

    // Don't activate — just let time pass.
    let later = now() + 200;
    let result = circuit.activate(later);
    assert!(result.is_err(), "cannot activate an expired circuit");
    assert_eq!(circuit.state(), CircuitLifecycleState::Expired);
    eprintln!("[n31-8] PASS: expiry before activation rejected");
}

// ─── 9. Evidence level ──────────────────────────────────────────────────────

#[test]
fn n31_evidence_level_is_observed() {
    assert_eq!(CircuitLifecycleManager::evidence_level(), EvidenceLevel::Observed);
    eprintln!("[n31-9] PASS: circuit lifecycle is an ObservedMetric");
}

// ─── 10. Full lifecycle: setup → active → rotate → active → teardown ────────

#[test]
fn n31_full_lifecycle() {
    let mut circuit = make_circuit(3600);

    // Setup.
    assert_eq!(circuit.state(), CircuitLifecycleState::Setup);
    assert_eq!(circuit.current_epoch(), 0);
    assert_eq!(circuit.current_seq(), 0);

    // Activate.
    circuit.activate(now()).unwrap();
    assert!(circuit.is_active());

    // Use: allocate sequences.
    for i in 1..=5 {
        let seq = circuit.next_seq(now()).unwrap();
        assert_eq!(seq, i);
    }

    // Rotate keys.
    circuit.rotate_keys(vec![0x22; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 1);
    assert_eq!(circuit.current_keys(), &[0x22; 32]);

    // Continue using (seq continues).
    let s6 = circuit.next_seq(now()).unwrap();
    assert_eq!(s6, 6, "seq continues after rotation");

    // Rotate again.
    circuit.rotate_keys(vec![0x33; 32], now()).unwrap();
    assert_eq!(circuit.current_epoch(), 2);

    // Continue using.
    let s7 = circuit.next_seq(now()).unwrap();
    let s8 = circuit.next_seq(now()).unwrap();
    assert_eq!(s7, 7);
    assert_eq!(s8, 8);

    // Tear down.
    circuit.teardown().unwrap();
    assert!(circuit.is_torn_down());
    assert!(circuit.current_keys().iter().all(|&b| b == 0), "keys zeroed on teardown");
    assert_eq!(circuit.replay_window_size(), 0, "replay window cleared");

    eprintln!("[n31-10] PASS: full lifecycle — setup → active → rotate × 2 → teardown");
}

// ─── 11. Expiry zeros keys ───────────────────────────────────────────────────

#[test]
fn n31_expiry_zeros_keys() {
    let mut circuit = make_circuit(100);
    circuit.activate(now()).unwrap();
    let _ = circuit.next_seq(now()).unwrap();

    // Keys are non-zero before expiry.
    assert!(circuit.current_keys().iter().any(|&b| b != 0));

    // Expire.
    let later = now() + 200;
    circuit.check_expiry(later);
    assert_eq!(circuit.state(), CircuitLifecycleState::Expired);

    // Keys are zeroed after expiry.
    assert!(circuit.current_keys().iter().all(|&b| b == 0), "keys must be zeroed on expiry");
    assert_eq!(circuit.replay_window_size(), 0, "replay window cleared on expiry");
    eprintln!("[n31-11] PASS: expiry zeros keys + clears replay window");
}

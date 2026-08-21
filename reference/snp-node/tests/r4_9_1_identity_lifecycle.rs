//! R4.9.1 — Identity Lifecycle Foundation tests.
//!
//! Tests for:
//! - Identity rotation preserves service (old identity active until new is durable)
//! - Failed rotation keeps previous identity
//! - Revoked identity rejected for new operations
//! - Retired identity not selected for new sessions
//! - Startup persistence/recovery
//! - Corrupt identity file fails closed

#![allow(clippy::pedantic)]

use snp_identity::{IdentityLifecycle, IdentityLifecycleError, IdentityState, NodeIdentity};

fn ephemeral_path() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r4-9-1-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("identity.bin")
}

fn fresh_identity() -> NodeIdentity {
    let mut secret = [0u8; 32];
    let _ = getrandom::getrandom(&mut secret);
    NodeIdentity::from_secret(secret)
}

// ─── 1. Rotation preserves service ──────────────────────────────────────

/// Old identity is active → begin rotation → persist new → new becomes active.
/// The old identity's NodeId differs from the new identity's NodeId.
#[test]
fn r4_9_1_identity_rotation_preserves_service() {
    let path = ephemeral_path();
    let old_identity = fresh_identity();
    let new_identity = fresh_identity();
    let old_node_id = old_identity.node_id;
    let new_node_id = new_identity.node_id;
    assert_ne!(old_node_id, new_node_id, "identities must differ");

    let mut lifecycle = IdentityLifecycle::new(old_identity)
        .with_path(&path);
    lifecycle.save().expect("initial save");
    assert_eq!(lifecycle.state(), IdentityState::Active);
    assert_eq!(lifecycle.identity().node_id, old_node_id);

    // Begin rotation.
    lifecycle.begin_rotation(new_identity).expect("begin rotation");
    assert_eq!(lifecycle.state(), IdentityState::Rotating);
    // Old identity remains authoritative during rotation.
    assert_eq!(lifecycle.identity().node_id, old_node_id);

    // Complete rotation.
    lifecycle.complete_rotation().expect("complete rotation");
    assert_eq!(lifecycle.state(), IdentityState::Active);
    // New identity is now authoritative.
    assert_eq!(lifecycle.identity().node_id, new_node_id);

    // Reload from disk — new identity must be persisted.
    let reloaded = IdentityLifecycle::load(&path).expect("reload");
    assert_eq!(reloaded.state(), IdentityState::Active);
    assert_eq!(reloaded.identity().node_id, new_node_id);
    eprintln!("[test] PASS: rotation preserves service — new identity persisted");
}

// ─── 2. Failed rotation keeps previous identity ────────────────────────

/// If persistence fails during rotation, the old identity remains active.
#[test]
fn r4_9_1_failed_rotation_keeps_previous_identity() {
    let old_identity = fresh_identity();
    let new_identity = fresh_identity();
    let old_node_id = old_identity.node_id;
    let new_node_id = new_identity.node_id;
    let old_secret = old_identity.secret_key;

    // Create lifecycle with a path that doesn't exist yet.
    let path = ephemeral_path();
    let mut lifecycle = IdentityLifecycle::new(old_identity).with_path(&path);
    lifecycle.save().expect("initial save");

    // Make the parent directory read-only → save will fail.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))
            .expect("set read-only");
    }

    // Begin rotation.
    lifecycle.begin_rotation(new_identity).expect("begin rotation");
    assert_eq!(lifecycle.state(), IdentityState::Rotating);

    // Attempt complete_rotation — should fail (persistence error).
    let result = lifecycle.complete_rotation();
    assert!(
        result.is_err(),
        "rotation must fail when persistence fails"
    );

    // Restore permissions for cleanup.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .expect("restore permissions");
    }

    // The old identity MUST remain active.
    assert_eq!(lifecycle.state(), IdentityState::Active);
    assert_eq!(
        lifecycle.identity().node_id, old_node_id,
        "old identity must remain active after failed rotation"
    );
    assert_eq!(
        lifecycle.identity().secret_key, old_secret,
        "old secret key must remain after failed rotation"
    );
    // The new identity must NOT be active.
    assert_ne!(
        lifecycle.identity().node_id, new_node_id,
        "new identity must NOT be active after failed rotation"
    );
    eprintln!("[test] PASS: failed rotation keeps previous identity");
}

// ─── 3. Revoked identity rejected ──────────────────────────────────────

/// A revoked identity cannot be used for new authenticated operations.
#[test]
fn r4_9_1_revoked_identity_rejected() {
    let path = ephemeral_path();
    let identity = fresh_identity();
    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");

    assert!(lifecycle.is_active(), "identity must be active initially");

    // Revoke.
    lifecycle.revoke().expect("revoke");
    assert_eq!(lifecycle.state(), IdentityState::Revoked);
    assert!(
        !lifecycle.is_active(),
        "revoked identity must not be active for new operations"
    );

    // Cannot begin rotation from Revoked state.
    let result = lifecycle.begin_rotation(fresh_identity());
    assert!(
        result.is_err(),
        "cannot begin rotation from Revoked state"
    );
    match result {
        Err(IdentityLifecycleError::InvalidRotationSource { current }) => {
            assert_eq!(current, IdentityState::Revoked);
        }
        _ => panic!("expected InvalidRotationSource"),
    }

    // Reload from disk — revocation must be persisted.
    let reloaded = IdentityLifecycle::load(&path).expect("reload");
    assert_eq!(reloaded.state(), IdentityState::Revoked);
    assert!(!reloaded.is_active());
    eprintln!("[test] PASS: revoked identity rejected for new operations");
}

// ─── 4. Retired identity not selected ──────────────────────────────────

/// A retired identity must never be selected as the active identity.
#[test]
fn r4_9_1_retired_identity_not_selected_for_new_sessions() {
    let path = ephemeral_path();
    let identity = fresh_identity();
    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");

    assert!(lifecycle.is_active());

    // Retire.
    lifecycle.retire().expect("retire");
    assert_eq!(lifecycle.state(), IdentityState::Retired);
    assert!(
        !lifecycle.is_active(),
        "retired identity must not be active for new sessions"
    );

    // Cannot begin rotation from Retired state.
    let result = lifecycle.begin_rotation(fresh_identity());
    assert!(
        result.is_err(),
        "cannot begin rotation from Retired state"
    );

    // Reload — retirement must be persisted.
    let reloaded = IdentityLifecycle::load(&path).expect("reload");
    assert_eq!(reloaded.state(), IdentityState::Retired);
    assert!(!reloaded.is_active());
    eprintln!("[test] PASS: retired identity not selected for new sessions");
}

// ─── 5. Startup: load_or_create ────────────────────────────────────────

/// First call creates + persists. Second call loads the same identity.
#[test]
fn r4_9_1_load_or_create_initializes_and_persists() {
    let path = ephemeral_path();
    assert!(!path.exists(), "identity file must not exist initially");

    // First call — creates + persists.
    let lifecycle1 = IdentityLifecycle::load_or_create(&path).expect("create");
    assert!(path.exists(), "identity file must be created");
    assert_eq!(lifecycle1.state(), IdentityState::Active);
    let node_id1 = lifecycle1.identity().node_id;

    // Second call — loads the same identity.
    let lifecycle2 = IdentityLifecycle::load_or_create(&path).expect("load");
    assert_eq!(lifecycle2.state(), IdentityState::Active);
    let node_id2 = lifecycle2.identity().node_id;
    assert_eq!(
        node_id1, node_id2,
        "loaded identity must match the created identity"
    );
    eprintln!("[test] PASS: load_or_create initializes + persists + reloads");
}

// ─── 6. Corrupt identity file fails closed ─────────────────────────────

/// A corrupt identity file must NOT silently generate a new identity.
/// Missing file = first initialization. Corrupt file = integrity failure.
#[test]
fn r4_9_1_corrupt_identity_file_fails_closed() {
    let path = ephemeral_path();

    // Write garbage to the file.
    std::fs::write(&path, b"NOT A VALID IDENTITY FILE").expect("write garbage");
    assert!(path.exists());

    // load_or_create must FAIL (not silently create a new identity).
    let result = IdentityLifecycle::load_or_create(&path);
    assert!(
        result.is_err(),
        "corrupt identity file must fail closed — not silently generate new identity"
    );
    match result {
        Err(IdentityLifecycleError::Corrupt(_)) => {
            eprintln!("[test] PASS: corrupt identity file fails closed (Corrupt error)");
        }
        Err(e) => panic!("expected Corrupt error, got {e:?}"),
        Ok(_) => panic!("must NOT succeed with corrupt file"),
    }
}

// ─── 7. Truncated identity file fails closed ───────────────────────────

#[test]
fn r4_9_1_truncated_identity_file_fails_closed() {
    let path = ephemeral_path();

    // Write a valid magic + version but truncated (no secret key).
    let mut data = Vec::new();
    data.extend_from_slice(b"SNPI");
    data.push(1); // version
    std::fs::write(&path, &data).expect("write truncated");

    let result = IdentityLifecycle::load_or_create(&path);
    assert!(result.is_err(), "truncated identity file must fail closed");
    eprintln!("[test] PASS: truncated identity file fails closed");
}

// ─── 8. Wrong magic fails closed ───────────────────────────────────────

#[test]
fn r4_9_1_wrong_magic_fails_closed() {
    let path = ephemeral_path();

    let mut data = Vec::new();
    data.extend_from_slice(b"XXXX"); // wrong magic
    data.push(1);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(b"active\0");
    std::fs::write(&path, &data).expect("write wrong magic");

    let result = IdentityLifecycle::load_or_create(&path);
    assert!(result.is_err(), "wrong magic must fail closed");
    eprintln!("[test] PASS: wrong magic fails closed");
}

// ─── 9. Unsupported version fails closed ───────────────────────────────

#[test]
fn r4_9_1_unsupported_version_fails_closed() {
    let path = ephemeral_path();

    let mut data = Vec::new();
    data.extend_from_slice(b"SNPI");
    data.push(99); // unsupported version
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(b"active\0");
    std::fs::write(&path, &data).expect("write unsupported version");

    let result = IdentityLifecycle::load_or_create(&path);
    assert!(result.is_err(), "unsupported version must fail closed");
    eprintln!("[test] PASS: unsupported version fails closed");
}

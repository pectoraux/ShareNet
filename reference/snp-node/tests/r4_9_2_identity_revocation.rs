//! R4.9.2 — Identity Revocation and Trust Update tests.
//!
//! Tests for:
//! - Revocation survives restart
//! - Revoked identity rejected for new sessions
//! - Revoked peer not trusted for new authenticated sessions
//! - Historical signatures remain verifiable after revocation
//! - Revocation persistence failure preserves active state

#![allow(clippy::pedantic)]

use snp_identity::{
    IdentityLifecycle, IdentityState, NodeIdentity, RevocationStore,
};

fn ephemeral_path(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r4-9-2-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join(suffix)
}

fn fresh_identity() -> NodeIdentity {
    let mut secret = [0u8; 32];
    let _ = getrandom::getrandom(&mut secret);
    NodeIdentity::from_secret(secret)
}

// ─── 1. Revocation survives restart ─────────────────────────────────────

/// Create identity → revoke → drop → reload → assert revoked.
#[test]
fn r4_9_2_revocation_survives_restart() {
    let path = ephemeral_path("identity.bin");
    let identity = fresh_identity();
    let node_id = identity.node_id;

    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");
    assert_eq!(lifecycle.state(), IdentityState::Active);

    // Revoke.
    lifecycle.revoke().expect("revoke");
    assert_eq!(lifecycle.state(), IdentityState::Revoked);
    assert!(lifecycle.is_revoked());
    assert!(!lifecycle.is_authorized_for_new_sessions());

    // Drop + reload from disk.
    drop(lifecycle);
    let reloaded = IdentityLifecycle::load(&path).expect("reload");

    // Revocation must survive restart.
    assert_eq!(reloaded.state(), IdentityState::Revoked);
    assert!(reloaded.is_revoked());
    assert!(!reloaded.is_authorized_for_new_sessions());
    assert_eq!(reloaded.identity().node_id, node_id);
    eprintln!("[test] PASS: revocation survives restart");
}

// ─── 2. Revoked identity rejected ───────────────────────────────────────

/// A revoked identity cannot be used for new authenticated operations.
/// The lifecycle layer rejects rotation attempts and reports not-authorized.
#[test]
fn r4_9_2_revoked_identity_rejected() {
    let path = ephemeral_path("identity2.bin");
    let identity = fresh_identity();
    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");

    assert!(lifecycle.is_authorized_for_new_sessions());

    // Revoke.
    lifecycle.revoke().expect("revoke");
    assert!(!lifecycle.is_authorized_for_new_sessions());
    assert!(lifecycle.is_revoked());

    // Cannot begin rotation from Revoked state.
    let result = lifecycle.begin_rotation(fresh_identity());
    assert!(result.is_err(), "cannot begin rotation from Revoked state");

    // The identity's cryptographic material is still accessible
    // (for historical verification).
    let _pub_key = lifecycle.identity().public_key;
    let _node_id = lifecycle.identity().node_id;
    eprintln!("[test] PASS: revoked identity rejected for new operations");
}

// ─── 3. Revoked peer not trusted ────────────────────────────────────────

/// A peer whose NodeId is in the RevocationStore is not authorized for
/// new authenticated sessions.
#[test]
fn r4_9_2_revoked_peer_not_trusted_for_new_session() {
    let rev_path = ephemeral_path("revocation.bin");
    let peer_identity = fresh_identity();
    let peer_node_id = peer_identity.node_id;
    let other_identity = fresh_identity();
    let other_node_id = other_identity.node_id;

    let mut store = RevocationStore::load_or_create(&rev_path).expect("create store");
    assert!(store.is_empty());
    assert!(store.is_authorized_for_new_sessions(&peer_node_id));
    assert!(store.is_authorized_for_new_sessions(&other_node_id));

    // Revoke the peer.
    store.revoke(peer_node_id).expect("revoke peer");
    assert_eq!(store.len(), 1);
    assert!(!store.is_authorized_for_new_sessions(&peer_node_id));
    assert!(store.is_revoked(&peer_node_id));

    // Other peer is still authorized.
    assert!(store.is_authorized_for_new_sessions(&other_node_id));
    assert!(!store.is_revoked(&other_node_id));

    // Restart — revocation survives.
    drop(store);
    let reloaded = RevocationStore::load(&rev_path).expect("reload");
    assert!(!reloaded.is_authorized_for_new_sessions(&peer_node_id));
    assert!(reloaded.is_revoked(&peer_node_id));
    assert!(reloaded.is_authorized_for_new_sessions(&other_node_id));
    eprintln!("[test] PASS: revoked peer not trusted for new sessions");
}

// ─── 4. Historical signature remains verifiable ─────────────────────────

/// A signature created while the identity was Active remains
/// cryptographically valid AFTER revocation. Revocation does NOT erase
/// the ability to verify historical signatures.
#[test]
fn r4_9_2_historical_signature_remains_verifiable() {
    use snp_crypto::{ed25519_sign, ed25519_verify};

    let path = ephemeral_path("identity3.bin");
    let identity = fresh_identity();
    let public_key = identity.public_key;
    let secret_key = identity.secret_key;

    // Create a signature while Active.
    let message = b"historical custody receipt";
    let signature = ed25519_sign(&secret_key, message);
    assert!(ed25519_verify(&public_key, message, &signature));

    // Now revoke the identity.
    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");
    lifecycle.revoke().expect("revoke");
    assert!(lifecycle.is_revoked());

    // The historical signature is STILL valid — revocation does not
    // invalidate past signatures. It only prevents new authenticated
    // sessions.
    assert!(
        ed25519_verify(&public_key, message, &signature),
        "historical signature must remain verifiable after revocation"
    );

    // But the identity is NOT authorized for new sessions.
    assert!(
        !lifecycle.is_authorized_for_new_sessions(),
        "revoked identity must NOT be authorized for new sessions"
    );
    eprintln!("[test] PASS: historical signature remains verifiable — revocation ≠ cryptographic invalidation");
}

// ─── 5. Revocation persistence failure preserves active state ───────────

/// If persistence fails during revocation, the identity remains Active.
#[test]
fn r4_9_2_revocation_persistence_failure_preserves_active_state() {
    let path = ephemeral_path("identity4.bin");
    let identity = fresh_identity();
    let mut lifecycle = IdentityLifecycle::new(identity).with_path(&path);
    lifecycle.save().expect("initial save");

    // Make the parent directory read-only → save will fail.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))
            .expect("set read-only");
    }

    // Attempt revoke — should fail (persistence error).
    let result = lifecycle.revoke();
    assert!(
        result.is_err(),
        "revoke must fail when persistence fails"
    );

    // Restore permissions for cleanup.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = path.parent().unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .expect("restore permissions");
    }

    // The identity MUST remain Active.
    assert_eq!(
        lifecycle.state(),
        IdentityState::Active,
        "identity must remain Active after failed revocation"
    );
    assert!(
        lifecycle.is_authorized_for_new_sessions(),
        "identity must remain authorized after failed revocation"
    );
    assert!(
        !lifecycle.is_revoked(),
        "identity must NOT be revoked after failed revocation"
    );

    // Reload from disk — the persisted state must still be Active.
    let reloaded = IdentityLifecycle::load(&path).expect("reload");
    assert_eq!(reloaded.state(), IdentityState::Active);
    eprintln!("[test] PASS: revocation persistence failure preserves active state");
}

// ─── 6. RevocationStore corruption fails closed ────────────────────────

/// A corrupt revocation file must fail closed — not silently load empty.
#[test]
fn r4_9_2_revocation_store_corruption_fails_closed() {
    let path = ephemeral_path("revocation_corrupt.bin");

    // Write garbage.
    std::fs::write(&path, b"NOT A VALID REVOCATION FILE").expect("write garbage");

    let result = RevocationStore::load_or_create(&path);
    assert!(
        result.is_err(),
        "corrupt revocation file must fail closed"
    );
    eprintln!("[test] PASS: revocation store corruption fails closed");
}

// ─── 7. Idempotent revocation ──────────────────────────────────────────

/// Revoking an already-revoked NodeId is a no-op (idempotent).
#[test]
fn r4_9_2_idempotent_revocation() {
    let path = ephemeral_path("revocation_idempotent.bin");
    let peer_node_id = fresh_identity().node_id;

    let mut store = RevocationStore::load_or_create(&path).expect("create");
    store.revoke(peer_node_id).expect("first revoke");
    assert_eq!(store.len(), 1);

    // Second revoke — idempotent.
    store.revoke(peer_node_id).expect("second revoke (idempotent)");
    assert_eq!(store.len(), 1, "idempotent revoke must not duplicate");
    eprintln!("[test] PASS: idempotent revocation");
}

//! N3.4 — Content Re-integration Tests
//!
//! Tests proving content can be distributed over the ShareNet mesh:
//! - Content is chunked, Merkle-rooted, content-addressed
//! - Manifests are signed by the publisher
//! - Content can be published and retrieved
//! - Content integrity is verified (Merkle root + manifest signature)

#![allow(clippy::pedantic)]

use snp_crypto::sha256;
use snp_node::node::content_service::*;

fn now() -> u64 {
    1_700_000_000
}

fn fresh_secret(label: &[u8]) -> [u8; 32] {
    sha256(label)
}

// ─── 1. Publish + retrieve round-trip ────────────────────────────────────────

#[test]
fn n34_publish_and_retrieve_round_trip() {
    let publisher_sk = fresh_secret(b"n34-publisher");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();

    let content = b"Hello, ShareNet content mesh!";
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "text/plain",
        content,
        now(),
    );

    // The manifest is stored.
    assert_eq!(service.manifest_count(), 1);
    // The chunks are stored.
    assert!(service.chunk_count() > 0);

    // Retrieve the content.
    let retrieved = service.retrieve(&manifest_hash).unwrap();

    // The retrieved content matches the original.
    assert_eq!(retrieved, content);
    eprintln!("[n34-1] PASS: publish + retrieve round-trip");
}

// ─── 2. Manifest signature verifies ─────────────────────────────────────────

#[test]
fn n34_manifest_signature_verifies() {
    let publisher_sk = fresh_secret(b"n34-pub-sig");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "application/octet-stream",
        b"signed content",
        now(),
    );

    // The manifest signature verifies.
    assert!(service.verify_manifest(&manifest_hash, &publisher_pk),
        "manifest signature must verify");

    // A wrong public key does NOT verify.
    let wrong_pk = snp_crypto::derive_public_key(&fresh_secret(b"n34-wrong"));
    assert!(!service.verify_manifest(&manifest_hash, &wrong_pk),
        "manifest must NOT verify with wrong key");
    eprintln!("[n34-2] PASS: manifest signature verifies (and rejects wrong key)");
}

// ─── 3. Merkle root verification ─────────────────────────────────────────────

#[test]
fn n34_merkle_root_verification() {
    let publisher_sk = fresh_secret(b"n34-merkle");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "text/plain",
        b"content with multiple chunks if > 1MiB",
        now(),
    );

    // The manifest's Merkle root matches the chunk hashes.
    let manifest = service.store().get_manifest(&manifest_hash).unwrap();
    assert!(manifest.verify_merkle_root(),
        "Merkle root must match the chunk hashes");
    eprintln!("[n34-3] PASS: Merkle root verification");
}

// ─── 4. Large content (> 1 MiB) is multi-chunk ───────────────────────────────

#[test]
fn n34_large_content_multi_chunk() {
    let publisher_sk = fresh_secret(b"n34-large");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();

    // 3 MiB of content → at least 3 chunks (1 per MiB).
    // Use different data per MiB so chunks aren't deduplicated.
    let mut content = Vec::new();
    for i in 0..3u8 {
        content.extend_from_slice(&vec![i + 1; 1024 * 1024]); // 1 MiB of 0x01, 0x02, 0x03
    }
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "application/octet-stream",
        &content,
        now(),
    );

    // 3 chunks stored (each is different, so no dedup).
    assert_eq!(service.chunk_count(), 3, "3 MiB of unique data → 3 chunks");

    // Retrieve matches.
    let retrieved = service.retrieve(&manifest_hash).unwrap();
    assert_eq!(retrieved.len(), content.len());
    assert_eq!(retrieved, content);
    eprintln!("[n34-4] PASS: large content (3 MiB) → 3 chunks + round-trip");
}

// ─── 5. Chunk hash verification ──────────────────────────────────────────────

#[test]
fn n34_chunk_hash_verification() {
    let chunk = ContentChunk::new(b"chunk data".to_vec());
    assert!(chunk.verify_hash(), "chunk hash must match its data");

    // Tampered chunk.
    let mut tampered = chunk.clone();
    tampered.data[0] ^= 0xFF;
    assert!(!tampered.verify_hash(), "tampered chunk must NOT verify");
    eprintln!("[n34-5] PASS: chunk hash verification (tamper detected)");
}

// ─── 6. Missing chunk → retrieve fails ───────────────────────────────────────

#[test]
fn n34_missing_chunk_fails() {
    let publisher_sk = fresh_secret(b"n34-missing");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "text/plain",
        b"some content",
        now(),
    );

    // Get the manifest.
    let manifest = service.store.get_manifest(&manifest_hash).unwrap();
    let first_chunk_hash = manifest.chunk_hashes[0];

    // Create a new service that has the manifest but NOT the chunks.
    let mut service2 = ContentService::new();
    service2.store.put_manifest(manifest.clone());

    // Retrieve must fail — chunks are missing.
    let result = service2.retrieve(&manifest_hash);
    assert!(matches!(result, Err(ContentError::ChunkMissing { hash }) if hash == first_chunk_hash),
        "missing chunk must produce ChunkMissing error");
    eprintln!("[n34-6] PASS: missing chunk → retrieve fails");
}

// ─── 7. Manifest not found ───────────────────────────────────────────────────

#[test]
fn n34_manifest_not_found() {
    let service = ContentService::new();
    let fake_hash = [0xFF; 32];
    let result = service.retrieve(&fake_hash);
    assert!(matches!(result, Err(ContentError::ManifestNotFound { hash }) if hash == fake_hash),
        "non-existent manifest must produce ManifestNotFound");
    eprintln!("[n34-7] PASS: manifest not found → error");
}

// ─── 8. Content service shares identity with network layer ──────────────────

#[test]
fn n34_content_shares_network_identity() {
    // The publisher's Ed25519 keypair is the SAME keypair used for the
    // network layer (NodeAdvertisement, TransitRequest signatures, etc.).
    // Content is NOT a separate identity system.
    let publisher_sk = fresh_secret(b"n34-shared-identity");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    // The same keypair signs both the content manifest AND would sign
    // network-level objects (NodeAdvertisement, etc.).
    let mut service = ContentService::new();
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "text/plain",
        b"shared identity",
        now(),
    );

    // The manifest verifies with the SAME key used for network identity.
    assert!(service.verify_manifest(&manifest_hash, &publisher_pk),
        "content manifest must verify with the network-layer key");
    eprintln!("[n34-8] PASS: content shares identity with network layer");
}

// ─── 9. Multiple manifests coexist ───────────────────────────────────────────

#[test]
fn n34_multiple_manifests_coexist() {
    let publisher_sk = fresh_secret(b"n34-multi");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();

    let hash1 = service.publish(&publisher_sk, publisher_id, "text/plain", b"content A", now());
    let hash2 = service.publish(&publisher_sk, publisher_id, "text/plain", b"content B", now());
    let hash3 = service.publish(&publisher_sk, publisher_id, "application/json", b"{}", now());

    assert_eq!(service.manifest_count(), 3);

    // Each manifest retrieves independently.
    assert_eq!(service.retrieve(&hash1).unwrap(), b"content A");
    assert_eq!(service.retrieve(&hash2).unwrap(), b"content B");
    assert_eq!(service.retrieve(&hash3).unwrap(), b"{}");
    eprintln!("[n34-9] PASS: multiple manifests coexist");
}

// ─── 10. Empty content ────────────────────────────────────────────────────────

#[test]
fn n34_empty_content() {
    let publisher_sk = fresh_secret(b"n34-empty");
    let publisher_pk = snp_crypto::derive_public_key(&publisher_sk);
    let publisher_id = snp_crypto::derive_node_id(&publisher_pk);

    let mut service = ContentService::new();
    let manifest_hash = service.publish(
        &publisher_sk,
        publisher_id,
        "text/plain",
        b"",
        now(),
    );

    // Empty content produces 0 chunks (the chunks() iterator produces nothing).
    assert_eq!(service.chunk_count(), 0, "empty content → 0 chunks");
    assert_eq!(service.manifest_count(), 1);

    // Retrieve returns empty.
    let retrieved = service.retrieve(&manifest_hash).unwrap();
    assert!(retrieved.is_empty());
    eprintln!("[n34-10] PASS: empty content handled");
}

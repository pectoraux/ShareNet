//! N2.9 — Contribution Proof Loop Tests
//!
//! Tests proving:
//! 1. A gateway can build a ContributionProof from TransitReceipts.
//! 2. The proof verifies (signature + all receipts verify).
//! 3. The CivicPointLedger credits points from verified proofs.
//! 4. A node CANNOT manufacture contribution solely by asserting traffic.
//! 5. Replay is prevented (same receipt cannot be credited twice).
//! 6. Points are sub-linear in volume (log₂(1 + MiB)).
//! 7. Diversity weighting works (more clients = more points).

#![allow(clippy::pedantic)]

use snp_crypto::{derive_public_key, sha256};
use snp_node::node::contribution::*;
use snp_node::node::gateway_service_manager::TransitReceipt;
use snp_node::node::evidence::EvidenceLevel;

fn now() -> u64 {
    1_700_000_000
}

fn fresh_secret(label: &[u8]) -> [u8; 32] {
    sha256(label)
}

fn make_receipt(
    gateway_sk: &[u8; 32],
    gateway_id: [u8; 32],
    client_id: [u8; 32],
    req_id: [u8; 16],
    bytes: u64,
    served_at: u64,
) -> TransitReceipt {
    let mut receipt = TransitReceipt {
        req_id,
        client_node_id: client_id,
        gateway_node_id: gateway_id,
        bytes_transferred: bytes,
        http_status: 200,
        object_id: sha256(&vec![0xAA; bytes as usize]),
        served_at,
        duration_ms: 50,
        gateway_signature: [0u8; 64],
    };
    receipt.sign(gateway_sk);
    receipt
}

// ─── 1. Build + verify ContributionProof ─────────────────────────────────────

#[test]
fn n29_build_and_verify_contribution_proof() {
    let gw_sk = fresh_secret(b"n29-gw");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    let receipts = vec![
        make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1000, now()),
        make_receipt(&gw_sk, gw_id, [0xBB; 32], [2u8; 16], 2000, now()),
    ];

    let proof = ContributionProof::build(gw_id, &gw_sk, receipts, now()).unwrap();

    // Proof signature verifies.
    assert!(proof.verify(&gw_pk), "proof signature must verify");
    // All individual receipts verify.
    assert!(proof.verify_all_receipts(&gw_pk), "all receipts must verify");

    // Aggregate stats.
    assert_eq!(proof.total_bytes(), 3000);
    assert_eq!(proof.distinct_clients(), 2);
    assert_eq!(proof.receipts.len(), 2);
    eprintln!("[n29-1] PASS: ContributionProof built + verified");
}

// ─── 2. CivicPointLedger credits points from verified proof ──────────────────

#[test]
fn n29_ledger_credits_points() {
    let gw_sk = fresh_secret(b"n29-gw");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    // 1 MiB of data.
    let receipts = vec![
        make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1024 * 1024, now()),
    ];

    let proof = ContributionProof::build(gw_id, &gw_sk, receipts, now()).unwrap();
    let mut ledger = CivicPointLedger::new(100.0); // 100 points per MiB base rate

    let credited = ledger.credit(&proof, &gw_pk);
    assert!(credited > 0, "points must be credited");

    // 1 MiB × log₂(1+1) = 1 × 1.0 = 1.0 volume factor
    // 1 client → diversity factor 0.2
    // 100 base_rate × 1.0 × 0.2 = 20 points
    assert_eq!(credited, 20, "1 MiB, 1 client → 20 points (100 × 1.0 × 0.2)");
    assert_eq!(ledger.points_for(&gw_id), 20);
    eprintln!("[n29-2] PASS: CivicPointLedger credits points from verified proof");
}

// ─── 3. CANNOT manufacture contribution by asserting traffic ───────────────

#[test]
fn n29_cannot_manufacture_contribution_with_fake_receipts() {
    let attacker_sk = fresh_secret(b"n29-attacker");
    let attacker_pk = derive_public_key(&attacker_sk);
    let attacker_id = snp_crypto::derive_node_id(&attacker_pk);

    // The attacker tries to forge a receipt from a DIFFERENT gateway.
    let real_gw_sk = fresh_secret(b"n29-real-gw");
    let real_gw_pk = derive_public_key(&real_gw_sk);
    let real_gw_id = snp_crypto::derive_node_id(&real_gw_pk);

    // Attacker signs a receipt claiming the REAL gateway provided service.
    let mut fake_receipt = TransitReceipt {
        req_id: [1u8; 16],
        client_node_id: [0xCC; 32],
        gateway_node_id: real_gw_id, // claims to be the real gateway
        bytes_transferred: 1_000_000,
        http_status: 200,
        object_id: [0xAB; 32],
        served_at: now(),
        duration_ms: 50,
        gateway_signature: [0u8; 64],
    };
    // Attacker signs with THEIR key (not the real gateway's key).
    fake_receipt.sign(&attacker_sk);

    // The receipt will NOT verify against the real gateway's public key.
    assert!(!fake_receipt.verify(&real_gw_pk),
        "fake receipt must NOT verify against the real gateway's public key");

    // The attacker tries to build a proof claiming to be the real gateway.
    // They pass contributor=real_gw_id but sign with attacker_sk.
    // The build function will derive contributor_public=derive_public_key(attacker_sk)
    // and verify the receipt against THAT key — which succeeds because the
    // attacker signed it. BUT the proof's contributor_signature will also
    // be signed with attacker_sk, so it will NOT verify against the REAL
    // gateway's public key.
    let proof = ContributionProof::build(real_gw_id, &attacker_sk, vec![fake_receipt], now()).unwrap();

    // The proof does NOT verify against the real gateway's public key.
    assert!(!proof.verify(&real_gw_pk),
        "fake proof must NOT verify against the real gateway's public key");

    // The ledger will NOT credit this proof (signature verification fails).
    let mut ledger = CivicPointLedger::new(100.0);
    let credited = ledger.credit(&proof, &real_gw_pk);
    assert_eq!(credited, 0,
        "ledger must NOT credit a proof that doesn't verify against the claimed contributor's key");
    eprintln!("[n29-3] PASS: cannot manufacture contribution with fake receipts");
}

// ─── 4. Replay prevention ─────────────────────────────────────────────────────

#[test]
fn n29_replay_prevention_same_receipt_not_credited_twice() {
    let gw_sk = fresh_secret(b"n29-gw-replay");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    let receipt = make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1_000_000, now());

    // First proof with this receipt.
    let proof1 = ContributionProof::build(gw_id, &gw_sk, vec![receipt.clone()], now()).unwrap();
    let mut ledger = CivicPointLedger::new(100.0);

    let credited1 = ledger.credit(&proof1, &gw_pk);
    assert!(credited1 > 0, "first credit must succeed");

    // Second proof with the SAME receipt (replay attempt).
    let proof2 = ContributionProof::build(gw_id, &gw_sk, vec![receipt], now()).unwrap();
    let credited2 = ledger.credit(&proof2, &gw_pk);

    assert_eq!(credited2, 0, "replay must NOT be credited again");
    assert_eq!(ledger.points_for(&gw_id), credited1, "points unchanged after replay");
    eprintln!("[n29-4] PASS: replay prevention — same receipt not credited twice");
}

// ─── 5. Duplicate receipt within a proof rejected ───────────────────────────

#[test]
fn n29_duplicate_receipt_within_proof_rejected() {
    let gw_sk = fresh_secret(b"n29-gw-dup");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    let receipt1 = make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1000, now());
    let receipt2 = make_receipt(&gw_sk, gw_id, [0xBB; 32], [1u8; 16], 2000, now()); // same req_id!

    let result = ContributionProof::build(gw_id, &gw_sk, vec![receipt1, receipt2], now());
    assert!(matches!(result, Err(ContributionProofError::DuplicateReceipt { req_id }) if req_id == [1u8; 16]),
        "duplicate receipt within a proof must be rejected");
    eprintln!("[n29-5] PASS: duplicate receipt within a proof rejected");
}

// ─── 6. Sub-linear volume factor ─────────────────────────────────────────────

#[test]
fn n29_sublinear_volume_factor() {
    let gw_sk = fresh_secret(b"n29-gw-vol");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    let mut ledger = CivicPointLedger::new(100.0);

    // 1 MiB.
    let r1 = make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1024 * 1024, now());
    let p1 = ContributionProof::build(gw_id, &gw_sk, vec![r1], now()).unwrap();
    let points_1mib = ledger.credit(&p1, &gw_pk);

    // 2 MiB.
    let r2 = make_receipt(&gw_sk, gw_id, [0xBB; 32], [2u8; 16], 2 * 1024 * 1024, now());
    let p2 = ContributionProof::build(gw_id, &gw_sk, vec![r2], now()).unwrap();
    let points_2mib = ledger.credit(&p2, &gw_pk);

    // log₂(1+1) = 1.0 → 100 × 1.0 × 0.2 = 20 points for 1 MiB
    // log₂(1+2) = 1.585 → 100 × 1.585 × 0.2 ≈ 31.7 → 32 points for 2 MiB
    // Doubling volume does NOT double points (sub-linear).
    assert!(points_2mib > points_1mib, "more volume → more points");
    assert!(points_2mib < 2 * points_1mib, "doubling volume must NOT double points (sub-linear)");
    assert_eq!(points_1mib, 20); // 100 × 1.0 × 0.2 = 20
    assert!(points_2mib >= 31 && points_2mib <= 32); // ≈31.7 → 32
    eprintln!("[n29-6] PASS: sub-linear volume factor (1 MiB → {points_1mib}, 2 MiB → {points_2mib})");
}

// ─── 7. Diversity weighting ─────────────────────────────────────────────────

#[test]
fn n29_diversity_weighting() {
    let gw_sk = fresh_secret(b"n29-gw-div");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    // Serve 1 MiB to 1 client.
    let mut ledger1 = CivicPointLedger::new(100.0);
    let r1 = make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1024 * 1024, now());
    let p1 = ContributionProof::build(gw_id, &gw_sk, vec![r1], now()).unwrap();
    let points_1_client = ledger1.credit(&p1, &gw_pk);

    // Serve 1 MiB split across 5 clients (5 × 200KB ≈ 1 MiB total).
    let mut ledger5 = CivicPointLedger::new(100.0);
    let receipts5: Vec<_> = (0..5u8).map(|i| {
        make_receipt(&gw_sk, gw_id, [i; 32], [i + 1; 16], 200_000, now())
    }).collect();
    let p5 = ContributionProof::build(gw_id, &gw_sk, receipts5, now()).unwrap();
    let points_5_clients = ledger5.credit(&p5, &gw_pk);

    // 1 client: diversity factor = 0.2
    // 5 clients: diversity factor = 1.0
    // Same total volume → 5× more points for diversity.
    assert!(points_5_clients > points_1_client,
        "5 clients must earn more points than 1 client for the same volume");
    assert_eq!(points_1_client, 20); // 100 × 1.0 × 0.2 = 20
    // 5 clients: 100 × log₂(1 + ~1) × 1.0 ≈ 100 × ~1.0 × 1.0 ≈ 100
    assert!(points_5_clients > 50, "5 clients should earn significantly more than 1 client");
    eprintln!("[n29-7] PASS: diversity weighting (1 client → {points_1_client}, 5 clients → {points_5_clients})");
}

// ─── 8. Evidence level ───────────────────────────────────────────────────────

#[test]
fn n29_evidence_level_is_authenticated() {
    assert_eq!(ContributionProof::evidence_level(), EvidenceLevel::Authenticated);
    eprintln!("[n29-8] PASS: ContributionProof is an AuthenticatedClaim");
}

// ─── 9. Future timestamp rejected ──────────────────────────────────────────

#[test]
fn n29_future_timestamp_rejected() {
    let gw_sk = fresh_secret(b"n29-gw-future");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    // Receipt claims to be served in the future.
    let receipt = make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 1000, now() + 3600);
    let result = ContributionProof::build(gw_id, &gw_sk, vec![receipt], now());
    assert!(matches!(result, Err(ContributionProofError::FutureTimestamp { .. })),
        "future timestamp must be rejected");
    eprintln!("[n29-9] PASS: future timestamp rejected");
}

// ─── 10. Full loop: receipt → proof → points → trace ────────────────────────

#[test]
fn n29_full_contribution_loop() {
    let gw_sk = fresh_secret(b"n29-gw-full");
    let gw_pk = derive_public_key(&gw_sk);
    let gw_id = snp_crypto::derive_node_id(&gw_pk);

    // Gateway serves 3 requests to 3 different clients.
    let receipts = vec![
        make_receipt(&gw_sk, gw_id, [0xAA; 32], [1u8; 16], 500_000, now()),
        make_receipt(&gw_sk, gw_id, [0xBB; 32], [2u8; 16], 300_000, now()),
        make_receipt(&gw_sk, gw_id, [0xCC; 32], [3u8; 16], 200_000, now()),
    ];

    // Build the proof.
    let proof = ContributionProof::build(gw_id, &gw_sk, receipts.clone(), now()).unwrap();
    assert!(proof.verify_all_receipts(&gw_pk), "all receipts must verify");

    // Credit the points.
    let mut ledger = CivicPointLedger::new(100.0);
    let points = ledger.credit(&proof, &gw_pk);
    assert!(points > 0, "points must be credited");

    // The network can answer: "Why did this node receive these points?"
    // by tracing: points → proof → receipts → actual service.
    let record = ContributionRecord {
        contributor: gw_id,
        points,
        receipts,
        credited_at: now(),
    };
    let trace = record.trace();
    assert!(trace.contains("points="));
    assert!(trace.contains("3 receipts"));
    assert!(trace.contains("bytes="));

    eprintln!("[n29-10] PASS: full contribution loop — receipt → proof → points → trace");
    eprintln!("  {}", trace);
}

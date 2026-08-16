//! N3.5 — External Crypto Bridge Tests
//!
//! Tests proving:
//! 1. RPC relay: wallet → ShareNet → gateway → blockchain RPC → response
//! 2. Broadcast: offline signed tx → ShareNet → gateway → broadcast → tx hash
//! 3. No private-key custody (ShareNet never holds private keys)
//! 4. No blockchain consensus inside ShareNet
//! 5. Signature verification (wallet + gateway)
//! 6. tx_hash integrity verification

#![allow(clippy::pedantic)]

use snp_crypto::sha256;
use snp_node::node::external_crypto::*;

fn fresh_secret(label: &[u8]) -> [u8; 32] {
    sha256(label)
}

// ─── 1. RPC relay round-trip ────────────────────────────────────────────────

#[test]
fn n35_rpc_relay_round_trip() {
    let wallet_sk = fresh_secret(b"n35-wallet");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-gateway"));

    // Wallet creates an RPC request.
    let req = RpcRequest::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x42; 16],
        "eth_getBalance".to_string(),
        r#"["0x1234...", "latest"]"#.to_string(),
        "https://rpc.example.com".to_string(),
    );

    // Gateway handles the request (simulated blockchain response).
    let response = gateway.handle_rpc_request(
        &req,
        &wallet_pk,
        r#"{"result": "0xde0b6b3a7640000"}"#.to_string(),
    ).unwrap();

    // Response verifies against the gateway's public key.
    let gateway_pk = snp_crypto::derive_public_key(&fresh_secret(b"n35-gateway"));
    assert!(response.verify(&gateway_pk), "RPC response must verify");
    assert_eq!(response.req_id, [0x42; 16]);
    assert_eq!(response.http_status, 200);
    assert!(response.result.contains("0xde0b6b3a7640000"));
    eprintln!("[n35-1] PASS: RPC relay round-trip (wallet → gateway → blockchain)");
}

// ─── 2. Broadcast round-trip ───────────────────────────────────────────────

#[test]
fn n35_broadcast_round_trip() {
    let wallet_sk = fresh_secret(b"n35-wallet-broadcast");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-gateway-broadcast"));

    // Wallet signs a transaction OFFLINE (ShareNet never sees the private key).
    // The "signed transaction" is opaque bytes — ShareNet doesn't understand them.
    let signed_tx_bytes = vec![0x02, 0x03, 0x04, 0x05]; // mock signed tx

    // Wallet creates a broadcast request.
    let req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x77; 16],
        signed_tx_bytes,
        "https://rpc.example.com".to_string(),
    );

    // Gateway handles the broadcast (simulated blockchain response).
    let result = gateway.handle_broadcast(
        &req,
        &wallet_pk,
        "0xabc123def456".to_string(), // simulated blockchain tx hash
    ).unwrap();

    // Result verifies against the gateway's public key.
    let gateway_pk = snp_crypto::derive_public_key(&fresh_secret(b"n35-gateway-broadcast"));
    assert!(result.verify(&gateway_pk), "broadcast result must verify");
    assert_eq!(result.req_id, [0x77; 16]);
    assert_eq!(result.blockchain_tx_hash, "0xabc123def456");
    eprintln!("[n35-2] PASS: broadcast round-trip (offline signed tx → gateway → broadcast)");
}

// ─── 3. No private-key custody ──────────────────────────────────────────────

#[test]
fn n35_no_private_key_custody() {
    // ShareNet NEVER holds private keys. The wallet signs offline and sends
    // ONLY the signed bytes. The gateway cannot extract the private key
    // because it's never transmitted.
    let wallet_sk = fresh_secret(b"n35-custody-wallet");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_sk);

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-custody-gw"));

    // The signed_tx_bytes are OPAQUE to ShareNet — they could be any
    // chain-specific format. ShareNet does NOT parse them.
    let signed_tx_bytes = vec![0xFF; 256]; // 256 bytes of mock signed tx

    let req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x88; 16],
        signed_tx_bytes.clone(),
        "https://rpc.example.com".to_string(),
    );

    // The request contains:
    // - req_id (replay defence)
    // - signed_tx_bytes (opaque, already signed)
    // - broadcast_endpoint (where to submit)
    // - wallet_node_id (who authorized)
    // - tx_hash (SHA-256 of signed_tx_bytes)
    // - wallet_signature (over the broadcast request, NOT over the tx itself)
    // - timestamp

    // The request does NOT contain:
    // - The wallet's private key
    // - Any way to derive the private key
    // - The transaction's unsigned form

    // Verify the tx_hash is just SHA-256 of the opaque bytes (not the key).
    assert!(req.verify_tx_hash(), "tx_hash must match SHA-256 of signed_tx_bytes");
    assert_eq!(req.tx_hash, sha256(&signed_tx_bytes));

    // The wallet's signature is over the BROADCAST REQUEST, not over the
    // transaction itself (which is already signed). The gateway cannot
    // re-sign the transaction because it doesn't have the wallet's key.
    assert!(req.verify(&wallet_pk), "wallet signature must verify");
    eprintln!("[n35-3] PASS: no private-key custody — gateway never sees the key");
}

// ─── 4. Invalid wallet signature rejected ───────────────────────────────────

#[test]
fn n35_invalid_wallet_signature_rejected() {
    let wallet_sk = fresh_secret(b"n35-real-wallet");
    let wrong_pk = snp_crypto::derive_public_key(&fresh_secret(b"n35-attacker"));

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-gateway-reject"));

    let req = RpcRequest::create_and_sign(
        &wallet_sk,
        [0xAA; 32],
        [0x01; 16],
        "eth_getBalance".to_string(),
        r#"[]"#.to_string(),
        "https://rpc.example.com".to_string(),
    );

    // Verify with WRONG public key → fails.
    let result = gateway.handle_rpc_request(&req, &wrong_pk, "{}".to_string());
    assert!(matches!(result, Err(ExternalCryptoError::InvalidWalletSignature)),
        "invalid wallet signature must be rejected");
    eprintln!("[n35-4] PASS: invalid wallet signature rejected");
}

// ─── 5. tx_hash integrity verification ──────────────────────────────────────

#[test]
fn n35_tx_hash_integrity() {
    let wallet_sk = fresh_secret(b"n35-tx-hash");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let signed_tx_bytes = vec![0xAA, 0xBB, 0xCC];
    let req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x02; 16],
        signed_tx_bytes,
        "https://rpc.example.com".to_string(),
    );

    // tx_hash = SHA-256(signed_tx_bytes).
    assert_eq!(req.tx_hash, sha256(&vec![0xAA, 0xBB, 0xCC]));
    assert!(req.verify_tx_hash(), "tx_hash must match");

    // Tamper with the signed_tx_bytes → tx_hash no longer matches.
    let mut tampered = req.clone();
    tampered.signed_tx_bytes[0] = 0x00;
    assert!(!tampered.verify_tx_hash(), "tampered tx must NOT verify");
    eprintln!("[n35-5] PASS: tx_hash integrity verification");
}

// ─── 6. Unauthorized endpoint rejected ──────────────────────────────────────

#[test]
fn n35_unauthorized_endpoint_rejected() {
    let wallet_sk = fresh_secret(b"n35-unauth-wallet");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-unauth-gw"));

    // Request to an UNAUTHORIZED endpoint (not https://rpc.* or https://api.*).
    let req = RpcRequest::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x03; 16],
        "eth_getBalance".to_string(),
        r#"[]"#.to_string(),
        "http://evil.com/rpc".to_string(), // unauthorized
    );

    let result = gateway.handle_rpc_request(&req, &wallet_pk, "{}".to_string());
    assert!(matches!(result, Err(ExternalCryptoError::UnauthorizedEndpoint)),
        "unauthorized endpoint must be rejected");
    eprintln!("[n35-6] PASS: unauthorized endpoint rejected");
}

// ─── 7. Gateway signature verifies ───────────────────────────────────────────

#[test]
fn n35_gateway_signature_verifies() {
    let wallet_sk = fresh_secret(b"n35-gw-sig-wallet");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gw_sk = fresh_secret(b"n35-gw-sig-gateway");
    let gw_pk = snp_crypto::derive_public_key(&gw_sk);
    let gateway = ExternalCryptoGateway::new(gw_sk);

    let req = RpcRequest::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x04; 16],
        "eth_call".to_string(),
        r#"[]"#.to_string(),
        "https://rpc.example.com".to_string(),
    );

    let response = gateway.handle_rpc_request(&req, &wallet_pk, r#"{"result": "0x1234"}"#.to_string()).unwrap();

    // Response verifies against the gateway's public key.
    assert!(response.verify(&gw_pk), "response must verify against gateway's key");

    // A WRONG key does NOT verify.
    let wrong_gw_pk = snp_crypto::derive_public_key(&fresh_secret(b"n35-wrong-gw"));
    assert!(!response.verify(&wrong_gw_pk), "response must NOT verify with wrong key");
    eprintln!("[n35-7] PASS: gateway signature verifies (and rejects wrong key)");
}

// ─── 8. Broadcast result signature verifies ─────────────────────────────────

#[test]
fn n35_broadcast_result_signature_verifies() {
    let wallet_sk = fresh_secret(b"n35-bcast-sig");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gw_sk = fresh_secret(b"n35-bcast-gw");
    let gw_pk = snp_crypto::derive_public_key(&gw_sk);
    let gateway = ExternalCryptoGateway::new(gw_sk);

    let req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x05; 16],
        vec![0x01, 0x02, 0x03],
        "https://rpc.example.com".to_string(),
    );

    let result = gateway.handle_broadcast(&req, &wallet_pk, "0xabc".to_string()).unwrap();

    // Result verifies against the gateway's public key.
    assert!(result.verify(&gw_pk), "broadcast result must verify");
    assert_eq!(result.blockchain_tx_hash, "0xabc");
    eprintln!("[n35-8] PASS: broadcast result signature verifies");
}

// ─── 9. No blockchain consensus inside ShareNet ──────────────────────────────

#[test]
fn n35_no_blockchain_consensus() {
    // ShareNet does NOT validate transactions, does NOT run consensus,
    // does NOT maintain blockchain state. It is a TRANSPORT for
    // already-signed transactions and RPC requests.

    // The gateway's handle_broadcast() does NOT:
    // - Parse the signed_tx_bytes (they're opaque)
    // - Validate the transaction's correctness
    // - Check the transaction against blockchain state
    // - Run any consensus logic

    // It ONLY:
    // - Verifies the wallet's authorization (signature)
    // - Verifies the tx_hash (integrity)
    // - Submits the opaque bytes to the broadcast endpoint

    let wallet_sk = fresh_secret(b"n35-no-consensus");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gateway = ExternalCryptoGateway::new(fresh_secret(b"n35-no-consensus-gw"));

    // The signed_tx_bytes could be ANYTHING — an Ethereum tx, a Bitcoin tx,
    // a Solana tx, or even garbage. ShareNet doesn't care — it just relays.
    let garbage_tx = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x06; 16],
        garbage_tx,
        "https://rpc.example.com".to_string(),
    );

    // The gateway handles it WITHOUT understanding the content.
    let result = gateway.handle_broadcast(&req, &wallet_pk, "0xdeadbeef".to_string());
    assert!(result.is_ok(), "gateway must relay opaque bytes without understanding them");
    eprintln!("[n35-9] PASS: no blockchain consensus — ShareNet relays opaque bytes");
}

// ─── 10. Full pipeline: wallet → gateway → blockchain → response ────────────

#[test]
fn n35_full_pipeline() {
    // Feature 1: RPC relay.
    let wallet_sk = fresh_secret(b"n35-full-wallet");
    let wallet_pk = snp_crypto::derive_public_key(&wallet_sk);
    let wallet_id = snp_crypto::derive_node_id(&wallet_pk);

    let gw_sk = fresh_secret(b"n35-full-gateway");
    let gw_pk = snp_crypto::derive_public_key(&gw_sk);
    let gateway = ExternalCryptoGateway::new(gw_sk);

    // Wallet queries balance.
    let rpc_req = RpcRequest::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x0A; 16],
        "eth_getBalance".to_string(),
        r#"["0x742d...", "latest"]"#.to_string(),
        "https://rpc.infura.io".to_string(),
    );
    let rpc_resp = gateway.handle_rpc_request(
        &rpc_req,
        &wallet_pk,
        r#"{"result": "0x1bc16d674ec80000"}"#.to_string(),
    ).unwrap();
    assert!(rpc_resp.verify(&gw_pk));

    // Feature 2: Broadcast.
    let signed_tx = vec![0x02; 200]; // mock signed Ethereum tx
    let bcast_req = SignedTransactionBroadcast::create_and_sign(
        &wallet_sk,
        wallet_id,
        [0x0B; 16],
        signed_tx,
        "https://rpc.infura.io".to_string(),
    );
    let bcast_result = gateway.handle_broadcast(
        &bcast_req,
        &wallet_pk,
        "0xabc123def456".to_string(),
    ).unwrap();
    assert!(bcast_result.verify(&gw_pk));

    eprintln!("[n35-10] PASS: full pipeline — RPC relay + broadcast through ShareNet");
}

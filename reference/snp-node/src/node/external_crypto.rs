//! N3.5 — External Crypto Bridge
//!
//! Implements the path for external cryptocurrency operations through ShareNet:
//!
//! ```text
//! Feature 1: RPC relay
//! ordinary wallet → ShareNet → gateway → blockchain RPC → response
//!
//! Feature 2: Signed transaction broadcast
//! offline signed tx → ShareNet → gateway → broadcast → tx hash
//! ```
//!
//! ## CRITICAL: No private-key custody
//!
//! ShareNet NEVER holds private keys. The wallet signs transactions
//! offline and sends ONLY the signed transaction bytes through the mesh.
//! The gateway relays the signed bytes to the blockchain — it cannot
//! modify the transaction or extract the private key.
//!
//! ## CRITICAL: No blockchain consensus inside ShareNet
//!
//! ShareNet does NOT validate transactions, does NOT run a consensus
//! engine, does NOT maintain a blockchain state. It is a TRANSPORT
//! for already-signed transactions and RPC requests.

use snp_crypto::{sha256, ed25519_sign, ed25519_verify, derive_public_key, SecretKey};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── RpcRequest ──────────────────────────────────────────────────────────────

/// A blockchain RPC request from a wallet, relayed through ShareNet.
///
/// The wallet constructs the RPC payload (e.g., `eth_call`, `eth_getBalance`)
/// and signs the request with its Ed25519 key. ShareNet relays it to the
/// gateway, which forwards it to the blockchain RPC endpoint.
///
/// ## No private-key custody
///
/// The RPC request contains NO private keys. It is a read-only query
/// (or a pre-signed transaction for broadcast — see `SignedTransactionBroadcast`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcRequest {
    /// 16-byte request ID (replay defence).
    pub req_id: [u8; 16],
    /// The blockchain RPC method (e.g. "eth_getBalance", "eth_call").
    pub method: String,
    /// The JSON-encoded RPC parameters.
    pub params: String,
    /// The blockchain RPC endpoint URL (e.g. "https://rpc.example.com").
    pub rpc_endpoint: String,
    /// The wallet's NodeId.
    pub wallet_node_id: [u8; 32],
    /// When the request was made (unix seconds).
    pub timestamp: u64,
    /// The wallet's Ed25519 signature over the request.
    pub wallet_signature: [u8; 64],
}

impl RpcRequest {
    /// Compute the canonical preimage for signing.
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 rpc-request\0");
        data.extend_from_slice(&self.req_id);
        data.extend_from_slice(self.method.as_bytes());
        data.extend_from_slice(self.params.as_bytes());
        data.extend_from_slice(self.rpc_endpoint.as_bytes());
        data.extend_from_slice(&self.wallet_node_id);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data
    }

    /// Create and sign an RPC request.
    pub fn create_and_sign(
        wallet_secret: &SecretKey,
        wallet_node_id: [u8; 32],
        req_id: [u8; 16],
        method: String,
        params: String,
        rpc_endpoint: String,
    ) -> Self {
        let mut req = Self {
            req_id,
            method,
            params,
            rpc_endpoint,
            wallet_node_id,
            timestamp: now_unix(),
            wallet_signature: [0u8; 64],
        };
        let preimage = req.preimage();
        req.wallet_signature = ed25519_sign(wallet_secret, &preimage);
        req
    }

    /// Verify the wallet's signature.
    #[must_use]
    pub fn verify(&self, wallet_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        ed25519_verify(wallet_public_key, &preimage, &self.wallet_signature)
    }
}

// ─── RpcResponse ────────────────────────────────────────────────────────────

/// A blockchain RPC response, relayed back through ShareNet.
///
/// The gateway fetches the RPC response from the blockchain endpoint and
/// signs it. The wallet verifies the gateway's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcResponse {
    /// Matches the RpcRequest.req_id.
    pub req_id: [u8; 16],
    /// The JSON-encoded RPC response.
    pub result: String,
    /// HTTP status code from the RPC endpoint.
    pub http_status: u16,
    /// The gateway's NodeId.
    pub gateway_node_id: [u8; 32],
    /// When the response was fetched (unix seconds).
    pub fetched_at: u64,
    /// The gateway's Ed25519 signature.
    pub gateway_signature: [u8; 64],
}

impl RpcResponse {
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 rpc-response\0");
        data.extend_from_slice(&self.req_id);
        data.extend_from_slice(self.result.as_bytes());
        data.extend_from_slice(&self.http_status.to_be_bytes());
        data.extend_from_slice(&self.gateway_node_id);
        data.extend_from_slice(&self.fetched_at.to_be_bytes());
        data
    }

    /// Sign the response with the gateway's key.
    pub fn sign(&mut self, gateway_secret: &SecretKey) {
        let preimage = self.preimage();
        self.gateway_signature = ed25519_sign(gateway_secret, &preimage);
    }

    /// Verify the gateway's signature.
    #[must_use]
    pub fn verify(&self, gateway_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        ed25519_verify(gateway_public_key, &preimage, &self.gateway_signature)
    }
}

// ─── SignedTransactionBroadcast ──────────────────────────────────────────────

/// A pre-signed transaction sent through ShareNet for broadcast.
///
/// ## CRITICAL: No private-key custody
///
/// The transaction is ALREADY signed by the wallet's private key BEFORE
/// entering ShareNet. ShareNet NEVER sees the private key — it only
/// relays the signed bytes to the blockchain's broadcast endpoint.
///
/// The gateway CANNOT:
/// - Modify the transaction (the signature would break)
/// - Extract the private key (it's never transmitted)
/// - Re-sign the transaction (it doesn't have the key)
///
/// The gateway CAN:
/// - Read the signed transaction bytes (it's opaque to ShareNet)
/// - Submit it to the blockchain's broadcast endpoint
/// - Report the resulting transaction hash
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransactionBroadcast {
    /// 16-byte request ID (replay defence).
    pub req_id: [u8; 16],
    /// The signed transaction bytes (opaque to ShareNet — chain-specific format).
    pub signed_tx_bytes: Vec<u8>,
    /// The blockchain broadcast endpoint URL (e.g. "https://rpc.example.com").
    pub broadcast_endpoint: String,
    /// The wallet's NodeId.
    pub wallet_node_id: [u8; 32],
    /// SHA-256 of the signed_tx_bytes (for integrity verification).
    pub tx_hash: [u8; 32],
    /// When the broadcast request was made (unix seconds).
    pub timestamp: u64,
    /// The wallet's Ed25519 signature over the broadcast request.
    pub wallet_signature: [u8; 64],
}

impl SignedTransactionBroadcast {
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 tx-broadcast\0");
        data.extend_from_slice(&self.req_id);
        data.extend_from_slice(&self.tx_hash);
        data.extend_from_slice(self.broadcast_endpoint.as_bytes());
        data.extend_from_slice(&self.wallet_node_id);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data
    }

    /// Create a broadcast request from a pre-signed transaction.
    ///
    /// The wallet signs the broadcast request (NOT the transaction itself —
    /// the transaction is already signed). This proves the wallet authorized
    /// the broadcast through ShareNet.
    pub fn create_and_sign(
        wallet_secret: &SecretKey,
        wallet_node_id: [u8; 32],
        req_id: [u8; 16],
        signed_tx_bytes: Vec<u8>,
        broadcast_endpoint: String,
    ) -> Self {
        let tx_hash = sha256(&signed_tx_bytes);
        let mut req = Self {
            req_id,
            signed_tx_bytes,
            broadcast_endpoint,
            wallet_node_id,
            tx_hash,
            timestamp: now_unix(),
            wallet_signature: [0u8; 64],
        };
        let preimage = req.preimage();
        req.wallet_signature = ed25519_sign(wallet_secret, &preimage);
        req
    }

    /// Verify the wallet's signature.
    #[must_use]
    pub fn verify(&self, wallet_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        ed25519_verify(wallet_public_key, &preimage, &self.wallet_signature)
    }

    /// Verify that the tx_hash matches SHA-256 of the signed_tx_bytes.
    #[must_use]
    pub fn verify_tx_hash(&self) -> bool {
        let computed = sha256(&self.signed_tx_bytes);
        computed == self.tx_hash
    }
}

// ─── BroadcastResult ────────────────────────────────────────────────────────

/// The result of a transaction broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastResult {
    /// Matches the SignedTransactionBroadcast.req_id.
    pub req_id: [u8; 16],
    /// The blockchain's transaction hash (chain-specific format).
    pub blockchain_tx_hash: String,
    /// The gateway's NodeId.
    pub gateway_node_id: [u8; 32],
    /// When the broadcast was submitted (unix seconds).
    pub broadcast_at: u64,
    /// The gateway's Ed25519 signature.
    pub gateway_signature: [u8; 64],
}

impl BroadcastResult {
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 broadcast-result\0");
        data.extend_from_slice(&self.req_id);
        data.extend_from_slice(self.blockchain_tx_hash.as_bytes());
        data.extend_from_slice(&self.gateway_node_id);
        data.extend_from_slice(&self.broadcast_at.to_be_bytes());
        data
    }

    /// Sign the result with the gateway's key.
    pub fn sign(&mut self, gateway_secret: &SecretKey) {
        let preimage = self.preimage();
        self.gateway_signature = ed25519_sign(gateway_secret, &preimage);
    }

    /// Verify the gateway's signature.
    #[must_use]
    pub fn verify(&self, gateway_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        ed25519_verify(gateway_public_key, &preimage, &self.gateway_signature)
    }
}

// ─── ExternalCryptoError ─────────────────────────────────────────────────────

/// Errors from the external crypto bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCryptoError {
    /// The wallet's signature on the request is invalid.
    InvalidWalletSignature,
    /// The tx_hash doesn't match SHA-256 of the signed_tx_bytes.
    TxHashMismatch,
    /// The blockchain RPC/broadcast endpoint returned an error.
    BlockchainError(String),
    /// The gateway is not authorized to relay to the requested endpoint.
    UnauthorizedEndpoint,
}

impl fmt::Display for ExternalCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWalletSignature => write!(f, "invalid wallet signature"),
            Self::TxHashMismatch => write!(f, "tx_hash does not match SHA-256 of signed bytes"),
            Self::BlockchainError(msg) => write!(f, "blockchain error: {msg}"),
            Self::UnauthorizedEndpoint => write!(f, "gateway not authorized for this endpoint"),
        }
    }
}

// ─── ExternalCryptoGateway ──────────────────────────────────────────────────

/// The gateway-side handler for external crypto operations.
///
/// ## What the gateway does
///
/// 1. Verifies the wallet's signature on the request (authentication).
/// 2. For RPC: fetches the response from the blockchain endpoint.
/// 3. For broadcast: submits the signed transaction to the broadcast endpoint.
/// 4. Signs the response/result with the gateway's key.
///
/// ## What the gateway does NOT do
///
/// - Hold private keys (no custody)
/// - Validate transactions (no consensus)
/// - Modify transactions (the signature would break)
/// - Extract private keys (they're never transmitted)
#[derive(Debug)]
pub struct ExternalCryptoGateway {
    gateway_secret: SecretKey,
    gateway_node_id: [u8; 32],
    /// Authorized blockchain endpoints (URL prefixes).
    authorized_endpoints: Vec<String>,
}

impl ExternalCryptoGateway {
    /// Create a new external crypto gateway.
    #[must_use]
    pub fn new(gateway_secret: SecretKey) -> Self {
        let gateway_public = derive_public_key(&gateway_secret);
        let gateway_node_id = snp_crypto::derive_node_id(&gateway_public);
        Self {
            gateway_secret,
            gateway_node_id,
            authorized_endpoints: vec![
                "https://rpc.".to_string(),
                "https://api.".to_string(),
            ],
        }
    }

    /// Get the gateway's NodeId.
    #[must_use]
    pub fn gateway_node_id(&self) -> [u8; 32] {
        self.gateway_node_id
    }

    /// Check if an endpoint is authorized.
    #[must_use]
    fn is_authorized(&self, endpoint: &str) -> bool {
        self.authorized_endpoints.iter().any(|prefix| endpoint.starts_with(prefix))
    }

    /// Handle an RPC request: verify wallet signature, simulate fetch, sign response.
    ///
    /// In production, this would fetch from the blockchain endpoint via the
    /// GatewayServiceManager (N2.7). For this test, we simulate the fetch
    /// with a provided result.
    pub fn handle_rpc_request(
        &self,
        request: &RpcRequest,
        wallet_public_key: &[u8; 32],
        simulated_result: String,
    ) -> Result<RpcResponse, ExternalCryptoError> {
        // 1. Verify the wallet's signature.
        if !request.verify(wallet_public_key) {
            return Err(ExternalCryptoError::InvalidWalletSignature);
        }

        // 2. Check endpoint authorization.
        if !self.is_authorized(&request.rpc_endpoint) {
            return Err(ExternalCryptoError::UnauthorizedEndpoint);
        }

        // 3. Sign the response.
        let mut response = RpcResponse {
            req_id: request.req_id,
            result: simulated_result,
            http_status: 200,
            gateway_node_id: self.gateway_node_id,
            fetched_at: now_unix(),
            gateway_signature: [0u8; 64],
        };
        response.sign(&self.gateway_secret);
        Ok(response)
    }

    /// Handle a broadcast request: verify wallet signature + tx_hash, simulate broadcast.
    pub fn handle_broadcast(
        &self,
        request: &SignedTransactionBroadcast,
        wallet_public_key: &[u8; 32],
        simulated_tx_hash: String,
    ) -> Result<BroadcastResult, ExternalCryptoError> {
        // 1. Verify the wallet's signature.
        if !request.verify(wallet_public_key) {
            return Err(ExternalCryptoError::InvalidWalletSignature);
        }

        // 2. Verify the tx_hash matches the signed_tx_bytes.
        if !request.verify_tx_hash() {
            return Err(ExternalCryptoError::TxHashMismatch);
        }

        // 3. Check endpoint authorization.
        if !self.is_authorized(&request.broadcast_endpoint) {
            return Err(ExternalCryptoError::UnauthorizedEndpoint);
        }

        // 4. Sign the result.
        let mut result = BroadcastResult {
            req_id: request.req_id,
            blockchain_tx_hash: simulated_tx_hash,
            gateway_node_id: self.gateway_node_id,
            broadcast_at: now_unix(),
            gateway_signature: [0u8; 64],
        };
        result.sign(&self.gateway_secret);
        Ok(result)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

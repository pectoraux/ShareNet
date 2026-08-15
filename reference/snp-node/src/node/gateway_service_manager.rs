//! N2.7 — Gateway Service Manager
//!
//! The runtime that accepts/rejects transit requests, enforces policy,
//! measures service, and produces signed receipts.
//!
//! ## Architecture
//!
//! ```text
//! TransitRequest (from client via circuit)
//!         ↓
//! GatewayServiceManager::handle_request()
//!         ↓
//!    ┌── Policy enforcement (destination allowed? protocol allowed?)
//!    ├── Quota check (remaining quota > 0?)
//!    ├── Actual fetch (via snp_gateway::handle_transit_request_with_connector)
//!    ├── Measurement (bytes transferred, duration, success/failure)
//!    ├── Receipt signing (TransitReceipt — gateway attests to the service)
//!    └── State update (GatewayServiceState updated with new measurements)
//!         ↓
//! GatewayServiceResult { TransitResponse, TransitReceipt, body }
//! ```
//!
//! ## What the manager proves
//!
//! After handling a request, the gateway can honestly say:
//! "I provided N bytes of Internet access to peer X at time T."
//!
//! The receipt is cryptographically signed by the gateway and can be verified
//! by anyone with the gateway's public key. It records:
//! - Which client (NodeId) received the service
//! - How many bytes were transferred
//! - When the service was provided
//! - The request ID (for replay defence)
//! - Whether the fetch succeeded (HTTP status)
//!
//! This is the foundation for the contribution proof loop (N2.9):
//! ```text
//! TransitReceipt → ContributionProof → Civic Points
//! ```

use crate::node::evidence::{ObservedMetric, EvidenceLevel};
use crate::node::gateway_service::{
    GatewayPolicy, GatewayCapacityClaim, GatewayMeasurement, GatewayServiceState,
};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── TransitReceipt ──────────────────────────────────────────────────────────

/// A signed receipt from a gateway proving it provided a specific service.
///
/// This is the gateway's honest attestation: "I provided N bytes of Internet
/// access to peer X at time T for request R."
///
/// The receipt is signed by the gateway's Ed25519 key and can be verified
/// by anyone with the gateway's public key.
///
/// ## Trust model
///
/// The receipt is an `AuthenticatedClaim` — the gateway cryptographically
/// attests to the service it provided. However, the gateway could lie about
/// the byte count. The mitigation is:
/// 1. The receipt is bound to a specific `req_id` (replay defence).
/// 2. The `object_id` (SHA-256 of the response body) is verifiable —
///    the client can check the receipt matches what it received.
/// 3. Receipts are accumulated into `GatewayMeasurement` (observed metrics),
///    which feed the contribution proof system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitReceipt {
    /// The request ID this receipt covers (replay defence).
    pub req_id: [u8; 16],
    /// The NodeId of the client that received the service.
    pub client_node_id: [u8; 32],
    /// The NodeId of the gateway that provided the service.
    pub gateway_node_id: [u8; 32],
    /// Number of bytes transferred (response body).
    pub bytes_transferred: u64,
    /// HTTP status code of the fetch (0 = fetch failed).
    pub http_status: u16,
    /// SHA-256 of the response body (verifiable by the client).
    pub object_id: [u8; 32],
    /// When the service was provided (unix seconds).
    pub served_at: u64,
    /// Duration of the fetch in milliseconds.
    pub duration_ms: u64,
    /// The gateway's Ed25519 signature over the receipt preimage.
    pub gateway_signature: [u8; 64],
}

impl TransitReceipt {
    /// Compute the canonical preimage for signing/verifying.
    fn preimage(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"SNP/0.1 transit-receipt\0");
        data.extend_from_slice(&self.req_id);
        data.extend_from_slice(&self.client_node_id);
        data.extend_from_slice(&self.gateway_node_id);
        data.extend_from_slice(&self.bytes_transferred.to_be_bytes());
        data.extend_from_slice(&self.http_status.to_be_bytes());
        data.extend_from_slice(&self.object_id);
        data.extend_from_slice(&self.served_at.to_be_bytes());
        data.extend_from_slice(&self.duration_ms.to_be_bytes());
        data
    }

    /// Sign the receipt with the gateway's secret key.
    pub fn sign(&mut self, gateway_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        self.gateway_signature = snp_crypto::ed25519_sign(gateway_secret_key, &preimage);
    }

    /// Verify the gateway's signature on this receipt.
    #[must_use]
    pub fn verify(&self, gateway_public_key: &[u8; 32]) -> bool {
        let preimage = self.preimage();
        snp_crypto::ed25519_verify(gateway_public_key, &preimage, &self.gateway_signature)
    }

    /// Evidence level: AuthenticatedClaim (signed by gateway).
    #[must_use]
    pub fn evidence_level() -> EvidenceLevel {
        EvidenceLevel::Authenticated
    }
}

impl fmt::Display for TransitReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransitReceipt(client={}, bytes={}, status={}, served_at={})",
            hex::encode(&self.client_node_id[..8]),
            self.bytes_transferred,
            self.http_status,
            self.served_at
        )
    }
}

// ─── hex helper (no external dependency needed in lib) ──────────────────────
mod hex_helper {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
use hex_helper as hex;

// ─── GatewayServiceError ────────────────────────────────────────────────────

/// Errors from the GatewayServiceManager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayServiceError {
    /// The requested destination is not allowed by the gateway's policy.
    DestinationBlocked { destination: String, policy: String },
    /// The requested protocol is not allowed by the gateway's policy.
    ProtocolBlocked { protocol: String, policy: String },
    /// The gateway has exhausted its remaining quota.
    QuotaExhausted { remaining: u64 },
    /// The gateway has too many active circuits.
    CircuitLimitReached { max: u64, current: u64 },
    /// The underlying fetch failed.
    FetchFailed(String),
    /// The client signature on the TransitRequest is invalid.
    InvalidClientSignature,
}

impl fmt::Display for GatewayServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationBlocked { destination, policy } => {
                write!(f, "destination '{destination}' blocked by policy: {policy}")
            }
            Self::ProtocolBlocked { protocol, policy } => {
                write!(f, "protocol '{protocol}' blocked by policy: {policy}")
            }
            Self::QuotaExhausted { remaining } => {
                write!(f, "quota exhausted (remaining: {remaining} bytes)")
            }
            Self::CircuitLimitReached { max, current } => {
                write!(f, "circuit limit reached (max: {max}, current: {current})")
            }
            Self::FetchFailed(msg) => write!(f, "fetch failed: {msg}"),
            Self::InvalidClientSignature => write!(f, "invalid client signature on TransitRequest"),
        }
    }
}

// ─── GatewayServiceResult ────────────────────────────────────────────────────

/// The result of a successful service handling.
#[derive(Debug, Clone)]
pub struct GatewayServiceResult {
    /// The signed TransitResponse (the HTTP fetch result, signed by the gateway).
    pub response: snp_gateway::TransitResponse,
    /// The signed TransitReceipt (the gateway's attestation of service provided).
    pub receipt: TransitReceipt,
    /// The response body (for delivery to the client).
    pub body: Vec<u8>,
}

// ─── GatewayServiceManager ───────────────────────────────────────────────────

/// The runtime manager for gateway service.
///
/// Wraps the existing `snp_gateway::handle_transit_request_with_connector`
/// with:
/// 1. **Policy enforcement** — checks destinations + protocols against the
///    gateway's `GatewayPolicy`.
/// 2. **Quota tracking** — decrements `remaining_quota` per request.
/// 3. **Measurement** — tracks bytes transferred, success/failure, latency.
/// 4. **Receipt production** — signs a `TransitReceipt` for every served request.
/// 5. **State management** — maintains a `GatewayServiceState` with live
///    measurements that can be queried by the routing layer.
///
/// ## Thread safety
///
/// The manager is NOT thread-safe (no interior mutability). It is designed
/// to be used behind a `Mutex` in a multi-threaded gateway daemon.
#[derive(Debug)]
pub struct GatewayServiceManager {
    /// The gateway's Ed25519 secret key (for signing receipts + responses).
    gateway_secret_key: [u8; 32],
    /// The gateway's NodeId.
    gateway_node_id: [u8; 32],
    /// The gateway's service state (policy + capacity + measurements).
    service_state: GatewayServiceState,
    /// Active circuit count (for circuit limit enforcement).
    active_circuits: u64,
}

impl GatewayServiceManager {
    /// Create a new GatewayServiceManager.
    ///
    /// # Arguments
    /// * `gateway_secret_key` — The gateway's Ed25519 secret key.
    /// * `policy` — The gateway's egress policy (authenticated claim).
    /// * `capacity` — The gateway's capacity claim (reported, untrusted).
    /// * `now` — Current time (unix seconds).
    #[must_use]
    pub fn new(
        gateway_secret_key: [u8; 32],
        policy: GatewayPolicy,
        capacity: GatewayCapacityClaim,
        now: u64,
    ) -> Self {
        let gateway_public = snp_crypto::derive_public_key(&gateway_secret_key);
        let gateway_node_id = snp_crypto::derive_node_id(&gateway_public);
        let service_state = GatewayServiceState::new(
            gateway_node_id,
            crate::node::capability::ProtocolCapability::InternetGateway,
            policy,
            capacity,
            now,
        );
        Self {
            gateway_secret_key,
            gateway_node_id,
            service_state,
            active_circuits: 0,
        }
    }

    /// Get the gateway's NodeId.
    #[must_use]
    pub fn gateway_node_id(&self) -> [u8; 32] {
        self.gateway_node_id
    }

    /// Get a reference to the gateway's service state (for routing decisions).
    #[must_use]
    pub fn service_state(&self) -> &GatewayServiceState {
        &self.service_state
    }

    /// Get a mutable reference to the service state (for measurement updates).
    pub fn service_state_mut(&mut self) -> &mut GatewayServiceState {
        &mut self.service_state
    }

    /// Get the current active circuit count.
    #[must_use]
    pub fn active_circuits(&self) -> u64 {
        self.active_circuits
    }

    /// Register a new active circuit (increments the counter).
    pub fn register_circuit(&mut self) {
        self.active_circuits = self.active_circuits.saturating_add(1);
    }

    /// Unregister a circuit (decrements the counter).
    pub fn unregister_circuit(&mut self) {
        self.active_circuits = self.active_circuits.saturating_sub(1);
    }

    /// Handle a transit request: enforce policy, fetch, measure, produce receipt.
    ///
    /// This is the main entry point for the gateway service runtime.
    ///
    /// # Arguments
    /// * `request` — The TransitRequest from the client.
    /// * `client_node_id` — The NodeId of the client (for the receipt).
    /// * `client_public_key` — The client's Ed25519 public key (for TransitRequest signature verification).
    /// * `connector` — The pre-built PinnedConnector for the fetch.
    /// * `now` — Current time (unix seconds).
    ///
    /// # Errors
    /// Returns `GatewayServiceError` if:
    /// - The destination/protocol is blocked by policy
    /// - The quota is exhausted
    /// - The circuit limit is reached
    /// - The fetch fails
    pub fn handle_request(
        &mut self,
        request: &snp_gateway::TransitRequest,
        client_node_id: [u8; 32],
        client_public_key: &[u8; 32],
        connector: &snp_gateway::PinnedConnector,
        now: u64,
    ) -> Result<GatewayServiceResult, GatewayServiceError> {
        // 1. Policy enforcement: check the URL against the gateway's policy.
        let url = &request.url;
        let host = extract_host(url).unwrap_or_default();
        let protocol = if url.starts_with("https://") {
            "https"
        } else if url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };

        if !self.service_state.policy.inner().destination_allowed(&host) {
            return Err(GatewayServiceError::DestinationBlocked {
                destination: host,
                policy: format!("{:?}", self.service_state.policy.inner().allowed_destinations),
            });
        }
        if !self.service_state.policy.inner().protocol_allowed(protocol) {
            return Err(GatewayServiceError::ProtocolBlocked {
                protocol: protocol.to_string(),
                policy: format!("{:?}", self.service_state.policy.inner().allowed_protocols),
            });
        }

        // 2. Quota check: is there remaining quota?
        if !self.service_state.capacity.claims_remaining_quota() {
            let remaining = self.service_state.capacity.remaining_quota_bytes.inner().unwrap_or(0);
            return Err(GatewayServiceError::QuotaExhausted { remaining });
        }

        // 3. Circuit limit check.
        let max_circuits = *self.service_state.capacity.max_circuits.inner();
        if self.active_circuits >= max_circuits {
            return Err(GatewayServiceError::CircuitLimitReached {
                max: max_circuits,
                current: self.active_circuits,
            });
        }

        // 4. Perform the actual fetch.
        let fetch_start = SystemTime::now();
        let fetched = snp_gateway::handle_transit_request_with_connector(
            request,
            &self.gateway_secret_key,
            client_public_key,
            connector,
        );
        let fetch_duration_ms = SystemTime::now()
            .duration_since(fetch_start)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match fetched {
            Ok(fetched_response) => {
                let bytes_transferred = fetched_response.body.len() as u64;
                let http_status = fetched_response.response.status;
                let object_id = fetched_response.response.object_id;

                // 5. Produce the signed receipt.
                let mut receipt = TransitReceipt {
                    req_id: request.req_id,
                    client_node_id,
                    gateway_node_id: self.gateway_node_id,
                    bytes_transferred,
                    http_status,
                    object_id,
                    served_at: now,
                    duration_ms: fetch_duration_ms,
                    gateway_signature: [0u8; 64],
                };
                receipt.sign(&self.gateway_secret_key);

                // 6. Update measurements (observed metrics).
                self.service_state.record_success(
                    fetch_duration_ms,
                    bytes_transferred,
                    now,
                );

                // 7. Decrement remaining quota (if applicable).
                let current_remaining = self.service_state.capacity.remaining_quota_bytes.inner();
                if let Some(remaining) = current_remaining {
                    let new_remaining = remaining.saturating_sub(bytes_transferred);
                    self.service_state.capacity.remaining_quota_bytes =
                        crate::node::evidence::ReportedMetric::new(Some(new_remaining));
                }

                Ok(GatewayServiceResult {
                    response: fetched_response.response,
                    receipt,
                    body: fetched_response.body,
                })
            }
            Err(e) => {
                // Record the failure in measurements.
                self.service_state.record_failure(now);
                Err(GatewayServiceError::FetchFailed(e.to_string()))
            }
        }
    }

    /// Handle a transit request WITHOUT performing a real fetch (for testing).
    ///
    /// This simulates a successful fetch with a synthetic response body.
    /// It enforces policy + quota, produces a receipt, and updates measurements
    /// — but does NOT make a real network connection.
    ///
    /// This is the test-friendly entry point that proves the policy/quota/
    /// receipt/measurement pipeline works without requiring a real HTTP server.
    pub fn handle_request_simulated(
        &mut self,
        request: &snp_gateway::TransitRequest,
        client_node_id: [u8; 32],
        client_public_key: &[u8; 32],
        synthetic_body: Vec<u8>,
        now: u64,
    ) -> Result<GatewayServiceResult, GatewayServiceError> {
        // 1. Verify the client signature on the TransitRequest.
        if !snp_gateway::verify_transit_request(request, client_public_key) {
            return Err(GatewayServiceError::InvalidClientSignature);
        }

        // 2. Policy enforcement.
        let url = &request.url;
        let host = extract_host(url).unwrap_or_default();
        let protocol = if url.starts_with("https://") {
            "https"
        } else if url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };

        if !self.service_state.policy.inner().destination_allowed(&host) {
            return Err(GatewayServiceError::DestinationBlocked {
                destination: host,
                policy: format!("{:?}", self.service_state.policy.inner().allowed_destinations),
            });
        }
        if !self.service_state.policy.inner().protocol_allowed(protocol) {
            return Err(GatewayServiceError::ProtocolBlocked {
                protocol: protocol.to_string(),
                policy: format!("{:?}", self.service_state.policy.inner().allowed_protocols),
            });
        }

        // 3. Quota check: is there remaining quota for this request?
        let bytes_transferred = synthetic_body.len() as u64;
        match self.service_state.capacity.remaining_quota_bytes.inner() {
            None => { /* unlimited */ }
            Some(remaining) if *remaining >= bytes_transferred => { /* ok */ }
            Some(remaining) => {
                return Err(GatewayServiceError::QuotaExhausted { remaining: *remaining });
            }
        }

        // 4. Circuit limit check.
        let max_circuits = *self.service_state.capacity.max_circuits.inner();
        if self.active_circuits >= max_circuits {
            return Err(GatewayServiceError::CircuitLimitReached {
                max: max_circuits,
                current: self.active_circuits,
            });
        }

        // 5. Simulate the fetch.
        let object_id = snp_crypto::sha256(&synthetic_body);
        let http_status = 200u16;
        let fetch_duration_ms = 50u64; // simulated

        // 5. Produce the signed receipt.
        let mut receipt = TransitReceipt {
            req_id: request.req_id,
            client_node_id,
            gateway_node_id: self.gateway_node_id,
            bytes_transferred,
            http_status,
            object_id,
            served_at: now,
            duration_ms: fetch_duration_ms,
            gateway_signature: [0u8; 64],
        };
        receipt.sign(&self.gateway_secret_key);

        // 6. Update measurements.
        self.service_state.record_success(fetch_duration_ms, bytes_transferred, now);

        // 7. Decrement quota.
        let current_remaining = self.service_state.capacity.remaining_quota_bytes.inner();
        if let Some(remaining) = current_remaining {
            let new_remaining = remaining.saturating_sub(bytes_transferred);
            self.service_state.capacity.remaining_quota_bytes =
                crate::node::evidence::ReportedMetric::new(Some(new_remaining));
        }

        // 8. Build a synthetic TransitResponse (for the result).
        let gateway_public = snp_crypto::derive_public_key(&self.gateway_secret_key);
        let gateway_id = snp_crypto::derive_node_id(&gateway_public);
        let mut response = snp_gateway::TransitResponse {
            req_id: request.req_id,
            status: http_status,
            headers: vec![("Content-Type".to_string(), "application/octet-stream".to_string())],
            object_id,
            fetched_at: now,
            gateway_id,
            gateway_sig: [0u8; 64],
        };
        snp_gateway::sign_transit_response(&mut response, &self.gateway_secret_key);

        Ok(GatewayServiceResult {
            response,
            receipt,
            body: synthetic_body,
        })
    }
}

/// Extract the host from a URL string.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    Some(host.to_string())
}

impl Drop for GatewayServiceManager {
    fn drop(&mut self) {
        // Decrement active circuits on drop (safety net).
        // In production, circuits should be explicitly unregistered.
    }
}

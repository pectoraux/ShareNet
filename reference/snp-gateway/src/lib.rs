//! SNP-GATEWAY — L7 Internet gateway for ShareNet 2.0
//!
//! Implements the SNP/0.1 L7 gateway layer (per `01-ARCHITECTURE.md` §2.4 and
//! `02-PROTOCOL-SPEC.md` §10). The gateway is the only node type that has
//! Internet egress, and it is the keystone of the thesis.
//!
//! Responsibilities:
//! - **Egress policy** — what may be relayed out to the Internet. Default:
//!   allow TCP to ports 80/443, deny everything else; **RFC 1918 blocking**
//!   (the gateway MUST NOT relay to private addresses — this prevents SSRF
//!   and exfiltration to internal services).
//! - **Mode A (bundle custody)** — a peer hands the gateway a `Bundle`
//!   containing a URL, deadline, and max-response-bytes. The gateway fetches
//!   the URL, packages the response as a CAS object, and returns it via the
//!   bundle's custody chain. Mandatory fields: `tlsTermination`, `deadline`,
//!   `maxResponseBytes`.
//! - **Mode B (local SOCKS5)** — the peer opens a circuit to the gateway and
//!   speaks SOCKS5 over it. The gateway dials the requested target.
//! - **Mode C (TUN/VpnService)** — the peer's TUN interface routes IP packets
//!   over the circuit; the gateway does userspace NAT. Unmodified Chrome on
//!   the peer can browse the real web. **This is the thesis, demonstrated.**
//! - **Quotas and DNS** — the gateway enforces per-peer byte quotas and
//!   resolves DNS requests on behalf of the peer (the peer has no DNS path
//!   of its own).
//!
//! This is the Rust equivalent of `/src/lib/snp/gateway.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/11-gateway.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L7 gateway.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// The requested destination is blocked by egress policy (e.g. RFC 1918).
    #[error("egress blocked by policy: {0}")]
    EgressBlocked(String),
    /// The peer has exceeded its per-window byte quota.
    #[error("quota exceeded")]
    QuotaExceeded,
    /// A Mode A bundle was malformed (missing mandatory field).
    #[error("malformed bundle: missing {0}")]
    MalformedBundle(&'static str),
    /// A fetch deadline elapsed before the response completed.
    #[error("deadline exceeded")]
    DeadlineExceeded,
    /// The upstream fetch failed (DNS, TCP, TLS, HTTP).
    #[error("upstream error: {0}")]
    Upstream(String),
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying object layer failure.
    #[error("object error: {0}")]
    Object(#[from] snp_object::ObjectError),
}

/// Convenience `Result` alias.
pub type GatewayResult<T> = Result<T, GatewayError>;

/// The three operating modes per SNP/0.1 §10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Mode A — bundle custody (relay-only, async).
    A,
    /// Mode B — local SOCKS5 over a circuit.
    B,
    /// Mode C — TUN/VpnService IP-packet relay (the thesis).
    C,
}

/// Egress policy: what the gateway will and will not dial.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Allowed TCP destination ports (default: 80, 443).
    pub allowed_ports: Vec<u16>,
    /// Whether to block RFC 1918 destinations (default: true, MUST be true
    /// in production — this prevents SSRF).
    pub block_rfc1918: bool,
    /// Per-peer byte quota per window.
    pub per_peer_quota_bytes: u64,
    /// Window length in seconds for the quota.
    pub quota_window_seconds: u64,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_ports: vec![80, 443],
            block_rfc1918: true,
            per_peer_quota_bytes: 100 * 1024 * 1024, // 100 MB / window
            quota_window_seconds: 3600,              // 1 hour
        }
    }
}

impl EgressPolicy {
    /// Returns `Ok(())` if the gateway may dial `host:port` under this policy.
    pub fn check(&self, _host: &str, _port: u16) -> GatewayResult<()> {
        todo!("Enforce allowed_ports + RFC 1918 blocking")
    }
}

/// A Mode A request bundle.
#[derive(Debug, Clone)]
pub struct ModeARequest {
    /// The URL to fetch.
    pub url: String,
    /// Mandatory: where the gateway terminates TLS.
    pub tls_termination: TlsTermination,
    /// Mandatory: deadline as a Unix timestamp (seconds).
    pub deadline: u64,
    /// Mandatory: maximum response body size in bytes.
    pub max_response_bytes: u64,
    /// Optional: request headers.
    pub headers: Vec<(String, String)>,
    /// Optional: request body (for POST/PUT).
    pub body: Option<Vec<u8>>,
}

/// Where TLS terminates for a Mode A request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTermination {
    /// TLS terminates at the gateway (gateway holds the cert chain).
    Gateway,
    /// TLS terminates end-to-end (gateway relays raw TCP and the peer verifies).
    EndToEnd,
}

/// A Mode A response: a CAS object reference plus metadata.
#[derive(Debug, Clone)]
pub struct ModeAResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// CAS object ID of the response body.
    pub body_object_id: [u8; 32],
    /// Actual body size in bytes.
    pub body_size: u64,
    /// `TransitReceipt` chain back to the requesting peer.
    pub transit_receipt: TransitReceipt,
}

/// A `TransitReceipt` proves the gateway fetched and delivered the response,
/// and is the input to `snp-civic` contribution accounting.
#[derive(Debug, Clone)]
pub struct TransitReceipt {
    /// Gateway NodeId.
    pub gateway: snp_identity::NodeId,
    /// Requesting peer NodeId.
    pub requester: snp_identity::NodeId,
    /// Bytes relayed (counts toward Civic Points).
    pub bytes_relayed: u64,
    /// Unix timestamp (seconds) at which the receipt was issued.
    pub issued_at: u64,
    /// Gateway signature over canonical CBOR of the fields above.
    pub signature: snp_crypto::Signature,
}

impl TransitReceipt {
    /// Build and sign a `TransitReceipt`.
    pub fn issue(
        _gateway: &snp_identity::NodeId,
        _requester: &snp_identity::NodeId,
        _bytes_relayed: u64,
        _now: u64,
        _gateway_secret: &snp_crypto::SecretKey,
    ) -> GatewayResult<Self> {
        todo!("Build and sign a TransitReceipt per SNP/0.1 §10.3")
    }

    /// Verify the gateway's signature.
    pub fn verify(&self, _gateway_public: &snp_crypto::PublicKey) -> GatewayResult<()> {
        todo!("Verify TransitReceipt signature via snp_crypto::ed25519_verify")
    }
}

/// Run a Mode A fetch: validate the request, dial the URL under policy,
/// store the response body in the CAS, and return a signed `ModeAResponse`.
pub fn handle_mode_a(
    _request: ModeARequest,
    _policy: &EgressPolicy,
    _cas: &impl snp_object::Cas,
    _gateway_identity: &snp_identity::NodeDescriptor,
    _gateway_secret: &snp_crypto::SecretKey,
) -> GatewayResult<ModeAResponse> {
    todo!("Execute a Mode A fetch end-to-end")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/11-gateway.json (egress policy,
        // ModeARequest/Response wire format, TransitReceipt signatures).
        let _ = EgressPolicy::default();
    }
}

//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
//!
//! N2.0.5: The deprecated `Circuit::for_gateway(GatewayChoice)` constructor
//! has been REMOVED from this module. It now lives in `crate::legacy`.
//! The canonical Circuit API is `Circuit::new(gateway_node_id,
//! gateway_public_key, circuit_keys)` — no GatewayChoice, no deterministic
//! seeds. Legacy tests that need `for_gateway` should use
//! `crate::legacy::Circuit::for_gateway` instead.
use super::*;

// ─── Circuit ─────────────────────────────────────────────────────────────────

/// An active end-to-end circuit between a client and a gateway. The circuit
/// keys MUST be derived from a fresh client↔gateway X25519 DH (via
/// [`snp_link::seal_circuit_payload_with_fresh_eph`] /
/// [`snp_link::open_circuit_payload_with_fresh_eph`]), NOT from deterministic
/// test seeds.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// The gateway's NodeId this circuit reaches.
    pub gateway_node_id: [u8; 32],
    /// The gateway's Ed25519 public key (for response signature verification).
    pub gateway_public_key: [u8; 32],
    /// Directional circuit keys (client-side: send = encrypt req, recv = decrypt resp).
    pub circuit_keys: CircuitKeys,
    /// Whether this circuit is currently usable. Set to `false` on upstream
    /// failure (so `send_request_with_failover` skips it on the next attempt).
    pub active: bool,
}

impl Circuit {
    /// **N2.0.2 production constructor.** Construct a circuit with EXPLICIT
    /// `(gateway_node_id, gateway_public_key, circuit_keys)` parameters — no
    /// `GatewayChoice` lookup, no deterministic test seeds.
    ///
    /// The caller is responsible for:
    /// - Looking up the gateway's identity (from a verified
    ///   [`GatewayAdvertisement`]).
    /// - Deriving the `circuit_keys` from a fresh client↔gateway DH (see
    ///   [`snp_link::seal_circuit_payload_with_fresh_eph`] /
    ///   [`snp_link::open_circuit_payload_with_fresh_eph`]).
    ///
    /// The returned circuit is `active = true` by default. The caller can
    /// mark it inactive by setting `circuit.active = false` after a failure.
    #[must_use]
    pub fn new(
        gateway_node_id: [u8; 32],
        gateway_public_key: [u8; 32],
        circuit_keys: CircuitKeys,
    ) -> Self {
        Self {
            gateway_node_id,
            gateway_public_key,
            circuit_keys,
            active: true,
        }
    }
}

// ─── PeerConnection ──────────────────────────────────────────────────────────

/// A persistent TCP connection to a peer node, wrapped in an AEAD Link.
pub struct PeerConnection {
    /// The peer's TCP address (e.g. `"127.0.0.1:7002"`).
    pub addr: String,
    /// The AEAD link over the TCP stream.
    pub link: Arc<Link>,
    /// The directional hop keys used for this link.
    pub hop_keys: LinkKeys,
}

// ─── UpstreamPeer (for multi-upstream relays) ────────────────────────────────

/// An upstream peer for a multi-upstream relay. The relay routes frames to
/// the upstream whose `dst_node_id` matches `frame.dst`.
#[derive(Debug, Clone)]
pub struct UpstreamPeer {
    /// The upstream's NodeId (frames with `dst == dst_node_id` route here).
    pub dst_node_id: [u8; 32],
    /// The upstream's TCP address.
    pub addr: String,
    /// The directional hop keys for this link.
    pub hop_keys: LinkKeys,
}


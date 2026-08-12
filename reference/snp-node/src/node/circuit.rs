//! Extracted from node/mod.rs for N2.0.4 Gate E (node decomposition).
use super::*;
use thiserror::Error;

// ─── Circuit ─────────────────────────────────────────────────────────────────

/// An active end-to-end circuit between a client and a gateway. The circuit
/// keys are derived from a shared seed (Ca for Gateway A, Cb for Gateway B in
/// N2.0.1). Production would derive the circuit seed from the SNP-IK/0.1
/// handshake transcript between client and gateway.
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
    /// Construct a circuit for the given gateway choice, using the N2.0.1
    /// deterministic client-side circuit keys.
    ///
    /// **N2.0.3: DEPRECATED.** This constructor uses
    /// [`crate::legacy::GatewayChoice`], which is now confined to legacy/demo code
    /// (per the N2.0.2 task spec). New production code MUST use
    /// [`Circuit::new`] with explicit `(gateway_node_id,
    /// gateway_public_key, circuit_keys)` parameters — the keys come from
    /// the SNP-IK/0.1 handshake and the client↔gateway circuit DH, NOT from
    /// a `GatewayChoice` lookup. See [`NodeIdentity::gateway`] for why this
    /// is NOT also `#[cfg(test)]`.
    #[deprecated(
        since = "N2.0.2",
        note = "Use Circuit::new(gateway_node_id, gateway_public_key, circuit_keys) instead. \
                The GatewayChoice-based constructor is retained for N2.0/N2.0.1 backward compat."
    )]
    #[must_use]
    pub fn for_gateway(gw: crate::legacy::GatewayChoice) -> Self {
        let circuit_keys = match gw {
            crate::legacy::GatewayChoice::A => client_circuit_keys_a(),
            crate::legacy::GatewayChoice::B => client_circuit_keys_b(),
        };
        Self {
            gateway_node_id: crate::legacy::gateway_node_id_for(gw),
            gateway_public_key: crate::legacy::gateway_public_key_for(gw),
            circuit_keys,
            active: true,
        }
    }

    /// **N2.0.2 production constructor.** Construct a circuit with EXPLICIT
    /// `(gateway_node_id, gateway_public_key, circuit_keys)` parameters — no
    /// `GatewayChoice` lookup, no deterministic test seeds.
    ///
    /// The caller is responsible for:
    /// - Looking up the gateway's identity (from a verified
    ///   [`GatewayAdvertisement`]).
    /// - Deriving the `circuit_keys` from a fresh client↔gateway DH (see
    ///   [`snp_link::seal_circuit_payload_with_fresh_eph`] /
    ///   [`snp_link::open_circuit_payload_with_fresh_eph`]) OR from a
    ///   pre-shared seed (legacy N1.9/N2.0 mode).
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


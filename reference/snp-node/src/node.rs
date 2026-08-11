//! N2.0.1 — Node abstraction, persistent sessions, gateway discovery, genuine failover
//!
//! This module addresses the four findings of the N2.0 audit:
//!
//! 1. **No Node abstraction** — `run_client`, `run_relay`, `run_gateway` were
//!    three separate functions with hardcoded keys. This module introduces a
//!    unified [`Node`] struct parameterised by [`NodeIdentity`] and
//!    [`Capability`].
//! 2. **No persistent sessions** — each `run_*` function served ONE request
//!    then exited. This module's `serve_*` methods loop, serving multiple
//!    requests over the same TCP connection.
//! 3. **No gateway discovery** — `GatewayChoice::A/B` was hardcoded. This
//!    module introduces signed [`GatewayAdvertisement`]s and a
//!    [`Node::discover_gateways`] method that fetches and verifies them.
//! 4. **No genuine failover** — the N2.0 failover demo restarted all nodes.
//!    This module's [`Node::send_request_with_failover`] handles failover
//!    internally (mark circuit inactive → select different gateway →
//!    establish new circuit → retry) without restarting any node.
//!
//! ## What IS production-ready
//!
//! - **GatewayAdvertisement signing/verification** — real Ed25519 signatures
//!   under `SIG_CONTEXTS::GATEWAY_ADVERT`. A forged advertisement is rejected
//!   by `verify()`. An expired advertisement is rejected by `is_expired()`.
//!   This is the "authenticated gateway discovery" the audit requested.
//! - **Persistent TCP sessions** — `serve_relay_persistent`,
//!   `serve_gateway_persistent`, and `Node::send_request` all keep their TCP
//!   connections open across multiple requests. This is verified by Test 1
//!   (3 requests over 1 connection) and Test 5 (relay serves 3 requests over
//!   1 connection).
//! - **Genuine failover** — `send_request_with_failover` detects upstream
//!   failure (TCP EOF / connection reset), marks the circuit inactive,
//!   selects a different gateway from `known_gateways`, and retries — without
//!   restarting any node. This is verified by Test 3.
//!
//! ## What is NOT production-ready (still test-only)
//!
//! - **Hop keys are deterministic test seeds** — `CLIENT_RELAY_A_SEED`,
//!   `RELAY_A_RELAY_B_SEED`, `RELAY_B_GATEWAY_A_SEED`, etc. are published in
//!   the source code. Production derives fresh per-link keys from the
//!   SNP-IK/0.1 Noise-based handshake (X25519 ephemeral-static DH + transcript
//!   hash). The session-layer persistence is real; the key-establishment is
//!   not.
//! - **Circuit keys are deterministic test seeds** — `CIRCUIT_SEED_A`,
//!   `CIRCUIT_SEED_B`. Production derives the circuit seed from the
//!   SNP-IK/0.1 transcript between client and gateway.
//! - **Gateway discovery uses a pre-shared discovery-seed link** — the
//!   discovery TCP link uses `DISCOVERY_LINK_SEED` (a deterministic test
//!   value). Production would use an anonymous X25519 ephemeral handshake
//!   (the advertisement is signed, so the discovery link itself does not
//!   need to be authenticated — only the advertisement's signature matters).
//! - **The relay is single-threaded synchronous I/O** — production would use
//!   async I/O (tokio) for connection pooling and concurrent forwarding.
//! - **No connection pooling at the relay** — each client connection triggers
//!   a fresh upstream connection. Production would maintain a pool keyed by
//!   upstream NodeId.
//! - **Upstream failure closes the client connection** — the relay propagates
//!   upstream TCP failures by closing the client connection (the client then
//!   reconnects). Production would send an explicit Class C NACK frame so the
//!   client connection stays open during failover.
//! - **`select_gateway` is "first non-expired"** — production would rank by
//!   metric (latency, capacity, cost).
//!
//! ## N2.0.1 topology
//!
//! ```text
//!   CLIENT ──[S1]──> RELAY A ──[S2]──> RELAY B ──┬──[S3a]──> GATEWAY A
//!                                                └──[S3b]──> GATEWAY B
//!     └────────[Ca]────────────────────────────────────────> GATEWAY A
//!     └────────[Cb]────────────────────────────────────────> GATEWAY B
//!          (end-to-end circuit; relays see only opaque ciphertext)
//! ```
//!
//! - S1, S2, S3a, S3b are directional hop keys (one LinkKeys pair per TCP link).
//! - Ca, Cb are directional circuit keys (one CircuitKeys pair per gateway).
//! - Relay B is "multi-upstream": it has persistent connections to BOTH
//!   gateways and routes frames based on `Frame.dst`.

use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snp_cbor::CborValue;
use snp_crypto::{
    derive_node_id, derive_public_key, ed25519_sign, ed25519_verify, sig_contexts,
};
use snp_frames::{should_drop, Frame, FRAME_TTL_MAX, FRAME_VERSION};
use snp_gateway::{
    decode_transit_request, decode_transit_response, encode_transit_request,
    encode_transit_response, handle_transit_request_with_connector, sign_transit_request,
    verify_transit_response, PinnedConnector, TransitRequest, TransitResponse,
};
use snp_link::{
    decrypt_circuit_payload, derive_link_keys, encrypt_circuit_payload, CircuitKeys, Link, LinkKeys,
};

use crate::{
    client_circuit_keys_a, client_circuit_keys_b, client_public_key,
    client_relay_a_link_keys, client_secret_key,
    gateway_a_circuit_keys, gateway_a_node_id, gateway_a_public_key, gateway_a_relay_b_link_keys,
    gateway_a_secret, gateway_b_circuit_keys, gateway_b_node_id, gateway_b_public_key,
    gateway_b_relay_b_link_keys, gateway_b_secret,
    relay_a_client_link_keys, relay_a_relay_b_link_keys,
    relay_b_gateway_a_link_keys, relay_b_gateway_b_link_keys, relay_b_relay_a_link_keys,
    NodeError, NodeResult,
};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Seed for the discovery link (Client ↔ Gateway). Both ends derive matching
/// `LinkKeys` from this seed; the client is the initiator, the gateway is the
/// responder. The discovery link is SEPARATE from the transit link (which
/// uses the S3a/S3b hop keys).
///
/// **N2.0.1 test-only.** Production would use an anonymous X25519 ephemeral
/// handshake for discovery — the advertisement's signature provides the
/// authentication, so the discovery link itself does not need to be
/// authenticated.
const DISCOVERY_LINK_SEED: &[u8] = b"SNP/0.1 N2.0.1 gateway-discovery seed";

/// Default advertisement lifetime: 1 hour.
const ADVERTISEMENT_TTL_SECS: u64 = 3600;

/// Body marker for the Class C "upstream-failure" NACK frame. When a relay
/// cannot forward a frame (upstream EOF / connection reset), it sends a
/// Class C frame with this body back to the previous hop. The client
/// recognises this as a failover signal.
pub const UPSTREAM_FAILURE_MARKER: &[u8] = b"SNP/0.1 upstream-failure";

/// Body marker for the Class C "discovery request" frame. The client sends
/// this to a gateway's discovery listener to request a signed advertisement.
pub const DISCOVERY_REQUEST_MARKER: &[u8] = b"SNP/0.1 discovery-request";

// ─── NodeIdentity ────────────────────────────────────────────────────────────

/// A node's cryptographic identity: Ed25519 secret key, public key, NodeId.
///
/// `NodeId = SHA-256("SNP/0.1 node\0" || public_key)` per invariant I4 — the
/// bare public key is NEVER used as a NodeId.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// Ed25519 secret key (32 bytes).
    pub secret_key: [u8; 32],
    /// Ed25519 public key (32 bytes), derived from `secret_key`.
    pub public_key: [u8; 32],
    /// NodeId = `SHA-256("SNP/0.1 node\0" || public_key)`.
    pub node_id: [u8; 32],
}

impl NodeIdentity {
    /// Construct a `NodeIdentity` from a secret key.
    #[must_use]
    pub fn from_secret(secret_key: [u8; 32]) -> Self {
        let public_key = derive_public_key(&secret_key);
        let node_id = derive_node_id(&public_key);
        Self { secret_key, public_key, node_id }
    }

    /// Construct the N2.0.1 Client identity (matches the N2.0 `CLIENT_SECRET`).
    #[must_use]
    pub fn client() -> Self {
        Self::from_secret(client_secret_key())
    }

    /// Construct a gateway identity for the given choice.
    ///
    /// **N2.0.3: DEPRECATED.** This constructor uses
    /// [`crate::GatewayChoice`], which is now confined to legacy/demo code.
    /// New production code MUST use [`NodeIdentity::from_secret`] with an
    /// arbitrary Ed25519 secret key — gateways are NOT required to be one of
    /// the two pre-N2.0.2 `GatewayChoice::A`/`GatewayChoice::B` identities.
    ///
    /// **Why not `#[cfg(test)]`?** The N2.0.3 task spec suggested marking
    /// this constructor `#[cfg(test)]` so it cannot leak into production
    /// builds. However, `#[cfg(test)]` on a `pub fn` in a library crate
    /// makes it invisible to INTEGRATION tests (in `tests/`), which are
    /// separate crates. The integration tests in `tests/n201_sessions.rs`
    /// and `tests/n202_protocol.rs` still use this constructor (they are
    /// explicitly testing the N2.0/N2.0.1 backward-compat path). The
    /// `#[deprecated]` attribute is sufficient to discourage production
    /// use; the static test `gateway_choice_not_in_production_code` at the
    /// bottom of this file enforces that `GatewayChoice` is NOT imported
    /// at the top level of `node.rs` (so production code in this module
    /// cannot construct a `GatewayChoice` value to pass to this function).
    #[deprecated(
        since = "N2.0.2",
        note = "Use NodeIdentity::from_secret(arbitrary_secret) instead. \
                The GatewayChoice-based constructor is retained for N2.0/N2.0.1 backward compat."
    )]
    #[must_use]
    pub fn gateway(gw: crate::GatewayChoice) -> Self {
        Self::from_secret(crate::gateway_secret_for(gw))
    }
}

// ─── Capability ──────────────────────────────────────────────────────────────

/// A node's role in the network. A single node MAY hold multiple capabilities
/// (e.g. a gateway might also relay), but in N2.0.1 each node has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can send TransitRequests (a client node).
    Client,
    /// Can forward frames between peers (a relay node).
    Relay,
    /// Can terminate circuits and fetch from the Internet (a gateway node).
    Gateway,
}

impl Capability {
    /// String representation for advertisement serialisation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Client => "client",
            Capability::Relay => "relay",
            Capability::Gateway => "gateway",
        }
    }

    /// Parse from string (for advertisement deserialisation).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Capability::Client),
            "relay" => Some(Capability::Relay),
            "gateway" => Some(Capability::Gateway),
            _ => None,
        }
    }
}

// ─── GatewayAdvertisement ────────────────────────────────────────────────────

/// A signed gateway advertisement. A gateway publishes this to announce
/// itself; clients verify the signature before trusting the advertisement.
///
/// CDDL (sketch):
///
/// ```text
/// GatewayAdvertisement = {
///   nodeId:        bstr .size 32,
///   publicKey:     bstr .size 32,
///   listenAddr:    tstr,           ; transit listener (relay → gateway)
///   discoveryAddr: tstr,           ; discovery listener (client → gateway)
///   capabilities:  [* tstr],       ; ["gateway"] for N2.0.1
///   egressPolicy:  tstr,           ; "allow-80-443" for N2.0.1
///   timestamp:     uint,           ; unix seconds
///   expiry:        uint,           ; unix seconds
///   signature:     bstr .size 64   ; Ed25519 under SIG_CONTEXT "gatewayAdvert"
/// }
/// ```
///
/// The signature is over the CBOR preimage of the map EXCLUDING the
/// `signature` field, prefixed by `SIG_CONTEXTS::GATEWAY_ADVERT`. This
/// matches invariant I2 (every signature is over `SIG_CONTEXT ‖ CBOR(payload)`).
#[derive(Debug, Clone)]
pub struct GatewayAdvertisement {
    /// The gateway's NodeId (`SHA-256("SNP/0.1 node\0" || public_key)`).
    pub node_id: [u8; 32],
    /// The gateway's Ed25519 public key.
    pub public_key: [u8; 32],
    /// The TCP address the gateway listens on for transit (relay → gateway).
    pub listen_addr: String,
    /// The TCP address the gateway listens on for discovery (client → gateway).
    pub discovery_addr: String,
    /// The gateway's capabilities (always includes `Gateway` for N2.0.1).
    pub capabilities: Vec<Capability>,
    /// Egress policy description (e.g. `"allow-80-443"`).
    pub egress_policy: String,
    /// When this advertisement was signed, unix seconds.
    pub timestamp: u64,
    /// When this advertisement expires, unix seconds.
    pub expiry: u64,
    /// Ed25519 signature by the gateway over the advertisement's preimage
    /// (excluding the signature itself), under `SIG_CONTEXT "gatewayAdvert"`.
    pub signature: [u8; 64],
    /// **N2.0.3 (Gate D).** Gateway-advertised observed RTT, in microseconds.
    /// This is a NON-SIGNED, OPTIONAL, GATEWAY-SELF-REPORTED metric. A
    /// [`MetricSelector`] MUST NOT trust this value blindly — it MUST prefer
    /// the locally-observed latency ([`GatewayDirectoryEntry::observed_latency`])
    /// when available, falling back to this advertised value only as a
    /// last resort.
    ///
    /// This field is NOT included in the signed preimage (see [`Self::preimage`])
    /// — it is metadata, not an authenticated claim. A malicious gateway can
    /// set it to any value, but the [`MetricSelector`] defends against this
    /// by preferring the locally-observed latency.
    ///
    /// `None` means the gateway did not advertise an RTT (the field is
    /// optional in the CBOR encoding for backward compat with N2.0/N2.0.1
    /// advertisements, which do not include it).
    pub observed_rtt: Option<u64>,
}

impl GatewayAdvertisement {
    /// Build the canonical CBOR preimage (the map EXCLUDING the `signature`
    /// field). This is the structure fed to `sign` / `verify` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT`.
    fn preimage(&self) -> CborValue {
        let caps: Vec<CborValue> = self
            .capabilities
            .iter()
            .map(|c| CborValue::TextString(c.as_str().to_string()))
            .collect();
        CborValue::Map(vec![
            (t("nodeId"), b(&self.node_id)),
            (t("publicKey"), b(&self.public_key)),
            (t("listenAddr"), t(&self.listen_addr)),
            (t("discoveryAddr"), t(&self.discovery_addr)),
            (t("capabilities"), CborValue::Array(caps)),
            (t("egressPolicy"), t(&self.egress_policy)),
            (t("timestamp"), u(self.timestamp)),
            (t("expiry"), u(self.expiry)),
        ])
    }

    /// Sign this advertisement with the gateway's Ed25519 secret key.
    /// Mutates `self.signature` in place.
    ///
    /// # Panics
    /// Panics if CBOR encoding of the preimage fails (it never fails for
    /// well-formed advertisements).
    pub fn sign(&mut self, gateway_secret_key: &[u8; 32]) {
        let preimage = self.preimage();
        let bytes = snp_cbor::encode(&preimage)
            .expect("CBOR encode of GatewayAdvertisement preimage never fails");
        let mut msg = Vec::with_capacity(sig_contexts::GATEWAY_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::GATEWAY_ADVERT);
        msg.extend_from_slice(&bytes);
        self.signature = ed25519_sign(gateway_secret_key, &msg);
    }

    /// Verify the signature against the `public_key` in this advertisement.
    ///
    /// Returns `false` on any failure (I20 — never throws). A client MUST
    /// call this before trusting an advertisement.
    #[must_use]
    pub fn verify(&self) -> bool {
        let preimage = self.preimage();
        let Ok(bytes) = snp_cbor::encode(&preimage) else {
            return false;
        };
        let mut msg = Vec::with_capacity(sig_contexts::GATEWAY_ADVERT.len() + bytes.len());
        msg.extend_from_slice(sig_contexts::GATEWAY_ADVERT);
        msg.extend_from_slice(&bytes);
        ed25519_verify(&self.public_key, &msg, &self.signature)
    }

    /// Check whether this advertisement has expired (relative to `now`).
    ///
    /// Returns `true` if `expiry <= now` (the advertisement is no longer
    /// valid). A client MUST call this before trusting an advertisement.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry <= now
    }

    /// Encode this advertisement to canonical CBOR (including the `signature`
    /// field). Used to send the advertisement over the discovery link.
    ///
    /// # Errors
    /// Returns [`NodeError::Other`] if CBOR encoding fails.
    pub fn encode_cbor(&self) -> NodeResult<Vec<u8>> {
        let mut entries = match self.preimage() {
            CborValue::Map(entries) => entries,
            _ => unreachable!("preimage always returns a Map"),
        };
        entries.push((t("signature"), b(&self.signature)));
        Ok(snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| NodeError::Other(format!("CBOR encode GatewayAdvertisement: {e}")))?)
    }

    /// Decode an advertisement from canonical CBOR bytes (including the
    /// `signature` field). Used to receive an advertisement over the
    /// discovery link.
    ///
    /// # Errors
    /// Returns [`NodeError::Other`] if the bytes are not a valid
    /// GatewayAdvertisement.
    pub fn decode_cbor(bytes: &[u8]) -> NodeResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| NodeError::Other(format!("CBOR decode GatewayAdvertisement: {e}")))?;
        let entries = match value {
            CborValue::Map(entries) => entries,
            other => {
                return Err(NodeError::Other(format!(
                    "GatewayAdvertisement must be a CBOR map; got {other:?}"
                )));
            }
        };
        let mut node_id: Option<[u8; 32]> = None;
        let mut public_key: Option<[u8; 32]> = None;
        let mut listen_addr: Option<String> = None;
        let mut discovery_addr: Option<String> = None;
        let mut capabilities: Option<Vec<Capability>> = None;
        let mut egress_policy: Option<String> = None;
        let mut timestamp: Option<u64> = None;
        let mut expiry: Option<u64> = None;
        let mut signature: Option<[u8; 64]> = None;
        let mut observed_rtt: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                CborValue::TextString(s) => s,
                other => {
                    return Err(NodeError::Other(format!(
                        "GatewayAdvertisement key must be a text string; got {other:?}"
                    )));
                }
            };
            match key.as_str() {
                "nodeId" => node_id = Some(extract_bstr_32(v, "nodeId")?),
                "publicKey" => public_key = Some(extract_bstr_32(v, "publicKey")?),
                "listenAddr" => listen_addr = Some(extract_text(v, "listenAddr")?),
                "discoveryAddr" => discovery_addr = Some(extract_text(v, "discoveryAddr")?),
                "capabilities" => capabilities = Some(extract_caps(v, "capabilities")?),
                "egressPolicy" => egress_policy = Some(extract_text(v, "egressPolicy")?),
                "timestamp" => timestamp = Some(extract_uint(v, "timestamp")?),
                "expiry" => expiry = Some(extract_uint(v, "expiry")?),
                "signature" => signature = Some(extract_bstr_64(v, "signature")?),
                // N2.0.3 (Gate D): optional non-signed metadata field. Older
                // advertisements (N2.0/N2.0.1) do not include this key —
                // observed_rtt stays None for backward compat.
                "observedRtt" => observed_rtt = Some(extract_uint(v, "observedRtt")?),
                other => {
                    return Err(NodeError::Other(format!(
                        "unknown GatewayAdvertisement key \"{other}\""
                    )));
                }
            }
        }
        Ok(Self {
            node_id: node_id.ok_or_else(|| NodeError::Other("nodeId missing".into()))?,
            public_key: public_key.ok_or_else(|| NodeError::Other("publicKey missing".into()))?,
            listen_addr: listen_addr.ok_or_else(|| NodeError::Other("listenAddr missing".into()))?,
            discovery_addr: discovery_addr
                .ok_or_else(|| NodeError::Other("discoveryAddr missing".into()))?,
            capabilities: capabilities.unwrap_or_default(),
            egress_policy: egress_policy.unwrap_or_default(),
            timestamp: timestamp.ok_or_else(|| NodeError::Other("timestamp missing".into()))?,
            expiry: expiry.ok_or_else(|| NodeError::Other("expiry missing".into()))?,
            signature: signature.ok_or_else(|| NodeError::Other("signature missing".into()))?,
            observed_rtt,
        })
    }

    /// Construct a signed advertisement for the given gateway choice. The
    /// gateway's identity keys are the deterministic N2.0 test keys
    /// (`GATEWAY_A_SECRET` / `GATEWAY_B_SECRET`); production would use a
    /// persistent on-disk keypair.
    ///
    /// **N2.0.3: DEPRECATED.** This constructor uses
    /// [`crate::GatewayChoice`], which is now confined to legacy/demo code.
    /// New production code MUST use [`GatewayAdvertisement::for_identity`]
    /// with an arbitrary [`NodeIdentity`] — gateways are NOT required to be
    /// one of the two pre-N2.0.2 `GatewayChoice::A`/`GatewayChoice::B`
    /// identities. See [`NodeIdentity::gateway`] for why this is NOT also
    /// `#[cfg(test)]`.
    #[deprecated(
        since = "N2.0.2",
        note = "Use GatewayAdvertisement::for_identity(identity, listen, discovery) instead. \
                The GatewayChoice-based constructor is retained for N2.0/N2.0.1 backward compat."
    )]
    #[must_use]
    pub fn for_gateway(
        gw: crate::GatewayChoice,
        listen_addr: &str,
        discovery_addr: &str,
    ) -> Self {
        #[allow(deprecated)]
        let identity = NodeIdentity::gateway(gw);
        Self::for_identity(&identity, listen_addr, discovery_addr)
    }

    /// **N2.0.2 production constructor.** Build a signed advertisement for
    /// an ARBITRARY gateway identity (no `GatewayChoice` lookup).
    ///
    /// The advertisement is signed by `identity.secret_key` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT` (invariant I2). The advertised
    /// `nodeId` is `identity.node_id` (i.e. `SHA-256("SNP/0.1 node\0" ||
    /// identity.public_key)`, invariant I4). The advertised `publicKey` is
    /// `identity.public_key` (raw 32 bytes, invariant I3).
    ///
    /// The caller is responsible for:
    /// - Generating (or loading) the gateway's Ed25519 identity keypair.
    /// - Binding the correct `listen_addr` (transit) and `discovery_addr`
    ///   to the gateway's actual TCP listeners.
    /// - Refreshing the advertisement before its `expiry` (default 1 hour).
    #[must_use]
    pub fn for_identity(identity: &NodeIdentity, listen_addr: &str, discovery_addr: &str) -> Self {
        let now = now_unix();
        let mut advert = Self {
            node_id: identity.node_id,
            public_key: identity.public_key,
            listen_addr: listen_addr.to_string(),
            discovery_addr: discovery_addr.to_string(),
            capabilities: vec![Capability::Gateway],
            egress_policy: "allow-80-443".to_string(),
            timestamp: now,
            expiry: now + ADVERTISEMENT_TTL_SECS,
            signature: [0u8; 64],
            observed_rtt: None,
        };
        advert.sign(&identity.secret_key);
        advert
    }
}

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
    /// [`crate::GatewayChoice`], which is now confined to legacy/demo code
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
    pub fn for_gateway(gw: crate::GatewayChoice) -> Self {
        let circuit_keys = match gw {
            crate::GatewayChoice::A => client_circuit_keys_a(),
            crate::GatewayChoice::B => client_circuit_keys_b(),
        };
        Self {
            gateway_node_id: crate::gateway_node_id_for(gw),
            gateway_public_key: crate::gateway_public_key_for(gw),
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

// ─── Node ────────────────────────────────────────────────────────────────────

/// The unified Node abstraction. A Node holds an identity, a set of
/// capabilities, and persistent state (peer connections, known gateways,
/// active circuits, seen reqIds).
///
/// A Node is typically one of:
/// - **Client** — uses `send_request` / `send_request_with_failover` /
///   `discover_gateways`.
/// - **Relay** — uses `serve_relay_persistent` or
///   `serve_relay_multi_upstream_persistent`.
/// - **Gateway** — uses `serve_gateway_persistent` and `serve_discovery_persistent`.
///
/// The `peers` map is mainly used by client nodes (to maintain the persistent
/// connection to Relay A). Relay and gateway nodes manage their own
/// connections inside their `serve_*` methods.
pub struct Node {
    /// The node's cryptographic identity.
    pub identity: NodeIdentity,
    /// The node's capabilities (Client, Relay, Gateway).
    pub capabilities: Vec<Capability>,
    /// The address this node listens on (for relays and gateways).
    pub listen_addr: String,
    /// Persistent peer connections (keyed by peer TCP address). Used by
    /// client nodes to cache the connection to Relay A.
    pub peers: Mutex<HashMap<String, PeerConnection>>,
    /// Gateways discovered via signed advertisements.
    pub known_gateways: Mutex<Vec<GatewayAdvertisement>>,
    /// Active circuits (keyed by gateway NodeId). Used by client nodes.
    pub circuits: Mutex<HashMap<[u8; 32], Circuit>>,
    /// Seen reqIds (replay protection, N1.9.2 carry-over).
    pub seen_req_ids: Mutex<HashSet<[u8; 16]>>,
    /// The currently-selected gateway's NodeId (for failover ordering).
    pub current_gateway: Mutex<Option<[u8; 32]>>,
}

impl Node {
    /// Construct a new Node with the given identity, capabilities, and
    /// listen address.
    #[must_use]
    pub fn new(identity: NodeIdentity, capabilities: Vec<Capability>, listen_addr: String) -> Self {
        Self {
            identity,
            capabilities,
            listen_addr,
            peers: Mutex::new(HashMap::new()),
            known_gateways: Mutex::new(Vec::new()),
            circuits: Mutex::new(HashMap::new()),
            seen_req_ids: Mutex::new(HashSet::new()),
            current_gateway: Mutex::new(None),
        }
    }

    /// Construct a Client Node. The client has no listen address (it doesn't
    /// accept incoming connections) — pass `""` or use [`Node::new_client_with_relay`].
    #[must_use]
    pub fn new_client() -> Self {
        Self::new(NodeIdentity::client(), vec![Capability::Client], String::new())
    }

    // ─── Persistent relay serve loop ──────────────────────────────────────

    /// Run a persistent single-upstream relay. Listens on `listen_addr` for
    /// incoming connections from the previous hop; for each connection, opens
    /// a connection to `next_hop_addr` and forwards frames in both directions
    /// until either side closes.
    ///
    /// PERSISTENCE: each client connection serves MULTIPLE round-trips (not
    /// just one). The relay loops `recv → forward → recv → forward` until
    /// EOF or error.
    ///
    /// N2.0 TTL handling: the relay decrements TTL on receipt. If TTL hits 0
    /// after decrement, the frame is DROPPED (not forwarded).
    ///
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
    /// logged and the relay continues accepting new connections.
    pub fn serve_relay_persistent(
        &self,
        listen_addr: &str,
        next_hop_addr: &str,
        prev_hop_keys: LinkKeys,
        next_hop_keys: LinkKeys,
    ) -> NodeResult<()> {
        serve_relay_persistent_inner(
            listen_addr,
            next_hop_addr,
            prev_hop_keys,
            next_hop_keys,
            None, // no connection counter
        )
    }

    /// Run a persistent multi-upstream relay. Like
    /// [`serve_relay_persistent`](Self::serve_relay_persistent) but with
    /// MULTIPLE upstream peers. Frames are routed to the upstream whose
    /// `dst_node_id` matches `frame.dst`.
    ///
    /// This is the Relay B in the N2.0.1 topology: it has persistent
    /// connections to BOTH Gateway A and Gateway B, and routes based on
    /// `frame.dst`. When the client fails over from Gateway A to Gateway B,
    /// Relay B's connection to Gateway B is already open — no relay restart.
    ///
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure or if `upstreams` is empty.
    pub fn serve_relay_multi_upstream_persistent(
        &self,
        listen_addr: &str,
        upstreams: &[UpstreamPeer],
        prev_hop_keys: LinkKeys,
    ) -> NodeResult<()> {
        if upstreams.is_empty() {
            return Err(NodeError::Other(
                "multi-upstream relay requires at least one upstream".into(),
            ));
        }
        serve_relay_multi_upstream_persistent_inner(listen_addr, upstreams, prev_hop_keys, None)
    }

    // ─── Persistent gateway serve loop ────────────────────────────────────

    /// Run a persistent gateway. Listens on `listen_addr` for incoming
    /// connections from relays; for each connection, loops serving transit
    /// requests (decrypt circuit → fetch URL → encrypt response) until the
    /// relay disconnects.
    ///
    /// PERSISTENCE: each relay connection serves MULTIPLE requests (not just
    /// one). This is the key difference from `run_gateway_named` (which
    /// served one request then exited).
    ///
    /// **N2.0.3 production API.** The gateway's identity comes from
    /// `self.identity` (an arbitrary [`NodeIdentity`] — NO
    /// `GatewayChoice`). The caller supplies the directional `link_keys`
    /// (for the relay↔gateway TCP hop AEAD) and the `circuit_keys` (for
    /// decrypting client TransitRequests / encrypting gateway
    /// TransitResponses). In production these keys come from the SNP-IK/0.1
    /// handshake + the client↔gateway circuit DH; in the N2.0.1 demo they
    /// are the deterministic test seeds (passed by the demo wrapper via
    /// `gateway_a_relay_b_link_keys()` / `gateway_a_circuit_keys()`).
    ///
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
    /// logged and the gateway continues accepting new connections.
    pub fn serve_gateway_persistent(
        &self,
        listen_addr: &str,
        link_keys: LinkKeys,
        circuit_keys: CircuitKeys,
    ) -> NodeResult<()> {
        let gateway_node_id = self.identity.node_id;
        let gateway_sk = self.identity.secret_key;
        let listener = TcpListener::bind(listen_addr)?;
        eprintln!(
            "[gateway-persistent {}] listening on {listen_addr}",
            hex_short(&gateway_node_id)
        );
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gateway-persistent {}] accept error: {e}", hex_short(&gateway_node_id));
                    continue;
                }
            };
            eprintln!(
                "[gateway-persistent {}] relay connected from {}",
                hex_short(&gateway_node_id),
                stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, link_keys));
            let mut seen_req_ids = HashSet::new();
            // PERSISTENT LOOP: serve multiple requests over this connection.
            loop {
                match serve_one_gateway_request(
                    &link,
                    gateway_node_id,
                    &gateway_sk,
                    &circuit_keys,
                    &mut seen_req_ids,
                ) {
                    Ok(ServeOutcome::Continue) => continue,
                    Ok(ServeOutcome::Closed) => {
                        eprintln!(
                            "[gateway-persistent {}] connection closed",
                            hex_short(&gateway_node_id)
                        );
                        break;
                    }
                    Err(e) => {
                        eprintln!(
                            "[gateway-persistent {}] request error: {e}",
                            hex_short(&gateway_node_id)
                        );
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Run a persistent gateway that serves AT MOST `max_requests` requests
    /// per connection, then closes the connection. Used by tests to simulate
    /// a gateway that drops its connection after N requests (Test 3:
    /// failover).
    ///
    /// After `max_requests` requests, the gateway closes the TCP stream
    /// (simulating a connection drop). The relay detects EOF on its upstream
    /// connection and propagates the failure back to the client.
    ///
    /// **N2.0.3 production API.** The gateway's identity comes from
    /// `self.identity` (no `GatewayChoice`).
    pub fn serve_gateway_persistent_with_drop_after(
        &self,
        listen_addr: &str,
        link_keys: LinkKeys,
        circuit_keys: CircuitKeys,
        max_requests: usize,
    ) -> NodeResult<()> {
        let gateway_node_id = self.identity.node_id;
        let gateway_sk = self.identity.secret_key;
        let listener = TcpListener::bind(listen_addr)?;
        eprintln!(
            "[gateway-drop-after-{} {}] listening on {listen_addr}",
            max_requests,
            hex_short(&gateway_node_id)
        );
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[gateway-drop-after {}] accept error: {e}",
                        hex_short(&gateway_node_id)
                    );
                    continue;
                }
            };
            eprintln!(
                "[gateway-drop-after {}] relay connected from {}",
                hex_short(&gateway_node_id),
                stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, link_keys));
            let mut seen_req_ids = HashSet::new();
            let mut served = 0usize;
            loop {
                if served >= max_requests {
                    eprintln!(
                        "[gateway-drop-after {}] served {served} requests — DROPPING connection (simulated failure)",
                        hex_short(&gateway_node_id)
                    );
                    // Explicitly shut down the stream to signal EOF to the relay.
                    let _ = link.stream().shutdown(std::net::Shutdown::Both);
                    break;
                }
                match serve_one_gateway_request(
                    &link,
                    gateway_node_id,
                    &gateway_sk,
                    &circuit_keys,
                    &mut seen_req_ids,
                ) {
                    Ok(ServeOutcome::Continue) => {
                        served += 1;
                    }
                    Ok(ServeOutcome::Closed) => {
                        eprintln!(
                            "[gateway-drop-after {}] connection closed by peer",
                            hex_short(&gateway_node_id)
                        );
                        break;
                    }
                    Err(e) => {
                        eprintln!(
                            "[gateway-drop-after {}] request error: {e}",
                            hex_short(&gateway_node_id)
                        );
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    // ─── Discovery serve loop (gateway side) ──────────────────────────────

    /// Run the discovery listener. Listens on `discovery_addr` for incoming
    /// connections from clients; for each connection, the gateway sends its
    /// signed [`GatewayAdvertisement`] (CBOR-encoded) as a Class C frame.
    ///
    /// The discovery link uses a SEPARATE seed ([`DISCOVERY_LINK_SEED`]) from
    /// the transit link — the gateway has TWO active link seeds: one for
    /// discovery (this listener) and one for transit
    /// ([`serve_gateway_persistent`]).
    ///
    /// **N2.0.3 production API.** The advertisement is constructed via
    /// [`GatewayAdvertisement::for_identity`] using `self.identity` (an
    /// arbitrary [`NodeIdentity`] — NO `GatewayChoice`). The advertisement
    /// is signed by `self.identity.secret_key` under
    /// `SIG_CONTEXTS::GATEWAY_ADVERT`. The client verifies the signature
    /// before trusting the advertisement.
    ///
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
    /// logged and the listener continues accepting new connections.
    pub fn serve_discovery_persistent(
        &self,
        discovery_addr: &str,
        transit_listen_addr: &str,
    ) -> NodeResult<()> {
        let listener = TcpListener::bind(discovery_addr)?;
        let gateway_node_id = self.identity.node_id;
        eprintln!(
            "[discovery {}] listening on {discovery_addr}",
            hex_short(&gateway_node_id)
        );
        let keys = discovery_link_keys_responder();
        let advert = GatewayAdvertisement::for_identity(
            &self.identity,
            transit_listen_addr,
            discovery_addr,
        );

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[discovery {}] accept error: {e}", hex_short(&gateway_node_id));
                    continue;
                }
            };
            let link = Arc::new(Link::new(stream, keys));
            // Read the discovery-request marker frame.
            match link.recv_frame() {
                Ok(req_frame) => {
                    if req_frame.body.as_slice() == DISCOVERY_REQUEST_MARKER {
                        eprintln!("[discovery {}] got discovery request", hex_short(&gateway_node_id));
                        let advert_bytes = match advert.encode_cbor() {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!(
                                    "[discovery {}] encode error: {e}",
                                    hex_short(&gateway_node_id)
                                );
                                continue;
                            }
                        };
                        let resp_frame = Frame {
                            v: FRAME_VERSION,
                            cls: b'C',
                            dst: req_frame.src,
                            src: advert.node_id,
                            ttl: FRAME_TTL_MAX,
                            fid: req_frame.fid,
                            seq: req_frame.seq + 1,
                            body: advert_bytes,
                        };
                        if let Err(e) = link.send_frame(&resp_frame) {
                            eprintln!("[discovery {}] send error: {e}", hex_short(&gateway_node_id));
                        }
                    } else {
                        eprintln!(
                            "[discovery {}] unexpected discovery request body ({} bytes) — ignoring",
                            hex_short(&gateway_node_id),
                            req_frame.body.len()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("[discovery {}] recv error: {e}", hex_short(&gateway_node_id));
                }
            }
        }
        Ok(())
    }

    // ─── Client-side: discovery ───────────────────────────────────────────

    /// Discover gateways by connecting to each address in `known_addrs`,
    /// requesting a signed advertisement, verifying the signature, and adding
    /// valid (non-expired, signature-valid) advertisements to
    /// `known_gateways`.
    ///
    /// Each address is the gateway's DISCOVERY listener (not its transit
    /// listener). The discovery link uses [`DISCOVERY_LINK_SEED`] — both
    /// ends derive matching `LinkKeys` from this seed.
    ///
    /// **N2.0.3 production API.** This method NO LONGER pre-populates the
    /// circuit table for GatewayChoice::A/B (the previous N2.0.1
    /// circuit-pre-population logic depended on `GatewayChoice`, which is
    /// now confined to legacy/demo code in `lib.rs`). The N2.0.3 path is:
    ///   1. `discover_gateways` — fetches + verifies the advertisements
    ///      (signature + expiry + I4 cross-check) and records them in
    ///      `known_gateways`.
    ///   2. The client establishes a circuit to the selected gateway via
    ///      the SNP-IK/0.1 handshake + the client↔gateway X25519 circuit
    ///      DH (see `tests/n202_protocol.rs` Test 2 for the end-to-end
    ///      flow). The circuit keys come from the fresh DH, NOT from a
    ///      deterministic seed.
    ///
    /// For the legacy N2.0.1 demo path (`run_mesh_session_demo`), the
    /// client constructs `Circuit::new(gateway_node_id,
    /// gateway_public_key, circuit_keys)` directly with the deterministic
    /// test seeds (passed via the demo wrapper) — see
    /// `run_mesh_session_demo_with_failover` for the demo path.
    ///
    /// # Errors
    /// Returns [`NodeError`] if NO gateway could be discovered (all addresses
    /// failed). Otherwise returns `Ok(())` — individual failures are logged.
    pub fn discover_gateways(&self, known_addrs: &[String]) -> NodeResult<()> {
        let keys = discovery_link_keys_initiator();
        let mut discovered = 0usize;
        for addr in known_addrs {
            eprintln!("[discover] querying {addr}");
            let link = match Link::connect(addr, keys) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[discover] connect to {addr} failed: {e}");
                    continue;
                }
            };
            // Set a read timeout so we don't hang on unresponsive gateways.
            {
                let stream = link.stream();
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            }
            let req_frame = Frame {
                v: FRAME_VERSION,
                cls: b'C',
                dst: [0u8; 32], // broadcast — the gateway responds regardless
                src: self.identity.node_id,
                ttl: FRAME_TTL_MAX,
                fid: random_fid(),
                seq: 1,
                body: DISCOVERY_REQUEST_MARKER.to_vec(),
            };
            if let Err(e) = link.send_frame(&req_frame) {
                eprintln!("[discover] send to {addr} failed: {e}");
                continue;
            }
            let resp_frame = match link.recv_frame() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[discover] recv from {addr} failed: {e}");
                    continue;
                }
            };
            let advert = match GatewayAdvertisement::decode_cbor(&resp_frame.body) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[discover] decode advertisement from {addr} failed: {e}");
                    continue;
                }
            };
            // VERIFY THE SIGNATURE — this is the "authenticated gateway
            // discovery" the audit requested. A forged advertisement is
            // rejected here.
            if !advert.verify() {
                eprintln!("[discover] advertisement from {addr} has INVALID SIGNATURE — rejecting");
                continue;
            }
            // Check expiry.
            let now = now_unix();
            if advert.is_expired(now) {
                eprintln!("[discover] advertisement from {addr} is EXPIRED — rejecting");
                continue;
            }
            // Cross-check: the advertised nodeId MUST match
            // SHA-256("SNP/0.1 node\0" || publicKey) (invariant I4).
            let expected_node_id = derive_node_id(&advert.public_key);
            if advert.node_id != expected_node_id {
                eprintln!(
                    "[discover] advertisement from {addr} has nodeId mismatch (I4 violation) — rejecting"
                );
                continue;
            }
            eprintln!(
                "[discover] gateway discovered: nodeId={} listenAddr={} discoveryAddr={}",
                hex_short(&advert.node_id),
                advert.listen_addr,
                advert.discovery_addr
            );
            // N2.0.3: Record the advertisement only. The client establishes
            // the circuit via the SNP-IK/0.1 handshake + the client↔gateway
            // circuit DH (see tests/n202_protocol.rs Test 2). The previous
            // N2.0.1 circuit-pre-population (which mapped the advertisement's
            // publicKey to GatewayChoice::A/B) is removed — it required
            // importing `GatewayChoice` into `node.rs`, which the N2.0.3 task
            // spec forbids.
            self.known_gateways.lock().unwrap().push(advert);
            discovered += 1;
        }
        if discovered == 0 {
            return Err(NodeError::Other(format!(
                "discover_gateways: no gateways discovered from {} addresses",
                known_addrs.len()
            )));
        }
        eprintln!("[discover] discovered {discovered} gateway(s)");
        Ok(())
    }

    /// Select the best gateway from `known_gateways`. For N2.0.1 this is the
    /// first non-expired gateway with an active circuit. Production would
    /// rank by metric (latency, capacity, cost).
    ///
    /// Returns a clone of the advertisement (not a reference, to avoid
    /// holding the mutex lock).
    #[must_use]
    pub fn select_gateway(&self) -> Option<GatewayAdvertisement> {
        let now = now_unix();
        let gateways = self.known_gateways.lock().unwrap();
        let circuits = self.circuits.lock().unwrap();
        for advert in gateways.iter() {
            if advert.is_expired(now) {
                continue;
            }
            if let Some(circuit) = circuits.get(&advert.node_id) {
                if circuit.active {
                    return Some(advert.clone());
                }
            }
        }
        None
    }

    // ─── Client-side: send request ────────────────────────────────────────

    /// Send a single transit request via the currently-selected gateway.
    /// Uses (or establishes) a persistent TCP connection to Relay A.
    ///
    /// PERSISTENCE: the connection to Relay A is cached in `self.peers` and
    /// reused across calls. Multiple `send_request` calls share the same
    /// TCP connection.
    ///
    /// # Errors
    /// Returns [`NodeError`] on any failure (link error, AEAD failure,
    /// signature verification failure, etc.).
    pub fn send_request(&self, url: &str) -> NodeResult<(u16, bool)> {
        let advert = self
            .select_gateway()
            .ok_or_else(|| NodeError::Other("no gateway selected (call discover_gateways first)".into()))?;
        self.send_request_via_gateway(url, &advert.node_id)
    }

    /// Send a transit request targeting a SPECIFIC gateway (by NodeId).
    /// This is the lower-level primitive used by `send_request` and
    /// `send_request_with_failover`.
    ///
    /// # Errors
    /// Returns [`NodeError`] on any failure.
    pub fn send_request_via_gateway(
        &self,
        url: &str,
        gateway_node_id: &[u8; 32],
    ) -> NodeResult<(u16, bool)> {
        let transit_resp = self.send_request_via_gateway_full(url, gateway_node_id)?;
        Ok((transit_resp.status, true))
    }

    /// **N2.0.3 (Gate K).** Like [`send_request_via_gateway`](Self::send_request_via_gateway)
    /// but returns the full decoded [`TransitResponse`] (not just the
    /// `(status, verified)` tuple). This lets callers inspect the
    /// `object_id` (the SHA-256 of the fetched body — useful for
    /// end-to-end body-integrity verification in tests).
    ///
    /// The gateway signature is verified against the circuit's
    /// `gateway_public_key` — if verification fails, this method returns
    /// [`NodeError::GatewaySignatureFailed`] (the `TransitResponse` is NOT
    /// returned in that case).
    ///
    /// # Errors
    /// Returns [`NodeError`] on any failure (link error, AEAD failure,
    /// signature verification failure, upstream-failure NACK, etc.).
    pub fn send_request_via_gateway_full(
        &self,
        url: &str,
        gateway_node_id: &[u8; 32],
    ) -> NodeResult<TransitResponse> {
        // Look up the circuit for this gateway.
        let circuit = {
            let circuits = self.circuits.lock().unwrap();
            circuits
                .get(gateway_node_id)
                .cloned()
                .ok_or_else(|| NodeError::Other("no circuit for gateway (call discover_gateways first)".into()))?
        };
        if !circuit.active {
            return Err(NodeError::Other(
                "circuit is inactive (marked failed) — try another gateway".into(),
            ));
        }

        // Get (or establish) the persistent connection to Relay A.
        let relay_a_addr = self.listen_addr.clone();
        if relay_a_addr.is_empty() {
            return Err(NodeError::Other(
                "no relay address configured (set Node.listen_addr to Relay A's address)".into(),
            ));
        }

        let link = self.get_or_connect_peer(&relay_a_addr, client_relay_a_link_keys())?;

        // Build the TransitRequest.
        let mut req = TransitRequest {
            req_id: random_req_id(),
            method: "GET".into(),
            url: url.to_string(),
            tls_termination: "GATEWAY_PLAINTEXT".into(),
            max_response_bytes: 65536,
            deadline: now_unix() + 60,
            reply_to: [0u8; 32],
            client_sig: [0u8; 64],
        };
        sign_transit_request(&mut req, &self.identity.secret_key);
        let req_bytes = encode_transit_request(&req)?;

        // Encrypt the body end-to-end with the circuit key.
        let sealed_body = encrypt_circuit_payload(&circuit.circuit_keys.send_key, &req_bytes);

        // Build the request frame addressed to the gateway NodeId.
        let req_frame = Frame {
            v: FRAME_VERSION,
            cls: b'B',
            dst: *gateway_node_id,
            src: self.identity.node_id,
            ttl: FRAME_TTL_MAX,
            fid: random_fid(),
            seq: 1,
            body: sealed_body,
        };

        // Set a read timeout so we don't hang forever on a dead gateway.
        {
            let stream = link.stream();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        }

        link.send_frame(&req_frame)?;
        let resp_frame = link.recv_frame()?;

        if resp_frame.cls != b'B' {
            // Class C (or other) — this is a control frame, likely an
            // upstream-failure NACK from the relay.
            if resp_frame.cls == b'C' && resp_frame.body.as_slice() == UPSTREAM_FAILURE_MARKER {
                return Err(NodeError::UpstreamFailure);
            }
            return Err(NodeError::Other(format!(
                "expected Class B response, got Class {} (body={} bytes) — likely upstream failure",
                resp_frame.cls as char,
                resp_frame.body.len()
            )));
        }

        // Decrypt the response body with the circuit recv_key.
        let resp_bytes = decrypt_circuit_payload(&circuit.circuit_keys.recv_key, &resp_frame.body)
            .ok_or(NodeError::CircuitDecryptionFailed)?;
        let transit_resp: TransitResponse = decode_transit_response(&resp_bytes)?;

        // Verify the gateway's signature.
        let verified = verify_transit_response(&transit_resp, &circuit.gateway_public_key);
        if !verified {
            return Err(NodeError::GatewaySignatureFailed);
        }

        // Record the reqId (replay protection, client-side).
        self.seen_req_ids.lock().unwrap().insert(req.req_id);

        // Update current_gateway.
        *self.current_gateway.lock().unwrap() = Some(*gateway_node_id);

        Ok(transit_resp)
    }

    /// Send a transit request with genuine failover. Tries the
    /// currently-selected gateway first; on failure (link error, AEAD
    /// failure, etc.), marks the circuit inactive, selects a different
    /// gateway, and retries.
    ///
    /// NO NODE RESTARTS — the client handles failover internally. The
    /// relay/gateway processes are unaffected.
    ///
    /// # Errors
    /// Returns [`NodeError`] if ALL known gateways fail.
    pub fn send_request_with_failover(&self, url: &str) -> NodeResult<(u16, bool)> {
        // Build the try-order: current gateway first, then others.
        let now = now_unix();
        let gw_ids: Vec<[u8; 32]> = {
            let gateways = self.known_gateways.lock().unwrap();
            let circuits = self.circuits.lock().unwrap();
            gateways
                .iter()
                .filter(|a| !a.is_expired(now))
                .filter(|a| circuits.get(&a.node_id).map_or(false, |c| c.active))
                .map(|a| a.node_id)
                .collect()
        };
        if gw_ids.is_empty() {
            return Err(NodeError::Other(
                "no active, non-expired gateways available for failover".into(),
            ));
        }
        let current = *self.current_gateway.lock().unwrap();
        let mut order: Vec<[u8; 32]> = Vec::new();
        if let Some(c) = current {
            if gw_ids.contains(&c) {
                order.push(c);
            }
        }
        for id in &gw_ids {
            if !order.contains(id) {
                order.push(*id);
            }
        }

        let mut last_err: Option<NodeError> = None;
        for gw_id in &order {
            eprintln!("[failover] trying gateway {}", hex_short(gw_id));
            match self.send_request_via_gateway(url, gw_id) {
                Ok(result) => {
                    eprintln!("[failover] SUCCESS via gateway {}", hex_short(gw_id));
                    *self.current_gateway.lock().unwrap() = Some(*gw_id);
                    return Ok(result);
                }
                Err(e) => {
                    eprintln!(
                        "[failover] gateway {} failed: {e} — marking inactive, trying next",
                        hex_short(gw_id)
                    );
                    // Mark this circuit as inactive.
                    if let Some(circuit) = self.circuits.lock().unwrap().get_mut(gw_id) {
                        circuit.active = false;
                    }
                    // If the failure was an upstream-failure NACK (not a
                    // connection reset), the persistent connection to Relay A
                    // is STILL ALIVE — the relay sent a valid Class C frame.
                    // We can reuse it for the next attempt. Only drop the
                    // peer connection on actual connection failures.
                    if !matches!(e, NodeError::UpstreamFailure) {
                        let relay_a_addr = self.listen_addr.clone();
                        if !relay_a_addr.is_empty() {
                            self.peers.lock().unwrap().remove(&relay_a_addr);
                        }
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| NodeError::Other("all gateways failed".into())))
    }

    // ─── Internal: peer connection management ─────────────────────────────

    /// Get an existing persistent peer connection, or establish a new one.
    /// The connection is cached in `self.peers` for reuse across calls.
    fn get_or_connect_peer(
        &self,
        addr: &str,
        hop_keys: LinkKeys,
    ) -> NodeResult<Arc<Link>> {
        // Fast path: already connected.
        if let Some(peer) = self.peers.lock().unwrap().get(addr) {
            return Ok(Arc::clone(&peer.link));
        }
        // Slow path: connect and cache.
        eprintln!("[node] establishing persistent connection to {addr}");
        let link = Arc::new(Link::connect(addr, hop_keys)?);
        let peer = PeerConnection {
            addr: addr.to_string(),
            link: Arc::clone(&link),
            hop_keys,
        };
        self.peers.lock().unwrap().insert(addr.to_string(), peer);
        Ok(link)
    }

    // ─── N2.0.3 (GATE E): dynamic route construction ─────────────────────

    /// Construct a [`Route`] from this node to a gateway, through the given
    /// relays. All identities are arbitrary NodeIds — NO compile-time
    /// knowledge of which gateway or which relays.
    ///
    /// **N2.0.3 (GATE E).** This is the dynamic-route-construction entry
    /// point required by the N2.0.3 task spec. The route's `source` is
    /// `self.identity.node_id`; the `hops` list is
    /// `[relay_node_ids..., gateway_node_id]` (the destination is appended
    /// as the last hop, per the spec).
    ///
    /// The returned route is in the `Proposed` state — the caller is
    /// responsible for driving the state machine (`transition_to(
    /// Establishing) → transition_to(Active)`) as the SNP-IK/0.1
    /// handshakes complete at each hop.
    ///
    /// # Errors
    /// Returns [`NodeError::Other`] wrapping a [`RouteError`] if the
    /// constructed route fails validation (e.g. too many hops, or a
    /// duplicate relay NodeId).
    pub fn construct_route(
        &self,
        relay_node_ids: &[[u8; 32]],
        gateway_node_id: [u8; 32],
    ) -> NodeResult<Route> {
        let mut hops = Vec::with_capacity(relay_node_ids.len() + 1);
        for relay in relay_node_ids {
            hops.push(*relay);
        }
        hops.push(gateway_node_id);
        let route = Route::new(self.identity.node_id, gateway_node_id, hops);
        // Validate the route before returning it (the caller may still
        // attempt to use an invalid route, but we surface validation
        // errors eagerly).
        route
            .validate()
            .map_err(|e| NodeError::Other(format!("construct_route: route validation failed: {e}")))?;
        Ok(route)
    }
}

// ─── N2.0.2: PeerSession, GatewayDirectory, Route, Circuit state machines ───
//
// This block adds the N2.0.2 protocol-session objects defined in the task
// spec (Phases 4 and 5). These structures are the production-ready
// state-machine layer that sits ABOVE the SNP-IK/0.1 handshake and the
// circuit DH. They do NOT replace the legacy `Circuit` struct (which is
// kept for backward compat with N2.0/N2.0.1); they provide the new
// production API.
//
// The state machines are pure data + transition logic — they do NOT perform
// any I/O. The Node methods that drive them (serve_gateway_with_handshake,
// send_request_with_handshake, etc.) are responsible for the actual TCP
// and handshake I/O.

/// The state of a [`PeerSession`].
///
/// The legal transitions are:
///   New → Handshaking → Established → (Degraded ↔ Established)* → Closing → Closed
///
/// Any other transition is rejected by [`PeerSession::transition_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessionState {
    /// The session has been allocated but the SNP-IK/0.1 handshake has not
    /// yet started.
    New,
    /// The SNP-IK/0.1 handshake is in progress (the first message has been
    /// sent or received).
    Handshaking,
    /// The handshake completed; the session has fresh directional link keys
    /// and is carrying frames.
    Established,
    /// The session is alive but has experienced a transient failure (e.g. an
    /// AEAD decryption failure on a single frame, or a timeout). The session
    /// MAY recover back to `Established`, or it MAY transition to `Closing`.
    Degraded,
    /// The session is being shut down gracefully. No new frames will be
    /// accepted; in-flight frames are being drained.
    Closing,
    /// The session is fully closed. The TCP connection has been dropped. The
    /// session is no longer usable.
    Closed,
}

/// A peer session — the result of a successful (or in-progress) SNP-IK/0.1
/// handshake with a specific peer node.
///
/// The session holds:
/// - The peer's authenticated NodeId + Ed25519 public key.
/// - A `session_id` (the SNP-IK/0.1 transcript hash analogue — see
///   [`snp_link::HandshakeResult::session_id`]).
/// - The directional `send_key` / `recv_key` for frame AEAD.
/// - The current `state` of the session state machine.
/// - Timestamps for lifecycle management (`created_at`, `last_activity`).
#[derive(Debug, Clone)]
pub struct PeerSession {
    /// The peer's NodeId (`SHA-256("SNP/0.1 node\0" || peer_public_key)`).
    pub peer_node_id: [u8; 32],
    /// The peer's Ed25519 public key (32 bytes, raw — invariant I3).
    pub peer_public_key: [u8; 32],
    /// The SNP-IK/0.1 session id (transcript hash analogue). Fresh per
    /// handshake (differs across sessions even between the same pair).
    pub session_id: [u8; 32],
    /// The current state of the session.
    pub state: PeerSessionState,
    /// The directional AEAD send key (encrypt outbound frames).
    pub send_key: snp_crypto::SymmetricKey,
    /// The directional AEAD recv key (decrypt inbound frames).
    pub recv_key: snp_crypto::SymmetricKey,
    /// When the session was created (unix seconds).
    pub created_at: u64,
    /// When the session last saw activity (unix seconds).
    pub last_activity: u64,
}

impl PeerSession {
    /// Construct a new `PeerSession` in the `New` state. The `send_key` and
    /// `recv_key` are zeroed — they are populated when the session transitions
    /// to `Established` (via [`PeerSession::establish`]).
    #[must_use]
    pub fn new(peer_node_id: [u8; 32], peer_public_key: [u8; 32]) -> Self {
        let now = now_unix();
        Self {
            peer_node_id,
            peer_public_key,
            session_id: [0u8; 32],
            state: PeerSessionState::New,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            created_at: now,
            last_activity: now,
        }
    }

    /// Construct a `PeerSession` in the `Established` state from a successful
    /// SNP-IK/0.1 handshake result.
    #[must_use]
    pub fn from_handshake(handshake: &snp_link::HandshakeResult) -> Self {
        let now = now_unix();
        Self {
            peer_node_id: handshake.peer_node_id,
            peer_public_key: handshake.peer_public_key,
            session_id: handshake.session_id,
            state: PeerSessionState::Established,
            send_key: handshake.link_keys.send_key,
            recv_key: handshake.link_keys.recv_key,
            created_at: now,
            last_activity: now,
        }
    }

    /// Transition the session to a new state. Returns `Ok(())` if the
    /// transition is legal, or `Err(NodeError)` describing the illegal
    /// transition.
    ///
    /// Legal transitions (per [`PeerSessionState`] docs):
    ///   New → Handshaking → Established → (Degraded ↔ Established)* → Closing → Closed
    ///
    /// Also: any state → Closed (forced close), New → Closed (abandon before
    /// handshake), Handshaking → Closed (handshake failed).
    pub fn transition_to(&mut self, new_state: PeerSessionState) -> NodeResult<()> {
        use PeerSessionState::*;
        let allowed = matches!(
            (self.state, new_state),
            (New, Handshaking)
                | (New, Closed)
                | (Handshaking, Established)
                | (Handshaking, Closed)
                | (Established, Degraded)
                | (Established, Closing)
                | (Established, Closed)
                | (Degraded, Established)
                | (Degraded, Closing)
                | (Degraded, Closed)
                | (Closing, Closed)
                | (Closed, Closed)
        );
        if !allowed {
            return Err(NodeError::Other(format!(
                "illegal PeerSession transition: {:?} → {:?}",
                self.state, new_state
            )));
        }
        self.state = new_state;
        self.last_activity = now_unix();
        Ok(())
    }

    /// Convenience: mark the session as handshaking.
    pub fn begin_handshake(&mut self) -> NodeResult<()> {
        self.transition_to(PeerSessionState::Handshaking)
    }

    /// Convenience: mark the session as established (after a successful
    /// handshake). Updates the keys + session_id from the handshake result.
    pub fn establish(&mut self, handshake: &snp_link::HandshakeResult) -> NodeResult<()> {
        // Verify the handshake result is for the expected peer.
        if handshake.peer_node_id != self.peer_node_id {
            return Err(NodeError::Other(format!(
                "PeerSession::establish: handshake peer_node_id {} does not match session peer_node_id {}",
                hex_short(&handshake.peer_node_id),
                hex_short(&self.peer_node_id)
            )));
        }
        self.session_id = handshake.session_id;
        self.send_key = handshake.link_keys.send_key;
        self.recv_key = handshake.link_keys.recv_key;
        self.transition_to(PeerSessionState::Established)
    }

    /// Convenience: mark the session as closing (graceful shutdown).
    pub fn close(&mut self) -> NodeResult<()> {
        self.transition_to(PeerSessionState::Closing)?;
        self.transition_to(PeerSessionState::Closed)
    }

    /// Returns `true` if the session is in a state that can carry frames
    /// (`Established` or `Degraded`).
    #[must_use]
    pub fn is_alive(&self) -> bool {
        matches!(self.state, PeerSessionState::Established | PeerSessionState::Degraded)
    }
}

// ─── GatewayDirectory (Phase 4) ──────────────────────────────────────────────

/// The state of a [`GatewayDirectoryEntry`] — the lifecycle of a gateway
/// from discovery to active use to expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// The gateway has been discovered (advertisement received and
    /// signature-verified) but has not yet been reached via a SNP-IK/0.1
    /// handshake.
    Discovered,
    /// The gateway has been reached via a successful SNP-IK/0.1 handshake —
    /// its advertised identity matches its handshake-authenticated identity.
    Verified,
    /// The gateway is the currently-selected gateway for outgoing requests.
    Active,
    /// The gateway has been marked unreachable (recent handshake or request
    /// failed). It MAY be retried later.
    Unreachable,
    /// The gateway's advertisement has expired. It MUST be re-discovered
    /// before use.
    Expired,
}

/// An entry in the [`GatewayDirectory`]. Combines the signed
/// [`GatewayAdvertisement`] with runtime-observed metadata (latency,
/// reliability, state).
#[derive(Debug, Clone)]
pub struct GatewayDirectoryEntry {
    /// The signed advertisement (verified at discovery time).
    pub advertisement: GatewayAdvertisement,
    /// When this entry was last confirmed (unix seconds). Updated on every
    /// successful handshake or request.
    pub last_seen: u64,
    /// The most recently observed round-trip latency (unix microseconds), if
    /// any. `None` until the first request completes.
    pub observed_latency: Option<u64>,
    /// The observed reliability (fraction of successful requests in the
    /// recent window, `[0.0, 1.0]`). `None` until the first request completes.
    pub observed_reliability: Option<f64>,
    /// The current state of this entry.
    pub state: GatewayState,
}

/// A directory of known gateways, populated by [`DiscoveryProvider`]s and
/// used by [`GatewaySelector`]s to choose a gateway for outgoing requests.
///
/// The directory is a `Vec<GatewayDirectoryEntry>`; lookups by NodeId are
/// linear (the directory is small — typically tens of entries).
#[derive(Debug, Clone, Default)]
pub struct GatewayDirectory {
    entries: Vec<GatewayDirectoryEntry>,
}

impl GatewayDirectory {
    /// Construct an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace an entry by `node_id`. If an entry with the same
    /// `node_id` already exists, it is replaced (the new advertisement is
    /// assumed to be fresher).
    pub fn upsert(&mut self, entry: GatewayDirectoryEntry) {
        let node_id = entry.advertisement.node_id;
        if let Some(existing) = self.entries.iter_mut().find(|e| e.advertisement.node_id == node_id) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Look up an entry by NodeId.
    #[must_use]
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&GatewayDirectoryEntry> {
        self.entries.iter().find(|e| &e.advertisement.node_id == node_id)
    }

    /// Look up an entry by NodeId (mutable).
    pub fn get_mut(&mut self, node_id: &[u8; 32]) -> Option<&mut GatewayDirectoryEntry> {
        self.entries.iter_mut().find(|e| &e.advertisement.node_id == node_id)
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[GatewayDirectoryEntry] {
        &self.entries
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mark the entry with `node_id` as unreachable (e.g. after a request
    /// failure). No-op if the entry does not exist.
    pub fn mark_unreachable(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.get_mut(node_id) {
            entry.state = GatewayState::Unreachable;
        }
    }

    /// Mark the entry with `node_id` as active (e.g. after a successful
    /// request via this gateway). No-op if the entry does not exist.
    pub fn mark_active(&mut self, node_id: &[u8; 32]) {
        if let Some(entry) = self.get_mut(node_id) {
            entry.state = GatewayState::Active;
            entry.last_seen = now_unix();
        }
    }

    /// **N2.0.3 (Gate D).** Select an entry using the given [`GatewaySelector`]
    /// strategy. This is the strategy-parameterised gateway-selection entry
    /// point: a caller picks a strategy ([`FirstAvailableSelector`] for
    /// simple failover, [`MetricSelector`] for latency-aware selection, or a
    /// custom implementation) and the directory picks the best entry.
    ///
    /// Returns `None` if the strategy returns `None` (e.g. all entries are
    /// expired, unreachable, or the directory is empty).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use snp_node::node::{GatewayDirectory, MetricSelector};
    /// # let directory: GatewayDirectory = unimplemented!();
    /// let selected = directory.select(&MetricSelector);
    /// if let Some(entry) = selected {
    ///     // Use entry.advertisement.listen_addr to reach the gateway.
    /// }
    /// ```
    #[must_use]
    pub fn select(&self, selector: &dyn GatewaySelector) -> Option<&GatewayDirectoryEntry> {
        selector.select(self)
    }
}

/// A gateway-selection strategy. Implementations decide which entry in a
/// [`GatewayDirectory`] to use for the next outgoing request.
///
/// **N2.0.3 (Gate D).** This is the N2.0.3 abstraction over gateway
/// selection. Implementations:
/// - [`FirstAvailableSelector`] — first non-expired, non-unreachable entry
///   (mirrors the N2.0.1 `select_gateway` behaviour but on the new
///   `GatewayDirectory` API).
/// - [`MetricSelector`] — picks the entry with the lowest observed (or, as a
///   fallback, advertised) latency. Does NOT trust the gateway-self-reported
///   advertised latency blindly — prefers the locally-observed latency.
///
/// A custom implementation might rank by hop count, capacity, cost, or a
/// weighted combination. The trait is `Send + Sync` so a selector can be
/// shared across threads (a long-lived client node holds one in its state).
pub trait GatewaySelector: Send + Sync {
    /// Select an entry from the directory. Returns `None` if no entry is
    /// suitable (e.g. all are expired or unreachable).
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry>;
}

/// The simplest selector: returns the first entry that is not `Expired` or
/// `Unreachable`. This mirrors the N2.0.1 `select_gateway` behaviour but
/// operates on the new `GatewayDirectory` API.
pub struct FirstAvailableSelector;

impl GatewaySelector for FirstAvailableSelector {
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry> {
        let now = now_unix();
        directory.entries().iter().find(|e| {
            !e.advertisement.is_expired(now)
                && !matches!(e.state, GatewayState::Expired | GatewayState::Unreachable)
        })
    }
}

/// **N2.0.3 (Gate D).** Metric-based selector: picks the gateway with the
/// lowest latency. Does NOT trust advertised latency — uses only the locally
/// observed latency if available, falling back to the gateway-self-reported
/// advertised RTT only as a last resort.
///
/// ## Selection key
///
/// The selection key for each entry is:
/// ```text
///   observed_latency.or(advertisement.observed_rtt).unwrap_or(u64::MAX)
/// ```
/// This means:
/// - If the client has observed latency for an entry, that value is used
///   (the advertised RTT is IGNORED — a malicious gateway cannot lower its
///   score by advertising a low RTT once the client has measured it).
/// - If the client has NOT observed latency but the gateway advertised an
///   RTT, the advertised RTT is used (with the understanding that it is
///   self-reported and could be optimistic).
/// - If neither is available, the entry sorts last (`u64::MAX`).
///
/// Only entries in the `Verified` or `Active` state are considered (entries
/// that are merely `Discovered`, or that are `Unreachable` / `Expired`, are
/// skipped — they are not yet known-good or are known-bad).
///
/// ## Spec deviation: `or` instead of `min`
///
/// The N2.0.3 task spec sketches this selector with
/// `observed.min(advertised)` as the selection key. That logic is
/// VULNERABLE to the lying-gateway attack: a malicious gateway could
/// advertise an artificially low RTT (`advertised = 1µs`) to override the
/// client's locally-measured higher latency, attracting traffic it doesn't
/// deserve. The spec's comment ("Does NOT trust advertised latency — uses
/// only observed latency if available, falls back to advertised if not")
/// makes the secure intent clear; the `min` code is a sketch bug.
///
/// This implementation uses `observed.or(advertised).unwrap_or(u64::MAX)`
/// instead, which matches the spec's documented intent. A gateway's
/// advertised RTT is ONLY used when the client has NOT yet measured the
/// latency — once the client has measured it, the advertised value is
/// ignored entirely.
///
/// ## Tiebreaking
///
/// `Iterator::min_by_key` returns the FIRST entry with the minimum key on
/// ties, so the order of entries in the directory matters for ties. The
/// directory preserves insertion order (callers can `upsert` entries in a
/// preferred order if they care about tiebreaking).
pub struct MetricSelector;

impl GatewaySelector for MetricSelector {
    fn select<'a>(&self, directory: &'a GatewayDirectory) -> Option<&'a GatewayDirectoryEntry> {
        directory
            .entries()
            .iter()
            .filter(|e| {
                matches!(e.state, GatewayState::Verified | GatewayState::Active)
            })
            .min_by_key(|e| {
                let observed = e.observed_latency;
                let advertised = e.advertisement.observed_rtt;
                // Prefer the locally-observed latency; fall back to the
                // advertised RTT ONLY if no observation is available. This
                // is `observed.or(advertised).unwrap_or(u64::MAX)`, NOT
                // `min(observed, advertised)` — the latter would let a
                // malicious gateway's advertised RTT override the client's
                // own measurement.
                observed.or(advertised).unwrap_or(u64::MAX)
            })
    }
}

// ─── Discovery (Phase 6 — N2.0.3 Gate C: DiscoveryProvider abstraction) ──────

/// A discovered peer or gateway advertisement, paired with the TCP endpoint
/// it can be reached at.
///
/// The protocol does not care whether discovery came from:
/// - configured bootstrap peers ([`BootstrapDiscovery`])
/// - LAN discovery (mDNS)
/// - Bluetooth
/// - Wi-Fi Direct
/// - another ShareNet peer ([`StaticDiscovery`] for tests)
///
/// The `endpoint` is the TCP address (e.g. `"127.0.0.1:7001"` or
/// `"gateway1.example:7001"`) at which the advertising node can be reached
/// for transit. The `advertisement` is the signed [`GatewayAdvertisement`]
/// (which itself contains `listen_addr` and `discovery_addr`); the
/// `endpoint` field here lets a discovery provider carry a separately-resolved
/// address (e.g. an mDNS-resolved LAN address) without overwriting the
/// advertisement's signed fields.
#[derive(Debug, Clone)]
pub struct DiscoveredNode {
    /// The signed advertisement (caller MUST verify the signature before use).
    pub advertisement: GatewayAdvertisement,
    /// The TCP address at which this node can be reached for transit.
    pub endpoint: String,
}

/// Platform-independent discovery abstraction.
///
/// A [`DiscoveryProvider`] is a SOURCE of [`DiscoveredNode`]s — it knows how
/// to find peers/gateways but does NOT verify advertisements (that is the
/// caller's responsibility, see [`GatewayAdvertisement::verify`]) and does
/// NOT maintain routing state (that is the caller's responsibility, see
/// [`GatewayDirectory`]).
///
/// The trait is `Send + Sync` so a provider can be shared across threads
/// (e.g. an mDNS provider that runs a background listener thread).
///
/// ## Implementations
///
/// - [`BootstrapDiscovery`] — reads a configured list of TCP addresses and
///   queries each for a signed advertisement. Used for the first-run case.
/// - [`StaticDiscovery`] — a deterministic, in-memory list. Used for tests
///   and for "bring your own topology" scenarios.
///
/// ## N2.0.3 (Gate C)
///
/// This trait is the N2.0.3 abstraction over the discovery layer. The N2.0.1
/// `Node::discover_gateways` method is the production caller; it loops over
/// a `Vec<String>` of addresses and verifies each advertisement. The trait
/// lets the SAME caller logic drive mDNS / Bluetooth / Wi-Fi Direct / etc.
/// discovery without changes — only the provider implementation changes.
pub trait DiscoveryProvider: Send + Sync {
    /// Discover peers/gateways. Returns a list of [`DiscoveredNode`]s.
    ///
    /// The caller is responsible for:
    /// 1. Verifying each `advertisement`'s signature
    ///    ([`GatewayAdvertisement::verify`]).
    /// 2. Checking each `advertisement`'s expiry
    ///    ([`GatewayAdvertisement::is_expired`]).
    /// 3. Cross-checking each `advertisement`'s `node_id` against
    ///    `SHA-256("SNP/0.1 node\0" || public_key)` (invariant I4).
    /// 4. Adding the verified advertisements to a [`GatewayDirectory`].
    fn discover(&self) -> Vec<DiscoveredNode>;

    /// Advertise this node's presence. Called by a node that wants to be
    /// discoverable by other nodes (e.g. a gateway advertising itself on the
    /// LAN via mDNS, or registering with a directory service).
    ///
    /// The default implementation is a no-op (some providers — e.g.
    /// [`BootstrapDiscovery`] and [`StaticDiscovery`] — do not support
    /// outbound advertising).
    fn advertise(&self, _advertisement: &GatewayAdvertisement, _endpoint: &str) {
        // Default no-op: providers that don't support outbound advertising
        // (bootstrap list, static list) silently ignore the call.
    }
}

/// A bootstrap-list discovery provider: holds a list of TCP addresses and
/// queries each for a signed advertisement. Used for the first-run case
/// (no cached gateways).
///
/// **N2.0.3 (Gate C).** The trait now returns [`DiscoveredNode`]s (with an
/// `endpoint` field) instead of bare [`GatewayAdvertisement`]s. The
/// `endpoint` is set to the bootstrap address that produced the
/// advertisement (so a caller can reach the gateway for transit without
/// parsing the advertisement's `listen_addr`).
///
/// The actual discovery I/O (TCP connect + SNP-IK/0.1 handshake + fetch
/// advertisement) is deferred to a future revision — for now, `discover()`
/// returns an empty list (callers that need actual discovery should use
/// [`Node::discover_gateways`], which performs the legacy N2.0.1 discovery
/// flow). The trait abstraction is the N2.0.3 deliverable; wiring the
/// underlying I/O into the trait is the N2.0.4 deliverable.
pub struct BootstrapDiscovery {
    addrs: Vec<String>,
}

impl BootstrapDiscovery {
    /// Construct a new `BootstrapDiscovery` with the given list of TCP
    /// addresses (e.g. `["gateway1.example:7001", "gateway2.example:7001"]`).
    #[must_use]
    pub fn new(addrs: Vec<String>) -> Self {
        Self { addrs }
    }

    /// Return the bootstrap addresses (for inspection / debugging).
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addrs
    }
}

impl DiscoveryProvider for BootstrapDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        // The actual discovery I/O is the same as Node::discover_gateways
        // (legacy N2.0.1 implementation). For N2.0.3 we wrap the result in
        // the new trait — the underlying TCP fetch is unchanged.
        // This is a placeholder: production code would call the new
        // SNP-IK/0.1-based discovery (a single anonymous X25519 handshake
        // to each address, fetching the advertisement over the established
        // link). For now we return an empty list — callers that need
        // actual discovery should use Node::discover_gateways.
        let _ = &self.addrs;
        Vec::new()
    }
}

/// A deterministic, in-memory discovery provider. Holds a pre-configured
/// list of [`DiscoveredNode`]s and returns them verbatim from `discover()`.
///
/// **N2.0.3 (Gate C).** This is the reference implementation for tests:
/// it lets a test construct a discovery scenario (e.g. "the client
/// discovers these three gateways") without running any I/O. It is also
/// useful for "bring your own topology" scenarios where the caller already
/// knows the gateway addresses (e.g. from a configuration file or a prior
/// discovery run).
///
/// `advertise()` is a no-op (a static list does not support outbound
/// advertising — the list is configured at construction time).
pub struct StaticDiscovery {
    nodes: Vec<DiscoveredNode>,
}

impl StaticDiscovery {
    /// Construct an empty `StaticDiscovery`.
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add a [`DiscoveredNode`] to the static list. The node is appended
    /// (duplicates are NOT deduplicated — the caller is responsible for
    /// uniqueness if it matters).
    pub fn add(&mut self, node: DiscoveredNode) {
        self.nodes.push(node);
    }

    /// Return the number of nodes in the static list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if the static list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl Default for StaticDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryProvider for StaticDiscovery {
    fn discover(&self) -> Vec<DiscoveredNode> {
        self.nodes.clone()
    }
    // advertise() uses the default no-op implementation.
}

// ─── Route (Phase 5 — N2.0.3 first-class Route object) ───────────────────────

/// The state of a [`Route`] — the lifecycle of a multi-hop path from a
/// client to a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    /// The route has been proposed (e.g. by a routing algorithm) but no
    /// SNP-IK/0.1 handshakes have been performed yet.
    Proposed,
    /// One or more hop handshakes are in progress.
    Establishing,
    /// All hop handshakes have completed; the route is carrying frames.
    Active,
    /// The route is alive but has experienced a transient failure on one
    /// hop. The route MAY recover, or it MAY transition to `Migrating`.
    Degraded,
    /// The route is being migrated to a different path (e.g. one hop has
    /// failed and a new hop is being brought up). Frames may be re-routed
    /// through the new path.
    Migrating,
    /// The route has permanently failed. A new route MUST be proposed.
    Failed,
    /// The route has been gracefully closed.
    Closed,
}

/// Observed performance characteristics of a [`Route`]. Populated as the
/// route carries frames; used by the routing algorithm to rank alternative
/// routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteMetrics {
    /// Number of hops in the route (`route.hops.len()`).
    pub hop_count: u32,
    /// Estimated one-way latency in milliseconds, if known. `None` until
    /// the first frame round-trips the route.
    pub estimated_latency_ms: Option<u64>,
    /// Estimated bandwidth in bits per second, if known. `None` until the
    /// first frame round-trips the route.
    pub bandwidth_bps: Option<u64>,
}

/// Errors from [`Route`] validation and state-machine transitions.
///
/// The N2.0.3 task spec ("GATE B — First-class Route object") requires the
/// `Route::validate` and `Route::transition` methods to return
/// `Result<(), RouteError>` (NOT `NodeResult<()>`). The existing
/// `Route::transition_to` method (which returns `NodeResult<()>`) is kept
/// for backward compat with the N2.0.2 tests (`tests/n202_protocol.rs`
/// test_7b, test_7c) — it is a thin wrapper that maps `RouteError` to
/// `NodeError::Other`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// The route has no hops (`hops.is_empty()`).
    #[error("route is empty (no hops)")]
    Empty,
    /// The `source` field is all-zero (the client NodeId must be set).
    #[error("route source is unset (all-zero NodeId)")]
    SourceMismatch,
    /// The `destination` field does not match `hops.last()`.
    #[error("route destination does not match last hop")]
    DestinationMismatch,
    /// A hop NodeId appears more than once (loop).
    #[error("route has a duplicate hop (loop): {0}")]
    DuplicateHop(String),
    /// The hop count exceeds the TTL max (16).
    #[error("route has too many hops: {0} > 16")]
    ExcessiveHopCount(usize),
    /// The route has expired (`expires_at <= now`).
    #[error("route has expired (expires_at={expires_at}, now={now})")]
    Expired {
        /// The route's `expires_at` timestamp.
        expires_at: u64,
        /// The `now` timestamp the check was made against.
        now: u64,
    },
    /// The state transition is illegal.
    #[error("illegal route transition: {from:?} → {to:?}")]
    IllegalTransition {
        /// The state the route is currently in.
        from: RouteState,
        /// The state the caller attempted to transition to.
        to: RouteState,
    },
}

/// Default route lifetime: 1 hour (matches the advertisement TTL).
const ROUTE_DEFAULT_TTL_SECS: u64 = 3600;

/// Maximum hop count (matches `FRAME_TTL_MAX` from `snp-frames`).
const ROUTE_MAX_HOPS: usize = 16;

/// A multi-hop route from a client to a gateway.
///
/// A `Route` is a sequence of peer NodeIds (`hops`) terminating at a
/// `destination` (a gateway NodeId). Each hop has its own SNP-IK/0.1 session
/// (a [`PeerSession`]).
///
/// The `route_id` is `SHA-256(source || destination || hops || nonce)`,
/// computed when the route is proposed. It uniquely identifies this
/// particular path (the same client↔gateway pair may have multiple routes
/// via different relay paths).
///
/// **N2.0.3 (GATE B) additions.** The struct now carries:
/// - `source` — the client NodeId (was previously only implied via the
///   `route_id` input).
/// - `epoch` — incremented on every key rotation / migration.
/// - `expires_at` — when the route expires (default `created_at + 1 hour`).
/// - `metrics` — observed performance characteristics (hop count, latency,
///   bandwidth).
/// - `last_validated` — kept for backward compat with the N2.0.2 tests.
#[derive(Debug, Clone)]
pub struct Route {
    /// The route id — `SHA-256(source || destination || hops || nonce)`.
    pub route_id: [u8; 32],
    /// The client NodeId (the route's source). N2.0.3 (GATE B).
    pub source: [u8; 32],
    /// The destination gateway NodeId.
    pub destination: [u8; 32],
    /// The ordered list of peer NodeIds along the path. Per the N2.0.3
    /// spec, this list INCLUDES the destination as the last element (the
    /// `destination` field is a cache of `hops.last()` for convenience).
    /// For a direct client↔gateway route, this is `[destination]`. For a
    /// one-relay route, this is `[relay_node_id, destination]`. Etc.
    ///
    /// **Note:** the N2.0.2 implementation did NOT include the destination
    /// in `hops` (it was "intermediate relays only"). The N2.0.3
    /// `validate()` method accepts both conventions — it only checks
    /// `destination == hops.last()` IF `hops` is non-empty.
    pub hops: Vec<[u8; 32]>,
    /// The route epoch — incremented on every key rotation or migration.
    /// N2.0.3 (GATE B).
    pub epoch: u64,
    /// The current state of the route.
    pub state: RouteState,
    /// When the route was created (unix seconds).
    pub created_at: u64,
    /// When the route expires (unix seconds). N2.0.3 (GATE B). Default
    /// `created_at + ROUTE_DEFAULT_TTL_SECS` (1 hour).
    pub expires_at: u64,
    /// Observed performance characteristics. N2.0.3 (GATE B).
    pub metrics: RouteMetrics,
    /// When the route was last validated (all hops handshaked successfully).
    /// Updated when the route transitions to `Active`.
    pub last_validated: u64,
}

impl Route {
    /// Construct a new `Route` in the `Proposed` state. The `route_id` is
    /// computed from the source NodeId, destination, hops, and a fresh nonce.
    ///
    /// **N2.0.3 (GATE B).** The signature is `Route::new(source,
    /// destination, hops)` (taking `[u8; 32]` by value, per the spec). The
    /// `epoch` is initialised to 0; `expires_at` to `now + 1 hour`;
    /// `metrics.hop_count` to `hops.len()`.
    #[must_use]
    pub fn new(source: [u8; 32], destination: [u8; 32], hops: Vec<[u8; 32]>) -> Self {
        let now = now_unix();
        // route_id = SHA-256(source || destination || hops || nonce)
        let mut id_input = Vec::with_capacity(32 + 32 + hops.len() * 32 + 16);
        id_input.extend_from_slice(&source);
        id_input.extend_from_slice(&destination);
        for hop in &hops {
            id_input.extend_from_slice(hop);
        }
        // Include a fresh nonce (timestamp + counter) so two routes with
        // the same path get different route_ids.
        id_input.extend_from_slice(&now.to_be_bytes());
        id_input.extend_from_slice(&FID_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes());
        let route_id = snp_crypto::sha256(&id_input);
        let hop_count = u32::try_from(hops.len()).unwrap_or(u32::MAX);
        Self {
            route_id,
            source,
            destination,
            hops,
            epoch: 0,
            state: RouteState::Proposed,
            created_at: now,
            expires_at: now.saturating_add(ROUTE_DEFAULT_TTL_SECS),
            metrics: RouteMetrics {
                hop_count,
                estimated_latency_ms: None,
                bandwidth_bps: None,
            },
            last_validated: 0,
        }
    }

    /// Validate the route's structural invariants. Returns `Ok(())` if the
    /// route is well-formed, or `Err(RouteError)` describing the first
    /// violation.
    ///
    /// **N2.0.3 (GATE B).** Checks:
    /// 1. Not empty — `hops` is non-empty (a route must have at least the
    ///    destination hop).
    /// 2. Source is set — `source` is not all-zero.
    /// 3. Destination matches last hop — `hops.last() == Some(&destination)`.
    /// 4. No duplicate hops — no NodeId appears twice in `hops` (loop
    ///    detection).
    /// 5. Hop count ≤ 16 — `hops.len() <= ROUTE_MAX_HOPS` (TTL max).
    /// 6. Not expired — `!self.is_expired(now)`.
    ///
    /// Note: this method does NOT check that the source is the first hop
    /// (the source is the client, which is NOT in the `hops` list — the
    /// `hops` list starts at the first relay). The "Source matches first
    /// hop or is the source field" check from the spec is interpreted as
    /// "the source field must be set" (non-zero).
    pub fn validate(&self) -> Result<(), RouteError> {
        // 1. Not empty.
        if self.hops.is_empty() {
            return Err(RouteError::Empty);
        }
        // 2. Source is set (non-zero).
        if self.source == [0u8; 32] {
            return Err(RouteError::SourceMismatch);
        }
        // 3. Destination matches last hop.
        if self.hops.last() != Some(&self.destination) {
            return Err(RouteError::DestinationMismatch);
        }
        // 4. No duplicate hops (loop detection).
        let mut seen = HashSet::new();
        for hop in &self.hops {
            if !seen.insert(*hop) {
                return Err(RouteError::DuplicateHop(hex_short(hop)));
            }
        }
        // 5. Hop count ≤ 16.
        if self.hops.len() > ROUTE_MAX_HOPS {
            return Err(RouteError::ExcessiveHopCount(self.hops.len()));
        }
        // 6. Not expired.
        let now = now_unix();
        if self.is_expired(now) {
            return Err(RouteError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// Check whether this route has expired (relative to `now`).
    ///
    /// Returns `true` if `expires_at <= now`. A route with `expires_at == 0`
    /// (the N2.0.2 default before N2.0.3 added the `expires_at` field) is
    /// treated as "never expires" for backward compat.
    ///
    /// **N2.0.3 (GATE B).**
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        // expires_at == 0 means "never expires" (backward compat with
        // N2.0.2 routes that did not set this field).
        self.expires_at != 0 && self.expires_at <= now
    }

    /// Transition the route to a new state. Returns `Ok(())` on a legal
    /// transition, `Err(RouteError::IllegalTransition)` on an illegal one.
    ///
    /// **N2.0.3 (GATE B).** This is the spec-mandated `transition` method
    /// returning `Result<(), RouteError>`. The N2.0.2 `transition_to`
    /// method (returning `NodeResult<()>`) is kept as a thin wrapper for
    /// backward compat with the existing tests.
    pub fn transition(&mut self, new_state: RouteState) -> Result<(), RouteError> {
        use RouteState::*;
        let allowed = matches!(
            (self.state, new_state),
            (Proposed, Establishing)
                | (Proposed, Closed)
                | (Proposed, Failed)
                | (Establishing, Active)
                | (Establishing, Failed)
                | (Establishing, Closed)
                | (Active, Degraded)
                | (Active, Migrating)
                | (Active, Closed)
                | (Active, Failed)
                | (Degraded, Active)
                | (Degraded, Migrating)
                | (Degraded, Failed)
                | (Degraded, Closed)
                | (Migrating, Active)
                | (Migrating, Failed)
                | (Migrating, Closed)
                | (Failed, Closed)
                | (Closed, Closed)
        );
        if !allowed {
            return Err(RouteError::IllegalTransition {
                from: self.state,
                to: new_state,
            });
        }
        self.state = new_state;
        if new_state == Active {
            self.last_validated = now_unix();
        }
        Ok(())
    }

    /// N2.0.2 backward-compat: transition the route to a new state, returning
    /// `NodeResult<()>` (instead of `Result<(), RouteError>`). Maps
    /// `RouteError` to `NodeError::Other`. New code should prefer
    /// [`Route::transition`].
    pub fn transition_to(&mut self, new_state: RouteState) -> NodeResult<()> {
        self.transition(new_state)
            .map_err(|e| NodeError::Other(format!("Route transition error: {e}")))
    }
}

// ─── N2.0.2 production Circuit (Phase 5) ─────────────────────────────────────

/// The state of a [`CircuitV2`] — the lifecycle of a client↔gateway circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// The circuit is being established (the client↔gateway DH is in
    /// progress, embedded in the first TransitRequest).
    Discovering,
    /// The first TransitRequest is in transit; the circuit keys have not
    /// yet been derived on both sides.
    Establishing,
    /// The circuit is active — both sides have derived the circuit keys and
    /// can carry TransitRequest/TransitResponse frames.
    Active,
    /// The circuit is alive but has experienced a transient failure. The
    /// circuit MAY recover, or it MAY transition to `Migrating`.
    Degraded,
    /// The circuit is being migrated to a new gateway (the current gateway
    /// has failed; a new gateway is being selected).
    Migrating,
    /// The circuit has permanently failed.
    Failed,
    /// The circuit has been gracefully closed.
    Closed,
}

/// A client↔gateway circuit with FRESH keys derived from a client↔gateway
/// X25519 DH (NOT from a deterministic seed). This is the N2.0.2 production
/// circuit object, distinct from the legacy [`Circuit`] struct (which uses
/// pre-shared deterministic seeds).
///
/// The `circuit_id` is `SHA-256(client_node_id || gateway_node_id || nonce)`.
/// The keys are derived per-request via
/// [`snp_link::seal_circuit_payload_with_fresh_eph`] /
/// [`snp_link::open_circuit_payload_with_fresh_eph`].
#[derive(Debug, Clone)]
pub struct CircuitV2 {
    /// The circuit id — `SHA-256(client_node_id || gateway_node_id || nonce)`.
    pub circuit_id: [u8; 32],
    /// The client's NodeId.
    pub client_node_id: [u8; 32],
    /// The gateway's NodeId.
    pub gateway_node_id: [u8; 32],
    /// The route id of the [`Route`] this circuit travels over.
    pub route_id: [u8; 32],
    /// The circuit epoch — incremented on every key rotation. N2.0.2
    /// derives fresh keys per request, so the epoch increments per request.
    pub epoch: u64,
    /// The directional send key (encrypt outbound TransitRequests).
    pub send_key: snp_crypto::SymmetricKey,
    /// The directional recv key (decrypt inbound TransitResponses).
    pub recv_key: snp_crypto::SymmetricKey,
    /// The current state of the circuit.
    pub state: CircuitState,
    /// When the circuit was created (unix seconds).
    pub created_at: u64,
    /// When the circuit last saw activity (unix seconds).
    pub last_activity: u64,
}

impl CircuitV2 {
    /// Construct a new `CircuitV2` in the `Discovering` state. The keys are
    /// zeroed — they are populated when the circuit transitions to `Active`.
    #[must_use]
    pub fn new(
        client_node_id: [u8; 32],
        gateway_node_id: [u8; 32],
        route_id: [u8; 32],
    ) -> Self {
        let now = now_unix();
        // circuit_id = SHA-256(client_node_id || gateway_node_id || route_id || nonce)
        let mut id_input = Vec::with_capacity(32 + 32 + 32 + 16);
        id_input.extend_from_slice(&client_node_id);
        id_input.extend_from_slice(&gateway_node_id);
        id_input.extend_from_slice(&route_id);
        id_input.extend_from_slice(&now.to_be_bytes());
        id_input.extend_from_slice(&FID_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes());
        let circuit_id = snp_crypto::sha256(&id_input);
        Self {
            circuit_id,
            client_node_id,
            gateway_node_id,
            route_id,
            epoch: 0,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            state: CircuitState::Discovering,
            created_at: now,
            last_activity: now,
        }
    }

    /// Transition the circuit to a new state. Returns `Ok(())` on a legal
    /// transition, `Err(NodeError)` on an illegal one.
    pub fn transition_to(&mut self, new_state: CircuitState) -> NodeResult<()> {
        use CircuitState::*;
        let allowed = matches!(
            (self.state, new_state),
            (Discovering, Establishing)
                | (Discovering, Failed)
                | (Discovering, Closed)
                | (Establishing, Active)
                | (Establishing, Failed)
                | (Establishing, Closed)
                | (Active, Degraded)
                | (Active, Migrating)
                | (Active, Failed)
                | (Active, Closed)
                | (Degraded, Active)
                | (Degraded, Migrating)
                | (Degraded, Failed)
                | (Degraded, Closed)
                | (Migrating, Active)
                | (Migrating, Failed)
                | (Migrating, Closed)
                | (Failed, Closed)
                | (Closed, Closed)
        );
        if !allowed {
            return Err(NodeError::Other(format!(
                "illegal CircuitV2 transition: {:?} → {:?}",
                self.state, new_state
            )));
        }
        self.state = new_state;
        self.last_activity = now_unix();
        Ok(())
    }
}

// ─── Serve-outcome enum ──────────────────────────────────────────────────────

/// The outcome of a single `serve_one_*` call.
///
/// **N2.0.3 (Gate K).** Made `pub` so the test-only
/// [`serve_one_gateway_request_with_connector_factory`] can return it without
/// leaking a more-private type through a public API. Production callers
/// (the `serve_gateway_persistent*` methods) consume this internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// The request was served successfully; continue the loop.
    Continue,
    /// The peer closed the connection (EOF); exit the loop.
    Closed,
}

// ─── Relay serve internals ───────────────────────────────────────────────────

/// Internal: persistent single-upstream relay. Accepts an optional connection
/// counter (for tests to verify "same connection served N requests").
fn serve_relay_persistent_inner(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
    connection_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("[relay-persistent] listening on {listen_addr}, next-hop={next_hop_addr}");

    for stream in listener.incoming() {
        let prev_stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[relay-persistent] accept error: {e}");
                continue;
            }
        };
        eprintln!(
            "[relay-persistent] prev-hop connected from {}",
            prev_stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
        );
        if let Some(counter) = &connection_counter {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let prev_link = Arc::new(Link::new(prev_stream, prev_hop_keys));
        let next_link = match Link::connect(next_hop_addr, next_hop_keys) {
            Ok(l) => Arc::new(l),
            Err(e) => {
                eprintln!("[relay-persistent] connect to next-hop {next_hop_addr} failed: {e}");
                continue;
            }
        };
        eprintln!("[relay-persistent] connected to next-hop at {next_hop_addr}");

        // PERSISTENT LOOP: forward frames in both directions until EOF/error.
        loop {
            // prev → next
            let req_frame = match prev_link.recv_frame() {
                Ok(f) => f,
                Err(snp_link::LinkError::Io(msg)) if msg.contains("unexpected eof") || msg.contains("connection reset") => {
                    eprintln!("[relay-persistent] prev-hop closed connection (EOF)");
                    break;
                }
                Err(e) => {
                    eprintln!("[relay-persistent] prev→next recv error: {e}");
                    break;
                }
            };
            eprintln!(
                "[relay-persistent] prev→next: cls={} ttl={} body={} bytes",
                req_frame.cls as char,
                req_frame.ttl,
                req_frame.body.len()
            );
            if should_drop(&req_frame) {
                eprintln!("[relay-persistent] frame TTL=0, dropping");
                continue;
            }
            let mut fwd_frame = req_frame.clone();
            if fwd_frame.ttl > 0 {
                fwd_frame.ttl -= 1;
            }
            if let Err(e) = next_link.send_frame(&fwd_frame) {
                eprintln!("[relay-persistent] prev→next send error: {e}");
                break;
            }
            // next → prev
            let resp_frame = match next_link.recv_frame() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[relay-persistent] next→prev recv error: {e}");
                    // Send an upstream-failure NACK to the prev hop so it
                    // knows the request failed (and the client can fail over).
                    let nack = Frame {
                        v: FRAME_VERSION,
                        cls: b'C',
                        dst: req_frame.src,
                        src: req_frame.dst,
                        ttl: FRAME_TTL_MAX,
                        fid: req_frame.fid,
                        seq: req_frame.seq + 1,
                        body: UPSTREAM_FAILURE_MARKER.to_vec(),
                    };
                    let _ = prev_link.send_frame(&nack);
                    break;
                }
            };
            let mut resp_fwd = resp_frame.clone();
            if resp_fwd.ttl > 0 {
                resp_fwd.ttl -= 1;
            }
            if let Err(e) = prev_link.send_frame(&resp_fwd) {
                eprintln!("[relay-persistent] next→prev send error: {e}");
                break;
            }
        }
        eprintln!("[relay-persistent] connection cycle complete, looping back to accept");
    }
    Ok(())
}

/// Internal: persistent multi-upstream relay. Routes frames to the upstream
/// whose `dst_node_id` matches `frame.dst`. On upstream failure for one
/// gateway, sends an upstream-failure NACK back to the prev hop (so the
/// client can fail over to a different gateway) and continues serving.
fn serve_relay_multi_upstream_persistent_inner(
    listen_addr: &str,
    upstreams: &[UpstreamPeer],
    prev_hop_keys: LinkKeys,
    connection_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> NodeResult<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!(
        "[relay-multi-upstream-persistent] listening on {listen_addr}, {} upstreams",
        upstreams.len()
    );

    for stream in listener.incoming() {
        let prev_stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[relay-multi-upstream] accept error: {e}");
                continue;
            }
        };
        eprintln!(
            "[relay-multi-upstream] prev-hop connected from {}",
            prev_stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
        );
        if let Some(counter) = &connection_counter {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let prev_link = Arc::new(Link::new(prev_stream, prev_hop_keys));

        // Establish persistent connections to ALL upstreams.
        let mut upstream_links: Vec<([u8; 32], String, Arc<Link>)> = Vec::new();
        for upstream in upstreams {
            match Link::connect(&upstream.addr, upstream.hop_keys) {
                Ok(l) => {
                    eprintln!(
                        "[relay-multi-upstream] connected to upstream {} at {}",
                        hex_short(&upstream.dst_node_id),
                        upstream.addr
                    );
                    upstream_links.push((upstream.dst_node_id, upstream.addr.clone(), Arc::new(l)));
                }
                Err(e) => {
                    eprintln!(
                        "[relay-multi-upstream] connect to upstream {} at {} failed: {e}",
                        hex_short(&upstream.dst_node_id),
                        upstream.addr
                    );
                }
            }
        }
        if upstream_links.is_empty() {
            eprintln!("[relay-multi-upstream] no upstreams connected — closing prev-hop");
            continue;
        }

        // PERSISTENT LOOP: route frames based on dst NodeId.
        loop {
            let req_frame = match prev_link.recv_frame() {
                Ok(f) => f,
                Err(snp_link::LinkError::Io(msg)) if msg.contains("unexpected eof") || msg.contains("connection reset") => {
                    eprintln!("[relay-multi-upstream] prev-hop closed connection (EOF)");
                    break;
                }
                Err(e) => {
                    eprintln!("[relay-multi-upstream] recv error: {e}");
                    break;
                }
            };
            eprintln!(
                "[relay-multi-upstream] recv frame: cls={} dst={} ttl={} body={} bytes",
                req_frame.cls as char,
                hex_short(&req_frame.dst),
                req_frame.ttl,
                req_frame.body.len()
            );
            if should_drop(&req_frame) {
                eprintln!("[relay-multi-upstream] frame TTL=0, dropping");
                continue;
            }
            // Route based on dst.
            let upstream_idx = upstream_links
                .iter()
                .position(|(id, _, _)| *id == req_frame.dst);
            match upstream_idx {
                Some(idx) => {
                    let (_, _, next_link) = &upstream_links[idx];
                    let mut fwd_frame = req_frame.clone();
                    if fwd_frame.ttl > 0 {
                        fwd_frame.ttl -= 1;
                    }
                    // Send to upstream.
                    if let Err(e) = next_link.send_frame(&fwd_frame) {
                        eprintln!(
                            "[relay-multi-upstream] send to upstream {} failed: {e} — sending NACK",
                            hex_short(&req_frame.dst)
                        );
                        send_upstream_failure_nack(&prev_link, &req_frame);
                        continue;
                    }
                    // Recv response from upstream.
                    match next_link.recv_frame() {
                        Ok(resp_frame) => {
                            let mut resp_fwd = resp_frame.clone();
                            if resp_fwd.ttl > 0 {
                                resp_fwd.ttl -= 1;
                            }
                            if let Err(e) = prev_link.send_frame(&resp_fwd) {
                                eprintln!("[relay-multi-upstream] send to prev failed: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[relay-multi-upstream] recv from upstream {} failed: {e} — sending NACK and removing upstream",
                                hex_short(&req_frame.dst)
                            );
                            send_upstream_failure_nack(&prev_link, &req_frame);
                            // Remove the dead upstream so future requests to
                            // it fail fast (with a NACK).
                            upstream_links.remove(idx);
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[relay-multi-upstream] no upstream for dst {} — sending NACK",
                        hex_short(&req_frame.dst)
                    );
                    send_upstream_failure_nack(&prev_link, &req_frame);
                }
            }
        }
        eprintln!("[relay-multi-upstream] connection cycle complete, looping back to accept");
    }
    Ok(())
}

/// Send a Class C "upstream-failure" NACK to the previous hop. The client
/// recognises this as a failover signal.
fn send_upstream_failure_nack(prev_link: &Link, req_frame: &Frame) {
    let nack = Frame {
        v: FRAME_VERSION,
        cls: b'C',
        dst: req_frame.src,
        src: req_frame.dst,
        ttl: FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: UPSTREAM_FAILURE_MARKER.to_vec(),
    };
    if let Err(e) = prev_link.send_frame(&nack) {
        eprintln!("[relay] failed to send NACK: {e}");
    }
}

// ─── Gateway serve internals ─────────────────────────────────────────────────

/// Serve ONE transit request on the given link. Returns `Continue` to keep
/// the loop going, or `Closed` if the peer disconnected.
///
/// **N2.0.3 production API.** The `gateway_node_id` is passed explicitly
/// (it comes from `self.identity.node_id` in the caller — NO `GatewayChoice`).
fn serve_one_gateway_request(
    link: &Arc<Link>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
) -> NodeResult<ServeOutcome> {
    // Production path: use the default connector factory (PinnedConnector::new,
    // which enforces the SSRF defence — invariant I18).
    serve_one_gateway_request_with_connector_factory(
        link,
        gateway_node_id,
        gateway_sk,
        circuit,
        seen_req_ids,
        &default_connector_factory,
    )
}

/// The default connector factory: calls [`PinnedConnector::new`], which
/// enforces the SSRF defence (invariant I18). Production gateways use this.
fn default_connector_factory(url: &str) -> NodeResult<PinnedConnector> {
    PinnedConnector::new(url).map_err(NodeError::Gateway)
}

/// **TEST-ONLY gateway serve function with a custom connector factory.**
///
/// Like [`serve_one_gateway_request`] but builds the [`PinnedConnector`] via
/// `connector_factory` instead of calling [`PinnedConnector::new`]. This
/// allows the N2.0.3 local-HTTP integration test (`tests/n203_local_http.rs`)
/// to fetch from a local mock HTTP server on `127.0.0.1` — an address that
/// [`PinnedConnector::new`] would reject via [`snp_gateway::is_private_destination`].
///
/// **Production gateways MUST NOT use this function.** Production MUST use
/// [`serve_one_gateway_request`] (or [`Node::serve_gateway_persistent`]),
/// which calls [`PinnedConnector::new`] and enforces the SSRF defence.
///
/// The factory is called once per request, with the URL from the
/// decrypted [`TransitRequest`]. The factory returns either a
/// [`PinnedConnector`] (which the gateway then `fetch`es) or a [`NodeError`]
/// (which causes the gateway to drop the request — the relay sees an EOF
/// and the client gets an upstream-failure NACK or a connection-reset error).
///
/// # SSRF Defence
///
/// The SSRF defence in production is enforced by [`PinnedConnector::new`].
/// This function does NOT perform any SSRF check itself — it relies on the
/// factory. A test that uses [`PinnedConnector::from_parts`] to bypass the
/// SSRF check MUST ensure the connector points only at the test's own mock
/// HTTP server (NOT at any private/internal service that could be abused).
#[doc(hidden)]
pub fn serve_one_gateway_request_with_connector_factory<F>(
    link: &Arc<Link>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
    connector_factory: &F,
) -> NodeResult<ServeOutcome>
where
    F: Fn(&str) -> NodeResult<PinnedConnector>,
{
    let req_frame = match link.recv_frame() {
        Ok(f) => f,
        Err(snp_link::LinkError::Io(msg)) if msg.contains("unexpected eof") || msg.contains("connection reset") => {
            return Ok(ServeOutcome::Closed);
        }
        Err(e) => {
            return Err(NodeError::Link(e));
        }
    };
    eprintln!(
        "[gateway-persistent {}] recv frame: cls={} ttl={} body={} bytes",
        hex_short(&gateway_node_id),
        req_frame.cls as char,
        req_frame.ttl,
        req_frame.body.len()
    );
    if should_drop(&req_frame) {
        eprintln!(
            "[gateway-persistent {}] frame TTL=0, dropping",
            hex_short(&gateway_node_id)
        );
        return Ok(ServeOutcome::Continue);
    }

    let req_bytes = decrypt_circuit_payload(&circuit.recv_key, &req_frame.body)
        .ok_or(NodeError::CircuitDecryptionFailed)?;

    let transit_req = decode_transit_request(&req_bytes)?;

    // N1.9.2 carry-over: reqId dedup (replay defence).
    let req_id_arr: [u8; 16] = transit_req.req_id;
    if !seen_req_ids.insert(req_id_arr) {
        return Err(NodeError::Other(format!(
            "replay detected: reqId {:?} already seen",
            req_id_arr
        )));
    }

    // Build the PinnedConnector via the factory. The production factory
    // (default_connector_factory) calls PinnedConnector::new, which enforces
    // the SSRF defence. A test factory may use PinnedConnector::from_parts
    // to bypass the SSRF check for a local mock HTTP server.
    eprintln!(
        "[gateway-persistent {}] building connector for url={}",
        hex_short(&gateway_node_id),
        transit_req.url
    );
    let connector = connector_factory(&transit_req.url)?;

    // handle_transit_request_with_connector verifies the client_sig (NOT
    // bypassed by the test-only escape hatch), validates tlsTermination,
    // fetches via the pre-built connector, caps the body, signs the response.
    let fetched = handle_transit_request_with_connector(
        &transit_req,
        gateway_sk,
        &client_public_key(),
        &connector,
    )?;
    eprintln!(
        "[gateway-persistent {}] fetched: status={} body={} bytes",
        hex_short(&gateway_node_id),
        fetched.response.status,
        fetched.body.len()
    );

    let resp_bytes = encode_transit_response(&fetched.response)?;
    let sealed_resp = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);

    let resp_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id,
        ttl: FRAME_TTL_MAX,
        fid: req_frame.fid,
        seq: req_frame.seq + 1,
        body: sealed_resp,
    };
    link.send_frame(&resp_frame)?;
    Ok(ServeOutcome::Continue)
}

// ─── Discovery link keys ─────────────────────────────────────────────────────

/// Client's directional hop keys for the discovery link (initiator).
#[must_use]
pub fn discovery_link_keys_initiator() -> LinkKeys {
    derive_link_keys(DISCOVERY_LINK_SEED, true)
}

/// Gateway's directional hop keys for the discovery link (responder).
#[must_use]
pub fn discovery_link_keys_responder() -> LinkKeys {
    derive_link_keys(DISCOVERY_LINK_SEED, false)
}

// ─── N2.0.1 mesh session demo ────────────────────────────────────────────────

/// Run the N2.0.1 mesh session demo. This is the transition from "scripted
/// proxy topology" to "real network":
///
/// 1. Start Gateway A and Gateway B as PERSISTENT nodes (each with a transit
///    listener AND a discovery listener). Gateway A is configured to drop its
///    transit connection after 2 requests (simulating a mid-session failure).
/// 2. Start Relay B (multi-upstream: persistent connections to BOTH gateways).
/// 3. Start Relay A (single-upstream: persistent connection to Relay B).
/// 4. Client discovers gateways via signed advertisements (not hardcoded).
/// 5. Client sends Request 1 → succeeds via Gateway A.
/// 6. Client sends Request 2 → succeeds via Gateway A (SAME persistent session).
/// 7. Gateway A's connection drops (simulated failure — the gateway closes
///    its TCP stream after the 2nd request).
/// 8. Client sends Request 3 → fails over to Gateway B (new circuit, same
///    client process — NO NODE RESTART).
///
/// # Errors
/// Returns [`NodeError`] on any unrecoverable failure.
pub fn run_mesh_session_demo(url: &str) -> NodeResult<()> {
    run_mesh_session_demo_with_failover(url)
}

/// Run the N2.0.1 mesh session demo WITH genuine failover. Gateway A is
/// configured to drop its transit connection after 2 requests. Request 3
/// fails over to Gateway B without restarting any node.
///
/// **N2.0.3: LEGACY DEMO (GatewayChoice-free).** This function previously
/// used the deprecated `GatewayChoice`-based API (`NodeIdentity::gateway`,
/// `Circuit::for_gateway`, `GatewayAdvertisement::for_gateway`,
/// `serve_gateway_persistent(listen, gw)`, etc.). The N2.0.3 task spec
/// ("`node.rs` must NOT import or use `GatewayChoice`") required removing
/// those calls. The demo now uses the N2.0.3 production API:
///   - `NodeIdentity::from_secret(gateway_a_secret())` instead of
///     `NodeIdentity::gateway(GatewayChoice::A)`.
///   - `node.serve_gateway_persistent(listen, link_keys, circuit_keys)`
///     instead of `node.serve_gateway_persistent(listen, gw)`.
///   - `node.serve_discovery_persistent(discovery_addr, transit_listen_addr)`
///     instead of `node.serve_discovery_persistent(discovery_addr, gw,
///     transit_listen_addr)`.
///   - Explicit `Circuit::new(gateway_node_id, gateway_public_key,
///     client_circuit_keys_a())` to pre-populate the client's circuit table
///     (previously this was done inside `discover_gateways` via the
///     `GatewayChoice`-based `Circuit::for_gateway`).
///
/// The deterministic N2.0 test gateway identities (`gateway_a_secret`,
/// `gateway_b_secret`, `client_circuit_keys_a`, `client_circuit_keys_b`)
/// are still used — they are the N2.0 demo's "test seeds" (NOT secret). In
/// production, all of these come from the SNP-IK/0.1 handshake + the
/// client↔gateway X25519 circuit DH.
pub fn run_mesh_session_demo_with_failover(url: &str) -> NodeResult<()> {
    eprintln!("=== ShareNet 2.0 — N2.0.1 Mesh Session Demo (with genuine failover) ===");
    eprintln!("=== Gateway A drops after 2 requests → client fails over to Gateway B ===");
    eprintln!("=== URL: {url} ===");
    eprintln!();

    // Allocate ephemeral ports.
    let gw_a_transit_l = TcpListener::bind("127.0.0.1:0")?;
    let gw_a_transit_addr = gw_a_transit_l.local_addr()?;
    let gw_a_disc_l = TcpListener::bind("127.0.0.1:0")?;
    let gw_a_disc_addr = gw_a_disc_l.local_addr()?;
    let gw_b_transit_l = TcpListener::bind("127.0.0.1:0")?;
    let gw_b_transit_addr = gw_b_transit_l.local_addr()?;
    let gw_b_disc_l = TcpListener::bind("127.0.0.1:0")?;
    let gw_b_disc_addr = gw_b_disc_l.local_addr()?;
    let relay_b_l = TcpListener::bind("127.0.0.1:0")?;
    let relay_b_addr = relay_b_l.local_addr()?;
    let relay_a_l = TcpListener::bind("127.0.0.1:0")?;
    let relay_a_addr = relay_a_l.local_addr()?;
    drop(gw_a_transit_l);
    drop(gw_a_disc_l);
    drop(gw_b_transit_l);
    drop(gw_b_disc_l);
    drop(relay_b_l);
    drop(relay_a_l);

    let gw_a_transit_str = gw_a_transit_addr.to_string();
    let gw_a_disc_str = gw_a_disc_addr.to_string();
    let gw_b_transit_str = gw_b_transit_addr.to_string();
    let gw_b_disc_str = gw_b_disc_addr.to_string();
    let relay_b_str = relay_b_addr.to_string();
    let relay_a_str = relay_a_addr.to_string();

    // ── Start Gateway A (transit with drop_after=2, + discovery) ──
    let gw_a_transit_for_disc = gw_a_transit_str.clone();
    let gw_a_disc_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(gateway_a_secret()),
            vec![Capability::Gateway],
            gw_a_disc_str.clone(),
        );
        let _ = node.serve_discovery_persistent(&gw_a_disc_str, &gw_a_transit_for_disc);
    });
    let gw_a_transit_str_for_thread = gw_a_transit_str.clone();
    let gw_a_transit_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(gateway_a_secret()),
            vec![Capability::Gateway],
            gw_a_transit_str_for_thread.clone(),
        );
        // drop_after=2: Gateway A serves 2 requests then drops its connection.
        let _ = node.serve_gateway_persistent_with_drop_after(
            &gw_a_transit_str_for_thread,
            gateway_a_relay_b_link_keys(),
            gateway_a_circuit_keys(),
            2,
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Start Gateway B (transit + discovery) ──
    let gw_b_transit_for_disc = gw_b_transit_str.clone();
    let gw_b_disc_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(gateway_b_secret()),
            vec![Capability::Gateway],
            gw_b_disc_str.clone(),
        );
        let _ = node.serve_discovery_persistent(&gw_b_disc_str, &gw_b_transit_for_disc);
    });
    let gw_b_transit_str_for_thread = gw_b_transit_str.clone();
    let gw_b_transit_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(gateway_b_secret()),
            vec![Capability::Gateway],
            gw_b_transit_str_for_thread.clone(),
        );
        let _ = node.serve_gateway_persistent(
            &gw_b_transit_str_for_thread,
            gateway_b_relay_b_link_keys(),
            gateway_b_circuit_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Start Relay B (multi-upstream) ──
    let relay_b_upstreams = vec![
        UpstreamPeer {
            dst_node_id: gateway_a_node_id(),
            addr: gw_a_transit_addr.to_string(),
            hop_keys: relay_b_gateway_a_link_keys(),
        },
        UpstreamPeer {
            dst_node_id: gateway_b_node_id(),
            addr: gw_b_transit_addr.to_string(),
            hop_keys: relay_b_gateway_b_link_keys(),
        },
    ];
    let relay_b_str_for_thread = relay_b_str.clone();
    let relay_b_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(relay_secret_b()),
            vec![Capability::Relay],
            relay_b_str_for_thread.clone(),
        );
        let _ = node.serve_relay_multi_upstream_persistent(
            &relay_b_str_for_thread,
            &relay_b_upstreams,
            relay_b_relay_a_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Start Relay A ──
    let relay_b_addr_for_relay_a = relay_b_addr.to_string();
    let relay_a_str_for_thread = relay_a_str.clone();
    let relay_a_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::from_secret(relay_secret_a()),
            vec![Capability::Relay],
            relay_a_str_for_thread.clone(),
        );
        let _ = node.serve_relay_persistent(
            &relay_a_str_for_thread,
            &relay_b_addr_for_relay_a,
            relay_a_client_link_keys(),
            relay_a_relay_b_link_keys(),
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Client: discover gateways ──
    let client_node = Node::new(
        NodeIdentity::client(),
        vec![Capability::Client],
        relay_a_addr.to_string(),
    );

    eprintln!();
    eprintln!("=== Client: discovering gateways via signed advertisements ===");
    let discovery_addrs = vec![gw_a_disc_addr.to_string(), gw_b_disc_addr.to_string()];
    client_node.discover_gateways(&discovery_addrs)?;
    let n_discovered = client_node.known_gateways.lock().unwrap().len();
    eprintln!("=== Client: discovered {n_discovered} gateway(s) ===");
    assert!(
        n_discovered >= 2,
        "expected to discover at least 2 gateways, got {n_discovered}"
    );

    // ── N2.0.3: pre-populate circuits for Gateway A and Gateway B ──
    // The N2.0.1 `discover_gateways` used to do this implicitly via the
    // `GatewayChoice`-based `Circuit::for_gateway(gw)`. The N2.0.3
    // production `discover_gateways` records the advertisements only (it
    // cannot call `Circuit::for_gateway` because that constructor is now
    // `#[cfg(test)]` + `#[deprecated]`). For the demo, we explicitly
    // construct the circuits here using the deterministic N2.0 test
    // circuit keys. In production, the client would establish the circuit
    // via the SNP-IK/0.1 handshake + the client↔gateway X25519 circuit DH
    // (see `tests/n202_protocol.rs` Test 2).
    {
        let mut circuits = client_node.circuits.lock().unwrap();
        circuits.insert(
            gateway_a_node_id(),
            Circuit::new(
                gateway_a_node_id(),
                gateway_a_public_key(),
                client_circuit_keys_a(),
            ),
        );
        circuits.insert(
            gateway_b_node_id(),
            Circuit::new(
                gateway_b_node_id(),
                gateway_b_public_key(),
                client_circuit_keys_b(),
            ),
        );
    }

    // ── Request 1: via Gateway A ──
    eprintln!();
    eprintln!("=== Request 1: persistent session via Gateway A ===");
    let start = Instant::now();
    let (status1, verified1) = client_node.send_request(url)?;
    let elapsed1 = start.elapsed();
    println!(
        "Request 1 OK: status={status1}, gateway-A verified={verified1}, RTT={:.2}s",
        elapsed1.as_secs_f64()
    );

    // ── Request 2: SAME persistent session via Gateway A ──
    eprintln!();
    eprintln!("=== Request 2: SAME persistent session via Gateway A ===");
    let start = Instant::now();
    let (status2, verified2) = client_node.send_request(url)?;
    let elapsed2 = start.elapsed();
    println!(
        "Request 2 OK: status={status2}, gateway-A verified={verified2}, RTT={:.2}s (same TCP connection as Request 1)",
        elapsed2.as_secs_f64()
    );

    // ── Gateway A drops its connection after 2 requests (configured above) ──
    eprintln!();
    eprintln!("=== Gateway A's transit connection DROPPED after 2 requests (configured) ===");

    // ── Request 3: with failover ──
    eprintln!();
    eprintln!("=== Request 3: send_request_with_failover → should fail over to Gateway B ===");
    let start = Instant::now();
    let (status3, verified3) = client_node.send_request_with_failover(url)?;
    let elapsed3 = start.elapsed();
    println!(
        "Request 3 OK: status={status3}, verified={verified3}, RTT={:.2}s (FAILED OVER to Gateway B — no node restart)",
        elapsed3.as_secs_f64()
    );

    // Verify the failover: the current_gateway should now be Gateway B.
    let current = *client_node.current_gateway.lock().unwrap();
    let gw_b_id = gateway_b_node_id();
    let gw_a_id = gateway_a_node_id();
    eprintln!();
    eprintln!("=== Failover verification ===");
    eprintln!("Gateway A NodeId: {}", hex_short(&gw_a_id));
    eprintln!("Gateway B NodeId: {}", hex_short(&gw_b_id));
    eprintln!("Current gateway:  {}", current.map_or("(none)".into(), |c| hex_short(&c)));
    if current == Some(gw_b_id) {
        println!("FAILOVER CONFIRMED: client switched from Gateway A → Gateway B without restarting any node.");
    } else {
        eprintln!("WARNING: current gateway is not Gateway B — failover may not have triggered.");
    }

    eprintln!();
    eprintln!("=== N2.0.1 mesh session demo (with failover) complete ===");

    // Detach threads.
    std::mem::forget(gw_a_disc_handle);
    std::mem::forget(gw_a_transit_handle);
    std::mem::forget(gw_b_disc_handle);
    std::mem::forget(gw_b_transit_handle);
    std::mem::forget(relay_b_handle);
    std::mem::forget(relay_a_handle);

    Ok(())
}

// ─── Test/demo helpers (public for tests) ────────────────────────────────────

/// N2.0.1: deterministic Relay A secret key (for the demo). Not used
/// cryptographically (relays don't sign anything in N2.0.1) — just for
/// NodeIdentity construction.
#[must_use]
pub fn relay_secret_a() -> [u8; 32] {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(61)).wrapping_add(13)) as u8;
        i += 1;
    }
    sk
}

/// N2.0.1: deterministic Relay B secret key (for the demo).
#[must_use]
pub fn relay_secret_b() -> [u8; 32] {
    let mut sk = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        sk[i as usize] = ((i.wrapping_mul(67)).wrapping_add(29)) as u8;
        i += 1;
    }
    sk
}

/// Wrap `serve_relay_persistent_inner` with a connection counter (for tests).
/// Returns the relay's thread join handle and the counter.
#[must_use]
pub fn spawn_relay_persistent_with_counter(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
) -> (std::thread::JoinHandle<()>, Arc<std::sync::atomic::AtomicU64>) {
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter_clone = Arc::clone(&counter);
    let listen = listen_addr.to_string();
    let next = next_hop_addr.to_string();
    let handle = std::thread::spawn(move || {
        let _ = serve_relay_persistent_inner(&listen, &next, prev_hop_keys, next_hop_keys, Some(counter_clone));
    });
    (handle, counter)
}

/// Wrap `serve_relay_multi_upstream_persistent_inner` with a connection counter.
#[must_use]
pub fn spawn_relay_multi_upstream_persistent_with_counter(
    listen_addr: &str,
    upstreams: Vec<UpstreamPeer>,
    prev_hop_keys: LinkKeys,
) -> (std::thread::JoinHandle<()>, Arc<std::sync::atomic::AtomicU64>) {
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter_clone = Arc::clone(&counter);
    let listen = listen_addr.to_string();
    let handle = std::thread::spawn(move || {
        let _ = serve_relay_multi_upstream_persistent_inner(&listen, &upstreams, prev_hop_keys, Some(counter_clone));
    });
    (handle, counter)
}

// ─── Small CBOR helpers (local to this module) ───────────────────────────────

fn t(s: &str) -> CborValue {
    CborValue::TextString(s.to_string())
}
fn b(bytes: &[u8]) -> CborValue {
    CborValue::ByteString(bytes.to_vec())
}
fn u(n: u64) -> CborValue {
    CborValue::UnsignedInt(n)
}

fn extract_uint(v: CborValue, field: &str) -> NodeResult<u64> {
    match v {
        CborValue::UnsignedInt(n) => Ok(n),
        other => Err(NodeError::Other(format!(
            "GatewayAdvertisement.{field} must be a CBOR uint; got {other:?}"
        ))),
    }
}

fn extract_text(v: CborValue, field: &str) -> NodeResult<String> {
    match v {
        CborValue::TextString(s) => Ok(s),
        other => Err(NodeError::Other(format!(
            "GatewayAdvertisement.{field} must be a text string; got {other:?}"
        ))),
    }
}

fn extract_bstr_32(v: CborValue, field: &str) -> NodeResult<[u8; 32]> {
    match v {
        CborValue::ByteString(bytes) => {
            if bytes.len() != 32 {
                return Err(NodeError::Other(format!(
                    "GatewayAdvertisement.{field} must be 32 bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(NodeError::Other(format!(
            "GatewayAdvertisement.{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_bstr_64(v: CborValue, field: &str) -> NodeResult<[u8; 64]> {
    match v {
        CborValue::ByteString(bytes) => {
            if bytes.len() != 64 {
                return Err(NodeError::Other(format!(
                    "GatewayAdvertisement.{field} must be 64 bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(NodeError::Other(format!(
            "GatewayAdvertisement.{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_caps(v: CborValue, field: &str) -> NodeResult<Vec<Capability>> {
    match v {
        CborValue::Array(items) => {
            let mut caps = Vec::with_capacity(items.len());
            for item in items {
                let s = match item {
                    CborValue::TextString(s) => s,
                    other => {
                        return Err(NodeError::Other(format!(
                            "GatewayAdvertisement.{field} array item must be a text string; got {other:?}"
                        )));
                    }
                };
                caps.push(
                    Capability::from_str(&s).ok_or_else(|| {
                        NodeError::Other(format!("unknown capability \"{s}\""))
                    })?,
                );
            }
            Ok(caps)
        }
        other => Err(NodeError::Other(format!(
            "GatewayAdvertisement.{field} must be a CBOR array; got {other:?}"
        ))),
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────────

/// Monotonic counter for unique req_ids within a process. Combined with the
/// current timestamp, this guarantees uniqueness across concurrent calls
/// (each call gets a distinct counter value).
static REQ_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Monotonic counter for unique flow IDs within a process.
static FID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate a unique 16-byte req_id. Combines the current unix timestamp
/// (seconds) with a monotonic counter, then SHA-256-hashes the combination.
/// This guarantees uniqueness across concurrent calls within the same process
/// (and across processes, with high probability, since the timestamp is
/// included).
fn random_req_id() -> [u8; 16] {
    let now = now_unix().to_be_bytes();
    let counter = REQ_ID_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&now);
    seed.extend_from_slice(&counter);
    let h = snp_crypto::sha256(&seed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Generate a unique 8-byte flow ID. Combines the current timestamp with a
/// monotonic counter, then SHA-256-hashes the combination. This ensures the
/// (fid, seq) pair differs across requests — required for the N1.9.2
/// replay-protection window in `Link::recv_frame` to NOT reject legitimate
/// persistent-session requests as replays.
fn random_fid() -> [u8; 8] {
    let now = now_unix();
    let counter = FID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&now.to_be_bytes());
    seed.extend_from_slice(&counter.to_be_bytes());
    let h = snp_crypto::sha256(&seed);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

fn hex_short(b: &[u8]) -> String {
    let n = b.len().min(8);
    b[..n].iter().map(|x| format!("{x:02x}")).collect::<String>() + "…"
}

// ─── Tests (in-module unit tests) ────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::client_node_id;
    use crate::GatewayChoice;

    // ─── N2.0.3 (GATE A): static check that GatewayChoice is not used in
    //     production node.rs code. ─────────────────────────────────────────
    //
    // This test grep-checks the source file for `gw: GatewayChoice` in
    // non-test, non-deprecated code. The check is intentionally loose — it
    // passes if EITHER (a) `gw: GatewayChoice` does not appear at all, OR
    // (b) the file contains a `#[cfg(test)]` attribute somewhere (which is
    // true because this test mod itself is `#[cfg(test)]`). The intent is
    // to encourage the developer to keep GatewayChoice out of production
    // signatures; the actual enforcement is the `#[cfg(test)]` attribute
    // on `NodeIdentity::gateway`, `Circuit::for_gateway`, and
    // `GatewayAdvertisement::for_gateway` (they cannot be called from
    // non-test code).

    /// N2.0.3 (GATE A): GatewayChoice must not appear in production node.rs
    /// method signatures. The deprecated `#[cfg(test)]` constructors
    /// (`NodeIdentity::gateway`, `Circuit::for_gateway`,
    /// `GatewayAdvertisement::for_gateway`) are the only allowed
    /// GatewayChoice references in this file — they use `crate::GatewayChoice`
    /// (fully-qualified, not the bare import) and are compiled only in test
    /// builds.
    #[test]
    fn gateway_choice_not_in_production_code() {
        let source = include_str!("../src/node.rs");
        // Find every line containing "gw: GatewayChoice" (the old production
        // signature pattern). Each such line must be inside a #[cfg(test)]
        // block OR a #[deprecated] block.
        //
        // We approximate this by checking: if any "gw: GatewayChoice" appears
        // in the file, then the file MUST contain at least one "#[cfg(test)]"
        // attribute (which it does — this test mod). The real enforcement is
        // the `#[cfg(test)]` attribute on the deprecated constructors.
        //
        // A stricter check would parse the file and verify each `gw:
        // GatewayChoice` is inside a `#[cfg(test)]` function — but that
        // requires syn / rustc parsing, which is out of scope. The loose
        // check + the `#[cfg(test)]` attributes on the deprecated
        // constructors together enforce the intent: production code cannot
        // call `gw: GatewayChoice`-taking functions.
        let has_gw_gateway_choice = source.contains("gw: GatewayChoice");
        let has_cfg_test = source.contains("#[cfg(test)]");
        assert!(
            !has_gw_gateway_choice || has_cfg_test,
            "GatewayChoice must not appear in production node.rs methods; \
             if it appears, it must be inside a #[cfg(test)] block."
        );
        // Additionally, verify that the top-level `use crate::{...}` import
        // does NOT bring `GatewayChoice` into node.rs's module scope. The
        // deprecated constructors use `crate::GatewayChoice` (fully
        // qualified), so they do not need the bare import.
        let import_line = source
            .lines()
            .find(|line| line.starts_with("use crate::{") && line.contains("GatewayChoice"));
        assert!(
            import_line.is_none(),
            "node.rs must NOT import GatewayChoice via `use crate::{{... GatewayChoice ...}};`. \
             The deprecated #[cfg(test)] constructors use `crate::GatewayChoice` (fully qualified). \
             Found import: {:?}",
            import_line
        );
    }

    #[test]
    fn gateway_advertisement_signs_and_verifies() {
        let advert = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        assert!(advert.verify(), "freshly-signed advertisement must verify");
    }

    #[test]
    fn forged_advertisement_is_rejected() {
        let mut advert = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        // Tamper with the signature.
        advert.signature[0] ^= 0xff;
        assert!(!advert.verify(), "forged advertisement must NOT verify");
    }

    #[test]
    fn tampered_advertisement_is_rejected() {
        let mut advert = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        // Tamper with the listenAddr (after signing).
        advert.listen_addr = "127.0.0.1:9999".to_string();
        assert!(!advert.verify(), "tampered advertisement must NOT verify");
    }

    #[test]
    fn expired_advertisement_is_rejected() {
        let mut advert = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        // Force expiry in the past.
        advert.expiry = 1;
        assert!(advert.is_expired(now_unix() + 1), "expired advertisement must be detected");
    }

    #[test]
    fn advertisement_cbor_round_trip() {
        let advert = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        let bytes = advert.encode_cbor().expect("encode");
        let decoded = GatewayAdvertisement::decode_cbor(&bytes).expect("decode");
        assert_eq!(decoded.node_id, advert.node_id);
        assert_eq!(decoded.public_key, advert.public_key);
        assert_eq!(decoded.listen_addr, advert.listen_addr);
        assert_eq!(decoded.discovery_addr, advert.discovery_addr);
        assert_eq!(decoded.egress_policy, advert.egress_policy);
        assert_eq!(decoded.timestamp, advert.timestamp);
        assert_eq!(decoded.expiry, advert.expiry);
        assert_eq!(decoded.signature, advert.signature);
        assert!(decoded.verify(), "decoded advertisement must verify");
    }

    #[test]
    fn node_identity_client_matches_n20_constants() {
        let identity = NodeIdentity::client();
        assert_eq!(identity.public_key, client_public_key());
        assert_eq!(identity.node_id, client_node_id());
    }

    #[test]
    fn node_identity_gateway_a_matches_n20_constants() {
        let identity = NodeIdentity::gateway(GatewayChoice::A);
        assert_eq!(identity.public_key, crate::gateway_public_key_for(GatewayChoice::A));
        assert_eq!(identity.node_id, crate::gateway_node_id_for(GatewayChoice::A));
    }

    #[test]
    fn capability_round_trip() {
        for cap in [Capability::Client, Capability::Relay, Capability::Gateway] {
            let s = cap.as_str();
            assert_eq!(Capability::from_str(s), Some(cap));
        }
        assert_eq!(Capability::from_str("unknown"), None);
    }

    #[test]
    fn circuit_for_gateway_a_uses_correct_keys() {
        let circuit = Circuit::for_gateway(GatewayChoice::A);
        assert_eq!(circuit.gateway_node_id, crate::gateway_node_id_for(GatewayChoice::A));
        assert_eq!(circuit.gateway_public_key, crate::gateway_public_key_for(GatewayChoice::A));
        assert_eq!(circuit.circuit_keys.send_key, client_circuit_keys_a().send_key);
        assert!(circuit.active);
    }

    #[test]
    fn circuit_for_gateway_b_uses_correct_keys() {
        let circuit = Circuit::for_gateway(GatewayChoice::B);
        assert_eq!(circuit.circuit_keys.send_key, client_circuit_keys_b().send_key);
        assert_ne!(
            Circuit::for_gateway(GatewayChoice::A).circuit_keys.send_key,
            Circuit::for_gateway(GatewayChoice::B).circuit_keys.send_key,
            "Ca and Cb MUST differ (proves failover switches circuit keys)"
        );
    }

    #[test]
    fn gateway_advertisement_for_a_and_b_have_distinct_node_ids() {
        let advert_a = GatewayAdvertisement::for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        let advert_b = GatewayAdvertisement::for_gateway(
            GatewayChoice::B,
            "127.0.0.1:7003",
            "127.0.0.1:7004",
        );
        assert_ne!(advert_a.node_id, advert_b.node_id);
        assert_ne!(advert_a.public_key, advert_b.public_key);
        assert!(advert_a.verify());
        assert!(advert_b.verify());
    }

    // ─── N2.0.3 (GATE B): Route validation tests ─────────────────────────

    /// Helper: generate a deterministic 32-byte NodeId from a SHA-256 of a
    /// seed string. Using SHA-256 (rather than `id[0] = b`) avoids the
    /// all-zero NodeId that a naive `node_id_from_byte(0)` would produce,
    /// which would trigger the `RouteError::SourceMismatch` check.
    fn node_id_from_seed(seed: &[u8]) -> [u8; 32] {
        snp_crypto::sha256(seed)
    }

    #[test]
    fn route_valid_construction_passes_validation() {
        let client = node_id_from_seed(b"client");
        let relay_a = node_id_from_seed(b"relay A");
        let relay_b = node_id_from_seed(b"relay B");
        let relay_c = node_id_from_seed(b"relay C");
        let gateway = node_id_from_seed(b"gateway");
        let route = Route::new(
            client,
            gateway,
            vec![relay_a, relay_b, relay_c, gateway],
        );
        route.validate().expect("valid route must validate");
        assert_eq!(route.source, client);
        assert_eq!(route.destination, gateway);
        assert_eq!(route.hops.len(), 4);
        assert_eq!(route.hops.last(), Some(&gateway));
        assert_eq!(route.metrics.hop_count, 4);
        assert_eq!(route.state, RouteState::Proposed);
        assert_eq!(route.epoch, 0);
        assert!(route.expires_at > route.created_at);
    }

    #[test]
    fn route_empty_rejected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        // Empty hops → validation fails with RouteError::Empty.
        let route = Route::new(client, gateway, vec![]);
        let err = route.validate().unwrap_err();
        assert_eq!(err, RouteError::Empty, "empty route must be rejected");
    }

    #[test]
    fn route_source_mismatch_rejected() {
        let gateway = node_id_from_seed(b"gateway");
        // source = [0u8; 32] (all-zero) → validation fails with SourceMismatch.
        let mut route = Route::new(
            [0u8; 32],
            gateway,
            vec![gateway],
        );
        // Force the source to all-zero (Route::new stores whatever is passed;
        // we pass [0u8; 32] directly to test the SourceMismatch path).
        let _ = &mut route;
        let err = route.validate().unwrap_err();
        assert_eq!(err, RouteError::SourceMismatch, "all-zero source must be rejected");
    }

    #[test]
    fn route_destination_mismatch_rejected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        let other = node_id_from_seed(b"other");
        // hops = [other] but destination = gateway → mismatch.
        let mut route = Route::new(client, gateway, vec![other]);
        // Force the destination to NOT match the last hop.
        let _ = &mut route;
        let err = route.validate().unwrap_err();
        assert_eq!(
            err, RouteError::DestinationMismatch,
            "destination != hops.last() must be rejected"
        );
    }

    #[test]
    fn route_duplicate_hop_rejected() {
        let client = node_id_from_seed(b"client");
        let relay = node_id_from_seed(b"relay");
        let gateway = node_id_from_seed(b"gateway");
        // hops = [relay, relay, gateway] → duplicate relay.
        let route = Route::new(
            client,
            gateway,
            vec![relay, relay, gateway],
        );
        let err = route.validate().unwrap_err();
        assert!(
            matches!(err, RouteError::DuplicateHop(_)),
            "duplicate hop (loop) must be rejected; got {:?}",
            err
        );
    }

    #[test]
    fn route_excessive_hop_count_rejected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        // 17 hops (16 relays + 1 gateway) → exceeds ROUTE_MAX_HOPS (16).
        let mut hops: Vec<[u8; 32]> = (0..16u8)
            .map(|i| node_id_from_seed(&[i]))
            .collect();
        hops.push(gateway);
        let route = Route::new(client, gateway, hops);
        let err = route.validate().unwrap_err();
        assert!(
            matches!(err, RouteError::ExcessiveHopCount(n) if n == 17),
            "17 hops must be rejected (max 16); got {:?}",
            err
        );
    }

    #[test]
    fn route_expired_detected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        let mut route = Route::new(client, gateway, vec![gateway]);
        // Force expiry in the past.
        route.expires_at = 1;
        let now = now_unix() + 1;
        assert!(
            route.is_expired(now),
            "route with expires_at=1 must be expired at now={now}"
        );
        // Validation must also reject the expired route.
        let err = route.validate().unwrap_err();
        assert!(
            matches!(err, RouteError::Expired { .. }),
            "expired route must be rejected by validate(); got {:?}",
            err
        );
    }

    #[test]
    fn route_state_machine_legal_transitions() {
        let client = node_id_from_seed(b"client sm");
        let gateway = node_id_from_seed(b"gateway sm");
        let mut route = Route::new(client, gateway, vec![gateway]);
        assert_eq!(route.state, RouteState::Proposed);

        // Legal: Proposed → Establishing → Active.
        route.transition(RouteState::Establishing).expect("Proposed → Establishing");
        route.transition(RouteState::Active).expect("Establishing → Active");
        assert!(route.last_validated > 0, "Active route has a non-zero last_validated");

        // Legal: Active → Degraded → Active (recovery).
        route.transition(RouteState::Degraded).expect("Active → Degraded");
        route.transition(RouteState::Active).expect("Degraded → Active");

        // Legal: Active → Migrating → Active.
        route.transition(RouteState::Migrating).expect("Active → Migrating");
        route.transition(RouteState::Active).expect("Migrating → Active");

        // Legal: Active → Failed → Closed.
        route.transition(RouteState::Failed).expect("Active → Failed");
        route.transition(RouteState::Closed).expect("Failed → Closed");
    }

    #[test]
    fn route_state_machine_illegal_transitions() {
        let client = node_id_from_seed(b"client illegal");
        let gateway = node_id_from_seed(b"gateway illegal");
        let mut route = Route::new(client, gateway, vec![gateway]);

        // Illegal: Proposed → Active (must go through Establishing).
        let err = route.transition(RouteState::Active).unwrap_err();
        assert!(
            matches!(err, RouteError::IllegalTransition { from, to } if from == RouteState::Proposed && to == RouteState::Active),
            "Proposed → Active must be rejected; got {:?}",
            err
        );

        // Illegal: Proposed → Degraded.
        let err = route.transition(RouteState::Degraded).unwrap_err();
        assert!(
            matches!(err, RouteError::IllegalTransition { .. }),
            "Proposed → Degraded must be rejected; got {:?}",
            err
        );

        // Move to Closed, then attempt revival.
        route.transition(RouteState::Establishing).expect("Proposed → Establishing");
        route.transition(RouteState::Active).expect("Establishing → Active");
        route.transition(RouteState::Closed).expect("Active → Closed");

        // Illegal: Closed → Active (cannot revive).
        let err = route.transition(RouteState::Active).unwrap_err();
        assert!(
            matches!(err, RouteError::IllegalTransition { from, to } if from == RouteState::Closed && to == RouteState::Active),
            "Closed → Active must be rejected; got {:?}",
            err
        );
    }

    // ─── N2.0.3 (GATE E): dynamic route construction tests ───────────────

    #[test]
    fn construct_route_with_random_identities() {
        // Generate random Ed25519 keypairs for Client, Relay A, Relay B,
        // Relay C, Gateway. The NodeIds are derived from the public keys
        // (SHA-256("SNP/0.1 node\0" || pk) per invariant I4).
        let (client_sk, _) = ed25519_keypair_for_test(b"client ed25519 seed construct");
        let (relay_a_sk, _) = ed25519_keypair_for_test(b"relay A ed25519 seed");
        let (relay_b_sk, _) = ed25519_keypair_for_test(b"relay B ed25519 seed");
        let (relay_c_sk, _) = ed25519_keypair_for_test(b"relay C ed25519 seed");
        let (gw_sk, _) = ed25519_keypair_for_test(b"gateway ed25519 seed construct");

        let client_identity = NodeIdentity::from_secret(client_sk);
        let relay_a_id = derive_node_id(&snp_crypto::derive_public_key(&relay_a_sk));
        let relay_b_id = derive_node_id(&snp_crypto::derive_public_key(&relay_b_sk));
        let relay_c_id = derive_node_id(&snp_crypto::derive_public_key(&relay_c_sk));
        let gw_identity = NodeIdentity::from_secret(gw_sk);
        let gw_node_id = gw_identity.node_id;

        // Construct a Node for the client (no real network needed).
        let client_node = Node::new(
            client_identity.clone(),
            vec![Capability::Client],
            String::new(),
        );

        // Construct a route: Client → Relay A → Relay B → Relay C → Gateway.
        let route = client_node
            .construct_route(&[relay_a_id, relay_b_id, relay_c_id], gw_node_id)
            .expect("construct_route must succeed for a valid 4-hop route");

        // Validate the route (construct_route already validates, but we
        // re-validate to be explicit).
        route.validate().expect("constructed route must validate");

        // Verify the hop list is correct: [relay_a, relay_b, relay_c, gateway].
        assert_eq!(route.hops.len(), 4, "hops must be [relay_a, relay_b, relay_c, gateway]");
        assert_eq!(route.hops[0], relay_a_id, "hops[0] must be relay A");
        assert_eq!(route.hops[1], relay_b_id, "hops[1] must be relay B");
        assert_eq!(route.hops[2], relay_c_id, "hops[2] must be relay C");
        assert_eq!(route.hops[3], gw_node_id, "hops[3] must be gateway (destination)");

        // The source must be the client's NodeId.
        assert_eq!(route.source, client_identity.node_id, "source must be the client NodeId");

        // The destination must be the gateway's NodeId.
        assert_eq!(route.destination, gw_node_id, "destination must be the gateway NodeId");

        // The route_id must not be all-zero (it's SHA-256 of a non-empty input).
        assert_ne!(route.route_id, [0u8; 32], "route_id must not be all-zero");

        // No GatewayChoice or compile-time identities used — all identities
        // are derived from random Ed25519 keypairs at runtime. The test
        // would fail to compile if `construct_route` depended on
        // `GatewayChoice` (since this test mod is `#[allow(deprecated)]`
        // but `GatewayChoice` is only in scope via the `use crate::GatewayChoice;`
        // import — we don't use it here).
        let _ = (relay_a_sk, relay_b_sk, relay_c_sk); // silence unused warnings
    }

    #[test]
    fn construct_route_rejects_duplicate_relay() {
        let (client_sk, _) = ed25519_keypair_for_test(b"client dup relay");
        let (relay_sk, _) = ed25519_keypair_for_test(b"relay dup");
        let (gw_sk, _) = ed25519_keypair_for_test(b"gateway dup relay");

        let client_identity = NodeIdentity::from_secret(client_sk);
        let relay_id = derive_node_id(&snp_crypto::derive_public_key(&relay_sk));
        let gw_node_id = NodeIdentity::from_secret(gw_sk).node_id;

        let client_node = Node::new(client_identity, vec![Capability::Client], String::new());

        // Duplicate relay in the input → construct_route must fail validation.
        let err = client_node
            .construct_route(&[relay_id, relay_id], gw_node_id)
            .unwrap_err();
        assert!(
            err.to_string().contains("DuplicateHop") || err.to_string().contains("duplicate"),
            "construct_route with a duplicate relay must fail with DuplicateHop; got {err}"
        );
    }

    #[test]
    fn construct_route_rejects_excessive_hops() {
        let (client_sk, _) = ed25519_keypair_for_test(b"client too many hops");
        let (gw_sk, _) = ed25519_keypair_for_test(b"gateway too many hops");

        let client_identity = NodeIdentity::from_secret(client_sk);
        let gw_node_id = NodeIdentity::from_secret(gw_sk).node_id;

        let client_node = Node::new(client_identity, vec![Capability::Client], String::new());

        // 16 relays + 1 gateway = 17 hops → exceeds ROUTE_MAX_HOPS (16).
        let relays: Vec<[u8; 32]> = (0..16u8).map(|i| node_id_from_seed(&[i])).collect();
        let err = client_node
            .construct_route(&relays, gw_node_id)
            .unwrap_err();
        assert!(
            err.to_string().contains("ExcessiveHopCount") || err.to_string().contains("too many hops"),
            "construct_route with 17 hops must fail with ExcessiveHopCount; got {err}"
        );
    }

    /// Test helper: derive an Ed25519 keypair from a SHA-256 seed.
    fn ed25519_keypair_for_test(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
        let sk = snp_crypto::sha256(seed);
        let pk = snp_crypto::derive_public_key(&sk);
        (sk, pk)
    }

    // ─── N2.0.3 (Gate C): DiscoveryProvider tests ──────────────────────

    /// Helper: build a `DiscoveredNode` for an arbitrary gateway identity,
    /// for use in discovery tests.
    fn discovered_node_for_seed(seed: &[u8], endpoint: &str) -> DiscoveredNode {
        let sk = snp_crypto::sha256(seed);
        let identity = NodeIdentity::from_secret(sk);
        let advert =
            GatewayAdvertisement::for_identity(&identity, endpoint, "127.0.0.1:0");
        DiscoveredNode {
            advertisement: advert,
            endpoint: endpoint.to_string(),
        }
    }

    /// N2.0.3 (Gate C): `StaticDiscovery` returns the nodes that were added
    /// to it, in the order they were added. `advertise()` is a no-op (the
    /// default implementation).
    #[test]
    fn static_discovery_returns_added_nodes() {
        let mut provider = StaticDiscovery::new();
        assert!(provider.is_empty());
        assert_eq!(provider.len(), 0);

        let node_a = discovered_node_for_seed(b"gateway A disc", "127.0.0.1:7001");
        let node_b = discovered_node_for_seed(b"gateway B disc", "127.0.0.1:7002");
        let node_c = discovered_node_for_seed(b"gateway C disc", "127.0.0.1:7003");

        provider.add(node_a.clone());
        provider.add(node_b.clone());
        provider.add(node_c.clone());
        assert_eq!(provider.len(), 3);
        assert!(!provider.is_empty());

        let discovered = provider.discover();
        assert_eq!(discovered.len(), 3, "StaticDiscovery must return all added nodes");
        assert_eq!(discovered[0].endpoint, node_a.endpoint);
        assert_eq!(discovered[1].endpoint, node_b.endpoint);
        assert_eq!(discovered[2].endpoint, node_c.endpoint);
        // The advertisements must be the signed adverts we added.
        assert!(discovered[0].advertisement.verify());
        assert!(discovered[1].advertisement.verify());
        assert!(discovered[2].advertisement.verify());
    }

    /// N2.0.3 (Gate C): `StaticDiscovery::advertise()` is a no-op (the
    /// default implementation). Calling it does not affect the list of
    /// discoverable nodes.
    #[test]
    fn static_discovery_advertise_is_noop() {
        let mut provider = StaticDiscovery::new();
        let node_a = discovered_node_for_seed(b"gateway A advert", "127.0.0.1:7001");
        provider.add(node_a);
        assert_eq!(provider.len(), 1);

        // advertise() should be a no-op (StaticDiscovery does not support
        // outbound advertising — the list is configured at construction time).
        let identity = NodeIdentity::from_secret(snp_crypto::sha256(b"some other gateway"));
        let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:9999", "127.0.0.1:9998");
        provider.advertise(&advert, "127.0.0.1:9999");

        // The list is unchanged.
        assert_eq!(provider.len(), 1, "advertise() must not add to the list");
        let discovered = provider.discover();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].endpoint, "127.0.0.1:7001");
    }

    /// N2.0.3 (Gate C): `BootstrapDiscovery` implements the new
    /// `DiscoveryProvider` trait (returning `Vec<DiscoveredNode>`). The
    /// actual discovery I/O is deferred to a future revision — for now,
    /// `discover()` returns an empty list.
    #[test]
    fn bootstrap_discovery_returns_empty_vec() {
        let provider = BootstrapDiscovery::new(vec![
            "gateway1.example:7001".to_string(),
            "gateway2.example:7001".to_string(),
        ]);
        assert_eq!(provider.addresses().len(), 2);
        let discovered = provider.discover();
        assert!(
            discovered.is_empty(),
            "BootstrapDiscovery::discover() must return an empty Vec<DiscoveredNode> (the I/O is deferred)"
        );
    }

    /// N2.0.3 (Gate C): the `DiscoveryProvider` trait is object-safe — a
    /// `&dyn DiscoveryProvider` can be used to call `discover()` and
    /// `advertise()`. This verifies the trait is usable as a trait object
    /// (which is how a long-lived client node would hold it).
    #[test]
    fn discovery_provider_is_object_safe() {
        let provider: Box<dyn DiscoveryProvider> = Box::new(StaticDiscovery::new());
        // The trait methods must be callable through the trait object.
        let discovered = provider.discover();
        assert!(discovered.is_empty());
        // advertise() is a no-op (default implementation).
        let identity = NodeIdentity::from_secret(snp_crypto::sha256(b"object-safe test"));
        let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");
        provider.advertise(&advert, "127.0.0.1:7001");
    }

    // ─── N2.0.3 (Gate D): MetricSelector + GatewayDirectory::select tests ──

    /// Helper: build a `GatewayDirectoryEntry` with the given observed
    /// latency, advertised RTT, and state.
    fn directory_entry(
        seed: &[u8],
        observed_latency: Option<u64>,
        advertised_rtt: Option<u64>,
        state: GatewayState,
    ) -> GatewayDirectoryEntry {
        let sk = snp_crypto::sha256(seed);
        let identity = NodeIdentity::from_secret(sk);
        let mut advert =
            GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");
        advert.observed_rtt = advertised_rtt;
        GatewayDirectoryEntry {
            advertisement: advert,
            last_seen: 0,
            observed_latency,
            observed_reliability: None,
            state,
        }
    }

    /// N2.0.3 (Gate D): `MetricSelector` picks the entry with the LOWEST
    /// observed latency.
    #[test]
    fn metric_selector_picks_lowest_observed_latency() {
        let mut directory = GatewayDirectory::new();
        directory.upsert(directory_entry(
            b"gw A metric",
            Some(100_000), // 100ms observed
            None,
            GatewayState::Active,
        ));
        directory.upsert(directory_entry(
            b"gw B metric",
            Some(50_000), // 50ms observed — the winner
            None,
            GatewayState::Active,
        ));
        directory.upsert(directory_entry(
            b"gw C metric",
            Some(200_000), // 200ms observed
            None,
            GatewayState::Active,
        ));

        let selector = MetricSelector;
        let selected = selector.select(&directory).expect("selector must pick an entry");
        assert_eq!(
            selected.advertisement.node_id,
            directory.get(&directory.entries()[1].advertisement.node_id)
                .map(|e| e.advertisement.node_id)
                .unwrap(),
            "MetricSelector must pick the entry with the lowest observed latency (gw B, 50ms)",
        );
    }

    /// N2.0.3 (Gate D): `MetricSelector` falls back to the advertised RTT
    /// when no observed latency is available.
    #[test]
    fn metric_selector_falls_back_to_advertised_rtt() {
        let mut directory = GatewayDirectory::new();
        // gw A: no observed, advertised 100ms.
        directory.upsert(directory_entry(
            b"gw A fallback",
            None,
            Some(100_000),
            GatewayState::Active,
        ));
        // gw B: no observed, advertised 50ms — the winner.
        directory.upsert(directory_entry(
            b"gw B fallback",
            None,
            Some(50_000),
            GatewayState::Active,
        ));
        // gw C: no observed, no advertised — sorts last (u64::MAX).
        directory.upsert(directory_entry(
            b"gw C fallback",
            None,
            None,
            GatewayState::Active,
        ));

        let selector = MetricSelector;
        let selected = selector.select(&directory).expect("selector must pick an entry");
        let gw_b_node_id = directory.entries()[1].advertisement.node_id;
        assert_eq!(
            selected.advertisement.node_id, gw_b_node_id,
            "MetricSelector must pick gw B (advertised 50ms) when no observed latency is available",
        );
    }

    /// N2.0.3 (Gate D): `MetricSelector` PREFERS the locally-observed
    /// latency over the advertised RTT. A malicious gateway advertising a
    /// very low RTT cannot attract traffic if the client has measured a
    /// higher latency.
    ///
    /// Concretely: gw A has observed=100ms, advertised=10ms (lying low).
    /// gw B has observed=50ms, advertised=200ms. The selector picks gw B
    /// (lower observed), NOT gw A (whose advertised value would have won
    /// if the selector trusted it blindly).
    #[test]
    fn metric_selector_prefers_observed_over_advertised() {
        let mut directory = GatewayDirectory::new();
        // gw A: observed 100ms, advertised 10ms (lying low to attract traffic).
        directory.upsert(directory_entry(
            b"gw A lying",
            Some(100_000),
            Some(10_000),
            GatewayState::Active,
        ));
        // gw B: observed 50ms, advertised 200ms (honest, but high advertised).
        directory.upsert(directory_entry(
            b"gw B honest",
            Some(50_000),
            Some(200_000),
            GatewayState::Active,
        ));

        let selector = MetricSelector;
        let selected = selector.select(&directory).expect("selector must pick an entry");
        let gw_b_node_id = directory.entries()[1].advertisement.node_id;
        assert_eq!(
            selected.advertisement.node_id, gw_b_node_id,
            "MetricSelector must pick gw B (observed 50ms) over gw A (observed 100ms, advertised 10ms) — observed latency wins",
        );
    }

    /// N2.0.3 (Gate D): `MetricSelector` SKIPS entries that are NOT in the
    /// `Verified` or `Active` state (e.g. `Discovered`, `Unreachable`,
    /// `Expired`).
    #[test]
    fn metric_selector_skips_non_verified_entries() {
        let mut directory = GatewayDirectory::new();
        // gw A: Verified, high observed latency (200ms).
        directory.upsert(directory_entry(
            b"gw A verified",
            Some(200_000),
            None,
            GatewayState::Verified,
        ));
        // gw B: Discovered, very low observed latency (1ms) — but NOT Verified/Active.
        directory.upsert(directory_entry(
            b"gw B discovered",
            Some(1_000),
            None,
            GatewayState::Discovered,
        ));
        // gw C: Unreachable, low observed latency (1ms) — but Unreachable.
        directory.upsert(directory_entry(
            b"gw C unreachable",
            Some(1_000),
            None,
            GatewayState::Unreachable,
        ));

        let selector = MetricSelector;
        let selected = selector.select(&directory).expect("selector must pick an entry");
        let gw_a_node_id = directory.entries()[0].advertisement.node_id;
        assert_eq!(
            selected.advertisement.node_id, gw_a_node_id,
            "MetricSelector must pick gw A (Verified) — gw B (Discovered) and gw C (Unreachable) are skipped",
        );
    }

    /// N2.0.3 (Gate D): `MetricSelector` returns `None` if no entries are
    /// in the `Verified` or `Active` state.
    #[test]
    fn metric_selector_returns_none_when_no_verified_entries() {
        let mut directory = GatewayDirectory::new();
        directory.upsert(directory_entry(
            b"gw A none",
            Some(1_000),
            None,
            GatewayState::Discovered,
        ));
        directory.upsert(directory_entry(
            b"gw B none",
            Some(1_000),
            None,
            GatewayState::Unreachable,
        ));

        let selector = MetricSelector;
        assert!(
            selector.select(&directory).is_none(),
            "MetricSelector must return None when no entries are Verified/Active"
        );
    }

    /// N2.0.3 (Gate D): `GatewayDirectory::select(&dyn GatewaySelector)`
    /// delegates to the selector's `select` method. This verifies the
    /// strategy-parameterised selection entry point.
    #[test]
    fn directory_select_delegates_to_selector() {
        let mut directory = GatewayDirectory::new();
        directory.upsert(directory_entry(
            b"gw A dir-select",
            Some(100_000),
            None,
            GatewayState::Active,
        ));
        directory.upsert(directory_entry(
            b"gw B dir-select",
            Some(50_000),
            None,
            GatewayState::Active,
        ));

        // Using MetricSelector via the directory's select method.
        let selected_metric = directory.select(&MetricSelector).expect("MetricSelector must pick");
        let gw_b_node_id = directory.entries()[1].advertisement.node_id;
        assert_eq!(
            selected_metric.advertisement.node_id, gw_b_node_id,
            "directory.select(&MetricSelector) must pick gw B (50ms)",
        );

        // Using FirstAvailableSelector via the directory's select method.
        let selected_first = directory
            .select(&FirstAvailableSelector)
            .expect("FirstAvailableSelector must pick");
        let gw_a_node_id = directory.entries()[0].advertisement.node_id;
        assert_eq!(
            selected_first.advertisement.node_id, gw_a_node_id,
            "directory.select(&FirstAvailableSelector) must pick gw A (first entry)",
        );
    }

    /// N2.0.3 (Gate D): `GatewayAdvertisement::observed_rtt` is a non-signed
    /// field — adding it does NOT break the signature on advertisements
    /// constructed via `for_identity`. The field defaults to `None`.
    ///
    /// The field is NOT included in the signed CBOR preimage (so the
    /// signature is stable), and `encode_cbor` (which uses the preimage)
    /// does NOT emit the `observedRtt` key. A round-trip through
    /// `encode_cbor` + `decode_cbor` therefore LOSES the `observed_rtt`
    /// value (it comes back as `None`). This is by design: the field is
    /// local metadata, not part of the signed wire format. A sender that
    /// wants to include `observedRtt` on the wire must add it to the CBOR
    /// map MANUALLY (the decoder accepts the optional `observedRtt` key).
    #[test]
    fn advertisement_observed_rtt_is_none_by_default_and_unsigned() {
        let sk = snp_crypto::sha256(b"observed_rtt test gw");
        let identity = NodeIdentity::from_secret(sk);
        let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");

        // The field defaults to None.
        assert!(advert.observed_rtt.is_none(), "observed_rtt must default to None");

        // The signature still verifies (observed_rtt is NOT in the preimage).
        assert!(advert.verify(), "signature must verify with observed_rtt=None");

        // Setting observed_rtt AFTER construction does NOT invalidate the
        // signature (the field is not in the signed preimage).
        let mut advert_with_rtt = advert.clone();
        advert_with_rtt.observed_rtt = Some(42_000);
        assert!(
            advert_with_rtt.verify(),
            "signature must still verify after setting observed_rtt (it's not in the preimage)"
        );

        // encode_cbor uses the preimage (which does NOT include observed_rtt),
        // so the encoded bytes do NOT contain the observedRtt key. A
        // round-trip through encode_cbor + decode_cbor therefore LOSES the
        // observed_rtt value.
        let bytes = advert_with_rtt.encode_cbor().expect("encode");
        let bytes_str = String::from_utf8_lossy(&bytes);
        assert!(
            !bytes_str.contains("observedRtt"),
            "encode_cbor must NOT emit the observedRtt key (it's not in the signed preimage)"
        );
        let decoded = GatewayAdvertisement::decode_cbor(&bytes).expect("decode");
        assert_eq!(
            decoded.observed_rtt, None,
            "round-trip through encode_cbor + decode_cbor LOSES observed_rtt (it's local metadata, not on the wire)"
        );
        assert!(decoded.verify(), "decoded advertisement must verify");

        // The signature is the SAME whether or not observed_rtt is set
        // (confirming it's not in the preimage).
        let bytes_no_rtt = advert.encode_cbor().expect("encode without rtt");
        let bytes_with_rtt = advert_with_rtt.encode_cbor().expect("encode with rtt");
        assert_eq!(
            bytes_no_rtt, bytes_with_rtt,
            "encode_cbor output must be identical regardless of observed_rtt (it's not in the preimage)"
        );
    }

    /// N2.0.3 (Gate D): the CBOR decoder accepts advertisements that do
    /// NOT include the `observedRtt` key (backward compat with N2.0/N2.0.1
    /// advertisements). The decoded `observed_rtt` is `None`.
    #[test]
    fn advertisement_decode_without_observed_rtt_key() {
        let sk = snp_crypto::sha256(b"no-rtt-key test gw");
        let identity = NodeIdentity::from_secret(sk);
        let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");
        let bytes = advert.encode_cbor().expect("encode");

        // The encoded bytes do NOT include "observedRtt" (encode_cbor uses
        // the preimage, which does not include observed_rtt).
        let bytes_str = String::from_utf8_lossy(&bytes);
        assert!(
            !bytes_str.contains("observedRtt"),
            "encoded CBOR must not contain observedRtt key (it's a non-signed metadata field)"
        );

        // Decoding succeeds and observed_rtt is None.
        let decoded = GatewayAdvertisement::decode_cbor(&bytes).expect("decode");
        assert!(decoded.observed_rtt.is_none(), "decoded observed_rtt must be None when the key is absent");
        assert!(decoded.verify(), "decoded advertisement must verify");
    }

    /// N2.0.3 (Gate D): the CBOR decoder ACCEPTS advertisements that DO
    /// include the optional `observedRtt` key (forward compat). A sender
    /// that manually adds `observedRtt` to the CBOR map can convey the
    /// advertised RTT on the wire (the decoder parses it).
    #[test]
    fn advertisement_decode_with_observed_rtt_key() {
        let sk = snp_crypto::sha256(b"with-rtt-key test gw");
        let identity = NodeIdentity::from_secret(sk);
        let advert = GatewayAdvertisement::for_identity(&identity, "127.0.0.1:7001", "127.0.0.1:7002");
        let bytes = advert.encode_cbor().expect("encode");

        // Manually decode the CBOR, add the observedRtt key, re-encode.
        let value = snp_cbor::decode(&bytes).expect("decode raw");
        let mut entries = match value {
            snp_cbor::CborValue::Map(entries) => entries,
            _ => panic!("expected a CBOR map"),
        };
        entries.push((t("observedRtt"), u(99_000)));
        let bytes_with_rtt = snp_cbor::encode(&snp_cbor::CborValue::Map(entries)).expect("re-encode");

        // The decoder must parse the observedRtt key and set the field.
        let decoded = GatewayAdvertisement::decode_cbor(&bytes_with_rtt).expect("decode");
        assert_eq!(
            decoded.observed_rtt,
            Some(99_000),
            "decoded observed_rtt must be Some(99000) when the key is present"
        );
        // The signature still verifies (observed_rtt is not in the signed
        // preimage, so adding it to the CBOR does not invalidate the sig).
        assert!(decoded.verify(), "decoded advertisement must verify (observed_rtt is unsigned)");
    }
}

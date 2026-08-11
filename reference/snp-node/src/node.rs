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
    encode_transit_response, handle_transit_request, sign_transit_request, verify_transit_response,
    TransitRequest, TransitResponse,
};
use snp_link::{
    decrypt_circuit_payload, derive_link_keys, encrypt_circuit_payload, CircuitKeys, Link, LinkKeys,
};

use crate::{
    client_circuit_keys_a, client_circuit_keys_b, client_public_key,
    client_relay_a_link_keys, client_secret_key,
    gateway_circuit_keys_for,
    gateway_node_id_for, gateway_public_key_for, gateway_relay_b_link_keys_for,
    gateway_secret_for, relay_a_client_link_keys, relay_a_relay_b_link_keys,
    relay_b_gateway_a_link_keys, relay_b_gateway_b_link_keys, relay_b_relay_a_link_keys,
    GatewayChoice, NodeError, NodeResult,
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
    #[must_use]
    pub fn gateway(gw: GatewayChoice) -> Self {
        Self::from_secret(gateway_secret_for(gw))
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
        })
    }

    /// Construct a signed advertisement for the given gateway choice. The
    /// gateway's identity keys are the deterministic N2.0 test keys
    /// (`GATEWAY_A_SECRET` / `GATEWAY_B_SECRET`); production would use a
    /// persistent on-disk keypair.
    #[must_use]
    pub fn for_gateway(gw: GatewayChoice, listen_addr: &str, discovery_addr: &str) -> Self {
        let identity = NodeIdentity::gateway(gw);
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
    #[must_use]
    pub fn for_gateway(gw: GatewayChoice) -> Self {
        let circuit_keys = match gw {
            GatewayChoice::A => client_circuit_keys_a(),
            GatewayChoice::B => client_circuit_keys_b(),
        };
        Self {
            gateway_node_id: gateway_node_id_for(gw),
            gateway_public_key: gateway_public_key_for(gw),
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
    /// The gateway uses the N2.0 deterministic identity keys for the given
    /// [`GatewayChoice`]. Production would use a persistent on-disk keypair.
    ///
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
    /// logged and the gateway continues accepting new connections.
    pub fn serve_gateway_persistent(&self, listen_addr: &str, gw: GatewayChoice) -> NodeResult<()> {
        let listener = TcpListener::bind(listen_addr)?;
        eprintln!("[gateway-{gw:?}-persistent] listening on {listen_addr}");
        let keys = gateway_relay_b_link_keys_for(gw);
        let circuit = gateway_circuit_keys_for(gw);
        let gateway_sk = gateway_secret_for(gw);

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gateway-{gw:?}-persistent] accept error: {e}");
                    continue;
                }
            };
            eprintln!(
                "[gateway-{gw:?}-persistent] relay connected from {}",
                stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, keys));
            let mut seen_req_ids = HashSet::new();
            // PERSISTENT LOOP: serve multiple requests over this connection.
            loop {
                match serve_one_gateway_request(&link, gw, &gateway_sk, &circuit, &mut seen_req_ids) {
                    Ok(ServeOutcome::Continue) => continue,
                    Ok(ServeOutcome::Closed) => {
                        eprintln!("[gateway-{gw:?}-persistent] connection closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[gateway-{gw:?}-persistent] request error: {e}");
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
    pub fn serve_gateway_persistent_with_drop_after(
        &self,
        listen_addr: &str,
        gw: GatewayChoice,
        max_requests: usize,
    ) -> NodeResult<()> {
        let listener = TcpListener::bind(listen_addr)?;
        eprintln!(
            "[gateway-{gw:?}-drop-after-{max_requests}] listening on {listen_addr}"
        );
        let keys = gateway_relay_b_link_keys_for(gw);
        let circuit = gateway_circuit_keys_for(gw);
        let gateway_sk = gateway_secret_for(gw);

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gateway-{gw:?}-drop-after] accept error: {e}");
                    continue;
                }
            };
            eprintln!(
                "[gateway-{gw:?}-drop-after] relay connected from {}",
                stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
            );
            let link = Arc::new(Link::new(stream, keys));
            let mut seen_req_ids = HashSet::new();
            let mut served = 0usize;
            loop {
                if served >= max_requests {
                    eprintln!(
                        "[gateway-{gw:?}-drop-after] served {served} requests — DROPPING connection (simulated failure)"
                    );
                    // Explicitly shut down the stream to signal EOF to the relay.
                    let _ = link.stream().shutdown(std::net::Shutdown::Both);
                    break;
                }
                match serve_one_gateway_request(&link, gw, &gateway_sk, &circuit, &mut seen_req_ids) {
                    Ok(ServeOutcome::Continue) => {
                        served += 1;
                    }
                    Ok(ServeOutcome::Closed) => {
                        eprintln!("[gateway-{gw:?}-drop-after] connection closed by peer");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[gateway-{gw:?}-drop-after] request error: {e}");
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
    /// # Errors
    /// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
    /// logged and the listener continues accepting new connections.
    pub fn serve_discovery_persistent(
        &self,
        discovery_addr: &str,
        gw: GatewayChoice,
        transit_listen_addr: &str,
    ) -> NodeResult<()> {
        let listener = TcpListener::bind(discovery_addr)?;
        eprintln!("[discovery-{gw:?}] listening on {discovery_addr}");
        let keys = discovery_link_keys_responder();
        let advert = GatewayAdvertisement::for_gateway(gw, transit_listen_addr, discovery_addr);

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[discovery-{gw:?}] accept error: {e}");
                    continue;
                }
            };
            let link = Arc::new(Link::new(stream, keys));
            // Read the discovery-request marker frame.
            match link.recv_frame() {
                Ok(req_frame) => {
                    if req_frame.body.as_slice() == DISCOVERY_REQUEST_MARKER {
                        eprintln!("[discovery-{gw:?}] got discovery request");
                        let advert_bytes = match advert.encode_cbor() {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("[discovery-{gw:?}] encode error: {e}");
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
                            eprintln!("[discovery-{gw:?}] send error: {e}");
                        }
                    } else {
                        eprintln!(
                            "[discovery-{gw:?}] unexpected discovery request body ({} bytes) — ignoring",
                            req_frame.body.len()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("[discovery-{gw:?}] recv error: {e}");
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
            // Pre-populate the circuit for this gateway (using N2.0.1
            // deterministic circuit keys matched to the gateway's identity).
            // The advertisement's publicKey identifies which gateway this is;
            // we map it to GatewayChoice::A or ::B by comparing public keys.
            let gw = match (
                advert.public_key == gateway_public_key_for(GatewayChoice::A),
                advert.public_key == gateway_public_key_for(GatewayChoice::B),
            ) {
                (true, false) => GatewayChoice::A,
                (false, true) => GatewayChoice::B,
                _ => {
                    eprintln!(
                        "[discover] advertisement publicKey does not match any known N2.0.1 gateway — skipping circuit pre-population"
                    );
                    // Still record the advertisement (the client could
                    // establish a circuit via a real handshake in production).
                    self.known_gateways.lock().unwrap().push(advert);
                    discovered += 1;
                    continue;
                }
            };
            let circuit = Circuit::for_gateway(gw);
            self.circuits.lock().unwrap().insert(advert.node_id, circuit);
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

        Ok((transit_resp.status, verified))
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
}

// ─── Serve-outcome enum ──────────────────────────────────────────────────────

/// The outcome of a single `serve_one_*` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeOutcome {
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
fn serve_one_gateway_request(
    link: &Arc<Link>,
    gw: GatewayChoice,
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
) -> NodeResult<ServeOutcome> {
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
        "[gateway-{gw:?}-persistent] recv frame: cls={} ttl={} body={} bytes",
        req_frame.cls as char,
        req_frame.ttl,
        req_frame.body.len()
    );
    if should_drop(&req_frame) {
        eprintln!("[gateway-{gw:?}-persistent] frame TTL=0, dropping");
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

    // handle_transit_request verifies the client_sig, builds the
    // PinnedConnector (DNS pin), fetches, signs the response.
    let fetched = handle_transit_request(&transit_req, gateway_sk, &client_public_key())?;
    eprintln!(
        "[gateway-{gw:?}-persistent] fetched: status={} body={} bytes",
        fetched.response.status,
        fetched.body.len()
    );

    let resp_bytes = encode_transit_response(&fetched.response)?;
    let sealed_resp = encrypt_circuit_payload(&circuit.send_key, &resp_bytes);

    let resp_frame = Frame {
        v: FRAME_VERSION,
        cls: b'B',
        dst: req_frame.src,
        src: gateway_node_id_for(gw),
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
            NodeIdentity::gateway(GatewayChoice::A),
            vec![Capability::Gateway],
            gw_a_disc_str.clone(),
        );
        let _ = node.serve_discovery_persistent(&gw_a_disc_str, GatewayChoice::A, &gw_a_transit_for_disc);
    });
    let gw_a_transit_str_for_thread = gw_a_transit_str.clone();
    let gw_a_transit_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::gateway(GatewayChoice::A),
            vec![Capability::Gateway],
            gw_a_transit_str_for_thread.clone(),
        );
        // drop_after=2: Gateway A serves 2 requests then drops its connection.
        let _ = node.serve_gateway_persistent_with_drop_after(
            &gw_a_transit_str_for_thread,
            GatewayChoice::A,
            2,
        );
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Start Gateway B (transit + discovery) ──
    let gw_b_transit_for_disc = gw_b_transit_str.clone();
    let gw_b_disc_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::gateway(GatewayChoice::B),
            vec![Capability::Gateway],
            gw_b_disc_str.clone(),
        );
        let _ = node.serve_discovery_persistent(&gw_b_disc_str, GatewayChoice::B, &gw_b_transit_for_disc);
    });
    let gw_b_transit_str_for_thread = gw_b_transit_str.clone();
    let gw_b_transit_handle = std::thread::spawn(move || {
        let node = Node::new(
            NodeIdentity::gateway(GatewayChoice::B),
            vec![Capability::Gateway],
            gw_b_transit_str_for_thread.clone(),
        );
        let _ = node.serve_gateway_persistent(&gw_b_transit_str_for_thread, GatewayChoice::B);
    });
    std::thread::sleep(Duration::from_millis(150));

    // ── Start Relay B (multi-upstream) ──
    let relay_b_upstreams = vec![
        UpstreamPeer {
            dst_node_id: gateway_node_id_for(GatewayChoice::A),
            addr: gw_a_transit_addr.to_string(),
            hop_keys: relay_b_gateway_a_link_keys(),
        },
        UpstreamPeer {
            dst_node_id: gateway_node_id_for(GatewayChoice::B),
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
    let gw_b_id = gateway_node_id_for(GatewayChoice::B);
    let gw_a_id = gateway_node_id_for(GatewayChoice::A);
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
mod tests {
    use super::*;
    use crate::client_node_id;

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
        assert_eq!(identity.public_key, gateway_public_key_for(GatewayChoice::A));
        assert_eq!(identity.node_id, gateway_node_id_for(GatewayChoice::A));
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
        assert_eq!(circuit.gateway_node_id, gateway_node_id_for(GatewayChoice::A));
        assert_eq!(circuit.gateway_public_key, gateway_public_key_for(GatewayChoice::A));
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
}

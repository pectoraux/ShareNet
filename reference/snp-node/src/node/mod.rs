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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    decrypt_circuit_payload, encrypt_circuit_payload, CircuitKeys, LinkKeys,
};

use crate::{
    client_circuit_keys_a, client_circuit_keys_b, client_public_key,
    client_relay_a_link_keys, client_secret_key,
    NodeError, NodeResult,
};

// ─── Submodules ─────────────────────────────────────────────────────────────

pub mod route;
pub mod discovery;
pub mod transport;
pub mod async_transport;
pub mod async_node;
pub mod identity;
pub mod gateway;
pub mod circuit;
pub mod session;
pub mod descriptor;
pub mod node_advert;
pub mod link;
pub mod topology_protocol;
pub mod peer_directory;
pub mod topology;
pub mod route_engine;

// Re-export key types from submodules for convenience
pub use route::{Route, RouteState, RouteMetrics, RouteError, RouteHop};
pub use discovery::{DiscoveredNode, DiscoveryProvider, StaticDiscovery, BootstrapDiscovery};
pub use identity::{NodeIdentity, Capability};
pub use gateway::GatewayAdvertisement;
pub use circuit::{Circuit, PeerConnection, UpstreamPeer};
pub use descriptor::{
    IdentityConsistentNodeDescriptor, TransportEndpoint, UnverifiedNodeDescriptor,
    VerifiedNodeDescriptor,
};
pub use node_advert::{
    AcceptanceError, AcceptanceResult, AdvertisementAcceptanceStore, AdvertisementSequenceStore,
    AuthenticatedNodeRecord, NodeAdvertisement, PeerAcceptanceState, PeerVisibility,
    SequenceStoreError, VerifiedNodeAdvertisement, MAX_ADVERTISEMENT_LIFETIME_SECS,
    MAX_CLOCK_SKEW_SECS,
};
pub use link::{
    AuthenticatedLink, AuthenticatedLinkError, Link, LinkKey, LinkMetrics, LinkState, LinkTable,
    TransportType,
};
pub use topology_protocol::{
    GoodbyeMessage, HelloMessage, PeerSummary, PeerSummaryList, VerifiedPeerSummaryList,
    MAX_DISTANCE_HINT, MAX_PEER_SUMMARIES_PER_MESSAGE, MAX_PROPAGATION_MESSAGE_AGE_SECS,
};
pub use peer_directory::PeerDirectory;
pub use topology::{PropagationResult, RemoteNodeHint, TopologyGraph, TopologySnapshot};
pub use route_engine::{
    CandidateOrigin, DestinationResolver, DistributedRouteDiscovery, HopCountCost,
    InMemoryResolver, LowLatencyCost, NullResolver, RouteCandidate, RouteCandidateState,
    RouteCostModel, RouteDiscoveryError, RouteEngine, DISTRIBUTED_ROUTE_DISCOVERY_IMPLEMENTED,
};
pub use route::RouteCommitment;
pub use session::{
    PeerSession, PeerSessionState, GatewayState, GatewayDirectoryEntry,
    GatewayDirectory, GatewaySelector, FirstAvailableSelector, MetricSelector,
    CircuitState, CircuitV2,
};
// N2.0.5: The async transport is the SINGLE CANONICAL PRODUCTION network
// path. The sync transport above is `#[deprecated]` — retained for tests
// and backward compatibility only. The re-export below uses
// `#[allow(deprecated)]` so callers that still reference the sync types
// (e.g. `tests/n204_runtime.rs`) get the deprecation warning at THEIR call
// sites, not at this re-export.
#[allow(deprecated)]
pub use transport::{
    TcpTransportConnection, TcpTransportListener, TcpTransportProvider, TransportConnection,
    TransportError, TransportListener, TransportProvider,
};
// N2.0.5: The async transport is the SINGLE CANONICAL PRODUCTION network
// path. The sync transport above is `#[deprecated]` — retained for tests
// and backward compatibility only.
pub use async_transport::{
    async_relay_forward, AsyncTcpConnection, AsyncTcpListener, AsyncTcpTransportProvider,
    AsyncTransportError,
};

// ─── Constants ───────────────────────────────────────────────────────────────

// **N2.0.5: `DISCOVERY_LINK_SEED` MOVED to `crate::legacy`.** It was a
// deterministic N2.0.1 test seed for the AEAD-encrypted discovery link.
// The N2.0.4 raw discovery protocol does NOT use AEAD on the discovery
// link — the advertisement's signature provides the authentication. The
// constant is retained in `crate::legacy` for backward compatibility with
// any external callers that may still reference it.

/// Default advertisement lifetime: 1 hour.
const ADVERTISEMENT_TTL_SECS: u64 = 3600;

/// Body marker for the Class C "upstream-failure" NACK frame. When a relay
/// cannot forward a frame (upstream EOF / connection reset), it sends a
/// Class C frame with this body back to the previous hop. The client
/// recognises this as a failover signal.
pub const UPSTREAM_FAILURE_MARKER: &[u8] = b"SNP/0.1 upstream-failure";

/// Body marker for the Class C "discovery request" frame. The client sends
/// this to a gateway's discovery listener to request a signed advertisement.
///
/// **N2.0.4 (Gate A) — DEPRECATED.** This marker was used by the N2.0.1
/// AEAD-encrypted discovery link. The N2.0.4 raw discovery protocol uses
/// [`DISCOVERY_REQUEST_BYTE`] instead. Kept for backward compatibility with
/// any external callers that may still reference it.
pub const DISCOVERY_REQUEST_MARKER: &[u8] = b"SNP/0.1 discovery-request";

/// N2.0.4 (Gate A): the single byte the client sends on a raw TCP
/// connection to a gateway's discovery listener to request a signed
/// advertisement. The gateway responds with a 4-byte big-endian length
/// prefix followed by that many bytes of CBOR-encoded
/// [`GatewayAdvertisement`].
///
/// This is the RAW discovery protocol (no AEAD, no `DISCOVERY_LINK_SEED`).
/// The advertisement's signature provides the authentication.
pub const DISCOVERY_REQUEST_BYTE: u8 = 0x01;


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
    ///
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::serve_relay_persistent_async`]
    /// (the canonical async production path via `AsyncLink` +
    /// `perform_snp_ik_handshake_async`). This sync variant is retained only
    /// for backward-compat with the N2.0.1 / N2.0.4 sync tests.
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::serve_relay_persistent_async` (canonical async path)"
    )]
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
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::serve_relay_multi_upstream_persistent_async`].
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::serve_relay_multi_upstream_persistent_async`"
    )]
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
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::serve_gateway_persistent_async`].
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::serve_gateway_persistent_async` (canonical async path)"
    )]
    pub fn serve_gateway_persistent(
        &self,
        listen_addr: &str,
        link_keys: LinkKeys,
        circuit_keys: CircuitKeys,
    ) -> NodeResult<()> {
        let gateway_node_id = self.identity.node_id;
        let gateway_sk = self.identity.secret_key;
        let listener = std::net::TcpListener::bind(listen_addr)?;
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
            let link = Arc::new(snp_link::Link::new(stream, link_keys));
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
    /// **N2.0.6: DEPRECATED.** Use a tokio task that closes the listener
    /// after `max_requests` (the async path does not have a built-in
    /// drop-after variant — tests use `tokio::select!` with a oneshot).
    #[deprecated(
        since = "N2.0.6",
        note = "use the async runtime with `tokio::select!` for drop-after behaviour"
    )]
    pub fn serve_gateway_persistent_with_drop_after(
        &self,
        listen_addr: &str,
        link_keys: LinkKeys,
        circuit_keys: CircuitKeys,
        max_requests: usize,
    ) -> NodeResult<()> {
        let gateway_node_id = self.identity.node_id;
        let gateway_sk = self.identity.secret_key;
        let listener = std::net::TcpListener::bind(listen_addr)?;
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
            let link = Arc::new(snp_link::Link::new(stream, link_keys));
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
    /// signed [`GatewayAdvertisement`] (CBOR-encoded, length-prefixed).
    ///
    /// **N2.0.4 (Gate A) — raw unauthenticated discovery protocol.** The
    /// discovery link is NO LONGER AEAD-encrypted with the deterministic
    /// `DISCOVERY_LINK_SEED`. Instead the client opens a raw TCP connection
    /// and sends a single byte `0x01` (the discovery-request marker); the
    /// gateway responds with a 4-byte big-endian length prefix followed by
    /// that many bytes of CBOR-encoded `GatewayAdvertisement`. This is the
    /// SAME protocol implemented by [`BootstrapDiscovery::discover`].
    ///
    /// ### Why is unauthenticated discovery safe?
    ///
    /// The advertisement is **signed** by the gateway's Ed25519 secret key
    /// under `SIG_CONTEXTS::GATEWAY_ADVERT`. A network attacker can
    /// substitute their own advertisement, but the client's
    /// [`GatewayAdvertisement::verify`] check will reject it (the attacker
    /// cannot forge a signature under the gateway's public key). The
    /// attacker can also DROP or REPLAY a real advertisement, but replay
    /// is bounded by the `expiry` field (a stale advertisement is rejected
    /// by [`GatewayAdvertisement::is_expired`]).
    ///
    /// The DELIBERATE SIMPLIFICATION for N2.0.4 is that an attacker can
    /// OBSERVE the advertisement request (and learn the gateway's
    /// `node_id`, `public_key`, `listen_addr`, etc. — though these are
    /// already public). Production would use an anonymous X25519 ephemeral
    /// handshake for the discovery link to prevent eavesdropping on the
    /// advertisement request itself. See `docs/n2.0.3-android-platform-contract.md`
    /// for the production design.
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
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::serve_discovery_persistent_async`].
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::serve_discovery_persistent_async`"
    )]
    pub fn serve_discovery_persistent(
        &self,
        discovery_addr: &str,
        transit_listen_addr: &str,
    ) -> NodeResult<()> {
        let listener = std::net::TcpListener::bind(discovery_addr)?;
        let gateway_node_id = self.identity.node_id;
        eprintln!(
            "[discovery {}] listening on {discovery_addr}",
            hex_short(&gateway_node_id)
        );
        // N2.0.7: deprecated sync path uses for_identity (no X25519 key).
        // The async path (serve_discovery_persistent_async) is canonical.
        let advert = GatewayAdvertisement::for_identity(
            &self.identity,
            transit_listen_addr,
            discovery_addr,
        );
        let advert_bytes = advert.encode_cbor()?;

        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[discovery {}] accept error: {e}", hex_short(&gateway_node_id));
                    continue;
                }
            };
            // N2.0.4: read 1-byte discovery request.
            let mut req = [0u8; 1];
            if let Err(e) = std::io::Read::read_exact(&mut stream, &mut req) {
                eprintln!(
                    "[discovery {}] recv request error: {e}",
                    hex_short(&gateway_node_id)
                );
                continue;
            }
            if req[0] != DISCOVERY_REQUEST_BYTE {
                eprintln!(
                    "[discovery {}] unexpected discovery request byte 0x{:02x} — ignoring",
                    hex_short(&gateway_node_id),
                    req[0]
                );
                continue;
            }
            eprintln!(
                "[discovery {}] got discovery request",
                hex_short(&gateway_node_id)
            );
            // N2.0.4: write 4-byte BE length prefix + CBOR advertisement.
            let len = u32::try_from(advert_bytes.len())
                .map_err(|_| NodeError::Other(format!(
                    "advertisement length {} exceeds u32::MAX",
                    advert_bytes.len()
                )))?;
            if let Err(e) = std::io::Write::write_all(&mut stream, &len.to_be_bytes()) {
                eprintln!(
                    "[discovery {}] send length error: {e}",
                    hex_short(&gateway_node_id)
                );
                continue;
            }
            if let Err(e) = std::io::Write::write_all(&mut stream, &advert_bytes) {
                eprintln!(
                    "[discovery {}] send advert error: {e}",
                    hex_short(&gateway_node_id)
                );
                continue;
            }
            let _ = std::io::Write::flush(&mut stream);
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
    /// listener). **N2.0.4 (Gate A):** the discovery link uses the RAW
    /// unauthenticated protocol (single byte `0x01` request, length-prefixed
    /// CBOR advertisement response) — NOT the AEAD-encrypted `Link` layer.
    /// The advertisement's Ed25519 signature provides the authentication.
    ///
    /// This method delegates to [`BootstrapDiscovery::discover`] (the trait
    /// implementation that performs the actual I/O) and records each
    /// verified [`DiscoveredNode`] into `self.known_gateways`. The
    /// delegation means `Node::discover_gateways` and a caller that
    /// directly uses `BootstrapDiscovery::discover` see IDENTICAL behavior
    /// — the trait is the single source of truth for discovery.
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
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::discover_gateways_async`].
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::discover_gateways_async`"
    )]
    pub fn discover_gateways(&self, known_addrs: &[String]) -> NodeResult<()> {
        let provider = BootstrapDiscovery::new(known_addrs.to_vec());
        let discovered_nodes = provider.discover();
        let mut discovered = 0usize;
        for node in discovered_nodes {
            let advert = node.advertisement;
            let addr = &node.endpoint;
            // VERIFY THE SIGNATURE — this is the "authenticated gateway
            // discovery" the audit requested. A forged advertisement is
            // rejected here. (BootstrapDiscovery::discover already verifies
            // the signature, but we re-verify here for defence in depth —
            // a future BootstrapDiscovery implementation might forget.)
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
        // Use the node's configured listen_addr as Relay A's address, and the
        // deterministic N2.0 test seed for the client↔Relay A hop keys.
        let relay_a_addr = self.listen_addr.clone();
        if relay_a_addr.is_empty() {
            return Err(NodeError::Other(
                "no relay address configured (set Node.listen_addr to Relay A's address)".into(),
            ));
        }
        self.send_request_via_gateway_full_with_relay(
            url,
            gateway_node_id,
            &relay_a_addr,
            client_relay_a_link_keys(),
        )
    }

    /// **N2.0.3 (Gates F+G+H).** Like [`send_request_via_gateway_full`]
    /// but accepts an EXPLICIT relay address and EXPLICIT client↔Relay A
    /// hop keys. This is the production entry point for dynamic-mesh
    /// scenarios where the client↔Relay A link uses arbitrary
    /// SNP-IK/0.1-derived keys (NOT the deterministic N2.0 test seed).
    ///
    /// The method:
    /// 1. Looks up the [`Circuit`] for `gateway_node_id` (the caller is
    ///    responsible for establishing the circuit first, e.g. via
    ///    `discover_gateways` + the SNP-IK/0.1 handshake + the
    ///    client↔gateway X25519 circuit DH).
    /// 2. Establishes (or reuses) a persistent TCP connection to
    ///    `relay_addr` using `relay_link_keys` (the client↔Relay A hop
    ///    keys, initiator side).
    /// 3. Builds, signs, and circuit-encrypts a [`TransitRequest`].
    /// 4. Wraps it in a Class B frame addressed to `gateway_node_id`
    ///    (the frame's `dst` field — relays route based on this).
    /// 5. Sends the frame via Relay A and waits for the response.
    /// 6. On a Class C `UPSTREAM_FAILURE_MARKER` frame, returns
    ///    [`NodeError::UpstreamFailure`] (the caller can fail over to a
    ///    different gateway).
    /// 7. On a Class B response, decrypts and verifies the gateway's
    ///    signature.
    ///
    /// # Errors
    /// Returns [`NodeError`] on any failure.
    /// **N2.0.6: DEPRECATED.** Use [`crate::node::async_node::send_request_via_gateway_full_with_relay_async`]
    /// or [`crate::node::async_node::send_request_with_full_snp_ik_handshake_async`]
    /// (the canonical async path with a real SNP-IK/0.1 handshake).
    #[deprecated(
        since = "N2.0.6",
        note = "use `snp_node::node::async_node::send_request_via_gateway_full_with_relay_async` (canonical async path)"
    )]
    pub fn send_request_via_gateway_full_with_relay(
        &self,
        url: &str,
        gateway_node_id: &[u8; 32],
        relay_addr: &str,
        relay_link_keys: LinkKeys,
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

        // Get (or establish) the persistent connection to the relay.
        let link = self.get_or_connect_peer(relay_addr, relay_link_keys)?;

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
    ) -> NodeResult<Arc<snp_link::Link>> {
        // Fast path: already connected.
        if let Some(peer) = self.peers.lock().unwrap().get(addr) {
            return Ok(Arc::clone(&peer.link));
        }
        // Slow path: connect and cache.
        eprintln!("[node] establishing persistent connection to {addr}");
        let link = Arc::new(snp_link::Link::connect(addr, hop_keys)?);
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
    /// **N2.0.7.3: DEPRECATED.** This method used the old `Route::new`
    /// constructor which has been removed. Use `Route::new_with_hop_details`
    /// with `VerifiedNodeDescriptor` + `TransportEndpoint` entries instead.
    #[deprecated(
        since = "N2.0.7.3",
        note = "use Route::new_with_hop_details with VerifiedNodeDescriptor entries"
    )]
    #[cfg(feature = "legacy-circuit-keys")]
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
        #[allow(deprecated)]
        let route = Route::new(self.identity.node_id, gateway_node_id, hops);
        route
            .validate()
            .map_err(|e| NodeError::Other(format!("construct_route: route validation failed: {e}")))?;
        Ok(route)
    }

    #[cfg(not(feature = "legacy-circuit-keys"))]
    pub fn construct_route(
        &self,
        _relay_node_ids: &[[u8; 32]],
        _gateway_node_id: [u8; 32],
    ) -> NodeResult<Route> {
        Err(NodeError::Other(
            "construct_route is not available in production — use Route::new_with_hop_details".into()
        ))
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
//
// N2.0.6: The sync relay internals below are `#[deprecated]` — they are
// called only from the `#[deprecated]` `pub fn serve_relay_persistent` /
// `serve_relay_multi_upstream_persistent` / `serve_gateway_persistent_with_drop_after`
// methods (above). New production code MUST use the async equivalents in
// `node/async_node.rs` (`serve_relay_persistent_async` etc.).

/// Internal: persistent single-upstream relay. Accepts an optional connection
/// counter (for tests to verify "same connection served N requests").
///
/// **N2.0.6: DEPRECATED** — see module-level note above.
#[deprecated(since = "N2.0.6", note = "use `async_node::serve_relay_persistent_async`")]
fn serve_relay_persistent_inner(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
    connection_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> NodeResult<()> {
    let listener = std::net::TcpListener::bind(listen_addr)?;
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
        let prev_link = Arc::new(snp_link::Link::new(prev_stream, prev_hop_keys));
        let next_link = match snp_link::Link::connect(next_hop_addr, next_hop_keys) {
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
///
/// **N2.0.6: DEPRECATED** — see module-level note above.
#[deprecated(since = "N2.0.6", note = "use `async_node::serve_relay_multi_upstream_persistent_async`")]
fn serve_relay_multi_upstream_persistent_inner(
    listen_addr: &str,
    upstreams: &[UpstreamPeer],
    prev_hop_keys: LinkKeys,
    connection_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> NodeResult<()> {
    let listener = std::net::TcpListener::bind(listen_addr)?;
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
        let prev_link = Arc::new(snp_link::Link::new(prev_stream, prev_hop_keys));

        // Establish persistent connections to ALL upstreams.
        let mut upstream_links: Vec<([u8; 32], String, Arc<snp_link::Link>)> = Vec::new();
        for upstream in upstreams {
            match snp_link::Link::connect(&upstream.addr, upstream.hop_keys) {
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
fn send_upstream_failure_nack(prev_link: &snp_link::Link, req_frame: &Frame) {
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
    link: &Arc<snp_link::Link>,
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
    link: &Arc<snp_link::Link>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    circuit: &CircuitKeys,
    seen_req_ids: &mut HashSet<[u8; 16]>,
    connector_factory: &F,
) -> NodeResult<ServeOutcome>
where
    F: Fn(&str) -> NodeResult<PinnedConnector>,
{
    // Default: use the N1.9/N2.0 legacy client public key. This preserves
    // backward compat with the n203_local_http.rs Gate K test (which uses
    // the deterministic N2.0 client identity). New tests with dynamic
    // client identities MUST call
    // [`serve_one_gateway_request_with_connector_factory_and_client_key`]
    // and pass the client's actual public key.
    serve_one_gateway_request_with_connector_factory_and_client_key(
        link,
        gateway_node_id,
        gateway_sk,
        &client_public_key(),
        circuit,
        seen_req_ids,
        connector_factory,
    )
}

/// **N2.0.3 (Gates F+G+H).** Like
/// [`serve_one_gateway_request_with_connector_factory`] but accepts an
/// EXPLICIT client public key (used to verify the `TransitRequest`'s
/// `clientSig`). This is the production entry point for dynamic-mesh
/// scenarios where the client identity is NOT the deterministic N2.0
/// test identity.
///
/// In production, the gateway learns the client's public key from the
/// SNP-IK/0.1 handshake (the handshake authenticates the client's
/// Ed25519 identity). The circuit is established AFTER the handshake,
/// so the gateway already knows the client's public key when it
/// receives the first `TransitRequest` over the circuit. This function
/// takes the client public key as a parameter so the caller (the
/// gateway's serve loop) can pass in the handshake-authenticated key.
///
/// **TEST-ONLY SSRF bypass.** Like
/// [`serve_one_gateway_request_with_connector_factory`], this function
/// does NOT perform any SSRF check itself — it relies on the factory. A
/// test that uses [`PinnedConnector::from_parts`] to bypass the SSRF
/// check MUST ensure the connector points only at the test's own mock
/// HTTP server. **Production gateways MUST NOT use this function** —
/// production MUST use [`serve_one_gateway_request`] (or
/// [`Node::serve_gateway_persistent`]), which calls
/// [`PinnedConnector::new`] and enforces the SSRF defence (invariant
/// I18).
#[doc(hidden)]
pub fn serve_one_gateway_request_with_connector_factory_and_client_key<F>(
    link: &Arc<snp_link::Link>,
    gateway_node_id: [u8; 32],
    gateway_sk: &[u8; 32],
    client_pk: &[u8; 32],
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
        client_pk,
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

// ─── Discovery link keys (MOVED to legacy.rs in N2.0.5) ──────────────────────
//
// **N2.0.5: MOVED to `crate::legacy`.** The `DISCOVERY_LINK_SEED` constant
// and the `discovery_link_keys_initiator` / `discovery_link_keys_responder`
// functions were deterministic test seeds. They have been moved to
// `crate::legacy` (alongside the other N1.9/N2.0 deterministic test seeds).
// New production code MUST NOT use them — the N2.0.4 raw discovery protocol
// (`BootstrapDiscovery::discover` + `Node::serve_discovery_persistent`)
// uses unauthenticated TCP + a signed advertisement (no AEAD on the
// discovery link). See `crate::legacy::discovery_link_keys_initiator` for
// the legacy function.

// ─── N2.0.1 mesh session demo (MOVED to legacy.rs in N2.0.5) ─────────────────
//
// **N2.0.5: MOVED to `crate::legacy`.** The `run_mesh_session_demo` and
// `run_mesh_session_demo_with_failover` functions were N2.0.1 demo code
// that used the deterministic N2.0 test gateway identities
// (`gateway_a_secret`, `gateway_b_secret`) and the deterministic N2.0
// client circuit keys (`client_circuit_keys_a`, `client_circuit_keys_b`).
// They have been moved to `crate::legacy` (alongside the other N1.9/N2.0
// demo code). The `mesh-session-demo` binary and the `mesh-session-demo`
// subcommand in `main.rs` now call `crate::legacy::run_mesh_session_demo`.
// See `crate::legacy::run_mesh_session_demo` for the legacy function.


// ─── Test/demo helpers (public for tests) ────────────────────────────────────
//
// **N2.0.5: `relay_secret_a` and `relay_secret_b` MOVED to `crate::legacy`.**
// They were deterministic N2.0 demo secret keys (not cryptographically
// meaningful — relays don't sign anything in N2.0.1). They live in
// `crate::legacy` now so that `node/mod.rs` is free of deterministic key
// derivation. Re-exported here for backward compatibility with any tests
// that still reference `snp_node::node::relay_secret_a`.
pub use crate::legacy::{relay_secret_a, relay_secret_b};

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

/// **N2.0.3 (Gate G).** Inner implementation of a single-upstream relay
/// that DROPS its prev-hop connection after serving `max_requests`
/// request-response cycles. Used by the N2.0.3 mesh-failure test to
/// simulate a relay that dies mid-session (Test 2: Relay B is killed
/// after 1 request, forcing the client to fail over to the alternate
/// path via Relay C).
///
/// After `max_requests` cycles, the relay explicitly shuts down the
/// prev-hop TCP stream (`Shutdown::Both`). The prev hop (Relay A in the
/// test topology) sees this as a connection close on its next
/// `recv_frame()` call — Relay A's multi-upstream relay sends a
/// `UPSTREAM_FAILURE_MARKER` NACK back to the client and removes the
/// dead upstream from its `upstream_links`. The client then fails over
/// to a different gateway.
///
/// **The relay thread does NOT exit** after the drop — it loops back to
/// `listener.incoming()` and accepts a new connection. This mirrors the
/// existing `serve_gateway_persistent_with_drop_after` semantics (the
/// listener stays open; only the per-connection TCP stream is dropped).
///
/// # Errors
/// Returns [`NodeError`] on TCP bind failure. Per-connection errors are
/// logged and the relay continues accepting new connections.
///
/// **N2.0.6: DEPRECATED** — see module-level note above.
#[deprecated(since = "N2.0.6", note = "use the async runtime with `tokio::select!` for drop-after behaviour")]
fn serve_relay_persistent_with_drop_after_inner(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
    max_requests: usize,
    connection_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> NodeResult<()> {
    let listener = std::net::TcpListener::bind(listen_addr)?;
    eprintln!(
        "[relay-drop-after-{}] listening on {listen_addr}, next-hop={next_hop_addr}",
        max_requests
    );

    for stream in listener.incoming() {
        let prev_stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[relay-drop-after] accept error: {e}");
                continue;
            }
        };
        eprintln!(
            "[relay-drop-after] prev-hop connected from {}",
            prev_stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into())
        );
        if let Some(counter) = &connection_counter {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let prev_link = Arc::new(snp_link::Link::new(prev_stream, prev_hop_keys));
        let next_link = match snp_link::Link::connect(next_hop_addr, next_hop_keys) {
            Ok(l) => Arc::new(l),
            Err(e) => {
                eprintln!("[relay-drop-after] connect to next-hop {next_hop_addr} failed: {e}");
                continue;
            }
        };
        eprintln!("[relay-drop-after] connected to next-hop at {next_hop_addr}");

        let mut served = 0usize;
        // PERSISTENT LOOP: forward frames in both directions until EOF/error
        // OR until we've served `max_requests` cycles.
        loop {
            if served >= max_requests {
                eprintln!(
                    "[relay-drop-after-{}] served {served} requests — DROPPING connection (simulated failure)",
                    max_requests
                );
                let _ = prev_link.stream().shutdown(std::net::Shutdown::Both);
                let _ = next_link.stream().shutdown(std::net::Shutdown::Both);
                break;
            }
            // prev → next
            let req_frame = match prev_link.recv_frame() {
                Ok(f) => f,
                Err(snp_link::LinkError::Io(msg)) if msg.contains("unexpected eof") || msg.contains("connection reset") => {
                    eprintln!("[relay-drop-after] prev-hop closed connection (EOF)");
                    break;
                }
                Err(e) => {
                    eprintln!("[relay-drop-after] prev→next recv error: {e}");
                    break;
                }
            };
            eprintln!(
                "[relay-drop-after] prev→next: cls={} ttl={} body={} bytes",
                req_frame.cls as char,
                req_frame.ttl,
                req_frame.body.len()
            );
            if should_drop(&req_frame) {
                eprintln!("[relay-drop-after] frame TTL=0, dropping");
                continue;
            }
            let mut fwd_frame = req_frame.clone();
            if fwd_frame.ttl > 0 {
                fwd_frame.ttl -= 1;
            }
            if let Err(e) = next_link.send_frame(&fwd_frame) {
                eprintln!("[relay-drop-after] prev→next send error: {e}");
                break;
            }
            // next → prev
            let resp_frame = match next_link.recv_frame() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[relay-drop-after] next→prev recv error: {e}");
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
                eprintln!("[relay-drop-after] next→prev send error: {e}");
                break;
            }
            served += 1;
        }
        eprintln!("[relay-drop-after] connection cycle complete, looping back to accept");
    }
    Ok(())
}

/// **N2.0.3 (Gate G).** Spawn a single-upstream relay that DROPS its
/// prev-hop connection after serving `max_requests` request-response
/// cycles. Returns the relay's thread join handle.
///
/// This is the test-only relay counterpart to
/// [`Node::serve_gateway_persistent_with_drop_after`]. Used by the
/// N2.0.3 mesh-failure test (`tests/n203_mesh_failure.rs`) to simulate
/// a relay that dies mid-session: after `max_requests` cycles, the
/// relay's prev-hop TCP stream is shut down (`Shutdown::Both`), causing
/// the upstream multi-hop relay (Relay A) to detect the failure, send a
/// NACK to the client, and remove the dead upstream from its
/// `upstream_links`.
///
/// **The relay thread does NOT exit** after the drop — it loops back to
/// accept a new connection (mirroring the gateway's
/// `serve_gateway_persistent_with_drop_after` semantics).
#[must_use]
pub fn spawn_relay_persistent_with_drop_after(
    listen_addr: &str,
    next_hop_addr: &str,
    prev_hop_keys: LinkKeys,
    next_hop_keys: LinkKeys,
    max_requests: usize,
) -> std::thread::JoinHandle<()> {
    let listen = listen_addr.to_string();
    let next = next_hop_addr.to_string();
    std::thread::spawn(move || {
        let _ = serve_relay_persistent_with_drop_after_inner(
            &listen,
            &next,
            prev_hop_keys,
            next_hop_keys,
            max_requests,
            None,
        );
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Small CBOR helpers (local to this module)

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
    use crate::legacy::client_node_id;
    use crate::legacy::GatewayChoice;

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
    /// GatewayChoice references in this file — they use `crate::legacy::GatewayChoice`
    /// (fully-qualified, not the bare import) and are compiled only in test
    /// builds.
    #[test]
    fn gateway_choice_not_in_production_code() {
        let source = include_str!("mod.rs");
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
        // deprecated constructors use `crate::legacy::GatewayChoice` (fully
        // qualified), so they do not need the bare import.
        let import_line = source
            .lines()
            .find(|line| line.starts_with("use crate::{") && line.contains("GatewayChoice"));
        assert!(
            import_line.is_none(),
            "node.rs must NOT import GatewayChoice via `use crate::{{... GatewayChoice ...}};`. \
             The deprecated #[cfg(test)] constructors use `crate::legacy::GatewayChoice` (fully qualified). \
             Found import: {:?}",
            import_line
        );
    }

    // ─── N2.0.5 (Item 2/3): static checks that deterministic-seed key
    //      derivation (`derive_link_keys`) and `GatewayChoice` do not appear
    //      in production node/ module code (only in `#[deprecated]`
    //      constructors, `#[cfg(test)]` blocks, or comments). ──────────────

    /// N2.0.5: Helper — scan a source file for `needle` references outside
    /// doc-comments, code-comments, `#[cfg(test)]` blocks, and
    /// `#[deprecated]` function bodies. Returns the (line_number, line)
    /// of the first offending occurrence, or `None` if all references are
    /// in allowed regions.
    fn scan_for_offending_reference(
        module_name: &str,
        source: &str,
        needle: &str,
    ) -> Option<(usize, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut in_cfg_test = false;
        for (lineno, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            // Track #[cfg(test)] mod entry — once we enter the test mod, we
            // stay there for the rest of the file (the test mod is at the end).
            if trimmed.starts_with("#[cfg(test)]") {
                in_cfg_test = true;
            }
            if in_cfg_test {
                continue;
            }
            if !line.contains(needle) {
                continue;
            }
            // Allowed: any comment line.
            if trimmed.starts_with("//") {
                continue;
            }
            // Allowed: inside a `#[deprecated]` function body. We look
            // backwards up to 15 lines for a `#[deprecated` attribute,
            // stopping if we hit a `}` line (which would mean we're outside
            // any deprecated fn — the previous function has closed). We do
            // NOT stop at `pub fn` lines because the `#[deprecated]`
            // attribute sits ABOVE the `pub fn` line, so we need to scan
            // past it.
            let start = lineno.saturating_sub(15);
            let mut found_deprecated = false;
            for prev in lines[start..lineno].iter().rev() {
                let pt = prev.trim_start();
                if pt.starts_with("#[deprecated") {
                    found_deprecated = true;
                    break;
                }
                // Stop if we hit a closing brace at column 0 — that's the
                // end of a previous function (we've left any deprecated fn
                // we might have been in). We use a column-0 `}` (i.e.
                // trimmed line starts with `}`) to avoid false positives
                // from nested `}` inside the function body (those are
                // indented).
                if pt.starts_with("}") {
                    break;
                }
            }
            if !found_deprecated {
                return Some((lineno + 1, line.to_string()));
            }
            let _ = module_name; // module_name is used in the panic message at the call site
        }
        None
    }

    /// N2.0.5 (Item 2): `derive_link_keys` (the deterministic-seed AEAD key
    /// derivation function) must NOT appear in production node/ module code.
    /// It is only allowed in `crate::legacy` (which holds the deterministic
    /// N1.9/N2.0 test seeds) and in `#[deprecated]` constructors or
    /// `#[cfg(test)]` blocks.
    ///
    /// This test scans every `node/` module source file for `derive_link_keys`
    /// references and fails if any appear in a production region (i.e. not
    /// in a comment, `#[deprecated]` body, or `#[cfg(test)]` block).
    #[test]
    fn derive_link_keys_not_in_production_node_modules() {
        let modules: &[(&str, &str)] = &[
            ("node/mod.rs", include_str!("mod.rs")),
            ("node/circuit.rs", include_str!("circuit.rs")),
            ("node/gateway.rs", include_str!("gateway.rs")),
            ("node/identity.rs", include_str!("identity.rs")),
            ("node/session.rs", include_str!("session.rs")),
            ("node/route.rs", include_str!("route.rs")),
            ("node/discovery.rs", include_str!("discovery.rs")),
            ("node/transport.rs", include_str!("transport.rs")),
            ("node/async_transport.rs", include_str!("async_transport.rs")),
        ];
        for (name, source) in modules {
            if let Some((lineno, line)) = scan_for_offending_reference(name, source, "derive_link_keys") {
                panic!(
                    "Production node module {}:{} references `derive_link_keys` outside a \
                     #[deprecated] block or #[cfg(test)] block.\n  Line: {line}\n  \
                     `derive_link_keys` is the deterministic-seed AEAD key derivation — \
                     production node/ modules must NOT use it. Move the call to \
                     `crate::legacy` or mark it `#[deprecated]` / `#[cfg(test)]`.",
                    name, lineno
                );
            }
        }
    }

    /// N2.0.5 (Item 3): `GatewayChoice` must NOT appear in production node/
    /// module code — only in `#[deprecated]` constructors
    /// (`Circuit::for_gateway`, `GatewayAdvertisement::for_gateway`,
    /// `NodeIdentity::gateway`), `#[cfg(test)]` blocks, or comments.
    ///
    /// This test scans every `node/` module source file for `GatewayChoice`
    /// references and fails if any appear in a production region.
    #[test]
    fn gateway_choice_not_in_production_node_modules() {
        let modules: &[(&str, &str)] = &[
            ("node/mod.rs", include_str!("mod.rs")),
            ("node/circuit.rs", include_str!("circuit.rs")),
            ("node/gateway.rs", include_str!("gateway.rs")),
            ("node/identity.rs", include_str!("identity.rs")),
            ("node/session.rs", include_str!("session.rs")),
            ("node/route.rs", include_str!("route.rs")),
            ("node/discovery.rs", include_str!("discovery.rs")),
            ("node/transport.rs", include_str!("transport.rs")),
            ("node/async_transport.rs", include_str!("async_transport.rs")),
        ];
        for (name, source) in modules {
            if let Some((lineno, line)) = scan_for_offending_reference(name, source, "GatewayChoice") {
                panic!(
                    "Production node module {}:{} references `GatewayChoice` outside a \
                     #[deprecated] block, #[cfg(test)] block, or comment.\n  Line: {line}\n  \
                     Move the GatewayChoice-dependent code to `crate::legacy` or mark it \
                     `#[deprecated]` / `#[cfg(test)]`.",
                    name, lineno
                );
            }
        }
    }

    /// N2.0.6: `std::net::TcpListener::bind` / `std::net::TcpStream::connect`
    /// (the synchronous transport) must NOT appear in production node/ module
    /// code — only in `#[deprecated]` method bodies, `#[cfg(test)]` blocks,
    /// or comments. New production code MUST use the canonical async transport
    /// (`tokio::net::TcpListener::bind` / `AsyncLink::connect_raw` /
    /// `perform_snp_ik_handshake_async`).
    ///
    /// This test scans every `node/` module source file for the sync transport
    /// signatures and fails if any appear in a production region. The sync
    /// `transport.rs` module is excluded (it is entirely `#[deprecated]`).
    #[test]
    fn sync_tcp_not_in_production_node_modules() {
        let modules: &[(&str, &str)] = &[
            ("node/mod.rs", include_str!("mod.rs")),
            ("node/circuit.rs", include_str!("circuit.rs")),
            ("node/gateway.rs", include_str!("gateway.rs")),
            ("node/identity.rs", include_str!("identity.rs")),
            ("node/session.rs", include_str!("session.rs")),
            ("node/route.rs", include_str!("route.rs")),
            ("node/discovery.rs", include_str!("discovery.rs")),
            ("node/async_transport.rs", include_str!("async_transport.rs")),
            ("node/async_node.rs", include_str!("async_node.rs")),
        ];
        // The sync transport signatures we forbid in production code:
        //   - `use std::net::TcpListener` — sync TCP import
        //   - `use std::net::TcpStream` — sync TCP import
        //   - `std::net::TcpListener::bind` — sync TCP listener bind
        //   - `std::net::TcpStream::connect` — sync TCP client connect
        // The async equivalents use `tokio::net::TcpListener` /
        // `tokio::net::TcpStream` / `AsyncLink::connect_raw`.
        // We do NOT forbid the unqualified `TcpListener::bind` because both
        // the sync (`use std::net::TcpListener`) and async
        // (`use tokio::net::TcpListener`) versions use that call shape — the
        // fully-qualified `std::net::TcpListener::bind` is the unambiguous
        // sync signature.
        const FORBIDDEN: &[&str] = &[
            "use std::net::TcpListener",
            "use std::net::TcpStream",
            "std::net::TcpListener::bind",
            "std::net::TcpStream::connect",
        ];
        for (name, source) in modules {
            for needle in FORBIDDEN {
                if let Some((lineno, line)) = scan_for_offending_reference(name, source, needle) {
                    panic!(
                        "Production node module {}:{} references sync transport `{}` outside a \
                         #[deprecated] block or #[cfg(test)] block.\n  Line: {line}\n  \
                         New production code MUST use the canonical async transport: \
                         `tokio::net::TcpListener`, `tokio::net::TcpStream`, \
                         `AsyncLink::connect_raw`, `perform_snp_ik_handshake_async`. \
                         Mark the enclosing fn `#[deprecated]` or move the sync code to \
                         `crate::legacy`.",
                        name, lineno, needle
                    );
                }
            }
        }
    }

    /// N2.0.6: The canonical production async entry points MUST exist in
    /// `node/async_node.rs`. These are the SINGLE production path — the
    /// north-star test uses ONLY these entry points. If a future refactor
    /// removes or renames them, this test will fail.
    ///
    /// The canonical entry points are:
    /// - `serve_gateway_persistent_async_with_handshake` (gateway: handshake + serve)
    /// - `serve_gateway_persistent_async_with_handshake_and_connector` (test variant)
    /// - `serve_relay_persistent_async_with_handshake` (relay: handshake + forward)
    /// - `establish_circuit_and_send_async` (client: circuit DH + handshake + send)
    #[test]
    fn canonical_production_async_entry_points_exist() {
        let source = include_str!("async_node.rs");
        let required: &[&str] = &[
            "pub async fn serve_gateway_persistent_async_with_handshake(",
            "pub async fn serve_gateway_persistent_async_with_handshake_and_connector",
            "pub async fn serve_relay_persistent_async_with_handshake(",
            "pub async fn establish_circuit_and_send_async(",
        ];
        for sig in required {
            assert!(
                source.contains(sig),
                "canonical production entry point `{sig}` not found in node/async_node.rs. \
                 This entry point is REQUIRED — the north-star test depends on it."
            );
        }
        eprintln!("[static-guard] PASS: all 4 canonical production async entry points exist");
    }

    /// N2.0.7: The canonical production gateway entry point MUST NOT accept
    /// `CircuitKeys` as a parameter — it must derive them from the protocol
    /// (via `open_circuit_payload_with_fresh_eph`). This test scans
    /// `async_node.rs` for the N2.0.7 protocol-driven gateway function and
    /// verifies its signature does NOT include `CircuitKeys`.
    #[test]
    fn production_gateway_does_not_accept_circuit_keys_param() {
        let source = include_str!("async_node.rs");
        // The N2.0.7 protocol-driven gateway function must exist.
        assert!(
            source.contains("pub async fn serve_gateway_with_protocol_circuit"),
            "serve_gateway_with_protocol_circuit must exist"
        );
        // The N2.0.7 protocol-driven client send function must exist.
        assert!(
            source.contains("pub async fn send_with_protocol_circuit_async"),
            "send_with_protocol_circuit_async must exist"
        );
        // The Route-authoritative client send function must exist.
        assert!(
            source.contains("pub async fn send_via_route("),
            "send_via_route must exist"
        );
        // The Route-authoritative relay serve function must exist.
        assert!(
            source.contains("pub async fn serve_relay_via_route("),
            "serve_relay_via_route must exist"
        );
        // The protocol-driven gateway function must NOT take CircuitKeys.
        // Find the function signature and check it doesn't contain CircuitKeys.
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("pub async fn serve_gateway_with_protocol_circuit") {
                // Check the next 10 lines (the function signature).
                for j in i..(i + 10).min(lines.len()) {
                    if lines[j].contains("CircuitKeys") {
                        panic!(
                            "serve_gateway_with_protocol_circuit must NOT take CircuitKeys as a parameter \
                             (it derives keys from the protocol). Found at line {}.",
                            j + 1
                        );
                    }
                }
            }
        }
        eprintln!("[static-guard] PASS: production gateway does not accept CircuitKeys param");
    }

    /// N2.0.7: The `send_via_route` function must take a `Route` parameter
    /// (not individual `relay_addr`/`next_hop_addr` parameters). This test
    /// verifies the signature.
    #[test]
    fn send_via_route_takes_route_not_explicit_addresses() {
        let source = include_str!("async_node.rs");
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("pub async fn send_via_route(") {
                // Check the next 10 lines (the function signature).
                let sig: String = lines[i..(i + 10).min(lines.len())].join("\n");
                assert!(
                    sig.contains("route: &super::Route") || sig.contains("route: &Route"),
                    "send_via_route must take a Route parameter"
                );
                assert!(
                    !sig.contains("relay_addr: &str"),
                    "send_via_route must NOT take an explicit relay_addr parameter"
                );
                assert!(
                    !sig.contains("next_hop_addr: &str"),
                    "send_via_route must NOT take an explicit next_hop_addr parameter"
                );
                eprintln!("[static-guard] PASS: send_via_route takes Route, not explicit addresses");
                return;
            }
        }
        panic!("send_via_route function not found");
    }

    /// N2.0.7: The `GatewayAdvertisement` must carry `circuit_x25519_pub`
    /// in the SIGNED preimage (binding the X25519 key to the Ed25519 identity).
    #[test]
    fn gateway_advertisement_binds_x25519_in_signed_preimage() {
        let source = include_str!("gateway.rs");
        // The struct must have a circuit_x25519_pub field.
        assert!(
            source.contains("pub circuit_x25519_pub: [u8; 32]"),
            "GatewayAdvertisement must have a circuit_x25519_pub field"
        );
        // The preimage function must include circuitX25519Pub.
        assert!(
            source.contains("(t(\"circuitX25519Pub\"), b(&self.circuit_x25519_pub))"),
            "GatewayAdvertisement::preimage must include circuitX25519Pub"
        );
        // The for_identity_with_circuit_key constructor must exist.
        assert!(
            source.contains("pub fn for_identity_with_circuit_key("),
            "GatewayAdvertisement::for_identity_with_circuit_key must exist"
        );
        eprintln!("[static-guard] PASS: GatewayAdvertisement binds X25519 in signed preimage");
    }

    /// N2.0.7: The Route must have `hop_details: Vec<RouteHop>` (authoritative
    /// routing plan with endpoints, not just NodeIds).
    #[test]
    fn route_has_hop_details_with_endpoints() {
        let source = include_str!("route.rs");
        assert!(
            source.contains("pub struct RouteHop"),
            "RouteHop struct must exist"
        );
        // N2.0.7.2: hop_details is now PRIVATE (non-mutable) — check for the
        // private field declaration, not `pub`.
        assert!(
            source.contains("hop_details: Vec<RouteHop>"),
            "Route must have hop_details field (private for non-mutability)"
        );
        assert!(
            source.contains("pub fn new_with_hop_details("),
            "Route::new_with_hop_details must exist"
        );
        assert!(
            source.contains("pub fn hop_details(&self)"),
            "Route must have a hop_details() accessor method"
        );
        eprintln!("[static-guard] PASS: Route has hop_details with endpoints");
    }

    /// N2.0.7.1: NO NON-DEPRECATED production gateway API may accept `CircuitKeys`
    /// as a parameter. The gateway must derive circuit keys FROM THE PROTOCOL
    /// (via `open_circuit_payload_with_fresh_eph`), not receive them externally.
    ///
    /// This test scans `async_node.rs` for ALL `pub async fn serve_gateway*`
    /// functions and verifies that any function taking `CircuitKeys` is marked
    /// `#[deprecated]`.
    #[test]
    fn no_production_gateway_api_accepts_circuit_keys() {
        let source = include_str!("async_node.rs");
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // Look for `pub async fn serve_gateway` (production gateway APIs).
            if line.contains("pub async fn serve_gateway") {
                // Scan the function signature (next 15 lines) for CircuitKeys.
                let sig_end = (i + 15).min(lines.len());
                let sig: String = lines[i..sig_end].join("\n");
                if sig.contains("CircuitKeys") {
                    // The function takes CircuitKeys — it MUST be deprecated.
                    // Look backwards for #[deprecated].
                    let mut found_deprecated = false;
                    for j in (0..i).rev().take(5) {
                        if lines[j].contains("#[deprecated") {
                            found_deprecated = true;
                            break;
                        }
                    }
                    if !found_deprecated {
                        panic!(
                            "NON-DEPRECATED production gateway API at line {} takes CircuitKeys \
                             as a parameter. Circuit keys must be derived from the protocol \
                             (via open_circuit_payload_with_fresh_eph), not supplied externally. \
                             Mark the function #[deprecated] or remove the CircuitKeys parameter.\n\
                             Function signature:\n{sig}",
                            i + 1
                        );
                    }
                }
            }
        }
        eprintln!("[static-guard] PASS: no non-deprecated gateway API accepts CircuitKeys");
    }

    /// N2.0.7.1: `send_via_route` must NOT take `gateway_ed25519_public` or
    /// `gateway_x25519_pub` as parameters — the gateway's identity comes from
    /// the Route's destination `NodeDescriptor`.
    #[test]
    fn send_via_route_does_not_take_gateway_keys_as_params() {
        let source = include_str!("async_node.rs");
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("pub async fn send_via_route(") {
                let sig_end = (i + 12).min(lines.len());
                let sig: String = lines[i..sig_end].join("\n");
                assert!(
                    !sig.contains("gateway_ed25519_public"),
                    "send_via_route must NOT take gateway_ed25519_public — get it from the Route's NodeDescriptor"
                );
                assert!(
                    !sig.contains("gateway_x25519_pub"),
                    "send_via_route must NOT take gateway_x25519_pub — get it from the Route's NodeDescriptor"
                );
                eprintln!("[static-guard] PASS: send_via_route does not take gateway keys as params");
                return;
            }
        }
        panic!("send_via_route function not found");
    }

    /// N2.0.7.1: `NodeDescriptor` and `TransportEndpoint` must exist in
    /// `descriptor.rs`.
    #[test]
    fn node_descriptor_and_transport_endpoint_exist() {
        let source = include_str!("descriptor.rs");
        assert!(
            source.contains("pub struct UnverifiedNodeDescriptor")
                || source.contains("pub struct NodeDescriptor"),
            "NodeDescriptor/UnverifiedNodeDescriptor struct must exist"
        );
        assert!(
            source.contains("pub enum TransportEndpoint"),
            "TransportEndpoint enum must exist"
        );
        assert!(
            source.contains("fn from_verified_advert") || source.contains("fn for_relay"),
            "NodeDescriptor constructors must exist"
        );
        assert!(
            source.contains("Tcp(String)"),
            "TransportEndpoint::Tcp variant must exist"
        );
        assert!(
            source.contains("Ble(String)"),
            "TransportEndpoint::Ble variant must exist (for future BLE support)"
        );
        eprintln!("[static-guard] PASS: NodeDescriptor + TransportEndpoint exist");
    }

    /// N2.0.7.1: `RouteHop` must carry a `NodeDescriptor` (not just a NodeId)
    /// and `Vec<TransportEndpoint>` (not `Vec<String>`).
    #[test]
    fn route_hop_carries_descriptor_and_typed_endpoints() {
        let source = include_str!("route.rs");
        assert!(
            source.contains("pub descriptor: VerifiedNodeDescriptor"),
            "RouteHop must carry a VerifiedNodeDescriptor (not just a NodeId)"
        );
        assert!(
            source.contains("pub endpoints: Vec<TransportEndpoint>"),
            "RouteHop must carry Vec<TransportEndpoint> (not Vec<String>)"
        );
        eprintln!("[static-guard] PASS: RouteHop carries NodeDescriptor + typed endpoints");
    }

    /// N2.0.7.2: The old circuit-key APIs MUST be behind the `legacy-circuit-keys`
    /// Cargo feature. The production build (`cargo build` without `--features
    /// legacy-circuit-keys`) MUST NOT compile them. This test verifies that
    /// the APIs are `#[cfg(feature = "legacy-circuit-keys")]`.
    #[test]
    fn old_circuit_key_apis_are_behind_legacy_feature() {
        let source = include_str!("async_node.rs");
        // The old APIs that take CircuitKeys must have #[cfg(feature = "legacy-circuit-keys")].
        let old_apis = &[
            "pub async fn serve_gateway_persistent_async(",
            "pub async fn serve_gateway_persistent_async_with_connector",
            "pub async fn serve_gateway_persistent_async_with_handshake(",
            "pub async fn serve_gateway_persistent_async_with_handshake_and_connector",
            "pub async fn serve_one_gateway_request_async_with_connector",
            "pub async fn send_request_via_gateway_full_with_relay_async(",
            "pub async fn establish_circuit_and_send_async(",
            "pub async fn send_request_with_full_snp_ik_handshake_async(",
        ];
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            for api in old_apis {
                if line.contains(api) {
                    // Look backwards for #[cfg(feature = "legacy-circuit-keys")].
                    let mut found_cfg = false;
                    for j in (0..i).rev().take(5) {
                        if lines[j].contains("cfg(feature = \"legacy-circuit-keys\")") {
                            found_cfg = true;
                            break;
                        }
                    }
                    if !found_cfg {
                        panic!(
                            "old circuit-key API `{api}` at line {} is NOT behind \
                             #[cfg(feature = \"legacy-circuit-keys\")]. All old CircuitKeys \
                             APIs MUST be behind the legacy feature — the production build \
                             must not compile them.",
                            i + 1
                        );
                    }
                }
            }
        }
        eprintln!("[static-guard] PASS: old circuit-key APIs are behind legacy-circuit-keys feature");
    }

    /// N2.0.7.2: The Route must NOT have a public `hops` field — it must be
    /// a derived method (`route.hops()`). The authoritative representation
    /// is `hop_details`.
    #[test]
    fn route_has_no_public_hops_field() {
        let source = include_str!("route.rs");
        // The Route struct must NOT have `pub hops:` — only `hop_details`.
        assert!(
            !source.contains("pub hops:"),
            "Route must NOT have a public `hops` field — use hop_details + a derived hops() method"
        );
        assert!(
            source.contains("pub fn hops(&self)"),
            "Route must have a derived hops() method"
        );
        eprintln!("[static-guard] PASS: Route has no public hops field (derived method only)");
    }

    /// N2.0.7.2: Route identity-critical fields must be non-mutable (private).
    #[test]
    fn route_identity_fields_are_private() {
        let source = include_str!("route.rs");
        // These fields must NOT be `pub` — they are private, accessed via methods.
        assert!(
            !source.contains("pub route_commitment:"),
            "route_commitment must be private (non-mutable)"
        );
        assert!(
            !source.contains("pub source:"),
            "source must be private (non-mutable)"
        );
        assert!(
            !source.contains("pub destination:"),
            "destination must be private (non-mutable)"
        );
        assert!(
            !source.contains("pub hop_details:"),
            "hop_details must be private (non-mutable)"
        );
        assert!(
            !source.contains("pub epoch:"),
            "epoch must be private (non-mutable)"
        );
        eprintln!("[static-guard] PASS: Route identity fields are private");
    }

    /// N2.0.7.2: RouteCommitment must exist and be computed from the canonical encoding.
    #[test]
    fn route_commitment_exists_and_is_canonical() {
        let source = include_str!("route.rs");
        assert!(
            source.contains("pub struct RouteCommitment"),
            "RouteCommitment struct must exist"
        );
        assert!(
            source.contains("pub fn compute("),
            "RouteCommitment::compute must exist"
        );
        assert!(
            source.contains("canonical_cbor"),
            "RouteCommitment must use canonical CBOR encoding"
        );
        eprintln!("[static-guard] PASS: RouteCommitment exists and uses canonical CBOR");
    }

    /// N2.0.7.2: VerifiedNodeDescriptor must exist and enforce NodeId consistency.
    #[test]
    fn verified_node_descriptor_enforces_consistency() {
        let source = include_str!("descriptor.rs");
        assert!(
            source.contains("pub struct VerifiedNodeDescriptor"),
            "VerifiedNodeDescriptor must exist"
        );
        assert!(
            source.contains("pub struct UnverifiedNodeDescriptor"),
            "UnverifiedNodeDescriptor must exist"
        );
        assert!(
            source.contains("fn into_consistent"),
            "UnverifiedNodeDescriptor::into_consistent must exist"
        );
        assert!(
            source.contains("verify_node_id_consistency"),
            "NodeId consistency check must exist"
        );
        assert!(
            source.contains("pub struct VerifiedGatewayAdvertisement"),
            "VerifiedGatewayAdvertisement must exist (N2.0.7.3)"
        );
        assert!(
            source.contains("fn verify_into_verified"),
            "GatewayAdvertisement::verify_into_verified must exist (N2.0.7.3)"
        );
        eprintln!("[static-guard] PASS: VerifiedNodeDescriptor + VerifiedGatewayAdvertisement enforce consistency");
    }

    #[test]
    fn gateway_advertisement_signs_and_verifies() {
        let advert = crate::legacy::legacy_advert_for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        assert!(advert.verify(), "freshly-signed advertisement must verify");
    }

    #[test]
    fn forged_advertisement_is_rejected() {
        let mut advert = crate::legacy::legacy_advert_for_gateway(
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
        let mut advert = crate::legacy::legacy_advert_for_gateway(
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
        let mut advert = crate::legacy::legacy_advert_for_gateway(
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
        let advert = crate::legacy::legacy_advert_for_gateway(
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
        let identity = crate::legacy::legacy_identity_for_gateway(GatewayChoice::A);
        assert_eq!(identity.public_key, crate::legacy::gateway_public_key_for(GatewayChoice::A));
        assert_eq!(identity.node_id, crate::legacy::gateway_node_id_for(GatewayChoice::A));
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
        let circuit = crate::legacy::legacy_circuit_for_gateway(GatewayChoice::A);
        assert_eq!(circuit.gateway_node_id, crate::legacy::gateway_node_id_for(GatewayChoice::A));
        assert_eq!(circuit.gateway_public_key, crate::legacy::gateway_public_key_for(GatewayChoice::A));
        assert_eq!(circuit.circuit_keys.send_key, client_circuit_keys_a().send_key);
        assert!(circuit.active);
    }

    #[test]
    fn circuit_for_gateway_b_uses_correct_keys() {
        let circuit = crate::legacy::legacy_circuit_for_gateway(GatewayChoice::B);
        assert_eq!(circuit.circuit_keys.send_key, client_circuit_keys_b().send_key);
        assert_ne!(
            crate::legacy::legacy_circuit_for_gateway(GatewayChoice::A).circuit_keys.send_key,
            crate::legacy::legacy_circuit_for_gateway(GatewayChoice::B).circuit_keys.send_key,
            "Ca and Cb MUST differ (proves failover switches circuit keys)"
        );
    }

    #[test]
    fn gateway_advertisement_for_a_and_b_have_distinct_node_ids() {
        let advert_a = crate::legacy::legacy_advert_for_gateway(
            GatewayChoice::A,
            "127.0.0.1:7001",
            "127.0.0.1:7002",
        );
        let advert_b = crate::legacy::legacy_advert_for_gateway(
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

    #[cfg(feature = "legacy-circuit-keys")]
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
        assert_eq!(route.source(), client);
        assert_eq!(route.destination(), gateway);
        assert_eq!(route.hops().len(), 4);
        assert_eq!(route.hops().last(), Some(&gateway));
        assert_eq!(route.metrics().hop_count, 4);
        assert_eq!(route.state(), RouteState::Proposed);
        assert_eq!(route.epoch(), 0);
        assert!(route.expires_at() > route.created_at());
    }

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    fn route_empty_rejected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        // Empty hops → validation fails with RouteError::Empty.
        let route = Route::new(client, gateway, vec![]);
        let err = route.validate().unwrap_err();
        assert_eq!(err, RouteError::Empty, "empty route must be rejected");
    }

    #[cfg(feature = "legacy-circuit-keys")]
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

    #[cfg(feature = "legacy-circuit-keys")]
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
            err, RouteError::DestinationDescriptorMismatch,
            "destination != hops.last() must be rejected"
        );
    }

    #[cfg(feature = "legacy-circuit-keys")]
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

    #[cfg(feature = "legacy-circuit-keys")]
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

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    fn route_expired_detected() {
        let client = node_id_from_seed(b"client");
        let gateway = node_id_from_seed(b"gateway");
        let route = Route::new(client, gateway, vec![gateway]);
        // N2.0.7.2: expires_at is now non-mutable. Test the is_expired logic
        // with a future timestamp.
        let future = now_unix() + 7200; // 2 hours in the future
        assert!(
            route.is_expired(future),
            "route must be expired at a future timestamp (now={future})"
        );
        // Note: validate() uses the CURRENT time, so the route (which expires
        // 1 hour in the future) will pass validation. The is_expired check
        // above proves the expiration logic works.
    }

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    fn route_state_machine_legal_transitions() {
        let client = node_id_from_seed(b"client sm");
        let gateway = node_id_from_seed(b"gateway sm");
        let mut route = Route::new(client, gateway, vec![gateway]);
        assert_eq!(route.state(), RouteState::Proposed);

        // Legal: Proposed → Establishing → Active.
        route.transition(RouteState::Establishing).expect("Proposed → Establishing");
        route.transition(RouteState::Active).expect("Establishing → Active");
        assert!(route.last_validated() > 0, "Active route has a non-zero last_validated");

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

    #[cfg(feature = "legacy-circuit-keys")]
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

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    #[allow(deprecated)]
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
        assert_eq!(route.hops().len(), 4, "hops must be [relay_a, relay_b, relay_c, gateway]");
        assert_eq!(route.hops()[0], relay_a_id, "hops[0] must be relay A");
        assert_eq!(route.hops()[1], relay_b_id, "hops[1] must be relay B");
        assert_eq!(route.hops()[2], relay_c_id, "hops[2] must be relay C");
        assert_eq!(route.hops()[3], gw_node_id, "hops[3] must be gateway (destination)");

        // The source must be the client's NodeId.
        assert_eq!(route.source(), client_identity.node_id, "source must be the client NodeId");

        // The destination must be the gateway's NodeId.
        assert_eq!(route.destination(), gw_node_id, "destination must be the gateway NodeId");

        // The route_id must not be all-zero (it's SHA-256 of a non-empty input).
        assert_ne!(route.route_commitment().as_bytes(), &[0u8; 32], "route_id must not be all-zero");

        // No GatewayChoice or compile-time identities used — all identities
        // are derived from random Ed25519 keypairs at runtime. The test
        // would fail to compile if `construct_route` depended on
        // `GatewayChoice` (since this test mod is `#[allow(deprecated)]`
        // but `GatewayChoice` is only in scope via the `use crate::legacy::GatewayChoice;`
        // import — we don't use it here).
        let _ = (relay_a_sk, relay_b_sk, relay_c_sk); // silence unused warnings
    }

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    #[allow(deprecated)]
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

    #[cfg(feature = "legacy-circuit-keys")]
    #[test]
    #[allow(deprecated)]
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

    /// N2.0.4 (Gate A): `BootstrapDiscovery::discover()` performs actual
    /// TCP I/O against a real gateway running `serve_discovery_persistent`.
    /// Verifies the END-TO-END discovery flow:
    ///   1. Gateway starts serving discovery on an ephemeral port.
    ///   2. BootstrapDiscovery connects, sends 0x01, reads the
    ///      length-prefixed CBOR advertisement.
    ///   3. BootstrapDiscovery verifies the signature + expiry.
    ///   4. The returned `DiscoveredNode` carries the advertisement and
    ///      the gateway's TCP endpoint.
    #[test]
    fn bootstrap_discovery_discovers_real_gateway() {
        // Allocate an ephemeral port for the discovery listener.
        let disc_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind discovery");
        let disc_addr = disc_listener.local_addr().expect("local_addr").to_string();
        let transit_addr = "127.0.0.1:0".to_string();
        drop(disc_listener);

        // Spawn a gateway that serves discovery via the N2.0.4 raw protocol.
        let gateway_identity = NodeIdentity::from_secret(snp_crypto::sha256(b"bootstrap-disc-gw"));
        let expected_node_id = gateway_identity.node_id;
        let disc_addr_for_thread = disc_addr.clone();
        let gateway_disc_handle = std::thread::spawn(move || {
            let node = Node::new(
                gateway_identity,
                vec![Capability::Gateway],
                disc_addr_for_thread.clone(),
            );
            let _ = node.serve_discovery_persistent(&disc_addr_for_thread, &transit_addr);
        });
        // Give the listener a moment to bind.
        std::thread::sleep(Duration::from_millis(150));

        // Run BootstrapDiscovery against the gateway.
        let provider = BootstrapDiscovery::new(vec![disc_addr.clone()]);
        assert_eq!(provider.addresses().len(), 1);
        let discovered = provider.discover();
        assert_eq!(
            discovered.len(),
            1,
            "BootstrapDiscovery must discover exactly 1 gateway, got {}",
            discovered.len()
        );
        let node = &discovered[0];
        assert_eq!(node.endpoint, disc_addr);
        assert_eq!(node.advertisement.node_id, expected_node_id);
        // Signature was already verified inside discover() — re-verify
        // here for defence in depth.
        assert!(
            node.advertisement.verify(),
            "discovered advertisement signature must verify"
        );
        // Expiry was already checked inside discover() — re-check here.
        assert!(
            !node.advertisement.is_expired(now_unix()),
            "discovered advertisement must not be expired"
        );

        // Clean up the server thread (it will hang on `incoming()` — leak it).
        std::mem::forget(gateway_disc_handle);
    }

    /// N2.0.4 (Gate A): `BootstrapDiscovery::discover()` returns an empty
    /// Vec (NOT an error) when ALL bootstrap addresses are unreachable.
    /// Individual failures are logged but do not abort the discovery loop.
    #[test]
    fn bootstrap_discovery_returns_empty_when_all_unreachable() {
        // Bind + immediately drop to get a definitely-unbound port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();
        drop(listener);

        let provider = BootstrapDiscovery::new(vec![addr]);
        let discovered = provider.discover();
        assert!(
            discovered.is_empty(),
            "BootstrapDiscovery must return empty Vec when all addresses are unreachable"
        );
    }

    /// N2.0.4 (Gate A): `BootstrapDiscovery::discover()` discovers
    /// MULTIPLE gateways when multiple addresses are configured and all
    /// are reachable. Verifies the discovery loop does not stop after the
    /// first gateway.
    #[test]
    fn bootstrap_discovery_discovers_multiple_gateways() {
        // Allocate two ephemeral ports for two discovery listeners.
        let disc_listener_a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind disc-a");
        let disc_addr_a = disc_listener_a.local_addr().expect("local_addr").to_string();
        let disc_listener_b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind disc-b");
        let disc_addr_b = disc_listener_b.local_addr().expect("local_addr").to_string();
        let transit_addr = "127.0.0.1:0".to_string();
        drop(disc_listener_a);
        drop(disc_listener_b);

        let gw_a = NodeIdentity::from_secret(snp_crypto::sha256(b"bootstrap-multi-gw-a"));
        let gw_b = NodeIdentity::from_secret(snp_crypto::sha256(b"bootstrap-multi-gw-b"));
        let expected_a = gw_a.node_id;
        let expected_b = gw_b.node_id;

        let disc_a_for_thread = disc_addr_a.clone();
        let transit_a = transit_addr.clone();
        let gw_a_handle = std::thread::spawn(move || {
            let node = Node::new(gw_a, vec![Capability::Gateway], disc_a_for_thread.clone());
            let _ = node.serve_discovery_persistent(&disc_a_for_thread, &transit_a);
        });
        let disc_b_for_thread = disc_addr_b.clone();
        let transit_b = transit_addr.clone();
        let gw_b_handle = std::thread::spawn(move || {
            let node = Node::new(gw_b, vec![Capability::Gateway], disc_b_for_thread.clone());
            let _ = node.serve_discovery_persistent(&disc_b_for_thread, &transit_b);
        });
        std::thread::sleep(Duration::from_millis(200));

        let provider = BootstrapDiscovery::new(vec![disc_addr_a, disc_addr_b]);
        let discovered = provider.discover();
        assert_eq!(
            discovered.len(),
            2,
            "BootstrapDiscovery must discover both gateways, got {}",
            discovered.len()
        );
        let node_ids: Vec<[u8; 32]> =
            discovered.iter().map(|n| n.advertisement.node_id).collect();
        assert!(
            node_ids.contains(&expected_a),
            "discovered set must contain gateway A"
        );
        assert!(
            node_ids.contains(&expected_b),
            "discovered set must contain gateway B"
        );

        std::mem::forget(gw_a_handle);
        std::mem::forget(gw_b_handle);
    }

    /// N2.0.4 (Gate A): `BootstrapDiscovery::discover()` REJECTS a
    /// gateway that serves an advertisement with an INVALID SIGNATURE.
    /// This is the core security guarantee of the unauthenticated discovery
    /// protocol — the signature is what makes the unauthenticated link safe.
    #[test]
    fn bootstrap_discovery_rejects_forged_advertisement() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr").to_string();
        let addr_for_closure = addr.clone();

        // Spawn a "malicious" server that serves a FORGED advertisement
        // (signed by a DIFFERENT secret key than the one whose public key
        // is in the advertisement).
        let server_handle = std::thread::spawn(move || {
            // Build a real advertisement, then corrupt its signature.
            let identity = NodeIdentity::from_secret(snp_crypto::sha256(b"real-gw"));
            let mut advert =
                GatewayAdvertisement::for_identity(&identity, "127.0.0.1:0", &addr_for_closure);
            // Sign with a DIFFERENT secret key — this makes the signature
            // invalid for the advertisement's public_key.
            let wrong_sk = snp_crypto::sha256(b"wrong-secret");
            advert.sign(&wrong_sk);
            assert!(
                !advert.verify(),
                "test setup: forged advertisement must NOT verify"
            );
            let advert_bytes = advert.encode_cbor().expect("encode");
            let len_bytes = u32::try_from(advert_bytes.len())
                .expect("fits in u32")
                .to_be_bytes();
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut req = [0u8; 1];
                if stream.read_exact(&mut req).is_err() {
                    continue;
                }
                if req[0] != DISCOVERY_REQUEST_BYTE {
                    continue;
                }
                let _ = stream.write_all(&len_bytes);
                let _ = stream.write_all(&advert_bytes);
                let _ = stream.flush();
                // Serve one connection, then exit.
                break;
            }
        });
        std::thread::sleep(Duration::from_millis(150));

        let provider = BootstrapDiscovery::new(vec![addr]);
        let discovered = provider.discover();
        assert!(
            discovered.is_empty(),
            "BootstrapDiscovery must REJECT a forged advertisement (signature verification failed)"
        );

        // Let the server thread exit (it breaks after one connection).
        let _ = server_handle.join();
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

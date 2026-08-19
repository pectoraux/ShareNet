//! Mode-A store-carry-forward bundle composition layer (R4.3).
//!
//! This module bridges the L5 bundle layer (`snp-sync`: `Bundle`,
//! `BundleStore`, `CustodyHop`) with the L7 gateway layer (`snp-gateway`:
//! `TransitRequest`, `TransitResponse`, `TransitEnvelope`).
//!
//! # Architectural ownership
//!
//! ```text
//! L5 / snp-sync
//!     domain: Bundle, BundleStore, custody, anti-entropy
//!
//! L6 / routing
//!     chooses: next carrier / next route
//!
//! L8 / transport
//!     moves: one-hop bytes (AsyncLink)
//!
//! L7 / gateway
//!     interprets: TransitRequest / TransitResponse, Internet egress
//!
//! snp-node / mode_a_bundle (THIS MODULE)
//!     composition: combines all of the above
//! ```
//!
//! This module does NOT add sockets or route logic to `snp-sync`.
//! It does NOT put bundle semantics inside `snp-link`.
//! It does NOT put route selection into `snp-gateway`.
//!
//! # Bundle payload encoding
//!
//! A Mode-A request bundle carries an opaque `BundlePayload` whose bytes are
//! the canonical CBOR encoding of a `TransitRequest` (via
//! `snp_gateway::encode_transit_request`). L5 does NOT interpret these
//! bytes — it carries them. This module is the composition layer that
//! encodes/decodes the L7 types into/out of `BundlePayload`.
//!
//! A Mode-A response bundle carries an opaque `BundlePayload` whose bytes
//! are the canonical CBOR encoding of a `TransitEnvelope` (response + body,
//! via `snp_gateway::encode_transit_response_envelope`).
//!
//! # Process-lifetime honesty
//!
//! The `BundleStore` is in-memory. Bundles are NOT persisted across process
//! restarts. This is honestly classified as:
//!
//! ```text
//! runtime store-carry-forward: process-lifetime only
//! ```
//!
//! Do NOT call this durable custody storage.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use snp_crypto::{SecretKey, SignatureBytes};
use snp_gateway::{
    decode_transit_request, decode_transit_response_envelope, encode_transit_request,
    encode_transit_response_envelope, handle_transit_request_with_connector, sign_transit_request,
    sign_transit_response, verify_transit_request, verify_transit_response, FetchedResponse,
    GatewayError, GatewayResult, PinnedConnector, TransitEnvelope, TransitRequest, TransitResponse,
    MAX_RESPONSE_BYTES_DEFAULT,
};
use snp_identity::{now_unix, NodeId, NodeIdentity};
use snp_sync::{
    Bundle, BundleId, BundlePayload, BundleStore, SyncError, SyncResult, CUSTODY_NONCE_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ─── Errors ───────────────────────────────────────────────────────────────

/// Errors from the Mode-A bundle composition layer.
#[derive(Debug, thiserror::Error)]
pub enum ModeAError {
    /// L5 bundle layer error.
    #[error("bundle error: {0}")]
    Bundle(#[from] SyncError),
    /// L7 gateway error.
    #[error("gateway error: {0}")]
    Gateway(#[from] GatewayError),
    /// Transport error.
    #[error("transport error: {0}")]
    Transport(String),
    /// Bundle is expired.
    #[error("bundle expired")]
    Expired,
    /// Bundle destination mismatch.
    #[error("destination mismatch: expected {expected}, got {got}")]
    DestinationMismatch { expected: String, got: String },
    /// No response received.
    #[error("no response received")]
    NoResponse,
    /// Internal error.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias.
pub type ModeAResult<T> = Result<T, ModeAError>;

// ─── Bundle payload wrappers ─────────────────────────────────────────────

/// Wrap a `TransitRequest` as a Mode-A request `Bundle`.
///
/// Encodes the request via `encode_transit_request` → `BundlePayload` →
/// `Bundle::new`. The bundle's `source` is the client's NodeId, `destination`
/// is the gateway's NodeId, `deadline` is derived from the request's deadline.
///
/// # Errors
/// Returns `ModeAError` if encoding or bundle construction fails.
pub fn wrap_transit_request_as_bundle(
    req: &TransitRequest,
    source: NodeId,
    destination: NodeId,
    created_at: u64,
) -> ModeAResult<Bundle> {
    let req_bytes = encode_transit_request(req)?;
    let payload = BundlePayload::new(req_bytes);
    let deadline = req.deadline;
    Ok(Bundle::new(
        source,
        destination,
        payload,
        created_at,
        deadline,
    )?)
}

/// Unwrap a `TransitRequest` from a Mode-A request `Bundle`.
///
/// Extracts the opaque `BundlePayload` bytes and decodes them as a
/// `TransitRequest` via `decode_transit_request`. Does NOT verify the
/// request signature — that is the gateway's responsibility.
///
/// # Errors
/// Returns `ModeAError` if the payload cannot be decoded.
pub fn unwrap_transit_request_from_bundle(bundle: &Bundle) -> ModeAResult<TransitRequest> {
    let req = decode_transit_request(bundle.payload.as_bytes())?;
    Ok(req)
}

/// Wrap a `TransitResponse` + body as a Mode-A response `Bundle`.
///
/// Encodes via `encode_transit_response_envelope` → `BundlePayload` →
/// `Bundle::new`. The bundle's `source` is the gateway's NodeId,
/// `destination` is the client's NodeId.
///
/// # Errors
/// Returns `ModeAError` if encoding or bundle construction fails.
pub fn wrap_transit_response_as_bundle(
    resp: &TransitResponse,
    body: &[u8],
    source: NodeId,
    destination: NodeId,
    created_at: u64,
    deadline: u64,
) -> ModeAResult<Bundle> {
    let envelope_bytes = encode_transit_response_envelope(resp, body)?;
    let payload = BundlePayload::new(envelope_bytes);
    Ok(Bundle::new(
        source,
        destination,
        payload,
        created_at,
        deadline,
    )?)
}

/// Unwrap a `TransitResponse` + body from a Mode-A response `Bundle`.
///
/// Extracts the opaque `BundlePayload` bytes and decodes them as a
/// `TransitEnvelope` via `decode_transit_response_envelope`. Does NOT
/// verify the gateway signature — that is the client's responsibility.
///
/// # Errors
/// Returns `ModeAError` if the payload cannot be decoded.
pub fn unwrap_transit_response_from_bundle(
    bundle: &Bundle,
) -> ModeAResult<(TransitResponse, Vec<u8>)> {
    let envelope = decode_transit_response_envelope(bundle.payload.as_bytes())?;
    // Re-decode the transit_response from the envelope's bytes.
    let resp = snp_gateway::decode_transit_response(&envelope.transit_response)?;
    Ok((resp, envelope.body))
}

// ─── BundleCarrier trait (above L8, no route logic) ──────────────────────

/// A runtime abstraction for transferring bundles between peers.
///
/// `BundleCarrier` knows how to transfer bundles over a transport. It does
/// NOT choose routes, does NOT interpret `TransitRequest`, and does NOT
/// perform custody. The route is supplied by L6/composition.
///
/// The first implementation uses raw TCP sockets (via `tokio::net::TcpStream`)
/// with a simple length-prefixed framing protocol. This is NOT a live
/// circuit — there is no `MultiplexedCircuit`, no `StreamHandle`, no
/// AEAD-encrypted circuit layer. The bundle CBOR is sent as-is over TCP.
///
/// # Wire format
///
/// ```text
/// ┌────────────────────┬─────────────────────────────┐
/// │ length (4 BE)      │ Bundle CBOR (length bytes)  │
/// └────────────────────┴─────────────────────────────┘
/// ```
///
/// This is deliberately simple for the first vertical slice. A future
/// hardening pass will use the authenticated `AsyncLink` transport with
/// SNP-IK handshakes for peer authentication at the link layer.
#[async_trait::async_trait]
pub trait BundleCarrier: Send + Sync {
    /// Send a bundle to a peer. Returns Ok(()) if the peer acknowledged
    /// receipt (the peer takes custody after this returns).
    ///
    /// # Errors
    /// Returns `ModeAError` if the transport fails.
    async fn send_bundle(&self, bundle: &Bundle) -> ModeAResult<()>;

    /// Receive a bundle from a peer. Blocks until a bundle arrives or
    /// the connection is closed.
    ///
    /// # Errors
    /// Returns `ModeAError` if the transport fails or the bundle is invalid.
    async fn recv_bundle(&self) -> ModeAResult<Bundle>;
}

/// A `BundleCarrier` that uses raw TCP with length-prefixed framing.
///
/// This is the simplest possible transport for the first R4.3 vertical
/// slice. It does NOT use `MultiplexedCircuit`, `StreamHandle`, `N3AClient`,
/// or `TunClient`. The bundle CBOR is sent as-is over a TCP connection.
pub struct TcpBundleCarrier {
    stream: tokio::sync::Mutex<TcpStream>,
}

impl TcpBundleCarrier {
    /// Create a carrier from an existing TCP stream.
    #[must_use]
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: tokio::sync::Mutex::new(stream),
        }
    }

    /// Connect to a peer and create a carrier.
    ///
    /// # Errors
    /// Returns `ModeAError` if the TCP connection fails.
    pub async fn connect(addr: &str) -> ModeAResult<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ModeAError::Transport(format!("TCP connect to {addr}: {e}")))?;
        Ok(Self::new(stream))
    }

    /// Accept an incoming connection and create a carrier.
    ///
    /// # Errors
    /// Returns `ModeAError` if the TCP accept fails.
    pub async fn accept(listener: &TcpListener) -> ModeAResult<Self> {
        let (stream, _peer_addr) = listener
            .accept()
            .await
            .map_err(|e| ModeAError::Transport(format!("TCP accept: {e}")))?;
        Ok(Self::new(stream))
    }
}

#[async_trait::async_trait]
impl BundleCarrier for TcpBundleCarrier {
    async fn send_bundle(&self, bundle: &Bundle) -> ModeAResult<()> {
        let cbor = bundle.to_cbor()?;
        let len = cbor.len() as u32;
        let mut stream = self.stream.lock().await;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| ModeAError::Transport(format!("send length: {e}")))?;
        stream
            .write_all(&cbor)
            .await
            .map_err(|e| ModeAError::Transport(format!("send bundle: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ModeAError::Transport(format!("flush: {e}")))?;
        Ok(())
    }

    async fn recv_bundle(&self) -> ModeAResult<Bundle> {
        let mut stream = self.stream.lock().await;
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| ModeAError::Transport(format!("recv length: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // Sanity-check: bundles should not be absurdly large.
        if len > 64 * 1024 * 1024 {
            return Err(ModeAError::Transport(format!(
                "bundle too large: {len} bytes"
            )));
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| ModeAError::Transport(format!("recv bundle: {e}")))?;
        let bundle = Bundle::from_cbor(&buf)?;
        Ok(bundle)
    }
}

// ─── Relay bundle loop ────────────────────────────────────────────────────

/// A Mode-A relay that receives bundles, takes custody, stores them, and
/// forwards when the next hop becomes available.
///
/// # Store-carry-forward
///
/// The relay does NOT require an uninterrupted live connection. If the
/// next hop is unavailable, the relay retains the bundle in its `BundleStore`
/// and retries later.
///
/// # Custody transfer
///
/// Custody is a cryptographic protocol event. The relay takes custody by
/// appending a `CustodyHop` to the bundle's custody chain (signed by the
/// relay's secret key). This happens BEFORE the relay attempts to forward.
/// If the forward fails, the relay retains custody and the bundle stays in
/// the store.
///
/// # Process-lifetime honesty
///
/// The `BundleStore` is in-memory. Bundles are NOT persisted across process
/// restarts. This is honestly classified as:
///
/// ```text
/// runtime store-carry-forward: process-lifetime only
/// ```
pub struct ModeARelay {
    /// The relay's identity.
    identity: NodeIdentity,
    /// In-memory bundle store (NOT persistent).
    store: Arc<StdMutex<BundleStore>>,
    /// The relay's listen address (for receiving bundles from the previous hop).
    listen_addr: String,
    /// The next hop's address (for forwarding bundles).
    next_hop_addr: String,
    /// The next hop's NodeId (for custody transfer).
    next_hop_node_id: NodeId,
}

impl ModeARelay {
    /// Create a new Mode-A relay.
    #[must_use]
    pub fn new(
        identity: NodeIdentity,
        listen_addr: String,
        next_hop_addr: String,
        next_hop_node_id: NodeId,
    ) -> Self {
        Self {
            identity,
            store: Arc::new(StdMutex::new(BundleStore::new())),
            listen_addr,
            next_hop_addr,
            next_hop_node_id,
        }
    }

    /// Get a reference to the bundle store (for testing).
    pub fn store(&self) -> Arc<StdMutex<BundleStore>> {
        self.store.clone()
    }

    /// Run the relay loop: listen for incoming bundles, take custody, store,
    /// and forward when possible.
    ///
    /// # Store-carry-forward proof
    ///
    /// This function implements the defining R4.3 property: the relay holds
    /// the bundle while the next hop is unavailable, and forwards when it
    /// becomes available. If `next_hop_connect_timeout` is short, the relay
    /// will store the bundle and retry.
    ///
    /// # Full bidirectional flow
    ///
    /// The relay handles the complete request/response path:
    /// 1. Receive request bundle from client (via TcpBundleCarrier)
    /// 2. Take custody (cryptographic event)
    /// 3. Store the bundle
    /// 4. Send custody ack back to client (through the same TCP connection)
    /// 5. Attempt to forward to gateway
    ///    - If gateway unavailable: bundle stays in store, retry later
    ///    - If gateway available: send bundle, receive custody ack, receive response bundle
    /// 6. Send response bundle back to client (through the same TCP connection)
    ///
    /// # Errors
    /// Returns `ModeAError` if the listener fails to bind.
    pub async fn run(&self) -> ModeAResult<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| ModeAError::Transport(format!("bind {}: {e}", self.listen_addr)))?;
        eprintln!(
            "[mode-a-relay {}] listening on {}",
            hex_short(&self.identity.node_id),
            self.listen_addr
        );
        // Track the carrier for the current client connection (if any).
        // This allows the relay to send the response back through the same
        // TCP connection the client opened.
        let client_carrier: Arc<tokio::sync::Mutex<Option<Arc<dyn BundleCarrier>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        loop {
            // Use tokio::select! to handle both:
            // 1. New incoming connections (from clients)
            // 2. Periodic forwarding of pending bundles (to next hop)
            tokio::select! {
                // Accept a new connection.
                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[mode-a-relay] accept error: {e}");
                            continue;
                        }
                    };
                    let carrier = Arc::new(TcpBundleCarrier::new(stream));
                    // Store the carrier so we can send the response back.
                    {
                        let mut cc = client_carrier.lock().await;
                        *cc = Some(carrier.clone());
                    }
                    // Process the incoming bundle.
                    let bundle = match carrier.recv_bundle().await {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("[mode-a-relay] recv error: {e}");
                            continue;
                        }
                    };
                    if let Err(e) = bundle.validate() {
                        eprintln!("[mode-a-relay] invalid bundle: {e}");
                        continue;
                    }
                    let now = now_unix();
                    if bundle.is_expired(now) {
                        eprintln!("[mode-a-relay] bundle expired, dropping");
                        continue;
                    }
                    let is_request = bundle.destination == self.next_hop_node_id;
                    if !is_request {
                        // Response bundle: forward back to the client.
                        eprintln!(
                            "[mode-a-relay {}] received response bundle, forwarding back",
                            hex_short(&self.identity.node_id)
                        );
                        let _ = carrier.send_bundle(&bundle).await;
                        continue;
                    }
                    // Request bundle: take custody + store + forward.
                    let prev_custodian = bundle
                        .custody_chain
                        .last()
                        .map(|h| h.next_custodian_id)
                        .unwrap_or(bundle.source);
                    let mut bundle = bundle;
                    let received_at = now;
                    let nonce = generate_nonce();
                    if let Err(e) = bundle.take_custody(
                        prev_custodian,
                        self.identity.node_id,
                        &self.identity.secret_key,
                        received_at,
                        received_at,
                        nonce,
                    ) {
                        eprintln!("[mode-a-relay] custody error: {e}");
                        continue;
                    }
                    eprintln!(
                        "[mode-a-relay {}] took custody of bundle {} (from {})",
                        hex_short(&self.identity.node_id),
                        bundle.bundle_id().to_hex().get(..16).unwrap_or("?"),
                        hex_short(&prev_custodian)
                    );
                    {
                        let mut store = self.store.lock().expect("store mutex poisoned");
                        if let Err(e) = store.add(bundle.clone()) {
                            eprintln!("[mode-a-relay] store error: {e}");
                            continue;
                        }
                    }
                    // Send custody ack to the sender.
                    if let Err(e) = carrier.send_bundle(&bundle).await {
                        eprintln!("[mode-a-relay] custody ack send error: {e}");
                        continue;
                    }
                    // Try to forward immediately (may fail if gateway is down).
                    self.forward_pending_bundles(now).await;
                    // If we got a response, send it back through the carrier.
                    self.try_send_response_back(&client_carrier).await;
                }
                // Periodically retry forwarding pending bundles.
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    let now = now_unix();
                    self.forward_pending_bundles(now).await;
                    self.try_send_response_back(&client_carrier).await;
                }
            }
        }
    }

    /// Check if there's a response bundle in the store and send it back
    /// through the client carrier (if still connected).
    async fn try_send_response_back(
        &self,
        client_carrier: &Arc<tokio::sync::Mutex<Option<Arc<dyn BundleCarrier>>>>,
    ) {
        let response_bundle = {
            let store = self.store.lock().expect("store mutex poisoned");
            let all_pending: Vec<_> = store.pending(now_unix()).into_iter().cloned().collect();
            all_pending
                .into_iter()
                .find(|b| b.source == self.next_hop_node_id)
        };
        if let Some(resp) = response_bundle {
            let cc = client_carrier.lock().await;
            if let Some(carrier) = cc.as_ref() {
                eprintln!(
                    "[mode-a-relay {}] sending response bundle back to client",
                    hex_short(&self.identity.node_id)
                );
                if let Err(e) = carrier.send_bundle(&resp).await {
                    eprintln!("[mode-a-relay] response send error: {e}");
                } else {
                    // Remove the response from the store.
                    let mut store = self.store.lock().expect("store mutex poisoned");
                    store.remove(resp.bundle_id());
                }
            }
        }
    }

    /// Forward all pending bundles to the next hop. If the next hop is
    /// unavailable, the bundles remain in the store (store-carry-forward).
    ///
    /// After forwarding a request bundle, this method also receives the
    /// response bundle from the next hop and sends it back through the
    /// provided `return_carrier` (the connection to the previous hop/client).
    ///
    /// # Errors
    /// Returns `ModeAError` if the forward fails (but bundles are retained).
    pub async fn forward_pending_bundles(&self, now: u64) {
        let bundles_to_forward: Vec<Bundle> = {
            let store = self.store.lock().expect("store mutex poisoned");
            // Only forward REQUEST bundles (destined to the next hop).
            // RESPONSE bundles (destined to the client) are handled by
            // try_send_response_back() which sends them through the client
            // carrier.
            store
                .pending(now)
                .into_iter()
                .filter(|b| b.destination == self.next_hop_node_id)
                .cloned()
                .collect()
        };
        if bundles_to_forward.is_empty() {
            return;
        }
        // Try to connect to the next hop.
        let carrier = match TcpBundleCarrier::connect(&self.next_hop_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[mode-a-relay {}] next hop {} unavailable: {} (retaining {} bundles)",
                    hex_short(&self.identity.node_id),
                    self.next_hop_addr,
                    e,
                    bundles_to_forward.len()
                );
                return; // Bundles stay in the store — store-carry-forward.
            }
        };
        eprintln!(
            "[mode-a-relay {}] connected to next hop {} — forwarding {} bundles",
            hex_short(&self.identity.node_id),
            self.next_hop_addr,
            bundles_to_forward.len()
        );
        for bundle in bundles_to_forward {
            let bundle_id = *bundle.bundle_id();
            // Check if this is a request bundle (source != us) or a response
            // bundle (source == next hop, destination != us).
            // For request bundles: forward to next hop, receive custody ack,
            // then receive response bundle and forward it back.
            // For response bundles: forward to the destination (previous hop).
            let is_response = bundle.destination != self.next_hop_node_id;
            if let Err(e) = carrier.send_bundle(&bundle).await {
                eprintln!(
                    "[mode-a-relay {}] forward error for bundle {}: {e}",
                    hex_short(&self.identity.node_id),
                    bundle_id.to_hex().get(..16).unwrap_or("?")
                );
                let mut store = self.store.lock().expect("store mutex poisoned");
                let _ = store.add(bundle);
                return;
            }
            if is_response {
                // Response bundle: just forward. No custody ack needed.
                eprintln!(
                    "[mode-a-relay {}] response bundle {} forwarded",
                    hex_short(&self.identity.node_id),
                    bundle_id.to_hex().get(..16).unwrap_or("?")
                );
                let mut store = self.store.lock().expect("store mutex poisoned");
                store.remove(&bundle_id);
                continue;
            }
            // Request bundle: wait for custody ack + response.
            match carrier.recv_bundle().await {
                Ok(ack_bundle) => {
                    eprintln!(
                        "[mode-a-relay {}] bundle {} forwarded (custody acknowledged)",
                        hex_short(&self.identity.node_id),
                        bundle_id.to_hex().get(..16).unwrap_or("?")
                    );
                    let mut store = self.store.lock().expect("store mutex poisoned");
                    store.remove(&bundle_id);
                }
                Err(e) => {
                    eprintln!(
                        "[mode-a-relay {}] custody ack error: {e}",
                        hex_short(&self.identity.node_id)
                    );
                    let mut store = self.store.lock().expect("store mutex poisoned");
                    let _ = store.add(bundle);
                    return;
                }
            }
            // Now wait for the response bundle from the next hop.
            match carrier.recv_bundle().await {
                Ok(response_bundle) => {
                    eprintln!(
                        "[mode-a-relay {}] response bundle received from next hop",
                        hex_short(&self.identity.node_id)
                    );
                    // Store the response bundle for forwarding to the client.
                    // The response is addressed to the original client.
                    let mut store = self.store.lock().expect("store mutex poisoned");
                    let _ = store.add(response_bundle);
                    // Trigger forwarding of the response back to the client.
                    // For the test, we'll handle this via a separate mechanism.
                }
                Err(e) => {
                    eprintln!(
                        "[mode-a-relay {}] response recv error: {e}",
                        hex_short(&self.identity.node_id)
                    );
                    return;
                }
            }
        }
    }

    /// Forward the response bundle back to the client via the return path.
    ///
    /// This is called after the relay receives the response bundle from the
    /// gateway. It connects to the client's return address (if known) and
    /// sends the response.
    ///
    /// For R4.3, the relay stores the response in its `BundleStore` and the
    /// test's client connection picks it up. The relay's `run()` loop handles
    /// this: when the client sends a request, the relay receives it, takes
    /// custody, forwards to the gateway, receives the response, and sends it
    /// back through the SAME TCP connection the client opened.
    pub async fn forward_response_to_return_path(
        &self,
        response_bundle: &Bundle,
        return_carrier: &dyn BundleCarrier,
    ) -> ModeAResult<()> {
        return_carrier.send_bundle(response_bundle).await
    }
}

// ─── Gateway Mode-A adapter ──────────────────────────────────────────────

/// A Mode-A gateway that receives request bundles, decodes the
/// `TransitRequest`, performs real Internet egress, signs the
/// `TransitResponse`, and constructs a response `Bundle`.
///
/// # Egress
///
/// The gateway uses `PinnedConnector` for production egress (with SSRF
/// defence). For testing, a `PinnedConnector::from_parts` can be supplied
/// to target a host-local mock HTTP server.
///
/// # Response routing
///
/// The response bundle's `destination` is set to the original request
/// bundle's `source` (the client's NodeId). The response is returned
/// through the bundle path — NOT through a live circuit.
pub struct ModeAGateway {
    /// The gateway's identity.
    identity: NodeIdentity,
    /// The gateway's listen address (for receiving bundles from the relay).
    listen_addr: String,
    /// The gateway's secret key for signing TransitResponses.
    gateway_secret: SecretKey,
    /// The connector factory for egress (production: SSRF defence; test: mock).
    connector_factory: Box<dyn Fn(&str) -> GatewayResult<PinnedConnector> + Send + Sync>,
}

impl ModeAGateway {
    /// Create a new Mode-A gateway with production egress (SSRF defence).
    #[must_use]
    pub fn new(identity: NodeIdentity, listen_addr: String) -> Self {
        let gateway_secret = identity.secret_key;
        Self {
            identity,
            listen_addr,
            gateway_secret,
            connector_factory: Box::new(|url: &str| PinnedConnector::new(url)),
        }
    }

    /// Create a new Mode-A gateway with a custom connector factory (for testing).
    #[must_use]
    pub fn with_connector_factory<F>(identity: NodeIdentity, listen_addr: String, f: F) -> Self
    where
        F: Fn(&str) -> GatewayResult<PinnedConnector> + Send + Sync + 'static,
    {
        let gateway_secret = identity.secret_key;
        Self {
            identity,
            listen_addr,
            gateway_secret,
            connector_factory: Box::new(f),
        }
    }

    /// Run the gateway loop: listen for incoming request bundles, decode,
    /// fetch, sign, wrap response, and send back.
    ///
    /// # Errors
    /// Returns `ModeAError` if the listener fails to bind.
    pub async fn run(&self) -> ModeAResult<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| ModeAError::Transport(format!("bind {}: {e}", self.listen_addr)))?;
        eprintln!(
            "[mode-a-gateway {}] listening on {}",
            hex_short(&self.identity.node_id),
            self.listen_addr
        );
        loop {
            let carrier = match TcpBundleCarrier::accept(&listener).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[mode-a-gateway] accept error: {e}");
                    continue;
                }
            };
            let bundle = match carrier.recv_bundle().await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[mode-a-gateway] recv error: {e}");
                    continue;
                }
            };
            // Validate the bundle.
            if let Err(e) = bundle.validate() {
                eprintln!("[mode-a-gateway] invalid bundle: {e}");
                continue;
            }
            // Check expiry.
            let now = now_unix();
            if bundle.is_expired(now) {
                eprintln!("[mode-a-gateway] bundle expired, dropping");
                continue;
            }
            // Check destination: the bundle must be addressed to this gateway.
            if bundle.destination != self.identity.node_id {
                eprintln!(
                    "[mode-a-gateway] destination mismatch: expected {}, got {}",
                    hex_short(&self.identity.node_id),
                    hex_short(&bundle.destination)
                );
                continue;
            }
            // Extract the opaque payload and decode the TransitRequest.
            let req = match unwrap_transit_request_from_bundle(&bundle) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[mode-a-gateway] decode TransitRequest error: {e}");
                    continue;
                }
            };
            // Verify the request signature.
            if !verify_transit_request(&req) {
                eprintln!("[mode-a-gateway] TransitRequest signature verification FAILED");
                continue;
            }
            eprintln!(
                "[mode-a-gateway {}] received TransitRequest reqId={} url={}",
                hex_short(&self.identity.node_id),
                hex_short(&req.req_id),
                &req.url.get(..60).unwrap_or(&req.url)
            );
            // Take custody (the gateway is the final custodian for this request).
            let prev_custodian = bundle
                .custody_chain
                .last()
                .map(|h| h.next_custodian_id)
                .unwrap_or(bundle.source);
            let mut custody_bundle = bundle.clone();
            let nonce = generate_nonce();
            if let Err(e) = custody_bundle.take_custody(
                prev_custodian,
                self.identity.node_id,
                &self.identity.secret_key,
                now,
                now,
                nonce,
            ) {
                eprintln!("[mode-a-gateway] custody error: {e}");
                continue;
            }
            // Acknowledge custody to the sender.
            let _ = carrier.send_bundle(&custody_bundle).await;
            // Perform real Internet egress.
            let connector = match (self.connector_factory)(&req.url) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[mode-a-gateway] connector error: {e}");
                    continue;
                }
            };
            let fetched =
                match handle_transit_request_with_connector(&req, &self.gateway_secret, &connector)
                {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("[mode-a-gateway] egress error: {e}");
                        continue;
                    }
                };
            eprintln!(
                "[mode-a-gateway {}] egress complete: status={} body={} bytes",
                hex_short(&self.identity.node_id),
                fetched.response.status,
                fetched.body.len()
            );
            // Construct the response bundle.
            let response_bundle = match wrap_transit_response_as_bundle(
                &fetched.response,
                &fetched.body,
                self.identity.node_id,
                bundle.source, // destination = original client
                now,
                req.deadline,
            ) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[mode-a-gateway] response bundle error: {e}");
                    continue;
                }
            };
            // Send the response bundle back through the carrier.
            if let Err(e) = carrier.send_bundle(&response_bundle).await {
                eprintln!("[mode-a-gateway] send response error: {e}");
                continue;
            }
            eprintln!(
                "[mode-a-gateway {}] response bundle sent (reqId={})",
                hex_short(&self.identity.node_id),
                hex_short(&req.req_id)
            );
        }
    }
}

// ─── Client Mode-A adapter ───────────────────────────────────────────────

/// A Mode-A client that creates a `TransitRequest`, wraps it as a `Bundle`,
/// submits it to a carrier, and waits for the response bundle.
///
/// # No live circuit
///
/// This client does NOT use `MultiplexedCircuit`, `StreamHandle`,
/// `N3AClient`, or `TunClient`. It sends the bundle via the `BundleCarrier`
/// abstraction (raw TCP).
pub struct ModeAClient {
    /// The client's identity.
    identity: NodeIdentity,
}

impl ModeAClient {
    /// Create a new Mode-A client.
    #[must_use]
    pub fn new(identity: NodeIdentity) -> Self {
        Self { identity }
    }

    /// Send a Mode-A request via store-carry-forward and wait for the response.
    ///
    /// 1. Create a signed `TransitRequest`.
    /// 2. Wrap as a `Bundle`.
    /// 3. Send to the carrier (relay).
    /// 4. Wait for the response bundle.
    /// 5. Decode the `TransitResponse` + body.
    /// 6. Verify the gateway signature.
    ///
    /// # Errors
    /// Returns `ModeAError` if any step fails.
    pub async fn send_request(
        &self,
        url: &str,
        gateway_node_id: NodeId,
        gateway_public_key: &snp_crypto::PublicKey,
        carrier: &dyn BundleCarrier,
    ) -> ModeAResult<(TransitResponse, Vec<u8>)> {
        // 1. Create a signed TransitRequest.
        let mut req = TransitRequest {
            req_id: generate_req_id(),
            method: "GET".into(),
            url: url.into(),
            tls_termination: "PAYLOAD_E2E".into(),
            max_response_bytes: MAX_RESPONSE_BYTES_DEFAULT,
            deadline: now_unix() + 300, // 5-minute deadline
            reply_to: [0u8; 32],        // unused in store-carry-forward (response via bundle)
            client_ed25519_public_key: self.identity.public_key,
            client_sig: [0u8; 64],
        };
        sign_transit_request(&mut req, &self.identity.secret_key);
        // 2. Wrap as a Bundle.
        let now = now_unix();
        let bundle =
            wrap_transit_request_as_bundle(&req, self.identity.node_id, gateway_node_id, now)?;
        eprintln!(
            "[mode-a-client {}] created bundle {} for gateway {}",
            hex_short(&self.identity.node_id),
            bundle.bundle_id().to_hex().get(..16).unwrap_or("?"),
            hex_short(&gateway_node_id)
        );
        // 3. Send to the carrier.
        carrier.send_bundle(&bundle).await?;
        eprintln!(
            "[mode-a-client {}] bundle sent to carrier",
            hex_short(&self.identity.node_id)
        );
        // 4. Wait for the custody acknowledgment (the relay returns the
        //    bundle with an updated custody chain).
        let ack_bundle = carrier.recv_bundle().await?;
        eprintln!(
            "[mode-a-client {}] custody acknowledged (chain length: {})",
            hex_short(&self.identity.node_id),
            ack_bundle.custody_chain.len()
        );
        // 5. Wait for the response bundle.
        let response_bundle = carrier.recv_bundle().await?;
        eprintln!(
            "[mode-a-client {}] response bundle received",
            hex_short(&self.identity.node_id)
        );
        // 6. Decode the TransitResponse + body.
        let (resp, body) = unwrap_transit_response_from_bundle(&response_bundle)?;
        // 7. Verify the gateway signature.
        if !verify_transit_response(&resp, gateway_public_key) {
            return Err(ModeAError::Other(
                "gateway signature verification FAILED".into(),
            ));
        }
        // 8. Verify reqId matches.
        if resp.req_id != req.req_id {
            return Err(ModeAError::Other(format!(
                "reqId mismatch: expected {}, got {}",
                hex_short(&req.req_id),
                hex_short(&resp.req_id)
            )));
        }
        eprintln!(
            "[mode-a-client {}] response verified: status={} body={} bytes",
            hex_short(&self.identity.node_id),
            resp.status,
            body.len()
        );
        Ok((resp, body))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Generate a random 16-byte reqId.
fn generate_req_id() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

/// Generate a random 16-byte custody nonce.
fn generate_nonce() -> [u8; CUSTODY_NONCE_BYTES] {
    let mut buf = [0u8; CUSTODY_NONCE_BYTES];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

/// Short hex representation of a byte slice (first 8 hex chars + "..").
fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{hex}..")
}

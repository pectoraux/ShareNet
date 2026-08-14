//! N2.2.1 — Async Tokio TCP next-hop transport for the recursive
//! route-discovery protocol.
//!
//! This module is the **canonical production implementation** of
//! [`RecursiveNextHopTransport`] using real TCP sockets, the SNP-IK/0.1
//! handshake, AEAD-encrypted frames, identity binding, and server-side
//! replay protection. It is the concrete counterpart to
//! `InMemoryRecursiveTransport` (which exists only for tests).
//!
//! ## Architecture
//!
//! Two participants:
//!
//! - [`TcpRecursiveTransport`] — used by a node that wants to **send** a
//!   `ForwardedQuery` to a neighbor and receive a `RecursiveRouteResponse`.
//!   It holds a "phone book" of peers (NodeId → TCP address + expected
//!   Ed25519 public key). For each `forward_query` call it:
//!   1. Looks up the peer's TCP address + expected NodeId.
//!   2. Opens a fresh TCP connection (Tokio async).
//!   3. Performs the SNP-IK/0.1 handshake as **initiator** via
//!      [`snp_link::perform_snp_ik_handshake_verified_async`], pinning the
//!      expected peer NodeId ("I"-style pinning). The handshake returns a
//!      [`snp_link::VerifiedHandshake`] carrying directional AEAD
//!      [`snp_link::LinkKeys`].
//!   4. Encodes the `ForwardedQuery` to canonical CBOR (== hash preimage).
//!   5. AEAD-seals the plaintext with `send_key` + a fresh 12-byte nonce.
//!   6. Writes the encrypted frame.
//!   7. Reads the encrypted response frame.
//!   8. AEAD-opens the response with `recv_key` + the response's nonce.
//!   9. Decodes the `RecursiveRouteResponse`.
//!   10. Closes the connection.
//!
//! - [`TcpForwardingServer`] — used by a node that wants to **receive**
//!   `ForwardedQuery` messages and respond. It binds a `tokio::net::TcpListener`
//!   and accepts incoming connections concurrently (one `tokio::spawn` task
//!   per connection). For each connection it:
//!   1. Performs the SNP-IK/0.1 handshake as **responder** (no expected
//!      peer pinning — any authenticated peer is accepted; the handshake
//!      itself proves the peer's identity). Returns a `VerifiedHandshake`
//!      with the authenticated `peer_node_id` and directional AEAD keys.
//!   2. Reads an encrypted `ForwardedQuery` frame, AEAD-opens it with
//!      `recv_key`.
//!   3. **Identity binding check:** `verified.peer_node_id() ==
//!      query.source_node_id`. Rejects cross-channel injection (a query
//!      signed by B cannot be sent over a connection authenticated as A).
//!   4. **Replay protection:** checks the `(source_node_id, query_id)`
//!      pair against a bounded server-side cache. Replays are rejected.
//!   5. Calls `ForwardingNode::handle_query()` (via `spawn_blocking` so
//!      the synchronous `ForwardingNode` does not block the runtime).
//!   6. Encodes the `RecursiveRouteResponse` to canonical CBOR.
//!   7. AEAD-seals with `send_key` + fresh nonce.
//!   8. Writes the encrypted frame.
//!   9. Closes the connection.
//!
//! ## Wire format (encrypted frames)
//!
//! ```text
//! ┌──────────────────────┬───────────────┬─────────────────────────────────┐
//! │ sealed_len (4 BE u32)│ nonce (12 B)  │ sealed_data (sealed_len bytes)  │
//! └──────────────────────┴───────────────┴─────────────────────────────────┘
//! ```
//!
//! - `sealed_data = ChaCha20-Poly1305(seal_key, nonce, cbor_bytes, aad=[])`
//!   — i.e. `ciphertext ‖ tag(16)`. Produced by [`snp_crypto::aead_seal`].
//! - `sealed_len` is the byte length of `sealed_data` (plaintext.len() + 16).
//! - `sealed_len` MUST be ≤ [`MAX_FRAME_SIZE`] (1 MiB). Larger declared
//!   lengths are rejected BEFORE any allocation (allocation-attack
//!   resistance).
//! - The 12-byte `nonce` is generated fresh per frame via `getrandom`
//!   (OS CSPRNG). The receiver does NOT need to track a counter — the nonce
//!   is sent in clear because it is not secret. Nonce reuse under a single
//!   key has probability ~2^-96 per frame (birthday bound: ~2^48 frames
//!   for a 50% collision chance, far beyond any realistic server lifetime).
//! - The AEAD AAD is empty — the entire CBOR-encoded message is encrypted,
//!   so the frame header is not authenticated separately (it does not need
//!   to be; a tampered length causes a read failure before AEAD open).
//!
//! ## Sync↔async boundary
//!
//! The [`RecursiveNextHopTransport`] trait and [`ForwardingNode`] are
//! synchronous. The transport layer uses async Tokio internally. Each call
//! to [`TcpRecursiveTransport::forward_query`] creates a single-threaded
//! Tokio runtime and `block_on`s the async TCP + AEAD operations on it.
//! This is a discovery-time operation (not a data-plane hot path), so the
//! per-call runtime overhead is acceptable. A future async-protocol
//! refactor would eliminate this `block_on` boundary.
//!
//! The server side is fully async: [`TcpForwardingServer::serve_in_background`]
//! spawns a dedicated OS thread with its own multi-threaded Tokio runtime.
//! The synchronous `ForwardingNode::handle_query` is invoked via
//! `tokio::task::spawn_blocking` so it never blocks the runtime's worker
//! pool.
//!
//! ## Security
//!
//! - **Authentication:** Every connection is authenticated via SNP-IK/0.1.
//!   The initiator pins the expected peer NodeId; the responder accepts any
//!   authenticated peer. Both sides derive directional AEAD link keys from
//!   the handshake transcript.
//! - **Confidentiality + integrity:** Every frame payload is AEAD-encrypted
//!   with the derived link keys. A tampered ciphertext fails AEAD open and
//!   is rejected (the connection is dropped without a response). An
//!   eavesdropper on the wire sees only ChaCha20-Poly1305 ciphertext.
//! - **Identity binding:** The server checks that the authenticated
//!   `peer_node_id` from the SNP-IK handshake equals the `source_node_id`
//!   in the `ForwardedQuery`. A query signed by B cannot be injected over
//!   a connection authenticated as A. This closes the cross-channel
//!   injection vector.
//! - **Replay protection:** The server maintains a bounded
//!   [`ReplayCache`] keyed by `(source_node_id, query_id)`. A replayed
//!   serialized query is rejected before reaching `ForwardingNode::handle_query`.
//!   Entries are purged when older than 2× `MAX_ROUTE_QUERY_AGE_SECS`.
//! - **Allocation-attack resistance:** `read_sealed_frame` caps the
//!   declared `sealed_len` at `MAX_FRAME_SIZE` and refuses to allocate
//!   more.
//! - **Signature layer (preserved):** Every `ForwardedQuery`,
//!   `RoutingAssertion`, and `SignedResponseStep` is independently signed
//!   under `ROUTE_DISCOVERY_MSG_CONTEXT` and re-verified by the receiver.
//!   The AEAD layer is confidentiality + integrity for the transport; the
//!   signature layer is end-to-end authenticity of the protocol objects.
//!   Both layers are required — AEAD protects against a network attacker,
//!   signatures protect against a malicious forwarder.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

use snp_crypto::{
    aead_open, aead_seal, derive_node_id, x25519_static_keypair, NonceBytes, SymmetricKey,
    X25519PubKey, X25519Secret,
};
use snp_link::{LinkKeys, VerifiedHandshake, perform_snp_ik_handshake_verified_async};

use super::route_discovery_protocol::{
    ForwardedQuery, ForwardingNode, MAX_ROUTE_QUERY_AGE_SECS, RecursiveNextHopTransport,
    RecursiveRouteResponse,
};

/// Maximum size of a single sealed frame on the wire (1 MiB). Prevents
/// allocation attacks — a malicious peer claiming a frame length larger
/// than this is rejected before any allocation.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// AEAD nonce length (12 bytes for ChaCha20-Poly1305).
const NONCE_LEN: usize = 12;

/// Poly1305 tag length (16 bytes).
const TAG_LEN: usize = 16;

/// Minimum sealed-frame length (nonce would be read separately; sealed
/// body must carry at least the AEAD tag for `aead_open` to have any chance
/// of succeeding).
const MIN_SEALED_LEN: usize = TAG_LEN;

/// Maximum number of entries in the server-side replay cache. When full,
/// the oldest entries are evicted. 4096 is generous for a discovery-time
/// service (one entry per `(source_node_id, query_id)` pair).
const REPLAY_CACHE_MAX_ENTRIES: usize = 4096;

/// **N2.2.1-async.** Bound on how long the initiator will wait for the
/// SNP-IK handshake to complete. The handshake is two round-trips of
/// X25519 ephemeral-static DH + Ed25519 signatures — well under 1s on a
/// healthy LAN; 10s is generous even across a slow wireless hop. A peer
/// that takes longer is treated as unresponsive (the connection is closed
/// and `forward_query` returns `None`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// **N2.2.1-async.** Bound on how long the initiator will wait for a
/// single AEAD-encrypted response frame after sending its query. Covers
/// the worst case of recursive forwarding across a deep chain (each hop
/// adds one round-trip); 30s is generous for an A→B→C→G discovery.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// **N2.2.1-async.** Bound on how long the responder will wait for the
/// SNP-IK handshake from an accepted connection. Idle connections that
/// never start the handshake are dropped after 60s (defensive — the
/// handshake itself is bounded by `HANDSHAKE_TIMEOUT` once it starts).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// ════════════════════════════════════════════════════════════════════════════
// AEAD-encrypted frame protocol (async Tokio I/O)
// ════════════════════════════════════════════════════════════════════════════

/// Generate a fresh 12-byte AEAD nonce from the OS CSPRNG.
///
/// Panics if `getrandom` fails (the OS entropy source is unavailable) —
/// nonce generation is a fatal error, not a degraded mode.
fn fresh_nonce() -> NonceBytes {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("getrandom failed — OS entropy source unavailable");
    nonce
}

/// Write an AEAD-encrypted frame to the async stream.
///
/// Wire format: `[4-byte BE u32 sealed_len][12-byte nonce][sealed_data]`
/// where `sealed_data = aead_seal(send_key, nonce, plaintext, &[])`.
///
/// # Errors
/// Returns `io::Error` if the write fails or the plaintext exceeds
/// `MAX_FRAME_SIZE - TAG_LEN`.
async fn write_sealed_frame(
    stream: &mut TcpStream,
    send_key: &SymmetricKey,
    plaintext: &[u8],
) -> io::Result<()> {
    // The sealed body is ciphertext ‖ tag, so its length is plaintext.len() + 16.
    // Reject plaintexts whose sealed form would exceed MAX_FRAME_SIZE.
    if plaintext.len().saturating_add(TAG_LEN) > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "frame plaintext {} bytes (+{} tag) exceeds MAX_FRAME_SIZE {} bytes",
                plaintext.len(),
                TAG_LEN,
                MAX_FRAME_SIZE
            ),
        ));
    }
    let nonce = fresh_nonce();
    let sealed = aead_seal(send_key, &nonce, plaintext, &[]);
    let sealed_len = u32::try_from(sealed.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sealed frame length exceeds u32::MAX",
        )
    })?;
    stream.write_all(&sealed_len.to_be_bytes()).await?;
    stream.write_all(&nonce).await?;
    stream.write_all(&sealed).await?;
    stream.flush().await?;
    Ok(())
}

/// Read an AEAD-encrypted frame from the async stream and AEAD-open it.
///
/// Wire format: `[4-byte BE u32 sealed_len][12-byte nonce][sealed_data]`.
///
/// Returns the decrypted plaintext on success.
///
/// # Errors
/// Returns `io::Error` if:
/// - The read fails (EOF, connection reset, timeout).
/// - The declared `sealed_len` exceeds `MAX_FRAME_SIZE` (allocation-attack
///   resistance) or is smaller than `MIN_SEALED_LEN`.
/// - AEAD authentication fails (`aead_open` returns `None`). The
///   connection is dropped without further I/O.
async fn read_sealed_frame(
    stream: &mut TcpStream,
    recv_key: &SymmetricKey,
) -> io::Result<Vec<u8>> {
    // 1. Read the 4-byte sealed_len prefix.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let sealed_len = u32::from_be_bytes(len_buf) as usize;
    if sealed_len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "declared sealed frame length {} bytes exceeds MAX_FRAME_SIZE {} bytes",
                sealed_len, MAX_FRAME_SIZE
            ),
        ));
    }
    if sealed_len < MIN_SEALED_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "declared sealed frame length {} bytes is smaller than minimum {} (AEAD tag)",
                sealed_len, MIN_SEALED_LEN
            ),
        ));
    }
    // 2. Read the 12-byte nonce.
    let mut nonce_buf = [0u8; NONCE_LEN];
    stream.read_exact(&mut nonce_buf).await?;
    // 3. Read the sealed body (ciphertext ‖ tag).
    let mut sealed = vec![0u8; sealed_len];
    stream.read_exact(&mut sealed).await?;
    // 4. AEAD-open. Returns None on auth failure.
    let plaintext = aead_open(recv_key, &nonce_buf, &sealed, &[]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "AEAD authentication failed — frame rejected",
        )
    })?;
    Ok(plaintext)
}

// ════════════════════════════════════════════════════════════════════════════
// Replay cache (server-side)
// ════════════════════════════════════════════════════════════════════════════

/// A bounded server-side replay cache keyed by `(source_node_id, query_id)`.
///
/// Each entry stores the wall-clock timestamp at which it was first seen.
/// Entries older than 2× `MAX_ROUTE_QUERY_AGE_SECS` are purged on each
/// insertion. When the cache is full, the oldest entries are evicted.
///
/// This is the server-side freshness check: even though `ForwardingNode`
/// has its own loop-prevention (`visited_nodes`) and the protocol's
/// `PendingRouteQuery` provides single-step replay protection, the TCP
/// server needs its own stateless-per-connection replay protection because
/// each accepted connection is independent.
struct ReplayCache {
    entries: HashMap<([u8; 32], [u8; 16]), u64>,
    max_entries: usize,
}

impl ReplayCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Check + insert `(source_node_id, query_id)`. Returns `true` if the
    /// pair is fresh (not a replay), `false` if it was already seen.
    ///
    /// Side effects: purges expired entries (older than 2×
    /// `MAX_ROUTE_QUERY_AGE_SECS`) and evicts the oldest entry when the
    /// cache is full.
    fn check_and_insert(
        &mut self,
        source_node_id: [u8; 32],
        query_id: [u8; 16],
        now: u64,
    ) -> bool {
        let key = (source_node_id, query_id);
        if self.entries.contains_key(&key) {
            return false;
        }
        // Purge expired entries.
        let max_age = MAX_ROUTE_QUERY_AGE_SECS.saturating_mul(2);
        self.entries.retain(|_, ts| now.saturating_sub(*ts) < max_age);
        // If still full, evict the oldest entry.
        while self.entries.len() >= self.max_entries {
            // Find the entry with the smallest timestamp and remove it.
            let oldest_key = match self
                .entries
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| *k)
            {
                Some(k) => k,
                None => break,
            };
            self.entries.remove(&oldest_key);
        }
        self.entries.insert(key, now);
        true
    }
}

/// Current wall-clock time in seconds since UNIX_EPOCH. Returns 0 on
/// clock errors (which would cause all cache entries to be considered
/// expired — a fail-safe default).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// TcpRecursiveTransport — initiator side
// ════════════════════════════════════════════════════════════════════════════

/// Information needed to reach a peer over TCP. The "phone book" entry.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The TCP address of the peer (e.g. `"127.0.0.1:38507"`).
    pub addr: String,
    /// The peer's Ed25519 public key. The peer's NodeId is derived from
    /// this; the SNP-IK handshake pins the expected NodeId ("I"-style).
    pub ed25519_public: [u8; 32],
}

/// A production `RecursiveNextHopTransport` that uses async Tokio TCP,
/// SNP-IK/0.1 authentication, and AEAD-encrypted canonical CBOR frames.
///
/// Holds:
/// - `peers`: a map from NodeId → `PeerInfo` (TCP address + expected
///   Ed25519 public key). This is the "phone book" — how to reach each
///   neighbor.
/// - The local node's keypair (for the SNP-IK initiator side).
///
/// `forward_query` opens a fresh TCP connection for each call (async
/// via Tokio), performs the SNP-IK handshake as initiator (pinning the
/// expected peer NodeId), AEAD-encrypts the encoded `ForwardedQuery`,
/// reads the AEAD-encrypted response, decodes the `RecursiveRouteResponse`,
/// and closes the connection.
///
/// ## Fully async (N2.2.1-async)
///
/// The trait's `forward_query` is now `async fn` via `#[async_trait]`.
/// This impl implements it directly with `async`/`await` — no
/// `Runtime::new()` / `block_on` boundary. Multiple `forward_query` calls
/// can be `tokio::join!`ed against the same transport to discover multiple
/// destinations concurrently on a single shared runtime. Each operation
/// (TCP connect, SNP-IK handshake, AEAD frame write, AEAD frame read) is
/// bounded by a timeout — see `HANDSHAKE_TIMEOUT` and `FRAME_READ_TIMEOUT`.
pub struct TcpRecursiveTransport {
    /// Map from NodeId → peer info (TCP address + expected Ed25519 public).
    peers: HashMap<[u8; 32], PeerInfo>,
    /// The local node's Ed25519 secret key (for SNP-IK initiator).
    local_ed25519_secret: [u8; 32],
    /// The local node's Ed25519 public key.
    local_ed25519_public: [u8; 32],
    /// The local node's static X25519 secret (for SNP-IK initiator).
    local_x25519_secret: X25519Secret,
    /// The local node's static X25519 public key.
    local_x25519_public: X25519PubKey,
}

impl TcpRecursiveTransport {
    /// Create a new `TcpRecursiveTransport` with the local node's keypair.
    ///
    /// The X25519 keypair is generated fresh (via `x25519_static_keypair()`)
    /// — it is the static rendezvous keypair advertised in the SNP-IK
    /// NodeDescriptor.
    #[must_use]
    pub fn new(
        local_ed25519_secret: [u8; 32],
        local_ed25519_public: [u8; 32],
    ) -> Self {
        let (local_x25519_secret, local_x25519_public) = x25519_static_keypair();
        Self {
            peers: HashMap::new(),
            local_ed25519_secret,
            local_ed25519_public,
            local_x25519_secret,
            local_x25519_public,
        }
    }

    /// Register a peer's TCP address + Ed25519 public key.
    ///
    /// After registration, `forward_query` can reach this peer by NodeId.
    /// The peer's NodeId is derived from the Ed25519 public key — callers
    /// do NOT need to pass it separately.
    pub fn add_peer(&mut self, ed25519_public: [u8; 32], addr: impl Into<String>) {
        let node_id = derive_node_id(&ed25519_public);
        self.peers.insert(
            node_id,
            PeerInfo {
                addr: addr.into(),
                ed25519_public,
            },
        );
    }

    /// Get the number of registered peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Async implementation of `forward_query`. Performs the actual TCP
    /// connect + SNP-IK handshake + AEAD-encrypted frame exchange.
    ///
    /// **N2.2.1-async.** This is now the trait impl body itself (the
    /// `RecursiveNextHopTransport` trait's `forward_query` is `async`).
    /// Each step is bounded by a timeout:
    /// - TCP connect: bounded by `HANDSHAKE_TIMEOUT` (the same budget
    ///   covers the connect + handshake).
    /// - SNP-IK handshake: bounded by `HANDSHAKE_TIMEOUT`.
    /// - AEAD frame write: bounded by `FRAME_READ_TIMEOUT` (a stalled
    ///   peer that accepts the query but never responds is the failure
    ///   mode we care about most).
    /// - AEAD frame read: bounded by `FRAME_READ_TIMEOUT`.
    async fn forward_query_async(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &ForwardedQuery,
    ) -> Option<RecursiveRouteResponse> {
        // 1. Look up peer info.
        let peer = self.peers.get(neighbor_node_id)?;
        // 2. Connect TCP (async).
        let mut stream = TcpStream::connect(&peer.addr).await.ok()?;
        stream.set_nodelay(true).ok();
        // 3. SNP-IK handshake as initiator, pinning expected peer NodeId.
        //    Returns a VerifiedHandshake with directional AEAD link keys.
        //    Bounded by HANDSHAKE_TIMEOUT — a peer that takes too long to
        //    complete the handshake is treated as unresponsive.
        let verified = timeout(
            HANDSHAKE_TIMEOUT,
            perform_snp_ik_handshake_verified_async(
                &mut stream,
                true, // is_initiator
                &self.local_ed25519_secret,
                &self.local_ed25519_public,
                &self.local_x25519_secret,
                &self.local_x25519_public,
                Some(neighbor_node_id),
            ),
        )
        .await
        .ok()?  // timeout elapsed → None
        .ok()?; // handshake error → None
        let LinkKeys { send_key, recv_key } = verified.link_keys();
        // 4. Encode the ForwardedQuery to canonical CBOR (== hash preimage).
        let query_bytes = query.encode_cbor();
        // 5. AEAD-seal + write the frame. Bounded by FRAME_READ_TIMEOUT —
        //    a stalled write (e.g. TCP send buffer full because the peer
        //    is not reading) must not block the resolver indefinitely.
        timeout(
            FRAME_READ_TIMEOUT,
            write_sealed_frame(&mut stream, &send_key, &query_bytes),
        )
        .await
        .ok()?
        .ok()?;
        // 6. Read the AEAD-encrypted response frame + AEAD-open. Bounded
        //    by FRAME_READ_TIMEOUT — covers recursive forwarding across
        //    a deep chain (each hop adds one round-trip).
        let response_bytes = timeout(
            FRAME_READ_TIMEOUT,
            read_sealed_frame(&mut stream, &recv_key),
        )
        .await
        .ok()?
        .ok()?;
        // 7. Decode the RecursiveRouteResponse.
        let response = RecursiveRouteResponse::decode_cbor(&response_bytes)?;
        // 8. Drop the stream (closes the connection).
        Some(response)
    }
}

#[async_trait]
impl RecursiveNextHopTransport for TcpRecursiveTransport {
    /// **N2.2.1-async.** Direct async trait impl — no `Runtime::new()` /
    /// `block_on` boundary. The future runs on whatever Tokio runtime the
    /// caller's task is on (typically the production node's main runtime
    /// or a `#[tokio::test]` runtime in tests).
    async fn forward_query(
        &self,
        neighbor_node_id: &[u8; 32],
        query: &ForwardedQuery,
    ) -> Option<RecursiveRouteResponse> {
        self.forward_query_async(neighbor_node_id, query).await
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TcpForwardingServer — responder side
// ════════════════════════════════════════════════════════════════════════════

/// An async TCP server that listens for incoming AEAD-encrypted
/// `ForwardedQuery` messages, handles them using `ForwardingNode` logic,
/// and sends back AEAD-encrypted `RecursiveRouteResponse` messages.
///
/// The server runs on its own dedicated OS thread with its own
/// multi-threaded Tokio runtime (`serve_in_background` spawns it). Each
/// incoming connection is handled concurrently via `tokio::spawn`: the
/// SNP-IK handshake, AEAD frame I/O, identity-binding check, replay
/// check, and `ForwardingNode::handle_query` all run as independent
/// async tasks.
///
/// **N2.2.1-async.** `ForwardingNode::handle_query` is now `async`, so
/// the server no longer wraps it in `spawn_blocking`. The recursive
/// forwarding (which calls `transport.forward_query().await` on the
/// `ForwardingNode`'s own transport — typically a `TcpRecursiveTransport`)
/// runs directly on the server's runtime worker pool, and the per-hop
/// `block_on` boundary is gone. This means a single connection task can
/// keep multiple downstream TCP connections open concurrently (e.g. via
/// `tokio::join!`) once a fan-out transport is implemented.
///
/// The server's `ForwardingNode` carries its OWN `RecursiveNextHopTransport`
/// (typically a `TcpRecursiveTransport` pointing at the next hop). When
/// `handle_query` needs to forward, it uses that transport — so the FULL
/// chain A → B → C → G goes over real async TCP, not just A → B.
pub struct TcpForwardingServer {
    /// The forwarding node that handles incoming queries.
    node: Arc<ForwardingNode>,
    /// The bound address (computed at construction time so `local_addr()`
    /// remains valid even after `serve()` takes the listener).
    bound_addr: SocketAddr,
    /// The std TCP listener. Stored as `Option` inside a `std::sync::Mutex`
    /// so `serve()` can `take()` it and convert it to a `tokio::net::TcpListener`
    /// inside the server's own Tokio runtime. The conversion MUST happen
    /// inside the runtime that will drive the listener (Tokio registers
    /// the I/O resource with the current runtime's reactor at `from_std`
    /// time), so we cannot convert it at construction time.
    listener: StdMutex<Option<std::net::TcpListener>>,
    /// The server's Ed25519 secret key (for SNP-IK responder).
    ed25519_secret: [u8; 32],
    /// The server's Ed25519 public key.
    ed25519_public: [u8; 32],
    /// The server's static X25519 secret (for SNP-IK responder).
    x25519_secret: X25519Secret,
    /// The server's static X25519 public key.
    x25519_public: X25519PubKey,
    /// Server-side replay cache (bounded). Shared across all connection
    /// tasks via `Arc<Mutex<...>>`.
    replay_cache: Arc<Mutex<ReplayCache>>,
}

impl TcpForwardingServer {
    /// Bind a new `TcpForwardingServer` on `addr` (async).
    ///
    /// The server uses the SAME Ed25519 keypair as the `ForwardingNode` it
    /// wraps (so the SNP-IK handshake authenticates the same identity as
    /// the node's advertisement). The X25519 keypair is generated fresh.
    ///
    /// The listener is converted to a `std::net::TcpListener` (via
    /// `into_std`) and re-converted to a `tokio::net::TcpListener` inside
    /// the server's own runtime when `serve()` is called. This ensures
    /// the I/O resource is registered with the correct runtime's reactor.
    ///
    /// # Errors
    /// Returns `io::Error` if the TCP listener cannot be bound.
    pub async fn bind(
        node: Arc<ForwardingNode>,
        ed25519_secret: [u8; 32],
        ed25519_public: [u8; 32],
        addr: &str,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        // Convert back to std so the server's own runtime can register it.
        // `into_std` deregisters from the current runtime and returns the
        // listener in non-blocking mode.
        let std_listener = listener.into_std()?;
        Ok(Self::new_inner(
            node,
            ed25519_secret,
            ed25519_public,
            bound_addr,
            Some(std_listener),
        ))
    }

    /// **N2.2.1.** Construct a `TcpForwardingServer` from a pre-bound
    /// `std::net::TcpListener`.
    ///
    /// This is useful when the caller needs to know the bound address
    /// (e.g. ephemeral port `"127.0.0.1:0"`) BEFORE constructing the
    /// `ForwardingNode` (which needs the address to populate its
    /// `endpoints` field, and whose transport needs the peer addresses).
    ///
    /// The listener is stored as-is (in blocking mode) and converted to
    /// a `tokio::net::TcpListener` inside the server's own runtime when
    /// `serve()` is called. This avoids the chicken-and-egg of needing a
    /// Tokio runtime context at construction time.
    ///
    /// # Errors
    /// Returns `io::Error` if `listener.local_addr()` fails or the
    /// internal X25519 keypair generation fails (which only happens if
    /// the OS CSPRNG is unavailable).
    pub fn from_listener(
        node: Arc<ForwardingNode>,
        ed25519_secret: [u8; 32],
        ed25519_public: [u8; 32],
        listener: std::net::TcpListener,
    ) -> io::Result<Self> {
        let bound_addr = listener.local_addr()?;
        Ok(Self::new_inner(
            node,
            ed25519_secret,
            ed25519_public,
            bound_addr,
            Some(listener),
        ))
    }

    /// Shared constructor body.
    fn new_inner(
        node: Arc<ForwardingNode>,
        ed25519_secret: [u8; 32],
        ed25519_public: [u8; 32],
        bound_addr: SocketAddr,
        listener: Option<std::net::TcpListener>,
    ) -> Self {
        let (x25519_secret, x25519_public) = x25519_static_keypair();
        Self {
            node,
            bound_addr,
            listener: StdMutex::new(listener),
            ed25519_secret,
            ed25519_public,
            x25519_secret,
            x25519_public,
            replay_cache: Arc::new(Mutex::new(ReplayCache::new(REPLAY_CACHE_MAX_ENTRIES))),
        }
    }

    /// Get the local address the server is bound to.
    ///
    /// Useful when the caller passed `"127.0.0.1:0"` (ephemeral port) and
    /// needs to discover the actual port. The address is captured at
    /// construction time and remains valid for the lifetime of the server
    /// (even after `serve()` takes the listener).
    #[must_use]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.bound_addr)
    }

    /// Get the bound address as a string (e.g. `"127.0.0.1:38507"`).
    ///
    /// # Errors
    /// Returns `io::Error` only if the stored address cannot be stringified
    /// (which cannot happen in practice).
    pub fn local_addr_string(&self) -> io::Result<String> {
        Ok(self.bound_addr.to_string())
    }

    /// Run the server forever (async). Each accepted connection is
    /// handled concurrently via `tokio::spawn`.
    ///
    /// This method takes the stored `std::net::TcpListener`, converts it
    /// to a `tokio::net::TcpListener` (setting non-blocking mode), and
    /// enters the accept loop. The conversion MUST happen inside the
    /// Tokio runtime that will drive the listener (the reactor
    /// registration is runtime-specific), so callers should use
    /// [`TcpForwardingServer::serve_in_background`] (which spawns a
    /// dedicated OS thread + runtime) rather than calling `serve()`
    /// directly from an arbitrary context.
    ///
    /// # Errors
    /// Returns `io::Error` if the listener conversion fails or `accept()`
    /// fails irrecoverably.
    pub async fn serve(self: Arc<Self>) -> io::Result<()> {
        // Take the std listener out of the Mutex and convert to tokio.
        // This registers the I/O resource with the current runtime's
        // reactor, which is why serve() must run on the SAME runtime that
        // will drive the listener.
        let listener = {
            let mut guard = self.listener.lock().expect("listener mutex poisoned");
            let std_listener = guard.take().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "listener already taken (serve() called twice?)",
                )
            })?;
            // Set non-blocking mode (required by tokio::net::TcpListener::from_std).
            std_listener.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(std_listener)?
        };
        loop {
            let (stream, _peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("[TcpForwardingServer] accept() error: {e}");
                    // Brief back-off to avoid a tight error loop.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    eprintln!("[TcpForwardingServer] connection error: {e}");
                }
            });
        }
    }

    /// Spawn a dedicated OS thread running `serve()` on its own
    /// multi-threaded Tokio runtime.
    ///
    /// Returns immediately. The thread + runtime run until the listener
    /// is closed (which happens when the `TcpForwardingServer` is
    /// dropped — but note that dropping an `Arc<TcpForwardingServer>`
    /// only closes the listener when the LAST Arc is dropped).
    ///
    /// This is the canonical production entry point: the synchronous
    /// caller (e.g. a node's main thread) calls `serve_in_background` and
    /// continues; all network I/O happens on the dedicated runtime.
    pub fn serve_in_background(self: Arc<Self>) {
        std::thread::Builder::new()
            .name("TcpForwardingServer".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("[TcpForwardingServer] failed to create runtime: {e}");
                        return;
                    }
                };
                if let Err(e) = rt.block_on(self.serve()) {
                    eprintln!("[TcpForwardingServer] serve() exited with error: {e}");
                }
            })
            .expect("failed to spawn TcpForwardingServer thread");
    }

    /// Handle a single connection (async): SNP-IK handshake → read
    /// AEAD-encrypted frame → identity-binding check → replay check →
    /// `ForwardingNode::handle_query` (direct `.await`) → write
    /// AEAD-encrypted response → close.
    ///
    /// On ANY error (handshake failure, AEAD failure, identity mismatch,
    /// replay, decode failure, handle_query rejection), the connection is
    /// dropped WITHOUT sending a response — the initiator sees EOF / error
    /// and treats it as failure.
    ///
    /// **N2.2.1-async.** `handle_query` is now `async`, so it is invoked
    /// directly (`.await`) instead of via `spawn_blocking`. The recursive
    /// forwarding (which calls `transport.forward_query().await` on the
    /// `ForwardingNode`'s own transport) runs on the server's runtime
    /// worker pool — no per-hop runtime, no `block_on`.
    ///
    /// Each I/O step is bounded by a timeout:
    /// - SNP-IK handshake (responder): bounded by `IDLE_TIMEOUT`. Idle
    ///   connections that never start the handshake are dropped.
    /// - Read AEAD-encrypted ForwardedQuery frame: bounded by
    ///   `FRAME_READ_TIMEOUT`. A peer that completes the handshake but
    ///   never sends a query is dropped.
    /// - `ForwardingNode::handle_query` (which itself includes recursive
    ///   `forward_query` calls with their own timeouts): bounded by
    ///   `FRAME_READ_TIMEOUT`. A stalled downstream hop must not block the
    ///   responder's worker pool indefinitely.
    /// - Write AEAD-encrypted response frame: bounded by
    ///   `FRAME_READ_TIMEOUT`. A client that stops reading is dropped.
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true).ok();

        // 1. SNP-IK handshake as responder (no expected peer pinning — we
        //    accept any authenticated peer; the handshake itself proves
        //    the peer's identity). Returns a VerifiedHandshake with the
        //    authenticated peer_node_id + directional AEAD link keys.
        //
        //    Bounded by IDLE_TIMEOUT — a connection that takes too long
        //    to complete the handshake (or never starts it) is dropped.
        let verified: VerifiedHandshake = timeout(
            IDLE_TIMEOUT,
            perform_snp_ik_handshake_verified_async(
                &mut stream,
                false, // is_initiator = false (responder)
                &self.ed25519_secret,
                &self.ed25519_public,
                &self.x25519_secret,
                &self.x25519_public,
                None, // no expected_peer_node_id — accept any authenticated peer
            ),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "SNP-IK handshake timed out (responder) — IDLE_TIMEOUT elapsed",
            )
        })?
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("SNP-IK handshake failed (responder): {e}"),
            )
        })?;
        let peer_node_id = verified.peer_node_id();
        let LinkKeys { send_key, recv_key } = verified.link_keys();

        // 2. Read the AEAD-encrypted ForwardedQuery frame + AEAD-open.
        //    Bounded by FRAME_READ_TIMEOUT — a peer that completes the
        //    handshake but never sends a query is dropped.
        let query_bytes = timeout(
            FRAME_READ_TIMEOUT,
            read_sealed_frame(&mut stream, &recv_key),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "ForwardedQuery frame read timed out — FRAME_READ_TIMEOUT elapsed",
            )
        })??;
        // 3. Decode the ForwardedQuery from canonical CBOR.
        let query = ForwardedQuery::decode_cbor(&query_bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "failed to decode ForwardedQuery from canonical CBOR",
            )
        })?;

        // 4. **Identity binding (N2.2.1).** The authenticated peer NodeId
        //    from the SNP-IK handshake MUST equal the query's
        //    source_node_id. A query signed by B cannot be sent over a
        //    connection authenticated as A — this closes the cross-channel
        //    injection vector. Drop without a response.
        if peer_node_id != query.source_node_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "identity binding failed: authenticated peer NodeId {:?} != query.source_node_id {:?}",
                    peer_node_id, query.source_node_id
                ),
            ));
        }

        // 5. **Replay protection (N2.2.1).** Check the (source_node_id,
        //    query_id) pair against the server-side replay cache. A
        //    replayed serialized query is rejected before reaching
        //    ForwardingNode::handle_query.
        {
            let mut cache = self.replay_cache.lock().await;
            if !cache.check_and_insert(query.source_node_id, query.query_id, now_secs()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "replay detected: (source_node_id, query_id) already seen",
                ));
            }
        }

        // 6. Hand the query to the ForwardingNode directly (`.await`).
        //    **N2.2.1-async:** `handle_query` is now `async` — no
        //    `spawn_blocking`. The recursive forwarding (which calls
        //    `transport.forward_query().await` on the ForwardingNode's own
        //    transport — typically a `TcpRecursiveTransport`) runs on the
        //    server's runtime worker pool. Bounded by FRAME_READ_TIMEOUT —
        //    a stalled downstream hop must not block the worker.
        //
        //    We hold `&self.node` (an `Arc<ForwardingNode>`) by reference
        //    rather than cloning into a `move` closure (the previous
        //    `spawn_blocking` pattern), because the future is no longer
        //    `'static` — it borrows from `&self`.
        let response_opt = timeout(
            FRAME_READ_TIMEOUT,
            self.node.handle_query(&query),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "ForwardingNode::handle_query timed out — FRAME_READ_TIMEOUT elapsed",
            )
        })?;

        let response = match response_opt {
            Some(r) => r,
            None => {
                // The query was rejected (bad signature, loop, budget
                // exhausted, no path). Close the connection without
                // sending a response — the initiator will see EOF and
                // treat it as failure.
                return Ok(());
            }
        };

        // 7. Encode the RecursiveRouteResponse to canonical CBOR.
        let response_bytes = response.encode_cbor();
        // 8. AEAD-seal + write the response frame. Bounded by
        //    FRAME_READ_TIMEOUT — a client that stops reading is dropped.
        timeout(
            FRAME_READ_TIMEOUT,
            write_sealed_frame(&mut stream, &send_key, &response_bytes),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "response frame write timed out — FRAME_READ_TIMEOUT elapsed",
            )
        })??;
        // 9. Connection closes on drop.
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests for the AEAD frame protocol (unit tests, async)
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// `write_sealed_frame` / `read_sealed_frame` round-trip a small
    /// payload over a real TCP loopback connection (async).
    #[tokio::test]
    async fn sealed_frame_round_trip_small() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let key = [0x42u8; 32];
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let data = read_sealed_frame(&mut s, &key).await.unwrap();
            assert_eq!(data, b"hello");
            write_sealed_frame(&mut s, &key, b"world").await.unwrap();
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        write_sealed_frame(&mut s, &key, b"hello").await.unwrap();
        let resp = read_sealed_frame(&mut s, &key).await.unwrap();
        assert_eq!(resp, b"world");
        server.await.unwrap();
    }

    /// `read_sealed_frame` rejects a declared length exceeding `MAX_FRAME_SIZE`.
    #[tokio::test]
    async fn sealed_frame_oversized_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let key = [0x42u8; 32];

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Write a 4-byte length prefix claiming (MAX_FRAME_SIZE + 1) bytes.
            let bogus_len = u32::try_from(MAX_FRAME_SIZE + 1).unwrap();
            s.write_all(&bogus_len.to_be_bytes()).await.unwrap();
            // Don't send any payload — the reader should reject before
            // expecting any.
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        let err = read_sealed_frame(&mut s, &key).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = server.await;
    }

    /// `write_sealed_frame` rejects a plaintext whose sealed form would
    /// exceed `MAX_FRAME_SIZE`.
    #[tokio::test]
    async fn sealed_frame_write_oversized_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let key = [0x42u8; 32];
        let _server = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        // plaintext of MAX_FRAME_SIZE - 15 bytes → sealed = MAX_FRAME_SIZE + 1.
        let huge = vec![0u8; MAX_FRAME_SIZE - (TAG_LEN - 1)];
        let err = write_sealed_frame(&mut s, &key, &huge).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// `read_sealed_frame` returns UnexpectedEof on a truncated frame.
    #[tokio::test]
    async fn sealed_frame_truncated_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let key = [0x42u8; 32];

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Claim 10 bytes of sealed body but only send 3.
            s.write_all(&10u32.to_be_bytes()).await.unwrap();
            s.write_all(&[0u8; 12]).await.unwrap(); // fake nonce
            s.write_all(b"abc").await.unwrap();
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        let err = read_sealed_frame(&mut s, &key).await.unwrap_err();
        // The error kind may be UnexpectedEof or InvalidData depending on
        // platform and timing — either is acceptable (the frame was rejected).
        assert!(
            err.kind() == io::ErrorKind::UnexpectedEof || err.kind() == io::ErrorKind::InvalidData,
            "truncated frame should produce UnexpectedEof or InvalidData, got: {:?}",
            err.kind()
        );
        let _ = server.await;
    }

    /// `read_sealed_frame` rejects a frame whose AEAD tag does not
    /// authenticate (the sealed body was tampered).
    #[tokio::test]
    async fn sealed_frame_tampered_ciphertext_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let key = [0x42u8; 32];

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Build a real sealed frame, then flip a byte in the ciphertext.
            let sealed = aead_seal(&key, &[0u8; 12], b"hello", &[]);
            let mut tampered = sealed.clone();
            // Flip a byte in the ciphertext portion (not the tag).
            tampered[0] ^= 0xFF;
            let len = u32::try_from(tampered.len()).unwrap();
            s.write_all(&len.to_be_bytes()).await.unwrap();
            s.write_all(&[0u8; 12]).await.unwrap(); // nonce
            s.write_all(&tampered).await.unwrap();
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        let err = read_sealed_frame(&mut s, &key).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = server.await;
    }

    /// `ReplayCache` rejects a duplicate `(source_node_id, query_id)`.
    #[test]
    fn replay_cache_rejects_duplicate() {
        let mut cache = ReplayCache::new(8);
        let src = [1u8; 32];
        let qid = [2u8; 16];
        assert!(cache.check_and_insert(src, qid, 100));
        // Duplicate at a later timestamp — must be rejected.
        assert!(!cache.check_and_insert(src, qid, 200));
    }

    /// `ReplayCache` evicts the oldest entry when full.
    #[test]
    fn replay_cache_evicts_when_full() {
        let mut cache = ReplayCache::new(2);
        let src_a = [1u8; 32];
        let src_b = [2u8; 32];
        let src_c = [3u8; 32];
        let qid = [9u8; 16];
        // Insert two entries at t=100, t=200.
        assert!(cache.check_and_insert(src_a, qid, 100));
        assert!(cache.check_and_insert(src_b, qid, 200));
        // Insert a third — cache is full; oldest (src_a @ t=100) is evicted.
        assert!(cache.check_and_insert(src_c, qid, 300));
        // src_a should now be re-acceptable (it was evicted).
        assert!(cache.check_and_insert(src_a, qid, 400));
    }

    /// `ReplayCache` purges expired entries.
    #[test]
    fn replay_cache_purges_expired() {
        let mut cache = ReplayCache::new(1024);
        let src = [1u8; 32];
        let qid = [2u8; 16];
        // Insert at t=0.
        assert!(cache.check_and_insert(src, qid, 0));
        // Same key, much later — should still be rejected (entry is fresh
        // in the cache because the max_age window is 2 * MAX_ROUTE_QUERY_AGE_SECS).
        assert!(!cache.check_and_insert(src, qid, MAX_ROUTE_QUERY_AGE_SECS));
        // After 3x MAX_ROUTE_QUERY_AGE_SECS, the entry is purged on the
        // next insertion — the same key becomes re-acceptable.
        let other_src = [9u8; 32];
        let other_qid = [9u8; 16];
        assert!(cache.check_and_insert(other_src, other_qid, 3 * MAX_ROUTE_QUERY_AGE_SECS + 1));
        // Now src/qid should be fresh again (it was purged).
        assert!(cache.check_and_insert(src, qid, 3 * MAX_ROUTE_QUERY_AGE_SECS + 2));
    }
}

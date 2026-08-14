//! SNP-LINK — L8 link abstraction with AEAD-encrypted frame transport
//!
//! For N1.9 (Secure Rust Link + Gateway Boundary) this crate implements a
//! SIMPLE synchronous TCP transport that AEAD-encrypts every SNP frame with
//! **directional** pre-shared symmetric keys. The full SNP-IK/0.1 Noise-based
//! handshake is a separate future task — for now the link keys are derived
//! from deterministic test seeds, identical on both ends of each hop.
//!
//! ## N1.9 changes (this revision)
//!
//! N1.8 used a SINGLE 32-byte AEAD key bidirectionally. That created a nonce
//! reuse risk: if `(fid, seq)` ever appeared in both directions of the same
//! link (e.g. a client and a server both sent `seq=1` on the same `fid`),
//! ChaCha20-Poly1305 would have been invoked twice with the same `(key, nonce)`
//! pair — a catastrophic confidentiality break.
//!
//! N1.9 replaces the single key with a [`LinkKeys`] struct:
//!
//! ```text
//!   LinkKeys {
//!     send_key: SymmetricKey,  // key for sending (encrypt outbound)
//!     recv_key: SymmetricKey,  // key for receiving (decrypt inbound)
//!   }
//! ```
//!
//! Both are derived via HKDF from a shared seed with distinct `info` strings
//! (`b"initiator-to-responder"` and `b"responder-to-initiator"`). The
//! initiator's `send_key` equals the responder's `recv_key`, and vice versa.
//! Because the AEAD key differs across directions, `(fid, seq)` collisions
//! across directions no longer cause nonce reuse. See [`derive_link_keys`].
//!
//! ## N1.9 also adds: end-to-end circuit encryption
//!
//! The relay re-encrypts the OUTER frame at each hop (it has the hop keys for
//! both links it touches) but it MUST NOT possess the circuit key that
//! encrypts the TransitRequest body. The client encrypts the TransitRequest
//! body with `circuit_send_key` BEFORE wrapping it in a frame; the gateway
//! decrypts the body with `circuit_recv_key` AFTER decrypting the frame. The
//! relay sees only opaque ciphertext in the frame body. See
//! [`CircuitKeys`], [`encrypt_circuit_payload`], [`decrypt_circuit_payload`].
//!
//! ## Wire format
//!
//! Every frame on the wire is:
//!
//! ```text
//!   ┌──────────────┬───────────────┬─────────────────────────────┬──────────────┐
//!   │ length (4 BE) │ nonce (12 B)  │ ciphertext (= plaintext len)│ tag (16 B)   │
//!   └──────────────┴───────────────┴─────────────────────────────┴──────────────┘
//! ```
//!
//! - `length` is the byte length of everything that follows (nonce +
//!   ciphertext + tag).
//! - `nonce` is `fid ‖ seq_BE(u32)` per SNP/0.1 §7.3 — the receiver does
//!   NOT need to track a counter; the nonce is sent in clear because it is
//!   not secret.
//! - `ciphertext` is the same length as the plaintext (ChaCha20 is a stream
//!   cipher).
//! - `tag` is the Poly1305 MAC.
//! - The AEAD AAD is empty (the frame header is authenticated by being part
//!   of the AEAD plaintext — the entire CBOR-encoded Frame is encrypted).
//!
//! ## Class B invariant (I8)
//!
//! In N1.8 the relay forwarded still-encrypted OUTER blobs verbatim via
//! [`recv_raw`] / [`send_raw`] — it never decrypted anything. In N1.9, with
//! per-hop directional keys, the relay must decrypt the OUTER frame and
//! re-encrypt it for the next hop (the hop keys differ). However, the relay
//! still DOES NOT decrypt the FRAME BODY (the inner circuit payload) — the
//! body remains opaque ciphertext to the relay. This preserves invariant I8
//! (Class B transit payloads are never inspected by relays) at the semantic
//! level: the relay sees the body bytes but cannot read them.
//!
//! ## Production readiness
//!
//! **What IS production-ready in this crate (N1.9):**
//!
//! - The ChaCha20-Poly1305 AEAD over real TCP sockets (delegated to the
//!   well-reviewed `chacha20poly1305` crate — no hand-rolled crypto).
//! - The directional-key derivation `derive_link_keys(seed, is_initiator)`
//!   via HKDF-SHA256 with cryptographically distinct `info` strings. This
//!   eliminates the nonce-reuse-across-directions risk that existed in N1.8.
//! - The circuit-encryption helpers `encrypt_circuit_payload` /
//!   `decrypt_circuit_payload` — they produce a fresh random 12-byte nonce
//!   per call (process-local counter + wall clock + SHA-256).
//! - The frame wire format `[4-byte BE length][nonce][ciphertext][tag]`
//!   and the relay's I8 forwarding semantics.
//!
//! **What is NOT production-ready (future tasks):**
//!
//! - The pre-shared seed model. N1.9 derives all keys from deterministic
//!   test seeds (visible in `snp-node/src/lib.rs`). Production ShareNet
//!   uses the SNP-IK/0.1 Noise-based handshake (X25519 ephemeral-static
//!   DH + transcript hash) so each TCP link has a UNIQUE key unknown to
//!   anyone but the two endpoints.
//! - The circuit-seed distribution. N1.9 derives the circuit seed from a
//!   deterministic test value. Production derives it from the SNP-IK/0.1
//!   transcript between client and gateway, so the relay (which only sees
//!   the outer hop handshakes) cannot derive it.
//! - The circuit-nonce RNG. N1.9.1 uses `getrandom()` (OS CSPRNG) for the
//!   circuit nonce, replacing the N1.9 `SHA-256(wall_clock_ns ‖ counter)`
//!   heuristic. This guarantees nonce uniqueness across processes, threads,
//!   reconnects, and session restarts.
//! - The synchronous `std::net::TcpStream` API. Production ShareNet uses
//!   async I/O (tokio) for connection pooling and concurrent relays.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use snp_cbor::CborValue;
use snp_crypto::{
    aead_decrypt, aead_encrypt, aead_nonce, aead_open, aead_seal, derive_node_id, ed25519_sign,
    ed25519_verify, hkdf_sha256, sha256, sig_contexts, x25519_dh, x25519_ephemeral_keypair,
    x25519_public_from_bytes, SymmetricKey, X25519PubKey, X25519Secret,
};
use snp_frames::Frame;
use thiserror::Error;

// N2.0.6 — canonical async production transport.
pub mod async_link;

// N2.2.1 — re-export the async verified-handshake wrapper at the crate root
// so callers can use `snp_link::perform_snp_ik_handshake_verified_async`
// (mirroring the sync `snp_link::perform_snp_ik_handshake_verified`).
pub use async_link::perform_snp_ik_handshake_verified_async;

/// Errors from the L8 link layer.
#[derive(Debug, Error)]
pub enum LinkError {
    /// A frame failed AEAD decryption. The link MUST be killed.
    #[error("AEAD decryption failed — link killed")]
    DecryptionFailed,
    /// The underlying transport returned an IO error.
    #[error("transport IO error: {0}")]
    Io(String),
    /// The length prefix was absurd (e.g. > 16 MiB) — almost certainly a
    /// corrupted stream or an attacker.
    #[error("absurd length prefix: {0}")]
    AbsurdLength(u32),
    /// Frame (de)serialization failure.
    #[error("frame error: {0}")]
    Frame(#[from] snp_frames::FrameError),
    /// N1.9.2: A replayed (fid, seq) was detected — the same nonce was
    /// already seen on this link. The link MUST be killed.
    #[error("replay detected: (fid, seq) already seen — link killed")]
    ReplayDetected,
    /// CBOR (de)serialization failure (only when the AEAD plaintext is not
    /// a valid Frame — should not happen for well-behaved peers).
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// SNP-IK/0.1 handshake failed: the peer's NodeDescriptor signature did
    /// NOT verify under the peer's claimed Ed25519 public key. The link is
    /// rejected; no further I/O occurs on the stream.
    #[error("SNP-IK/0.1: peer NodeDescriptor signature verification FAILED")]
    HandshakeBadSignature,
    /// SNP-IK/0.1 handshake failed: the peer's NodeId does NOT match
    /// `SHA-256("SNP/0.1 node\0" || peer_pubKey)` (invariant I4 violation).
    /// The peer attempted to name-squat a NodeId it does not own.
    #[error("SNP-IK/0.1: peer NodeId does not match SHA-256(...||peer_pubKey) (I4 violation)")]
    HandshakeNodeIdMismatch,
    /// SNP-IK/0.1 handshake failed: the peer's NodeId does not match the
    /// `expected_peer_node_id` supplied by the caller ("I"-style pinning).
    /// The peer is NOT the node the caller intended to connect to.
    #[error("SNP-IK/0.1: peer NodeId does not match expected_peer_node_id (I-style pinning failed)")]
    HandshakeUnexpectedPeer,
    /// SNP-IK/0.1 handshake failed: the peer sent a malformed handshake
    /// message (missing field, wrong length, wrong CBOR shape, …). The
    /// handshake aborts before any DH computation.
    #[error("SNP-IK/0.1: malformed handshake message: {0}")]
    HandshakeMalformed(String),
}

/// Convenience `Result` alias.
pub type LinkResult<T> = Result<T, LinkError>;

/// Maximum length of a frame on the wire (nonce + ciphertext + tag).
/// 16 MiB is generous — frames are normally small.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Length of the AEAD nonce in bytes.
const NONCE_LEN: usize = 12;

/// Length of the Poly1305 tag in bytes.
const TAG_LEN: usize = 16;

// ─── Directional link keys (N1.9) ───────────────────────────────────────────

/// A pair of AEAD keys for a single TCP link: one for sending, one for
/// receiving.
///
/// Both ends of a link derive a `LinkKeys` from the SAME seed via
/// [`derive_link_keys`], but the initiator and responder swap which key is
/// `send_key` vs `recv_key`. Concretely:
///
/// ```text
///   initiator.send_key  == responder.recv_key  == HKDF(..., "initiator-to-responder")
///   initiator.recv_key  == responder.send_key  == HKDF(..., "responder-to-initiator")
/// ```
///
/// This guarantees that even if the same `(fid, seq)` appears in both
/// directions of a link, the AEAD `(key, nonce)` pair is never reused: each
/// direction has a distinct key, so the same nonce under two different keys
/// is cryptographically independent.
#[derive(Debug, Clone, Copy)]
pub struct LinkKeys {
    /// Key used by `send_frame` (encrypt outbound).
    pub send_key: SymmetricKey,
    /// Key used by `recv_frame` (decrypt inbound).
    pub recv_key: SymmetricKey,
}

/// Derive directional AEAD link keys from a deterministic seed.
///
/// Both ends of a TCP link MUST pass the SAME `seed`. The `is_initiator`
/// parameter distinguishes the two ends — the side that opened the TCP
/// connection passes `true`, the side that accepted passes `false`.
///
/// # Derivation
///
/// ```text
///   base  = HKDF-SHA256(seed, salt="SNP/0.1 link base",            info="",            L=32)
///   i2r   = HKDF-SHA256(base, salt="SNP/0.1 link dir",             info="initiator-to-responder", L=32)
///   r2i   = HKDF-SHA256(base, salt="SNP/0.1 link dir",             info="responder-to-initiator", L=32)
///   initiator: LinkKeys { send_key: i2r, recv_key: r2i }
///   responder: LinkKeys { send_key: r2i, recv_key: i2r }
/// ```
///
/// The directional `info` strings ensure that `i2r` and `r2i` are
/// cryptographically independent 32-byte keys.
///
/// # N1.9 vs production
///
/// This is the simplified N1.9 pre-shared-key derivation, NOT the production
/// SNP-IK/0.1 Noise-based handshake. The seed is a known test value; the
/// production handshake derives fresh per-link seeds from X25519 ephemeral-static
/// Diffie-Hellman and a transcript hash.
#[must_use]
pub fn derive_link_keys(seed: &[u8], is_initiator: bool) -> LinkKeys {
    let base = hkdf_sha256(seed, b"SNP/0.1 link base", b"", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let i2r = hkdf_sha256(&base, b"SNP/0.1 link dir", b"initiator-to-responder", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let r2i = hkdf_sha256(&base, b"SNP/0.1 link dir", b"responder-to-initiator", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let mut i2r_arr = [0u8; 32];
    i2r_arr.copy_from_slice(&i2r);
    let mut r2i_arr = [0u8; 32];
    r2i_arr.copy_from_slice(&r2i);
    if is_initiator {
        LinkKeys {
            send_key: i2r_arr,
            recv_key: r2i_arr,
        }
    } else {
        LinkKeys {
            send_key: r2i_arr,
            recv_key: i2r_arr,
        }
    }
}

/// Derive a single 32-byte AEAD link key from a deterministic seed.
///
/// **Deprecated (N1.9).** Kept for backward compatibility with N1.8 callers.
/// New code MUST use [`derive_link_keys`] which produces directional keys
/// (`send_key` + `recv_key`) — a single bidirectional key risks nonce reuse
/// when `(fid, seq)` appears in both directions of a link.
#[must_use]
pub fn derive_link_key(seed: &[u8]) -> SymmetricKey {
    let salt = b"SNP/0.1 link N1.8 pre-shared";
    let info = b"SNP/0.1 link-key N1.8\0";
    let okm = hkdf_sha256(seed, salt, info, 32).expect("HKDF-SHA256 32-byte expand never fails");
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

// ─── SNP-IK/0.1 — custom authenticated key agreement (N2.0.2) ───────────────
//
// Implements the construction defined in ADR-0006:
//
//   1. Initiator generates ephemeral X25519 keypair (e, E)
//   2. Initiator sends E + their signed NodeDescriptor to responder
//   3. Responder generates ephemeral X25519 keypair (e', E')
//   4. Responder sends E' + their signed NodeDescriptor to initiator
//   5. Both compute three DH operations:
//        dh1 = initiator_ephemeral × responder_static (rendezvousPub)
//        dh2 = initiator_static × responder_ephemeral
//        dh3 = initiator_ephemeral × responder_ephemeral
//   6. Both derive link keys via HKDF-SHA256(dh1 || dh2 || dh3,
//        salt=empty, info="SNP-IK/0.1 link keys")
//   7. Both verify the peer's NodeDescriptor signature BEFORE accepting the link
//
// The "static" X25519 keypair is the node's persistent rendezvous key (passed
// in as `my_x25519_*`). The "ephemeral" X25519 keypair is generated FRESH
// inside [`perform_snp_ik_handshake`] per session — this provides forward
// secrecy (compromising both static keys after the handshake does NOT recover
// the derived link keys, because the ephemeral secrets are erased).
//
// Each node therefore needs BOTH an Ed25519 identity keypair (signs the
// NodeDescriptor) AND an X25519 rendezvous keypair (participates in the DH).
// The Ed25519 key signs; the X25519 key agrees.

/// HKDF `info` literal for SNP-IK/0.1 link-key derivation. Per ADR-0006, this
/// is the construction's binding info string. A future ADR that adopts a
/// vetted Noise_IK library will replace the entire key derivation (and this
/// literal will be deleted at that time).
pub const SNP_IK_LINK_KEYS_INFO: &[u8] = b"SNP-IK/0.1 link keys";

/// HKDF `salt` literal for the directional link-key derivation step.
pub const SNP_IK_LINK_DIR_SALT: &[u8] = b"SNP/0.1 link dir";

/// HKDF `info` literal for the initiator→responder directional key.
pub const SNP_IK_LINK_DIR_I2R: &[u8] = b"initiator-to-responder";

/// HKDF `info` literal for the responder→initiator directional key.
pub const SNP_IK_LINK_DIR_R2I: &[u8] = b"responder-to-initiator";

/// The result of a successful SNP-IK/0.1 handshake.
///
/// Contains the freshly-derived directional AEAD [`LinkKeys`] and the peer's
/// authenticated identity (NodeId + Ed25519 public key). The peer's identity
/// has been signature-verified by the time this struct is returned; the
/// caller MAY trust it without further verification.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// Directional AEAD link keys derived from the SNP-IK/0.1 DH computations.
    /// The initiator's `send_key` equals the responder's `recv_key`, and vice
    /// versa (same directional-inversion rule as N1.9 [`derive_link_keys`]).
    pub link_keys: LinkKeys,
    /// The peer's NodeId (`SHA-256("SNP/0.1 node\0" || peer_public_key)`).
    pub peer_node_id: [u8; 32],
    /// The peer's Ed25519 public key (32 bytes, raw wire form per I3).
    pub peer_public_key: [u8; 32],
    /// The peer's static X25519 rendezvous public key (32 bytes). The caller
    /// MAY cache this to recognise the same peer in future sessions.
    pub peer_x25519_public: [u8; 32],
    /// The peer's ephemeral X25519 public key for THIS session (32 bytes).
    /// Fresh per handshake; included for transcript-hashing by callers that
    /// want to derive additional keys bound to this session.
    pub peer_ephemeral_public: [u8; 32],
    /// The session id: `SHA-256(initiator_eph || responder_eph || dh3)`.
    /// This is the closest analogue to Noise's handshake hash that
    /// SNP-IK/0.1 provides (ADR-0006 acknowledges the absence of a true
    /// transcript hash; this `session_id` is the per-session binding value).
    pub session_id: [u8; 32],
}

// ─── TransportBinding (N2.1.2.5) ───────────────────────────────────────────

/// **N2.1.2.5.** An authenticated binding to the actual transport endpoint
/// used by a successful handshake.
///
/// `TransportBinding` records **which transport endpoint the handshake
/// actually occurred over**. This is distinct from "which endpoint the
/// advertisement authorized" — both checks are needed for a complete
/// security boundary:
///
/// 1. **Advertisement authorization**: `key.endpoint ∈ advert.endpoints()`
///    (checked by `AuthenticatedLink::from_verified_handshake`).
/// 2. **Actual transport binding**: `proof.transport_binding == key.endpoint`
///    (checked by `AuthenticatedLink::from_verified_handshake`).
///
/// Without the second check, a caller could perform a handshake over
/// endpoint A, then construct an `AuthenticatedLink` claiming endpoint B
/// (as long as B is also advertised). The transport binding prevents this
/// identity/location confusion.
///
/// ## Canonical representation
///
/// For TCP, the binding is the canonical `host:port` string obtained from
/// `TcpStream::peer_addr()`. The canonicalization normalizes IPv6 addresses
/// (e.g., `::1` → `[::1]:port`) to ensure consistent comparison.
///
/// ## Future transports
///
/// The `TransportType` enum is designed to support future transports (BLE,
/// Wi-Fi Direct, Nearby Connections, QUIC) without redefining the identity
/// model. Each transport will provide its own canonical binding
/// representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportBinding {
    /// The transport type.
    transport: TransportType,
    /// The canonical address string (e.g. `"127.0.0.1:12345"` for TCP).
    canonical_addr: String,
}

/// The type of transport used for a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// TCP transport.
    Tcp,
    /// BLE transport (not yet implemented).
    Ble,
    /// Wi-Fi Direct transport (not yet implemented).
    WifiDirect,
    /// Nearby Connections transport (not yet implemented).
    NearbyConnections,
}

impl TransportBinding {
    /// **Private constructor.** Only callable from within `snp-link`.
    #[must_use]
    pub(crate) fn new(transport: TransportType, canonical_addr: String) -> Self {
        Self { transport, canonical_addr }
    }

    /// Create a TCP transport binding from a `SocketAddr`.
    ///
    /// This canonicalizes the address representation.
    #[must_use]
    pub(crate) fn from_tcp_socket_addr(addr: std::net::SocketAddr) -> Self {
        Self {
            transport: TransportType::Tcp,
            canonical_addr: canonicalize_tcp_addr(&addr),
        }
    }

    /// Get the transport type.
    #[must_use]
    pub fn transport(&self) -> TransportType {
        self.transport
    }

    /// Get the canonical address string.
    #[must_use]
    pub fn canonical_addr(&self) -> &str {
        &self.canonical_addr
    }
}

/// Canonicalize a TCP `SocketAddr` into a stable string representation.
///
/// IPv4: `"a.b.c.d:port"` (e.g., `"127.0.0.1:12345"`)
/// IPv6: `"[::1]:port"` (e.g., `"[::1]:12345"`)
///
/// This normalization ensures that the same socket address always produces
/// the same canonical string, enabling reliable equality comparison.
fn canonicalize_tcp_addr(addr: &std::net::SocketAddr) -> String {
    match addr {
        std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

// ─── VerifiedHandshake (N2.1.2.4 / N2.1.2.5) ─────────────────────────────────

/// **N2.1.2.4 / N2.1.2.5.** An **unforgeable** proof that a successful
/// SNP-IK/0.1 handshake was completed with a specific peer, **bound to the
/// actual transport endpoint used**.
///
/// ## Why this exists
///
/// `HandshakeResult` (above) has public fields and can be constructed by
/// anyone. It is useful as a data container but is NOT sufficient as a
/// security proof — a caller could synthesize a `HandshakeResult` with
/// matching fields and claim a handshake occurred.
///
/// `VerifiedHandshake` solves this by having **private fields and a private
/// constructor**. The ONLY way to create a `VerifiedHandshake` is through
/// [`perform_snp_ik_handshake_verified`], which performs the actual
/// SNP-IK/0.1 protocol over a real transport. The proof is minted inside
/// the handshake implementation and cannot be manufactured by external code.
///
/// ## N2.1.2.5: Transport binding
///
/// The proof includes a [`TransportBinding`] that records **which transport
/// endpoint the handshake actually occurred over**. This prevents
/// identity/location confusion: a caller cannot perform a handshake over
/// endpoint A, then construct an `AuthenticatedLink` claiming endpoint B
/// (even if B is also advertised).
///
/// ## Usage
///
/// `snp-node`'s `AuthenticatedLink::from_verified_handshake()` consumes a
/// `&VerifiedHandshake` to create an `AuthenticatedLink`. This makes the
/// security boundary real:
///
/// ```text
/// No actual successful handshake
///     → No VerifiedHandshake
///     → No AuthenticatedLink
///     → No route hop
/// ```
///
/// ## Read-only access
///
/// The fields are private. Read-only accessors are provided for the
/// information `snp-node` needs to verify bindings against a
/// `VerifiedNodeAdvertisement`.
#[derive(Debug, Clone)]
pub struct VerifiedHandshake {
    /// The session ID from the completed handshake.
    session_id: [u8; 32],
    /// The authenticated peer NodeId.
    peer_node_id: [u8; 32],
    /// The authenticated peer Ed25519 public key.
    peer_public_key: [u8; 32],
    /// The authenticated peer static X25519 public key.
    peer_x25519_public: [u8; 32],
    /// The peer's ephemeral X25519 public key for THIS session.
    peer_ephemeral_public: [u8; 32],
    /// Directional AEAD link keys.
    link_keys: LinkKeys,
    /// **N2.1.2.5.** The actual transport endpoint used by the handshake.
    /// Bound to the proof at mint time.
    transport_binding: TransportBinding,
}

impl VerifiedHandshake {
    /// **Private constructor.** Only callable from within the `snp-link` crate
    /// (including the `test_support` submodule). External code CANNOT create
    /// a `VerifiedHandshake`.
    #[must_use]
    pub(crate) fn new(
        session_id: [u8; 32],
        peer_node_id: [u8; 32],
        peer_public_key: [u8; 32],
        peer_x25519_public: [u8; 32],
        peer_ephemeral_public: [u8; 32],
        link_keys: LinkKeys,
        transport_binding: TransportBinding,
    ) -> Self {
        Self {
            session_id,
            peer_node_id,
            peer_public_key,
            peer_x25519_public,
            peer_ephemeral_public,
            link_keys,
            transport_binding,
        }
    }

    /// Get the session ID.
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Get the authenticated peer NodeId.
    #[must_use]
    pub fn peer_node_id(&self) -> [u8; 32] {
        self.peer_node_id
    }

    /// Get the authenticated peer Ed25519 public key.
    #[must_use]
    pub fn peer_public_key(&self) -> [u8; 32] {
        self.peer_public_key
    }

    /// Get the authenticated peer static X25519 public key.
    #[must_use]
    pub fn peer_x25519_public(&self) -> [u8; 32] {
        self.peer_x25519_public
    }

    /// Get the peer's ephemeral X25519 public key for this session.
    #[must_use]
    pub fn peer_ephemeral_public(&self) -> [u8; 32] {
        self.peer_ephemeral_public
    }

    /// Get the directional AEAD link keys.
    ///
    /// These keys are the output of the handshake and are used for
    /// encrypted frame transport. The caller takes ownership.
    #[must_use]
    pub fn link_keys(&self) -> LinkKeys {
        self.link_keys.clone()
    }

    /// **N2.1.2.5.** Get the transport binding — the actual transport
    /// endpoint used by the handshake.
    ///
    /// This is the proof that the handshake occurred over this specific
    /// endpoint, not just any advertised endpoint.
    #[must_use]
    pub fn transport_binding(&self) -> &TransportBinding {
        &self.transport_binding
    }

    /// Convert from a `HandshakeResult` (internal only).
    ///
    /// This is `pub(crate)` — only callable from within `snp-link` (including
    /// the `async_link` submodule). It is used by
    /// `perform_snp_ik_handshake_verified` (sync) and
    /// `perform_snp_ik_handshake_verified_async` (async) to convert their
    /// internal `HandshakeResult` into the unforgeable `VerifiedHandshake`
    /// proof, binding it to the actual transport endpoint.
    #[must_use]
    pub(crate) fn from_handshake_result(result: &HandshakeResult, transport_binding: TransportBinding) -> Self {
        Self::new(
            result.session_id,
            result.peer_node_id,
            result.peer_public_key,
            result.peer_x25519_public,
            result.peer_ephemeral_public,
            result.link_keys.clone(),
            transport_binding,
        )
    }
}

/// Derive directional AEAD link keys from the three SNP-IK/0.1 DH outputs.
///
/// Per ADR-0006 step 6: `HKDF-SHA256(dh1 || dh2 || dh3, salt=empty,
/// info="SNP-IK/0.1 link keys")` produces a 32-byte base key. The base key
/// is then HKDF-expanded twice with directional `info` strings to produce
/// the initiator→responder and responder→initiator keys, following the
/// same pattern as N1.9 [`derive_link_keys`].
///
/// The `is_initiator` parameter controls which directional key becomes
/// `send_key` vs `recv_key` — the side that opened the TCP connection
/// passes `true`; the side that accepted passes `false`.
///
/// # Panics
/// Never panics (HKDF-SHA256 32-byte expand is infallible for valid IKM).
#[must_use]
pub fn derive_link_keys_from_dh(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    is_initiator: bool,
) -> LinkKeys {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    let base = hkdf_sha256(&ikm, b"", SNP_IK_LINK_KEYS_INFO, 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let i2r = hkdf_sha256(&base, SNP_IK_LINK_DIR_SALT, SNP_IK_LINK_DIR_I2R, 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let r2i = hkdf_sha256(&base, SNP_IK_LINK_DIR_SALT, SNP_IK_LINK_DIR_R2I, 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let mut i2r_arr = [0u8; 32];
    i2r_arr.copy_from_slice(&i2r);
    let mut r2i_arr = [0u8; 32];
    r2i_arr.copy_from_slice(&r2i);
    if is_initiator {
        LinkKeys { send_key: i2r_arr, recv_key: r2i_arr }
    } else {
        LinkKeys { send_key: r2i_arr, recv_key: i2r_arr }
    }
}

/// Build the CBOR preimage of a NodeDescriptor for signing/verifying.
///
/// Per ADR-0006 the descriptor contains:
/// - `nodeId`: SHA-256("SNP/0.1 node\0" || ed25519_pub) (invariant I4)
/// - `pubKey`: Ed25519 identity public key (32 bytes, raw — invariant I3)
/// - `ephPub`: ephemeral X25519 public key for THIS session (32 bytes)
/// - `staticPub`: static X25519 rendezvous public key (32 bytes)
///
/// The signature is over `SIG_CONTEXTS.NODE_DESCRIPTOR || CBOR(preimage)` (I2).
///
/// The `ephPub` field is included in the signed preimage (NOT just sent
/// alongside the descriptor) so that an active attacker cannot strip the
/// ephemeral key and substitute their own — the signature binds all four
/// fields together.
pub(crate) fn node_descriptor_preimage(
    node_id: &[u8; 32],
    pub_key: &[u8; 32],
    eph_pub: &[u8; 32],
    static_pub: &[u8; 32],
) -> CborValue {
    CborValue::Map(vec![
        (CborValue::TextString("nodeId".into()), CborValue::ByteString(node_id.to_vec())),
        (CborValue::TextString("pubKey".into()), CborValue::ByteString(pub_key.to_vec())),
        (CborValue::TextString("ephPub".into()), CborValue::ByteString(eph_pub.to_vec())),
        (CborValue::TextString("staticPub".into()), CborValue::ByteString(static_pub.to_vec())),
    ])
}

/// Encode a full SNP-IK/0.1 handshake message (descriptor + signature).
pub(crate) fn encode_handshake_message(
    node_id: &[u8; 32],
    pub_key: &[u8; 32],
    eph_pub: &[u8; 32],
    static_pub: &[u8; 32],
    sig: &[u8; 64],
) -> LinkResult<Vec<u8>> {
    let msg = CborValue::Map(vec![
        (CborValue::TextString("nodeId".into()), CborValue::ByteString(node_id.to_vec())),
        (CborValue::TextString("pubKey".into()), CborValue::ByteString(pub_key.to_vec())),
        (CborValue::TextString("ephPub".into()), CborValue::ByteString(eph_pub.to_vec())),
        (CborValue::TextString("staticPub".into()), CborValue::ByteString(static_pub.to_vec())),
        (CborValue::TextString("sig".into()), CborValue::ByteString(sig.to_vec())),
    ]);
    Ok(snp_cbor::encode(&msg)?)
}

/// Decode a SNP-IK/0.1 handshake message. Returns the five fields in order.
pub(crate) fn decode_handshake_message(
    bytes: &[u8],
) -> LinkResult<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 64])> {
    let value = snp_cbor::decode(bytes)?;
    let entries = match value {
        CborValue::Map(e) => e,
        other => {
            return Err(LinkError::HandshakeMalformed(format!(
                "handshake message must be a CBOR map; got {other:?}"
            )));
        }
    };
    let mut node_id: Option<[u8; 32]> = None;
    let mut pub_key: Option<[u8; 32]> = None;
    let mut eph_pub: Option<[u8; 32]> = None;
    let mut static_pub: Option<[u8; 32]> = None;
    let mut sig: Option<[u8; 64]> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::TextString(s) => s,
            other => {
                return Err(LinkError::HandshakeMalformed(format!(
                    "handshake key must be text; got {other:?}"
                )));
            }
        };
        let bytes_val = match v {
            CborValue::ByteString(b) => b,
            other => {
                return Err(LinkError::HandshakeMalformed(format!(
                    "handshake value for \"{key}\" must be a byte string; got {other:?}"
                )));
            }
        };
        match key.as_str() {
            "nodeId" => {
                if bytes_val.len() != 32 {
                    return Err(LinkError::HandshakeMalformed(format!(
                        "nodeId must be 32 bytes; got {}",
                        bytes_val.len()
                    )));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes_val);
                node_id = Some(a);
            }
            "pubKey" => {
                if bytes_val.len() != 32 {
                    return Err(LinkError::HandshakeMalformed(format!(
                        "pubKey must be 32 bytes; got {}",
                        bytes_val.len()
                    )));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes_val);
                pub_key = Some(a);
            }
            "ephPub" => {
                if bytes_val.len() != 32 {
                    return Err(LinkError::HandshakeMalformed(format!(
                        "ephPub must be 32 bytes; got {}",
                        bytes_val.len()
                    )));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes_val);
                eph_pub = Some(a);
            }
            "staticPub" => {
                if bytes_val.len() != 32 {
                    return Err(LinkError::HandshakeMalformed(format!(
                        "staticPub must be 32 bytes; got {}",
                        bytes_val.len()
                    )));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes_val);
                static_pub = Some(a);
            }
            "sig" => {
                if bytes_val.len() != 64 {
                    return Err(LinkError::HandshakeMalformed(format!(
                        "sig must be 64 bytes; got {}",
                        bytes_val.len()
                    )));
                }
                let mut a = [0u8; 64];
                a.copy_from_slice(&bytes_val);
                sig = Some(a);
            }
            other => {
                return Err(LinkError::HandshakeMalformed(format!(
                    "unknown handshake field \"{other}\""
                )));
            }
        }
    }
    let node_id = node_id.ok_or_else(|| LinkError::HandshakeMalformed("nodeId missing".into()))?;
    let pub_key = pub_key.ok_or_else(|| LinkError::HandshakeMalformed("pubKey missing".into()))?;
    let eph_pub = eph_pub.ok_or_else(|| LinkError::HandshakeMalformed("ephPub missing".into()))?;
    let static_pub =
        static_pub.ok_or_else(|| LinkError::HandshakeMalformed("staticPub missing".into()))?;
    let sig = sig.ok_or_else(|| LinkError::HandshakeMalformed("sig missing".into()))?;
    Ok((node_id, pub_key, eph_pub, static_pub, sig))
}

/// Write a length-prefixed handshake message to the stream.
///
/// The wire format is `[4-byte BE length][CBOR handshake message]`. The
/// length is capped at 8 KiB — handshake messages are tiny (~190 bytes), so
/// any larger value indicates a corrupted stream or an attacker.
fn write_handshake_message(stream: &mut TcpStream, bytes: &[u8]) -> LinkResult<()> {
    if bytes.len() > 8 * 1024 {
        return Err(LinkError::AbsurdLength(u32::try_from(bytes.len()).unwrap_or(u32::MAX)));
    }
    let len = u32::try_from(bytes.len()).map_err(|_| LinkError::AbsurdLength(u32::MAX))?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| LinkError::Io(e.to_string()))?;
    stream
        .write_all(bytes)
        .map_err(|e| LinkError::Io(e.to_string()))?;
    stream.flush().map_err(|e| LinkError::Io(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed handshake message from the stream.
fn read_handshake_message(stream: &mut TcpStream) -> LinkResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| LinkError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf);
    if len > 8 * 1024 {
        return Err(LinkError::AbsurdLength(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .map_err(|e| LinkError::Io(e.to_string()))?;
    Ok(buf)
}

/// Perform the SNP-IK/0.1 handshake over an already-connected TCP stream.
///
/// Per ADR-0006, the construction is:
/// 1. Both sides generate a fresh ephemeral X25519 keypair.
/// 2. The initiator sends `E + signed NodeDescriptor` first.
/// 3. The responder sends `E' + signed NodeDescriptor` second.
/// 4. Both compute dh1, dh2, dh3 and derive `LinkKeys`.
/// 5. Both verify the peer's NodeDescriptor signature BEFORE accepting the link.
///
/// The function returns a [`HandshakeResult`] containing the freshly-derived
/// link keys and the peer's authenticated identity.
///
/// # Parameters
/// - `stream`: the connected TCP stream. The caller MAY set a read timeout
///   on the stream before calling this function.
/// - `is_initiator`: `true` for the side that opened the TCP connection,
///   `false` for the side that accepted.
/// - `my_ed25519_secret`/`my_ed25519_public`: the node's Ed25519 identity
///   keypair. Signs the NodeDescriptor.
/// - `my_x25519_secret`/`my_x25519_public`: the node's STATIC X25519
///   rendezvous keypair. Used in dh1 and dh2 (the static DH operations).
/// - `expected_peer_node_id`: if `Some`, the handshake fails if the peer's
///   verified NodeId does not match. This is the "I"-style pinning
///   (initiator knows the responder's identity in advance).
///
/// # Errors
/// Returns [`LinkError::HandshakeBadSignature`] if the peer's signature
/// does not verify; [`LinkError::HandshakeNodeIdMismatch`] if the peer's
/// NodeId does not match `SHA-256("SNP/0.1 node\0" || peer_pubKey)`;
/// [`LinkError::HandshakeUnexpectedPeer`] if `expected_peer_node_id` is set
/// and does not match the peer's NodeId; [`LinkError::HandshakeMalformed`]
/// if the peer sent an invalid CBOR message; [`LinkError::Io`] on transport
/// failure.
///
/// # Forward secrecy
/// The ephemeral X25519 secrets are dropped when this function returns
/// (Rust's drop semantics handle this). An attacker who compromises both
/// static keys AFTER the handshake cannot recover the link keys.
///
/// # Panics
/// Never panics for well-formed inputs.
pub fn perform_snp_ik_handshake(
    stream: &mut TcpStream,
    is_initiator: bool,
    my_ed25519_secret: &[u8; 32],
    my_ed25519_public: &[u8; 32],
    my_x25519_secret: &X25519Secret,
    my_x25519_public: &X25519PubKey,
    expected_peer_node_id: Option<&[u8; 32]>,
) -> LinkResult<HandshakeResult> {
    // 1. Generate a fresh ephemeral X25519 keypair for this session.
    let (eph_secret, eph_public) = x25519_ephemeral_keypair();
    let eph_pub_bytes: [u8; 32] = eph_public.to_bytes();
    let static_pub_bytes: [u8; 32] = my_x25519_public.to_bytes();
    let my_node_id = derive_node_id(my_ed25519_public);

    // 2. Build + sign our NodeDescriptor.
    let preimage = node_descriptor_preimage(&my_node_id, my_ed25519_public, &eph_pub_bytes, &static_pub_bytes);
    let preimage_bytes = snp_cbor::encode(&preimage)?;
    let mut signed_msg = Vec::with_capacity(sig_contexts::NODE_DESCRIPTOR.len() + preimage_bytes.len());
    signed_msg.extend_from_slice(sig_contexts::NODE_DESCRIPTOR);
    signed_msg.extend_from_slice(&preimage_bytes);
    let sig = ed25519_sign(my_ed25519_secret, &signed_msg);

    // 3. Encode the handshake message.
    let my_msg = encode_handshake_message(
        &my_node_id,
        my_ed25519_public,
        &eph_pub_bytes,
        &static_pub_bytes,
        &sig,
    )?;

    // 4. Exchange messages: initiator sends first, then receives;
    //    responder receives first, then sends.
    let peer_msg_bytes = if is_initiator {
        write_handshake_message(stream, &my_msg)?;
        read_handshake_message(stream)?
    } else {
        let received = read_handshake_message(stream)?;
        write_handshake_message(stream, &my_msg)?;
        received
    };

    // 5. Decode + verify the peer's handshake message.
    let (peer_node_id, peer_pub_key, peer_eph_pub, peer_static_pub, peer_sig) =
        decode_handshake_message(&peer_msg_bytes)?;

    // 5a. Verify the peer's signature over its NodeDescriptor.
    let peer_preimage = node_descriptor_preimage(&peer_node_id, &peer_pub_key, &peer_eph_pub, &peer_static_pub);
    let peer_preimage_bytes = snp_cbor::encode(&peer_preimage)?;
    let mut peer_signed = Vec::with_capacity(sig_contexts::NODE_DESCRIPTOR.len() + peer_preimage_bytes.len());
    peer_signed.extend_from_slice(sig_contexts::NODE_DESCRIPTOR);
    peer_signed.extend_from_slice(&peer_preimage_bytes);
    if !ed25519_verify(&peer_pub_key, &peer_signed, &peer_sig) {
        return Err(LinkError::HandshakeBadSignature);
    }

    // 5b. Verify I4: peer's NodeId == SHA-256("SNP/0.1 node\0" || peer_pubKey).
    let derived_peer_node_id = derive_node_id(&peer_pub_key);
    if peer_node_id != derived_peer_node_id {
        return Err(LinkError::HandshakeNodeIdMismatch);
    }

    // 5c. Verify "I"-style pinning: peer's NodeId matches expected (if set).
    if let Some(expected) = expected_peer_node_id {
        if &peer_node_id != expected {
            return Err(LinkError::HandshakeUnexpectedPeer);
        }
    }

    // 6. Compute the three DH operations.
    //
    //    The IKM order MUST be the same on both sides (initiator and
    //    responder). We use the canonical order:
    //      dh1 = DH(initiator_eph,  responder_static)
    //      dh2 = DH(initiator_static, responder_eph)
    //      dh3 = DH(initiator_eph,  responder_eph)
    //
    //    X25519 DH is symmetric: DH(a, B) == DH(b, A). So:
    //    - The initiator computes dh1 = DH(my_eph, peer_static), dh2 = DH(my_static, peer_eph), dh3 = DH(my_eph, peer_eph).
    //    - The responder computes the SAME dh1 = DH(peer_eph, my_static) = DH(my_static, peer_eph) — note the swap!
    //      To produce the same dh1, the responder uses my_static × peer_eph (NOT my_eph × peer_static).
    //      Similarly, the responder's dh2 = DH(peer_static, my_eph) = DH(my_eph, peer_static).
    //
    //    Concretely:
    //    - initiator: dh1 = DH(my_eph, peer_static), dh2 = DH(my_static, peer_eph), dh3 = DH(my_eph, peer_eph)
    //    - responder: dh1 = DH(my_static, peer_eph), dh2 = DH(my_eph, peer_static), dh3 = DH(my_eph, peer_eph)
    //
    //    dh3 is the same on both sides (DH is symmetric).
    let peer_eph_pub_key = x25519_public_from_bytes(&peer_eph_pub);
    let peer_static_pub_key = x25519_public_from_bytes(&peer_static_pub);
    let (dh1, dh2, dh3) = if is_initiator {
        let dh1 = x25519_dh(&eph_secret, &peer_static_pub_key);
        let dh2 = x25519_dh(my_x25519_secret, &peer_eph_pub_key);
        let dh3 = x25519_dh(&eph_secret, &peer_eph_pub_key);
        (dh1, dh2, dh3)
    } else {
        // Responder: swap dh1 and dh2 to match the initiator's IKM order.
        let dh1 = x25519_dh(my_x25519_secret, &peer_eph_pub_key);
        let dh2 = x25519_dh(&eph_secret, &peer_static_pub_key);
        let dh3 = x25519_dh(&eph_secret, &peer_eph_pub_key);
        (dh1, dh2, dh3)
    };

    // 7. Derive link keys.
    let link_keys = derive_link_keys_from_dh(&dh1, &dh2, &dh3, is_initiator);

    // 8. Compute the session_id: SHA-256(initiator_eph || responder_eph || dh3).
    //    This is the closest analogue to Noise's handshake hash that
    //    SNP-IK/0.1 provides. The session_id is bound to the ephemeral
    //    keys (fresh per session) AND to dh3 (the ephemeral-ephemeral DH),
    //    so it differs across sessions even between the same pair of nodes.
    let mut session_id_input = Vec::with_capacity(96);
    if is_initiator {
        session_id_input.extend_from_slice(&eph_pub_bytes);
        session_id_input.extend_from_slice(&peer_eph_pub);
    } else {
        session_id_input.extend_from_slice(&peer_eph_pub);
        session_id_input.extend_from_slice(&eph_pub_bytes);
    }
    session_id_input.extend_from_slice(&dh3);
    let session_id = sha256(&session_id_input);

    Ok(HandshakeResult {
        link_keys,
        peer_node_id,
        peer_public_key: peer_pub_key,
        peer_x25519_public: peer_static_pub,
        peer_ephemeral_public: peer_eph_pub,
        session_id,
    })
}

/// **N2.1.2.4 / N2.1.2.5.** Perform the SNP-IK/0.1 handshake and return an
/// **unforgeable** `VerifiedHandshake` proof, **bound to the actual transport
/// endpoint**.
///
/// This is the same as [`perform_snp_ik_handshake`], but returns a
/// `VerifiedHandshake` instead of a `HandshakeResult`. The
/// `VerifiedHandshake` has private fields and a private constructor — it
/// can ONLY be created by this function. External code cannot manufacture
/// a `VerifiedHandshake`.
///
/// **N2.1.2.5:** The proof includes a `TransportBinding` obtained from
/// `stream.peer_addr()` — the actual TCP endpoint the handshake occurred
/// over. This prevents identity/location confusion.
///
/// Use this function when you need to create an `AuthenticatedLink` in
/// `snp-node`. The `VerifiedHandshake` is the security proof that the
/// handshake actually occurred over a specific endpoint.
///
/// # Errors
/// Returns `LinkError` if the handshake fails (I/O error, signature
/// verification failure, NodeId mismatch, etc.) or if the transport
/// binding cannot be obtained.
pub fn perform_snp_ik_handshake_verified(
    stream: &mut TcpStream,
    is_initiator: bool,
    my_ed25519_secret: &[u8; 32],
    my_ed25519_public: &[u8; 32],
    my_x25519_secret: &X25519Secret,
    my_x25519_public: &X25519PubKey,
    expected_peer_node_id: Option<&[u8; 32]>,
) -> LinkResult<VerifiedHandshake> {
    let result = perform_snp_ik_handshake(
        stream,
        is_initiator,
        my_ed25519_secret,
        my_ed25519_public,
        my_x25519_secret,
        my_x25519_public,
        expected_peer_node_id,
    )?;
    // N2.1.2.5: Extract the actual transport endpoint from the TcpStream.
    // This binds the proof to the specific endpoint the handshake occurred over.
    let peer_addr = stream.peer_addr().map_err(|e| LinkError::Io(e.to_string()))?;
    let transport_binding = TransportBinding::from_tcp_socket_addr(peer_addr);
    // Mint the unforgeable proof from the internal HandshakeResult + transport binding.
    // This conversion is private — external code cannot call it.
    Ok(VerifiedHandshake::from_handshake_result(&result, transport_binding))
}

// ─── Circuit keys (N1.9 — end-to-end client↔gateway) ────────────────────────

/// A pair of AEAD keys for the end-to-end client↔gateway circuit.
///
/// The circuit key encrypts the TransitRequest body (and the TransitResponse
/// body) end-to-end. The relay NEVER possesses this key — it sees only the
/// opaque ciphertext inside the frame body.
///
/// Derivation mirrors [`LinkKeys`]: a shared seed produces two directional
/// keys via HKDF with distinct `info` strings. The client (initiator of the
/// transit request) uses `send_key` to encrypt the request and `recv_key` to
/// decrypt the response; the gateway (responder) does the opposite.
#[derive(Debug, Clone, Copy)]
pub struct CircuitKeys {
    /// Key used to encrypt outbound circuit payloads (TransitRequest for the
    /// client, TransitResponse for the gateway).
    pub send_key: SymmetricKey,
    /// Key used to decrypt inbound circuit payloads.
    pub recv_key: SymmetricKey,
}

/// Derive directional end-to-end circuit keys from a deterministic seed.
///
/// Both the client and the gateway MUST pass the SAME `seed`. The
/// `is_initiator` parameter distinguishes them: the client (who initiates the
/// TransitRequest) passes `true`, the gateway passes `false`.
///
/// # Derivation
///
/// ```text
///   base  = HKDF-SHA256(seed, salt="SNP/0.1 circuit base", info="", L=32)
///   i2r   = HKDF-SHA256(base, salt="SNP/0.1 circuit dir", info="initiator-to-responder", L=32)
///   r2i   = HKDF-SHA256(base, salt="SNP/0.1 circuit dir", info="responder-to-initiator", L=32)
///   client (initiator):  CircuitKeys { send_key: i2r, recv_key: r2i }
///   gateway (responder): CircuitKeys { send_key: r2i, recv_key: i2r }
/// ```
///
/// # N1.9 vs production
///
/// For N1.9 the circuit seed is pre-shared (a deterministic test value). The
/// production target derives the circuit seed from the SNP-IK/0.1 handshake
/// transcript between client and gateway, so the relay (which only sees the
/// outer hop-handshake) cannot derive it.
#[must_use]
pub fn derive_circuit_keys(seed: &[u8], is_initiator: bool) -> CircuitKeys {
    let base = hkdf_sha256(seed, b"SNP/0.1 circuit base", b"", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let i2r = hkdf_sha256(&base, b"SNP/0.1 circuit dir", b"initiator-to-responder", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let r2i = hkdf_sha256(&base, b"SNP/0.1 circuit dir", b"responder-to-initiator", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let mut i2r_arr = [0u8; 32];
    i2r_arr.copy_from_slice(&i2r);
    let mut r2i_arr = [0u8; 32];
    r2i_arr.copy_from_slice(&r2i);
    if is_initiator {
        CircuitKeys {
            send_key: i2r_arr,
            recv_key: r2i_arr,
        }
    } else {
        CircuitKeys {
            send_key: r2i_arr,
            recv_key: i2r_arr,
        }
    }
}

// ─── N2.0.2 — Fresh circuit keys via client↔gateway X25519 DH ────────────────
//
// Per ADR-0011 Layer 2, the circuit key MUST be end-to-end (client ↔ gateway)
// and MUST NOT be derivable by any relay. The N1.9 `derive_circuit_keys`
// function above uses a pre-shared seed — production derives the seed from
// a CLIENT ↔ GATEWAY key agreement that the relay does not participate in.
//
// The N2.0.2 construction (this block) uses a fresh X25519 ephemeral-static
// DH between the client and the gateway. The gateway holds a STATIC X25519
// "circuit" keypair (separate from its SNP-IK/0.1 link keypair); the client
// generates a fresh EPHEMERAL X25519 keypair per request. The client sends
// its ephemeral pub in the first 32 bytes of the request frame body; the
// gateway derives the circuit keys from `DH(client_eph, gateway_static)`.
//
// Two requests to the same gateway produce DIFFERENT circuit keys (because
// the client's ephemeral is fresh per request). The relay sees the frame
// body (including the client's eph pub) but cannot derive the DH output
// (it lacks the gateway's static secret). This satisfies ADR-0011 Layer 2
// for N2.0.2.

/// HKDF `salt` literal for the N2.0.2 fresh-DH circuit-key derivation.
pub const CIRCUIT_DH_BASE_SALT: &[u8] = b"SNP/0.1 circuit-dh base";

/// HKDF `info` literal for the N2.0.2 fresh-DH circuit-key derivation.
pub const CIRCUIT_DH_BASE_INFO: &[u8] = b"SNP/0.1 N2.0.2 circuit-from-dh";

/// Derive directional end-to-end circuit keys from a single X25519 DH output.
///
/// Used by the N2.0.2 fresh-circuit-key construction (see module docs above).
/// Both the client and the gateway pass the SAME 32-byte DH output (computed
/// independently via `DH(client_eph, gateway_static)`); the `is_initiator`
/// parameter distinguishes them (client = initiator, gateway = responder).
///
/// # Derivation
/// ```text
///   base  = HKDF-SHA256(dh, salt="SNP/0.1 circuit-dh base",
///                        info="SNP/0.1 N2.0.2 circuit-from-dh", L=32)
///   i2r   = HKDF-SHA256(base, salt="SNP/0.1 circuit dir",
///                        info="initiator-to-responder", L=32)
///   r2i   = HKDF-SHA256(base, salt="SNP/0.1 circuit dir",
///                        info="responder-to-initiator", L=32)
///   client:  CircuitKeys { send_key: i2r, recv_key: r2i }
///   gateway: CircuitKeys { send_key: r2i, recv_key: i2r }
/// ```
///
/// # Panics
/// Never panics (HKDF-SHA256 32-byte expand is infallible for valid IKM).
#[must_use]
pub fn derive_circuit_keys_from_dh(dh: &[u8; 32], is_initiator: bool) -> CircuitKeys {
    let base = hkdf_sha256(dh, CIRCUIT_DH_BASE_SALT, CIRCUIT_DH_BASE_INFO, 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let i2r = hkdf_sha256(&base, b"SNP/0.1 circuit dir", b"initiator-to-responder", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let r2i = hkdf_sha256(&base, b"SNP/0.1 circuit dir", b"responder-to-initiator", 32)
        .expect("HKDF-SHA256 32-byte expand never fails");
    let mut i2r_arr = [0u8; 32];
    i2r_arr.copy_from_slice(&i2r);
    let mut r2i_arr = [0u8; 32];
    r2i_arr.copy_from_slice(&r2i);
    if is_initiator {
        CircuitKeys { send_key: i2r_arr, recv_key: r2i_arr }
    } else {
        CircuitKeys { send_key: r2i_arr, recv_key: i2r_arr }
    }
}

/// Length of the X25519 public key prefix on a circuit-frame body.
pub const CIRCUIT_EPH_PUB_LEN: usize = 32;

/// Seal a TransitRequest payload with a FRESH client X25519 ephemeral key.
///
/// Generates a fresh X25519 keypair, computes `DH(client_eph, gateway_static)`,
/// derives `CircuitKeys` (initiator role), encrypts the `plaintext` with
/// `send_key`, and returns the frame body:
///
/// ```text
///   frame_body = client_eph_pub (32 bytes) || sealed_payload
/// ```
///
/// The gateway reads the first 32 bytes to recover `client_eph_pub`, computes
/// the same DH (using its static secret), derives the same `CircuitKeys`
/// (responder role), and decrypts with `recv_key` via
/// [`open_circuit_payload_with_fresh_eph`].
///
/// Returns `(circuit_keys, client_eph_pub, frame_body)`. The caller uses
/// `circuit_keys.recv_key` to decrypt the gateway's response (which is sealed
/// with the responder's `send_key`, equal to the initiator's `recv_key`).
///
/// The fresh `eph_secret` is dropped at the end of this function — it is NOT
/// returned to the caller. This provides forward secrecy: a later compromise
/// of the caller's memory cannot recover the ephemeral secret.
///
/// # Panics
/// Never panics for a 32-byte `gateway_static_pub` (X25519 + AEAD are
/// infallible for valid inputs).
#[must_use]
pub fn seal_circuit_payload_with_fresh_eph(
    gateway_static_pub: &X25519PubKey,
    plaintext: &[u8],
) -> (CircuitKeys, X25519PubKey, Vec<u8>) {
    let (eph_secret, eph_pub) = x25519_ephemeral_keypair();
    let dh = x25519_dh(&eph_secret, gateway_static_pub);
    let keys = derive_circuit_keys_from_dh(&dh, true);
    let sealed = encrypt_circuit_payload(&keys.send_key, plaintext);
    let mut body = Vec::with_capacity(CIRCUIT_EPH_PUB_LEN + sealed.len());
    body.extend_from_slice(&eph_pub.to_bytes());
    body.extend_from_slice(&sealed);
    // eph_secret is dropped here — forward secrecy.
    drop(eph_secret);
    (keys, eph_pub, body)
}

/// Open a circuit-frame body that was sealed with
/// [`seal_circuit_payload_with_fresh_eph`].
///
/// Extracts `client_eph_pub` from the first 32 bytes of `body`, computes
/// `DH(gateway_static_secret, client_eph_pub)`, derives `CircuitKeys`
/// (responder role), and decrypts the remainder of `body` with `recv_key`.
///
/// Returns `Some((client_eph_pub, plaintext))` on success, or `None` on AEAD
/// authentication failure (I20 — never throws).
#[must_use]
pub fn open_circuit_payload_with_fresh_eph(
    gateway_static_secret: &X25519Secret,
    body: &[u8],
) -> Option<(X25519PubKey, Vec<u8>)> {
    if body.len() < CIRCUIT_EPH_PUB_LEN {
        return None;
    }
    let mut eph_pub_arr = [0u8; 32];
    eph_pub_arr.copy_from_slice(&body[..CIRCUIT_EPH_PUB_LEN]);
    let eph_pub = x25519_public_from_bytes(&eph_pub_arr);
    let dh = x25519_dh(gateway_static_secret, &eph_pub);
    let keys = derive_circuit_keys_from_dh(&dh, false);
    let sealed = &body[CIRCUIT_EPH_PUB_LEN..];
    let plaintext = decrypt_circuit_payload(&keys.recv_key, sealed)?;
    Some((eph_pub, plaintext))
}

/// Derive the gateway's response-direction circuit key from the SAME
/// `DH(client_eph, gateway_static)` used to open the request.
///
/// After the gateway has opened the request (via
/// [`open_circuit_payload_with_fresh_eph`]), it uses this function to derive
/// the `send_key` for encrypting the response. The response frame body is
/// just the sealed TransitResponse (NO eph-pub prefix — the gateway's static
/// key is already known to the client, and the client derived `recv_key`
/// alongside `send_key` in [`seal_circuit_payload_with_fresh_eph`]).
///
/// Returns the `CircuitKeys` (in responder role) so the gateway can call
/// `encrypt_circuit_payload(&keys.send_key, ...)` for the response.
#[must_use]
pub fn derive_gateway_response_keys(
    gateway_static_secret: &X25519Secret,
    client_eph_pub: &X25519PubKey,
) -> CircuitKeys {
    let dh = x25519_dh(gateway_static_secret, client_eph_pub);
    derive_circuit_keys_from_dh(&dh, false)
}

/// AAD used for circuit-layer AEAD. Distinguishes circuit ciphertext from
/// frame ciphertext (which uses empty AAD) so the same key cannot be reused
/// across layers even by accident.
pub const CIRCUIT_AAD: &[u8] = b"SNP/0.1 circuit\0";

/// Encrypt a circuit payload (e.g. a CBOR-encoded TransitRequest) with the
/// caller's `circuit_send_key`.
///
/// Returns `nonce(12) ‖ ciphertext ‖ tag(16)`. The 12-byte nonce is fresh per
/// call (derived from a monotonic counter + wall clock — see
/// [`random_circuit_nonce`]); it is prepended to the sealed blob so the
/// decryptor does not need to track counters.
///
/// # Errors
/// This function is infallible for a 32-byte key (ChaCha20-Poly1305 never
/// fails to encrypt). It returns `Vec<u8>` rather than `Result` for
/// ergonomics.
#[must_use]
pub fn encrypt_circuit_payload(key: &SymmetricKey, plaintext: &[u8]) -> Vec<u8> {
    let nonce = random_circuit_nonce();
    encrypt_circuit_payload_with_nonce(key, &nonce, plaintext)
}

/// Encrypt a circuit payload with an explicit nonce. Exposed for tests that
/// need deterministic ciphertext.
///
/// # Panics
/// Never panics for a 32-byte key.
#[must_use]
pub fn encrypt_circuit_payload_with_nonce(
    key: &SymmetricKey,
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Vec<u8> {
    let sealed = aead_seal(key, nonce, plaintext, CIRCUIT_AAD);
    let mut out = Vec::with_capacity(NONCE_LEN + sealed.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Decrypt a circuit payload produced by [`encrypt_circuit_payload`] (or
/// [`encrypt_circuit_payload_with_nonce`]).
///
/// The first 12 bytes of `sealed` are the nonce; the rest is
/// `ciphertext ‖ tag`. Returns `None` on AEAD auth failure (I20 — never
/// throws). This is the function the gateway calls after decrypting the outer
/// frame; it is also the function a malicious relay would call (with the
/// wrong key) and observe returning `None`.
#[must_use]
pub fn decrypt_circuit_payload(key: &SymmetricKey, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ct_tag = &sealed[NONCE_LEN..];
    aead_open(key, &nonce, ct_tag, CIRCUIT_AAD)
}

/// Generate a 12-byte nonce for circuit-layer AEAD using `getrandom()`.
///
/// N1.9.1: Replaced the previous `SHA-256(wall_clock_ns ‖ counter)` heuristic
/// with a proper CSPRNG. The nonce does not need to be secret, but it MUST be
/// unique per key. `getrandom()` provides cryptographic randomness from the
/// OS entropy source ( `/dev/urandom` on Linux, `BCryptGenRandom` on Windows,
/// `SecRandomCopyBytes` on macOS). This guarantees uniqueness across:
///   - multiple processes
///   - multiple threads
///   - reconnects and session restarts
///   - Android lifecycle interruptions
///   - key rotation
///
/// The 2^96 collision probability under a single key is negligible
/// (birthday bound: ~2^48 messages for a 50% collision chance, far beyond
/// any realistic circuit lifetime).
pub fn random_circuit_nonce() -> [u8; 12] {
    let mut out = [0u8; 12];
    // getrandom() fills the buffer from the OS CSPRNG. On any platform
    // where getrandom is available (Linux 3.17+, Windows, macOS, Android,
    // iOS), this cannot fail in practice. If it does fail, we panic —
    // a failed nonce generation is a fatal error, not a degraded mode.
    getrandom::getrandom(&mut out).expect("getrandom failed — OS entropy source unavailable");
    out
}

// ─── Link (directional keys) ────────────────────────────────────────────────

/// A bidirectional AEAD-encrypted link over a TCP stream.
///
/// The link holds a `TcpStream` and a [`LinkKeys`] pair (one key for sending,
/// one for receiving). Every call to `send_frame` AEAD-encrypts the frame
/// with `send_key` and a nonce derived from the frame's `(fid, seq)`; every
/// call to `recv_frame` reads, decrypts with `recv_key`, and decodes a frame.
///
/// Because `send_key != recv_key` (when both ends use directional keys), the
/// same `(fid, seq)` appearing in both directions of a link does NOT cause
/// AEAD `(key, nonce)` reuse — see [`derive_link_keys`].
///
/// The `Mutex<TcpStream>` is required so the link can be shared between
/// threads (a relay may want to read on one thread and write on another).
pub struct Link {
    stream: Mutex<TcpStream>,
    send_key: SymmetricKey,
    recv_key: SymmetricKey,
    /// N1.9.2: Replay window — tracks seen (fid, seq) pairs.
    seen_nonces: Mutex<std::collections::HashMap<[u8; 8], SeenNonceSet>>,
}

/// N1.9.2: Sliding-window replay tracker for a single flow ID.
struct SeenNonceSet {
    highest_seq: u32,
    window: [u64; 16], // 1024-bit bitmap
}

impl SeenNonceSet {
    fn new() -> Self {
        Self { highest_seq: 0, window: [0u64; 16] }
    }

    /// Returns true if seq is NEW (accept), false if replay (reject).
    fn check_and_mark(&mut self, seq: u32) -> bool {
        const WSIZE: u32 = 1024;
        if seq == 0 { return false; }
        if self.highest_seq == 0 {
            self.highest_seq = seq;
            self.set_bit(seq);
            return true;
        }
        if seq > self.highest_seq {
            let shift = seq - self.highest_seq;
            if shift >= WSIZE {
                self.window = [0u64; 16];
            } else {
                let ws = (shift / 64) as usize;
                let bs = (shift % 64) as u32;
                let mut nw = [0u64; 16];
                for i in 0usize..16 {
                    let src = i.wrapping_sub(ws);
                    if src < 16 {
                        nw[i] = self.window[src] >> bs;
                        if bs > 0 && src > 0 {
                            nw[i] |= self.window[src - 1] << (64 - bs);
                        }
                    }
                }
                self.window = nw;
            }
            self.highest_seq = seq;
            self.set_bit(seq);
            return true;
        }
        let dist = self.highest_seq.saturating_sub(seq);
        if dist >= WSIZE { return false; }
        if self.get_bit(seq) { return false; }
        self.set_bit(seq);
        true
    }

    fn set_bit(&mut self, seq: u32) {
        let p = (seq % 1024) as usize;
        self.window[p / 64] |= 1u64 << (p % 64);
    }

    fn get_bit(&self, seq: u32) -> bool {
        let p = (seq % 1024) as usize;
        (self.window[p / 64] & (1u64 << (p % 64))) != 0
    }
}

impl Link {
    /// Wrap an already-connected `TcpStream` with an AEAD link.
    ///
    /// Both ends MUST pass matching `LinkKeys` (the initiator's `send_key`
    /// equals the responder's `recv_key`, and vice versa) — typically derived
    /// from the same seed via [`derive_link_keys`].
    #[must_use]
    pub fn new(stream: TcpStream, keys: LinkKeys) -> Self {
        Self {
            stream: Mutex::new(stream),
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            seen_nonces: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Connect to `addr` and wrap the resulting stream in a Link.
    ///
    /// # Errors
    /// Returns [`LinkError::Io`] if the TCP connection fails.
    pub fn connect(addr: &str, keys: LinkKeys) -> LinkResult<Self> {
        let stream = TcpStream::connect(addr).map_err(|e| LinkError::Io(e.to_string()))?;
        // Disable Nagle — SNP frames are small and we want low latency.
        stream
            .set_nodelay(true)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        Ok(Self::new(stream, keys))
    }

    /// Send a Frame: CBOR-encode it, AEAD-encrypt with `send_key` and nonce
    /// `fid ‖ seq_BE`, write `[4-byte BE length][nonce][ciphertext][tag]` to
    /// the stream.
    ///
    /// # Errors
    /// Returns [`LinkError`] on encode or IO failure.
    pub fn send_frame(&self, frame: &Frame) -> LinkResult<()> {
        let plaintext = frame.encode_cbor()?;
        let nonce = aead_nonce(&frame.fid, frame.seq);
        let (ciphertext, tag) = aead_encrypt(&self.send_key, &nonce, &plaintext, b"");
        let mut wire = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        wire.extend_from_slice(&tag);
        let len = u32::try_from(wire.len()).map_err(|_| {
            LinkError::AbsurdLength(u32::MAX)
        })?;
        let mut stream = self.stream.lock().expect("link mutex poisoned");
        stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| LinkError::Io(e.to_string()))?;
        stream
            .write_all(&wire)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        stream.flush().map_err(|e| LinkError::Io(e.to_string()))?;
        Ok(())
    }

    /// Receive a Frame: read `[4-byte BE length][nonce][ciphertext][tag]`,
    /// AEAD-decrypt with `recv_key`, decode the Frame.
    ///
    /// # Errors
    /// Returns [`LinkError::DecryptionFailed`] on AEAD auth failure — the
    /// caller MUST drop the link in this case.
    pub fn recv_frame(&self) -> LinkResult<Frame> {
        let blob = self.recv_raw()?;
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(LinkError::DecryptionFailed);
        }
        let nonce = &blob[..NONCE_LEN];
        let ciphertext = &blob[NONCE_LEN..blob.len() - TAG_LEN];
        let tag = &blob[blob.len() - TAG_LEN..];
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        let plaintext = aead_decrypt(&self.recv_key, &nonce_arr, ciphertext, &tag_arr, b"")
            .ok_or(LinkError::DecryptionFailed)?;
        let frame = Frame::decode_cbor(&plaintext)?;

        // N1.9.2: Replay protection — check (fid, seq) against the seen-nonces window.
        // This prevents catastrophic nonce reuse: without this check, an attacker
        // who replays a captured frame causes the same (key, nonce) to be used
        // twice, leaking plaintext via XOR.
        let mut seen = self.seen_nonces.lock().expect("seen_nonces mutex poisoned");
        let fid_arr: [u8; 8] = frame.fid;
        let set = seen.entry(fid_arr).or_insert_with(SeenNonceSet::new);
        if !set.check_and_mark(frame.seq) {
            return Err(LinkError::ReplayDetected);
        }

        Ok(frame)
    }

    /// Receive a still-encrypted frame blob (the relay's raw path).
    ///
    /// Reads `[4-byte BE length][nonce][ciphertext][tag]` and returns the
    /// full blob (nonce + ciphertext + tag) WITHOUT decrypting. The relay
    /// forwards this blob verbatim — it never holds the plaintext, never
    /// calls AEAD decrypt, never inspects the body.
    ///
    /// # Errors
    /// Returns [`LinkError`] on IO failure or absurd length.
    pub fn recv_raw(&self) -> LinkResult<Vec<u8>> {
        let mut stream = self.stream.lock().expect("link mutex poisoned");
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(LinkError::AbsurdLength(len));
        }
        let mut blob = vec![0u8; len as usize];
        stream
            .read_exact(&mut blob)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        Ok(blob)
    }

    /// Send a still-encrypted frame blob (the relay's raw path).
    ///
    /// Writes `[4-byte BE length][blob]` verbatim. The blob is the same
    /// shape returned by [`recv_raw`]: nonce + ciphertext + tag.
    ///
    /// # Errors
    /// Returns [`LinkError`] on IO failure.
    pub fn send_raw(&self, blob: &[u8]) -> LinkResult<()> {
        let len = u32::try_from(blob.len()).map_err(|_| LinkError::AbsurdLength(u32::MAX))?;
        let mut stream = self.stream.lock().expect("link mutex poisoned");
        stream
            .write_all(&len.to_be_bytes())
            .map_err(|e| LinkError::Io(e.to_string()))?;
        stream
            .write_all(blob)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        stream.flush().map_err(|e| LinkError::Io(e.to_string()))?;
        Ok(())
    }

    /// Access the underlying TCP stream (e.g. to set timeouts).
    ///
    /// Returns a `MutexGuard` so callers can configure the stream safely.
    pub fn stream(&self) -> std::sync::MutexGuard<'_, TcpStream> {
        self.stream.lock().expect("link mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn make_frame(seq: u32) -> Frame {
        let mut frame = Frame::new(b'B', [7u8; 32], [9u8; 32]);
        frame.fid = [1, 2, 3, 4, 5, 6, 7, 8];
        frame.seq = seq;
        frame.body = vec![0xde, 0xad, 0xbe, 0xef];
        frame
    }

    #[test]
    fn send_recv_round_trip_over_tcp() {
        // Spin up a local TCP listener, accept one connection, echo a frame.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Both ends derive from the same seed; the SERVER is the responder,
        // the CLIENT is the initiator. Their send_key/recv_key are swapped.
        let client_keys = derive_link_keys(b"test-seed-A", true);
        let server_keys = derive_link_keys(b"test-seed-A", false);

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let link = Link::new(stream, server_keys);
            let frame = link.recv_frame().unwrap();
            // Echo the same frame back with seq+1.
            let mut echo = frame.clone();
            echo.seq += 1;
            link.send_frame(&echo).unwrap();
        });

        let client_link = Link::connect(&addr.to_string(), client_keys).unwrap();
        let original = make_frame(1);
        client_link.send_frame(&original).unwrap();
        let echoed = client_link.recv_frame().unwrap();
        assert_eq!(echoed.seq, 2);
        assert_eq!(echoed.cls, original.cls);
        assert_eq!(echoed.dst, original.dst);
        assert_eq!(echoed.body, original.body);

        server_thread.join().unwrap();
    }

    #[test]
    fn wrong_key_kills_link() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_keys = derive_link_keys(b"server-seed", false);
        let client_keys = derive_link_keys(b"different-seed", true);

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let link = Link::new(stream, server_keys);
            // Recv will fail (AEAD auth) — caller should kill the link.
            let _ = link.recv_frame();
        });

        let client_link = Link::connect(&addr.to_string(), client_keys).unwrap();
        client_link.send_frame(&make_frame(1)).unwrap();
        // Server thread will end with the AEAD failure logged.

        server_thread.join().unwrap();
    }

    #[test]
    fn relay_forwards_blob_without_decrypting() {
        // Set up: client → relay → gateway. The relay forwards the raw blob.
        let gateway_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        // N1.9: each link has its own seed. For this test we reuse the same
        // seed for both links but use directional keys.
        let client_keys = derive_link_keys(b"mesh-seed", true);
        let relay_to_client_keys = derive_link_keys(b"mesh-seed", false);
        let relay_to_gw_keys = derive_link_keys(b"mesh-seed", true);
        let gw_keys = derive_link_keys(b"mesh-seed", false);

        // Gateway: accept one connection, recv a raw blob, decrypt it as a
        // Frame, echo back with seq+1.
        let gw_thread = std::thread::spawn(move || {
            let (stream, _) = gateway_listener.accept().unwrap();
            let link = Link::new(stream, gw_keys);
            let blob = link.recv_raw().unwrap();
            // The gateway CAN decrypt (it's an endpoint) — but the relay
            // did NOT decrypt. Verify by decrypting here.
            let nonce = &blob[..NONCE_LEN];
            let tag = &blob[blob.len() - TAG_LEN..];
            let ct = &blob[NONCE_LEN..blob.len() - TAG_LEN];
            let mut n = [0u8; 12];
            n.copy_from_slice(nonce);
            let mut t = [0u8; 16];
            t.copy_from_slice(tag);
            let pt = aead_decrypt(&gw_keys.recv_key, &n, ct, &t, b"").unwrap();
            let frame = Frame::decode_cbor(&pt).unwrap();
            assert_eq!(frame.cls, b'B');
            // Echo back.
            let mut echo = frame.clone();
            echo.seq += 1;
            link.send_frame(&echo).unwrap();
        });

        // Relay: accept one connection from client, forward raw blob to
        // gateway, forward raw response back to client.
        let relay_thread = std::thread::spawn(move || {
            let (client_stream, _) = client_listener.accept().unwrap();
            let client_link = Link::new(client_stream, relay_to_client_keys);
            let gw_link = Link::connect(&gateway_addr.to_string(), relay_to_gw_keys).unwrap();
            // Forward: client → gateway (raw, no decrypt).
            let blob = client_link.recv_raw().unwrap();
            gw_link.send_raw(&blob).unwrap();
            // Forward: gateway → client (raw, no decrypt).
            let resp = gw_link.recv_raw().unwrap();
            client_link.send_raw(&resp).unwrap();
        });

        // Client: send a frame to the relay, receive a frame back.
        let client_link = Link::connect(&client_addr.to_string(), client_keys).unwrap();
        client_link.send_frame(&make_frame(1)).unwrap();
        let resp = client_link.recv_frame().unwrap();
        assert_eq!(resp.seq, 2);

        relay_thread.join().unwrap();
        gw_thread.join().unwrap();
    }

    // ─── N1.9 directional-key tests ─────────────────────────────────────────

    #[test]
    fn directional_keys_differ_across_directions() {
        // The initiator's send_key MUST equal the responder's recv_key, and
        // the initiator's recv_key MUST equal the responder's send_key. The
        // two keys MUST differ from each other (else there's no separation).
        let init = derive_link_keys(b"seed-X", true);
        let resp = derive_link_keys(b"seed-X", false);
        assert_eq!(init.send_key, resp.recv_key, "init.send == resp.recv (i2r)");
        assert_eq!(init.recv_key, resp.send_key, "init.recv == resp.send (r2i)");
        assert_ne!(
            init.send_key, init.recv_key,
            "send_key and recv_key MUST differ — else directional separation is broken"
        );
        // Different seeds MUST produce different keys.
        let init2 = derive_link_keys(b"seed-Y", true);
        assert_ne!(init.send_key, init2.send_key);
    }

    #[test]
    fn same_fid_seq_in_both_directions_does_not_reuse_key() {
        // The N1.9 invariant: even if (fid, seq) is the SAME in both
        // directions of a link, the AEAD (key, nonce) pair differs because
        // the directional keys differ. Encrypting the same plaintext under
        // each direction MUST produce different ciphertexts.
        let init = derive_link_keys(b"seed-Y", true);
        let resp = derive_link_keys(b"seed-Y", false);
        let frame = make_frame(1);
        let plaintext = frame.encode_cbor().unwrap();
        let nonce = aead_nonce(&frame.fid, frame.seq);

        // Initiator → responder direction (uses init.send_key == resp.recv_key).
        let (ct_i2r, tag_i2r) = aead_encrypt(&init.send_key, &nonce, &plaintext, b"");
        // Responder → initiator direction (uses resp.send_key == init.recv_key).
        let (ct_r2i, tag_r2i) = aead_encrypt(&resp.send_key, &nonce, &plaintext, b"");

        // The two ciphertexts MUST differ — if they were equal, that would
        // mean the same (key, nonce, plaintext) was used, i.e. NO directional
        // separation. This assertion is the core of N1.9 Finding 1.
        assert_ne!(
            ct_i2r, ct_r2i,
            "ciphertexts MUST differ — directional separation is broken if they match"
        );
        assert_ne!(tag_i2r, tag_r2i, "tags MUST differ too");

        // Each direction's ciphertext MUST decrypt with the matching recv_key.
        let pt_i2r = aead_decrypt(&resp.recv_key, &nonce, &ct_i2r, &tag_i2r, b"").unwrap();
        let pt_r2i = aead_decrypt(&init.recv_key, &nonce, &ct_r2i, &tag_r2i, b"").unwrap();
        assert_eq!(pt_i2r, plaintext);
        assert_eq!(pt_r2i, plaintext);

        // Cross-direction decryption MUST fail (the recv_key for one
        // direction cannot decrypt the other direction's ciphertext).
        assert!(
            aead_decrypt(&resp.send_key, &nonce, &ct_i2r, &tag_i2r, b"").is_none(),
            "wrong-direction key MUST NOT decrypt"
        );
        assert!(
            aead_decrypt(&init.send_key, &nonce, &ct_r2i, &tag_r2i, b"").is_none(),
            "wrong-direction key MUST NOT decrypt"
        );
    }

    // ─── N1.9 circuit encryption tests ──────────────────────────────────────

    #[test]
    fn circuit_payload_round_trip() {
        let client = derive_circuit_keys(b"circuit-seed-A", true);
        let gateway = derive_circuit_keys(b"circuit-seed-A", false);
        // Sanity: same swap rule as LinkKeys.
        assert_eq!(client.send_key, gateway.recv_key);
        assert_eq!(client.recv_key, gateway.send_key);

        let plaintext = b"{\"hello\":\"circuit\"}".to_vec();
        let sealed = encrypt_circuit_payload(&client.send_key, &plaintext);
        // Output shape: nonce(12) + ciphertext + tag(16)
        assert!(sealed.len() > 12 + 16);
        let recovered = decrypt_circuit_payload(&gateway.recv_key, &sealed).unwrap();
        assert_eq!(recovered, plaintext);

        // Wrong key (the relay's hop key, for example) MUST fail.
        let wrong_key = derive_link_keys(b"hop-seed", true).send_key;
        assert!(decrypt_circuit_payload(&wrong_key, &sealed).is_none());
    }

    #[test]
    fn circuit_payload_tamper_rejected() {
        let client = derive_circuit_keys(b"circuit-seed-B", true);
        let gateway = derive_circuit_keys(b"circuit-seed-B", false);
        let plaintext = b"transit-request-body".to_vec();
        let mut sealed = encrypt_circuit_payload(&client.send_key, &plaintext);
        // Flip one byte of the ciphertext (NOT the nonce — flipping the nonce
        // also breaks decryption, but flipping a ciphertext byte specifically
        // tests the AEAD auth tag).
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(decrypt_circuit_payload(&gateway.recv_key, &sealed).is_none());
    }
}

// ════════════════════════════════════════════════════════════════════════════
// N2.1.2.4 / N2.1.2.5: Test-only VerifiedHandshake factory
// ════════════════════════════════════════════════════════════════════════════

/// **N2.1.2.4 / N2.1.2.5 test-support module.**
///
/// ONLY compiled when the `test-support` Cargo feature is enabled.
/// Provides a test-only factory for creating `VerifiedHandshake` proofs
/// WITHOUT performing an actual SNP-IK handshake over a real transport.
///
/// ## Security
///
/// This module is gated behind `feature = "test-support"` and is NOT
/// compiled in production builds. It allows deterministic testing of
/// `snp-node`'s `AuthenticatedLink` without network I/O.
///
/// The factory creates a genuine `VerifiedHandshake` (using the private
/// constructor) — the proof is real, it just bypasses the transport layer.
/// The caller must supply the `transport_binding` that the proof should
/// be bound to (N2.1.2.5).
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    /// **TEST-ONLY.** Create a `VerifiedHandshake` from explicit fields,
    /// including the transport binding.
    ///
    /// This bypasses the actual SNP-IK handshake but produces a genuine
    /// `VerifiedHandshake` using the private constructor. The proof is
    /// real — it just doesn't come from a real transport handshake.
    ///
    /// # Parameters
    /// - `peer_node_id`: The authenticated peer NodeId.
    /// - `peer_public_key`: The authenticated peer Ed25519 public key.
    /// - `peer_x25519_public`: The authenticated peer static X25519 public key.
    /// - `session_id`: The session ID (must be non-zero).
    /// - `transport_binding`: The transport endpoint the proof is bound to
    ///   (N2.1.2.5). Use `transport_binding_tcp(addr)` to create one.
    ///
    /// **Production code MUST NOT use this.**
    #[must_use]
    pub fn verified_handshake_from_fields(
        peer_node_id: [u8; 32],
        peer_public_key: [u8; 32],
        peer_x25519_public: [u8; 32],
        session_id: [u8; 32],
        transport_binding: TransportBinding,
    ) -> VerifiedHandshake {
        VerifiedHandshake::new(
            session_id,
            peer_node_id,
            peer_public_key,
            peer_x25519_public,
            [0u8; 32], // ephemeral — not used by snp-node link verification
            LinkKeys {
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
            },
            transport_binding,
        )
    }

    /// **TEST-ONLY.** Create a TCP `TransportBinding` from an address string.
    ///
    /// The address should be in canonical `host:port` form (e.g.,
    /// `"127.0.0.1:12345"` or `"[::1]:12345"`).
    ///
    /// **Production code MUST NOT use this.**
    #[must_use]
    pub fn transport_binding_tcp(canonical_addr: &str) -> TransportBinding {
        TransportBinding::new(TransportType::Tcp, canonical_addr.to_string())
    }
}

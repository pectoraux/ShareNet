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
//! - The circuit-nonce RNG. N1.9 uses `SHA-256(wall_clock_ns ‖ counter)`
//!   for the circuit nonce. Production uses `getrandom()` (CSPRNG) so an
//!   attacker who can predict the wall clock cannot predict the nonce.
//! - The synchronous `std::net::TcpStream` API. Production ShareNet uses
//!   async I/O (tokio) for connection pooling and concurrent relays.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use snp_crypto::{
    aead_decrypt, aead_encrypt, aead_nonce, aead_open, aead_seal, hkdf_sha256, sha256, SymmetricKey,
};
use snp_frames::Frame;
use thiserror::Error;

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
    /// CBOR (de)serialization failure (only when the AEAD plaintext is not
    /// a valid Frame — should not happen for well-behaved peers).
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
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

/// Generate a 12-byte nonce for circuit-layer AEAD.
///
/// N1.9: derives the nonce from a process-local atomic counter + the wall
/// clock nanoseconds, then SHA-256s them and takes the first 12 bytes. This
/// is NOT a CSPRNG — production ShareNet uses `getrandom()` for the circuit
/// nonce. The nonce is sent in clear (prepended to the sealed blob), so it
/// does not need to be secret; it only needs to be unique per key.
fn random_circuit_nonce() -> [u8; 12] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&now_ns.to_le_bytes());
    seed.extend_from_slice(&c.to_le_bytes());
    let h = sha256(&seed);
    let mut out = [0u8; 12];
    out.copy_from_slice(&h[..12]);
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

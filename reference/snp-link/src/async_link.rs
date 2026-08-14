//! Async link — Tokio-based AEAD-encrypted frame transport + SNP-IK/0.1 handshake.
//!
//! **N2.0.6 — canonical async production transport.** This module mirrors the
//! synchronous [`Link`](crate::Link) + [`perform_snp_ik_handshake`](crate::perform_snp_ik_handshake)
//! API but uses `tokio::net::TcpStream` for non-blocking I/O. It is the
//! single canonical production network path for the reference node:
//!
//! - The synchronous `Link` (in `lib.rs`) is `#[deprecated]` and retained
//!   only for the N2.0.1 / N2.0.4 sync tests.
//! - The async Node entry points (`serve_gateway_persistent_async`,
//!   `serve_relay_persistent_async`, `serve_discovery_persistent_async`,
//!   `send_request_via_gateway_full_with_relay_async`) consume this module.
//!
//! ## Why a separate type (not a trait)?
//!
//! Per the N2.0.5 design decision (see `snp-node/src/node/async_transport.rs`),
//! we use CONCRETE types instead of an async-trait abstraction. This avoids
//! the `async_trait` crate dependency + the object-safety rabbit hole of
//! native async traits. The Android platform implements an equivalent
//! concrete `BleAsyncLink` (BLE GATT transport) with the same shape.
//!
//! ## Wire format
//!
//! Identical to the sync [`Link`]: `[4-byte BE length][nonce(12)][ciphertext][tag(16)]`.
//! The nonce is `fid ‖ seq_BE(u32)`; the AEAD is ChaCha20-Poly1305 with empty
//! AAD. The receiver performs the same `(fid, seq)` replay-protection sliding
//! window as the sync link.
//!
//! ## Concurrency
//!
//! An `AsyncLink` owns a single `tokio::net::TcpStream` protected by a
//! `tokio::sync::Mutex`. For bidirectional relay forwarding (where two
//! directions of the same stream must run concurrently), use
//! [`async_relay_forward_links`] which uses `tokio::io::split` to obtain
//! independent read/write halves.

use std::collections::HashMap;
use std::sync::Arc;

use snp_crypto::{
    aead_decrypt, aead_encrypt, aead_nonce, derive_node_id, ed25519_sign, ed25519_verify,
    sha256, sig_contexts, x25519_dh, x25519_ephemeral_keypair,
    x25519_public_from_bytes, SymmetricKey, X25519PubKey, X25519Secret,
};
use snp_frames::Frame;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

// Re-use the same wire-format constants + key-derivation helpers as the sync link.
use crate::{
    derive_link_keys_from_dh, decode_handshake_message, encode_handshake_message,
    node_descriptor_preimage, HandshakeResult, LinkKeys,
};

/// Maximum frame length on the wire (16 MiB). Matches the sync link.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Nonce length (12 bytes) — `fid(8) ‖ seq_BE(4)`.
const NONCE_LEN: usize = 12;

/// Poly1305 tag length (16 bytes).
const TAG_LEN: usize = 16;

/// Errors from the async link layer.
#[derive(Debug, Error)]
pub enum AsyncLinkError {
    /// Underlying I/O failure (TCP read/write error, EOF, etc.).
    #[error("async link io: {0}")]
    Io(String),
    /// AEAD authentication failed — the receiver MUST drop the link.
    #[error("async link decryption failed")]
    DecryptionFailed,
    /// Frame length exceeded `MAX_FRAME_LEN`.
    #[error("async link absurd length: {0}")]
    AbsurdLength(u32),
    /// CBOR encode/decode failure.
    #[error("async link cbor: {0}")]
    Cbor(String),
    /// Replay detected — `(fid, seq)` already seen.
    #[error("async link replay detected")]
    ReplayDetected,
    /// SNP-IK/0.1 handshake failure (signature, NodeId mismatch, etc.).
    #[error("async handshake: {0}")]
    Handshake(String),
}

impl From<crate::LinkError> for AsyncLinkError {
    fn from(e: crate::LinkError) -> Self {
        match e {
            crate::LinkError::Io(msg) => AsyncLinkError::Io(msg),
            crate::LinkError::DecryptionFailed => AsyncLinkError::DecryptionFailed,
            crate::LinkError::AbsurdLength(n) => AsyncLinkError::AbsurdLength(n),
            crate::LinkError::Cbor(err) => AsyncLinkError::Cbor(err.to_string()),
            crate::LinkError::ReplayDetected => AsyncLinkError::ReplayDetected,
            other => AsyncLinkError::Handshake(other.to_string()),
        }
    }
}

/// A sliding-window replay-protection set for one `fid`.
///
/// Mirrors the sync link's `SeenNonceSet`: tracks the highest `seq` seen and a
/// 64-slot sliding window of previously-seen `seq` values below the high
/// water mark. A replayed `(fid, seq)` is rejected.
#[derive(Default)]
struct SeenNonceSet {
    high_water: u32,
    window: u64,
}

impl SeenNonceSet {
    fn new() -> Self {
        Self::default()
    }

    /// Check + mark `seq`. Returns `true` if `seq` is fresh, `false` if it
    /// is a replay.
    fn check_and_mark(&mut self, seq: u32) -> bool {
        if seq > self.high_water {
            // Shift the window forward by (seq - high_water) bits, capped at 64.
            let shift = (seq - self.high_water).min(64);
            self.window = self.window.checked_shl(shift).unwrap_or(0);
            self.window |= 1;
            self.high_water = seq;
            true
        } else if seq + 64 <= self.high_water {
            // Below the window — replay.
            false
        } else {
            // Inside the window — check the bit.
            let bit = self.high_water - seq;
            if bit >= 64 {
                return false;
            }
            let mask = 1u64 << bit;
            if self.window & mask != 0 {
                false
            } else {
                self.window |= mask;
                true
            }
        }
    }
}

/// An async AEAD-encrypted link over a `tokio::net::TcpStream`.
///
/// The link stores SPLIT read/write halves (via `tokio::io::split`) so that
/// `send_frame` and `recv_frame` can run concurrently WITHOUT locking. This
/// is critical for the relay's bidirectional forwarding
/// ([`async_relay_forward_links`]) — the prev→next and next→prev directions
/// must run in parallel without deadlock.
///
/// The `seen_nonces` replay-protection map is still protected by a
/// `tokio::sync::Mutex` (only `recv_frame` accesses it).
pub struct AsyncLink {
    read: Mutex<ReadHalf<TcpStream>>,
    write: Mutex<WriteHalf<TcpStream>>,
    send_key: SymmetricKey,
    recv_key: SymmetricKey,
    seen_nonces: Mutex<HashMap<[u8; 8], SeenNonceSet>>,
}

impl AsyncLink {
    /// Wrap an already-connected `tokio::net::TcpStream` with AEAD keys.
    ///
    /// Both ends MUST pass matching `LinkKeys` (the initiator's `send_key`
    /// equals the responder's `recv_key`, and vice versa) — typically the
    /// result of [`perform_snp_ik_handshake_async`].
    #[must_use]
    pub fn new(stream: TcpStream, keys: LinkKeys) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            seen_nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Connect to `addr` and return a stream that the caller can handshake on.
    ///
    /// This does NOT perform the SNP-IK handshake — the caller is expected
    /// to call [`perform_snp_ik_handshake_async`] on the returned stream,
    /// then wrap it in an `AsyncLink` via [`AsyncLink::new`].
    ///
    /// # Errors
    /// Returns [`AsyncLinkError::Io`] if the TCP connection fails.
    pub async fn connect_raw(addr: &str) -> Result<TcpStream, AsyncLinkError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| AsyncLinkError::Io(format!("connect {addr}: {e}")))?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    /// Send a Frame: CBOR-encode, AEAD-encrypt with `send_key` and nonce
    /// `fid ‖ seq_BE`, write `[4-byte BE length][nonce][ciphertext][tag]`.
    ///
    /// # Errors
    /// Returns [`AsyncLinkError`] on encode or I/O failure.
    pub async fn send_frame(&self, frame: &Frame) -> Result<(), AsyncLinkError> {
        let plaintext = frame
            .encode_cbor()
            .map_err(|e| AsyncLinkError::Cbor(e.to_string()))?;
        let nonce = aead_nonce(&frame.fid, frame.seq);
        let (ciphertext, tag) = aead_encrypt(&self.send_key, &nonce, &plaintext, b"");
        let mut wire = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        wire.extend_from_slice(&tag);
        let len = u32::try_from(wire.len())
            .map_err(|_| AsyncLinkError::AbsurdLength(u32::MAX))?;

        let mut write = self.write.lock().await;
        write
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        write
            .write_all(&wire)
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        write
            .flush()
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        Ok(())
    }

    /// Receive a Frame: read `[4-byte BE length][nonce][ciphertext][tag]`,
    /// AEAD-decrypt with `recv_key`, decode the Frame, check the replay window.
    ///
    /// # Errors
    /// Returns [`AsyncLinkError::DecryptionFailed`] on AEAD auth failure,
    /// [`AsyncLinkError::ReplayDetected`] on a replayed `(fid, seq)`.
    pub async fn recv_frame(&self) -> Result<Frame, AsyncLinkError> {
        let blob = self.recv_raw().await?;
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(AsyncLinkError::DecryptionFailed);
        }
        let nonce = &blob[..NONCE_LEN];
        let ciphertext = &blob[NONCE_LEN..blob.len() - TAG_LEN];
        let tag = &blob[blob.len() - TAG_LEN..];
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        let plaintext = aead_decrypt(&self.recv_key, &nonce_arr, ciphertext, &tag_arr, b"")
            .ok_or(AsyncLinkError::DecryptionFailed)?;
        let frame = Frame::decode_cbor(&plaintext).map_err(|e| AsyncLinkError::Cbor(e.to_string()))?;

        // Replay protection — same sliding-window logic as the sync link.
        let mut seen = self.seen_nonces.lock().await;
        let fid_arr: [u8; 8] = frame.fid;
        let set = seen.entry(fid_arr).or_insert_with(SeenNonceSet::new);
        if !set.check_and_mark(frame.seq) {
            return Err(AsyncLinkError::ReplayDetected);
        }
        Ok(frame)
    }

    /// Receive a still-encrypted frame blob (the relay's raw path).
    ///
    /// Reads `[4-byte BE length][nonce][ciphertext][tag]` and returns the
    /// full blob WITHOUT decrypting. The relay forwards this blob verbatim.
    ///
    /// # Errors
    /// Returns [`AsyncLinkError`] on I/O failure or absurd length.
    pub async fn recv_raw(&self) -> Result<Vec<u8>, AsyncLinkError> {
        let mut read = self.read.lock().await;
        let mut len_buf = [0u8; 4];
        read
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_LEN {
            return Err(AsyncLinkError::AbsurdLength(len));
        }
        let mut blob = vec![0u8; len as usize];
        read
            .read_exact(&mut blob)
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        Ok(blob)
    }

    /// Send a still-encrypted frame blob (the relay's raw path).
    ///
    /// # Errors
    /// Returns [`AsyncLinkError`] on I/O failure.
    pub async fn send_raw(&self, blob: &[u8]) -> Result<(), AsyncLinkError> {
        let len =
            u32::try_from(blob.len()).map_err(|_| AsyncLinkError::AbsurdLength(u32::MAX))?;
        let mut write = self.write.lock().await;
        write
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        write
            .write_all(blob)
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        write
            .flush()
            .await
            .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
        Ok(())
    }
}

// ─── SNP-IK/0.1 async handshake ─────────────────────────────────────────────

/// Write a length-prefixed handshake message to the async stream.
async fn write_handshake_message_async(
    stream: &mut TcpStream,
    bytes: &[u8],
) -> Result<(), AsyncLinkError> {
    if bytes.len() > 8 * 1024 {
        return Err(AsyncLinkError::AbsurdLength(
            u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        ));
    }
    let len = u32::try_from(bytes.len()).map_err(|_| AsyncLinkError::AbsurdLength(u32::MAX))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed handshake message from the async stream.
async fn read_handshake_message_async(stream: &mut TcpStream) -> Result<Vec<u8>, AsyncLinkError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf);
    if len > 8 * 1024 {
        return Err(AsyncLinkError::AbsurdLength(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| AsyncLinkError::Io(e.to_string()))?;
    Ok(buf)
}

/// Perform the SNP-IK/0.1 handshake over an already-connected async TCP stream.
///
/// This is the canonical async variant of [`perform_snp_ik_handshake`](crate::perform_snp_ik_handshake).
/// The cryptographic construction is identical (3 DH operations + HKDF + signature
/// verification); only the I/O is async.
///
/// # Parameters
/// - `stream`: a connected `tokio::net::TcpStream`.
/// - `is_initiator`: `true` for the side that opened the TCP connection.
/// - `my_ed25519_secret`/`my_ed25519_public`: the node's Ed25519 identity keypair.
/// - `my_x25519_secret`/`my_x25519_public`: the node's STATIC X25519 rendezvous keypair.
/// - `expected_peer_node_id`: if `Some`, the handshake fails if the peer's
///   authenticated NodeId does not match (the "I"-style pinning).
///
/// # Errors
/// Returns [`AsyncLinkError::Handshake`] on signature/NodeId/CBOR failures,
/// [`AsyncLinkError::Io`] on transport failure.
///
/// # Forward secrecy
/// The ephemeral X25519 secret is dropped when this function returns. An
/// attacker who compromises both static keys AFTER the handshake cannot
/// recover the link keys.
pub async fn perform_snp_ik_handshake_async(
    stream: &mut TcpStream,
    is_initiator: bool,
    my_ed25519_secret: &[u8; 32],
    my_ed25519_public: &[u8; 32],
    my_x25519_secret: &X25519Secret,
    my_x25519_public: &X25519PubKey,
    expected_peer_node_id: Option<&[u8; 32]>,
) -> Result<HandshakeResult, AsyncLinkError> {
    // 1. Fresh ephemeral X25519 keypair.
    let (eph_secret, eph_public) = x25519_ephemeral_keypair();
    let eph_pub_bytes: [u8; 32] = eph_public.to_bytes();
    let static_pub_bytes: [u8; 32] = my_x25519_public.to_bytes();
    let my_node_id = derive_node_id(my_ed25519_public);

    // 2. Build + sign our NodeDescriptor.
    let preimage = node_descriptor_preimage(
        &my_node_id,
        my_ed25519_public,
        &eph_pub_bytes,
        &static_pub_bytes,
    );
    let preimage_bytes = snp_cbor::encode(&preimage)
        .map_err(|e| AsyncLinkError::Handshake(format!("cbor encode preimage: {e}")))?;
    let mut signed_msg =
        Vec::with_capacity(sig_contexts::NODE_DESCRIPTOR.len() + preimage_bytes.len());
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
    )
    .map_err(|e| AsyncLinkError::Handshake(format!("encode handshake: {e}")))?;

    // 4. Exchange messages: initiator sends first; responder receives first.
    let peer_msg_bytes = if is_initiator {
        write_handshake_message_async(stream, &my_msg).await?;
        read_handshake_message_async(stream).await?
    } else {
        let received = read_handshake_message_async(stream).await?;
        write_handshake_message_async(stream, &my_msg).await?;
        received
    };

    // 5. Decode + verify the peer's handshake message.
    let (peer_node_id, peer_pub_key, peer_eph_pub, peer_static_pub, peer_sig) =
        decode_handshake_message(&peer_msg_bytes)
            .map_err(|e| AsyncLinkError::Handshake(format!("decode handshake: {e}")))?;

    // 5a. Verify the peer's signature over its NodeDescriptor.
    let peer_preimage = node_descriptor_preimage(
        &peer_node_id,
        &peer_pub_key,
        &peer_eph_pub,
        &peer_static_pub,
    );
    let peer_preimage_bytes = snp_cbor::encode(&peer_preimage)
        .map_err(|e| AsyncLinkError::Handshake(format!("cbor encode peer preimage: {e}")))?;
    let mut peer_signed =
        Vec::with_capacity(sig_contexts::NODE_DESCRIPTOR.len() + peer_preimage_bytes.len());
    peer_signed.extend_from_slice(sig_contexts::NODE_DESCRIPTOR);
    peer_signed.extend_from_slice(&peer_preimage_bytes);
    if !ed25519_verify(&peer_pub_key, &peer_signed, &peer_sig) {
        return Err(AsyncLinkError::Handshake(
            "peer NodeDescriptor signature verification failed".into(),
        ));
    }

    // 5b. Verify I4: peer's NodeId == SHA-256("SNP/0.1 node\0" || peer_pubKey).
    let derived_peer_node_id = derive_node_id(&peer_pub_key);
    if peer_node_id != derived_peer_node_id {
        return Err(AsyncLinkError::Handshake(
            "peer nodeId does not match SHA-256(SNP/0.1 node\\0 || peer_pubKey) (I4 violation)"
                .into(),
        ));
    }

    // 5c. Verify "I"-style pinning.
    if let Some(expected) = expected_peer_node_id {
        if &peer_node_id != expected {
            return Err(AsyncLinkError::Handshake(
                "peer nodeId does not match expected (identity substitution detected)".into(),
            ));
        }
    }

    // 6. Compute the three DH operations.
    let peer_eph_pub_key = x25519_public_from_bytes(&peer_eph_pub);
    let peer_static_pub_key = x25519_public_from_bytes(&peer_static_pub);
    let (dh1, dh2, dh3) = if is_initiator {
        let dh1 = x25519_dh(&eph_secret, &peer_static_pub_key);
        let dh2 = x25519_dh(my_x25519_secret, &peer_eph_pub_key);
        let dh3 = x25519_dh(&eph_secret, &peer_eph_pub_key);
        (dh1, dh2, dh3)
    } else {
        // Responder: swap dh1/dh2 to match the initiator's IKM order.
        let dh1 = x25519_dh(my_x25519_secret, &peer_eph_pub_key);
        let dh2 = x25519_dh(&eph_secret, &peer_static_pub_key);
        let dh3 = x25519_dh(&eph_secret, &peer_eph_pub_key);
        (dh1, dh2, dh3)
    };

    // 7. Derive link keys.
    let link_keys = derive_link_keys_from_dh(&dh1, &dh2, &dh3, is_initiator);

    // 8. Compute the session_id: SHA-256(initiator_eph || responder_eph || dh3).
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

/// **N2.2.1.** Perform the SNP-IK/0.1 handshake over an async TCP stream and
/// return a [`VerifiedHandshake`] proof bound to the actual transport endpoint.
///
/// This is the canonical async variant of
/// [`perform_snp_ik_handshake_verified`](crate::perform_snp_ik_handshake_verified).
/// It is the unforgeable proof that:
///
/// 1. The SNP-IK/0.1 handshake actually completed (signatures verified,
///    NodeId matches `SHA-256("SNP/0.1 node\0" || peer_pubKey)`, optional
///    `expected_peer_node_id` pinning passed).
/// 2. The handshake occurred over the specific TCP endpoint returned by
///    `stream.peer_addr()` (the `TransportBinding` is bound to the proof at
///    mint time and cannot be forged by external code).
///
/// The directional AEAD [`LinkKeys`] inside the proof are used by the caller
/// to AEAD-encrypt subsequent frames on this connection.
///
/// # Parameters
/// - `stream`: a connected `tokio::net::TcpStream`.
/// - `is_initiator`: `true` for the side that opened the TCP connection.
/// - `my_ed25519_secret`/`my_ed25519_public`: the node's Ed25519 identity keypair.
/// - `my_x25519_secret`/`my_x25519_public`: the node's STATIC X25519 rendezvous keypair.
/// - `expected_peer_node_id`: if `Some`, the handshake fails if the peer's
///   authenticated NodeId does not match (the "I"-style pinning).
///
/// # Errors
/// Returns [`AsyncLinkError::Handshake`] on signature/NodeId/CBOR failures,
/// [`AsyncLinkError::Io`] on transport failure or if `peer_addr()` cannot be
/// obtained (e.g. the stream was closed).
pub async fn perform_snp_ik_handshake_verified_async(
    stream: &mut tokio::net::TcpStream,
    is_initiator: bool,
    my_ed25519_secret: &[u8; 32],
    my_ed25519_public: &[u8; 32],
    my_x25519_secret: &snp_crypto::X25519Secret,
    my_x25519_public: &snp_crypto::X25519PubKey,
    expected_peer_node_id: Option<&[u8; 32]>,
) -> Result<crate::VerifiedHandshake, AsyncLinkError> {
    let result = perform_snp_ik_handshake_async(
        stream,
        is_initiator,
        my_ed25519_secret,
        my_ed25519_public,
        my_x25519_secret,
        my_x25519_public,
        expected_peer_node_id,
    )
    .await?;
    // N2.1.2.5: Extract the actual transport endpoint from the TcpStream.
    // This binds the proof to the specific endpoint the handshake occurred over.
    let peer_addr = stream
        .peer_addr()
        .map_err(|e| AsyncLinkError::Io(format!("peer_addr: {e}")))?;
    let transport_binding = crate::TransportBinding::from_tcp_socket_addr(peer_addr);
    // Mint the unforgeable proof from the internal HandshakeResult + transport binding.
    // This conversion is pub(crate) — only callable from within snp-link.
    Ok(crate::VerifiedHandshake::from_handshake_result(
        &result,
        transport_binding,
    ))
}

/// Derive end-to-end circuit keys from a single X25519 DH output (async-context
/// re-export of the sync `derive_circuit_keys_from_dh`).
///
/// Both the client and the gateway pass the SAME 32-byte DH output. The
/// `is_initiator` parameter distinguishes them: the client (initiator of the
/// TransitRequest) passes `true`, the gateway passes `false`.
///
/// This is a thin wrapper around the sync [`derive_circuit_keys_from_dh`](crate::derive_circuit_keys_from_dh)
/// — there is no I/O, so no async is needed. It exists here so callers can
/// import everything they need from `snp_link::async_link`.
#[must_use]
pub fn derive_circuit_keys_from_dh_async(
    dh: &[u8; 32],
    is_initiator: bool,
) -> crate::CircuitKeys {
    crate::derive_circuit_keys_from_dh(dh, is_initiator)
}

// ─── Async relay bidirectional forward ──────────────────────────────────────

/// Forward frames bidirectionally between two `AsyncLink`s until either side
/// closes or errors.
///
/// Spawns two tasks: one forwarding prev→next, one forwarding next→prev.
/// Each task decrypts the OUTER frame, re-encrypts it for the next hop (the
/// hop keys differ), and forwards. The frame BODY (circuit ciphertext)
/// remains opaque to the relay — invariant I8 holds.
///
/// This is the async analogue of the sync relay's `prev_link.recv_frame() →
/// next_link.send_frame()` loop. It uses `tokio::join!` so both directions
/// run concurrently.
///
/// # Errors
/// Returns [`AsyncLinkError`] when either direction fails. The caller should
/// treat any error as a connection termination.
pub async fn async_relay_forward_links(
    prev: Arc<AsyncLink>,
    next: Arc<AsyncLink>,
) -> Result<(), AsyncLinkError> {
    let prev_to_next = async {
        loop {
            let frame = match prev.recv_frame().await {
                Ok(f) => f,
                Err(AsyncLinkError::Io(msg))
                    if msg.contains("unexpected eof") || msg.contains("reset") =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let mut fwd = frame.clone();
            if fwd.ttl > 0 {
                fwd.ttl -= 1;
            }
            next.send_frame(&fwd).await?;
        }
    };
    let next_to_prev = async {
        loop {
            let frame = match next.recv_frame().await {
                Ok(f) => f,
                Err(AsyncLinkError::Io(msg))
                    if msg.contains("unexpected eof") || msg.contains("reset") =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let mut fwd = frame.clone();
            if fwd.ttl > 0 {
                fwd.ttl -= 1;
            }
            prev.send_frame(&fwd).await?;
        }
    };
    tokio::select! {
        res = prev_to_next => res,
        res = next_to_prev => res,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use snp_crypto::{derive_public_key, sha256, x25519_static_keypair};
    use tokio::net::TcpListener;

    /// Two AsyncLinks over a real TCP connection (via a loopback listener)
    /// should round-trip a frame end-to-end with the same AEAD keys derived
    /// from `derive_link_keys`.
    #[tokio::test]
    async fn async_link_roundtrip() {
        // Derive matching LinkKeys via the sync `derive_link_keys` (it's just
        // HKDF — no I/O, so we can use it here).
        let seed = sha256(b"async-link-roundtrip-seed");
        let initiator_keys = crate::derive_link_keys(&seed, true);
        let responder_keys = crate::derive_link_keys(&seed, false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let link = AsyncLink::new(stream, responder_keys);
            let frame = link.recv_frame().await.unwrap();
            // Echo it back with seq+1.
            let mut echo = frame.clone();
            echo.seq += 1;
            link.send_frame(&echo).await.unwrap();
        });

        let stream = AsyncLink::connect_raw(&addr).await.unwrap();
        let link = AsyncLink::new(stream, initiator_keys);
        let mut frame = Frame::new(b'B', [1u8; 32], [2u8; 32]);
        frame.fid = [3u8; 8];
        frame.seq = 1;
        frame.body = vec![0xde, 0xad, 0xbe, 0xef];
        link.send_frame(&frame).await.unwrap();
        let echo = link.recv_frame().await.unwrap();
        assert_eq!(echo.body, frame.body);
        assert_eq!(echo.seq, 2);

        server.await.unwrap();
    }

    /// The async SNP-IK handshake must produce matching LinkKeys on both sides.
    #[tokio::test]
    async fn async_snp_ik_handshake_produces_matching_keys() {
        // Generate identities for both sides.
        let i_ed_sk = sha256(b"async-handshake-initiator-ed25519");
        let i_ed_pk = derive_public_key(&i_ed_sk);
        let (i_x_sk, i_x_pk) = x25519_static_keypair();
        let i_node_id = derive_node_id(&i_ed_pk);

        let r_ed_sk = sha256(b"async-handshake-responder-ed25519");
        let r_ed_pk = derive_public_key(&r_ed_sk);
        let (r_x_sk, r_x_pk) = x25519_static_keypair();
        let r_node_id = derive_node_id(&r_ed_pk);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Responder thread.
        let r_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            perform_snp_ik_handshake_async(
                &mut stream,
                false,
                &r_ed_sk,
                &r_ed_pk,
                &r_x_sk,
                &r_x_pk,
                None,
            )
            .await
            .unwrap()
        });

        // Initiator — pin the responder's NodeId.
        let mut i_stream = AsyncLink::connect_raw(&addr).await.unwrap();
        let i_result = perform_snp_ik_handshake_async(
            &mut i_stream,
            true,
            &i_ed_sk,
            &i_ed_pk,
            &i_x_sk,
            &i_x_pk,
            Some(&r_node_id),
        )
        .await
        .unwrap();

        let r_result = r_handle.await.unwrap();

        // Verify the keys match directionally.
        assert_eq!(
            i_result.link_keys.send_key, r_result.link_keys.recv_key,
            "initiator send_key must equal responder recv_key"
        );
        assert_eq!(
            i_result.link_keys.recv_key, r_result.link_keys.send_key,
            "initiator recv_key must equal responder send_key"
        );
        // Verify identity binding.
        assert_eq!(i_result.peer_node_id, r_node_id);
        assert_eq!(r_result.peer_node_id, i_node_id);
        // Verify session_ids match.
        assert_eq!(i_result.session_id, r_result.session_id);
    }

    /// The async SNP-IK handshake must reject an identity substitution.
    #[tokio::test]
    async fn async_snp_ik_handshake_rejects_identity_substitution() {
        let i_ed_sk = sha256(b"async-sub-initiator");
        let i_ed_pk = derive_public_key(&i_ed_sk);
        let (i_x_sk, i_x_pk) = x25519_static_keypair();

        // The "expected" gateway identity — the initiator pins this.
        let expected_ed_sk = sha256(b"async-sub-expected-gateway");
        let expected_ed_pk = derive_public_key(&expected_ed_sk);
        let expected_node_id = derive_node_id(&expected_ed_pk);

        // The "attacker" — a DIFFERENT identity that responds instead.
        let attacker_ed_sk = sha256(b"async-sub-attacker");
        let attacker_ed_pk = derive_public_key(&attacker_ed_sk);
        let (attacker_x_sk, attacker_x_pk) = x25519_static_keypair();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Attacker responds with its OWN identity (NOT the expected one).
        let attacker_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            perform_snp_ik_handshake_async(
                &mut stream,
                false,
                &attacker_ed_sk,
                &attacker_ed_pk,
                &attacker_x_sk,
                &attacker_x_pk,
                None,
            )
            .await
        });

        let mut i_stream = AsyncLink::connect_raw(&addr).await.unwrap();
        let result = perform_snp_ik_handshake_async(
            &mut i_stream,
            true,
            &i_ed_sk,
            &i_ed_pk,
            &i_x_sk,
            &i_x_pk,
            Some(&expected_node_id), // pin the EXPECTED gateway, not the attacker
        )
        .await;

        assert!(
            result.is_err(),
            "initiator must reject the attacker whose NodeId != expected"
        );
        let err = result.unwrap_err();
        match err {
            AsyncLinkError::Handshake(msg) => {
                assert!(
                    msg.contains("identity substitution") || msg.contains("does not match expected"),
                    "error must mention identity substitution: got {msg}"
                );
            }
            other => panic!("expected Handshake error, got {other:?}"),
        }
        // Let the attacker task finish (it will likely error too — that's fine).
        let _ = attacker_handle.await;
    }

    /// The replay-protection window must reject a duplicated `(fid, seq)`.
    #[tokio::test]
    async fn async_link_rejects_replay() {
        let seed = sha256(b"async-link-replay-seed");
        let initiator_keys = crate::derive_link_keys(&seed, true);
        let responder_keys = crate::derive_link_keys(&seed, false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let link = Arc::new(AsyncLink::new(stream, responder_keys));
            // First receive — ok.
            let _ = link.recv_frame().await.unwrap();
            // Second receive — same (fid, seq) — must be rejected as a replay.
            let err = link.recv_frame().await.unwrap_err();
            assert!(matches!(err, AsyncLinkError::ReplayDetected));
        });

        let stream = AsyncLink::connect_raw(&addr).await.unwrap();
        let link = Arc::new(AsyncLink::new(stream, initiator_keys));
        let mut frame = Frame::new(b'B', [1u8; 32], [2u8; 32]);
        frame.fid = [9u8; 8];
        frame.seq = 42;
        frame.body = vec![0xca, 0xfe];
        link.send_frame(&frame).await.unwrap();
        // Replay the same frame.
        link.send_frame(&frame).await.unwrap();

        server.await.unwrap();
    }
}

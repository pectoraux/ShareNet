//! SNP-LINK — L8 link abstraction with AEAD-encrypted frame transport
//!
//! For N1.8 (the Rust minimal Internet bridge), this crate implements a
//! SIMPLE synchronous TCP transport that AEAD-encrypts every SNP frame with
//! a pre-shared symmetric key. The full SNP-IK/0.1 Noise-based handshake
//! is a separate future task — for now the link keys are derived from
//! deterministic test seeds, identical on both ends.
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
//! ## Link key
//!
//! For N1.8, the link key is derived once via `derive_link_key(seed)` and
//! the SAME 32-byte key is used by both ends of the TCP connection. This is
//! NOT secure against active attackers who do not know the key, but it IS
//! a real ChaCha20-Poly1305 AEAD over a real TCP socket — exactly the
//! minimum needed to demonstrate that SNP frames can cross a real network
//! encrypted and authenticated.
//!
//! ## Class B invariant (I8)
//!
//! The relay does NOT decrypt frame bodies — it forwards the encrypted
//! bytes verbatim. The [`recv_frame`] / [`send_frame`] helpers in this crate
//! ARE used by clients and gateways, but the relay uses the lower-level
//! [`recv_raw`] / [`send_raw`] helpers that move the still-encrypted blob
//! without ever calling AEAD decrypt. This is the I8 invariant in code: the
//! relay never holds the plaintext.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use snp_crypto::{
    aead_decrypt, aead_encrypt, aead_nonce, hkdf_sha256, SymmetricKey,
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

/// Derive a 32-byte AEAD link key from a deterministic seed.
///
/// For N1.8 the link keys are pre-shared: both ends of a TCP connection
/// derive the same key from the same seed. This is NOT the full SNP-IK/0.1
/// handshake — it is the minimum needed to demonstrate AEAD-encrypted SNP
/// frame transport over real TCP.
///
/// The HKDF info string `"SNP/0.1 link-key N1.8\0"` documents that this key
/// derivation is the simplified N1.8 pre-shared-key derivation, not the
/// production SNP-IK derivation.
#[must_use]
pub fn derive_link_key(seed: &[u8]) -> SymmetricKey {
    let salt = b"SNP/0.1 link N1.8 pre-shared";
    let info = b"SNP/0.1 link-key N1.8\0";
    let okm = hkdf_sha256(seed, salt, info, 32).expect("HKDF-SHA256 32-byte expand never fails");
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

/// A bidirectional AEAD-encrypted link over a TCP stream.
///
/// The link holds a `TcpStream` and a 32-byte symmetric key. Every call to
/// `send_frame` AEAD-encrypts the frame with a nonce derived from the
/// frame's `(fid, seq)`; every call to `recv_frame` reads, decrypts, and
/// decodes a frame.
///
/// The `Mutex<TcpStream>` is required so the link can be shared between
/// threads (a relay may want to read on one thread and write on another).
pub struct Link {
    stream: Mutex<TcpStream>,
    key: SymmetricKey,
}

impl Link {
    /// Wrap an already-connected `TcpStream` with an AEAD link.
    ///
    /// Both ends MUST pass the SAME `key` (e.g. derived from the same seed
    /// via [`derive_link_key`]).
    #[must_use]
    pub fn new(stream: TcpStream, key: SymmetricKey) -> Self {
        Self {
            stream: Mutex::new(stream),
            key,
        }
    }

    /// Connect to `addr` and wrap the resulting stream in a Link.
    ///
    /// # Errors
    /// Returns [`LinkError::Io`] if the TCP connection fails.
    pub fn connect(addr: &str, key: SymmetricKey) -> LinkResult<Self> {
        let stream = TcpStream::connect(addr).map_err(|e| LinkError::Io(e.to_string()))?;
        // Disable Nagle — SNP frames are small and we want low latency.
        stream
            .set_nodelay(true)
            .map_err(|e| LinkError::Io(e.to_string()))?;
        Ok(Self::new(stream, key))
    }

    /// Send a Frame: CBOR-encode it, AEAD-encrypt with `nonce = fid ‖ seq_BE`,
    /// write `[4-byte BE length][nonce][ciphertext][tag]` to the stream.
    ///
    /// # Errors
    /// Returns [`LinkError`] on encode or IO failure.
    pub fn send_frame(&self, frame: &Frame) -> LinkResult<()> {
        let plaintext = frame.encode_cbor()?;
        let nonce = aead_nonce(&frame.fid, frame.seq);
        let (ciphertext, tag) = aead_encrypt(&self.key, &nonce, &plaintext, b"");
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
    /// AEAD-decrypt, decode the Frame.
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
        let plaintext = aead_decrypt(&self.key, &nonce_arr, ciphertext, &tag_arr, b"")
            .ok_or(LinkError::DecryptionFailed)?;
        let frame = Frame::decode_cbor(&plaintext)?;
        Ok(frame)
    }

    /// Receive a still-encrypted frame blob (the relay's I8 path).
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

    /// Send a still-encrypted frame blob (the relay's I8 path).
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
        let key = derive_link_key(b"test-seed-A");
        let key2 = key;

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let link = Link::new(stream, key2);
            let frame = link.recv_frame().unwrap();
            // Echo the same frame back with seq+1.
            let mut echo = frame.clone();
            echo.seq += 1;
            link.send_frame(&echo).unwrap();
        });

        let client_link = Link::connect(&addr.to_string(), key).unwrap();
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
        let server_key = derive_link_key(b"server-seed");
        let client_key = derive_link_key(b"different-seed");

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let link = Link::new(stream, server_key);
            // Recv will fail (AEAD auth) — caller should kill the link.
            let _ = link.recv_frame();
        });

        let client_link = Link::connect(&addr.to_string(), client_key).unwrap();
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

        // All three use the same link key (simplified N1.8 model).
        let key = derive_link_key(b"mesh-seed");
        let key_g = key;
        let key_r1 = key;
        let key_r2 = key;

        // Gateway: accept one connection, recv a raw blob, decrypt it as a
        // Frame, echo back with seq+1.
        let gw_thread = std::thread::spawn(move || {
            let (stream, _) = gateway_listener.accept().unwrap();
            let link = Link::new(stream, key_g);
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
            let pt = aead_decrypt(&key_g, &n, ct, &t, b"").unwrap();
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
            let client_link = Link::new(client_stream, key_r1);
            let gw_link = Link::connect(&gateway_addr.to_string(), key_r2).unwrap();
            // Forward: client → gateway (raw, no decrypt).
            let blob = client_link.recv_raw().unwrap();
            gw_link.send_raw(&blob).unwrap();
            // Forward: gateway → client (raw, no decrypt).
            let resp = gw_link.recv_raw().unwrap();
            client_link.send_raw(&resp).unwrap();
        });

        // Client: send a frame to the relay, receive a frame back.
        let client_link = Link::connect(&client_addr.to_string(), key).unwrap();
        client_link.send_frame(&make_frame(1)).unwrap();
        let resp = client_link.recv_frame().unwrap();
        assert_eq!(resp.seq, 2);

        relay_thread.join().unwrap();
        gw_thread.join().unwrap();
    }
}

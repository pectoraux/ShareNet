//! SNP-LINK — L8 Link abstraction and Noise_IK handshake structure
//!
//! Implements the SNP/0.1 L8 link layer (per `01-ARCHITECTURE.md` §2.4 and
//! `02-PROTOCOL-SPEC.md` §5):
//!
//! - A `Link` trait that abstracts any transport (TCP, BLE, Wi-Fi Direct,
//!   loopback). Each transport lives in `platform/` — NEVER here.
//! - The Noise_IK handshake structure (per ADR-0003, which uses a simplified
//!   Noise_IK with the static key authenticated by the responder's NodeId).
//! - L8 frame encoding (length-prefixed, AEAD-protected) — the Rust
//!   equivalent of `/src/lib/snp/frames.ts`.
//!
//! This crate is transport-agnostic. It accepts bytes from a `Link` and
//! produces bytes back; it does not know what a socket is.
//!
//! This is the Rust equivalent of `/src/lib/snp/link.ts` + `/src/lib/snp/frames.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors in
//! `/public/conformance/vectors/08-frames.json`.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the L8 link layer.
#[derive(Debug, Error)]
pub enum LinkError {
    /// The Noise_IK handshake failed (bad MAC, wrong static, …).
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame failed AEAD decryption.
    #[error("frame decryption failed")]
    DecryptionFailed,
    /// The underlying transport returned an IO error.
    #[error("transport IO error: {0}")]
    Io(String),
    /// The peer presented a NodeId that does not match its static key.
    #[error("peer NodeId mismatch")]
    PeerIdMismatch,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
}

/// Convenience `Result` alias.
pub type LinkResult<T> = Result<T, LinkError>;

/// A bidirectional byte stream with a peer. Implementations live in
/// `platform/linux`, `platform/android`, etc. — NEVER in this crate.
///
/// `Link` is async because every real transport is async. Native `async fn`
/// in traits is stable since Rust 1.75 (the workspace MSRV), so no
/// `#[async_trait]` is required. Object-safety is intentionally forfeited;
/// runtime polymorphism over transports is achieved via an enum in `snp-node`,
/// not via `dyn Link`.
pub trait Link: Send + Sync {
    /// Send `frame` to the peer. The implementation is responsible for any
    /// transport-level framing (length prefixes, MTU splitting, …).
    fn send(&self, frame: &[u8]) -> impl std::future::Future<Output = LinkResult<()>> + Send;

    /// Receive the next complete frame from the peer.
    fn recv(&self) -> impl std::future::Future<Output = LinkResult<Vec<u8>>> + Send;

    /// Close the link cleanly.
    fn close(&self) -> impl std::future::Future<Output = LinkResult<()>> + Send;
}

/// A Noise_IK session key pair derived after a successful handshake.
///
/// A real implementation will derive `zeroize::ZeroizeOnDrop` once the
/// `zeroize` crate is added as a dependency.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Key for encrypting frames we send.
    pub send_key: snp_crypto::SymmetricKey,
    /// Key for decrypting frames we receive.
    pub recv_key: snp_crypto::SymmetricKey,
    /// Next send nonce (incremented per frame).
    pub send_nonce: u64,
    /// Next recv nonce (incremented per frame).
    pub recv_nonce: u64,
    /// The peer's authenticated NodeId.
    pub peer_node_id: snp_identity::NodeId,
}

/// Initiator state for a Noise_IK handshake (per ADR-0003).
pub struct Initiator;

impl Initiator {
    /// Begin a Noise_IK handshake as the initiator. Returns the first
    /// handshake message to send to the responder.
    pub fn start(
        _our_identity: &snp_identity::NodeDescriptor,
        _our_ephemeral: &snp_crypto::Keypair,
        _peer_node_id: &snp_identity::NodeId,
        _peer_static: &snp_crypto::PublicKey,
    ) -> LinkResult<Vec<u8>> {
        todo!("Build Noise_IK message 1 per ADR-0003")
    }

    /// Consume the responder's reply and derive session keys.
    pub fn finish(_reply: &[u8]) -> LinkResult<SessionKeys> {
        todo!("Consume Noise_IK message 2 and derive session keys")
    }
}

/// Responder state for a Noise_IK handshake (per ADR-0003).
pub struct Responder;

impl Responder {
    /// Consume the initiator's first message and produce the reply.
    pub fn handle(
        _message: &[u8],
        _our_identity: &snp_identity::NodeDescriptor,
        _our_ephemeral: &snp_crypto::Keypair,
    ) -> LinkResult<(Vec<u8>, SessionKeys)> {
        todo!("Consume Noise_IK message 1, emit message 2, derive session keys")
    }
}

/// Encode an L8 frame: 4-byte big-endian length ‖ AEAD(plaintext).
pub fn encode_frame(_keys: &SessionKeys, _plaintext: &[u8]) -> LinkResult<Vec<u8>> {
    todo!("Encode an L8 frame per /src/lib/snp/frames.ts")
}

/// Decode an L8 frame and return its plaintext.
pub fn decode_frame(_keys: &SessionKeys, _frame: &[u8]) -> LinkResult<Vec<u8>> {
    todo!("Decode an L8 frame, rejecting replays and bad tags")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/08-frames.json (frame encoding,
        // replay rejection, AEAD failure modes).
        let _ = LinkError::DecryptionFailed;
    }
}

//! SNP-CIRCUIT — L6/L7 circuit abstraction for ShareNet 2.0
//!
//! Implements the SNP/0.1 circuit layer (per `01-ARCHITECTURE.md` §2.4 and
//! `02-PROTOCOL-SPEC.md` §9). A **circuit** is a bidirectional,
//! end-to-end-encrypted channel between two nodes (source ↔ gateway, or
//! source ↔ destination) that is carried hop-by-hop over routed L6 links.
//!
//! Key properties:
//! - **E2E AEAD** — each circuit has its own ChaCha20-Poly1305 keys derived
//!   via X25519 + HKDF between the two endpoints. Intermediate relays see
//!   only the next-hop circuit-id and the L8 frame; they never see the
//!   plaintext.
//! - **Replay windows** — each direction maintains a sliding 64-packet
//!   replay window keyed on the AEAD nonce. Out-of-window or duplicate
//!   nonces are dropped.
//! - **Circuit IDs are per-hop** — at each relay, the incoming circuit-id is
//!   swapped for an outgoing one. This means a circuit has N+1 distinct
//!   circuit-ids for N hops; only the endpoints know the full mapping.
//! - **Migration** — when a route migrates (per `snp-routing`), the circuit
//!   is rekeyed across the new path without dropping in-flight traffic.
//!
//! This is the Rust equivalent of (future) `src/lib/snp/circuit.ts`. The
//! TypeScript sandbox reference does not yet implement circuits; this crate
//! is the design surface.
//!
//! SKELETON — not yet implemented. A future `16-circuits.json` conformance
//! suite will cover circuit setup, rekeying, and replay-window behavior.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from the circuit layer.
#[derive(Debug, Error)]
pub enum CircuitError {
    /// A circuit cell failed AEAD decryption.
    #[error("circuit cell decryption failed")]
    DecryptionFailed,
    /// A cell was a replay (nonce inside the replay window's already-seen set).
    #[error("replay detected: nonce {0}")]
    Replay(u64),
    /// A cell's nonce was below the replay window floor.
    #[error("nonce {0} below replay window floor")]
    StaleNonce(u64),
    /// No circuit exists with the requested id.
    #[error("unknown circuit id: {0}")]
    UnknownCircuit(u64),
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] snp_crypto::CryptoError),
}

/// Convenience `Result` alias.
pub type CircuitResult<T> = Result<T, CircuitError>;

/// A per-hop circuit identifier. Each relay swaps incoming → outgoing.
pub type CircuitId = u64;

/// An established circuit between two endpoints.
#[derive(Debug)]
pub struct Circuit {
    /// Our endpoint's NodeId.
    pub local: snp_identity::NodeId,
    /// The remote endpoint's NodeId.
    pub remote: snp_identity::NodeId,
    /// Directional session keys.
    pub keys: CircuitKeys,
    /// Per-direction replay windows.
    pub replay: ReplayWindow,
}

/// Directional circuit keys: one for each direction of travel.
#[derive(Debug, Clone)]
pub struct CircuitKeys {
    /// Key for cells we send.
    pub send: snp_crypto::SymmetricKey,
    /// Key for cells we receive.
    pub recv: snp_crypto::SymmetricKey,
    /// Next outgoing nonce.
    pub send_nonce: u64,
}

/// A 64-packet sliding replay window.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest nonce seen so far.
    pub floor: u64,
    /// Bitmap of nonces in `[floor-63, floor]`. Bit 0 = floor, bit 63 = floor-63.
    pub seen: u64,
}

impl ReplayWindow {
    /// Construct a fresh window starting at nonce 0.
    pub fn new() -> Self {
        Self { floor: 0, seen: 0 }
    }

    /// Record `nonce` as seen. Returns `Err(Replay)` if it was already seen
    /// or `Err(StaleNonce)` if it was below the window floor.
    pub fn observe(&mut self, _nonce: u64) -> CircuitResult<()> {
        todo!("Sliding-window replay check and bit-set")
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl Circuit {
    /// Open a new circuit to `remote`. Performs an X25519+HKDF key exchange
    /// over the routed path; not a Noise handshake — the path itself is
    /// already authenticated by `snp-link`.
    pub fn open(
        _local: snp_identity::NodeId,
        _remote: snp_identity::NodeId,
        _local_ephemeral: &snp_crypto::Keypair,
        _remote_static: &snp_crypto::PublicKey,
    ) -> CircuitResult<Self> {
        todo!("Derive circuit keys via X25519 + HKDF")
    }

    /// Encrypt `plaintext` as a circuit cell. Returns the next nonce used
    /// plus the ciphertext (for the relay to forward).
    pub fn seal(&mut self, _plaintext: &[u8]) -> CircuitResult<(u64, Vec<u8>)> {
        todo!("AEAD-encrypt a circuit cell under send key + send_nonce++")
    }

    /// Decrypt a circuit cell, rejecting replays.
    pub fn open_cell(&mut self, _nonce: u64, _ciphertext: &[u8]) -> CircuitResult<Vec<u8>> {
        todo!("AEAD-decrypt a circuit cell, then replay-window check")
    }

    /// Rekey the circuit after a route migration. Both endpoints must call
    /// this with the same `migration_secret` (derived from the new path).
    pub fn rekey(&mut self, _migration_secret: &[u8; 32]) -> CircuitResult<()> {
        todo!("Rotate send/recv keys via HKDF(migration_secret, old_keys)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will cover:
        //   - Replay window observe/duplicate/stale
        //   - Circuit seal/open round-trip
        //   - Rekey after migration preserves in-flight cells
        let _ = ReplayWindow::new();
    }
}

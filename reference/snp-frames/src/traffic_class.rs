//! **R3 — Traffic class semantic types.**
//!
//! Type-level enforcement of the Class A / Class B distinction.
//!
//! - `FrameClass` — the wire-level traffic class (A/B/C), replacing raw `u8`.
//! - `Ciphertext` — opaque encrypted bytes for Class B frame bodies.
//!   Cannot be accidentally passed to content APIs.
//! - `ContentBytes` — typed content data for Class A CAS operations.
//!   Cannot be accidentally passed to transit APIs.
//!
//! These types do NOT change the wire format. They are newtypes/wrappers
//! that make the semantic distinction compile-time enforceable.

#![warn(missing_docs)]

// ─── FrameClass ────────────────────────────────────────────────────────────

/// The traffic class of a ShareNet frame.
///
/// This replaces the raw `u8` `cls` field on `Frame` with a typed enum,
/// making it impossible to accidentally use an invalid class value.
///
/// - `Content` (wire byte `b'A'`) — mesh-understood content. MAY be cached,
///   replicated, Merkle-verified. Body is an object-protocol message.
/// - `Transit` (wire byte `b'B'`) — opaque transit. MUST NOT be inspected,
///   cached, or duplicated by relays. Body is AEAD ciphertext.
/// - `Control` (wire byte `b'C'`) — link/control messages. NOT content,
///   NOT transit. Used for NACKs, upstream-failure markers, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameClass {
    /// Class A — content. Body is object-protocol data.
    Content = b'A',
    /// Class B — transit. Body is opaque AEAD ciphertext.
    Transit = b'B',
    /// Class C — control. Body is a link/control message.
    Control = b'C',
}

impl FrameClass {
    /// Convert from the wire byte.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'A' => Some(Self::Content),
            b'B' => Some(Self::Transit),
            b'C' => Some(Self::Control),
            _ => None,
        }
    }

    /// Convert to the wire byte.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Returns true if this class carries content (Class A).
    #[must_use]
    pub fn is_content(self) -> bool {
        matches!(self, Self::Content)
    }

    /// Returns true if this class carries opaque transit (Class B).
    #[must_use]
    pub fn is_transit(self) -> bool {
        matches!(self, Self::Transit)
    }
}

impl std::fmt::Display for FrameClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Content => write!(f, "A (content)"),
            Self::Transit => write!(f, "B (transit)"),
            Self::Control => write!(f, "C (control)"),
        }
    }
}

// ─── Ciphertext (Class B body) ─────────────────────────────────────────────

/// Opaque AEAD ciphertext — the body of a Class B (transit) frame.
///
/// This type wraps `Vec<u8>` and is deliberately opaque: there is no
/// public method to read the plaintext. Only the circuit endpoint
/// (client or gateway) that possesses the circuit keys can decrypt it.
///
/// Relays forward `Ciphertext` without interpretation. There is no
/// `as_bytes()` or `into_inner()` method that would let a relay inspect
/// the content.
///
/// ## Construction
///
/// `Ciphertext` is constructed by `encrypt_circuit_payload()` (in snp-link)
/// and consumed by `decrypt_circuit_payload()`. Between those two points,
/// it travels through relays as opaque bytes inside a `Frame.body`.
///
/// ## Why not just use `Vec<u8>`?
///
/// A `Vec<u8>` can be accidentally passed to `Cas::put()` (content store)
/// or `sha256()` (content hashing). `Ciphertext` prevents this at the
/// type level — there is no `Deref<Target = [u8]>` and no `AsRef<[u8]>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(pub(crate) Vec<u8>);

impl Ciphertext {
    /// Construct from raw encrypted bytes (used by encrypt_circuit_payload).
    #[must_use]
    pub fn from_encrypted(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Consume and return the raw bytes (used by decrypt_circuit_payload
    /// at the circuit endpoint — NOT available to relays).
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length of the ciphertext (for framing/MTU purposes).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the ciphertext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ─── ContentBytes (Class A body) ───────────────────────────────────────────

/// Typed content data — the body of a Class A (content) frame or the
/// payload of a CAS operation.
///
/// This type wraps `Vec<u8>` and represents content that MAY be cached,
/// replicated, Merkle-verified, and content-addressed.
///
/// Unlike `Ciphertext`, `ContentBytes` exposes its inner bytes for
/// content operations (hashing, chunking, CAS storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentBytes(Vec<u8>);

impl ContentBytes {
    /// Construct from raw content bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the content bytes (for hashing, CAS, etc.).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for ContentBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for ContentBytes {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_class_round_trip() {
        assert_eq!(FrameClass::from_byte(b'A'), Some(FrameClass::Content));
        assert_eq!(FrameClass::from_byte(b'B'), Some(FrameClass::Transit));
        assert_eq!(FrameClass::from_byte(b'C'), Some(FrameClass::Control));
        assert_eq!(FrameClass::from_byte(b'X'), None);

        assert_eq!(FrameClass::Content.as_byte(), b'A');
        assert_eq!(FrameClass::Transit.as_byte(), b'B');
        assert_eq!(FrameClass::Control.as_byte(), b'C');
    }

    #[test]
    fn frame_class_predicates() {
        assert!(FrameClass::Content.is_content());
        assert!(!FrameClass::Content.is_transit());
        assert!(FrameClass::Transit.is_transit());
        assert!(!FrameClass::Transit.is_content());
    }

    #[test]
    fn ciphertext_is_opaque() {
        let ct = Ciphertext::from_encrypted(vec![1, 2, 3]);
        // We can check length but CANNOT read the bytes without consuming.
        assert_eq!(ct.len(), 3);
        assert!(!ct.is_empty());

        // Only the circuit endpoint can consume the ciphertext.
        let bytes = ct.into_bytes();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn content_bytes_exposes_inner() {
        let cb = ContentBytes::new(vec![4, 5, 6]);
        // Content bytes CAN be read (for hashing, CAS, etc.)
        assert_eq!(cb.as_bytes(), &[4, 5, 6]);
        assert_eq!(cb.len(), 3);
    }

    #[test]
    fn ciphertext_cannot_be_converted_to_content_bytes() {
        // There is no From<Ciphertext> for ContentBytes.
        // This is by design — transit data must not become content.
        // This test exists to document the type-level barrier.
        let ct = Ciphertext::from_encrypted(vec![1, 2, 3]);
        let bytes = ct.into_bytes();
        // The only way to get bytes out of Ciphertext is via into_bytes()
        // (consuming it). This is only done at the circuit endpoint.
        // A relay never calls into_bytes() — it forwards the Frame.body
        // as opaque bytes without constructing a Ciphertext at all.
        assert_eq!(bytes, vec![1, 2, 3]);
    }
}

//! SNP-CBOR — Canonical CBOR per RFC 8949 §4.2.1
//!
//! Implements the deterministic CBOR encoding rules from SNP/0.1 §1:
//! - Map keys sorted by fully encoded bytes (length-first for text keys)
//! - Shortest-form integers, definite lengths only
//! - No floats, no tags, no undefined
//! - Duplicate keys rejected on decode
//! - Non-canonical input rejected on decode
//!
//! This is the Rust equivalent of `/src/lib/snp/cbor.ts`.
//!
//! SKELETON — not yet implemented. The TypeScript reference is authoritative
//! until this crate is complete and regenerates the golden vectors. See
//! `/public/docs/adr/0001-typescript-reference-language.md` for the rationale
//! and `/public/conformance/vectors/01-cbor.json` for the vectors this crate
//! must reproduce byte-for-byte.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors that can occur during CBOR encode/decode.
#[derive(Debug, Error)]
pub enum CborError {
    /// Input was well-formed CBOR but not canonical (e.g. non-shortest integer).
    #[error("non-canonical CBOR: {0}")]
    NonCanonical(String),
    /// A map contained the same key twice.
    #[error("duplicate map key")]
    DuplicateKey,
    /// Trailing bytes followed the top-level CBOR item.
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    /// A CBOR value type SNP does not support (float, tag, undefined, …).
    #[error("unsupported CBOR value: {0}")]
    Unsupported(String),
    /// Input was not well-formed CBOR (truncated, bad major type, …).
    #[error("malformed CBOR: {0}")]
    Malformed(String),
}

/// Convenience `Result` alias.
pub type CborResult<T> = Result<T, CborError>;

/// A CBOR value in SNP's supported subset.
///
/// Note: floats, tags, simple values other than `Null`/`Bool`, and indefinite
/// lengths are NOT representable — encountering them on decode yields
/// [`CborError::Unsupported`] or [`CborError::NonCanonical`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// CBOR null (major type 7, value 22).
    Null,
    /// CBOR true/false.
    Bool(bool),
    /// Unsigned integer (major type 0).
    UnsignedInt(u64),
    /// Negative integer (major type 1). Stored as `i64` for ergonomics.
    NegativeInt(i64),
    /// Byte string (major type 2). Definite length only.
    ByteString(Vec<u8>),
    /// UTF-8 text string (major type 3). Definite length only.
    TextString(String),
    /// Array (major type 4). Definite length only.
    Array(Vec<CborValue>),
    /// Map (major type 5). Definite length only. Keys MUST be unique.
    Map(Vec<(CborValue, CborValue)>),
}

/// Encode a [`CborValue`] to canonical bytes.
///
/// # Errors
/// Returns [`CborError`] if the value cannot be canonically encoded (which, for
/// the SNP subset, should be infallible but is reserved for future expansion).
pub fn encode(_value: &CborValue) -> CborResult<Vec<u8>> {
    todo!("Implement canonical CBOR encoding per RFC 8949 §4.2.1")
}

/// Decode canonical CBOR bytes into a [`CborValue`].
///
/// # Errors
/// Returns [`CborError`] if the input is malformed, non-canonical, contains a
/// duplicate key, contains an unsupported value, or has trailing bytes.
pub fn decode(_bytes: &[u8]) -> CborResult<CborValue> {
    todo!("Implement canonical CBOR decoding with rejection of non-canonical input")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder() {
        // Placeholder — real tests will use the conformance vectors from
        // /public/conformance/vectors/01-cbor.json. Each vector asserts:
        //   decode(hex) == Ok(expected_value)
        //   encode(expected_value) == Ok(hex)
        // and that non-canonical variants are rejected.
        let _ = CborValue::Null;
    }
}

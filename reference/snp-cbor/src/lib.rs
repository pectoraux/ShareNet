//! SNP-CBOR — Canonical CBOR per RFC 8949 §4.2.1
//!
//! Implements the deterministic CBOR encoding rules from SNP/0.1 §1:
//! - Map keys sorted by fully encoded bytes (length-first for text keys)
//! - Shortest-form integers, definite lengths only
//! - No floats, no tags, no undefined
//! - Duplicate keys rejected on decode and on encode
//! - Non-canonical input rejected on decode
//!
//! This crate is implemented independently of the TypeScript reference. The
//! normative authority is `public/spec/02-PROTOCOL-SPEC.md` §1 and RFC 8949
//! §4.2.1. The committed vectors in
//! `public/conformance/vectors/01-cbor.json` and `14-negative.json` are
//! consumed directly by the `snp-conformance` harness.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors that can occur during CBOR encode/decode.
#[derive(Debug, Error)]
pub enum CborError {
    /// Input was well-formed CBOR but not canonical (e.g. non-shortest integer,
    /// non-canonical map key order, indefinite-length encoding).
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

impl CborError {
    /// Returns the stable machine-readable error code used by the
    /// conformance vectors (e.g. `"NON_CANONICAL"`, `"DUPLICATE_KEY"`).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            CborError::NonCanonical(_) => "NON_CANONICAL",
            CborError::DuplicateKey => "DUPLICATE_KEY",
            CborError::TrailingBytes => "TRAILING_BYTES",
            CborError::Unsupported(_) => "UNSUPPORTED",
            CborError::Malformed(_) => "MALFORMED",
        }
    }
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
    /// Must be `< 0`.
    NegativeInt(i64),
    /// Byte string (major type 2). Definite length only.
    ByteString(Vec<u8>),
    /// UTF-8 text string (major type 3). Definite length only.
    TextString(String),
    /// Array (major type 4). Definite length only.
    Array(Vec<CborValue>),
    /// Map (major type 5). Definite length only. Keys MUST be unique.
    /// The `Vec` is permitted to be in any order on input; the encoder
    /// will sort entries by the fully encoded key bytes (RFC 8949 §4.2.1).
    Map(Vec<(CborValue, CborValue)>),
}

// Major type tags (high 3 bits of the head byte).
const MT_UNSIGNED: u8 = 0;
const MT_NEGATIVE: u8 = 1;
const MT_BYTE_STRING: u8 = 2;
const MT_TEXT_STRING: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

/// Encode a [`CborValue`] to canonical bytes.
///
/// # Errors
/// Returns [`CborError`] if the value cannot be canonically encoded. In
/// practice this only happens for duplicate map keys (after canonical sort).
pub fn encode(value: &CborValue) -> CborResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &CborValue, out: &mut Vec<u8>) -> CborResult<()> {
    match value {
        CborValue::Null => out.push(0xf6),
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::UnsignedInt(n) => encode_head(MT_UNSIGNED, *n, out),
        CborValue::NegativeInt(n) => {
            if *n >= 0 {
                return Err(CborError::Malformed(format!(
                    "NegativeInt must be < 0, got {n}"
                )));
            }
            // RFC 8949: negative int n is encoded as -1 - n in major type 1.
            // For i64::MIN, -1 - n would overflow i64, so cast via u64.
            let unsigned = (-1_i128 - i128::from(*n)) as u64;
            encode_head(MT_NEGATIVE, unsigned, out);
        }
        CborValue::ByteString(bytes) => {
            encode_head(MT_BYTE_STRING, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::TextString(s) => {
            let bytes = s.as_bytes();
            encode_head(MT_TEXT_STRING, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Array(items) => {
            encode_head(MT_ARRAY, items.len() as u64, out);
            for item in items {
                encode_into(item, out)?;
            }
        }
        CborValue::Map(entries) => {
            // Canonical: sort by fully encoded key bytes. Detect duplicates.
            let mut encoded_pairs: Vec<(Vec<u8>, &CborValue)> =
                Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kbuf = Vec::new();
                encode_into(k, &mut kbuf)?;
                encoded_pairs.push((kbuf, v));
            }
            encoded_pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for window in encoded_pairs.windows(2) {
                if window[0].0 == window[1].0 {
                    return Err(CborError::DuplicateKey);
                }
            }
            encode_head(MT_MAP, entries.len() as u64, out);
            for (kbuf, v) in encoded_pairs {
                out.extend_from_slice(&kbuf);
                encode_into(v, out)?;
            }
        }
    }
    Ok(())
}

/// Emit a CBOR head byte (major type + argument) with shortest-form encoding.
fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let base = major << 5;
    match n {
        0..=23 => out.push(base | n as u8),
        24..=255 => {
            out.push(base | 24);
            out.push(n as u8);
        }
        256..=65_535 => {
            out.push(base | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            out.push(base | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(base | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Decode canonical CBOR bytes into a [`CborValue`].
///
/// # Errors
/// Returns [`CborError`] if the input is malformed, non-canonical, contains a
/// duplicate key, contains an unsupported value, or has trailing bytes.
pub fn decode(bytes: &[u8]) -> CborResult<CborValue> {
    let mut cursor = 0usize;
    let value = decode_one(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

fn decode_one(buf: &[u8], cursor: &mut usize) -> CborResult<CborValue> {
    let head = read_u8(buf, cursor)?;
    let major = head >> 5;
    let info = head & 0x1f;
    match major {
        MT_UNSIGNED => {
            let n = decode_argument(info, buf, cursor)?;
            Ok(CborValue::UnsignedInt(n))
        }
        MT_NEGATIVE => {
            let n = decode_argument(info, buf, cursor)?;
            // RFC 8949: encoded value = -1 - n; n is in [0, 2^64-1].
            // For n = 2^63..2^64-1 this underflows i64::MIN. The SNP subset
            // stores negatives as i64; values outside i64 are unsupported.
            let signed = i128::from(n);
            let neg = -1_i128 - signed;
            if neg < i128::from(i64::MIN) {
                return Err(CborError::Unsupported(format!(
                    "negative int {neg} out of i64 range"
                )));
            }
            Ok(CborValue::NegativeInt(neg as i64))
        }
        MT_BYTE_STRING => {
            let len = decode_argument(info, buf, cursor)?;
            let len = usize_arg(len)?;
            let bytes = read_slice(buf, cursor, len)?;
            Ok(CborValue::ByteString(bytes.to_vec()))
        }
        MT_TEXT_STRING => {
            let len = decode_argument(info, buf, cursor)?;
            let len = usize_arg(len)?;
            let bytes = read_slice(buf, cursor, len)?;
            match std::str::from_utf8(bytes) {
                Ok(s) => Ok(CborValue::TextString(s.to_owned())),
                Err(_) => Err(CborError::Malformed("text string is not UTF-8".into())),
            }
        }
        MT_ARRAY => {
            if info == 31 {
                return Err(CborError::NonCanonical(
                    "indefinite-length array forbidden".into(),
                ));
            }
            let len = decode_argument(info, buf, cursor)?;
            let len = usize_arg(len)?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_one(buf, cursor)?);
            }
            Ok(CborValue::Array(items))
        }
        MT_MAP => {
            if info == 31 {
                return Err(CborError::NonCanonical(
                    "indefinite-length map forbidden".into(),
                ));
            }
            let len = decode_argument(info, buf, cursor)?;
            let len = usize_arg(len)?;
            let mut entries: Vec<(Vec<u8>, (CborValue, CborValue))> = Vec::with_capacity(len);
            for _ in 0..len {
                // We need the *fully encoded* key bytes to verify canonical
                // sort order on the wire. Decode the value, re-encode it
                // (canonical), and compare with the previous encoded key.
                let key_start = *cursor;
                let key = decode_one(buf, cursor)?;
                let mut kbuf = Vec::new();
                encode_into(&key, &mut kbuf)?;
                let value = decode_one(buf, cursor)?;
                // Verify strictly increasing canonical order, no duplicates.
                if let Some(prev) = entries.last() {
                    if kbuf <= prev.0 {
                        if kbuf == prev.0 {
                            return Err(CborError::DuplicateKey);
                        }
                        return Err(CborError::NonCanonical(format!(
                            "map keys not in canonical order at offset {key_start}"
                        )));
                    }
                }
                entries.push((kbuf, (key, value)));
            }
            // Drop the encoded-key bytes (used only for canonicality check).
            let pairs = entries.into_iter().map(|(_, (k, v))| (k, v)).collect();
            Ok(CborValue::Map(pairs))
        }
        MT_TAG => Err(CborError::Unsupported(format!(
            "CBOR tag (major type 6) is forbidden, head=0x{head:02x}"
        ))),
        MT_SIMPLE => match info {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            23 => Err(CborError::Unsupported("CBOR undefined (0xf7)".into())),
            // Float16/32/64 (info 25/26/27) are forbidden.
            25 | 26 | 27 => {
                Err(CborError::Unsupported(format!(
                    "CBOR float (major 7, info {info})"
                )))
            }
            // Other simple values (info 0..=19, 24, 28..=30) — unsupported.
            24 => Err(CborError::Unsupported(
                "CBOR simple value > 23 (0xf8..)".into(),
            )),
            31 => Err(CborError::Malformed(
                "unexpected break code 0xff at top level".into(),
            )),
            other => Err(CborError::Unsupported(format!(
                "CBOR simple value {other}"
            ))),
        },
        _ => Err(CborError::Malformed(format!(
            "unknown major type {major}"
        ))),
    }
}

/// Decode the argument portion of a CBOR head. `info` is the low 5 bits.
/// Validates shortest-form encoding.
fn decode_argument(info: u8, buf: &[u8], cursor: &mut usize) -> CborResult<u64> {
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => {
            let v = u64::from(read_u8(buf, cursor)?);
            // Shortest-form: values 0..23 MUST use the immediate form.
            if v <= 23 {
                return Err(CborError::NonCanonical(format!(
                    "integer {v} encoded with 1-byte form (0x18) instead of immediate"
                )));
            }
            Ok(v)
        }
        25 => {
            let v = u64::from(read_u16(buf, cursor)?);
            if v <= 255 {
                return Err(CborError::NonCanonical(format!(
                    "integer {v} encoded with 2-byte form (0x19) instead of shorter"
                )));
            }
            Ok(v)
        }
        26 => {
            let v = u64::from(read_u32(buf, cursor)?);
            if v <= 65_535 {
                return Err(CborError::NonCanonical(format!(
                    "integer {v} encoded with 4-byte form (0x1a) instead of shorter"
                )));
            }
            Ok(v)
        }
        27 => {
            let v = read_u64(buf, cursor)?;
            if v <= 4_294_967_295 {
                return Err(CborError::NonCanonical(format!(
                    "integer {v} encoded with 8-byte form (0x1b) instead of shorter"
                )));
            }
            Ok(v)
        }
        28..=30 => Err(CborError::Malformed(format!(
            "reserved info value {info}"
        ))),
        31 => Err(CborError::NonCanonical(
            "indefinite-length encoding forbidden in SNP-CBOR".into(),
        )),
        // info is the low 5 bits of the head byte, so 0..=31 is exhaustive.
        // Defensive catch-all (unreachable because info & 0x1f ∈ [0,31]).
        _ => Err(CborError::Malformed(format!(
            "invalid info value {info}"
        ))),
    }
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> CborResult<u8> {
    let b = buf.get(*cursor).copied().ok_or_else(|| {
        CborError::Malformed("unexpected end of input while reading head byte".into())
    })?;
    *cursor += 1;
    Ok(b)
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> CborResult<u16> {
    let end = *cursor + 2;
    if end > buf.len() {
        return Err(CborError::Malformed("truncated 2-byte argument".into()));
    }
    let v = u16::from_be_bytes(buf[*cursor..end].try_into().unwrap());
    *cursor = end;
    Ok(v)
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> CborResult<u32> {
    let end = *cursor + 4;
    if end > buf.len() {
        return Err(CborError::Malformed("truncated 4-byte argument".into()));
    }
    let v = u32::from_be_bytes(buf[*cursor..end].try_into().unwrap());
    *cursor = end;
    Ok(v)
}

fn read_u64(buf: &[u8], cursor: &mut usize) -> CborResult<u64> {
    let end = *cursor + 8;
    if end > buf.len() {
        return Err(CborError::Malformed("truncated 8-byte argument".into()));
    }
    let v = u64::from_be_bytes(buf[*cursor..end].try_into().unwrap());
    *cursor = end;
    Ok(v)
}

fn read_slice<'a>(buf: &'a [u8], cursor: &mut usize, len: usize) -> CborResult<&'a [u8]> {
    let end = (*cursor).checked_add(len).ok_or_else(|| {
        CborError::Malformed("byte/text string length overflows usize".into())
    })?;
    if end > buf.len() {
        return Err(CborError::Malformed(format!(
            "byte/text string of length {len} runs past end of input"
        )));
    }
    let s = &buf[*cursor..end];
    *cursor = end;
    Ok(s)
}

fn usize_arg(n: u64) -> CborResult<usize> {
    usize::try_from(n).map_err(|_| {
        CborError::Malformed(format!("length {n} exceeds usize::MAX on this platform"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn integer_shortest_forms() {
        let cases = [
            (CborValue::UnsignedInt(0), "00"),
            (CborValue::UnsignedInt(23), "17"),
            (CborValue::UnsignedInt(24), "1818"),
            (CborValue::UnsignedInt(255), "18ff"),
            (CborValue::UnsignedInt(256), "190100"),
            (CborValue::UnsignedInt(65536), "1a00010000"),
            (CborValue::NegativeInt(-1), "20"),
        ];
        for (val, expected) in cases {
            assert_eq!(hex(&encode(&val).unwrap()), expected);
            assert_eq!(decode(&from_hex(expected)).unwrap(), val);
        }
    }

    #[test]
    fn rejects_non_canonical_int_24() {
        // 0x18 0x17 = 1-byte form of value 23, which MUST be immediate
        let err = decode(&[0x18, 0x17]).unwrap_err();
        assert!(matches!(err, CborError::NonCanonical(_)));
        assert_eq!(err.code(), "NON_CANONICAL");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let err = decode(&[0x00, 0x01]).unwrap_err();
        assert!(matches!(err, CborError::TrailingBytes));
        assert_eq!(err.code(), "TRAILING_BYTES");
    }

    #[test]
    fn rejects_duplicate_keys() {
        // {"a":1, "a":2}
        let err = decode(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]).unwrap_err();
        assert!(matches!(err, CborError::DuplicateKey));
        assert_eq!(err.code(), "DUPLICATE_KEY");
    }

    #[test]
    fn rejects_non_canonical_key_order() {
        // {"bcd":1, "a":2} — non-canonical because "a" < "bcd" by encoded bytes
        let err = decode(&[
            0xa2, 0x63, b'b', b'c', b'd', 0x01, 0x61, b'a', 0x02,
        ])
        .unwrap_err();
        assert!(matches!(err, CborError::NonCanonical(_)));
        assert_eq!(err.code(), "NON_CANONICAL");
    }

    #[test]
    fn rejects_indefinite_length_array() {
        let err = decode(&[0x9f, 0x01, 0xff]).unwrap_err();
        assert!(matches!(err, CborError::NonCanonical(_)));
        assert_eq!(err.code(), "NON_CANONICAL");
    }

    #[test]
    fn encode_sorts_map_keys() {
        // Input in non-canonical order; encoder must sort.
        let m = CborValue::Map(vec![
            (CborValue::TextString("bcd".into()), CborValue::UnsignedInt(1)),
            (CborValue::TextString("a".into()), CborValue::UnsignedInt(2)),
        ]);
        let out = encode(&m).unwrap();
        // Expect: a(2) {"a":2, "bcd":1}
        let expected = [0xa2, 0x61, b'a', 0x02, 0x63, b'b', b'c', b'd', 0x01];
        assert_eq!(out, expected);
    }
}

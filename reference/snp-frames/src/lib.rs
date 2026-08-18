//! SNP-FRAMES — SNP/0.1 §7 Frame format
//!
//! The Frame is THE structural unit that crosses every SNP link. The single
//! most important design decision in the redesign is the split between:
//!
//! - **Class A** (content)  — body is an object-protocol message. MAY be
//!                            inspected, cached, deduplicated.
//! - **Class B** (transit)  — body is opaque AEAD ciphertext for a downstream
//!                            circuit. Relays MUST NOT inspect, cache, or
//!                            deduplicate (I8). The frame is forwarded purely
//!                            on `(dst, fid, ttl)`.
//! - **Class C** (control)  — body is a link/control message.
//!
//! The Frame CDDL (02-PROTOCOL-SPEC.md §7.1):
//!
//! ```text
//! Frame = {
//!   v:    uint,             ; protocol version = 1
//!   cls:  "A" / "B" / "C",  ; A=content, B=transit, C=control
//!   dst:  bstr .size 32,    ; destination NodeId
//!   src:  bstr .size 32,    ; source NodeId (or blinded per §7.4)
//!   ttl:  uint,             ; decrement per hop, drop at 0. Max 16.
//!   fid:  bstr .size 8,     ; flow/circuit id — opaque to relays
//!   seq:  uint,
//!   body: bstr              ; Class A: object protocol. Class B: ciphertext.
//! }
//! ```
//!
//! Invariants enforced:
//!
//! - **I7** — `Frame.ttl ≤ 16`, decremented every hop. `forward` errors at
//!   ttl=0; `should_drop` is the relay-side check.
//! - **I8** — Class B payloads are never inspected, cached, or duplicated by
//!   relays. The Frame type itself is neutral — the relay policy is enforced
//!   by the forwarding code keyed on `cls`. This crate does not look at the
//!   body of any frame.
//! - **I20** — `decode` returns an error on malformed input; it never
//!   silently accepts.
//!
//! This crate is implemented independently of the TypeScript reference. The
//! normative authority is `public/spec/02-PROTOCOL-SPEC.md` §7 and the
//! committed vectors in
//! `public/conformance/vectors/08-frames.json`. The TS reference lives at
//! `/src/lib/snp/frames.ts`; the Rust implementation here matches the wire
//! format byte-for-byte (verified against the `frame-encode-decode-roundtrip`
//! vector).

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Errors from SNP frame (de)serialization.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The frame failed structural validation (out-of-range field, wrong
    /// length, unknown `cls`, etc.).
    #[error("malformed frame: {0}")]
    Malformed(String),
    /// The decoded CBOR was not a Frame-shaped map (wrong major type, missing
    /// keys, extra keys, wrong value types).
    #[error("frame shape mismatch: {0}")]
    Shape(String),
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// The frame's TTL is exhausted and cannot be forwarded.
    #[error("TTL exhausted (ttl={0}) — frame must be dropped, not forwarded")]
    TtlExhausted(u8),
}

/// Convenience `Result` alias.
pub type FrameResult<T> = Result<T, FrameError>;

/// Protocol version carried in `Frame.v`. Frozen at 1.
pub const FRAME_VERSION: u8 = 1;

/// Maximum TTL a frame may carry (I7). Frozen at 16.
pub const FRAME_TTL_MAX: u8 = 16;

/// Length of the flow/circuit id in bytes. Frozen at 8.
pub const FRAME_FLOW_ID_BYTES: usize = 8;

/// Length of a NodeId in bytes (SHA-256 output, I4).
pub const NODE_ID_BYTES: usize = 32;

/// Frame map keys (string form, as they appear on the wire). Canonical
/// (length-first) sort by encoded bytes yields:
/// `v` (1) < `cls`, `dst`, `fid`, `seq`, `src`, `ttl` (3, alphabetic) < `body` (4).
const KEY_V: &str = "v";
const KEY_CLS: &str = "cls";
const KEY_DST: &str = "dst";
const KEY_SRC: &str = "src";
const KEY_TTL: &str = "ttl";
const KEY_FID: &str = "fid";
const KEY_SEQ: &str = "seq";
const KEY_BODY: &str = "body";

/// The number of keys in a Frame map (closed CDDL — extras MUST be rejected).
const FRAME_KEY_COUNT: usize = 8;

/// A SNP Frame — the wire unit every relay sees on every link.
///
/// Field semantics (02-PROTOCOL-SPEC.md §7.1):
///
/// - `v`    — protocol version. MUST equal [`FRAME_VERSION`] (1).
/// - `cls`  — traffic class discriminator: `b'A'`=content, `b'B'`=transit,
///            `b'C'`=control. Stored as the ASCII byte; converted to a
///            single-character text string on the wire.
/// - `dst`  — destination NodeId (32 bytes). For Class B transit the relay
///            forwards toward `dst` without inspecting `body`.
/// - `src`  — source NodeId (32 bytes). May be blinded/rotated per §7.4 for
///            metadata minimisation, but the wire field is always 32 bytes.
/// - `ttl`  — time-to-live in hops. Max [`FRAME_TTL_MAX`] (16). Decremented
///            every hop by [`forward`]; dropped at 0 by [`should_drop`].
/// - `fid`  — flow/circuit id (8 bytes). OPAQUE to relays.
/// - `seq`  — per-flow sequence number.
/// - `body` — payload bytes. The Frame type itself is neutral about how
///            `body` is handled — relay policy is enforced by the forwarding
///            code keyed on `cls`. Per I8, Class B bodies MUST NOT be
///            inspected, cached, or deduplicated by relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Protocol version. MUST equal [`FRAME_VERSION`] (1).
    pub v: u8,
    /// Traffic class: `b'A'`, `b'B'`, or `b'C'`.
    pub cls: u8,
    /// Destination NodeId (32 bytes).
    pub dst: [u8; NODE_ID_BYTES],
    /// Source NodeId (32 bytes).
    pub src: [u8; NODE_ID_BYTES],
    /// Time-to-live in hops, `[0, FRAME_TTL_MAX]`. Decremented per hop.
    pub ttl: u8,
    /// Flow/circuit id (8 bytes). Opaque to relays.
    pub fid: [u8; FRAME_FLOW_ID_BYTES],
    /// Per-flow sequence number.
    pub seq: u32,
    /// Payload bytes.
    pub body: Vec<u8>,
}

impl Frame {
    /// Construct a new Frame with `v=FRAME_VERSION`, the given `cls`, and
    /// `ttl=FRAME_TTL_MAX`. Other fields are zeroed/empty — the caller fills
    /// them in.
    #[must_use]
    pub fn new(cls: u8, dst: [u8; NODE_ID_BYTES], src: [u8; NODE_ID_BYTES]) -> Self {
        Self {
            v: FRAME_VERSION,
            cls,
            dst,
            src,
            ttl: FRAME_TTL_MAX,
            fid: [0u8; FRAME_FLOW_ID_BYTES],
            seq: 0,
            body: Vec::new(),
        }
    }

    /// Validate this frame's fields against the CDDL constraints (I20).
    ///
    /// # Errors
    /// Returns [`FrameError::Malformed`] if any field is out of range or has
    /// the wrong length.
    pub fn validate(&self) -> FrameResult<()> {
        if self.v != FRAME_VERSION {
            return Err(FrameError::Malformed(format!(
                "Frame.v must equal FRAME_VERSION ({FRAME_VERSION}); got {}",
                self.v
            )));
        }
        if self.cls != b'A' && self.cls != b'B' && self.cls != b'C' {
            return Err(FrameError::Malformed(format!(
                "Frame.cls must be b'A', b'B', or b'C'; got 0x{:02x} ({})",
                self.cls,
                self.cls as char
            )));
        }
        if self.ttl > FRAME_TTL_MAX {
            return Err(FrameError::Malformed(format!(
                "Frame.ttl must be in [0, {FRAME_TTL_MAX}]; got {}",
                self.ttl
            )));
        }
        // dst/src/fid are fixed-size arrays — length is enforced by the type.
        Ok(())
    }

    /// CBOR-encode this frame as a canonical map with string keys.
    ///
    /// The keys appear in canonical (length-first) sort order on the wire:
    /// `v`, `cls`, `dst`, `fid`, `seq`, `src`, `ttl`, `body`. The encoder
    /// sorts map keys by their fully encoded bytes, so the caller may insert
    /// in any order.
    ///
    /// # Errors
    /// Returns [`FrameError`] if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> FrameResult<Vec<u8>> {
        self.validate()?;
        let cls_str = char::from_u32(u32::from(self.cls))
            .ok_or_else(|| FrameError::Malformed(format!("Frame.cls 0x{:02x} is not a valid char", self.cls)))?
            .to_string();
        let map = snp_cbor::CborValue::Map(vec![
            (s(KEY_V), u(u64::from(self.v))),
            (s(KEY_CLS), snp_cbor::CborValue::TextString(cls_str)),
            (s(KEY_DST), b(&self.dst)),
            (s(KEY_SRC), b(&self.src)),
            (s(KEY_TTL), u(u64::from(self.ttl))),
            (s(KEY_FID), b(&self.fid)),
            (s(KEY_SEQ), u(u64::from(self.seq))),
            (s(KEY_BODY), b(&self.body)),
        ]);
        Ok(snp_cbor::encode(&map)?)
    }

    /// Decode a Frame from canonical CBOR bytes.
    ///
    /// The decoder rejects trailing bytes, non-canonical key order, duplicate
    /// keys, and non-shortest integer encodings. Anything that survives is
    /// well-formed SNP-CBOR; this function then verifies it is Frame-shaped
    /// (exactly 8 known keys, correct value types) and runs [`validate`].
    ///
    /// # Errors
    /// Returns [`FrameError`] on any decode or validation failure (I20).
    pub fn decode_cbor(bytes: &[u8]) -> FrameResult<Self> {
        let value = snp_cbor::decode(bytes)?;
        let entries = match value {
            snp_cbor::CborValue::Map(entries) => entries,
            other => {
                return Err(FrameError::Shape(format!(
                    "Frame must decode to a CBOR map; got {other:?}"
                )));
            }
        };
        if entries.len() != FRAME_KEY_COUNT {
            return Err(FrameError::Shape(format!(
                "Frame map must have exactly {FRAME_KEY_COUNT} keys; got {}",
                entries.len()
            )));
        }
        // Extract by key. All keys must be text strings; reject anything else.
        let mut v: Option<u64> = None;
        let mut cls: Option<u8> = None;
        let mut dst: Option<[u8; NODE_ID_BYTES]> = None;
        let mut src: Option<[u8; NODE_ID_BYTES]> = None;
        let mut ttl: Option<u8> = None;
        let mut fid: Option<[u8; FRAME_FLOW_ID_BYTES]> = None;
        let mut seq: Option<u32> = None;
        let mut body: Option<Vec<u8>> = None;
        for (k, val) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s,
                other => {
                    return Err(FrameError::Shape(format!(
                        "Frame map keys must be text strings; got {other:?}"
                    )));
                }
            };
            match key.as_str() {
                KEY_V => v = Some(extract_uint(val, KEY_V)?),
                KEY_CLS => cls = Some(extract_class(val, KEY_CLS)?),
                KEY_DST => dst = Some(extract_bstr_32(val, KEY_DST)?),
                KEY_SRC => src = Some(extract_bstr_32(val, KEY_SRC)?),
                KEY_TTL => ttl = Some(extract_uint(val, KEY_TTL)? as u8),
                KEY_FID => fid = Some(extract_bstr_8(val, KEY_FID)?),
                KEY_SEQ => seq = Some(extract_uint(val, KEY_SEQ)? as u32),
                KEY_BODY => body = Some(extract_bstr_any(val, KEY_BODY)?),
                other => {
                    return Err(FrameError::Shape(format!(
                        "unknown Frame key \"{other}\""
                    )));
                }
            }
        }
        let v = v.ok_or_else(|| FrameError::Shape("Frame.v missing".into()))?;
        let cls = cls.ok_or_else(|| FrameError::Shape("Frame.cls missing".into()))?;
        let dst = dst.ok_or_else(|| FrameError::Shape("Frame.dst missing".into()))?;
        let src = src.ok_or_else(|| FrameError::Shape("Frame.src missing".into()))?;
        let ttl = ttl.ok_or_else(|| FrameError::Shape("Frame.ttl missing".into()))?;
        let fid = fid.ok_or_else(|| FrameError::Shape("Frame.fid missing".into()))?;
        let seq = seq.ok_or_else(|| FrameError::Shape("Frame.seq missing".into()))?;
        let body = body.ok_or_else(|| FrameError::Shape("Frame.body missing".into()))?;
        let frame = Self {
            v: v as u8,
            cls,
            dst,
            src,
            ttl,
            fid,
            seq,
            body,
        };
        frame.validate()?;
        Ok(frame)
    }
}

/// Produce a forwarded copy of `frame` with `ttl` decremented by 1 (I7).
///
/// Returns a NEW [`Frame`] — the input is not mutated — with all fields
/// identical except `ttl`, which is `frame.ttl - 1`.
///
/// # Errors
/// Returns [`FrameError::TtlExhausted`] if `frame.ttl == 0`. A frame with no
/// TTL remaining cannot be forwarded — relays MUST drop frames whose TTL has
/// reached 0 rather than forwarding them with a negative or wrapped TTL.
pub fn forward(frame: &Frame) -> FrameResult<Frame> {
    if frame.ttl == 0 {
        return Err(FrameError::TtlExhausted(0));
    }
    let mut next = frame.clone();
    next.ttl -= 1;
    Ok(next)
}

/// Relay-side TTL exhaustion check (I7).
///
/// Returns `true` if the frame should be dropped because its TTL has been
/// exhausted (`ttl == 0`). Relays call this BEFORE forwarding: a frame with
/// `ttl == 0` is dropped on receipt rather than forwarded.
#[must_use]
pub fn should_drop(frame: &Frame) -> bool {
    frame.ttl == 0
}

// ─── Internal CBOR extraction helpers ───────────────────────────────────────

fn extract_uint(v: snp_cbor::CborValue, field: &str) -> FrameResult<u64> {
    match v {
        snp_cbor::CborValue::UnsignedInt(n) => Ok(n),
        other => Err(FrameError::Shape(format!(
            "Frame.{field} must be a CBOR uint; got {other:?}"
        ))),
    }
}

fn extract_class(v: snp_cbor::CborValue, field: &str) -> FrameResult<u8> {
    match v {
        snp_cbor::CborValue::TextString(s) => {
            let c = s.as_bytes();
            if c.len() == 1 && (c[0] == b'A' || c[0] == b'B' || c[0] == b'C') {
                Ok(c[0])
            } else {
                Err(FrameError::Shape(format!(
                    "Frame.{field} must be \"A\", \"B\", or \"C\"; got \"{s}\""
                )))
            }
        }
        other => Err(FrameError::Shape(format!(
            "Frame.{field} must be a text string; got {other:?}"
        ))),
    }
}

fn extract_bstr_32(v: snp_cbor::CborValue, field: &str) -> FrameResult<[u8; NODE_ID_BYTES]> {
    match v {
        snp_cbor::CborValue::ByteString(bytes) => {
            if bytes.len() != NODE_ID_BYTES {
                return Err(FrameError::Shape(format!(
                    "Frame.{field} must be {NODE_ID_BYTES} bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; NODE_ID_BYTES];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(FrameError::Shape(format!(
            "Frame.{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_bstr_8(v: snp_cbor::CborValue, field: &str) -> FrameResult<[u8; FRAME_FLOW_ID_BYTES]> {
    match v {
        snp_cbor::CborValue::ByteString(bytes) => {
            if bytes.len() != FRAME_FLOW_ID_BYTES {
                return Err(FrameError::Shape(format!(
                    "Frame.{field} must be {FRAME_FLOW_ID_BYTES} bytes; got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; FRAME_FLOW_ID_BYTES];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        other => Err(FrameError::Shape(format!(
            "Frame.{field} must be a byte string; got {other:?}"
        ))),
    }
}

fn extract_bstr_any(v: snp_cbor::CborValue, field: &str) -> FrameResult<Vec<u8>> {
    match v {
        snp_cbor::CborValue::ByteString(bytes) => Ok(bytes),
        other => Err(FrameError::Shape(format!(
            "Frame.{field} must be a byte string; got {other:?}"
        ))),
    }
}

// Tiny helpers for building CborValue entries concisely.
fn u(n: u64) -> snp_cbor::CborValue {
    snp_cbor::CborValue::UnsignedInt(n)
}
fn s(s: &str) -> snp_cbor::CborValue {
    snp_cbor::CborValue::TextString(s.to_string())
}
fn b(bytes: &[u8]) -> snp_cbor::CborValue {
    snp_cbor::CborValue::ByteString(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Vectors from /public/conformance/vectors/08-frames.json
    // — frame-encode-decode-roundtrip input.
    fn sample_frame() -> Frame {
        let dst_hex = "0f4db5b32661ec699e5fcbefabe8a9ac11670fc7df5e62c6ea1a9b872bf3c2d4";
        let src_hex = "4ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b414913";
        let fid_hex = "41f643b3d2c5c18c";
        let body_hex = "deadbeef";
        let mut dst = [0u8; 32];
        let mut src = [0u8; 32];
        let mut fid = [0u8; 8];
        dst.copy_from_slice(&from_hex(dst_hex));
        src.copy_from_slice(&from_hex(src_hex));
        fid.copy_from_slice(&from_hex(fid_hex));
        Frame {
            v: 1,
            cls: b'B',
            dst,
            src,
            ttl: 16,
            fid,
            seq: 1,
            body: from_hex(body_hex),
        }
    }

    #[test]
    fn roundtrip_matches_committed_vector() {
        let frame = sample_frame();
        let encoded = frame.encode_cbor().unwrap();
        let expected_hex = "a861760163636c7361426364737458200f4db5b32661ec699e5fcbefabe8a9ac11670fc7df5e62c6ea1a9b872bf3c2d4636669644841f643b3d2c5c18c63736571016373726358204ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b4149136374746c1064626f647944deadbeef";
        assert_eq!(hex(&encoded), expected_hex);
        let decoded = Frame::decode_cbor(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn forward_decrements_ttl() {
        let frame = sample_frame();
        let forwarded = forward(&frame).unwrap();
        assert_eq!(forwarded.ttl, 15);
        assert_eq!(frame.ttl, 16); // input not mutated
        // All other fields preserved.
        assert_eq!(forwarded.cls, frame.cls);
        assert_eq!(forwarded.dst, frame.dst);
        assert_eq!(forwarded.src, frame.src);
        assert_eq!(forwarded.fid, frame.fid);
        assert_eq!(forwarded.seq, frame.seq);
        assert_eq!(forwarded.body, frame.body);
    }

    #[test]
    fn forward_at_zero_errors() {
        let mut frame = sample_frame();
        frame.ttl = 0;
        let err = forward(&frame).unwrap_err();
        assert!(matches!(err, FrameError::TtlExhausted(0)));
    }

    #[test]
    fn should_drop_at_zero() {
        let mut frame = sample_frame();
        frame.ttl = 0;
        assert!(should_drop(&frame));
        frame.ttl = 1;
        assert!(!should_drop(&frame));
        frame.ttl = 16;
        assert!(!should_drop(&frame));
    }

    #[test]
    fn rejects_ttl_above_max() {
        let mut frame = sample_frame();
        frame.ttl = 17;
        let err = frame.encode_cbor().unwrap_err();
        assert!(matches!(err, FrameError::Malformed(_)));
    }

    #[test]
    fn rejects_unknown_class() {
        let mut frame = sample_frame();
        frame.cls = b'X';
        let err = frame.encode_cbor().unwrap_err();
        assert!(matches!(err, FrameError::Malformed(_)));
    }

    #[test]
    fn rejects_extra_keys() {
        // Add a 9th key to the map.
        let entries = snp_cbor::CborValue::Map(vec![
            (s("v"), u(1)),
            (s("cls"), s("B")),
            (s("dst"), b(&[0u8; 32])),
            (s("src"), b(&[0u8; 32])),
            (s("ttl"), u(16)),
            (s("fid"), b(&[0u8; 8])),
            (s("seq"), u(1)),
            (s("body"), b(&[])),
            (s("extra"), u(99)),
        ]);
        let bytes = snp_cbor::encode(&entries).unwrap();
        let err = Frame::decode_cbor(&bytes).unwrap_err();
        assert!(matches!(err, FrameError::Shape(_)));
    }

    #[test]
    fn class_a_roundtrip() {
        let mut frame = sample_frame();
        frame.cls = b'A';
        let encoded = frame.encode_cbor().unwrap();
        let decoded = Frame::decode_cbor(&encoded).unwrap();
        assert_eq!(decoded.cls, b'A');
    }

    #[test]
    fn class_c_roundtrip() {
        let mut frame = sample_frame();
        frame.cls = b'C';
        let encoded = frame.encode_cbor().unwrap();
        let decoded = Frame::decode_cbor(&encoded).unwrap();
        assert_eq!(decoded.cls, b'C');
    }
}

pub mod traffic_class;

// Re-export the traffic class types for convenience.
pub use traffic_class::{Ciphertext, ContentBytes, FrameClass};

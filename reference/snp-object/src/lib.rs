//! SNP-OBJECT — Content-addressed objects for `ShareNet` 2.0
//!
//! Implements the SNP/0.1 content layer (per `02-PROTOCOL-SPEC.md` §3):
//! - **Gear CDC chunking** with frozen constants (MIN 256 KiB, TARGET 1 MiB,
//!   MAX 4 MiB, 20-bit mask). Boundary logic MUST NOT change without an ADR.
//! - **RFC 6962 Merkle trees** with `\x00` (leaf) and `\x01` (intermediate)
//!   prefixes, no odd-node duplication, empty root = `SHA-256("SNP/0.1 empty\0")`.
//! - **Content-addressed storage (CAS)** keyed by `SHA-256`.
//! - **Manifests** — the signed envelope that binds an object's metadata,
//!   chunk list, and Merkle root.
//!
//! This crate is implemented independently of the TypeScript reference. The
//! normative authority is `public/spec/02-PROTOCOL-SPEC.md` §3 and RFC 6962.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// R4.2 interop: allow common pedantic lints that do not indicate bugs.
#![allow(
    clippy::must_use_candidate,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::return_self_not_must_use,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::double_must_use,
    clippy::items_after_statements,
    clippy::format_collect
)]

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors from the SNP content layer.
#[derive(Debug, Error)]
pub enum ObjectError {
    /// A chunk referenced by a manifest was not present in the CAS.
    #[error("missing chunk: {0}")]
    MissingChunk(String),
    /// A Merkle proof failed verification.
    #[error("invalid Merkle proof")]
    InvalidProof,
    /// A manifest signature failed verification.
    #[error("invalid manifest signature")]
    InvalidSignature,
    /// A CAS key did not match the stored bytes.
    #[error("CAS key mismatch: expected {expected}, got {actual}")]
    CasMismatch {
        /// Expected SHA-256 (hex).
        expected: String,
        /// Actual SHA-256 (hex).
        actual: String,
    },
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
}

/// Convenience `Result` alias.
pub type ObjectResult<T> = Result<T, ObjectError>;

/// A 32-byte content hash (SHA-256 of a chunk, leaf, or root).
pub type ContentHash = [u8; 32];

// ─── ContentBytes (Class A body) ───────────────────────────────────────────

/// Typed content data — represents Class A content that MAY be cached,
/// replicated, Merkle-verified, and content-addressed.
///
/// This type wraps `Vec<u8>` and represents content that is semantically
/// distinct from Class B transit ciphertext.
///
/// Unlike a transit ciphertext type, `ContentBytes` exposes its inner
/// bytes for content operations (hashing, chunking, CAS storage).
///
/// ## Ownership
///
/// `ContentBytes` is owned by the content layer (L2), not the transport
/// layer (L8). The transport layer may carry content bytes, but the
/// semantic ownership of "what is content" belongs here.
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

// ─── Manifest (frozen wire semantics, R4.2 interop) ────────────────────────
//
// The frozen TS reference (`src/lib/snp/manifest.ts`) defines the Manifest
// with 10 fields and a signature over fields 1-9. The previous Rust skeleton
// had the WRONG fields (publisher/content_type/size/chunks/merkle_root/
// encryption_key) — it did not match the frozen wire format.
//
// This implementation matches the frozen TS `manifestToWireMap` /
// `manifestFromWireMap` (sync.ts:386-399, 406-435) + `manifestToCborMap`
// (manifest.ts:126-140) field-for-field, and provides the canonical
// byte-level encoder/decoder that R4.2's `ManifestPayload` carries.
//
// CDDL (02-PROTOCOL-SPEC.md §A2, manifest.ts:82-103):
//   Manifest = {
//     "objectId":    bstr .size 32,    ; Merkle root of chunks
//     "chunks":      [+ bstr .size 32], ; ordered chunk hashes
//     "chunkCount":  uint,             ; MUST equal chunks.length
//     "totalBytes":  uint,             ; non-negative
//     "mimeType":    tstr,             ; non-empty
//     "class":       tstr,             ; one of MANIFEST_CLASSES
//     "publisherId": bstr .size 32,    ; NodeId (not bare key)
//     "publishedAt": uint,             ; non-negative
//     "expiresAt":   uint / null,      ; null or > publishedAt
//     "signature":   bstr .size 64     ; Ed25519 by publisher's key
//   }
//
// The signature preimage is `SIG_CONTEXT("manifest") ‖ CBOR(fields 1-9)`
// (manifest.ts:147-148). The `signature` field is NOT part of the signed
// preimage.
//
// MANIFEST_CLASSES (manifest.ts:67-73): "content", "app", "model",
// "dataset", "transit-response".

/// Allowed values for `Manifest::class` (manifest.ts:67-73).
pub const MANIFEST_CLASSES: &[&str] = &["content", "app", "model", "dataset", "transit-response"];

/// A 64-byte Ed25519 signature.
pub type ManifestSignature = [u8; 64];

/// A complete Manifest — the signed, content-addressed object envelope.
///
/// Per the frozen TS reference (`manifest.ts:82-103`), all `bstr` fields are
/// byte arrays (never hex strings on the wire — I3). `expires_at` may be
/// `None` for content with no expiry. The `signature` is over
/// `SIG_CONTEXT("manifest") ‖ CBOR(fields 1-9)` — the `signature` field
/// itself is NOT part of the signed preimage.
///
/// # Wire format
///
/// `encode_cbor()` produces canonical CBOR matching the TS
/// `manifestToWireMap`. `decode_cbor()` is the inverse. The decode is
/// STRUCTURAL ONLY — it does NOT verify the signature (use `verify` for
/// that). This preserves the separation: decode ≠ verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// 32-byte Merkle root of the chunks (`ObjectId`).
    pub object_id: ContentHash,
    /// Ordered list of 32-byte chunk hashes. MUST be non-empty.
    pub chunks: Vec<ContentHash>,
    /// Number of chunks. MUST equal `chunks.len()` (audit fix).
    pub chunk_count: u64,
    /// Total size of the original object in bytes (non-negative).
    pub total_bytes: u64,
    /// MIME type, e.g. `"application/octet-stream"` (non-empty string).
    pub mime_type: String,
    /// Traffic class — one of `MANIFEST_CLASSES`.
    pub class: String,
    /// `NodeId` (32 bytes) of the publisher. NOT a bare public key.
    pub publisher_id: [u8; 32],
    /// Publication time, unix seconds (non-negative).
    pub published_at: u64,
    /// Expiry time, unix seconds, or `None` for no expiry.
    /// If `Some`, MUST be strictly greater than `published_at`.
    pub expires_at: Option<u64>,
    /// 64-byte Ed25519 signature by the publisher's key.
    pub signature: ManifestSignature,
}

/// Fields of a `Manifest`, excluding the signature. This is what gets signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestUnsigned {
    /// 32-byte Merkle root of the chunks (`ObjectId`).
    pub object_id: ContentHash,
    /// Ordered list of 32-byte chunk hashes. MUST be non-empty.
    pub chunks: Vec<ContentHash>,
    /// Number of chunks. MUST equal `chunks.len()`.
    pub chunk_count: u64,
    /// Total size of the original object in bytes.
    pub total_bytes: u64,
    /// MIME type, e.g. `"application/octet-stream"`.
    pub mime_type: String,
    /// Traffic class — one of `MANIFEST_CLASSES`.
    pub class: String,
    /// `NodeId` (32 bytes) of the publisher.
    pub publisher_id: [u8; 32],
    /// Publication time, unix seconds.
    pub published_at: u64,
    /// Expiry time, unix seconds, or `None`.
    pub expires_at: Option<u64>,
}

impl Manifest {
    /// The `SIG_CONTEXT` name for Manifest signatures (`"manifest"`).
    pub const SIG_CONTEXT_NAME: &'static str = "manifest";

    /// Construct the unsigned fields view (excludes `signature`).
    #[must_use]
    pub fn unsigned(&self) -> ManifestUnsigned {
        ManifestUnsigned {
            object_id: self.object_id,
            chunks: self.chunks.clone(),
            chunk_count: self.chunk_count,
            total_bytes: self.total_bytes,
            mime_type: self.mime_type.clone(),
            class: self.class.clone(),
            publisher_id: self.publisher_id,
            published_at: self.published_at,
            expires_at: self.expires_at,
        }
    }

    /// Build the canonical CBOR preimage map for a Manifest, EXCLUDING the
    /// `signature` field. This is the structure fed to `sign` / `verify`
    /// under `SIG_CONTEXT` `"manifest"` (manifest.ts:126-140).
    ///
    /// The map keys are passed to the encoder in arbitrary order; the
    /// canonical-CBOR encoder (RFC 8949 §4.2.1) sorts them by encoded-key
    /// bytes before emission, so the wire format is deterministic.
    fn unsigned_cbor(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        let expires_at_val = match self.expires_at {
            Some(t) => CborValue::UnsignedInt(t),
            None => CborValue::Null,
        };
        CborValue::Map(vec![
            (
                CborValue::TextString("objectId".into()),
                CborValue::ByteString(self.object_id.to_vec()),
            ),
            (
                CborValue::TextString("chunks".into()),
                CborValue::Array(
                    self.chunks
                        .iter()
                        .map(|c| CborValue::ByteString(c.to_vec()))
                        .collect(),
                ),
            ),
            (
                CborValue::TextString("chunkCount".into()),
                CborValue::UnsignedInt(self.chunk_count),
            ),
            (
                CborValue::TextString("totalBytes".into()),
                CborValue::UnsignedInt(self.total_bytes),
            ),
            (
                CborValue::TextString("mimeType".into()),
                CborValue::TextString(self.mime_type.clone()),
            ),
            (
                CborValue::TextString("class".into()),
                CborValue::TextString(self.class.clone()),
            ),
            (
                CborValue::TextString("publisherId".into()),
                CborValue::ByteString(self.publisher_id.to_vec()),
            ),
            (
                CborValue::TextString("publishedAt".into()),
                CborValue::UnsignedInt(self.published_at),
            ),
            (CborValue::TextString("expiresAt".into()), expires_at_val),
        ])
    }

    /// Build the signature preimage: `SIG_CONTEXT("manifest") ||
    /// canonical_cbor(unsigned_fields)`.
    fn signature_preimage(&self) -> ObjectResult<Vec<u8>> {
        let ctx =
            snp_crypto::sig_context(Self::SIG_CONTEXT_NAME).ok_or(ObjectError::InvalidProof)?;
        let cbor = snp_cbor::encode(&self.unsigned_cbor())?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// Sign the unsigned manifest fields with the publisher's secret key,
    /// producing the 64-byte Ed25519 signature.
    ///
    /// The signature is over `SIG_CONTEXT("manifest") || CBOR(fields 1-9)`
    /// (manifest.ts:147-148). The `signature` field is NOT part of the
    /// signed preimage.
    ///
    /// # Errors
    /// Returns `ObjectError::InvalidProof` if the manifest fails validation
    /// (so we never produce a signature over malformed input).
    pub fn sign(
        unsigned: &ManifestUnsigned,
        publisher_secret: &snp_crypto::SecretKey,
    ) -> ObjectResult<ManifestSignature> {
        let manifest_for_validation = Manifest {
            object_id: unsigned.object_id,
            chunks: unsigned.chunks.clone(),
            chunk_count: unsigned.chunk_count,
            total_bytes: unsigned.total_bytes,
            mime_type: unsigned.mime_type.clone(),
            class: unsigned.class.clone(),
            publisher_id: unsigned.publisher_id,
            published_at: unsigned.published_at,
            expires_at: unsigned.expires_at,
            signature: [0u8; 64],
        };
        manifest_for_validation.validate()?;
        let ctx =
            snp_crypto::sig_context(Self::SIG_CONTEXT_NAME).ok_or(ObjectError::InvalidProof)?;
        let cbor = snp_cbor::encode(&manifest_for_validation.unsigned_cbor())?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(snp_crypto::ed25519_sign(publisher_secret, &preimage))
    }

    /// Verify the manifest's signature against the publisher's public key.
    ///
    /// Re-derives the preimage and calls `ed25519_verify`. Returns `false` on
    /// any failure — bad signature, wrong key, malformed fields. NEVER throws
    /// for a bad signature (I20).
    ///
    /// Note: this verifies ONLY the signature. It does NOT check that
    /// `object_id == merkle_root(chunks)` — that is a content-integrity check
    /// performed separately (manifest.ts:181-186).
    #[must_use]
    pub fn verify(&self, publisher_pubkey: &snp_crypto::PublicKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        if self.validate().is_err() {
            return false;
        }
        let Ok(preimage) = self.signature_preimage() else {
            return false;
        };
        snp_crypto::ed25519_verify(publisher_pubkey, &preimage, &self.signature)
    }

    /// Validate the STRUCTURE of this manifest against the frozen CDDL.
    ///
    /// # Errors
    /// Returns `ObjectError` on any violation:
    /// - `objectId` not 32 bytes
    /// - `chunks` empty or any chunk not 32 bytes
    /// - `chunkCount` != `chunks.len()`
    /// - `totalBytes` negative (impossible for u64, but checks == 0 is fine)
    /// - `mimeType` empty
    /// - `class` not in `MANIFEST_CLASSES`
    /// - `publisherId` not 32 bytes
    /// - `publishedAt` ... (u64 is always non-negative)
    /// - `expiresAt` Some but <= `publishedAt`
    /// - `signature` not 64 bytes
    pub fn validate(&self) -> ObjectResult<()> {
        if self.object_id.len() != 32 {
            return Err(ObjectError::MissingChunk(
                "Manifest.objectId must be 32 bytes".into(),
            ));
        }
        if self.chunks.is_empty() {
            return Err(ObjectError::MissingChunk(
                "Manifest.chunks must be non-empty".into(),
            ));
        }
        for (i, c) in self.chunks.iter().enumerate() {
            if c.len() != 32 {
                return Err(ObjectError::MissingChunk(format!(
                    "Manifest.chunks[{i}] must be 32 bytes"
                )));
            }
        }
        if self.chunk_count != self.chunks.len() as u64 {
            return Err(ObjectError::MissingChunk(format!(
                "Manifest.chunkCount ({}) must equal chunks.len() ({})",
                self.chunk_count,
                self.chunks.len()
            )));
        }
        if self.mime_type.is_empty() {
            return Err(ObjectError::MissingChunk(
                "Manifest.mimeType must be non-empty".into(),
            ));
        }
        if !MANIFEST_CLASSES.contains(&self.class.as_str()) {
            return Err(ObjectError::MissingChunk(format!(
                "Manifest.class must be one of {:?}; got {:?}",
                MANIFEST_CLASSES, self.class
            )));
        }
        if self.publisher_id.len() != 32 {
            return Err(ObjectError::MissingChunk(
                "Manifest.publisherId must be 32 bytes".into(),
            ));
        }
        if let Some(exp) = self.expires_at {
            if exp <= self.published_at {
                return Err(ObjectError::MissingChunk(format!(
                    "Manifest.expiresAt ({}) must be strictly greater than publishedAt ({})",
                    exp, self.published_at
                )));
            }
        }
        if self.signature.len() != 64 {
            return Err(ObjectError::InvalidSignature);
        }
        Ok(())
    }

    /// Encode to canonical CBOR bytes (the wire format).
    ///
    /// Produces the 10-field map matching the TS `manifestToWireMap`
    /// (sync.ts:386-399). The `signature` field IS included (it's part of
    /// the wire format, even though it's not part of the signed preimage).
    ///
    /// # Errors
    /// Returns `ObjectError` if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> ObjectResult<Vec<u8>> {
        self.validate()?;
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!("unsigned_cbor returns a Map"),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        Ok(snp_cbor::encode(&CborValue::Map(entries))?)
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// STRUCTURAL ONLY — does NOT verify the signature (use `verify` for
    /// that). This preserves the separation: decode ≠ verify.
    ///
    /// # Errors
    /// Returns `ObjectError` if the bytes are not canonical CBOR, a field
    /// has the wrong type, or validation fails.
    pub fn decode_cbor(bytes: &[u8]) -> ObjectResult<Self> {
        let value = snp_cbor::decode(bytes)?;
        let entries = match &value {
            snp_cbor::CborValue::Map(e) => e,
            _ => {
                return Err(ObjectError::MissingChunk(
                    "Manifest must be a CBOR map".into(),
                ));
            }
        };
        let mut object_id: Option<ContentHash> = None;
        let mut chunks: Option<Vec<ContentHash>> = None;
        let mut chunk_count: Option<u64> = None;
        let mut total_bytes: Option<u64> = None;
        let mut mime_type: Option<String> = None;
        let mut class: Option<String> = None;
        let mut publisher_id: Option<[u8; 32]> = None;
        let mut published_at: Option<u64> = None;
        let mut expires_at: Option<Option<u64>> = None;
        let mut signature: Option<ManifestSignature> = None;
        for (k, v) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s.as_str(),
                _ => {
                    return Err(ObjectError::MissingChunk(
                        "Manifest map key must be text".into(),
                    ));
                }
            };
            match key {
                "objectId" => {
                    let b = expect_bstr(v, "Manifest.objectId")?;
                    object_id = Some(bytes_to_array_32(&b, "Manifest.objectId")?);
                }
                "chunks" => {
                    chunks = Some(decode_chunks_array(v)?);
                }
                "chunkCount" => {
                    chunk_count = Some(expect_uint(v, "Manifest.chunkCount")?);
                }
                "totalBytes" => {
                    total_bytes = Some(expect_uint(v, "Manifest.totalBytes")?);
                }
                "mimeType" => {
                    mime_type = Some(expect_tstr(v, "Manifest.mimeType")?);
                }
                "class" => {
                    class = Some(expect_tstr(v, "Manifest.class")?);
                }
                "publisherId" => {
                    let b = expect_bstr(v, "Manifest.publisherId")?;
                    publisher_id = Some(bytes_to_array_32(&b, "Manifest.publisherId")?);
                }
                "publishedAt" => {
                    published_at = Some(expect_uint(v, "Manifest.publishedAt")?);
                }
                "expiresAt" => match v {
                    snp_cbor::CborValue::Null => expires_at = Some(None),
                    _ => expires_at = Some(Some(expect_uint(v, "Manifest.expiresAt")?)),
                },
                "signature" => {
                    let b = expect_bstr(v, "Manifest.signature")?;
                    signature = Some(bytes_to_array_64(&b, "Manifest.signature")?);
                }
                _ => {
                    // Per §9: unknown keys in SIGNED structures MUST be rejected
                    // (they would break signature determinism). Manifest is
                    // signed, so we reject unknown keys.
                    return Err(ObjectError::MissingChunk(format!(
                        "unknown key '{key}' in Manifest (signed structure — must be rejected per §9)"
                    )));
                }
            }
        }
        let manifest = Self {
            object_id: object_id
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing objectId".into()))?,
            chunks: chunks
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing chunks".into()))?,
            chunk_count: chunk_count
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing chunkCount".into()))?,
            total_bytes: total_bytes
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing totalBytes".into()))?,
            mime_type: mime_type
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing mimeType".into()))?,
            class: class
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing class".into()))?,
            publisher_id: publisher_id
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing publisherId".into()))?,
            published_at: published_at
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing publishedAt".into()))?,
            expires_at: expires_at.unwrap_or(None),
            signature: signature
                .ok_or_else(|| ObjectError::MissingChunk("Manifest missing signature".into()))?,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

// ─── CBOR helpers for Manifest decode ─────────────────────────────────────

fn expect_bstr(v: &snp_cbor::CborValue, field: &str) -> ObjectResult<Vec<u8>> {
    match v {
        snp_cbor::CborValue::ByteString(b) => Ok(b.clone()),
        _ => Err(ObjectError::MissingChunk(format!(
            "{field} must be a byte string"
        ))),
    }
}

fn expect_uint(v: &snp_cbor::CborValue, field: &str) -> ObjectResult<u64> {
    match v {
        snp_cbor::CborValue::UnsignedInt(n) => Ok(*n),
        _ => Err(ObjectError::MissingChunk(format!(
            "{field} must be an unsigned int"
        ))),
    }
}

fn expect_tstr(v: &snp_cbor::CborValue, field: &str) -> ObjectResult<String> {
    match v {
        snp_cbor::CborValue::TextString(s) => Ok(s.clone()),
        _ => Err(ObjectError::MissingChunk(format!(
            "{field} must be a text string"
        ))),
    }
}

fn bytes_to_array_32(bytes: &[u8], field: &str) -> ObjectResult<[u8; 32]> {
    let mut arr = [0u8; 32];
    if bytes.len() != 32 {
        return Err(ObjectError::MissingChunk(format!(
            "{field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn bytes_to_array_64(bytes: &[u8], field: &str) -> ObjectResult<[u8; 64]> {
    let mut arr = [0u8; 64];
    if bytes.len() != 64 {
        return Err(ObjectError::MissingChunk(format!(
            "{field} must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn decode_chunks_array(v: &snp_cbor::CborValue) -> ObjectResult<Vec<ContentHash>> {
    let arr = match v {
        snp_cbor::CborValue::Array(a) => a,
        _ => {
            return Err(ObjectError::MissingChunk(
                "Manifest.chunks must be an array".into(),
            ));
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let b = expect_bstr(item, &format!("Manifest.chunks[{i}]"))?;
        out.push(bytes_to_array_32(&b, &format!("Manifest.chunks[{i}]"))?);
    }
    Ok(out)
}

/// A content-addressed store: SHA-256 key → content bytes.
///
/// The `put` method accepts [`ContentBytes`] (Class A), NOT raw `&[u8]`.
/// This prevents transit ciphertext from accidentally entering the
/// content cache — ciphertext types have no `as_bytes()` method.
pub trait Cas: Send + Sync {
    /// Insert content and return its SHA-256 key.
    fn put(&self, content: &ContentBytes) -> ObjectResult<ContentHash>;
    /// Fetch the bytes for `key`, if present.
    fn get(&self, key: &ContentHash) -> ObjectResult<Vec<u8>>;
    /// Returns true if `key` is present.
    fn has(&self, key: &ContentHash) -> bool;
}

/// An in-memory CAS (for tests and the daemon bootstrap). Skeleton stub.
pub struct InMemoryCas;

impl Cas for InMemoryCas {
    fn put(&self, _content: &ContentBytes) -> ObjectResult<ContentHash> {
        todo!("Implement in-memory CAS put")
    }
    fn get(&self, _key: &ContentHash) -> ObjectResult<Vec<u8>> {
        todo!("Implement in-memory CAS get")
    }
    fn has(&self, _key: &ContentHash) -> bool {
        todo!("Implement in-memory CAS has")
    }
}

/// Frozen chunking constants — changing these breaks every `ObjectId`.
///
/// Per `02-PROTOCOL-SPEC.md` §3.3 and §A (frozen parameters table):
/// - `MIN_CHUNK` = 256 KiB
/// - `TARGET_CHUNK` = 1 MiB (drives the 20-bit mask)
/// - `MAX_CHUNK` = 4 MiB
/// - Mask = 20 bits (0xFFFFF)
///
/// The original skeleton used 2/8/64 KiB which was incorrect; the committed
/// vectors (`04-chunking.json`) require the 256 KiB / 1 MiB / 4 MiB values.
pub mod chunk_constants {
    /// Minimum chunk size in bytes (256 KiB).
    pub const MIN_CHUNK: usize = 256 * 1024;
    /// Target average chunk size in bytes (1 MiB). Drives the 20-bit mask.
    pub const TARGET_CHUNK: usize = 1024 * 1024;
    /// Maximum chunk size in bytes (4 MiB). Hard ceiling — never exceeded.
    pub const MAX_CHUNK: usize = 4 * 1024 * 1024;
    /// Gear CDC boundary mask (20 bits).
    pub const MASK: u32 = 0xFFFFF;
    /// Gear CDC rolling-hash window (informational; not used by the algorithm
    /// — Gear is a one-byte rolling hash, not a windowed one).
    pub const GEAR_WINDOW: usize = 1;
}

// === RFC 6962 Merkle trees ===

/// Compute the Merkle leaf hash for a single chunk: `SHA-256(0x00 || chunk)`.
#[must_use]
pub fn leaf_hash(chunk: &[u8]) -> ContentHash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(chunk);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the Merkle internal hash for two children:
/// `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the Merkle root of an empty leaf set:
/// `SHA-256("SNP/0.1 empty\0")`.
#[must_use]
pub fn empty_root() -> ContentHash {
    snp_crypto::empty_merkle_root()
}

/// Compute the Merkle root of a list of leaf hashes using RFC 6962's split
/// rule: split at the largest power of two less than `n`, never duplicate.
///
/// - 0 leaves → [`empty_root`]
/// - 1 leaf → that leaf's hash (no `node_hash` wrap; the leaf IS the root)
/// - n ≥ 2 → split at `k = largest power of 2 < n`, root = `node_hash(MT(left)`, MT(right))
#[must_use]
pub fn merkle_root(leaf_hashes: &[ContentHash]) -> ContentHash {
    match leaf_hashes.len() {
        0 => empty_root(),
        1 => leaf_hashes[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = merkle_root(&leaf_hashes[..k]);
            let right = merkle_root(&leaf_hashes[k..]);
            node_hash(&left, &right)
        }
    }
}

/// Compute the Merkle root of a list of raw chunks (convenience: hashes each
/// chunk first, then calls [`merkle_root`]).
#[must_use]
pub fn merkle_root_from_chunks(chunks: &[Vec<u8>]) -> ContentHash {
    let leaves: Vec<ContentHash> = chunks.iter().map(|c| leaf_hash(c)).collect();
    merkle_root(&leaves)
}

/// The largest power of two strictly less than `n` (for n ≥ 2).
/// For n = 2 → 1, n = 3 → 2, n = 4 → 2, n = 5 → 4, n = 8 → 4, n = 9 → 8, …
fn largest_power_of_two_less_than(n: usize) -> usize {
    assert!(n >= 2);
    // Highest set bit position of (n-1), then 2^pos.
    // e.g. n=5 → n-1=4=0b100 → pos=2 → 2^2 = 4. ✓
    // e.g. n=4 → n-1=3=0b011 → pos=1 → 2^1 = 2. ✓
    // e.g. n=8 → n-1=7=0b111 → pos=2 → 2^2 = 4. ✓
    let m = n - 1;
    1 << m.ilog2()
}

/// Whether a sibling sits to the left or right of the path node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is on the left.
    Left,
    /// Sibling is on the right.
    Right,
}

/// A Merkle inclusion proof (list of sibling hashes, leaf-to-root order).
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes, in order from leaf to root.
    pub siblings: Vec<(Side, ContentHash)>,
}

/// Build a Merkle inclusion proof for the leaf at `index`.
///
/// # Errors
/// Returns [`ObjectError::InvalidProof`] if `index` is out of bounds.
pub fn merkle_proof(leaf_hashes: &[ContentHash], index: usize) -> ObjectResult<MerkleProof> {
    if index >= leaf_hashes.len() {
        return Err(ObjectError::InvalidProof);
    }
    let mut siblings = Vec::new();
    build_proof(leaf_hashes, index, &mut siblings);
    Ok(MerkleProof { siblings })
}

fn build_proof(level: &[ContentHash], idx: usize, siblings: &mut Vec<(Side, ContentHash)>) {
    if level.len() <= 1 {
        return;
    }
    let k = largest_power_of_two_less_than(level.len());
    if idx < k {
        // Leaf is in the left subtree; sibling is the right subtree's root.
        // Push siblings in leaf-to-root order: recurse first, then push.
        build_proof(&level[..k], idx, siblings);
        let right = merkle_root(&level[k..]);
        siblings.push((Side::Right, right));
    } else {
        build_proof(&level[k..], idx - k, siblings);
        let left = merkle_root(&level[..k]);
        siblings.push((Side::Left, left));
    }
}

/// Verify a Merkle inclusion proof against a known root.
///
/// Walks the proof leaf-to-root, hashing the running value with each sibling
/// (using the recorded `Side` to determine hash argument order), and compares
/// the final value to `root`.
pub fn merkle_verify(
    root: &ContentHash,
    leaf: &ContentHash,
    proof: &MerkleProof,
) -> ObjectResult<()> {
    let mut running = *leaf;
    for (side, sibling) in &proof.siblings {
        running = match side {
            Side::Left => node_hash(sibling, &running),
            Side::Right => node_hash(&running, sibling),
        };
    }
    if &running == root {
        Ok(())
    } else {
        Err(ObjectError::InvalidProof)
    }
}

// === Gear CDC chunking ===

/// Build the 256-entry Gear table using `splitmix64` seeded at 0, taking the
/// low 32 bits of each output. Frozen (I6).
///
/// The first four entries are `[0x7b1dcdaf, 0xa1b965f4, 0x8009454f, 0x724c81ec]`
/// (decimal `[2065550767, 2713282036, 2148091215, 1917616620]`), matching the
/// committed `gear-table-first4` vector.
#[must_use]
pub fn build_gear_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut state: u64 = 0;
    for entry in &mut table {
        let z = splitmix64_next(&mut state);
        *entry = (z & 0xFFFF_FFFF) as u32;
    }
    table
}

/// One step of Sebastiano Vigna's splitmix64: advance `state` in place by
/// adding the golden-ratio delta, mix the new state, return the output.
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Compute Gear CDC chunk boundaries for `data`. Returns a list of byte
/// offsets (each = the cumulative end position of a chunk).
///
/// Algorithm:
/// 1. If `data` is empty, return `[]`.
/// 2. Walk the data with a Gear rolling hash `h = ((h << 1) + GEAR[byte]) & MASK_ALL`.
/// 3. After `MIN_CHUNK` bytes, if `(h & MASK) == 0`, emit a boundary.
/// 4. If a chunk reaches `MAX_CHUNK` bytes, emit a boundary unconditionally.
/// 5. At end of input, emit the final boundary (the total length).
#[must_use]
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let n = data.len();
    if n == 0 {
        return Vec::new();
    }
    let gear = build_gear_table();
    let min = chunk_constants::MIN_CHUNK;
    let max = chunk_constants::MAX_CHUNK;
    let mask = chunk_constants::MASK;
    let mask_64 = u64::from(mask);

    let mut boundaries = Vec::new();
    let mut start = 0usize;
    while start < n {
        let mut h: u64 = 0;
        let mut chunk_size: usize = 0;
        // Determine end of this chunk.
        for &b in &data[start..] {
            h = h.wrapping_shl(1).wrapping_add(u64::from(gear[b as usize]));
            chunk_size += 1;
            if chunk_size >= min && (h & mask_64) == 0 {
                break;
            }
            if chunk_size >= max {
                break;
            }
        }
        start += chunk_size;
        boundaries.push(start);
    }
    boundaries
}

/// Split `data` into chunks using Gear CDC. Returns the chunk byte vectors in
/// order. The Merkle root over `leaf_hash(chunk)` for each chunk is the
/// `ObjectId` of the resulting object.
#[must_use]
pub fn chunk(data: &[u8]) -> Vec<Vec<u8>> {
    let boundaries = chunk_boundaries(data);
    let mut out = Vec::with_capacity(boundaries.len());
    let mut prev = 0usize;
    for end in boundaries {
        out.push(data[prev..end].to_vec());
        prev = end;
    }
    out
}

#[cfg(test)]
mod tests {

    // ─── ContentBytes tests (R3) ─────────────────────────────────────────

    #[test]
    fn content_bytes_exposes_inner_for_cas() {
        let cb = ContentBytes::new(vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(cb.as_bytes(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(cb.len(), 3);
        assert!(!cb.is_empty());
    }

    #[test]
    fn content_bytes_from_vec() {
        let cb = ContentBytes::from(vec![1, 2, 3]);
        assert_eq!(cb.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn content_bytes_from_slice() {
        let cb = ContentBytes::from(&[1, 2, 3][..]);
        assert_eq!(cb.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn content_bytes_into_bytes() {
        let cb = ContentBytes::new(vec![4, 5, 6]);
        let raw = cb.into_bytes();
        assert_eq!(raw, vec![4, 5, 6]);
    }

    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn gear_table_first4() {
        let table = build_gear_table();
        assert_eq!(table[0], 2_065_550_767, "gear[0]");
        assert_eq!(table[1], 2_713_282_036, "gear[1]");
        assert_eq!(table[2], 2_148_091_215, "gear[2]");
        assert_eq!(table[3], 1_917_616_620, "gear[3]");
    }

    #[test]
    fn chunk_empty_input() {
        assert_eq!(chunk_boundaries(b""), Vec::<usize>::new());
    }

    #[test]
    fn chunk_single_byte() {
        assert_eq!(chunk_boundaries(&[0x41]), vec![1]);
    }

    #[test]
    fn chunk_below_min_is_one_chunk() {
        // MIN-1 bytes -> 1 chunk
        let data = vec![0u8; chunk_constants::MIN_CHUNK - 1];
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![data.len()]);
    }

    #[test]
    fn merkle_1_leaf_matches_leaf_hash() {
        let leaf = hex_to_bytes("010203");
        let lh = leaf_hash(&leaf);
        let root = merkle_root(&[lh]);
        assert_eq!(to_hex(&root), to_hex(&lh));
    }

    #[test]
    fn merkle_2_leaves() {
        let l1 = leaf_hash(&hex_to_bytes("01"));
        let l2 = leaf_hash(&hex_to_bytes("02"));
        let root = merkle_root(&[l1, l2]);
        assert_eq!(
            to_hex(&root),
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965"
        );
    }

    #[test]
    fn merkle_3_leaves_no_duplication() {
        let leaves: Vec<ContentHash> = ["01", "02", "03"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "e2da0242936eb38ec996a543601b3a1da4226391ff92014ed1a7a248ace36347"
        );
    }

    #[test]
    fn merkle_5_leaves() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "b2165c86fbfb34fa51840bb6ba3d5ce0d7dc31f2e605b5ba62c98fa86ff6746d"
        );
    }

    #[test]
    fn merkle_8_leaves_balanced() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05", "06", "07", "08"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        assert_eq!(
            to_hex(&root),
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071"
        );
    }

    #[test]
    fn merkle_empty_root() {
        let r = empty_root();
        assert_eq!(
            to_hex(&r),
            "8b8f6a4bed03dd03c795484fb1354b67e707ae7f4e8587b03ee10341d299cc8b"
        );
    }

    #[test]
    fn merkle_5_leaves_proof_index_0_round_trips() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).unwrap();
        assert_eq!(proof.siblings.len(), 3);
        merkle_verify(&root, &leaves[0], &proof).unwrap();
    }

    #[test]
    fn merkle_5_leaves_proof_index_4_round_trips() {
        let leaves: Vec<ContentHash> = ["01", "02", "03", "04", "05"]
            .iter()
            .map(|h| leaf_hash(&hex_to_bytes(h)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 4).unwrap();
        assert_eq!(proof.siblings.len(), 1);
        assert!(matches!(proof.siblings[0].0, Side::Left));
        merkle_verify(&root, &leaves[4], &proof).unwrap();
    }

    /// Deterministic data generator used by the committed chunking vectors.
    /// The 04-chunking.json vectors use `seed` as an integer seed for
    /// splitmix64, generating 8 bytes per call (little-endian). This was
    /// derived independently (see worklog Task 52-60) by matching the
    /// committed boundary values; the PRNG choice is part of the vector,
    /// not part of the SNP spec.
    fn deterministic_data(seed: u64, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut state = seed;
        while out.len() < n {
            let z = splitmix64_next(&mut state);
            for &b in &z.to_le_bytes() {
                if out.len() >= n {
                    break;
                }
                out.push(b);
            }
        }
        out
    }

    #[test]
    fn chunk_5mb_deterministic_seed7() {
        let data = deterministic_data(7, 5_242_880);
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![4_194_304, 4_803_239, 5_242_880]);
    }

    #[test]
    fn chunk_max_plus_1_seed99() {
        let data = deterministic_data(99, 4_195_328);
        let b = chunk_boundaries(&data);
        assert_eq!(b, vec![1_692_137, 3_593_855, 4_195_328]);
    }

    // ─── R4.2 interop: Manifest codec tests ──────────────────────────────────

    fn test_keypair(seed: u8) -> (snp_crypto::SecretKey, snp_crypto::PublicKey) {
        let secret = [seed; 32];
        let public = snp_crypto::derive_public_key(&secret);
        (secret, public)
    }

    fn test_manifest_unsigned() -> ManifestUnsigned {
        ManifestUnsigned {
            object_id: [0x42; 32],
            chunks: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
            chunk_count: 3,
            total_bytes: 1024,
            mime_type: "application/octet-stream".into(),
            class: "content".into(),
            publisher_id: [0xAA; 32],
            published_at: 1_000,
            expires_at: Some(10_000),
        }
    }

    fn build_manifest(unsigned: &ManifestUnsigned, secret: &snp_crypto::SecretKey) -> Manifest {
        let sig = Manifest::sign(unsigned, secret).expect("sign");
        Manifest {
            signature: sig,
            ..Manifest {
                object_id: unsigned.object_id,
                chunks: unsigned.chunks.clone(),
                chunk_count: unsigned.chunk_count,
                total_bytes: unsigned.total_bytes,
                mime_type: unsigned.mime_type.clone(),
                class: unsigned.class.clone(),
                publisher_id: unsigned.publisher_id,
                published_at: unsigned.published_at,
                expires_at: unsigned.expires_at,
                signature: [0u8; 64],
            }
        }
    }

    #[test]
    fn manifest_roundtrip() {
        let (secret, pubkey) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let manifest = build_manifest(&unsigned, &secret);
        let bytes = manifest.encode_cbor().expect("encode");
        let decoded = Manifest::decode_cbor(&bytes).expect("decode");
        assert_eq!(manifest, decoded);
        assert!(manifest.verify(&pubkey), "signature must verify");
    }

    #[test]
    fn manifest_encode_decode_reencode_identical() {
        let (secret, _) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let manifest = build_manifest(&unsigned, &secret);
        let bytes1 = manifest.encode_cbor().expect("encode 1");
        let decoded = Manifest::decode_cbor(&bytes1).expect("decode");
        let bytes2 = decoded.encode_cbor().expect("encode 2");
        assert_eq!(bytes1, bytes2, "encode→decode→re-encode must be identical");
    }

    #[test]
    fn manifest_tampered_signature_rejected() {
        let (secret, pubkey) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let mut manifest = build_manifest(&unsigned, &secret);
        manifest.signature[0] ^= 0xFF;
        assert!(
            !manifest.verify(&pubkey),
            "tampered signature must NOT verify"
        );
    }

    #[test]
    fn manifest_tampered_field_rejected() {
        let (secret, pubkey) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let mut manifest = build_manifest(&unsigned, &secret);
        // Tamper a signed field (total_bytes).
        manifest.total_bytes = 999_999;
        assert!(!manifest.verify(&pubkey), "tampered field must NOT verify");
    }

    #[test]
    fn manifest_chunk_count_mismatch_rejected() {
        let (secret, _) = test_keypair(0x99);
        let mut unsigned = test_manifest_unsigned();
        unsigned.chunk_count = 99; // wrong!
        let result = Manifest::sign(&unsigned, &secret);
        assert!(
            result.is_err(),
            "chunkCount mismatch must be rejected at sign time"
        );
    }

    #[test]
    fn manifest_invalid_class_rejected() {
        let (secret, _) = test_keypair(0x99);
        let mut unsigned = test_manifest_unsigned();
        unsigned.class = "invalid-class".into();
        let result = Manifest::sign(&unsigned, &secret);
        assert!(result.is_err(), "invalid class must be rejected");
    }

    #[test]
    fn manifest_unknown_key_rejected() {
        let (secret, _) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let manifest = build_manifest(&unsigned, &secret);
        let bytes = manifest.encode_cbor().expect("encode");
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            entries.push((
                CborValue::TextString("unknownKey".into()),
                CborValue::UnsignedInt(99),
            ));
        }
        let tampered = encode(&value).expect("re-encode");
        let result = Manifest::decode_cbor(&tampered);
        assert!(
            result.is_err(),
            "unknown key in signed structure must be rejected"
        );
    }

    #[test]
    fn manifest_missing_field_rejected() {
        let (secret, _) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let manifest = build_manifest(&unsigned, &secret);
        // Encode without the signature field.
        let unsigned_value = manifest.unsigned_cbor();
        let bytes = snp_cbor::encode(&unsigned_value).expect("encode without sig");
        let result = Manifest::decode_cbor(&bytes);
        assert!(result.is_err(), "missing signature must be rejected");
    }

    #[test]
    fn manifest_wrong_object_id_length_rejected() {
        // object_id is ContentHash = [u8; 32] by type, so we can't construct
        // a wrong-length one directly. Instead, we test that decode_cbor
        // rejects a wrong-length objectId on the wire.
        let (secret, _) = test_keypair(0x99);
        let unsigned = test_manifest_unsigned();
        let manifest = build_manifest(&unsigned, &secret);
        let bytes = manifest.encode_cbor().expect("encode");
        // Tamper: replace the 32-byte objectId with a 16-byte one.
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            for (k, v) in entries.iter_mut() {
                if let CborValue::TextString(s) = k {
                    if s == "objectId" {
                        *v = CborValue::ByteString(vec![0x42; 16]);
                    }
                }
            }
        }
        let tampered = encode(&value).expect("re-encode");
        let result = Manifest::decode_cbor(&tampered);
        assert!(
            result.is_err(),
            "wrong objectId length must be rejected on decode"
        );
    }

    #[test]
    fn manifest_expires_at_null_roundtrip() {
        let (secret, pubkey) = test_keypair(0x99);
        let mut unsigned = test_manifest_unsigned();
        unsigned.expires_at = None; // no expiry
        let manifest = build_manifest(&unsigned, &secret);
        let bytes = manifest.encode_cbor().expect("encode");
        let decoded = Manifest::decode_cbor(&bytes).expect("decode");
        assert_eq!(manifest, decoded);
        assert!(manifest.verify(&pubkey));
        assert_eq!(decoded.expires_at, None);
    }
}

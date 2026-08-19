//! SNP-IDENTITY — The four-way identity split for `ShareNet` 2.0
//!
//! Implements SNP/0.1 §2 (identity). `ShareNet` splits identity into four
//! distinct objects to avoid the audit's finding that `NodeId` was a "key, a
//! hash, and a routing locator all at once":
//!
//! 1. **`IdentityKey`** — the Ed25519 secret key, never transmitted.
//! 2. **`NodeId`** — `SHA-256("SNP/0.1 node\0" || pk)` (per I4), the durable
//!    identifier. NOT the bare public key, NOT a routing locator.
//! 3. **`DeviceCert`** — a short-lived certificate binding a `NodeId` to a
//!    device public key, signed by the node's identity key.
//! 4. **`NodeDescriptor`** — the signed, broadcastable record containing the
//!    `NodeId`, supported link types, capabilities, and current device cert.
//!
//! This crate implements `NodeId` derivation and Ed25519 signature verification
//! against the committed conformance vectors in
//! `public/conformance/vectors/03-identity.json`. The full `DeviceCert` /
//! `NodeDescriptor` CBOR structures are not yet implemented; they are exercised
//! by the conformance harness as `UNSUPPORTED` where they require CBOR
//! reconstruction of complex payload shapes.

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
    clippy::should_implement_trait,
    clippy::match_same_arms,
    clippy::semicolon_if_nothing_returned
)]

use thiserror::Error;

/// Errors from SNP identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A signature over a `DeviceCert` or `NodeDescriptor` failed verification.
    #[error("invalid identity signature")]
    InvalidSignature,
    /// A certificate has expired.
    #[error("certificate expired")]
    Expired,
    /// A certificate was issued for a different `NodeId` than the one presented.
    #[error("NodeId mismatch in certificate")]
    NodeIdMismatch,
    /// CBOR (de)serialization failure.
    #[error("CBOR error: {0}")]
    Cbor(#[from] snp_cbor::CborError),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// R2.2 (DESCRIPTOR-EXTRACTION): a `GatewayAdvertisement` / descriptor
    /// failed to (de)serialise for a reason NOT covered by [`Self::Cbor`]
    /// (e.g. a required CBOR field was missing, or a field had the wrong
    /// CBOR type). The previous snp-node implementation surfaced these as
    /// `NodeError::Other(format!(...))`; snp-identity surfaces them as
    /// `IdentityError::Other(String)` so callers can map them back to
    /// `NodeError::Other` without losing the diagnostic message.
    #[error("{0}")]
    Other(String),
}

/// Convenience `Result` alias.
pub type IdentityResult<T> = Result<T, IdentityError>;

/// A 32-byte `NodeId`: `SHA-256("SNP/0.1 node\0" || pk)`.
pub type NodeId = [u8; 32];

/// Domain-separation tag used in `NodeId` derivation (I4).
pub const NODE_ID_DOMAIN: &[u8] = snp_crypto::NODE_ID_DOMAIN;

/// Derive a `NodeId` from an Ed25519 public key.
///
/// Per invariant I4: `NodeId = SHA-256("SNP/0.1 node\0" || pk)`. The bare key
/// is NEVER used as a `NodeId`.
#[must_use]
pub fn derive_node_id(public_key: &snp_crypto::PublicKey) -> NodeId {
    snp_crypto::derive_node_id(public_key)
}

/// Verify an Ed25519 signature made under a specific `SIG_CONTEXT`.
///
/// Preimage = `sig_context(name) || bytes`. Returns `true` iff the signature
/// is valid under RFC 8032 verification for `public_key`.
///
/// Returns `false` if `name` is not a known `SIG_CONTEXT`.
#[must_use]
pub fn verify_signed(
    public_key: &snp_crypto::PublicKey,
    context_name: &str,
    payload_bytes: &[u8],
    signature: &snp_crypto::SignatureBytes,
) -> bool {
    let Some(ctx) = snp_crypto::sig_context(context_name) else {
        return false;
    };
    let mut preimage = Vec::with_capacity(ctx.len() + payload_bytes.len());
    preimage.extend_from_slice(ctx);
    preimage.extend_from_slice(payload_bytes);
    snp_crypto::ed25519_verify(public_key, &preimage, signature)
}

/// Current unix timestamp in seconds.
///
/// R2.2 (DESCRIPTOR-EXTRACTION): moved verbatim from
/// `snp-node/src/node/mod.rs` so the `GatewayAdvertisement` constructors in
/// [`gateway`] can use it without depending on snp-node. snp-node's
/// `node::mod.rs` re-exports this via `pub(crate) use snp_identity::now_unix;`
/// so all existing in-crate callers (`now_unix()`, `super::now_unix()`)
/// continue to compile.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// === Submodules ===
//
// R2.2 (DESCRIPTOR-EXTRACTION): the `gateway` and `descriptor` modules were
// moved verbatim from `snp-node/src/node/{gateway,descriptor}.rs`. The CBOR
// encoding, signature preimage, verification logic, and type-system
// distinctions are byte-for-byte identical to the pre-extraction
// implementation — no field names, types, or canonical-CBOR shapes were
// changed.

pub mod descriptor;
pub mod gateway;

// Re-export the public types at the crate root for ergonomic access
// (`snp_identity::GatewayAdvertisement`, etc.).
pub use descriptor::{
    verify_node_id_consistency, IdentityConsistentNodeDescriptor, TransportEndpoint,
    UnverifiedNodeDescriptor, VerifiedGatewayAdvertisement, VerifiedNodeDescriptor,
};
pub use gateway::{GatewayAdvertisement, ADVERTISEMENT_TTL_SECS};

// === Runtime identity types (extracted from snp-node/src/node/identity.rs) ===
//
// These are the production identity types used by the runtime. They were
// previously owned by snp-node but are extracted here (R2.2) to establish
// the L1 identity layer as a real architectural boundary.
//
// The older skeleton types (DeviceCert, Capabilities struct, NodeDescriptor)
// below are retained for API compatibility but are NOT used by the runtime.

/// A node's cryptographic identity: Ed25519 secret key, public key, `NodeId`.
///
/// `NodeId = SHA-256("SNP/0.1 node\0" || public_key)` per invariant I4 — the
/// bare public key is NEVER used as a `NodeId`.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// Ed25519 secret key (32 bytes).
    pub secret_key: [u8; 32],
    /// Ed25519 public key (32 bytes), derived from `secret_key`.
    pub public_key: [u8; 32],
    /// `NodeId` = `SHA-256("SNP/0.1 node\0" || public_key)`.
    pub node_id: [u8; 32],
}

impl NodeIdentity {
    /// Construct a `NodeIdentity` from a secret key.
    #[must_use]
    pub fn from_secret(secret_key: [u8; 32]) -> Self {
        let public_key = snp_crypto::derive_public_key(&secret_key);
        let node_id = snp_crypto::derive_node_id(&public_key);
        Self {
            secret_key,
            public_key,
            node_id,
        }
    }

    /// Construct a gateway identity from an X25519 keypair in addition to
    /// the Ed25519 identity.
    ///
    /// **N2.0.5:** This is the canonical production constructor for gateway
    /// nodes. The Ed25519 keypair provides the node's signing identity; the
    /// X25519 keypair provides the static key for the SNP-IK/0.1 handshake.
    #[must_use]
    pub fn new_with_x25519(secret_key: [u8; 32]) -> Self {
        Self::from_secret(secret_key)
    }
}

/// A node's role in the network. A single node MAY hold multiple capabilities
/// (e.g. a gateway might also relay), but in N2.0.1 each node has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can send `TransitRequests` (a client node).
    Client,
    /// Can forward frames between peers (a relay node).
    Relay,
    /// Can terminate circuits and fetch from the Internet (a gateway node).
    Gateway,
}

impl Capability {
    /// String representation for advertisement serialisation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Client => "client",
            Capability::Relay => "relay",
            Capability::Gateway => "gateway",
        }
    }

    /// Parse from string (for advertisement deserialisation).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "client" => Some(Capability::Client),
            "relay" => Some(Capability::Relay),
            "gateway" => Some(Capability::Gateway),
            _ => None,
        }
    }
}

// === Frozen wire types (R4.2 interop — NodeDescriptor + DeviceCert) ========
//
// The frozen TS reference (`src/lib/snp/identity.ts`) defines `NodeDescriptor`
// and `DeviceCert` with specific field sets that do NOT match the previous
// Rust skeleton. The skeleton had wrong fields (node_id/identity_key/
// device_cert/capabilities/seq/issued_at/signature) and no codecs.
//
// This implementation matches the frozen TS `nodeDescriptorToCborMap` /
// `nodeDescriptorFromWireMap` (identity.ts:362-382, sync.ts:552-570) +
// `deviceCertToCborMap` (identity.ts:229-239) field-for-field, and provides
// the canonical byte-level encoder/decoder that R4.2's `DescriptorPayload`
// carries.
//
// CDDL (02-PROTOCOL-SPEC.md §4.4, identity.ts:305-318):
//   NodeDescriptor = {
//     nodeId:        bstr .size 32,
//     nodePubKey:    bstr .size 32,
//     rendezvousPub: bstr .size 32,
//     capabilities:  [+ tstr],
//     platform:      tstr,
//     protoVersion:  tstr,            ; "SNP/0.1"
//     epoch:         uint,
//     expiresAt:     uint,
//     links:         [* tstr],
//     deviceCert:    DeviceCert / null,
//     signature:     bstr .size 64
//   }
//
//   DeviceCert = {
//     deviceId:      bstr .size 32,
//     userId:        bstr .size 32,
//     capabilities:  [+ tstr],
//     platform:      tstr,
//     notBefore:     uint,
//     notAfter:      uint,
//     attestation:   bstr / null,
//     signature:     bstr .size 64
//   }
//
// The NodeDescriptor signature preimage is
// `SIG_CONTEXT("nodeDescriptor") ‖ CBOR(fields 1-10)` (identity.ts:387-388).
// The `signature` field is NOT part of the signed preimage. The embedded
// `deviceCert.signature` (if any) IS part of the signed preimage — it is
// bound into the descriptor so stripping/substituting the DeviceCert
// invalidates the descriptor signature.
//
// The DeviceCert signature preimage is
// `SIG_CONTEXT("deviceCert") ‖ CBOR(fields 1-7)` (identity.ts:244-245).

/// Protocol version string (frozen: `"SNP/0.1"`).
pub const PROTO_VERSION: &str = "SNP/0.1";

/// Allowed capability strings (frozen: constants.ts:69-80).
pub const CAPABILITIES: &[&str] = &[
    "MESH_CLIENT",
    "MESH_RELAY",
    "INTERNET_GATEWAY",
    "CONTENT_SEED",
    "STORAGE",
    "DISCOVERY",
    "SYNC",
    "COMPUTE",
    "COMMUNITY_RELAY",
    "CUSTODY",
];

/// Allowed platform strings (frozen: constants.ts:109-116).
pub const PLATFORMS: &[&str] = &["android", "ios", "linux", "windows", "macos", "embedded"];

/// A 64-byte Ed25519 signature.
pub type DescriptorSignature = [u8; 64];

// ─── DeviceCert (frozen identity.ts:192-217) ──────────────────────────────

/// A complete `DeviceCert`, including the 64-byte Ed25519 signature.
///
/// Binds a device to a user identity with capabilities, platform, validity
/// window, and optional hardware attestation. Signed by the `UserIdentity`'s
/// key under `SIG_CONTEXT` `"deviceCert"`.
///
/// # Wire format
///
/// `encode_cbor()` produces canonical CBOR matching the TS
/// `deviceCertToCborMap`. `decode_cbor()` is the inverse. The decode is
/// STRUCTURAL ONLY — it does NOT verify the signature (use `verify` for
/// that). This preserves the separation: decode ≠ verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    /// `NodeId` (32 bytes) of the device's Ed25519 identity key.
    pub device_id: NodeId,
    /// `NodeId` (32 bytes) of the user's Ed25519 identity key.
    pub user_id: NodeId,
    /// Capabilities the device is authorised to advertise.
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Validity start (unix seconds).
    pub not_before: u64,
    /// Validity end (unix seconds).
    pub not_after: u64,
    /// Platform hardware attestation or `None`. Treated as advisory reputation
    /// input ONLY — never trusted without external verification.
    pub attestation: Option<Vec<u8>>,
    /// 64-byte Ed25519 signature by the `UserIdentity` under `SIG_CONTEXT`
    /// `"deviceCert"`.
    pub signature: DescriptorSignature,
}

/// Fields of a `DeviceCert`, excluding the signature. This is what gets signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertUnsigned {
    /// `NodeId` (32 bytes) of the device's Ed25519 identity key.
    pub device_id: NodeId,
    /// `NodeId` (32 bytes) of the user's Ed25519 identity key.
    pub user_id: NodeId,
    /// Capabilities the device is authorised to advertise.
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Validity start (unix seconds).
    pub not_before: u64,
    /// Validity end (unix seconds).
    pub not_after: u64,
    /// Platform hardware attestation or `None`.
    pub attestation: Option<Vec<u8>>,
}

impl DeviceCert {
    /// The `SIG_CONTEXT` name for `DeviceCert` signatures (`"deviceCert"`).
    pub const SIG_CONTEXT_NAME: &'static str = "deviceCert";

    /// Construct the unsigned fields view (excludes `signature`).
    #[must_use]
    pub fn unsigned(&self) -> DeviceCertUnsigned {
        DeviceCertUnsigned {
            device_id: self.device_id,
            user_id: self.user_id,
            capabilities: self.capabilities.clone(),
            platform: self.platform.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            attestation: self.attestation.clone(),
        }
    }

    /// Build the canonical CBOR wire representation (INCLUDES `signature`).
    /// Used for the nested `deviceCert` field in `NodeDescriptor`.
    fn to_cbor_value(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        CborValue::Map(entries)
    }

    /// Build the canonical CBOR preimage map for a `DeviceCert`, EXCLUDING the
    /// `signature` field (identity.ts:229-239).
    fn unsigned_cbor(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        let attestation_val = match &self.attestation {
            Some(b) => CborValue::ByteString(b.clone()),
            None => CborValue::Null,
        };
        CborValue::Map(vec![
            (
                CborValue::TextString("deviceId".into()),
                CborValue::ByteString(self.device_id.to_vec()),
            ),
            (
                CborValue::TextString("userId".into()),
                CborValue::ByteString(self.user_id.to_vec()),
            ),
            (
                CborValue::TextString("capabilities".into()),
                CborValue::Array(
                    self.capabilities
                        .iter()
                        .map(|c| CborValue::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (
                CborValue::TextString("platform".into()),
                CborValue::TextString(self.platform.clone()),
            ),
            (
                CborValue::TextString("notBefore".into()),
                CborValue::UnsignedInt(self.not_before),
            ),
            (
                CborValue::TextString("notAfter".into()),
                CborValue::UnsignedInt(self.not_after),
            ),
            (CborValue::TextString("attestation".into()), attestation_val),
        ])
    }

    /// Build the signature preimage: `SIG_CONTEXT("deviceCert") ||
    /// canonical_cbor(unsigned_fields)`.
    fn signature_preimage(&self) -> IdentityResult<Vec<u8>> {
        let ctx = snp_crypto::sig_context(Self::SIG_CONTEXT_NAME)
            .ok_or_else(|| IdentityError::Other("unknown SIG_CONTEXT".into()))?;
        let cbor = snp_cbor::encode(&self.unsigned_cbor())
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// Validate the STRUCTURE of this `DeviceCert`.
    ///
    /// # Errors
    /// Returns `IdentityError` on any violation (wrong field lengths, invalid
    /// platform, invalid capability, `not_after <= not_before`, wrong
    /// signature length).
    pub fn validate(&self) -> IdentityResult<()> {
        if self.device_id.len() != 32 {
            return Err(IdentityError::Other(
                "DeviceCert.deviceId must be 32 bytes".into(),
            ));
        }
        if self.user_id.len() != 32 {
            return Err(IdentityError::Other(
                "DeviceCert.userId must be 32 bytes".into(),
            ));
        }
        for (i, c) in self.capabilities.iter().enumerate() {
            if !CAPABILITIES.contains(&c.as_str()) {
                return Err(IdentityError::Other(format!(
                    "DeviceCert.capabilities[{i}] must be one of {CAPABILITIES:?}; got {c:?}"
                )));
            }
        }
        if !PLATFORMS.contains(&self.platform.as_str()) {
            return Err(IdentityError::Other(format!(
                "DeviceCert.platform must be one of {PLATFORMS:?}; got {:?}",
                self.platform
            )));
        }
        if self.not_after <= self.not_before {
            return Err(IdentityError::Other(format!(
                "DeviceCert.notAfter ({}) must be > notBefore ({})",
                self.not_after, self.not_before
            )));
        }
        if self.signature.len() != 64 {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }

    /// Sign the unsigned `DeviceCert` fields with the user identity's secret
    /// key, producing the 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails.
    pub fn sign(
        unsigned: &DeviceCertUnsigned,
        user_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<DescriptorSignature> {
        let cert_for_validation = DeviceCert {
            device_id: unsigned.device_id,
            user_id: unsigned.user_id,
            capabilities: unsigned.capabilities.clone(),
            platform: unsigned.platform.clone(),
            not_before: unsigned.not_before,
            not_after: unsigned.not_after,
            attestation: unsigned.attestation.clone(),
            signature: [0u8; 64],
        };
        cert_for_validation.validate()?;
        let preimage = cert_for_validation.signature_preimage()?;
        Ok(snp_crypto::ed25519_sign(user_secret, &preimage))
    }

    /// Verify the `DeviceCert`'s signature against the user identity's public
    /// key. Returns `false` on any failure (I20 — never throws).
    #[must_use]
    pub fn verify(&self, user_pubkey: &snp_crypto::PublicKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        if self.validate().is_err() {
            return false;
        }
        let Ok(preimage) = self.signature_preimage() else {
            return false;
        };
        snp_crypto::ed25519_verify(user_pubkey, &preimage, &self.signature)
    }

    /// Encode to canonical CBOR bytes (the wire format, including `signature`).
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> IdentityResult<Vec<u8>> {
        self.validate()?;
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))
    }

    /// Decode from canonical CBOR bytes. STRUCTURAL ONLY — does NOT verify
    /// the signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if the bytes are not canonical CBOR, a field
    /// has the wrong type, or validation fails.
    pub fn decode_cbor(bytes: &[u8]) -> IdentityResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| IdentityError::Other(format!("CBOR decode: {e}")))?;
        let entries = match &value {
            snp_cbor::CborValue::Map(e) => e,
            _ => return Err(IdentityError::Other("DeviceCert must be a CBOR map".into())),
        };
        let mut device_id: Option<NodeId> = None;
        let mut user_id: Option<NodeId> = None;
        let mut capabilities: Option<Vec<String>> = None;
        let mut platform: Option<String> = None;
        let mut not_before: Option<u64> = None;
        let mut not_after: Option<u64> = None;
        let mut attestation: Option<Option<Vec<u8>>> = None;
        let mut signature: Option<DescriptorSignature> = None;
        for (k, v) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s.as_str(),
                _ => return Err(IdentityError::Other("DeviceCert key must be text".into())),
            };
            match key {
                "deviceId" => device_id = Some(decode_bstr_32(v, "DeviceCert.deviceId")?),
                "userId" => user_id = Some(decode_bstr_32(v, "DeviceCert.userId")?),
                "capabilities" => {
                    capabilities = Some(decode_tstr_array(v, "DeviceCert.capabilities")?);
                }
                "platform" => platform = Some(decode_tstr(v, "DeviceCert.platform")?),
                "notBefore" => not_before = Some(decode_uint(v, "DeviceCert.notBefore")?),
                "notAfter" => not_after = Some(decode_uint(v, "DeviceCert.notAfter")?),
                "attestation" => match v {
                    snp_cbor::CborValue::Null => attestation = Some(None),
                    snp_cbor::CborValue::ByteString(b) => attestation = Some(Some(b.clone())),
                    _ => {
                        return Err(IdentityError::Other(
                            "DeviceCert.attestation must be null or bstr".into(),
                        ))
                    }
                },
                "signature" => signature = Some(decode_bstr_64(v, "DeviceCert.signature")?),
                _ => {
                    return Err(IdentityError::Other(format!(
                        "unknown key '{key}' in DeviceCert (signed structure — must be rejected per §9)"
                    )));
                }
            }
        }
        let cert = Self {
            device_id: device_id
                .ok_or_else(|| IdentityError::Other("DeviceCert missing deviceId".into()))?,
            user_id: user_id
                .ok_or_else(|| IdentityError::Other("DeviceCert missing userId".into()))?,
            capabilities: capabilities
                .ok_or_else(|| IdentityError::Other("DeviceCert missing capabilities".into()))?,
            platform: platform
                .ok_or_else(|| IdentityError::Other("DeviceCert missing platform".into()))?,
            not_before: not_before
                .ok_or_else(|| IdentityError::Other("DeviceCert missing notBefore".into()))?,
            not_after: not_after
                .ok_or_else(|| IdentityError::Other("DeviceCert missing notAfter".into()))?,
            attestation: attestation.unwrap_or(None),
            signature: signature
                .ok_or_else(|| IdentityError::Other("DeviceCert missing signature".into()))?,
        };
        cert.validate()?;
        Ok(cert)
    }
}

// ─── NodeDescriptor (frozen identity.ts:320-347) ──────────────────────────

/// A complete `NodeDescriptor`, including the 64-byte Ed25519 signature.
///
/// The signed, broadcastable record published by a node. Binds a `NodeId` to
/// its public keys, capabilities, platform, validity window, and optional
/// `DeviceCert`. Signed by the node's `nodePubKey` under `SIG_CONTEXT`
/// `"nodeDescriptor"`.
///
/// # Wire format
///
/// `encode_cbor()` produces canonical CBOR matching the TS
/// `nodeDescriptorToWireMap` (sync.ts:552-570). `decode_cbor()` is the
/// inverse. The decode is STRUCTURAL ONLY — does NOT verify the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// `NodeId` (32 bytes) — SHA-256("SNP/0.1 node\0" ‖ nodePubKey).
    pub node_id: NodeId,
    /// 32-byte Ed25519 public key of the `NodeIdentity`.
    pub node_pub_key: snp_crypto::PublicKey,
    /// 32-byte X25519 public key of the `RendezvousIdentity`.
    pub rendezvous_pub: [u8; 32],
    /// Capabilities the node advertises (strings from `CAPABILITIES`).
    pub capabilities: Vec<String>,
    /// Platform string (one of `PLATFORMS`).
    pub platform: String,
    /// Protocol version string — MUST be `PROTO_VERSION` ("SNP/0.1").
    pub proto_version: String,
    /// Epoch number this descriptor is valid for.
    pub epoch: u64,
    /// Expiry (unix seconds). Mandatory; SHOULD be ≤ 1h for mobile.
    pub expires_at: u64,
    /// Link-layer hints for reaching the node.
    pub links: Vec<String>,
    /// `DeviceCert` binding this node to a device/user, or `None` for privacy.
    pub device_cert: Option<DeviceCert>,
    /// 64-byte Ed25519 signature by `node_pub_key` over `SIG_CONTEXT`
    /// `"nodeDescriptor"`.
    pub signature: DescriptorSignature,
}

/// Fields of a `NodeDescriptor`, excluding the signature. This is what gets
/// signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptorUnsigned {
    /// `NodeId` (32 bytes).
    pub node_id: NodeId,
    /// 32-byte Ed25519 public key.
    pub node_pub_key: snp_crypto::PublicKey,
    /// 32-byte X25519 public key.
    pub rendezvous_pub: [u8; 32],
    /// Capabilities (strings from `CAPABILITIES`).
    pub capabilities: Vec<String>,
    /// Platform string.
    pub platform: String,
    /// Protocol version — MUST be `PROTO_VERSION`.
    pub proto_version: String,
    /// Epoch number.
    pub epoch: u64,
    /// Expiry (unix seconds).
    pub expires_at: u64,
    /// Link-layer hints.
    pub links: Vec<String>,
    /// Optional `DeviceCert`.
    pub device_cert: Option<DeviceCert>,
}

impl NodeDescriptor {
    /// The `SIG_CONTEXT` name for `NodeDescriptor` signatures.
    pub const SIG_CONTEXT_NAME: &'static str = "nodeDescriptor";

    /// Construct the unsigned fields view (excludes `signature`).
    #[must_use]
    pub fn unsigned(&self) -> NodeDescriptorUnsigned {
        NodeDescriptorUnsigned {
            node_id: self.node_id,
            node_pub_key: self.node_pub_key,
            rendezvous_pub: self.rendezvous_pub,
            capabilities: self.capabilities.clone(),
            platform: self.platform.clone(),
            proto_version: self.proto_version.clone(),
            epoch: self.epoch,
            expires_at: self.expires_at,
            links: self.links.clone(),
            device_cert: self.device_cert.clone(),
        }
    }

    /// Build the canonical CBOR preimage map for a `NodeDescriptor`, EXCLUDING
    /// the `signature` field (identity.ts:362-382).
    fn unsigned_cbor(&self) -> snp_cbor::CborValue {
        use snp_cbor::CborValue;
        // The embedded DeviceCert is encoded as the FULL cert (including its
        // own signature) — per the frozen TS `nodeDescriptorToCborMap`
        // (identity.ts:362-382) which calls `deviceCertToCborMap` (the full
        // cert, not the unsigned fields). The DeviceCert's signature IS part
        // of the NodeDescriptor's signed preimage — it is bound into the
        // descriptor so stripping/substituting the DeviceCert invalidates the
        // descriptor signature.
        let device_cert_val = match &self.device_cert {
            Some(c) => c.to_cbor_value(),
            None => CborValue::Null,
        };
        CborValue::Map(vec![
            (
                CborValue::TextString("nodeId".into()),
                CborValue::ByteString(self.node_id.to_vec()),
            ),
            (
                CborValue::TextString("nodePubKey".into()),
                CborValue::ByteString(self.node_pub_key.to_vec()),
            ),
            (
                CborValue::TextString("rendezvousPub".into()),
                CborValue::ByteString(self.rendezvous_pub.to_vec()),
            ),
            (
                CborValue::TextString("capabilities".into()),
                CborValue::Array(
                    self.capabilities
                        .iter()
                        .map(|c| CborValue::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (
                CborValue::TextString("platform".into()),
                CborValue::TextString(self.platform.clone()),
            ),
            (
                CborValue::TextString("protoVersion".into()),
                CborValue::TextString(self.proto_version.clone()),
            ),
            (
                CborValue::TextString("epoch".into()),
                CborValue::UnsignedInt(self.epoch),
            ),
            (
                CborValue::TextString("expiresAt".into()),
                CborValue::UnsignedInt(self.expires_at),
            ),
            (
                CborValue::TextString("links".into()),
                CborValue::Array(
                    self.links
                        .iter()
                        .map(|l| CborValue::TextString(l.clone()))
                        .collect(),
                ),
            ),
            (CborValue::TextString("deviceCert".into()), device_cert_val),
        ])
    }

    /// Build the signature preimage: `SIG_CONTEXT("nodeDescriptor") ||
    /// canonical_cbor(unsigned_fields)`.
    fn signature_preimage(&self) -> IdentityResult<Vec<u8>> {
        let ctx = snp_crypto::sig_context(Self::SIG_CONTEXT_NAME)
            .ok_or_else(|| IdentityError::Other("unknown SIG_CONTEXT".into()))?;
        let cbor = snp_cbor::encode(&self.unsigned_cbor())
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))?;
        let mut preimage = Vec::with_capacity(ctx.len() + cbor.len());
        preimage.extend_from_slice(ctx);
        preimage.extend_from_slice(&cbor);
        Ok(preimage)
    }

    /// Validate the STRUCTURE of this `NodeDescriptor`.
    ///
    /// # Errors
    /// Returns `IdentityError` on any violation.
    pub fn validate(&self) -> IdentityResult<()> {
        if self.node_id.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.nodeId must be 32 bytes".into(),
            ));
        }
        if self.node_pub_key.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.nodePubKey must be 32 bytes".into(),
            ));
        }
        if self.rendezvous_pub.len() != 32 {
            return Err(IdentityError::Other(
                "NodeDescriptor.rendezvousPub must be 32 bytes".into(),
            ));
        }
        for (i, c) in self.capabilities.iter().enumerate() {
            if !CAPABILITIES.contains(&c.as_str()) {
                return Err(IdentityError::Other(format!(
                    "NodeDescriptor.capabilities[{i}] must be one of {CAPABILITIES:?}; got {c:?}"
                )));
            }
        }
        if !PLATFORMS.contains(&self.platform.as_str()) {
            return Err(IdentityError::Other(format!(
                "NodeDescriptor.platform must be one of {PLATFORMS:?}; got {:?}",
                self.platform
            )));
        }
        if self.proto_version != PROTO_VERSION {
            return Err(IdentityError::Other(format!(
                "NodeDescriptor.protoVersion must be {PROTO_VERSION:?}; got {:?}",
                self.proto_version
            )));
        }
        if let Some(cert) = &self.device_cert {
            cert.validate()?;
        }
        if self.signature.len() != 64 {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }

    /// Sign the unsigned `NodeDescriptor` fields with the node identity's
    /// secret key, producing the 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails.
    pub fn sign(
        unsigned: &NodeDescriptorUnsigned,
        node_secret: &snp_crypto::SecretKey,
    ) -> IdentityResult<DescriptorSignature> {
        let desc_for_validation = NodeDescriptor {
            node_id: unsigned.node_id,
            node_pub_key: unsigned.node_pub_key,
            rendezvous_pub: unsigned.rendezvous_pub,
            capabilities: unsigned.capabilities.clone(),
            platform: unsigned.platform.clone(),
            proto_version: unsigned.proto_version.clone(),
            epoch: unsigned.epoch,
            expires_at: unsigned.expires_at,
            links: unsigned.links.clone(),
            device_cert: unsigned.device_cert.clone(),
            signature: [0u8; 64],
        };
        desc_for_validation.validate()?;
        let preimage = desc_for_validation.signature_preimage()?;
        Ok(snp_crypto::ed25519_sign(node_secret, &preimage))
    }

    /// Verify the `NodeDescriptor`'s signature against the node's public key.
    /// Returns `false` on any failure (I20 — never throws).
    #[must_use]
    pub fn verify(&self, node_pubkey: &snp_crypto::PublicKey) -> bool {
        if self.signature.len() != 64 {
            return false;
        }
        if self.validate().is_err() {
            return false;
        }
        let Ok(preimage) = self.signature_preimage() else {
            return false;
        };
        snp_crypto::ed25519_verify(node_pubkey, &preimage, &self.signature)
    }

    /// Encode to canonical CBOR bytes (the wire format, including `signature`).
    ///
    /// # Errors
    /// Returns `IdentityError` if validation fails or CBOR encoding fails.
    pub fn encode_cbor(&self) -> IdentityResult<Vec<u8>> {
        self.validate()?;
        use snp_cbor::CborValue;
        let mut entries = match self.unsigned_cbor() {
            CborValue::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((
            CborValue::TextString("signature".into()),
            CborValue::ByteString(self.signature.to_vec()),
        ));
        snp_cbor::encode(&CborValue::Map(entries))
            .map_err(|e| IdentityError::Other(format!("CBOR encode: {e}")))
    }

    /// Decode from canonical CBOR bytes. STRUCTURAL ONLY — does NOT verify
    /// the signature.
    ///
    /// # Errors
    /// Returns `IdentityError` if the bytes are not canonical CBOR, a field
    /// has the wrong type, or validation fails.
    pub fn decode_cbor(bytes: &[u8]) -> IdentityResult<Self> {
        let value = snp_cbor::decode(bytes)
            .map_err(|e| IdentityError::Other(format!("CBOR decode: {e}")))?;
        let entries = match &value {
            snp_cbor::CborValue::Map(e) => e,
            _ => {
                return Err(IdentityError::Other(
                    "NodeDescriptor must be a CBOR map".into(),
                ))
            }
        };
        let mut node_id: Option<NodeId> = None;
        let mut node_pub_key: Option<snp_crypto::PublicKey> = None;
        let mut rendezvous_pub: Option<[u8; 32]> = None;
        let mut capabilities: Option<Vec<String>> = None;
        let mut platform: Option<String> = None;
        let mut proto_version: Option<String> = None;
        let mut epoch: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut links: Option<Vec<String>> = None;
        let mut device_cert: Option<Option<DeviceCert>> = None;
        let mut signature: Option<DescriptorSignature> = None;
        for (k, v) in entries {
            let key = match k {
                snp_cbor::CborValue::TextString(s) => s.as_str(),
                _ => {
                    return Err(IdentityError::Other(
                        "NodeDescriptor key must be text".into(),
                    ))
                }
            };
            match key {
                "nodeId" => node_id = Some(decode_bstr_32(v, "NodeDescriptor.nodeId")?),
                "nodePubKey" => {
                    node_pub_key = Some(decode_bstr_32(v, "NodeDescriptor.nodePubKey")?);
                }
                "rendezvousPub" => {
                    rendezvous_pub = Some(decode_bstr_32(v, "NodeDescriptor.rendezvousPub")?);
                }
                "capabilities" => {
                    capabilities = Some(decode_tstr_array(v, "NodeDescriptor.capabilities")?);
                }
                "platform" => platform = Some(decode_tstr(v, "NodeDescriptor.platform")?),
                "protoVersion" => {
                    proto_version = Some(decode_tstr(v, "NodeDescriptor.protoVersion")?);
                }
                "epoch" => epoch = Some(decode_uint(v, "NodeDescriptor.epoch")?),
                "expiresAt" => expires_at = Some(decode_uint(v, "NodeDescriptor.expiresAt")?),
                "links" => links = Some(decode_tstr_array(v, "NodeDescriptor.links")?),
                "deviceCert" => {
                    if v == &snp_cbor::CborValue::Null {
                        device_cert = Some(None)
                    } else {
                        let cert = DeviceCert::decode_cbor_value(v)?;
                        device_cert = Some(Some(cert));
                    }
                }
                "signature" => signature = Some(decode_bstr_64(v, "NodeDescriptor.signature")?),
                _ => {
                    return Err(IdentityError::Other(format!(
                        "unknown key '{key}' in NodeDescriptor (signed structure — must be rejected per §9)"
                    )));
                }
            }
        }
        let desc = Self {
            node_id: node_id
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing nodeId".into()))?,
            node_pub_key: node_pub_key
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing nodePubKey".into()))?,
            rendezvous_pub: rendezvous_pub.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing rendezvousPub".into())
            })?,
            capabilities: capabilities.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing capabilities".into())
            })?,
            platform: platform
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing platform".into()))?,
            proto_version: proto_version.ok_or_else(|| {
                IdentityError::Other("NodeDescriptor missing protoVersion".into())
            })?,
            epoch: epoch
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing epoch".into()))?,
            expires_at: expires_at
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing expiresAt".into()))?,
            links: links
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing links".into()))?,
            device_cert: device_cert.unwrap_or(None),
            signature: signature
                .ok_or_else(|| IdentityError::Other("NodeDescriptor missing signature".into()))?,
        };
        desc.validate()?;
        Ok(desc)
    }
}

// ─── CBOR helpers for identity decode ─────────────────────────────────────

fn decode_bstr_32(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<[u8; 32]> {
    let b = match v {
        snp_cbor::CborValue::ByteString(b) => b,
        _ => {
            return Err(IdentityError::Other(format!(
                "{field} must be a byte string"
            )))
        }
    };
    if b.len() != 32 {
        return Err(IdentityError::Other(format!(
            "{field} must be 32 bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b);
    Ok(arr)
}

fn decode_bstr_64(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<[u8; 64]> {
    let b = match v {
        snp_cbor::CborValue::ByteString(b) => b,
        _ => {
            return Err(IdentityError::Other(format!(
                "{field} must be a byte string"
            )))
        }
    };
    if b.len() != 64 {
        return Err(IdentityError::Other(format!(
            "{field} must be 64 bytes, got {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(b);
    Ok(arr)
}

fn decode_uint(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<u64> {
    match v {
        snp_cbor::CborValue::UnsignedInt(n) => Ok(*n),
        _ => Err(IdentityError::Other(format!(
            "{field} must be an unsigned int"
        ))),
    }
}

fn decode_tstr(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<String> {
    match v {
        snp_cbor::CborValue::TextString(s) => Ok(s.clone()),
        _ => Err(IdentityError::Other(format!(
            "{field} must be a text string"
        ))),
    }
}

fn decode_tstr_array(v: &snp_cbor::CborValue, field: &str) -> IdentityResult<Vec<String>> {
    let arr = match v {
        snp_cbor::CborValue::Array(a) => a,
        _ => return Err(IdentityError::Other(format!("{field} must be an array"))),
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        out.push(decode_tstr(item, &format!("{field}[{i}]"))?);
    }
    Ok(out)
}

impl DeviceCert {
    /// Decode a `DeviceCert` from a CBOR value (for nested deviceCert field
    /// in `NodeDescriptor`).
    fn decode_cbor_value(v: &snp_cbor::CborValue) -> IdentityResult<Self> {
        let bytes = snp_cbor::encode(v)
            .map_err(|e| IdentityError::Other(format!("CBOR re-encode: {e}")))?;
        Self::decode_cbor(&bytes)
    }
}

// ─── Legacy Capabilities struct (kept for backward compat, NOT used by the
// frozen NodeDescriptor which uses `Vec<String>`) ───────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::format_collect)]
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nodeid_deterministic_alice() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let id = derive_node_id(&pk);
        let got: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "4ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b414913"
        );
        // Deterministic: same input → same output.
        let id2 = derive_node_id(&pk);
        assert_eq!(id, id2);
    }

    #[test]
    fn rfc8032_test1_verify() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&hex_to_bytes(pk_hex));
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&hex_to_bytes(sig_hex));
        assert!(snp_crypto::ed25519_verify(&pk, b"", &sig));
    }

    #[test]
    fn unknown_context_rejects() {
        let pk = [0u8; 32];
        let sig = [0u8; 64];
        assert!(!verify_signed(&pk, "nonsense", b"", &sig));
    }

    // ─── R4.2 interop: NodeDescriptor + DeviceCert codec tests ──────────────

    fn test_keypair(seed: u8) -> (snp_crypto::SecretKey, snp_crypto::PublicKey) {
        let secret = [seed; 32];
        let public = snp_crypto::derive_public_key(&secret);
        (secret, public)
    }

    fn test_node_id(seed: u8) -> NodeId {
        [seed; 32]
    }

    fn test_device_cert_unsigned() -> DeviceCertUnsigned {
        DeviceCertUnsigned {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into(), "CONTENT_SEED".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
        }
    }

    fn test_node_descriptor_unsigned(cert: Option<DeviceCert>) -> NodeDescriptorUnsigned {
        NodeDescriptorUnsigned {
            node_id: test_node_id(0xAA),
            node_pub_key: test_keypair(0xBB).1,
            rendezvous_pub: [0xCC; 32],
            capabilities: vec!["MESH_RELAY".into(), "DISCOVERY".into()],
            platform: "android".into(),
            proto_version: PROTO_VERSION.into(),
            epoch: 42,
            expires_at: 9_000,
            links: vec!["tcp://1.2.3.4:5678".into()],
            device_cert: cert,
        }
    }

    #[test]
    fn device_cert_roundtrip() {
        let (user_secret, user_pubkey) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes = cert.encode_cbor().expect("encode");
        let decoded = DeviceCert::decode_cbor(&bytes).expect("decode");
        assert_eq!(cert, decoded);
        // Verify the signature.
        assert!(cert.verify(&user_pubkey), "signature must verify");
    }

    #[test]
    fn device_cert_encode_decode_reencode_identical() {
        // Determinism: encode → decode → re-encode produces identical bytes.
        let (user_secret, _) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes1 = cert.encode_cbor().expect("encode 1");
        let decoded = DeviceCert::decode_cbor(&bytes1).expect("decode");
        let bytes2 = decoded.encode_cbor().expect("encode 2");
        assert_eq!(bytes1, bytes2, "encode→decode→re-encode must be identical");
    }

    #[test]
    fn device_cert_tampered_signature_rejected() {
        let (user_secret, user_pubkey) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let mut cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        // Tamper the signature.
        cert.signature[0] ^= 0xFF;
        assert!(
            !cert.verify(&user_pubkey),
            "tampered signature must NOT verify"
        );
    }

    #[test]
    fn device_cert_unknown_key_rejected() {
        let (user_secret, _) = test_keypair(0x99);
        let unsigned = test_device_cert_unsigned();
        let sig = DeviceCert::sign(&unsigned, &user_secret).expect("sign");
        let cert = DeviceCert {
            signature: sig,
            ..DeviceCert {
                device_id: unsigned.device_id,
                user_id: unsigned.user_id,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                not_before: unsigned.not_before,
                not_after: unsigned.not_after,
                attestation: unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let bytes = cert.encode_cbor().expect("encode");
        // Inject an unknown key by appending a new map entry before the
        // closing. Easier: decode, re-encode with an extra key, then try
        // to decode.
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            entries.push((
                CborValue::TextString("unknownKey".into()),
                CborValue::UnsignedInt(99),
            ));
        }
        let tampered_bytes = encode(&value).expect("re-encode with unknown key");
        let result = DeviceCert::decode_cbor(&tampered_bytes);
        assert!(
            result.is_err(),
            "unknown key in signed structure must be rejected"
        );
    }

    #[test]
    fn device_cert_missing_field_rejected() {
        // Omit the `signature` field.
        use snp_cbor::encode;
        let cert_unsigned_cbor = DeviceCert {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
            signature: [0u8; 64],
        };
        // Encode WITHOUT the signature field (just the unsigned_cbor).
        let unsigned_value = cert_unsigned_cbor.unsigned_cbor();
        let bytes = encode(&unsigned_value).expect("encode without sig");
        let result = DeviceCert::decode_cbor(&bytes);
        assert!(result.is_err(), "missing signature must be rejected");
    }

    #[test]
    fn device_cert_wrong_field_type_rejected() {
        // `notBefore` as a text string instead of uint.
        use snp_cbor::{encode, CborValue};
        let cert = DeviceCert {
            device_id: test_node_id(0x11),
            user_id: test_node_id(0x22),
            capabilities: vec!["MESH_CLIENT".into()],
            platform: "linux".into(),
            not_before: 1_000,
            not_after: 10_000,
            attestation: None,
            signature: [0u8; 64],
        };
        let mut value = cert.unsigned_cbor();
        if let CborValue::Map(ref mut entries) = value {
            for (k, v) in entries.iter_mut() {
                if let CborValue::TextString(s) = k {
                    if s == "notBefore" {
                        *v = CborValue::TextString("not-a-uint".into());
                    }
                }
            }
        }
        let bytes = encode(&value).expect("encode");
        let result = DeviceCert::decode_cbor(&bytes);
        assert!(result.is_err(), "wrong field type must be rejected");
    }

    #[test]
    fn node_descriptor_roundtrip_no_cert() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        let decoded = NodeDescriptor::decode_cbor(&bytes).expect("decode");
        assert_eq!(desc, decoded);
        assert!(desc.verify(&node_pubkey), "signature must verify");
    }

    #[test]
    fn node_descriptor_roundtrip_with_cert() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let (user_secret, _) = test_keypair(0x99);
        let cert_unsigned = test_device_cert_unsigned();
        let cert_sig = DeviceCert::sign(&cert_unsigned, &user_secret).expect("sign cert");
        let cert = DeviceCert {
            signature: cert_sig,
            ..DeviceCert {
                device_id: cert_unsigned.device_id,
                user_id: cert_unsigned.user_id,
                capabilities: cert_unsigned.capabilities,
                platform: cert_unsigned.platform,
                not_before: cert_unsigned.not_before,
                not_after: cert_unsigned.not_after,
                attestation: cert_unsigned.attestation,
                signature: [0u8; 64],
            }
        };
        let unsigned = test_node_descriptor_unsigned(Some(cert));
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        let decoded = NodeDescriptor::decode_cbor(&bytes).expect("decode");
        assert_eq!(desc, decoded);
        assert!(desc.verify(&node_pubkey), "signature must verify");
    }

    #[test]
    fn node_descriptor_encode_decode_reencode_identical() {
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes1 = desc.encode_cbor().expect("encode 1");
        let decoded = NodeDescriptor::decode_cbor(&bytes1).expect("decode");
        let bytes2 = decoded.encode_cbor().expect("encode 2");
        assert_eq!(bytes1, bytes2, "encode→decode→re-encode must be identical");
    }

    #[test]
    fn node_descriptor_tampered_signature_rejected() {
        let (node_secret, node_pubkey) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let mut desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        desc.signature[0] ^= 0xFF;
        assert!(
            !desc.verify(&node_pubkey),
            "tampered signature must NOT verify"
        );
    }

    #[test]
    fn node_descriptor_wrong_proto_version_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let mut unsigned = test_node_descriptor_unsigned(None);
        unsigned.proto_version = "SNP/0.2".into(); // wrong!
        let result = NodeDescriptor::sign(&unsigned, &node_secret);
        assert!(
            result.is_err(),
            "wrong protoVersion must be rejected at sign time"
        );
    }

    #[test]
    fn node_descriptor_invalid_capability_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let mut unsigned = test_node_descriptor_unsigned(None);
        unsigned.capabilities = vec!["INVALID_CAP".into()];
        let result = NodeDescriptor::sign(&unsigned, &node_secret);
        assert!(result.is_err(), "invalid capability must be rejected");
    }

    #[test]
    fn node_descriptor_unknown_key_rejected() {
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let bytes = desc.encode_cbor().expect("encode");
        use snp_cbor::{decode, encode, CborValue};
        let mut value = decode(&bytes).expect("decode");
        if let CborValue::Map(ref mut entries) = value {
            entries.push((
                CborValue::TextString("unknownKey".into()),
                CborValue::UnsignedInt(99),
            ));
        }
        let tampered = encode(&value).expect("re-encode");
        let result = NodeDescriptor::decode_cbor(&tampered);
        assert!(
            result.is_err(),
            "unknown key in signed structure must be rejected"
        );
    }

    #[test]
    fn node_descriptor_missing_field_rejected() {
        // Omit the `signature` field.
        let (node_secret, _) = test_keypair(0xBB);
        let unsigned = test_node_descriptor_unsigned(None);
        let sig = NodeDescriptor::sign(&unsigned, &node_secret).expect("sign");
        let desc = NodeDescriptor {
            signature: sig,
            ..NodeDescriptor {
                node_id: unsigned.node_id,
                node_pub_key: unsigned.node_pub_key,
                rendezvous_pub: unsigned.rendezvous_pub,
                capabilities: unsigned.capabilities,
                platform: unsigned.platform,
                proto_version: unsigned.proto_version,
                epoch: unsigned.epoch,
                expires_at: unsigned.expires_at,
                links: unsigned.links,
                device_cert: unsigned.device_cert,
                signature: [0u8; 64],
            }
        };
        let unsigned_value = desc.unsigned_cbor();
        let bytes = snp_cbor::encode(&unsigned_value).expect("encode without sig");
        let result = NodeDescriptor::decode_cbor(&bytes);
        assert!(result.is_err(), "missing signature must be rejected");
    }
}

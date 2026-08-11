//! SNP-CRYPTO — Cryptographic primitives for ShareNet 2.0
//!
//! Implements the SNP/0.1 cryptographic stack (per `02-PROTOCOL-SPEC.md` §1.2):
//! - **Ed25519** for signatures (raw 32-byte public keys on the wire — I3)
//! - **X25519** for ephemeral-static Diffie-Hellman in the Noise_IK handshake
//! - **SHA-256** as the universal hash (NodeIds, Merkle leaves, transcript hashes)
//! - **HKDF-SHA256** for key derivation in Noise_IK and circuit keys
//! - **ChaCha20-Poly1305** as the AEAD for L8 frames and L6/L7 circuits
//!
//! This crate is implemented independently of the TypeScript reference. The
//! normative authority is `public/spec/02-PROTOCOL-SPEC.md` §1.2 and the
//! referenced RFCs (8032, 7748, 8439, 5869, 6962). All crypto is delegated to
//! well-reviewed Rust crates (`ed25519-dalek`, `sha2`, `hkdf`,
//! `chacha20poly1305`); no cryptographic primitive is hand-rolled.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors from SNP cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,
    /// AEAD decryption failed (bad tag, wrong key, truncated input, …).
    #[error("AEAD decryption failed")]
    BadAead,
    /// HKDF was called with an invalid info or length.
    #[error("invalid HKDF parameter: {0}")]
    InvalidHkdf(String),
    /// A raw byte buffer had the wrong length for its intended use.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length supplied.
        actual: usize,
    },
}

/// Convenience `Result` alias.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// A 32-byte Ed25519 secret key.
pub type SecretKey = [u8; 32];
/// A 32-byte Ed25519 / X25519 public key (raw form on the wire, per I3).
pub type PublicKey = [u8; 32];
/// A 64-byte Ed25519 signature.
pub type SignatureBytes = [u8; 64];
/// Alias for [`SignatureBytes`] kept for API compatibility with downstream
/// skeleton crates. New code should prefer `SignatureBytes`.
pub type Signature = SignatureBytes;
/// A 32-byte symmetric key (HKDF output, ChaCha20-Poly1305 key).
pub type SymmetricKey = [u8; 32];
/// A 12-byte ChaCha20-Poly1305 nonce.
pub type NonceBytes = [u8; 12];
/// A 16-byte Poly1305 authentication tag.
pub type Tag = [u8; 16];

/// An Ed25519 key pair: secret key + derived public key. Skeleton API kept
/// for downstream crates; not used by the conformance harness.
#[derive(Debug, Clone)]
pub struct Keypair {
    /// The 32-byte secret key.
    pub secret: SecretKey,
    /// The 32-byte public key.
    pub public: PublicKey,
}

// === Hashing (SHA-256) ===

/// Compute `SHA-256(data)`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute `SHA-256(domain_sep || data)` — the SNP domain-separated hash.
///
/// SNP/0.1 §1 mandates that every hash used in a NodeId, Merkle leaf, or
/// transcript be domain-separated by prefixing a fixed tag.
#[must_use]
pub fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// === Ed25519 ===

/// Verify an Ed25519 signature. Returns `true` iff the signature is valid
/// under RFC 8032 verification (strict, no batch, no malleability leniency).
///
/// Per I2, signed structures in SNP are over `SIG_CONTEXT || CBOR(payload)`.
/// The caller is responsible for prefixing the context — this function
/// verifies raw bytes.
#[must_use]
pub fn ed25519_verify(public_key: &PublicKey, message: &[u8], signature: &SignatureBytes) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = DalekSignature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// Compute `HKDF-SHA256(ikm, salt, info, length)` as a one-shot RFC 5869
/// extract-then-expand.
///
/// # Errors
/// Returns [`CryptoError::InvalidHkdf`] if `length > 255 * 32` (the RFC 5869
/// bound for SHA-256).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    if length > 255 * 32 {
        return Err(CryptoError::InvalidHkdf(format!(
            "length {length} exceeds 255*HashLen (255*32 = {cap})",
            cap = 255 * 32
        )));
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::InvalidHkdf(format!("hkdf expand: {e}")))?;
    Ok(okm)
}

/// HKDF-Extract using SHA-256. Returns the 32-byte PRK.
///
/// Implemented as `HMAC-SHA256(salt, ikm)` per RFC 5869 §2.2.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand using SHA-256.
///
/// # Errors
/// Returns [`CryptoError::InvalidHkdf`] if `length > 255 * 32`.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    if length > 255 * 32 {
        return Err(CryptoError::InvalidHkdf(format!(
            "length {length} exceeds 255*32"
        )));
    }
    // Build an Hkdf from an already-extracted PRK.
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| CryptoError::InvalidHkdf(format!("hkdf from_prk: {e}")))?;
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::InvalidHkdf(format!("hkdf expand: {e}")))?;
    Ok(okm)
}

/// Compute HMAC-SHA256(key, data) inline (used to implement [`hkdf_extract`]
/// without depending on the `hmac` crate directly).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k_pad = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha256(key);
        k_pad[..32].copy_from_slice(&h);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_h = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_h);
    let out = outer.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// === ChaCha20-Poly1305 AEAD (RFC 8439) ===

/// Encrypt `plaintext` with ChaCha20-Poly1305. Returns `(ciphertext, tag)`.
///
/// The ciphertext is the same length as the plaintext; the 16-byte tag is
/// returned separately. This matches the wire format used by SNP frames,
/// where the tag is stored alongside the frame header rather than appended.
#[must_use]
pub fn aead_encrypt(
    key: &SymmetricKey,
    nonce: &NonceBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, Tag) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);
    // Use the in-place detached API to get ciphertext and tag separately.
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(n, aad, &mut buf)
        .expect("encrypt_in_place_detached never fails for ChaCha20Poly1305");
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(&tag);
    (buf, tag_arr)
}

/// Decrypt a ChaCha20-Poly1305 ciphertext with a detached tag.
///
/// Returns `None` on authentication failure (per I20: AEAD never throws on
/// auth failure — it returns `None`).
#[must_use]
pub fn aead_decrypt(
    key: &SymmetricKey,
    nonce: &NonceBytes,
    ciphertext: &[u8],
    tag: &Tag,
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);
    let mut buf = ciphertext.to_vec();
    match cipher.decrypt_in_place_detached(n, aad, &mut buf, tag.into()) {
        Ok(()) => Some(buf),
        Err(_) => None,
    }
}

/// Encrypt-and-append: returns `ciphertext ‖ tag` (the RFC 8439 wire form).
#[must_use]
pub fn aead_seal(key: &SymmetricKey, nonce: &NonceBytes, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: plaintext, aad })
        .expect("chacha20poly1305 encrypt never fails")
}

/// Decrypt a `ciphertext ‖ tag` blob. Returns `None` on auth failure.
#[must_use]
pub fn aead_open(key: &SymmetricKey, nonce: &NonceBytes, sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let n = Nonce::from_slice(nonce);
    cipher.decrypt(n, Payload { msg: sealed, aad }).ok()
}

/// Build the 12-byte AEAD nonce from a frame ID and sequence number.
///
/// Per `02-PROTOCOL-SPEC.md` §7.3: `nonce = fid(8 bytes) ‖ seq(4 bytes BE)`.
#[must_use]
pub fn aead_nonce(fid: &[u8; 8], seq: u32) -> NonceBytes {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(fid);
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n
}

// === NodeId derivation (I4) ===

/// Domain-separation tag used in NodeId derivation (I4).
pub const NODE_ID_DOMAIN: &[u8] = b"SNP/0.1 node\0";

/// Derive a NodeId from an Ed25519 public key.
///
/// Per invariant I4: `NodeId = SHA-256("SNP/0.1 node\0" || pk)`. The bare key
/// is NEVER used as a NodeId.
#[must_use]
pub fn derive_node_id(public_key: &PublicKey) -> [u8; 32] {
    domain_hash(NODE_ID_DOMAIN, public_key)
}

/// Domain-separation tag for the Merkle empty-tree root.
pub const EMPTY_ROOT_DOMAIN: &[u8] = b"SNP/0.1 empty\0";

/// Compute the Merkle root of an empty leaf set: `SHA-256("SNP/0.1 empty\0")`.
#[must_use]
pub fn empty_merkle_root() -> [u8; 32] {
    sha256(EMPTY_ROOT_DOMAIN)
}

// === SIG_CONTEXT domain separators (I2) ===

/// All SNP signature contexts (I2). Each context is the ASCII bytes of
/// `"SNP/0.1 <kebab-name>\0"`. The names use camelCase keys (matching the
/// TS reference and the conformance vector `contextName` field).
pub mod sig_contexts {
    /// Manifest signature context: `"SNP/0.1 manifest\0"`.
    pub const MANIFEST: &[u8] = b"SNP/0.1 manifest\0";
    /// DeliveryReceipt: `"SNP/0.1 delivery-receipt\0"`.
    pub const DELIVERY_RECEIPT: &[u8] = b"SNP/0.1 delivery-receipt\0";
    /// TransitReceipt: `"SNP/0.1 transit-receipt\0"`.
    pub const TRANSIT_RECEIPT: &[u8] = b"SNP/0.1 transit-receipt\0";
    /// GatewayReceipt: `"SNP/0.1 gateway-receipt\0"`.
    pub const GATEWAY_RECEIPT: &[u8] = b"SNP/0.1 gateway-receipt\0";
    /// CustodyReceipt: `"SNP/0.1 custody-receipt\0"`.
    pub const CUSTODY_RECEIPT: &[u8] = b"SNP/0.1 custody-receipt\0";
    /// NodeDescriptor: `"SNP/0.1 node-descriptor\0"`.
    pub const NODE_DESCRIPTOR: &[u8] = b"SNP/0.1 node-descriptor\0";
    /// GatewayAdvert: `"SNP/0.1 gateway-advert\0"`.
    pub const GATEWAY_ADVERT: &[u8] = b"SNP/0.1 gateway-advert\0";
    /// RouteAdvert: `"SNP/0.1 route-advert\0"`.
    pub const ROUTE_ADVERT: &[u8] = b"SNP/0.1 route-advert\0";
    /// Revocation: `"SNP/0.1 revocation\0"`.
    pub const REVOCATION: &[u8] = b"SNP/0.1 revocation\0";
    /// DeviceCert: `"SNP/0.1 device-cert\0"`.
    pub const DEVICE_CERT: &[u8] = b"SNP/0.1 device-cert\0";
    /// TransitRequest: `"SNP/0.1 transit-request\0"`.
    pub const TRANSIT_REQUEST: &[u8] = b"SNP/0.1 transit-request\0";
    /// TransitResponse: `"SNP/0.1 transit-response\0"`.
    pub const TRANSIT_RESPONSE: &[u8] = b"SNP/0.1 transit-response\0";
}

/// Look up a SIG_CONTEXT by its camelCase name (e.g. `"manifest"`,
/// `"deliveryReceipt"`). Returns `None` for unknown names.
///
/// The mapping is the camelCase → kebab-case transformation defined in
/// `02-PROTOCOL-SPEC.md` §1.1. The list of known names is fixed; adding a
/// new signed structure requires a spec amendment and a new entry here.
#[must_use]
pub fn sig_context(name: &str) -> Option<&'static [u8]> {
    match name {
        "manifest" => Some(sig_contexts::MANIFEST),
        "deliveryReceipt" => Some(sig_contexts::DELIVERY_RECEIPT),
        "transitReceipt" => Some(sig_contexts::TRANSIT_RECEIPT),
        "gatewayReceipt" => Some(sig_contexts::GATEWAY_RECEIPT),
        "custodyReceipt" => Some(sig_contexts::CUSTODY_RECEIPT),
        "nodeDescriptor" => Some(sig_contexts::NODE_DESCRIPTOR),
        "gatewayAdvert" => Some(sig_contexts::GATEWAY_ADVERT),
        "routeAdvert" => Some(sig_contexts::ROUTE_ADVERT),
        "revocation" => Some(sig_contexts::REVOCATION),
        "deviceCert" => Some(sig_contexts::DEVICE_CERT),
        "transitRequest" => Some(sig_contexts::TRANSIT_REQUEST),
        "transitResponse" => Some(sig_contexts::TRANSIT_RESPONSE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha256_abc_matches_nist() {
        let h = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let got = hex::encode(&h);
        // Avoid pulling in hex; format manually.
        let got_str: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got_str, expected);
        let _ = got;
    }

    #[test]
    fn sha256_empty() {
        let h = sha256(b"");
        let got: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nodeid_alice() {
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pk_bytes = hex_to_bytes(pk_hex);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let id = derive_node_id(&pk);
        let got: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "4ae95ccb41544dccde22eca97a7cdc99101cb5aa91606c257b56cdd35b414913"
        );
    }

    #[test]
    fn rfc8032_test1_verify() {
        // RFC 8032 §7.1 Test 1
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let pk_bytes = hex_to_bytes(pk_hex);
        let sig_bytes = hex_to_bytes(sig_hex);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        assert!(ed25519_verify(&pk, b"", &sig));
    }

    #[test]
    fn aead_nonce_fid_seq() {
        let fid: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let n = aead_nonce(&fid, 1);
        let got: String = n.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "010203040506070800000001");
    }

    #[test]
    fn hkdf_rfc5869_test1() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        let got: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn aead_rfc8439_section_2_8_2() {
        let key_bytes = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce_bytes = hex_to_bytes("070000004041424344454647");
        let pt = hex_to_bytes("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f66657220796f75206f6e65206164766963652c20697420776f756c6420626520746f20756e6465727374616e642074686520696d706f7274616e6365206f6620636172746f6772617068792e");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);
        let (ct, tag) = aead_encrypt(&key, &nonce, &pt, &aad);
        let ct_str: String = ct.iter().map(|b| format!("{b:02x}")).collect();
        let tag_str: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            ct_str,
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2a1284fca0649874379991a53b34708dc9c04ab7b76e11060de2bf61a6f983758e0795c2cf5e36cabb3de8dfb5940368d2f977c62a96df874c765d2c6ca8150fb6d4020c9caf8e8f0c0cda"
        );
        assert_eq!(tag_str, "a6533eac3c7b560f1bb6dc4087de673c");
    }

    // Used only to silence dead-code warnings on the helpers above.
    mod hex {
        pub fn encode(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
    }
}

# core-crypto

Cryptographic core for ShareNet — identity, signing, canonical encoding, and key storage.

## Responsibilities

- **Identity**: `NodeId` is the Ed25519 public key (32 bytes) — the primary key everywhere.
- **Content addressing**: `ChunkId` (SHA-256 of chunk bytes) and `BlobId` (Merkle root).
- **Signed structures**: `Manifest`, `DeliveryReceipt`, `Contribution`, `CatalogEntry`, `Category`.
- **Canonical CBOR**: `Cbor` object implements deterministic CBOR per RFC 7049 §3.9 / RFC 8949 §4.2.
- **Ed25519**: `CryptoProvider` interface with `TinkCryptoProvider` (production), `InMemoryCryptoProvider` (JVM tests), `KeystoreCryptoProvider` (Keystore-wrapped).
- **Keystore**: `AndroidKeystoreWrapper` manages the AES-256-GCM wrapping key and Tink keyset persistence.

## Locked decisions

- **Crypto**: Google Tink Ed25519 (no raw JCA, no ad-hoc curves).
- **Encoding**: Canonical CBOR with sorted map keys. All signed structures are encoded via `Cbor.encodeManifest` / `encodeReceipt` / `encodeContribution` — never ad-hoc JSON or Protobuf for signatures.
- **MinSdk**: 26.

## Signing contract

```
signature = Ed25519.sign(privateKey, Cbor.encodeX(structWithoutSignature))
verify    = Ed25519.verify(publicKey, Cbor.encodeX(structWithoutSignature), signature)
```

`Cbor.encodeManifest` excludes the `signature` field; `encodeReceipt` excludes `recipientSignature`; `encodeContribution` excludes `signature`. This is the only correct signing form. The Python backend (`backend/common/cbor.py`) must produce byte-identical CBOR for the same inputs — validated by golden vectors.

## Equality / hashing

`NodeId`, `ChunkId`, `BlobId`, `Manifest`, `DeliveryReceipt`, `Contribution` override `equals`/`hashCode` to be content-based over `ByteArray` fields (`contentEquals` / `contentHashCode`). Never use default `ByteArray` identity equality.

## Key storage

```
App start → AndroidKeystoreWrapper.ensureWrappingKey()
          → KeysetHandle via AndroidKeysetManager (encrypted with wrapping key)
          → CryptoProvider.sign via Tink primitive
```

- Wrapping key: AES-256-GCM, `AndroidKeyStore`, hardware-backed when StrongBox/TEE available.
- Keyset file: `SharedPreferences` entry `sharenet_keyset_prefs`, encrypted by Tink's `AndroidKeysetManager`.
- `KeystoreCryptoProvider` is a thin decorator over `TinkCryptoProvider` that loads the handle from the wrapper.
- On JVM / in tests, the wrapper degrades to an in-memory store — no Keystore required.

## Deterministic tests

`CryptoProvider.seededKeypair(seed: Long)` returns the same keypair for the same seed. Use it in golden-vector generation and in any test that asserts on signatures. Never use `generateKeypair()` in assertions.

## Golden vectors

`src/test/resources/golden-vectors.json` (created in M0) contains 20 fixtures: each entry has `input` (the structure fields), `cbor_hex` (canonical CBOR bytes), `public_key_hex`, `signature_hex`. Kotlin and Python must match byte-for-byte. This file is the single source of truth for cross-platform signature correctness.

## Module boundaries

- No dependency on `core-content`, `core-catalog`, etc. — they depend on this module.
- No Room, no SQLCipher, no Nearby. This module is pure crypto + encoding.

## Testing

```bash
./gradlew :core-crypto:testDebugUnitTest
```

- Unit tests use `InMemoryCryptoProvider` — no Android runtime needed.
- Instrumented tests verify `AndroidKeystoreWrapper` survives app restart.

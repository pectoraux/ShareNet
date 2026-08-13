# core-catalog

Publisher trust, manifest verification, revocation, and catalog queries.

## Responsibilities

- **PublisherRegistry**: Pinned root key, delegated publishers, root rotation via signed transition. See `PublisherRegistry`.
- **ManifestStore**: Room-backed manifest ingestion with mandatory signature verification (Ed25519 + publisher trust + Merkle root + expiry + revocation). See `ManifestStore`.
- **RevocationList**: High-priority revocation with strict propagation ordering (revocations before content) and immediate local deletion of manifests and blobs. See `RevocationList`.
- **CatalogRepository**: High-level query API combining the above with category / version / expiry filtering. See `CatalogRepository`.
- **Database**: `CatalogDatabase` (Room + SQLCipher) with `ManifestEntity`, `RevocationEntity`, `PublisherEntity`.

## Locked decisions

- **DB**: Room + SQLCipher, minSdk 26.
- **Signing**: All manifests, revocations, and publisher delegations are signed over canonical CBOR (`Cbor.encode`) and verified via `CryptoProvider` (Ed25519 / Tink).
- **Encoding**: Same deterministic CBOR as `core-crypto` — shared with Python backend via golden vectors.
- **Priority**: `CatalogEntry.PRIORITY_REVOCATION = Int.MAX_VALUE`. Revocations propagate strictly before content (M2 acceptance: revocation must arrive ahead of a queued large content transfer).

## Trust model

```
Pinned root (build-time hex)
  ├─ delegates ─► publisher A
  ├─ delegates ─► publisher B
  └─ rotation  ─► new root (old root signs transition)
        │
        payload = Cbor.encode(sortedMapOf("newRoot" to newKey, "rotatedAt" to ts))
```

- Root key is pinned via constructor `pinnedRootHex`; it can also be loaded from a bundled resource / `BuildConfig`.
- Delegation and rotation payloads are fixed; verifiers must reproduce the exact CBOR.
- Publisher additions and revocations require the current root's signature.

## ManifestStore contract

`put(entry)` checks in order and throws `ManifestVerificationException` on failure:

1. **Expiry** — `expiresAt <= now` → `Expired`.
2. **Trust** — publisher not in `PublisherRegistry` → `UntrustedPublisher`.
3. **Signature** — `crypto.verifyManifest(manifest)` → `BadSignature`.
4. **BlobId / chunks** — `MerkleTree.merkleRoot(chunks) != blobId` → `BlobIdMismatch`.
5. **Revoked** — already in `RevocationList` → `Revoked`.

Verified manifests are upserted. Unverified manifests are never stored (M2 acceptance: unsigned or wrong-key manifest is never written to the blob store — the catalog is the gate).

## RevocationList contract

| Operation | Behaviour |
|---|---|
| `revoke(blobId, publisherId, signature)` | Verifies signer is trusted and signature is valid, inserts revocation, deletes manifest and blob (via `BlobStore`). |
| `ingest(...)` | Same but for peer-received revocations; returns `false` if already revoked or invalid. |
| `isRevoked(blobId)` | Room query. |
| `orderedSyncBatch(entries)` | Returns `OrderedBatch(revocations, entries)` — revocations always first. Transport must send in this order. |
| `CatalogRepository.ingestSyncBatch` | Applies revocations before manifests; skips manifests for newly-revoked blobs. |

### Revocation payload

```
Cbor.encode(sortedMapOf("blobId" to blobId.bytes, "revokedAt" to revokedAt))
```

### Propagation ordering (M2)

The sync layer calls `orderedSyncBatch` and transmits `revocations + entries` in that order. The receiver calls `ingestSyncBatch` which enforces the same order. A test must prove: enqueue a large blob + a revocation for it, flush the queue, and assert the receiver deletes its local blob within one sync.

## CatalogRepository filtering

```kotlin
repository.query(
    category = Category.EDUCATION,  // null = all except REVOCATION
    appVersion = BuildConfig.VERSION_CODE,
    now = clock.now(),
)
// WHERE category = :category
//   AND minAppVersion <= :appVersion
//   AND (expiresAt IS NULL OR expiresAt > :now)
//   AND NOT isRevoked(blobId)
// ORDER BY priority DESC, publishedAt DESC
```

- `REVOCATION` category is never returned from queries — it lives in the revocation table.
- `minAppVersion` excludes entries the caller cannot handle.
- Expired entries are excluded (and were already rejected on `put`).
- Revoked blobs are excluded (defence in depth — `deleteRevoked` is also called after ingest).

## Module boundaries

- Depends on `core-crypto` (types, CBOR, CryptoProvider) and `core-content` (MerkleTree, BlobStore).
- Does not depend on transport — transport depends on this for the sync batch.

## Testing

```bash
./gradlew :core-catalog:testDebugUnitTest
```

- Use `InMemoryCryptoProvider` + in-memory Room (`Room.inMemoryDatabaseBuilder`) for unit tests.
- Use `InMemoryBlobStore` to assert revocation deletes the blob.
- Required adversarial tests (M2):
  - Unsigned manifest is rejected.
  - Wrong-key manifest is rejected.
  - Revocation propagates ahead of queued content (ordered batch test).
  - Revoked blob is deleted from `ManifestStore` and `BlobStore` within one sync.
  - Root rotation with signed transition succeeds; unsigned rotation is rejected.

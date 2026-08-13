# core-content

Content-addressed storage layer: chunking, Merkle tree, and blob store.

## Responsibilities

- **Chunking**: Content-defined chunking via Gear (Buzhash) rolling hash — target 1 MB, min 256 KB, max 4 MB. See `Chunking`.
- **Hashing**: SHA-256 chunk IDs (`ChunkId`) and Merkle root blob IDs (`BlobId`) via `MerkleTree`.
- **Models**: `Chunk` (id + bytes + index) and `Blob` (Merkle root + ordered chunks + totalBytes).
- **Persistence**: `BlobStore` interface with `DiskBlobStore` (encrypted file + Room index, SQLCipher) and `InMemoryBlobStore` (tests).
- **Database**: `ContentDatabase` (Room + SQLCipher) with `BlobEntity` and `ChunkEntity`.

## Locked decisions

- **DB**: Room + SQLCipher, minSdk 26.
- **Hash**: SHA-256 for chunks, Merkle root = `SHA-256(left || right)` with odd-node duplication.
- **Empty blob**: `BlobId = SHA-256("")`.
- **Chunking**: Gear rolling hash with `MASK_BITS=20` (avg 1 MB). Deterministic; no random seed.

## Chunking invariants

```
bytes --chunk--> List<Chunk> --reassemble--> bytes (byte-identical)
```

- `chunk(bytes).sumOf { it.bytes.size } == bytes.size`
- `reassemble(chunk(bytes)) == bytes`
- Each `Chunk.id == ChunkId(SHA-256(chunk.bytes))`
- Indices are contiguous 0..n-1; `reassemble` validates and sorts by index.

## Merkle tree

```
leaf = SHA-256(chunk bytes)
node = SHA-256(left || right)   // 32+32 bytes
odd  -> duplicated: hashPair(node, node)
root -> BlobId
```

- `MerkleTree.merkleRoot(leaves)` and `verify(chunks, root)` are the entry points.
- `buildProof` / `verifyProof` support selective chunk verification (future: partial fetch).
- Python backend must use identical construction — golden vectors cover this.

## BlobStore contract

| Method | Behaviour |
|---|---|
| `put(blobId, bytes)` | Verifies `MerkleRoot(chunk(bytes)) == blobId`, writes atomically, indexes chunks. |
| `get(blobId)` | Returns bytes if present and Merkle-verified; deletes corrupt entries and returns null. |
| `has` / `list` / `delete` | Straightforward index queries. |
| `pin` / `unpin` / `isPinned` | Pins are excluded from LRU eviction. |
| `lruEvict(quota)` | Evicts LRU unpinned blobs oldest-first until `totalBytes <= quota`. Returns evicted count. |

### File layout (DiskBlobStore)

```
<filesDir>/sharenet/blobs/<hex>       // blob bytes
Room table `blobs`                    // metadata + LRU state
Room table `chunks`                   // per-chunk offsets + hashes
```

- Files are written to `<hex>.tmp` then atomically renamed.
- Corrupt reads (Merkle mismatch) delete both file and index.
- Room is accessed via `Mutex` for thread safety; I/O on `Dispatchers.IO`.
- SQLCipher passphrase is provisioned via `AndroidKeystoreWrapper` (see `core-crypto`).

## Resumable partial blobs (M1 acceptance)

`DiskBlobStore` + `ChunkEntity` offsets enable fetching missing chunks without re-downloading the whole blob. The transport layer queries `ChunkDao.getByBlob` to determine which chunks are present.

## Testing

```bash
./gradlew :core-content:testDebugUnitTest
```

- Use `InMemoryBlobStore` in unit tests — no I/O, no Room, deterministic.
- `DiskBlobStore` tests run as instrumented tests with SQLCipher (or Robolectric with an in-memory Room fallback).
- Assertions to cover:
  - 3 GB file chunks and reassembles byte-identically (use a streaming test helper, not a literal 3 GB array in unit tests).
  - Corrupt one chunk → `get` returns null and deletes the entry.
  - Interrupt at 40% → remaining chunks are indexed and resumable.
  - Quota eviction never evicts a pinned blob.

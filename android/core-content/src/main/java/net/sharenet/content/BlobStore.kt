package net.sharenet.content

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import net.sharenet.content.db.BlobEntity
import net.sharenet.content.db.ChunkEntity
import net.sharenet.content.db.ContentDatabase
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.ChunkId
import java.io.File

/**
 * Abstraction over blob persistence.
 *
 * Blobs are content-addressed by [BlobId] (Merkle root). Implementations
 * must verify integrity on read and enforce pinning / LRU semantics.
 */
interface BlobStore {

    /** Compute [BlobId], store [bytes], and return the ID. */
    suspend fun put(bytes: ByteArray): BlobId {
        val chunks = Chunking.chunk(bytes)
        val blobId = if (chunks.isEmpty()) MerkleTree.merkleRoot(emptyList())
        else MerkleTree.merkleRoot(chunks.map { it.id })
        put(blobId, bytes)
        return blobId
    }

    /** Store [bytes] under [blobId]. Overwrites if already present. */
    suspend fun put(blobId: BlobId, bytes: ByteArray, mimeType: String = "application/octet-stream")

    /** Retrieve blob bytes, or `null` if absent or corrupt (corrupt entries are deleted). */
    suspend fun get(blobId: BlobId): ByteArray?

    /** Delete the blob and its index entries. No-op if absent. */
    suspend fun delete(blobId: BlobId)

    /** Whether the blob is present and intact. */
    suspend fun has(blobId: BlobId): Boolean

    /** Whether the blob is present and intact (alias for has). */
    suspend fun contains(blobId: BlobId): Boolean = has(blobId)

    /** List all stored blob IDs (most-recently-accessed first). */
    suspend fun list(): List<BlobId>

    /** Pin [blobId] to exclude it from LRU eviction. */
    suspend fun pin(blobId: BlobId)

    /** Unpin [blobId] so it becomes evictable. */
    suspend fun unpin(blobId: BlobId)

    /** Whether [blobId] is pinned. */
    suspend fun isPinned(blobId: BlobId): Boolean

    /** Store a single chunk (for resumable assembly). Defaults to no-op. */
    suspend fun putChunk(blobId: BlobId, index: Int, chunk: ByteArray) {}

    /** Assemble blob from stored chunks, verifying Merkle root. Defaults to null. */
    suspend fun assemble(blobId: net.sharenet.crypto.BlobId, chunkIds: List<net.sharenet.crypto.ChunkId>): ByteArray? = null

    /** Total bytes stored across all unpinned blobs. */
    suspend fun sizeBytes(): Long

    /**
     * Evict least-recently-used unpinned blobs until total stored bytes <= [quotaBytes].
     * @return Number of blobs evicted.
     */
    suspend fun lruEvict(quotaBytes: Long): Int

    /** Alias for lruEvict with a default quota if needed. */
    suspend fun evictIfNeeded() { /* default no-op or implementation specific */ }
}

// ---------------------------------------------------------------------------
// Disk-backed implementation (encrypted file + Room index)
// ---------------------------------------------------------------------------

/**
 * Disk-backed [BlobStore] using a file directory + [ContentDatabase] index.
 *
 * Files are stored under [blobsDir]/<hex>. On devices with encryption at rest
 * the directory is on an encrypted partition; SQLCipher encrypts the index.
 * Chunk metadata is indexed for partial-blob resumption and per-chunk verification.
 *
 * @param blobsDir Directory for blob files (created if absent).
 * @param db Room database (SQLCipher-backed).
 */
class DiskBlobStore(
    private val blobsDir: File,
    private val db: ContentDatabase,
) : BlobStore {

    private val mutex = Mutex()

    init {
        if (!blobsDir.exists()) blobsDir.mkdirs()
    }

    override suspend fun put(blobId: BlobId, bytes: ByteArray, mimeType: String) = mutex.withLock {
        withContext(Dispatchers.IO) {
            val hex = blobId.bytes.toHex()
            val chunks = Chunking.chunk(bytes)
            val computed = if (chunks.isEmpty()) MerkleTree.merkleRoot(emptyList())
            else MerkleTree.merkleRoot(chunks.map { it.id })
            require(computed == blobId) {
                "BlobId mismatch on put: expected $blobId, computed $computed"
            }
            // Write file atomically
            val tmp = File(blobsDir, "$hex.tmp")
            val dst = File(blobsDir, hex)
            tmp.writeBytes(bytes)
            if (dst.exists()) dst.delete()
            tmp.renameTo(dst)

            val now = System.currentTimeMillis()
            db.blobDao().upsert(
                BlobEntity(
                    blobIdHex = hex,
                    totalBytes = bytes.size.toLong(),
                    mimeType = mimeType,
                    chunkCount = chunks.size,
                    pinned = db.blobDao().getById(hex)?.pinned ?: false,
                    createdAt = db.blobDao().getById(hex)?.createdAt ?: now,
                    lastAccessed = now,
                ),
            )
            // Index chunks with offsets
            var offset = 0L
            val entities = chunks.map { c ->
                ChunkEntity(
                    blobIdHex = hex,
                    chunkIdHex = c.id.bytes.toHex(),
                    chunkIndex = c.index,
                    sizeBytes = c.bytes.size,
                    offset = offset.also { offset += c.bytes.size },
                    sha256Hex = c.id.bytes.toHex(),
                )
            }
            db.chunkDao().replaceForBlob(hex, entities)
        }
    }

    override suspend fun get(blobId: BlobId): ByteArray? = mutex.withLock {
        withContext(Dispatchers.IO) {
            val hex = blobId.bytes.toHex()
            val file = File(blobsDir, hex)
            if (!file.exists()) return@withContext null
            val bytes = file.readBytes()
            // Verify Merkle root
            val chunks = Chunking.chunk(bytes)
            val computed = if (chunks.isEmpty()) MerkleTree.merkleRoot(emptyList())
            else MerkleTree.merkleRoot(chunks.map { it.id })
            if (computed != blobId) {
                // Corrupt — delete
                file.delete()
                db.blobDao().deleteById(hex)
                db.chunkDao().deleteByBlob(hex)
                return@withContext null
            }
            db.blobDao().touch(hex, System.currentTimeMillis())
            bytes
        }
    }

    override suspend fun delete(blobId: BlobId) = mutex.withLock {
        withContext(Dispatchers.IO) {
            val hex = blobId.bytes.toHex()
            File(blobsDir, hex).delete()
            File(blobsDir, "$hex.tmp").delete()
            db.blobDao().deleteById(hex)
            db.chunkDao().deleteByBlob(hex)
        }
    }

    override suspend fun has(blobId: BlobId): Boolean {
        val hex = blobId.bytes.toHex()
        if (!File(blobsDir, hex).exists()) return false
        return db.blobDao().exists(hex)
    }

    override suspend fun list(): List<BlobId> {
        val entities = db.blobDao().listAll()
        return entities.map { BlobId(it.blobIdHex.hexToBytes()) }
    }

    override suspend fun pin(blobId: BlobId) {
        db.blobDao().setPinned(blobId.bytes.toHex(), true)
    }

    override suspend fun unpin(blobId: BlobId) {
        db.blobDao().setPinned(blobId.bytes.toHex(), false)
    }

    override suspend fun isPinned(blobId: BlobId): Boolean {
        val e = db.blobDao().getById(blobId.bytes.toHex()) ?: return false
        return e.pinned
    }

    override suspend fun sizeBytes(): Long {
        return db.blobDao().totalBytes() ?: 0L
    }

    override suspend fun lruEvict(quotaBytes: Long): Int = mutex.withLock {
        withContext(Dispatchers.IO) {
            val total = db.blobDao().totalBytes() ?: 0L
            if (total <= quotaBytes) return@withContext 0
            var reclaimed = 0L
            var evicted = 0
            val candidates = db.blobDao().lruUnpinned()
            for (entity in candidates) {
                if (total - reclaimed <= quotaBytes) break
                File(blobsDir, entity.blobIdHex).delete()
                db.blobDao().deleteById(entity.blobIdHex)
                db.chunkDao().deleteByBlob(entity.blobIdHex)
                reclaimed += entity.totalBytes
                evicted++
            }
            evicted
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation for tests
// ---------------------------------------------------------------------------

/**
 * In-memory [BlobStore] for unit tests — no I/O, no Room.
 */
class InMemoryBlobStore : BlobStore {

    private data class Entry(
        val bytes: ByteArray,
        val mimeType: String,
        var pinned: Boolean = false,
        var lastAccessed: Long = System.nanoTime(),
    )

    private val store = mutableMapOf<String, Entry>()
    private val mutex = Mutex()

    override suspend fun put(blobId: BlobId, bytes: ByteArray, mimeType: String) = mutex.withLock {
        val hex = blobId.bytes.toHex()
        val chunks = Chunking.chunk(bytes)
        val computed = if (chunks.isEmpty()) MerkleTree.merkleRoot(emptyList())
        else MerkleTree.merkleRoot(chunks.map { it.id })
        require(computed == blobId) { "BlobId mismatch on put" }
        val existing = store[hex]
        store[hex] = Entry(bytes.copyOf(), mimeType, pinned = existing?.pinned ?: false, lastAccessed = System.nanoTime())
    }

    override suspend fun get(blobId: BlobId): ByteArray? = mutex.withLock {
        val hex = blobId.bytes.toHex()
        val entry = store[hex] ?: return@withLock null
        // Verify
        val chunks = Chunking.chunk(entry.bytes)
        val computed = if (chunks.isEmpty()) MerkleTree.merkleRoot(emptyList())
        else MerkleTree.merkleRoot(chunks.map { it.id })
        if (computed != blobId) {
            store.remove(hex)
            return@withLock null
        }
        entry.lastAccessed = System.nanoTime()
        entry.bytes.copyOf()
    }

    override suspend fun delete(blobId: BlobId) {
        mutex.withLock { store.remove(blobId.bytes.toHex()) }
    }

    override suspend fun has(blobId: BlobId): Boolean = mutex.withLock {
        store.containsKey(blobId.bytes.toHex())
    }

    override suspend fun list(): List<BlobId> = mutex.withLock {
        store.entries.sortedByDescending { it.value.lastAccessed }
            .map { BlobId(it.key.hexToBytes()) }
    }

    override suspend fun pin(blobId: BlobId) = mutex.withLock {
        store[blobId.bytes.toHex()]?.pinned = true
    }

    override suspend fun unpin(blobId: BlobId) = mutex.withLock {
        store[blobId.bytes.toHex()]?.pinned = false
    }

    override suspend fun isPinned(blobId: BlobId): Boolean = mutex.withLock {
        store[blobId.bytes.toHex()]?.pinned ?: false
    }

    override suspend fun lruEvict(quotaBytes: Long): Int = mutex.withLock {
        var total = store.values.sumOf { it.bytes.size.toLong() }
        if (total <= quotaBytes) return@withLock 0
        val sorted = store.entries.filter { !it.value.pinned }.sortedBy { it.value.lastAccessed }
        var evicted = 0
        for (e in sorted) {
            if (total <= quotaBytes) break
            store.remove(e.key)
            total -= e.value.bytes.size
            evicted++
        }
        evicted
    }

    override suspend fun sizeBytes(): Long = mutex.withLock { store.values.sumOf { it.bytes.size.toLong() } }
}

// ---------------------------------------------------------------------------
// Hex helpers (mirrors core-crypto's internal helpers — duplicated to avoid
// exposing them as public API from core-crypto)
// ---------------------------------------------------------------------------

private fun ByteArray.toHex(): String {
    val chars = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        chars[i * 2] = "0123456789abcdef"[v ushr 4]
        chars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
    }
    return String(chars)
}

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0)
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        out[i] = ((hexChar(i * 2) shl 4) or hexChar(i * 2 + 1)).toByte()
    }
    return out
}

private fun String.hexChar(idx: Int): Int = when (val c = this[idx]) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("Invalid hex char: $c")
}

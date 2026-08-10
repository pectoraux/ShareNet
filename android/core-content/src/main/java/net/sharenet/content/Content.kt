package net.sharenet.content

import net.sharenet.crypto.BlobId
import net.sharenet.crypto.ChunkId
import java.io.File

/**
 * Blob storage and chunking contracts.
 * Real implementation does rolling-hash chunking, Merkle trees, LRU eviction.
 */

/** Chunking interface — rolling hash with target 1 MB, min 256 KB, max 4 MB. */
interface Chunker {
    /** Split [data] into ordered chunks. */
    fun chunk(data: ByteArray): List<ByteArray>
    /** SHA-256 chunk id. */
    fun chunkId(chunk: ByteArray): ChunkId
    /** Merkle root over ordered chunk ids. */
    fun merkleRoot(chunkIds: List<ChunkId>): BlobId
}

/** Metadata about locally stored blobs. */
data class BlobAvailability(
    val blobId: BlobId,
    val totalBytes: Long,
    val availableBytes: Long,
    val isComplete: Boolean,
    val pinned: Boolean,
)

/** Resolver that maps blobId → local availability. */
interface LocalAvailability {
    suspend fun query(blobId: BlobId): BlobAvailability?
    suspend fun listAll(): List<BlobAvailability>
}

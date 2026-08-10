package net.sharenet.content

import net.sharenet.crypto.BlobId
import net.sharenet.crypto.ChunkId

/**
 * A single content chunk produced by [Chunking.chunk].
 *
 * @property id SHA-256 of [bytes] — the content address.
 * @property bytes Raw chunk bytes (256 KB – 4 MB, target 1 MB).
 * @property index Ordinal position in the original blob (0-based).
 */
data class Chunk(
    val id: ChunkId,
    val bytes: ByteArray,
    val index: Int,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Chunk) return false
        return id == other.id && index == other.index && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + bytes.contentHashCode()
        result = 31 * result + index
        return result
    }
}

/**
 * A logical blob — the unit addressed by [BlobId] (Merkle root).
 *
 * @property id Merkle root of [chunks].
 * @property chunks Ordered chunks (Merkle leaves).
 * @property totalBytes Sum of chunk sizes.
 * @property mimeType IANA media type.
 */
data class Blob(
    val id: BlobId,
    val chunks: List<Chunk>,
    val totalBytes: Long,
    val mimeType: String,
) {
    init {
        require(chunks.isNotEmpty() || totalBytes == 0L) { "Non-empty blob must have chunks" }
        if (chunks.isNotEmpty()) {
            val computed = MerkleTree.merkleRoot(chunks.map { it.id })
            require(computed == id) { "BlobId mismatch: expected $computed, got $id" }
        }
    }
}

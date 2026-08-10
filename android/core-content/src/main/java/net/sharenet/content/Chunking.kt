package net.sharenet.content

import net.sharenet.crypto.ChunkId

/**
 * Content-defined chunking using a Gear / Buzhash rolling hash.
 *
 * Target chunk size: 1 MB, min 256 KB, max 4 MB (as per M1 spec).
 * Chunk boundaries are determined by the rolling hash masking, making
 * chunking stable under insertions (deduplication-friendly).
 *
 * This is a pure-Kotlin implementation with no native dependencies.
 */
object Chunking {

    const val TARGET_SIZE: Int = 1024 * 1024       // 1 MB
    const val MIN_SIZE: Int = 256 * 1024            // 256 KB
    const val MAX_SIZE: Int = 4 * 1024 * 1024       // 4 MB

    // Mask for boundary decision: 2^20 = 1 MB average target.
    // When (gearHash & mask) == 0 we cut, but only after MIN_SIZE.
    private const val MASK_BITS = 20
    private const val MASK: Long = (1L shl MASK_BITS) - 1

    // Gear table: 256 pseudo-random 64-bit values derived from splitmix64
    private val GEAR_TABLE: LongArray = LongArray(256) { i ->
        var z = (i.toLong() + 0x9E3779B97F4A7C15u.toLong())
        z = (z xor (z ushr 30)) * 0xBF58476D1CE4E5B9u.toLong()
        z = (z xor (z ushr 27)) * 0x94D049BB133111EBu.toLong()
        z xor (z ushr 31)
    }

    /**
     * Split [bytes] into content-defined [Chunk]s.
     *
     * @return Ordered list of chunks with computed [ChunkId] and [Chunk.index].
     */
    fun chunk(bytes: ByteArray): List<Chunk> {
        if (bytes.isEmpty()) return emptyList()
        val chunks = mutableListOf<Chunk>()
        var start = 0
        var hash = 0L
        var idx = 0

        for (i in bytes.indices) {
            // Gear update: hash = (hash << 1) + GEAR[byte]
            hash = (hash shl 1) + GEAR_TABLE[bytes[i].toInt() and 0xFF]
            val pos = i + 1
            val windowSize = pos - start
            val shouldCut = when {
                windowSize >= MAX_SIZE -> true
                windowSize >= MIN_SIZE && (hash and MASK) == 0L -> true
                else -> false
            }
            if (shouldCut) {
                val slice = bytes.copyOfRange(start, pos)
                val id = ChunkId(MerkleTree.sha256(slice))
                chunks.add(Chunk(id = id, bytes = slice, index = idx++))
                start = pos
                hash = 0L
            }
        }
        // Tail chunk
        if (start < bytes.size) {
            val slice = bytes.copyOfRange(start, bytes.size)
            val id = ChunkId(MerkleTree.sha256(slice))
            chunks.add(Chunk(id = id, bytes = slice, index = idx))
        }
        return chunks
    }

    /**
     * Reassemble [chunks] into the original byte array.
     * Chunks are ordered by [Chunk.index] before concatenation.
     *
     * @throws IllegalArgumentException if chunks are empty but expected non-empty is not handled.
     */
    fun reassemble(chunks: List<Chunk>): ByteArray {
        if (chunks.isEmpty()) return ByteArray(0)
        val sorted = chunks.sortedBy { it.index }
        // Validate contiguous indices
        for (i in sorted.indices) {
            require(sorted[i].index == i) { "Missing chunk index $i (got ${sorted[i].index})" }
        }
        val total = sorted.sumOf { it.bytes.size }
        val out = ByteArray(total)
        var off = 0
        for (c in sorted) {
            System.arraycopy(c.bytes, 0, out, off, c.bytes.size)
            off += c.bytes.size
        }
        return out
    }

    /**
     * Reassemble and verify against [expectedRoot].
     * @return The reassembled bytes if verification succeeds, `null` otherwise.
     */
    suspend fun reassembleAndVerify(chunks: List<Chunk>, expectedRoot: net.sharenet.crypto.BlobId): ByteArray? {
        if (!MerkleTree.verify(chunks, expectedRoot)) return null
        return reassemble(chunks)
    }
}

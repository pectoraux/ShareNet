package net.sharenet.content

import net.sharenet.crypto.BlobId
import net.sharenet.crypto.ChunkId
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/**
 * Merkle tree utilities for ShareNet content addressing.
 *
 * - Leaf hash = SHA-256(chunk bytes) == [ChunkId].
 * - Internal node = SHA-256(left || right).
 * - Odd node at any level is duplicated (hashed with itself).
 * - Single leaf: root == leaf hash.
 * - Empty blob: root == SHA-256(empty) (defined as 32 zero bytes hashed once).
 *
 * This construction is deterministic and shared with the backend Python
 * implementation via golden vectors.
 */
object MerkleTree {

    /** SHA-256 of [bytes]. */
    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    /** SHA-256 of the concatenation of [left] and [right] (each 32 bytes). */
    fun hashPair(left: ByteArray, right: ByteArray): ByteArray {
        require(left.size == 32 && right.size == 32) { "hashPair requires 32-byte inputs" }
        val md = MessageDigest.getInstance("SHA-256")
        md.update(left)
        md.update(right)
        return md.digest()
    }

    /**
     * Compute Merkle root from ordered chunk hashes.
     * @param leaves Ordered [ChunkId] list (Merkle leaves).
     * @return [BlobId] — 32-byte root.
     */
    fun merkleRoot(leaves: List<ChunkId>): BlobId {
        if (leaves.isEmpty()) {
            // Empty blob: defined as SHA-256("") — matches Python backend.
            return BlobId(sha256(ByteArray(0)))
        }
        if (leaves.size == 1) return BlobId(leaves[0].bytes.copyOf())
        var level: List<ByteArray> = leaves.map { it.bytes.copyOf() }
        while (level.size > 1) {
            val next = mutableListOf<ByteArray>()
            var i = 0
            while (i < level.size) {
                val left = level[i]
                val right = if (i + 1 < level.size) level[i + 1] else left // duplicate odd
                next.add(hashPair(left, right))
                i += 2
            }
            level = next
        }
        return BlobId(level[0])
    }

    /**
     * Compute Merkle root directly from raw chunk byte arrays.
     * Convenience for callers that have not yet hashed.
     */
    fun merkleRootFromBytes(chunks: List<ByteArray>): BlobId {
        val leaves = chunks.map { ChunkId(sha256(it)) }
        return merkleRoot(leaves)
    }

    /**
     * Verify that [chunks] hash to [expectedRoot].
     * Uses parallel hashing for efficiency on multi-core devices.
     * @return `true` iff the recomputed root equals [expectedRoot].
     */
    suspend fun verify(chunks: List<Chunk>, expectedRoot: BlobId): Boolean = coroutineScope {
        if (chunks.isEmpty()) return@coroutineScope merkleRoot(emptyList()) == expectedRoot
        
        // Verify each chunk's id matches its bytes in parallel
        val verified = chunks.map { c ->
            async(Dispatchers.Default) {
                sha256(c.bytes).contentEquals(c.id.bytes)
            }
        }.awaitAll().all { it }
        
        if (!verified) return@coroutineScope false
        
        val sorted = chunks.sortedBy { it.index }
        val leaves = sorted.map { it.id }
        merkleRoot(leaves) == expectedRoot
    }

    /**
     * Build a Merkle proof for chunk at [index] (for future selective verification).
     * Returns the sibling hashes from leaf to root.
     */
    fun buildProof(leaves: List<ChunkId>, index: Int): List<ByteArray> {
        require(index in leaves.indices) { "Index $index out of bounds for ${leaves.size} leaves" }
        if (leaves.size == 1) return emptyList()
        var level: List<ByteArray> = leaves.map { it.bytes.copyOf() }
        var idx = index
        val proof = mutableListOf<ByteArray>()
        while (level.size > 1) {
            val siblingIdx = if (idx % 2 == 0) {
                if (idx + 1 < level.size) idx + 1 else idx
            } else idx - 1
            proof.add(level[siblingIdx])
            // Build next level
            val next = mutableListOf<ByteArray>()
            var i = 0
            while (i < level.size) {
                val left = level[i]
                val right = if (i + 1 < level.size) level[i + 1] else left
                next.add(hashPair(left, right))
                i += 2
            }
            level = next
            idx /= 2
        }
        return proof
    }

    /**
     * Verify a Merkle proof.
     * @param leafHash SHA-256 of the chunk bytes.
     * @param proof Sibling hashes from [buildProof].
     * @param index Leaf index.
     * @param root Expected Merkle root.
     */
    fun verifyProof(leafHash: ByteArray, proof: List<ByteArray>, index: Int, root: BlobId): Boolean {
        var hash = leafHash
        var idx = index
        for (sibling in proof) {
            hash = if (idx % 2 == 0) hashPair(hash, sibling) else hashPair(sibling, hash)
            idx /= 2
        }
        return hash.contentEquals(root.bytes)
    }
}

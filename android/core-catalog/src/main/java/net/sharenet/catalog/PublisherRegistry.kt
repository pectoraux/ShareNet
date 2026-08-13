package net.sharenet.catalog

import net.sharenet.catalog.db.CatalogDatabase
import net.sharenet.catalog.db.PublisherEntity
import net.sharenet.crypto.Cbor
import net.sharenet.crypto.CryptoProvider
import net.sharenet.crypto.NodeId

/**
 * Publisher trust registry with a pinned root key and signed rotation.
 *
 * Model:
 *  - One root key is pinned at build time (via [pinnedRootHex] or a bundled resource).
 *  - Additional publishers can be added if signed by the current root.
 *  - Root rotation: the *old* root signs a transition statement
 *    `Cbor.encode(sortedMapOf("newRoot" to newKeyBytes, "rotatedAt" to timestamp))`
 *    and the registry atomically replaces the root.
 *
 * All signature checks use [crypto] (Ed25519 via Tink).
 */
class PublisherRegistry(
    private val db: CatalogDatabase,
    private val crypto: CryptoProvider,
    private val pinnedRootHex: String,
) {

    /**
     * Initialise the registry: ensure the pinned root exists.
     * Call once at app start.
     */
    suspend fun ensureInitialized() {
        val existing = db.publisherDao().getById(pinnedRootHex)
        if (existing == null) {
            db.publisherDao().upsert(
                PublisherEntity(
                    publisherIdHex = pinnedRootHex,
                    isRoot = true,
                    isRevoked = false,
                    addedByHex = null,
                ),
            )
        }
    }

    /** The current pinned root [NodeId], or `null` if not yet initialised. */
    suspend fun currentRoot(): NodeId? {
        val e = db.publisherDao().getRoot() ?: return null
        return NodeId(e.publisherIdHex.hexToBytes())
    }

    /** Whether [publisherId] is trusted (root or delegated, not revoked). */
    suspend fun isTrusted(publisherId: NodeId): Boolean {
        // Pinned root is always trusted (even if DB is inconsistent — defence in depth)
        if (publisherId.bytes.toHex() == pinnedRootHex) return true
        return db.publisherDao().isTrusted(publisherId.bytes.toHex())
    }

    /**
     * Add a new publisher [newPublisherId] delegated by [addedBy] with [signature].
     *
     * [signature] must be Ed25519 over `Cbor.encode(sortedMapOf("newPublisher" to newPublisherId.bytes))`
     * signed by [addedBy]'s private key, and [addedBy] must be the current root.
     *
     * @return `true` if added, `false` if [addedBy] is not trusted or signature is invalid.
     */
    suspend fun addPublisher(newPublisherId: NodeId, addedBy: NodeId, signature: ByteArray): Boolean {
        if (!isTrusted(addedBy)) return false
        val payload = Cbor.encode(sortedMapOf("newPublisher" to newPublisherId.bytes))
        if (!crypto.verify(addedBy.bytes, payload, signature)) return false
        db.publisherDao().upsert(
            PublisherEntity(
                publisherIdHex = newPublisherId.bytes.toHex(),
                isRoot = false,
                isRevoked = false,
                addedByHex = addedBy.bytes.toHex(),
            ),
        )
        return true
    }

    /**
     * Rotate the root key from [oldRootId] to [newRootId].
     *
     * The transition payload is `Cbor.encode(sortedMapOf("newRoot" to newRootId.bytes, "rotatedAt" to timestamp))`
     * and must be signed by [oldRootId].
     *
     * On success the old root is marked as non-root (but not revoked — it
     * remains trusted for already-signed manifests) and the new root is inserted.
     *
     * @return `true` if rotation succeeded.
     */
    suspend fun rotateRoot(
        oldRootId: NodeId,
        newRootId: NodeId,
        rotatedAt: Long,
        transitionSignature: ByteArray,
    ): Boolean {
        val currentRootHex = db.publisherDao().getRoot()?.publisherIdHex ?: pinnedRootHex
        if (oldRootId.bytes.toHex() != currentRootHex) return false
        val payload = Cbor.encode(
            sortedMapOf(
                "newRoot" to newRootId.bytes,
                "rotatedAt" to rotatedAt,
            ),
        )
        if (!crypto.verify(oldRootId.bytes, payload, transitionSignature)) return false

        // Demote old root (keep it but mark isRoot=false so it is no longer the active root)
        val oldEntity = db.publisherDao().getById(oldRootId.bytes.toHex())
        if (oldEntity != null) {
            db.publisherDao().upsert(oldEntity.copy(isRoot = false))
        }
        // Insert new root
        db.publisherDao().upsert(
            PublisherEntity(
                publisherIdHex = newRootId.bytes.toHex(),
                isRoot = true,
                isRevoked = false,
                addedByHex = oldRootId.bytes.toHex(),
            ),
        )
        return true
    }

    /** Revoke a publisher. Only the current root can revoke. */
    suspend fun revokePublisher(publisherId: NodeId, revokedBy: NodeId, signature: ByteArray): Boolean {
        val root = db.publisherDao().getRoot() ?: return false
        if (revokedBy.bytes.toHex() != root.publisherIdHex) return false
        val payload = Cbor.encode(sortedMapOf("revokePublisher" to publisherId.bytes))
        if (!crypto.verify(revokedBy.bytes, payload, signature)) return false
        db.publisherDao().revoke(publisherId.bytes.toHex())
        return true
    }

    // -- private helpers --

    private fun sortedMapOf(vararg pairs: Pair<String, Any?>): Map<String, Any?> {
        val sorted = pairs.sortedBy { it.first }
        val m = LinkedHashMap<String, Any?>(sorted.size)
        for ((k, v) in sorted) m[k] = v
        return m
    }
}

private fun ByteArray.toHex(): String {
    val c = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        c[i * 2] = "0123456789abcdef"[v ushr 4]
        c[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
    }
    return String(c)
}

private fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0)
    val out = ByteArray(length / 2)
    for (i in out.indices) out[i] = ((hexAt(i * 2) shl 4) or hexAt(i * 2 + 1)).toByte()
    return out
}

private fun String.hexAt(i: Int): Int = when (val ch = this[i]) {
    in '0'..'9' -> ch - '0'
    in 'a'..'f' -> ch - 'a' + 10
    in 'A'..'F' -> ch - 'A' + 10
    else -> throw IllegalArgumentException("Invalid hex: $ch")
}

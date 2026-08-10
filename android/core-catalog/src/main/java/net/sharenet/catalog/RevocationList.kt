package net.sharenet.catalog

import net.sharenet.catalog.db.CatalogDatabase
import net.sharenet.catalog.db.RevocationEntity
import net.sharenet.content.BlobStore
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.CatalogEntry
import net.sharenet.crypto.Cbor
import net.sharenet.crypto.CryptoProvider
import net.sharenet.crypto.NodeId

/**
 * Revocation list with strict priority propagation.
 *
 * Invariants (per M2 acceptance criteria):
 *  - A revocation entry has [CatalogEntry.PRIORITY_REVOCATION] (`Int.MAX_VALUE`) —
 *    the maximum priority. Sync and transport layers must order revocations
 *    strictly before normal content.
 *  - Adding a revocation immediately deletes the manifest (if present) and
 *    deletes the blob from [blobStore] (if present). Deletion is best-effort
 *    but must be attempted within one catalog sync.
 *  - Revocation signatures are verified via [crypto] and the publisher must be
 *    trusted via [publisherRegistry].
 *
 * Revocation payload (signed):
 * ```
 * Cbor.encode(sortedMapOf(
 *     "blobId"    to blobId.bytes,
 *     "revokedAt" to revokedAt,
 * ))
 * ```
 */
class RevocationList(
    private val db: CatalogDatabase,
    private val crypto: CryptoProvider,
    private val publisherRegistry: PublisherRegistry,
    private val blobStore: BlobStore? = null, // nullable for tests without a store
) {

    /**
     * Revoke [blobId] on behalf of [publisherId].
     *
     * @param signature Ed25519 over [revocationPayload] signed by [publisherId].
     * @throws RevocationException if verification fails.
     */
    suspend fun revoke(
        blobId: BlobId,
        publisherId: NodeId,
        revokedAt: Long = System.currentTimeMillis(),
        reason: String = "",
        signature: ByteArray,
    ) {
        if (!publisherRegistry.isTrusted(publisherId)) {
            throw RevocationException.UntrustedPublisher(publisherId)
        }
        val payload = revocationPayload(blobId, revokedAt)
        if (!crypto.verify(publisherId.bytes, payload, signature)) {
            throw RevocationException.BadSignature(blobId, publisherId)
        }
        val hex = blobId.bytes.toHex()
        db.revocationDao().upsert(
            RevocationEntity(
                blobIdHex = hex,
                publisherIdHex = publisherId.bytes.toHex(),
                revokedAt = revokedAt,
                reason = reason,
                signatureHex = signature.toHex(),
            ),
        )
        // Immediate local enforcement: delete manifest and blob
        db.manifestDao().deleteById(hex)
        try {
            blobStore?.delete(blobId)
        } catch (_: Exception) {
            // Best-effort — blob deletion failure should not roll back the revocation
        }
    }

    /**
     * Ingest a revocation received from a peer (no local signature generation).
     * Verifies and then enforces as above.
     *
     * @return `true` if accepted, `false` if already revoked or verification failed.
     */
    suspend fun ingest(
        blobId: BlobId,
        publisherId: NodeId,
        revokedAt: Long,
        reason: String,
        signature: ByteArray,
    ): Boolean {
        val hex = blobId.bytes.toHex()
        if (db.revocationDao().isRevoked(hex)) return false
        return try {
            revoke(blobId, publisherId, revokedAt, reason, signature)
            true
        } catch (_: RevocationException) {
            false
        }
    }

    /** Whether [blobId] is revoked. */
    suspend fun isRevoked(blobId: BlobId): Boolean =
        db.revocationDao().isRevoked(blobId.bytes.toHex())

    /** All revocation entries, newest first. */
    suspend fun listAll(): List<RevocationEntry> =
        db.revocationDao().listAll().map { it.toEntry() }

    /**
     * Ordered sync batch: revocations first (priority = MAX), then content.
     *
     * Transport layers should call this to build the send queue. Revocations
     * are always placed ahead of catalog entries.
     */
    suspend fun orderedSyncBatch(
        catalogEntries: List<CatalogEntry>,
    ): OrderedBatch {
        val revocations = listAll()
        return OrderedBatch(
            revocations = revocations,
            entries = catalogEntries.sortedByDescending { it.priority },
        )
    }

    /** Revocation payload bytes for signing / verification. */
    fun revocationPayload(blobId: BlobId, revokedAt: Long): ByteArray =
        Cbor.encode(
            sortedMapOf(
                "blobId" to blobId.bytes,
                "revokedAt" to revokedAt,
            ),
        )

    private fun RevocationEntity.toEntry(): RevocationEntry = RevocationEntry(
        blobId = BlobId(blobIdHex.hexToBytes()),
        publisherId = NodeId(publisherIdHex.hexToBytes()),
        revokedAt = revokedAt,
        reason = reason,
        signature = signatureHex.hexToBytes(),
    )

    private fun sortedMapOf(vararg pairs: Pair<String, Any?>): Map<String, Any?> {
        val sorted = pairs.sortedBy { it.first }
        val m = LinkedHashMap<String, Any?>(sorted.size)
        for ((k, v) in sorted) m[k] = v
        return m
    }
}

/**
 * Domain-level revocation entry (decoded from [RevocationEntity]).
 */
data class RevocationEntry(
    val blobId: BlobId,
    val publisherId: NodeId,
    val revokedAt: Long,
    val reason: String,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RevocationEntry) return false
        return blobId == other.blobId &&
            publisherId == other.publisherId &&
            revokedAt == other.revokedAt &&
            reason == other.reason &&
            signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var r = blobId.hashCode()
        r = 31 * r + publisherId.hashCode()
        r = 31 * r + revokedAt.hashCode()
        r = 31 * r + reason.hashCode()
        r = 31 * r + signature.contentHashCode()
        return r
    }
}

/**
 * Ordered batch for sync: revocations MUST be sent and applied before entries.
 */
data class OrderedBatch(
    val revocations: List<RevocationEntry>,
    val entries: List<CatalogEntry>,
)

/** Thrown when a revocation fails verification. */
sealed class RevocationException(message: String) : Exception(message) {
    class UntrustedPublisher(val publisher: NodeId) :
        RevocationException("Untrusted publisher $publisher")
    class BadSignature(val blobId: BlobId, val publisher: NodeId) :
        RevocationException("Bad revocation signature for $blobId from $publisher")
}

// -- hex helpers --

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
    for (i in out.indices) out[i] = ((hexVal(this[i * 2]) shl 4) or hexVal(this[i * 2 + 1])).toByte()
    return out
}

private fun hexVal(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("Invalid hex: $c")
}

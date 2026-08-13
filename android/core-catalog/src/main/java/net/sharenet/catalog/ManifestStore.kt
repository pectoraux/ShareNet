package net.sharenet.catalog

import net.sharenet.catalog.db.CatalogDatabase
import net.sharenet.catalog.db.ManifestEntity
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.CatalogEntry
import net.sharenet.crypto.Category
import net.sharenet.crypto.ChunkId
import net.sharenet.crypto.CryptoProvider
import net.sharenet.crypto.Manifest
import net.sharenet.crypto.NodeId
import org.json.JSONArray

/**
 * Room-backed manifest store with mandatory signature verification.
 *
 * Every [put] call:
 *  1. Rejects expired manifests.
 *  2. Rejects manifests from untrusted publishers ([PublisherRegistry.isTrusted]).
 *  3. Verifies the Ed25519 signature via [crypto] over [net.sharenet.crypto.Cbor.encodeManifest].
 *  4. Only then persists to Room.
 *
 * The store never holds an unverified manifest. Callers should handle
 * [ManifestVerificationException].
 *
 * @param db Backing Room database (SQLCipher).
 * @param crypto Ed25519 provider.
 * @param publisherRegistry Trust registry with pinned root.
 */
class ManifestStore(
    private val db: CatalogDatabase,
    private val crypto: CryptoProvider,
    private val publisherRegistry: PublisherRegistry,
) {

    /**
     * Store a verified [entry]. Replaces any existing entry for the same [BlobId].
     *
     * @throws ManifestVerificationException if any check fails.
     */
    suspend fun put(entry: CatalogEntry) {
        val m = entry.manifest
        val now = System.currentTimeMillis()

        // 1. Expiry
        val expiresAt = m.expiresAt
        if (expiresAt != null && expiresAt <= now) {
            throw ManifestVerificationException.Expired(m.blobId, expiresAt)
        }

        // 2. Publisher trust
        if (!publisherRegistry.isTrusted(m.publisherId)) {
            throw ManifestVerificationException.UntrustedPublisher(m.publisherId)
        }

        // 3. Signature
        if (!crypto.verifyManifest(m)) {
            throw ManifestVerificationException.BadSignature(m.blobId, m.publisherId)
        }

        // 4. Chunk / BlobId consistency
        val computedRoot = net.sharenet.content.MerkleTree.merkleRoot(m.chunks)
        if (computedRoot != m.blobId) {
            throw ManifestVerificationException.BlobIdMismatch(m.blobId, computedRoot)
        }

        // 5. Revocation check — do not store a manifest for a revoked blob
        val blobHex = m.blobId.bytes.toHex()
        if (db.revocationDao().isRevoked(blobHex)) {
            throw ManifestVerificationException.Revoked(m.blobId)
        }

        val entity = ManifestEntity(
            blobIdHex = blobHex,
            chunksJson = JSONArray(m.chunks.map { it.bytes.toHex() }).toString(),
            totalBytes = m.totalBytes,
            mimeType = m.mimeType,
            publisherIdHex = m.publisherId.bytes.toHex(),
            publishedAt = m.publishedAt,
            expiresAt = m.expiresAt,
            signatureHex = m.signature.toHex(),
            category = entry.category.code,
            priority = entry.priority,
            minAppVersion = entry.minAppVersion,
        )
        db.manifestDao().upsert(entity)
    }

    /** Retrieve a catalog entry by [blobId], or `null` if absent. */
    suspend fun get(blobId: BlobId): CatalogEntry? {
        val e = db.manifestDao().getById(blobId.bytes.toHex()) ?: return null
        return entityToEntry(e)
    }

    /** List all entries, newest first. */
    suspend fun listAll(): List<CatalogEntry> =
        db.manifestDao().listAll().map { entityToEntry(it) }

    /** Delete the manifest for [blobId]. No-op if absent. */
    suspend fun delete(blobId: BlobId) {
        db.manifestDao().deleteById(blobId.bytes.toHex())
    }

    /**
     * Delete all manifests whose blobs have been revoked.
     * Called after ingesting new revocations.
     * @return Number of deleted manifests.
     */
    suspend fun deleteRevoked(): Int = db.manifestDao().deleteRevoked()

    /** Whether a manifest for [blobId] exists. */
    suspend fun exists(blobId: BlobId): Boolean =
        db.manifestDao().exists(blobId.bytes.toHex())

    private fun entityToEntry(e: ManifestEntity): CatalogEntry {
        val chunkHexes = JSONArray(e.chunksJson).let { arr ->
            (0 until arr.length()).map { arr.getString(it) }
        }
        val chunks = chunkHexes.map { ChunkId(it.hexToBytes()) }
        val manifest = Manifest(
            blobId = BlobId(e.blobIdHex.hexToBytes()),
            chunks = chunks,
            totalBytes = e.totalBytes,
            mimeType = e.mimeType,
            publisherId = NodeId(e.publisherIdHex.hexToBytes()),
            publishedAt = e.publishedAt,
            expiresAt = e.expiresAt,
            signature = e.signatureHex.hexToBytes(),
        )
        return CatalogEntry(
            manifest = manifest,
            category = Category.fromCode(e.category),
            priority = e.priority,
            minAppVersion = e.minAppVersion,
        )
    }
}

/**
 * Thrown when a manifest fails verification.
 */
sealed class ManifestVerificationException(message: String) : Exception(message) {
    class Expired(val blobId: BlobId, val expiresAt: Long) :
        ManifestVerificationException("Manifest ${blobId} expired at $expiresAt")
    class UntrustedPublisher(val publisher: NodeId) :
        ManifestVerificationException("Untrusted publisher $publisher")
    class BadSignature(val blobId: BlobId, val publisher: NodeId) :
        ManifestVerificationException("Bad signature for $blobId from $publisher")
    class BlobIdMismatch(val expected: BlobId, val computed: BlobId) :
        ManifestVerificationException("BlobId mismatch: expected $expected, computed $computed")
    class Revoked(val blobId: BlobId) :
        ManifestVerificationException("Blob $blobId is revoked")
}

// -- hex helpers (private, duplicated across modules to avoid public exposure) --

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
    require(length % 2 == 0) { "Even hex length required" }
    val out = ByteArray(length / 2)
    for (i in out.indices) out[i] = ((hexVal(this[i * 2]) shl 4) or hexVal(this[i * 2 + 1])).toByte()
    return out
}

private fun hexVal(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("Invalid hex char: $c")
}

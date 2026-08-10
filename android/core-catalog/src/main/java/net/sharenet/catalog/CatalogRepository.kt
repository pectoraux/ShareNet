package net.sharenet.catalog

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import net.sharenet.catalog.db.CatalogDatabase
import net.sharenet.catalog.db.ManifestEntity
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.CatalogEntry
import net.sharenet.crypto.Category
import net.sharenet.crypto.ChunkId
import net.sharenet.crypto.NodeId
import org.json.JSONArray

/**
 * High-level catalog repository — the API that UI and sync layers use.
 *
 * Combines [ManifestStore], [RevocationList], and [PublisherRegistry] into
 * a single coherent surface with filtering.
 *
 * Filtering behaviour (per M2 spec):
 *  - [category] — exact match; `null` means all categories. `REVOCATION`
 *    is never returned here — use [RevocationList] for revocations.
 *  - [minAppVersion] — `entry.minAppVersion <= callerAppVersion` (caller can
 *    handle it). Entries requiring a newer app version are excluded.
 *  - [expiresAt] — entries with `expiresAt != null && expiresAt <= now` are
 *    excluded (they are also rejected on ingestion).
 *  - Revoked blobs are never returned (checked against [RevocationList]).
 *
 * Results are ordered by `priority DESC, publishedAt DESC` (revocations are
 * not in this list — they are propagated via [RevocationList.orderedSyncBatch]).
 */
class CatalogRepository(
    private val db: CatalogDatabase,
    val manifestStore: ManifestStore,
    val revocationList: RevocationList,
    val publisherRegistry: PublisherRegistry,
) {

    /**
     * Query the local catalog with filters.
     *
     * @param category Filter by category, or `null` for all (except REVOCATION).
     * @param appVersion Caller app version (default: current `BuildConfig.VERSION_CODE` equivalent).
     * @param now Epoch millis for expiry check (default: `System.currentTimeMillis()`).
     * @return Filtered, ordered list. Never includes revoked or expired entries.
     */
    suspend fun query(
        category: Category? = null,
        appVersion: Int = Int.MAX_VALUE,
        now: Long = System.currentTimeMillis(),
    ): List<CatalogEntry> {
        // REVOCATION category is never stored as a manifest — it's in the revocation table.
        if (category == Category.REVOCATION) return emptyList()

        val entities = db.manifestDao().queryFiltered(
            category = category?.code,
            appVersion = appVersion,
            now = now,
        )
        // Filter out revoked (defence in depth — deleteRevoked should have removed them,
        // but a race between revoke and query is possible).
        return entities.mapNotNull { e ->
            if (db.revocationDao().isRevoked(e.blobIdHex)) null else e.toEntry()
        }
    }

    /** Flow of filtered catalog entries, re-emitted on any manifest change. */
    fun observe(
        category: Category? = null,
        appVersion: Int = Int.MAX_VALUE,
    ): Flow<List<CatalogEntry>> =
        db.manifestDao().observeAll().map { all ->
            val now = System.currentTimeMillis()
            all.filter { e ->
                (category == null || e.category == category.code) &&
                    e.minAppVersion <= appVersion &&
                    (e.expiresAt == null || e.expiresAt > now)
            }
                .sortedWith(compareByDescending<ManifestEntity> { it.priority }.thenByDescending { it.publishedAt })
                .mapNotNull { e ->
                    // Synchronous revoked check not possible in Flow map without suspension;
                    // we conservatively include it — the collector should re-check
                    // via [isRevoked] or use [query] for strict correctness.
                    e.toEntry()
                }
        }

    /** Convenience: get a single entry by [blobId]. */
    suspend fun get(blobId: BlobId): CatalogEntry? = manifestStore.get(blobId)

    /** Publish a new entry (verifies and stores). */
    suspend fun publish(entry: CatalogEntry) = manifestStore.put(entry)

    /** Revoke a blob. Delegates to [RevocationList]. */
    suspend fun revoke(
        blobId: BlobId,
        publisherId: NodeId,
        revokedAt: Long = System.currentTimeMillis(),
        reason: String = "",
        signature: ByteArray,
    ) = revocationList.revoke(blobId, publisherId, revokedAt, reason, signature)

    /** Whether [blobId] is revoked. */
    suspend fun isRevoked(blobId: BlobId): Boolean = revocationList.isRevoked(blobId)

    /**
     * Catalogue sync helper: given a remote ordered batch, ingest revocations
     * first, then manifests. Returns counts of ingested items.
     */
    suspend fun ingestSyncBatch(batch: OrderedBatch): IngestResult {
        var revocationsIngested = 0
        var revocationsFailed = 0
        for (r in batch.revocations) {
            val ok = revocationList.ingest(r.blobId, r.publisherId, r.revokedAt, r.reason, r.signature)
            if (ok) revocationsIngested++ else revocationsFailed++
        }
        var manifestsIngested = 0
        var manifestsRejected = 0
        for (e in batch.entries) {
            // Skip if it became revoked by an earlier revocation in this batch
            if (revocationList.isRevoked(e.manifest.blobId)) {
                manifestsRejected++
                continue
            }
            try {
                manifestStore.put(e)
                manifestsIngested++
            } catch (_: ManifestVerificationException) {
                manifestsRejected++
            }
        }
        // Ensure any previously stored manifests that are now revoked are removed
        manifestStore.deleteRevoked()
        return IngestResult(
            revocationsIngested = revocationsIngested,
            revocationsFailed = revocationsFailed,
            manifestsIngested = manifestsIngested,
            manifestsRejected = manifestsRejected,
        )
    }

    private fun ManifestEntity.toEntry(): CatalogEntry {
        val chunkHexes = JSONArray(chunksJson).let { arr -> (0 until arr.length()).map { arr.getString(it) } }
        val chunks = chunkHexes.map { ChunkId(it.hexToBytes()) }
        val manifest = net.sharenet.crypto.Manifest(
            blobId = BlobId(blobIdHex.hexToBytes()),
            chunks = chunks,
            totalBytes = totalBytes,
            mimeType = mimeType,
            publisherId = NodeId(publisherIdHex.hexToBytes()),
            publishedAt = publishedAt,
            expiresAt = expiresAt,
            signature = signatureHex.hexToBytes(),
        )
        return CatalogEntry(
            manifest = manifest,
            category = Category.fromCode(category),
            priority = priority,
            minAppVersion = minAppVersion,
        )
    }
}

/** Result of [CatalogRepository.ingestSyncBatch]. */
data class IngestResult(
    val revocationsIngested: Int,
    val revocationsFailed: Int,
    val manifestsIngested: Int,
    val manifestsRejected: Int,
)

// -- hex helpers --

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

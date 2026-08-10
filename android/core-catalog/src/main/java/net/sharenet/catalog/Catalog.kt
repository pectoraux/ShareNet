package net.sharenet.catalog

import kotlinx.coroutines.flow.Flow
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.CatalogEntry
import net.sharenet.crypto.Category
import net.sharenet.crypto.Manifest
import net.sharenet.crypto.NodeId

/**
 * Local catalog store — verified manifests indexed by category.
 */
interface CatalogStore {
    /** Insert a verified [CatalogEntry]; revocations evict the targeted blob. */
    suspend fun put(entry: CatalogEntry)

    /** Entries for [category], ordered by [CatalogEntry.priority] descending. */
    suspend fun listByCategory(category: Category): List<CatalogEntry>

    /** All entries whose blob is locally available. */
    suspend fun listAvailable(): List<CatalogEntry>

    /** Lookup manifest by blob id. */
    suspend fun get(blobId: BlobId): CatalogEntry?

    /** Reactive stream of catalog changes. */
    fun observe(category: Category? = null): Flow<List<CatalogEntry>>

    /** Whether a blob has been revoked. */
    suspend fun isRevoked(blobId: BlobId): Boolean
}

/** Revocation entry. */
data class Revocation(
    val blobId: BlobId,
    val reason: String,
    val revokedAt: Long,
    val issuerId: NodeId,
    val signature: ByteArray,
)

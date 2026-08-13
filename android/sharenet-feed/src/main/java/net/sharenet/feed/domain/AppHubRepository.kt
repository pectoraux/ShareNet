package net.sharenet.feed.domain

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import net.sharenet.catalog.CatalogStore
import net.sharenet.content.BlobStore
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.Category

/**
 * Repository for discovering and launching "App Clones" (offline bundles).
 */
class AppHubRepository(
    private val catalogStore: CatalogStore,
    private val blobStore: BlobStore,
) {
    /** List apps available in the local mesh catalog. */
    fun observeApps(): Flow<List<AppBundle>> {
        return catalogStore.observe(Category.APP_BUNDLE).map { entries ->
            entries.map { entry ->
                AppBundle(
                    blobId = entry.manifest.blobId,
                    name = entry.manifest.mimeType.substringAfter("app/"), // stub
                    isDownloaded = false // real: blobStore.has(entry.manifest.blobId)
                )
            }
        }
    }

    suspend fun downloadApp(blobId: BlobId) {
        // Trigger SDK fetch
    }
}

data class AppBundle(
    val blobId: BlobId,
    val name: String,
    val isDownloaded: Boolean
)

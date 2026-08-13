package net.sharenet.feed.domain

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import net.sharenet.crypto.BlobId
import net.sharenet.feed.data.AppDao
import net.sharenet.feed.data.AppEntity
import net.sharenet.feed.data.UserStatsDao

interface AppStoreRepository {
    fun observeLibrary(): Flow<List<AppStoreItem>>
    fun observeStore(): Flow<List<AppStoreItem>>
    fun observeReviewQueue(): Flow<List<AppStoreItem>>
    
    suspend fun submitApp(name: String, description: String, developer: String, category: String)
    suspend fun approveApp(appId: String)
    suspend fun installApp(appId: String)
    suspend fun uninstallApp(appId: String)
    
    fun observeUserStats(): Flow<UserStats>
    suspend fun toggleBridging(enabled: Boolean)
}

data class AppStoreItem(
    val id: String,
    val name: String,
    val description: String,
    val developer: String,
    val status: String,
    val icon: String = "🚀" // Default emoji icon
)

data class UserStats(
    val civicPoints: Long,
    val bridgingEnabled: Boolean,
    val isAdmin: Boolean
)

class RealAppStoreRepository(
    private val appDao: AppDao,
    private val userStatsDao: UserStatsDao
) : AppStoreRepository {

    override fun observeLibrary(): Flow<List<AppStoreItem>> = 
        appDao.observeByStatus("INSTALLED").map { it.map { e -> e.toItem() } }

    override fun observeStore(): Flow<List<AppStoreItem>> = 
        appDao.observeByStatus("APPROVED").map { it.map { e -> e.toItem() } }

    override fun observeReviewQueue(): Flow<List<AppStoreItem>> = 
        appDao.observeByStatus("REVIEW_PENDING").map { it.map { e -> e.toItem() } }

    override suspend fun submitApp(name: String, description: String, developer: String, category: String) {
        val appId = "app_" + java.util.UUID.randomUUID().toString().take(8)
        appDao.upsert(
            AppEntity(
                id = appId,
                name = name,
                description = description,
                developerName = developer,
                category = category,
                status = "REVIEW_PENDING"
            )
        )
    }

    override suspend fun approveApp(appId: String) {
        appDao.updateStatus(appId, "APPROVED")
        // Reward admin/reviewer points
        userStatsDao.addPoints(50)
    }

    override suspend fun installApp(appId: String) {
        appDao.updateStatus(appId, "INSTALLED", System.currentTimeMillis())
        // Cost points? Or just record it.
    }

    override suspend fun uninstallApp(appId: String) {
        appDao.updateStatus(appId, "APPROVED", null)
    }

    override fun observeUserStats(): Flow<UserStats> = 
        userStatsDao.observeLocal().map { 
            it?.let { s -> UserStats(s.civicPoints, s.bridgingEnabled, s.isNetworkAdmin) } 
                ?: UserStats(0, false, false)
        }

    override suspend fun toggleBridging(enabled: Boolean) {
        val current = userStatsDao.getLocal() ?: net.sharenet.feed.data.UserStatsEntity()
        userStatsDao.upsert(current.copy(bridgingEnabled = enabled))
    }

    private fun AppEntity.toItem() = AppStoreItem(id, name, description, developerName, status)
}

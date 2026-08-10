package net.sharenet.feed.domain

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import net.sharenet.feed.data.ActiveAppDao
import net.sharenet.feed.data.ActiveAppEntity
import net.sharenet.feed.data.AppDao

interface LauncherRepository {
    fun observeActiveApps(): Flow<List<ActiveApp>>
    suspend fun launchApp(appId: String)
    suspend fun closeApp(appId: String)
}

data class ActiveApp(
    val appId: String,
    val name: String,
    val launchedAt: Long
)

class RealLauncherRepository(
    private val activeAppDao: ActiveAppDao,
    private val appDao: AppDao
) : LauncherRepository {

    override fun observeActiveApps(): Flow<List<ActiveApp>> = 
        activeAppDao.observeAll().map { entities ->
            entities.mapNotNull { e ->
                val app = appDao.getById(e.appId) ?: return@mapNotNull null
                ActiveApp(e.appId, app.name, e.launchedAt)
            }
        }

    override suspend fun launchApp(appId: String) {
        activeAppDao.upsert(ActiveAppEntity(appId))
    }

    override suspend fun closeApp(appId: String) {
        activeAppDao.delete(appId)
    }
}

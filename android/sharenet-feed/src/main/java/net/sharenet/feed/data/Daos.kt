package net.sharenet.feed.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface PostDao {
    @Query("SELECT * FROM posts ORDER BY publishedAt DESC")
    fun observeAll(): Flow<List<PostEntity>>

    @Query("SELECT * FROM posts WHERE blobIdHex = :blobIdHex")
    suspend fun getById(blobIdHex: String): PostEntity?

    @Upsert
    suspend fun upsert(post: PostEntity)

    @Query("UPDATE posts SET isLiked = :liked, likeCount = likeCount + :delta WHERE blobIdHex = :blobIdHex")
    suspend fun updateLike(blobIdHex: String, liked: Boolean, delta: Int)
}

@Dao
interface ActionDao {
    @Query("SELECT * FROM queued_actions WHERE status = 'PENDING' ORDER BY createdAt ASC")
    suspend fun getPending(): List<ActionEntity>

    @Upsert
    suspend fun upsert(action: ActionEntity)

    @Query("UPDATE queued_actions SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: String, status: String)

    @Query("DELETE FROM queued_actions WHERE id = :id")
    suspend fun delete(id: String)
}

@Dao
interface CursorDao {
    @Query("SELECT * FROM feed_cursors WHERE id = :id")
    suspend fun getById(id: String): CursorEntity?

    @Upsert
    suspend fun upsert(cursor: CursorEntity)
}

@Dao
interface AppDao {
    @Query("SELECT * FROM apps WHERE status = :status")
    fun observeByStatus(status: String): Flow<List<AppEntity>>

    @Query("SELECT * FROM apps WHERE id = :id")
    suspend fun getById(id: String): AppEntity?

    @Upsert
    suspend fun upsert(app: AppEntity)

    @Query("UPDATE apps SET status = :status, installedAt = :installedAt WHERE id = :id")
    suspend fun updateStatus(id: String, status: String, installedAt: Long? = null)

    @Query("DELETE FROM apps WHERE id = :id")
    suspend fun delete(id: String)
}

@Dao
interface UserStatsDao {
    @Query("SELECT * FROM user_stats WHERE userId = 'local'")
    fun observeLocal(): Flow<UserStatsEntity?>

    @Query("SELECT * FROM user_stats WHERE userId = 'local'")
    suspend fun getLocal(): UserStatsEntity?

    @Upsert
    suspend fun upsert(stats: UserStatsEntity)

    @Query("UPDATE user_stats SET civicPoints = civicPoints + :delta WHERE userId = 'local'")
    suspend fun addPoints(delta: Long)
}

@Dao
interface ActiveAppDao {
    @Query("SELECT * FROM active_apps ORDER BY launchedAt DESC")
    fun observeAll(): Flow<List<ActiveAppEntity>>

    @Upsert
    suspend fun upsert(activeApp: ActiveAppEntity)

    @Query("DELETE FROM active_apps WHERE appId = :appId")
    suspend fun delete(appId: String)
}

package net.sharenet.feed.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.UUID

@Entity(tableName = "posts")
data class PostEntity(
    @PrimaryKey val blobIdHex: String,
    val caption: String,
    val publisherIdHex: String,
    val publishedAt: Long,
    val mimeType: String,
    val likeCount: Int = 0,
    val commentCount: Int = 0,
    val isLiked: Boolean = false,
)

@Entity(tableName = "queued_actions")
data class ActionEntity(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val type: String, // POST, LIKE, COMMENT
    val targetBlobIdHex: String?,
    val payload: ByteArray?,
    val status: String, // PENDING, SYNCING, SYNCED
    val createdAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "feed_cursors")
data class CursorEntity(
    @PrimaryKey val id: String = "default",
    val lastRankedAt: Long,
)

@Entity(tableName = "apps")
data class AppEntity(
    @PrimaryKey val id: String, // BlobIdHex
    val name: String,
    val description: String,
    val developerName: String,
    val category: String, // SOCIAL, GAME, UTILITY
    val status: String, // REVIEW_PENDING, APPROVED, REJECTED, INSTALLED
    val version: Int = 1,
    val installedAt: Long? = null
)

@Entity(tableName = "user_stats")
data class UserStatsEntity(
    @PrimaryKey val userId: String = "local",
    val civicPoints: Long = 0,
    val bridgingEnabled: Boolean = false,
    val isNetworkAdmin: Boolean = false
)

@Entity(tableName = "active_apps")
data class ActiveAppEntity(
    @PrimaryKey val appId: String,
    val launchedAt: Long = System.currentTimeMillis()
)

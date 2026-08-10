package net.sharenet.catalog.db

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/**
 * Room database for the ShareNet catalog: manifests, revocations, publisher keys.
 *
 * Encrypted at rest via SQLCipher. All tables are local-only; sync is via
 * Nearby transport, not direct DB replication.
 */
@Database(
    entities = [ManifestEntity::class, RevocationEntity::class, PublisherEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class CatalogDatabase : RoomDatabase() {
    abstract fun manifestDao(): ManifestDao
    abstract fun revocationDao(): RevocationDao
    abstract fun publisherDao(): PublisherDao
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

/**
 * Persisted manifest. The signature is verified before insertion — never store
 * an unverified manifest.
 */
@Entity(tableName = "manifests")
data class ManifestEntity(
    @PrimaryKey
    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String,

    @ColumnInfo(name = "chunks_json")
    val chunksJson: String, // JSON array of hex chunk IDs (ordered)

    @ColumnInfo(name = "total_bytes")
    val totalBytes: Long,

    @ColumnInfo(name = "mime_type")
    val mimeType: String,

    @ColumnInfo(name = "publisher_id_hex")
    val publisherIdHex: String,

    @ColumnInfo(name = "published_at")
    val publishedAt: Long,

    @ColumnInfo(name = "expires_at")
    val expiresAt: Long?,

    @ColumnInfo(name = "signature_hex")
    val signatureHex: String,

    @ColumnInfo(name = "category")
    val category: String, // Category.code

    @ColumnInfo(name = "priority")
    val priority: Int,

    @ColumnInfo(name = "min_app_version")
    val minAppVersion: Int,

    @ColumnInfo(name = "received_at")
    val receivedAt: Long = System.currentTimeMillis(),
)

/**
 * Revocation entry. A revocation declares that [blobIdHex] must not be
 * distributed and any local copy must be deleted.
 *
 * Revocations have [priority] = [net.sharenet.crypto.CatalogEntry.PRIORITY_REVOCATION]
 * and propagate strictly before normal content.
 */
@Entity(tableName = "revocations")
data class RevocationEntity(
    @PrimaryKey
    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String,

    @ColumnInfo(name = "publisher_id_hex")
    val publisherIdHex: String,

    @ColumnInfo(name = "revoked_at")
    val revokedAt: Long,

    @ColumnInfo(name = "reason")
    val reason: String = "",

    @ColumnInfo(name = "signature_hex")
    val signatureHex: String, // publisher signature over (blobId || revokedAt)

    @ColumnInfo(name = "received_at")
    val receivedAt: Long = System.currentTimeMillis(),
)

/**
 * Publisher trust entry. The root publisher key is pinned; other publishers
 * are added via signed delegation or root rotation.
 */
@Entity(tableName = "publishers")
data class PublisherEntity(
    @PrimaryKey
    @ColumnInfo(name = "publisher_id_hex")
    val publisherIdHex: String,

    @ColumnInfo(name = "is_root")
    val isRoot: Boolean = false,

    @ColumnInfo(name = "is_revoked")
    val isRevoked: Boolean = false,

    @ColumnInfo(name = "added_at")
    val addedAt: Long = System.currentTimeMillis(),

    @ColumnInfo(name = "added_by_hex")
    val addedByHex: String? = null, // null for pinned root
)

// ---------------------------------------------------------------------------
// DAOs
// ---------------------------------------------------------------------------

@Dao
interface ManifestDao {

    @Query("SELECT * FROM manifests WHERE blob_id_hex = :hex")
    suspend fun getById(hex: String): ManifestEntity?

    @Query("SELECT * FROM manifests ORDER BY published_at DESC")
    suspend fun listAll(): List<ManifestEntity>

    @Query("SELECT * FROM manifests ORDER BY published_at DESC")
    fun observeAll(): Flow<List<ManifestEntity>>

    @Query(
        """
        SELECT * FROM manifests
        WHERE (:category IS NULL OR category = :category)
          AND min_app_version <= :appVersion
          AND (expires_at IS NULL OR expires_at > :now)
        ORDER BY priority DESC, published_at DESC
        """,
    )
    suspend fun queryFiltered(
        category: String?,
        appVersion: Int,
        now: Long,
    ): List<ManifestEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: ManifestEntity)

    @Query("DELETE FROM manifests WHERE blob_id_hex = :hex")
    suspend fun deleteById(hex: String)

    @Query("DELETE FROM manifests WHERE blob_id_hex IN (SELECT blob_id_hex FROM revocations)")
    suspend fun deleteRevoked(): Int

    @Query("SELECT EXISTS(SELECT 1 FROM manifests WHERE blob_id_hex = :hex)")
    suspend fun exists(hex: String): Boolean
}

@Dao
interface RevocationDao {

    @Query("SELECT * FROM revocations WHERE blob_id_hex = :hex")
    suspend fun getByBlobId(hex: String): RevocationEntity?

    @Query("SELECT * FROM revocations ORDER BY revoked_at DESC")
    suspend fun listAll(): List<RevocationEntity>

    @Query("SELECT * FROM revocations ORDER BY revoked_at DESC")
    fun observeAll(): Flow<List<RevocationEntity>>

    @Query("SELECT EXISTS(SELECT 1 FROM revocations WHERE blob_id_hex = :hex)")
    suspend fun isRevoked(hex: String): Boolean

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: RevocationEntity)

    @Query("DELETE FROM revocations WHERE blob_id_hex = :hex")
    suspend fun deleteById(hex: String)
}

@Dao
interface PublisherDao {

    @Query("SELECT * FROM publishers WHERE publisher_id_hex = :hex")
    suspend fun getById(hex: String): PublisherEntity?

    @Query("SELECT * FROM publishers WHERE is_root = 1 LIMIT 1")
    suspend fun getRoot(): PublisherEntity?

    @Query("SELECT * FROM publishers")
    suspend fun listAll(): List<PublisherEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: PublisherEntity)

    @Query("UPDATE publishers SET is_revoked = 1 WHERE publisher_id_hex = :hex")
    suspend fun revoke(hex: String)

    @Query("SELECT EXISTS(SELECT 1 FROM publishers WHERE publisher_id_hex = :hex AND is_revoked = 0)")
    suspend fun isTrusted(hex: String): Boolean
}

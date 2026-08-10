package net.sharenet.content.db

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

/**
 * Room database for ShareNet content index.
 *
 * Encrypted at rest via SQLCipher (passphrase from Keystore).
 * See `SqlCipherHelper` for passphrase provisioning.
 */
@Database(
    entities = [BlobEntity::class, ChunkEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class ContentDatabase : RoomDatabase() {
    abstract fun blobDao(): BlobDao
    abstract fun chunkDao(): ChunkDao
}

@Dao
interface BlobDao {

    @Query("SELECT * FROM blobs WHERE blob_id_hex = :hex")
    suspend fun getById(hex: String): BlobEntity?

    @Query("SELECT * FROM blobs ORDER BY last_accessed DESC")
    suspend fun listAll(): List<BlobEntity>

    @Query("SELECT * FROM blobs ORDER BY last_accessed DESC")
    fun observeAll(): Flow<List<BlobEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(blob: BlobEntity)

    @Query("DELETE FROM blobs WHERE blob_id_hex = :hex")
    suspend fun deleteById(hex: String)

    @Query("SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id_hex = :hex)")
    suspend fun exists(hex: String): Boolean

    @Query("UPDATE blobs SET pinned = :pinned WHERE blob_id_hex = :hex")
    suspend fun setPinned(hex: String, pinned: Boolean)

    @Query("UPDATE blobs SET last_accessed = :ts WHERE blob_id_hex = :hex")
    suspend fun touch(hex: String, ts: Long)

    /**
     * LRU eviction: delete unpinned blobs oldest-first until total bytes
     * of remaining blobs is <= [maxBytes]. Returns number of evicted blobs.
     */
    @Query(
        """
        DELETE FROM blobs WHERE blob_id_hex IN (
            SELECT blob_id_hex FROM blobs
            WHERE pinned = 0
            ORDER BY last_accessed ASC
        )
        """,
    )
    suspend fun deleteAllUnpinned(): Int

    @Query("SELECT SUM(total_bytes) FROM blobs")
    suspend fun totalBytes(): Long?

    @Query("SELECT * FROM blobs WHERE pinned = 0 ORDER BY last_accessed ASC")
    suspend fun lruUnpinned(): List<BlobEntity>
}

@Dao
interface ChunkDao {

    @Query("SELECT * FROM chunks WHERE blob_id_hex = :blobHex ORDER BY chunk_index ASC")
    suspend fun getByBlob(blobHex: String): List<ChunkEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(chunks: List<ChunkEntity>)

    @Query("DELETE FROM chunks WHERE blob_id_hex = :blobHex")
    suspend fun deleteByBlob(blobHex: String)

    @Query("SELECT * FROM chunks WHERE chunk_id_hex = :hex LIMIT 1")
    suspend fun getByChunkId(hex: String): ChunkEntity?

    @Transaction
    suspend fun replaceForBlob(blobHex: String, chunks: List<ChunkEntity>) {
        deleteByBlob(blobHex)
        if (chunks.isNotEmpty()) insertAll(chunks)
    }
}

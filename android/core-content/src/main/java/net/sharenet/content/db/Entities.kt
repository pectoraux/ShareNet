package net.sharenet.content.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity indexing a blob stored on disk.
 *
 * The blob file itself lives at `<filesDir>/sharenet/blobs/<blobHex>`.
 * This table tracks metadata and LRU state.
 */
@Entity(tableName = "blobs")
data class BlobEntity(
    @PrimaryKey
    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String, // hex of BlobId (32 bytes -> 64 hex chars)

    @ColumnInfo(name = "total_bytes")
    val totalBytes: Long,

    @ColumnInfo(name = "mime_type")
    val mimeType: String,

    @ColumnInfo(name = "chunk_count")
    val chunkCount: Int,

    @ColumnInfo(name = "pinned")
    val pinned: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis(),

    @ColumnInfo(name = "last_accessed")
    val lastAccessed: Long = System.currentTimeMillis(),
)

/**
 * Room entity for a single chunk's metadata.
 *
 * Chunk bytes may be stored inline (small) or as separate files; this
 * implementation stores them as part of the blob file and indexes offsets.
 * For M1 we index per-chunk hashes for verification without reading all bytes.
 */
@Entity(
    tableName = "chunks",
    foreignKeys = [
        ForeignKey(
            entity = BlobEntity::class,
            parentColumns = ["blob_id_hex"],
            childColumns = ["blob_id_hex"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [
        Index(value = ["blob_id_hex"]),
        Index(value = ["chunk_id_hex"], unique = false),
    ],
)
data class ChunkEntity(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = 0,

    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String,

    @ColumnInfo(name = "chunk_id_hex")
    val chunkIdHex: String, // hex of ChunkId

    @ColumnInfo(name = "chunk_index")
    val chunkIndex: Int,

    @ColumnInfo(name = "size_bytes")
    val sizeBytes: Int,

    @ColumnInfo(name = "offset")
    val offset: Long, // offset within the blob file

    @ColumnInfo(name = "sha256_hex")
    val sha256Hex: String, // redundant with chunkIdHex, kept for clarity
)

/**
 * DAO-adjacent data class for blob + its chunks.
 */
data class BlobWithChunks(
    val blob: BlobEntity,
    val chunks: List<ChunkEntity>,
)

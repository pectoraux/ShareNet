package net.sharenet.attest

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity for a queued delivery receipt.
 *
 * One row per receipt; primary key is a stable id derived from
 * (blobId || recipientId || nonce) so replays collide on insert.
 */
@Entity(tableName = "receipts")
data class ReceiptEntity(
    @PrimaryKey
    @ColumnInfo(name = "receipt_id")
    val receiptId: String, // hex(blobId) + ":" + hex(recipientId) + ":" + hex(nonce)

    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String,

    @ColumnInfo(name = "bytes_delivered")
    val bytesDelivered: Long,

    @ColumnInfo(name = "sender_id_hex")
    val senderIdHex: String,

    @ColumnInfo(name = "recipient_id_hex")
    val recipientIdHex: String,

    @ColumnInfo(name = "timestamp")
    val timestamp: Long,

    @ColumnInfo(name = "nonce_hex")
    val nonceHex: String,

    @ColumnInfo(name = "recipient_signature_hex")
    val recipientSignatureHex: String,

    /** Upload state. */
    @ColumnInfo(name = "status")
    val status: ReceiptStatus = ReceiptStatus.QUEUED,

    /** Monotonic insertion time for FIFO upload. */
    @ColumnInfo(name = "queued_at")
    val queuedAt: Long = System.currentTimeMillis(),

    /** Last upload attempt time (null if never attempted). */
    @ColumnInfo(name = "last_attempt_at")
    val lastAttemptAt: Long? = null,

    /** Consecutive failures (for exponential backoff). */
    @ColumnInfo(name = "attempts")
    val attempts: Int = 0,
)

enum class ReceiptStatus { QUEUED, UPLOADING, UPLOADED, FAILED }

/**
 * Room entity for the local points ledger.
 *
 * One row per settled receipt after verification.
 * Points are stored as integer minor units to avoid floating point in the ledger.
 */
@Entity(tableName = "points_ledger")
data class PointsEntry(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = 0,

    @ColumnInfo(name = "receipt_id")
    val receiptId: String,

    @ColumnInfo(name = "blob_id_hex")
    val blobIdHex: String,

    /** Points earned (integer minor units, e.g. 1 point = 1000). */
    @ColumnInfo(name = "points")
    val points: Long,

    /** When the points become spendable (payout holdback). */
    @ColumnInfo(name = "available_at")
    val availableAt: Long,

    /** Clawed back? */
    @ColumnInfo(name = "clawed_back")
    val clawedBack: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis(),
)

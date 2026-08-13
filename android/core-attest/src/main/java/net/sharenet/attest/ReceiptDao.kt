package net.sharenet.attest

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ReceiptDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: ReceiptEntity)

    /** Insert or ignore (replay protection — duplicate nonce is a no-op). */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertOrIgnore(entity: ReceiptEntity): Long

    @Query("SELECT * FROM receipts WHERE status = 'QUEUED' ORDER BY queued_at ASC LIMIT :limit")
    suspend fun queued(limit: Int = 100): List<ReceiptEntity>

    @Query("SELECT * FROM receipts WHERE receipt_id = :id LIMIT 1")
    suspend fun byId(id: String): ReceiptEntity?

    @Query("UPDATE receipts SET status = :status, last_attempt_at = :now, attempts = attempts + 1 WHERE receipt_id = :id")
    suspend fun markAttempt(id: String, status: ReceiptStatus, now: Long)

    @Query("UPDATE receipts SET status = 'UPLOADED' WHERE receipt_id = :id")
    suspend fun markUploaded(id: String)

    @Query("SELECT COUNT(*) FROM receipts WHERE status = 'QUEUED'")
    suspend fun queuedCount(): Int

    @Query("SELECT COUNT(*) FROM receipts WHERE status = 'QUEUED'")
    fun observeQueuedCount(): Flow<Int>

    @Query("DELETE FROM receipts WHERE status = 'UPLOADED' AND queued_at < :olderThan")
    suspend fun pruneUploaded(olderThan: Long)
}

@Dao
interface PointsLedgerDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entry: PointsEntry): Long

    @Query("SELECT COALESCE(SUM(points), 0) FROM points_ledger WHERE clawed_back = 0 AND available_at <= :now")
    suspend fun availablePoints(now: Long): Long

    @Query("SELECT COALESCE(SUM(points), 0) FROM points_ledger WHERE clawed_back = 0 AND available_at > :now")
    suspend fun pendingPoints(now: Long): Long

    @Query("SELECT * FROM points_ledger ORDER BY created_at DESC LIMIT :limit")
    suspend fun recent(limit: Int = 50): List<PointsEntry>

    @Query("SELECT * FROM points_ledger WHERE receipt_id = :receiptId LIMIT 1")
    suspend fun byReceiptId(receiptId: String): PointsEntry?

    @Query("UPDATE points_ledger SET clawed_back = 1 WHERE receipt_id = :receiptId")
    suspend fun clawBack(receiptId: String)

    fun observeAvailable(now: Long): Flow<Long> = throw NotImplementedError("Use Room's @Query Flow in real DB")
}

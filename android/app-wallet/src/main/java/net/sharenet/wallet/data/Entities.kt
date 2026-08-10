package net.sharenet.wallet.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "transactions")
data class TransactionRecord(
    @PrimaryKey val id: String,
    val amount: Int, // minor units, always positive
    val payerCardId: String,
    val payeeCardId: String,
    val timestamp: Long,
    val status: String, // PENDING_SETTLEMENT | SETTLED | FAILED
    val payerNewBalance: Int? = null,
    val payeeNewBalance: Int? = null,
    val nonce: String, // anti double-credit
)

@Dao
interface TransactionDao {
    @Query("SELECT * FROM transactions ORDER BY timestamp DESC")
    fun observeAll(): Flow<List<TransactionRecord>>

    @Query("SELECT * FROM transactions ORDER BY timestamp DESC")
    suspend fun listAll(): List<TransactionRecord>

    @Query("SELECT * FROM transactions WHERE status = 'PENDING_SETTLEMENT' ORDER BY timestamp ASC")
    suspend fun pending(): List<TransactionRecord>

    @Query("SELECT * FROM transactions WHERE nonce = :nonce LIMIT 1")
    suspend fun byNonce(nonce: String): TransactionRecord?

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(record: TransactionRecord)

    @Query("UPDATE transactions SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: String, status: String)

    @Query("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status = 'PENDING_SETTLEMENT'")
    suspend fun pendingTotal(): Long
}

@Entity(tableName = "revoked_cards")
data class RevokedCard(
    @PrimaryKey val cardId: String,
    val revokedAt: Long,
)

@Dao
interface RevokedCardDao {
    @Query("SELECT cardId FROM revoked_cards")
    suspend fun allIds(): List<String>

    @Query("SELECT EXISTS(SELECT 1 FROM revoked_cards WHERE cardId = :cardId)")
    suspend fun isRevoked(cardId: String): Boolean

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(cards: List<RevokedCard>)

    @Query("DELETE FROM revoked_cards")
    suspend fun clear()
}

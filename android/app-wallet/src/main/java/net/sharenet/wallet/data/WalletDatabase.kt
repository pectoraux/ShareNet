package net.sharenet.wallet.data

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [TransactionRecord::class, RevokedCard::class], version = 1, exportSchema = false)
abstract class WalletDatabase : RoomDatabase() {
    abstract fun transactionDao(): TransactionDao
    abstract fun revokedCardDao(): RevokedCardDao
}

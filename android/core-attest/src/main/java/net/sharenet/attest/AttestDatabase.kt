package net.sharenet.attest

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [ReceiptEntity::class, PointsEntry::class],
    version = 1,
    exportSchema = true,
)
abstract class AttestDatabase : RoomDatabase() {
    abstract fun receiptDao(): ReceiptDao
    abstract fun pointsLedgerDao(): PointsLedgerDao
}

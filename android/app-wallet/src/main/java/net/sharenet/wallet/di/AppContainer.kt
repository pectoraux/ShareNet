package net.sharenet.wallet.di

import android.content.Context
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.room.Room
import net.sharenet.wallet.data.WalletDatabase
import net.sharenet.wallet.nfc.NfcReaderManager
import net.sharenet.wallet.payment.PaymentFlow
import net.sharenet.wallet.payment.RevocationList

private val Context.walletDataStore by preferencesDataStore(name = "wallet_prefs")

/**
 * Manual DI — Hilt-less per spec.
 * Single container owned by Application / MainActivity. No global statics.
 */
class WalletAppContainer(private val context: Context) {

    val dataStore get() = context.walletDataStore

    val database: WalletDatabase by lazy {
        Room.databaseBuilder(context.applicationContext, WalletDatabase::class.java, "wallet.db")
            .fallbackToDestructiveMigration()
            .build()
    }

    /** Revocation list — refresh via ShareNet catalog sync (call [refreshRevocationList] when online). */
    var revocationList: RevocationList = RevocationList()
        private set

    suspend fun refreshRevocationList(ids: List<String>) {
        revocationList = RevocationList.fromIds(ids)
        // Also persist to Room for offline checks
        database.revokedCardDao().upsertAll(ids.map { net.sharenet.wallet.data.RevokedCard(it, System.currentTimeMillis()) })
    }

    val paymentFlow: PaymentFlow by lazy {
        PaymentFlow(database.transactionDao(), revocationList)
    }

    fun nfcReaderManager(onCard: suspend (android.nfc.Tag) -> Unit): NfcReaderManager =
        NfcReaderManager(context as android.app.Activity, onCard)

    object Prefs {
        val OFFLINE_CAP = intPreferencesKey("offline_cap")
        val LAST_SETTLEMENT = intPreferencesKey("last_settlement")
    }
}

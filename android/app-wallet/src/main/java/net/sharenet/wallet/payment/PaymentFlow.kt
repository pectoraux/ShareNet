package net.sharenet.wallet.payment

import net.sharenet.wallet.data.TransactionDao
import net.sharenet.wallet.data.TransactionRecord
import net.sharenet.wallet.nfc.ApduCommands
import net.sharenet.wallet.nfc.CardChannel

/**
 * Transaction invariant checks (enforced before any card write).
 */
object TransactionInvariants {

    /** Max offline transaction amount / cumulative cap (minor units). */
    const val OFFLINE_CAP = 50_000 // e.g. 500.00 in minor units — tune per deployment

    fun checkNoDoubleCredit(nonce: String, existing: TransactionRecord?) {
        if (existing != null) throw DoubleCreditException("Double credit rejected — nonce $nonce already used")
    }

    fun checkBalanceNonNegative(balanceAfter: Int) {
        if (balanceAfter < 0) throw NegativeBalanceException("Balance cannot be negative: $balanceAfter")
    }

    fun checkOfflineCap(amount: Int, pendingTotal: Long) {
        if (amount > OFFLINE_CAP) throw OfflineCapException("Single tx exceeds offline cap: $amount > $OFFLINE_CAP")
        if (pendingTotal + amount > OFFLINE_CAP * 10) throw OfflineCapException("Cumulative pending exceeds cap")
    }

    class DoubleCreditException(msg: String) : IllegalStateException(msg)
    class NegativeBalanceException(msg: String) : IllegalStateException(msg)
    class OfflineCapException(msg: String) : IllegalStateException(msg)
    class RevokedCardException(cardId: String) : IllegalStateException("Card revoked — transaction refused: $cardId")
}

/**
 * Revocation list — synced via ShareNet catalog (category REVOCATION has max priority).
 * In prod, fetched via `sharenet-sdk` catalog and written to [net.sharenet.wallet.data.RevokedCardDao].
 */
class RevocationList(
    private val revokedIds: Set<String> = emptySet(),
) {
    fun isRevoked(cardId: String): Boolean = cardId in revokedIds
    fun check(cardId: String) {
        if (isRevoked(cardId)) throw TransactionInvariants.RevokedCardException(cardId)
    }
    companion object {
        fun fromIds(ids: List<String>) = RevocationList(ids.toSet())
    }
}

/**
 * Payment flow — two-tap offline transfer:
 *  1. Tap payer card → SELECT → MUTUAL_AUTH → GET_BALANCE → DEBIT(amount)
 *  2. Tap payee card → SELECT → MUTUAL_AUTH → CREDIT(amount)
 *  3. Record TX for settlement; queue + settle on reconnect.
 *
 * All APDU errors map to typed exceptions. Invariants are checked before writes.
 */
class PaymentFlow(
    private val transactionDao: TransactionDao,
    private val revocationList: RevocationList = RevocationList(),
) {

    /**
     * Execute step 1 — debit payer. Returns new payer balance.
     * Caller must ensure [payerCardId] is not revoked before calling.
     */
    suspend fun debitPayer(
        channel: CardChannel,
        payerCardId: String,
        amount: Int,
        nonce: String,
    ): Int {
        revocationList.check(payerCardId)
        // Double-credit guard: nonce must be unique across all tx
        TransactionInvariants.checkNoDoubleCredit(nonce, transactionDao.byNonce(nonce))
        TransactionInvariants.checkOfflineCap(amount, transactionDao.pendingTotal())

        // SELECT
        val sel = channel.transceive(ApduCommands.select())
        if (sel.isRevoked) throw TransactionInvariants.RevokedCardException(payerCardId)
        check(sel.isSuccess) { "SELECT failed: sw=${sel.sw.toString(16)}" }

        // MUTUAL_AUTH (stub challenge)
        val auth = channel.transceive(ApduCommands.mutualAuth(ByteArray(8) { 0x42 }))
        check(auth.isSuccess) { "Mutual auth failed: sw=${auth.sw.toString(16)}" }

        // DEBIT
        val debit = channel.transceive(ApduCommands.debit(amount))
        if (debit.sw == ApduCommands.SW_INSUFFICIENT) throw TransactionInvariants.NegativeBalanceException("Insufficient funds")
        check(debit.isSuccess) { "DEBIT failed: sw=${debit.sw.toString(16)}" }
        val newBalance = bytesToInt(debit.data)
        TransactionInvariants.checkBalanceNonNegative(newBalance)
        return newBalance
    }

    /**
     * Execute step 2 — credit payee. Must be called after successful [debitPayer].
     */
    suspend fun creditPayee(
        channel: CardChannel,
        payeeCardId: String,
        amount: Int,
    ): Int {
        revocationList.check(payeeCardId)

        val sel = channel.transceive(ApduCommands.select())
        check(sel.isSuccess) { "SELECT failed" }
        val auth = channel.transceive(ApduCommands.mutualAuth(ByteArray(8) { 0x43 }))
        check(auth.isSuccess) { "Mutual auth failed" }

        val credit = channel.transceive(ApduCommands.credit(amount))
        check(credit.isSuccess) { "CREDIT failed: sw=${credit.sw.toString(16)}" }
        return bytesToInt(credit.data)
    }

    /**
     * Full two-tap flow — convenience when both channels are available sequentially.
     * Stores the settlement record (PENDING_SETTLEMENT) and returns it.
     */
    suspend fun executeTwoTap(
        payerChannel: CardChannel,
        payeeChannel: CardChannel,
        payerCardId: String,
        payeeCardId: String,
        amount: Int,
        nonce: String = java.util.UUID.randomUUID().toString(),
    ): TransactionRecord {
        val payerBal = debitPayer(payerChannel, payerCardId, amount, nonce)
        val payeeBal = creditPayee(payeeChannel, payeeCardId, amount)
        val record = TransactionRecord(
            id = nonce,
            amount = amount,
            payerCardId = payerCardId,
            payeeCardId = payeeCardId,
            timestamp = System.currentTimeMillis(),
            status = "PENDING_SETTLEMENT",
            payerNewBalance = payerBal,
            payeeNewBalance = payeeBal,
            nonce = nonce,
        )
        transactionDao.insert(record)
        return record
    }

    /** Queue for settlement — called when online to push to backend. */
    suspend fun settlePending(settler: suspend (List<TransactionRecord>) -> Unit) {
        val pending = transactionDao.pending()
        if (pending.isEmpty()) return
        settler(pending)
        pending.forEach { transactionDao.updateStatus(it.id, "SETTLED") }
    }

    private fun bytesToInt(b: ByteArray): Int {
        if (b.size < 4) return 0
        return ((b[0].toInt() and 0xFF) shl 24) or ((b[1].toInt() and 0xFF) shl 16) or ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    }
}

package net.sharenet.attest

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow

/**
 * Points ledger — local mirror of the backend points balance.
 *
 * Points are credited locally when a receipt is queued, but marked `availableAt`
 * 30 days in the future (payout holdback). The backend is authoritative; on
 * sync the local ledger is reconciled. Clawback within the holdback window
 * simply flips [PointsEntry.clawedBack].
 *
 * Ledger arithmetic is integer-only (minor units) — never floating point.
 */
class PointsLedger(
    private val dao: PointsLedgerDao,
    private val holdbackDays: Long = 30L,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    private val _available = MutableStateFlow(0L)
    val availablePoints: Flow<Long> = _available.asStateFlow()

    private val _pending = MutableStateFlow(0L)
    val pendingPoints: Flow<Long> = _pending.asStateFlow()

    /** Credit points for [entity] — called after receipt is persisted. */
    suspend fun credit(entity: ReceiptEntity, points: Long) {
        val now = clock()
        val entry = PointsEntry(
            receiptId = entity.receiptId,
            blobIdHex = entity.blobIdHex,
            points = points,
            availableAt = now + holdbackDays * 86_400_000L,
            createdAt = now,
        )
        dao.insert(entry)
        refresh()
    }

    /** Reconcile after backend reports clawback for [receiptId]. */
    suspend fun clawBack(receiptId: String) {
        dao.clawBack(receiptId)
        refresh()
    }

    /** Total available (holdback elapsed, not clawed back). */
    suspend fun available(): Long = dao.availablePoints(clock())

    /** Total pending (still in holdback). */
    suspend fun pending(): Long = dao.pendingPoints(clock())

    private suspend fun refresh() {
        val now = clock()
        _available.value = dao.availablePoints(now)
        _pending.value = dao.pendingPoints(now)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Deterministic points for a receipt — replace with backend-provided value. */
fun pointsForReceipt(bytesDelivered: Long, category: net.sharenet.crypto.Category? = null): Long {
    // Standard delivery: 1 point per MB.
    val mb = bytesDelivered / (1024 * 1024)
    val basePoints = mb * 1000L

    // If it's an AD, we might have a different logic or multiplier
    return if (category == net.sharenet.crypto.Category.AD) basePoints * 2 else basePoints
}

/** 
 * Rewards for bridging the mesh to the real internet.
 * Earned when a node fetches a manifest from a verified backend.
 */
fun pointsForBridging(bytesBridged: Long): Long {
    // Bridging is highly valued: 5 points per MB.
    val mb = bytesBridged / (1024 * 1024)
    return mb * 5000L
}

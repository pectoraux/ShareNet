package net.sharenet.attest

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.CryptoProvider
import net.sharenet.crypto.DeliveryReceipt
import net.sharenet.crypto.FakeCborCodec
import net.sharenet.crypto.Keypair
import net.sharenet.crypto.NodeId
import java.security.SecureRandom

/**
 * High-level receipt manager — the public surface for attestation.
 *
 * Responsibilities:
 * - Generate receipts: recipient signs over (blobId, bytesDelivered, senderId, recipientId, timestamp, nonce).
 * - Verify receipts (Ed25519 via [CryptoProvider]).
 * - Queue to Room ([ReceiptDao]) with fraud pre-checks ([FraudControls]).
 * - Opportunistic upload to backend (retry with exponential backoff).
 * - Credit [PointsLedger] (30-day holdback).
 *
 * Fraud controls are applied locally before queuing (fast feedback) and
 * authoritatively on the backend on upload. Local decisions never override
 * backend clawback.
 *
 * @param crypto Ed25519 provider (Tink in prod, [net.sharenet.crypto.FakeCryptoProvider] in tests).
 * @param receiptDao Room DAO for receipt queue.
 * @param pointsLedger local points ledger.
 * @param fraudControls local fraud pre-checks.
 * @param uploader backend upload client; inject fake in tests.
 * @param clock injectable clock for determinism.
 * @param scope coroutine scope for background upload.
 */
class ReceiptManager(
    private val crypto: CryptoProvider,
    private val receiptDao: ReceiptDao,
    private val pointsLedger: PointsLedger,
    private val fraudControls: FraudControls,
    private val uploader: ReceiptUploader,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO),
) {

    private val mutex = Mutex()

    /**
     * Generate a delivery receipt.
     *
     * MUST be called on the **recipient** device — it signs with [recipientKeypair].
     * The sender cannot forge this signature (adversarial test in roadmap M4).
     *
     * @param blobId content delivered.
     * @param bytesDelivered bytes actually transferred (may be < blob total for partial).
     * @param senderId who sent the bytes.
     * @param recipientKeypair recipient's keypair (signer).
     * @param nonce 16-byte anti-replay nonce; generated if omitted.
     */
    fun generateReceipt(
        blobId: BlobId,
        bytesDelivered: Long,
        senderId: NodeId,
        recipientKeypair: Keypair,
        nonce: ByteArray = randomNonce(),
    ): DeliveryReceipt {
        require(nonce.size == 16) { "nonce must be 16 bytes" }
        val recipientId = recipientKeypair.nodeId
        val timestamp = clock()
        val unsigned = DeliveryReceipt(
            blobId = blobId,
            bytesDelivered = bytesDelivered,
            senderId = senderId,
            recipientId = recipientId,
            timestamp = timestamp,
            nonce = nonce,
            recipientSignature = ByteArray(0), // placeholder
        )
        val message = FakeCborCodec.encodeReceipt(unsigned)
        val sig = crypto.sign(recipientKeypair.privateKey, message)
        return unsigned.copy(recipientSignature = sig)
    }

    /**
     * Verify a receipt's Ed25519 signature.
     * @return true if signature is valid for [receipt.recipientId].
     */
    fun verify(receipt: DeliveryReceipt): Boolean {
        val unsigned = receipt.copy(recipientSignature = ByteArray(0))
        val message = FakeCborCodec.encodeReceipt(unsigned)
        return crypto.verify(receipt.recipientId.publicKey, message, receipt.recipientSignature)
    }

    /**
     * Queue a receipt for upload.
     *
     * Applies [FraudControls.evaluate] before insert. On [FraudDecision.Blocked], the receipt
     * is not queued and an exception is thrown. On [FraudDecision.AllowedWithWeight(0.0)], the
     * receipt is queued but points will be 0 (diversity weighting).
     *
     * Duplicate (same receiptId) is a no-op (replay protection via Room IGNORE).
     *
     * @return the persisted [ReceiptEntity] or null if duplicate.
     * @throws FraudBlockedException if fraud controls block the receipt.
     */
    suspend fun queue(receipt: DeliveryReceipt): ReceiptEntity? = mutex.withLock {
        require(verify(receipt)) { "Receipt signature invalid" }
        val entity = receipt.toEntity()
        when (val decision = fraudControls.evaluate(entity)) {
            is FraudDecision.Blocked -> throw FraudBlockedException(decision.reason, decision.code)
            is FraudDecision.AllowedWithWeight -> {
                // Still queue, but ledger will credit 0 when weight is 0.
            }
            FraudDecision.Allowed -> Unit
        }
        val rowId = receiptDao.insertOrIgnore(entity)
        if (rowId == -1L) return null // duplicate
        fraudControls.record(entity)
        val points = when (val d = fraudControls.evaluate(entity)) {
            is FraudDecision.AllowedWithWeight -> if (d.weight == 0.0) 0L else pointsForReceipt(receipt.bytesDelivered)
            else -> pointsForReceipt(receipt.bytesDelivered)
        }
        pointsLedger.credit(entity, points)
        entity
    }

    /**
     * Upload all queued receipts to the backend.
     *
     * - Calls [PlayIntegrityVerifier] and attaches result.
     * - On success, marks receipts UPLOADED.
     * - On transient failure, leaves them QUEUED for retry (exponential backoff via WorkManager).
     *
     * @return number of receipts uploaded.
     */
    suspend fun upload(integrityVerifier: PlayIntegrityVerifier = StubPlayIntegrityVerifier()): Int {
        val pending = receiptDao.queued(limit = 100)
        if (pending.isEmpty()) return 0
        val integrity = integrityVerifier.verify()
        var uploaded = 0
        for (entity in pending) {
            try {
                receiptDao.markAttempt(entity.receiptId, ReceiptStatus.UPLOADING, clock())
                val receipt = entity.toReceipt()
                uploader.upload(receipt, integrity)
                receiptDao.markUploaded(entity.receiptId)
                uploaded++
            } catch (e: Exception) {
                receiptDao.markAttempt(entity.receiptId, ReceiptStatus.QUEUED, clock())
                // Exponential backoff: WorkManager schedules retry; we just log.
            }
        }
        return uploaded
    }

    /** Number of receipts still queued (not yet uploaded). */
    suspend fun queuedCount(): Int = receiptDao.queuedCount()

    /** Periodic upload loop — call from WorkManager or app foreground. */
    fun startPeriodicUpload(
        intervalMs: Long = 15 * 60 * 1000L,
        integrityVerifier: PlayIntegrityVerifier = StubPlayIntegrityVerifier(),
    ) {
        scope.launch {
            while (true) {
                delay(intervalMs)
                try { upload(integrityVerifier) } catch (_: Exception) { }
            }
        }
    }

    private fun randomNonce(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
}

// ---------------------------------------------------------------------------
// Upload abstraction
// ---------------------------------------------------------------------------

/** Backend receipt ingest client. */
interface ReceiptUploader {
    suspend fun upload(receipt: DeliveryReceipt, integrity: IntegrityResult)
}

/** No-op uploader for offline / tests — stores uploads in memory. */
class InMemoryUploader : ReceiptUploader {
    val uploaded = mutableListOf<Pair<DeliveryReceipt, IntegrityResult>>()
    var shouldFail: Boolean = false
    override suspend fun upload(receipt: DeliveryReceipt, integrity: IntegrityResult) {
        if (shouldFail) throw RuntimeException("Simulated upload failure")
        uploaded += receipt to integrity
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

class FraudBlockedException(message: String, val code: String) : Exception(message)

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun DeliveryReceipt.toEntity(): ReceiptEntity {
    val rid = "${blobId.merkleRoot.toHex()}:${recipientId.publicKey.toHex()}:${nonce.toHex()}"
    return ReceiptEntity(
        receiptId = rid,
        blobIdHex = blobId.merkleRoot.toHex(),
        bytesDelivered = bytesDelivered,
        senderIdHex = senderId.publicKey.toHex(),
        recipientIdHex = recipientId.publicKey.toHex(),
        timestamp = timestamp,
        nonceHex = nonce.toHex(),
        recipientSignatureHex = recipientSignature.toHex(),
    )
}

fun ReceiptEntity.toReceipt(): DeliveryReceipt = DeliveryReceipt(
    blobId = BlobId(blobIdHex.hexToBytes()),
    bytesDelivered = bytesDelivered,
    senderId = NodeId(senderIdHex.hexToBytes()),
    recipientId = NodeId(recipientIdHex.hexToBytes()),
    timestamp = timestamp,
    nonce = nonceHex.hexToBytes(),
    recipientSignature = recipientSignatureHex.hexToBytes(),
)

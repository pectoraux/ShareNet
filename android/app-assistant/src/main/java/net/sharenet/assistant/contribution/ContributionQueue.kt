package net.sharenet.assistant.contribution

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.UUID

/**
 * Signed contribution — mirrors backend `Contribution` shape.
 * In production the signature is Ed25519 over deterministic CBOR
 * produced by `core-crypto`.
 */
data class Contribution(
    val id: String = UUID.randomUUID().toString(),
    val contributorId: String, // hex NodeId public key
    val sourceLang: String,
    val targetLang: String,
    val sourceText: String,
    val correctedText: String,
    val originalModelOutput: String?,
    val modelVersion: String?,
    val capturedAt: Long = System.currentTimeMillis(),
    val signature: ByteArray? = null, // null until signed
) {
    fun isSigned(): Boolean = signature != null && signature.isNotEmpty()
}

/**
 * In-memory queue (backed by Room in prod, DataStore for consent).
 * Queued items are delivered opportunistically via ShareNet transport.
 */
class ContributionQueue {
    private val _queue = MutableStateFlow<List<Contribution>>(emptyList())
    val queue: StateFlow<List<Contribution>> = _queue

    private val _consentGranted = MutableStateFlow(false)
    val consentGranted: StateFlow<Boolean> = _consentGranted

    fun setConsent(granted: Boolean) {
        _consentGranted.value = granted
    }

    fun enqueue(contribution: Contribution) {
        check(_consentGranted.value) { "Consent required before enqueueing contributions" }
        // In prod: sign with core-crypto, then persist to Room
        val signed = contribution.copy(signature = fakeSign(contribution))
        _queue.value = _queue.value + signed
    }

    /** Called by transport layer when online — drains the queue. */
    suspend fun drainAndUpload(uploader: suspend (List<Contribution>) -> Unit) {
        val pending = _queue.value
        if (pending.isEmpty()) return
        uploader(pending)
        _queue.value = emptyList()
    }

    fun pendingCount(): Int = _queue.value.size

    private fun fakeSign(c: Contribution): ByteArray =
        "sig:${c.id}:${c.correctedText.hashCode()}".toByteArray()
}

/**
 * Contributor dashboard — read model over the queue + delivered history.
 */
data class ContributorStats(
    val pending: Int,
    val delivered: Int,
)

class ContributorDashboard(private val queue: ContributionQueue) {
    private var deliveredCount = 0

    fun stats(): ContributorStats = ContributorStats(
        pending = queue.pendingCount(),
        delivered = deliveredCount,
    )

    fun markDelivered(count: Int) { deliveredCount += count }
}

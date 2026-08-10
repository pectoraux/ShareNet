package net.sharenet.attest

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Fraud controls — M4 stubs with real interfaces.
 *
 * Real backend enforces these on ingest, but the client also applies local
 * pre-checks to avoid queuing obviously abusive receipts.
 *
 * Controls (from roadmap §M4):
 * - Recipient diversity — same (sender, recipient) pair beyond N/day weighted to zero.
 * - Rate caps — hard ceiling per identity per day.
 * - Geographic/temporal plausibility — reject impossible sequences.
 * - Play Integrity — device attestation on upload.
 * - Payout holdback — 30 days before points convert.
 */

data class FraudConfig(
    val maxReceiptsPerRecipientPerDay: Int = 10,
    val maxReceiptsPerSenderPerDay: Int = 100,
    val maxBytesPerSenderPerDay: Long = 10L * 1024 * 1024 * 1024, // 10 GiB
    val recipientDiversityWindowDays: Int = 1,
    val plausibilityMaxKmPerHour: Double = 120.0,
)

sealed interface FraudDecision {
    data object Allowed : FraudDecision
    data class Blocked(val reason: String, val code: String) : FraudDecision
    /** Allowed but flagged for reduced weighting. */
    data class AllowedWithWeight(val weight: Double, val reason: String) : FraudDecision
}

interface FraudControls {
    /** Evaluate [entity] before queuing. */
    suspend fun evaluate(entity: ReceiptEntity): FraudDecision

    /** Record that [entity] was queued (for diversity/rate counters). */
    suspend fun record(entity: ReceiptEntity)
}

/**
 * In-memory implementation backed by simple counters.
 * Replace with Room-backed counters and location history in production.
 */
class DefaultFraudControls(
    private val config: FraudConfig = FraudConfig(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) : FraudControls {

    // (senderHex:recipientHex:dayBucket) → count
    private val pairCounts = mutableMapOf<String, Int>()
    // senderHex:dayBucket → count
    private val senderCounts = mutableMapOf<String, Int>()

    override suspend fun evaluate(entity: ReceiptEntity): FraudDecision {
        val day = entity.timestamp / 86_400_000L
        val pairKey = "${entity.senderIdHex}:${entity.recipientIdHex}:$day"
        val senderKey = "${entity.senderIdHex}:$day"

        val pairCount = pairCounts[pairKey] ?: 0
        if (pairCount >= config.maxReceiptsPerRecipientPerDay) {
            // Diversity rule: beyond N/day weighted to zero — local equivalent is blocked with hint.
            return FraudDecision.AllowedWithWeight(0.0, "Recipient diversity cap: $pairCount >= ${config.maxReceiptsPerRecipientPerDay}")
        }
        val senderCount = senderCounts[senderKey] ?: 0
        if (senderCount >= config.maxReceiptsPerSenderPerDay) {
            return FraudDecision.Blocked("Rate cap: $senderCount receipts today >= ${config.maxReceiptsPerSenderPerDay}", "RATE_CAP")
        }
        // Geographic plausibility requires location — stub always passes locally; backend enforces.
        return FraudDecision.Allowed
    }

    override suspend fun record(entity: ReceiptEntity) {
        val day = entity.timestamp / 86_400_000L
        val pairKey = "${entity.senderIdHex}:${entity.recipientIdHex}:$day"
        val senderKey = "${entity.senderIdHex}:$day"
        pairCounts[pairKey] = (pairCounts[pairKey] ?: 0) + 1
        senderCounts[senderKey] = (senderCounts[senderKey] ?: 0) + 1
    }

    fun reset() { pairCounts.clear(); senderCounts.clear() }
}

// ---------------------------------------------------------------------------
// Play Integrity stub
// ---------------------------------------------------------------------------

/** Result of a Play Integrity check. */
sealed interface IntegrityResult {
    data object Passed : IntegrityResult
    data class Failed(val reason: String) : IntegrityResult
    data object Unavailable : IntegrityResult // e.g. Play Services not installed
}

interface PlayIntegrityVerifier {
    suspend fun verify(): IntegrityResult
}

/** Stub that always returns [IntegrityResult.Unavailable] on devices without Play Services. */
class StubPlayIntegrityVerifier : PlayIntegrityVerifier {
    override suspend fun verify(): IntegrityResult = IntegrityResult.Unavailable
}

/**
 * Real implementation placeholder — call Play Integrity API, send token to backend for verification.
 * Requires `com.google.android.play:integrity` dependency and a backend verifier.
 */
class PlayIntegrityVerifierImpl : PlayIntegrityVerifier {
    override suspend fun verify(): IntegrityResult {
        // Real:
        // val integrityManager = IntegrityManagerFactory.create(context)
        // val token = integrityManager.requestIntegrityToken(...)
        // return backend.verifyIntegrityToken(token)
        return IntegrityResult.Unavailable
    }
}

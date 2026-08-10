package net.sharenet.testing

import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Seeded fixtures for deterministic tests — 20 keypairs, sample manifests, blobs, contributions.
 *
 * All randomness is seeded via [seed] so golden-vector and adversarial tests are reproducible.
 * No `SecureRandom` in fixtures — use [Random(seed)] throughout.
 */

// ---------------------------------------------------------------------------
// Seeded keypairs
// ---------------------------------------------------------------------------

/**
 * Deterministic keypair derived from a 32-byte seed via HMAC-SHA256.
 * Mirrors [net.sharenet.crypto.FakeCryptoProvider.keypairFromSeed] so tests share the same derivation.
 */
data class FixtureKeypair(val publicKey: ByteArray, val privateKey: ByteArray) {
    val nodeIdHex: String get() = publicKey.toHex()
    override fun equals(other: Any?): Boolean {
        if (other !is FixtureKeypair) return false
        return publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
    }
    override fun hashCode(): Int = publicKey.contentHashCode()
}

private fun deriveKeypair(seed: ByteArray): FixtureKeypair {
    require(seed.size == 32)
    val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(seed, "HmacSHA256")) }
    val pub = mac.doFinal("sharenet-pub".toByteArray()).copyOf(32)
    return FixtureKeypair(pub, seed.copyOf())
}

/**
 * 20 deterministic fixtures — index 0..19.
 * Seed i is `SHA256("sharenet-fixture-$i")`.
 */
object Fixtures {
    /** 20 keypairs. */
    val keypairs: List<FixtureKeypair> = (0 until 20).map { i ->
        val seed = MessageDigest.getInstance("SHA-256").digest("sharenet-fixture-$i".toByteArray())
        deriveKeypair(seed)
    }

    /** Convenience: publisher fixture (index 0). */
    val publisher: FixtureKeypair get() = keypairs[0]

    /** Convenience: recipient fixture (index 1). */
    val recipient: FixtureKeypair get() = keypairs[1]

    /** Deterministic blob bytes for index [i] — size varies to exercise chunking. */
    fun blobBytes(i: Int, sizeBytes: Int = (i + 1) * 1024): ByteArray {
        val r = Random(1000L + i)
        return ByteArray(sizeBytes) { r.nextInt(256).toByte() }
    }

    /** SHA-256 hex of [data]. */
    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).toHex()

    /** Merkle root hex for a list of chunk hexes (simplified: SHA256 of concatenated chunk hashes). */
    fun merkleRootHex(chunkHexes: List<String>): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (h in chunkHexes) md.update(h.hexToBytes())
        return md.digest().toHex()
    }

    // ------------------------------------------------------------------ Sample manifests
    // ------------------------------------------------------------------

    data class ManifestFixture(
        val blobIdHex: String,
        val chunkHexes: List<String>,
        val totalBytes: Long,
        val mimeType: String,
        val publisherHex: String,
        val publishedAt: Long,
        val expiresAt: Long?,
        val category: String,
        val priority: Int,
        val minAppVersion: Int,
    )

    /** 5 sample manifests across categories. */
    val manifests: List<ManifestFixture> = listOf(
        ManifestFixture(
            blobIdHex = sha256Hex(blobBytes(0, 512)),
            chunkHexes = listOf(sha256Hex(blobBytes(0, 512))),
            totalBytes = 512, mimeType = "text/html", publisherHex = publisher.nodeIdHex,
            publishedAt = 1735689600000L, expiresAt = null, category = "EDUCATION", priority = 50, minAppVersion = 1,
        ),
        ManifestFixture(
            blobIdHex = sha256Hex(blobBytes(1, 2 * 1024)),
            chunkHexes = listOf(sha256Hex(blobBytes(1, 1024)), sha256Hex(blobBytes(2, 1024))),
            totalBytes = 2048, mimeType = "video/mp4", publisherHex = keypairs[2].nodeIdHex,
            publishedAt = 1735776000000L, expiresAt = 1767312000000L, category = "HEALTH", priority = 50, minAppVersion = 2,
        ),
        ManifestFixture(
            blobIdHex = sha256Hex(blobBytes(3, 0)),
            chunkHexes = emptyList(), totalBytes = 0, mimeType = "application/octet-stream",
            publisherHex = keypairs[3].nodeIdHex, publishedAt = 1735862400000L, expiresAt = null,
            category = "MODEL_WEIGHTS", priority = 80, minAppVersion = 1,
        ),
        ManifestFixture(
            blobIdHex = sha256Hex(blobBytes(4, 5 * 1024)),
            chunkHexes = (0 until 5).map { sha256Hex(blobBytes(10 + it, 1024)) },
            totalBytes = 5120, mimeType = "application/vnd.sharenet.revocation",
            publisherHex = publisher.nodeIdHex, publishedAt = 1735948800000L, expiresAt = null,
            category = "REVOCATION", priority = Int.MAX_VALUE, minAppVersion = 1,
        ),
        ManifestFixture(
            blobIdHex = sha256Hex(blobBytes(5, 10 * 1024)),
            chunkHexes = (0 until 10).map { sha256Hex(blobBytes(20 + it, 1024)) },
            totalBytes = 10 * 1024, mimeType = "application/octet-stream",
            publisherHex = keypairs[4].nodeIdHex, publishedAt = 1736035200000L, expiresAt = null,
            category = "APP_UPDATE", priority = 100, minAppVersion = 3,
        ),
    )

    // ------------------------------------------------------------------ Sample contributions
    // ------------------------------------------------------------------

    data class ContributionFixture(
        val id: String,
        val contributorHex: String,
        val sourceLang: String,
        val targetLang: String,
        val sourceText: String,
        val correctedText: String,
        val originalModelOutput: String?,
        val modelVersion: String?,
        val capturedAt: Long,
    )

    val contributions: List<ContributionFixture> = listOf(
        ContributionFixture(
            id = UUID.nameUUIDFromBytes("contrib-0".toByteArray()).toString(),
            contributorHex = keypairs[5].nodeIdHex, sourceLang = "en", targetLang = "twi",
            sourceText = "Good morning", correctedText = "Maakye", originalModelOutput = "Maakye pa",
            modelVersion = "gemma-3-1b-v1", capturedAt = 1735689600000L,
        ),
        ContributionFixture(
            id = UUID.nameUUIDFromBytes("contrib-1".toByteArray()).toString(),
            contributorHex = keypairs[6].nodeIdHex, sourceLang = "twi", targetLang = "en",
            sourceText = "Ɛte sɛn?", correctedText = "How are you?", originalModelOutput = "How is it?",
            modelVersion = "gemma-3-1b-v1", capturedAt = 1735776000000L,
        ),
        ContributionFixture(
            id = UUID.nameUUIDFromBytes("contrib-2".toByteArray()).toString(),
            contributorHex = keypairs[7].nodeIdHex, sourceLang = "ewe", targetLang = "en",
            sourceText = "Ŋdi na wo", correctedText = "Good morning", originalModelOutput = null,
            modelVersion = null, capturedAt = 1735862400000L,
        ),
    )

    // ------------------------------------------------------------------ Helpers
    // ------------------------------------------------------------------

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

// ---------------------------------------------------------------------------
// Shared hex helpers (also used by GoldenVectors)
// ---------------------------------------------------------------------------

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
internal fun String.hexToBytes(): ByteArray =
    if (isEmpty()) ByteArray(0) else chunked(2).map { it.toInt(16).toByte() }.toByteArray()

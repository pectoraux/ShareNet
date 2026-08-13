package net.sharenet.crypto

import java.util.UUID

/**
 * Stable identity for a node / publisher / contributor.
 *
 * The Ed25519 public key (32 bytes) is the primary key everywhere.
 * Equality and hashCode are content-based over the byte array.
 */
data class NodeId(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "NodeId must be 32 bytes, got ${bytes.size}" }
    }

    /** Alias for [bytes] — older stubs use `publicKey`. */
    val publicKey: ByteArray get() = bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NodeId) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = bytes.toHex()

    /** Hex encoding, lowercase, no prefix. */
    fun toHex(): String = bytes.toHex()

    companion object {
        fun fromHex(hex: String): NodeId = NodeId(hex.hexToBytes())
    }
}

/**
 * Content-addressed chunk identifier — SHA-256 of the chunk bytes.
 */
data class ChunkId(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "ChunkId must be 32 bytes (SHA-256), got ${bytes.size}" }
    }

    /** Alias for [bytes] — older stubs use `sha256`. */
    val sha256: ByteArray get() = bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChunkId) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    /** Hex encoding, lowercase, no prefix. */
    fun toHex(): String = bytes.toHex()

    companion object {
        fun fromHex(hex: String): BlobId = BlobId(hex.hexToBytes())
    }
}

/**
 * Blob identifier — Merkle root of the chunk list (SHA-256).
 * For a single-chunk blob, the root equals that chunk's hash.
 */
data class BlobId(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "BlobId must be 32 bytes (Merkle root), got ${bytes.size}" }
    }

    /** Alias for [bytes] — older stubs use `merkleRoot`. */
    val merkleRoot: ByteArray get() = bytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BlobId) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    /** Hex encoding, lowercase, no prefix. */
    fun toHex(): String = bytes.toHex()

    companion object {
        fun fromHex(hex: String): BlobId = BlobId(hex.hexToBytes())
    }
}

/**
 * Categories for catalog filtering and priority scheduling.
 * Ordinal is NOT persisted — [code] is the stable identifier.
 */
enum class Category(val code: String) {
    EDUCATION("education"),
    HEALTH("health"),
    APP_UPDATE("app_update"),
    MODEL_WEIGHTS("model_weights"),
    DATASET("dataset"),
    APP_BUNDLE("app_bundle"),
    AD("ad"),
    REVOCATION("revocation");

    companion object {
        fun fromCode(code: String): Category =
            entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unknown category code: $code")
    }
}

/**
 * Signed manifest describing a blob.
 *
 * @property blobId Merkle root of [chunks].
 * @property chunks Ordered list of chunk hashes (Merkle leaves).
 * @property totalBytes Sum of chunk sizes; verified on fetch.
 * @property mimeType IANA media type.
 * @property publisherId Ed25519 public key of the publisher.
 * @property publishedAt Epoch millis.
 * @property expiresAt Optional expiry; null means never expires.
 * @property signature Ed25519 signature over canonical CBOR encoding of the
 *   manifest without the signature field itself (see [Cbor.encodeManifest]).
 */
data class Manifest(
    val blobId: BlobId,
    val chunks: List<ChunkId>,
    val totalBytes: Long,
    val mimeType: String,
    val publisherId: NodeId,
    val publishedAt: Long,
    val expiresAt: Long?,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Manifest) return false
        return blobId == other.blobId &&
            chunks == other.chunks &&
            totalBytes == other.totalBytes &&
            mimeType == other.mimeType &&
            publisherId == other.publisherId &&
            publishedAt == other.publishedAt &&
            expiresAt == other.expiresAt &&
            signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = blobId.hashCode()
        result = 31 * result + chunks.hashCode()
        result = 31 * result + totalBytes.hashCode()
        result = 31 * result + mimeType.hashCode()
        result = 31 * result + publisherId.hashCode()
        result = 31 * result + publishedAt.hashCode()
        result = 31 * result + (expiresAt?.hashCode() ?: 0)
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

/**
 * Catalog entry wrapping a manifest with distribution metadata.
 *
 * @property priority Higher value = higher propagation priority. [REVOCATION] = Int.MAX_VALUE.
 * @property minAppVersion Minimum app version that can handle this content.
 */
data class CatalogEntry(
    val manifest: Manifest,
    val category: Category,
    val priority: Int,
    val minAppVersion: Int,
) {
    companion object {
        const val PRIORITY_REVOCATION: Int = Int.MAX_VALUE
        const val PRIORITY_DEFAULT: Int = 0
    }
}

/**
 * Delivery receipt — proof that [recipientId] received [blobId] from [senderId].
 *
 * The [recipientSignature] is produced by the *recipient* over canonical CBOR
 * of the receipt fields excluding the signature. The sender cannot forge it.
 * [nonce] is recipient-generated and prevents replay.
 */
data class DeliveryReceipt(
    val blobId: BlobId,
    val bytesDelivered: Long,
    val senderId: NodeId,
    val recipientId: NodeId,
    val timestamp: Long,
    val nonce: ByteArray,
    val recipientSignature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DeliveryReceipt) return false
        return blobId == other.blobId &&
            bytesDelivered == other.bytesDelivered &&
            senderId == other.senderId &&
            recipientId == other.recipientId &&
            timestamp == other.timestamp &&
            nonce.contentEquals(other.nonce) &&
            recipientSignature.contentEquals(other.recipientSignature)
    }

    override fun hashCode(): Int {
        var result = blobId.hashCode()
        result = 31 * result + bytesDelivered.hashCode()
        result = 31 * result + senderId.hashCode()
        result = 31 * result + recipientId.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + recipientSignature.contentHashCode()
        return result
    }
}

/**
 * Translation contribution for corpus building.
 *
 * @property signature Ed25519 signature over canonical CBOR without the signature field.
 */
data class Contribution(
    val id: UUID,
    val contributorId: NodeId,
    val sourceLang: String,
    val targetLang: String,
    val sourceText: String,
    val correctedText: String,
    val originalModelOutput: String?,
    val modelVersion: String?,
    val capturedAt: Long,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Contribution) return false
        return id == other.id &&
            contributorId == other.contributorId &&
            sourceLang == other.sourceLang &&
            targetLang == other.targetLang &&
            sourceText == other.sourceText &&
            correctedText == other.correctedText &&
            originalModelOutput == other.originalModelOutput &&
            modelVersion == other.modelVersion &&
            capturedAt == other.capturedAt &&
            signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + contributorId.hashCode()
        result = 31 * result + sourceLang.hashCode()
        result = 31 * result + targetLang.hashCode()
        result = 31 * result + sourceText.hashCode()
        result = 31 * result + correctedText.hashCode()
        result = 31 * result + (originalModelOutput?.hashCode() ?: 0)
        result = 31 * result + (modelVersion?.hashCode() ?: 0)
        result = 31 * result + capturedAt.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

// ---------------------------------------------------------------------------
// Internal hex helpers — not public API but used by toString / fromHex.
// ---------------------------------------------------------------------------

internal fun ByteArray.toHex(): String {
    val hexChars = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
        hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
    }
    return String(hexChars)
}

internal fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        out[i] = ((hexCharToInt(this[i * 2]) shl 4) or hexCharToInt(this[i * 2 + 1])).toByte()
    }
    return out
}

private fun hexCharToInt(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("Invalid hex char: $c")
}

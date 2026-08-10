package net.sharenet.crypto

import java.io.ByteArrayOutputStream

/**
 * Deterministic (canonical) CBOR encoder/decoder.
 *
 * Implements the subset needed for ShareNet signed structures:
 *  - unsigned int  (major 0)
 *  - negative int  (major 1)
 *  - byte string   (major 2)
 *  - text string   (major 3, UTF-8)
 *  - array         (major 4)
 *  - map           (major 5) — keys sorted lexicographically by UTF-8 bytes
 *  - simple values (major 7): false (0xF4), true (0xF5), null (0xF6)
 *
 * Canonical rules (RFC 7049 §3.9 / RFC 8949 §4.2):
 *  - Integers use the shortest encoding.
 *  - Map keys are sorted by their encoded byte representation; for this
 *    implementation keys are always text strings, so sorting by UTF-8
 *    string value is equivalent and deterministic.
 *  - No indefinite-length items.
 *  - Duplicate map keys are forbidden.
 *
 * This codec is shared with the Python backend via golden-vector tests.
 * Any change must be reflected in `backend/common/cbor.py` and re-validated
 * against `golden-vectors.json`.
 */
object Cbor {

    // -----------------------------------------------------------------------
    // Public high-level encoders — these define the canonical signing form.
    // -----------------------------------------------------------------------

    /**
     * Encode a [Manifest] for signing. The `signature` field is excluded;
     * the signer signs exactly the bytes returned here.
     */
    fun encodeManifest(m: Manifest): ByteArray = encode(
        sortedMapOf(
            "blobId" to m.blobId.bytes,
            "chunks" to m.chunks.map { it.bytes },
            "expiresAt" to m.expiresAt,
            "mimeType" to m.mimeType,
            "publishedAt" to m.publishedAt,
            "publisherId" to m.publisherId.bytes,
            "totalBytes" to m.totalBytes,
        ),
    )

    /**
     * Encode a [DeliveryReceipt] for signing. The `recipientSignature` field is excluded.
     */
    fun encodeReceipt(r: DeliveryReceipt): ByteArray = encode(
        sortedMapOf(
            "blobId" to r.blobId.bytes,
            "bytesDelivered" to r.bytesDelivered,
            "nonce" to r.nonce,
            "recipientId" to r.recipientId.bytes,
            "senderId" to r.senderId.bytes,
            "timestamp" to r.timestamp,
        ),
    )

    /**
     * Encode a [Contribution] for signing. The `signature` field is excluded.
     */
    fun encodeContribution(c: Contribution): ByteArray = encode(
        sortedMapOf(
            "capturedAt" to c.capturedAt,
            "contributorId" to c.contributorId.bytes,
            "correctedText" to c.correctedText,
            "id" to c.id.toString(),
            "modelVersion" to c.modelVersion,
            "originalModelOutput" to c.originalModelOutput,
            "sourceLang" to c.sourceLang,
            "sourceText" to c.sourceText,
            "targetLang" to c.targetLang,
        ),
    )

    // -----------------------------------------------------------------------
    // Generic encode / decode
    // -----------------------------------------------------------------------

    /**
     * Encode an arbitrary value to canonical CBOR bytes.
     *
     * Supported types:
     *  - `null`
     *  - `Boolean`
     *  - `Int`, `Long`
     *  - `ByteArray` → byte string
     *  - `String` → text string
     *  - `List<*>` → array
     *  - `Map<String, *>` → map with sorted keys
     *
     * Other types throw [IllegalArgumentException].
     */
    fun encode(value: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        encodeValue(value, out)
        return out.toByteArray()
    }

    /**
     * Decode CBOR bytes to a Kotlin value. Inverse of [encode].
     * Returns `null`, `Boolean`, `Long`, `ByteArray`, `String`, `List<Any?>`, or `Map<String, Any?>`.
     */
    fun decode(bytes: ByteArray): Any? {
        val decoder = Decoder(bytes)
        val result = decoder.decodeValue()
        require(decoder.isAtEnd()) { "Trailing bytes after CBOR value" }
        return result
    }

    // -----------------------------------------------------------------------
    // Internal encoder
    // -----------------------------------------------------------------------

    private fun encodeValue(value: Any?, out: ByteArrayOutputStream) {
        when (value) {
            null -> out.write(0xF6)
            is Boolean -> out.write(if (value) 0xF5 else 0xF4)
            is Int -> encodeInt(value.toLong(), out)
            is Long -> encodeInt(value, out)
            is ByteArray -> {
                encodeHead(2, value.size.toLong(), out)
                out.write(value)
            }
            is String -> {
                val utf8 = value.toByteArray(Charsets.UTF_8)
                encodeHead(3, utf8.size.toLong(), out)
                out.write(utf8)
            }
            is List<*> -> {
                encodeHead(4, value.size.toLong(), out)
                for (elem in value) encodeValue(elem, out)
            }
            is Map<*, *> -> {
                // Canonical: sort keys by string representation lexicographically.
                @Suppress("UNCHECKED_CAST")
                val map = value as Map<String, Any?>
                val sortedKeys = map.keys.sorted()
                encodeHead(5, sortedKeys.size.toLong(), out)
                for (k in sortedKeys) {
                    encodeValue(k, out)
                    encodeValue(map[k], out)
                }
            }
            else -> throw IllegalArgumentException("Unsupported CBOR type: ${value::class.java.name}")
        }
    }

    private fun encodeInt(v: Long, out: ByteArrayOutputStream) {
        if (v >= 0) {
            encodeHead(0, v, out)
        } else {
            // CBOR negative: value -1 - n
            encodeHead(1, -1 - v, out)
        }
    }

    private fun encodeHead(major: Int, value: Long, out: ByteArrayOutputStream) {
        val mt = major shl 5
        when {
            value < 24 -> out.write(mt or value.toInt())
            value < 256 -> {
                out.write(mt or 24)
                out.write(value.toInt())
            }
            value < 65536 -> {
                out.write(mt or 25)
                out.write((value ushr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            value < 4294967296L -> {
                out.write(mt or 26)
                out.write((value ushr 24).toInt() and 0xFF)
                out.write((value ushr 16).toInt() and 0xFF)
                out.write((value ushr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            else -> {
                out.write(mt or 27)
                for (shift in 56 downTo 0 step 8) {
                    out.write(((value ushr shift) and 0xFF).toInt())
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal decoder
    // -----------------------------------------------------------------------

    private class Decoder(private val bytes: ByteArray) {
        var pos: Int = 0

        fun isAtEnd(): Boolean = pos == bytes.size

        fun decodeValue(): Any? {
            require(pos < bytes.size) { "Unexpected end of CBOR data" }
            val initial = bytes[pos++].toInt() and 0xFF
            val major = initial ushr 5
            val info = initial and 0x1F
            return when (major) {
                0 -> readUInt(info)
                1 -> -1 - readUInt(info)
                2 -> {
                    val len = readUInt(info).toInt()
                    val slice = bytes.copyOfRange(pos, pos + len)
                    pos += len
                    slice
                }
                3 -> {
                    val len = readUInt(info).toInt()
                    val slice = bytes.copyOfRange(pos, pos + len)
                    pos += len
                    String(slice, Charsets.UTF_8)
                }
                4 -> {
                    val len = readUInt(info).toInt()
                    val list = ArrayList<Any?>(len)
                    repeat(len) { list.add(decodeValue()) }
                    list
                }
                5 -> {
                    val len = readUInt(info).toInt()
                    val map = LinkedHashMap<String, Any?>(len)
                    repeat(len) {
                        val k = decodeValue()
                        require(k is String) { "Map key must be text string, got ${k?.let { it::class.java.name }}" }
                        map[k] = decodeValue()
                    }
                    map
                }
                7 -> when (info) {
                    20 -> false
                    21 -> true
                    22 -> null
                    else -> throw IllegalArgumentException("Unsupported simple value: $info")
                }
                else -> throw IllegalArgumentException("Unsupported CBOR major type: $major")
            }
        }

        private fun readUInt(info: Int): Long = when (info) {
            in 0..23 -> info.toLong()
            24 -> (bytes[pos++].toInt() and 0xFF).toLong()
            25 -> {
                val v = ((bytes[pos].toInt() and 0xFF) shl 8) or (bytes[pos + 1].toInt() and 0xFF)
                pos += 2
                v.toLong()
            }
            26 -> {
                var v = 0L
                repeat(4) { v = (v shl 8) or (bytes[pos++].toInt() and 0xFF).toLong() }
                v
            }
            27 -> {
                var v = 0L
                repeat(8) { v = (v shl 8) or (bytes[pos++].toInt() and 0xFF).toLong() }
                v
            }
            else -> throw IllegalArgumentException("Invalid additional info: $info")
        }
    }
}

/**
 * Helper to build a [LinkedHashMap] with insertion order = sorted key order.
 * Useful for deterministic encoding where call-site map literal order must not matter.
 */
private fun sortedMapOf(vararg pairs: Pair<String, Any?>): Map<String, Any?> {
    val sorted = pairs.sortedBy { it.first }
    val map = LinkedHashMap<String, Any?>(sorted.size)
    for ((k, v) in sorted) map[k] = v
    return map
}

package net.sharenet.testing

import java.io.File
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Helper to generate and verify golden JSON vectors.
 *
 * Golden vectors are the M0 interop contract: Kotlin and Python must produce byte-identical
 * deterministic CBOR + Ed25519 signatures for the same input structures. The authoritative file is
 * `android/core-crypto/src/test/resources/golden-vectors.json` and `backend/common/golden_vectors.py`.
 *
 * Format per file:
 * ```json
 * [
 *   { "name": "manifest-0", "cbor_hex": "…", "signature_hex": "…", "public_key_hex": "…" },
 *   …
 * ]
 * ```
 *
 * This helper generates that JSON from [Fixtures] and can verify it without pulling a JSON library
 * (uses manual string building to keep `:testing` dependency-free).
 */
object GoldenVectors {

    data class Vector(
        val name: String,
        val cborHex: String,
        val signatureHex: String,
        val publicKeyHex: String,
    )

    /**
     * Generate golden vectors for all 20 fixtures.
     *
     * CBOR here is faked as `SHA256(cbor_input)` → still deterministic; real impl swaps in
     * the deterministic CBOR codec. Signature is HMAC-SHA256 expanded to 64 bytes (same as
     * [Fixtures] derivation) so Kotlin and Python can be compared once Python mirrors this.
     *
     * @param outFile file to write JSON to. Parent dirs are created.
     * @return generated vectors.
     */
    fun generate(outFile: File? = null): List<Vector> {
        val vectors = mutableListOf<Vector>()
        for (i in Fixtures.keypairs.indices) {
            val kp = Fixtures.keypairs[i]
            val name = "fixture-$i"
            // Canonical input: deterministic representation of the keypair index + public key.
            val input = "sharenet-golden:$i:${kp.nodeIdHex}".toByteArray()
            val cbor = MessageDigest.getInstance("SHA-256").digest(input) // placeholder CBOR
            val sig = signFake(kp.privateKey, cbor)
            vectors += Vector(name, cbor.toHex(), sig.toHex(), kp.nodeIdHex)
        }
        // Also vectors for manifests
        for ((idx, m) in Fixtures.manifests.withIndex()) {
            val input = "sharenet-manifest:$idx:${m.blobIdHex}:${m.totalBytes}".toByteArray()
            val cbor = MessageDigest.getInstance("SHA-256").digest(input)
            val sig = signFake(Fixtures.publisher.privateKey, cbor)
            vectors += Vector("manifest-$idx", cbor.toHex(), sig.toHex(), Fixtures.publisher.nodeIdHex)
        }
        if (outFile != null) {
            outFile.parentFile?.mkdirs()
            outFile.writeText(toJson(vectors))
        }
        return vectors
    }

    /**
     * Verify that [vectors] round-trip correctly (sign → verify) using the fake crypto.
     * @return list of failures (empty if all pass).
     */
    fun verify(vectors: List<Vector>): List<String> {
        val failures = mutableListOf<String>()
        for (v in vectors) {
            val cbor = v.cborHex.hexToBytes()
            val sig = v.signatureHex.hexToBytes()
            val pub = v.publicKeyHex.hexToBytes()
            // Re-derive private key from public fixture? Use signFake consistency check:
            // We verify by re-signing with the matching fixture private key and comparing.
            val fixture = Fixtures.keypairs.find { it.nodeIdHex == v.publicKeyHex }
            if (fixture == null) {
                failures += "${v.name}: unknown public key ${v.publicKeyHex}"
                continue
            }
            val expectedSig = signFake(fixture.privateKey, cbor)
            if (!expectedSig.contentEquals(sig)) {
                failures += "${v.name}: signature mismatch"
            }
            // Also check cbor is 32 bytes (SHA-256 placeholder)
            if (cbor.size != 32) failures += "${v.name}: cbor not 32 bytes"
            if (sig.size != 64) failures += "${v.name}: sig not 64 bytes"
        }
        return failures
    }

    /**
     * Read vectors from a golden JSON file produced by [generate].
     * Minimal parser — expects the exact format from [toJson].
     */
    fun readFrom(file: File): List<Vector> {
        val text = file.readText().trim()
        if (text == "[]" || text.isEmpty()) return emptyList()
        // Regex per entry: { "name": "…", "cbor_hex": "…", "signature_hex": "…", "public_key_hex": "…" }
        val entryRegex = Regex("""\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"cbor_hex"\s*:\s*"([^"]+)"\s*,\s*"signature_hex"\s*:\s*"([^"]+)"\s*,\s*"public_key_hex"\s*:\s*"([^"]+)"\s*\}""")
        return entryRegex.findAll(text).map { m ->
            Vector(m.groupValues[1], m.groupValues[2], m.groupValues[3], m.groupValues[4])
        }.toList()
    }

    // ------------------------------------------------------------------ internals

    private fun signFake(privateKey: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(privateKey, "HmacSHA256")) }
        val h1 = mac.doFinal(message)
        mac.init(SecretKeySpec(privateKey, "HmacSHA256"))
        val h2 = mac.doFinal(message + 1.toByte())
        return ByteArray(64).also { out -> h1.copyInto(out, 0, 0, 32); h2.copyInto(out, 32, 0, 32) }
    }

    private fun toJson(vectors: List<Vector>): String = buildString {
        append("[\n")
        vectors.forEachIndexed { idx, v ->
            append("  {\"name\": \"${v.name}\", \"cbor_hex\": \"${v.cborHex}\", \"signature_hex\": \"${v.signatureHex}\", \"public_key_hex\": \"${v.publicKeyHex}\"}")
            if (idx < vectors.lastIndex) append(",")
            append("\n")
        }
        append("]\n")
    }
}

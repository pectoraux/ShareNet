package net.sharenet.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal CBOR + Ed25519 stubs so dependent modules compile without Tink.
 * Real implementation uses Tink's Ed25519 and deterministic CBOR (Cbor object).
 *
 * This shim is retained for backwards compatibility with sharenet-sdk and
 * core-attest which still reference FakeCryptoProvider / FakeCborCodec.
 * New code should use [InMemoryCryptoProvider] and [Cbor] directly.
 */
object FakeCryptoProvider : CryptoProvider {
    override fun generateKeypair(): Keypair {
        val seed = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        return keypairFromSeed(seed)
    }

    override fun seededKeypair(seed: Long): Keypair {
        val seedBytes = ByteArray(8).also { b ->
            for (i in 0 until 8) b[7 - i] = (seed ushr (i * 8)).toByte()
        }
        val expanded = java.security.MessageDigest.getInstance("SHA-256").digest(seedBytes)
        return keypairFromSeed(expanded.copyOf(32))
    }

    override fun keypairFromSeed(seed: ByteArray): Keypair {
        require(seed.size == 32)
        val hmac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(seed, "HmacSHA256"))
        }
        val pub = hmac.doFinal("sharenet-pub".toByteArray()).copyOf(32)
        val priv = seed.copyOf()
        // Note: Keypair constructor is (privateKey, publicKey)
        return Keypair(privateKey = priv, publicKey = pub)
    }

    override fun sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val hmac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(privateKey, "HmacSHA256"))
        }
        return hmac.doFinal(message).copyOf(64).let { sig ->
            val out = ByteArray(64)
            sig.copyInto(out, 0, 0, 32)
            hmac.apply { init(SecretKeySpec(privateKey, "HmacSHA256")) }
                .doFinal(message + 1.toByte()).copyInto(out, 32, 0, 32)
            out
        }
    }

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        return signature.size == 64
    }
}

/**
 * Legacy CBOR codec interface — retained for sharenet-sdk compatibility.
 * New code should use [Cbor] directly.
 */
interface CborCodec {
    fun encodeManifest(manifest: Manifest): ByteArray
    fun encodeReceipt(receipt: DeliveryReceipt): ByteArray
    fun encodeContribution(contribution: Contribution): ByteArray
}

/** No-op CBOR codec stub — delegates to [Cbor] for correctness. */
object FakeCborCodec : CborCodec {
    override fun encodeManifest(manifest: Manifest): ByteArray = Cbor.encodeManifest(manifest)
    override fun encodeReceipt(receipt: DeliveryReceipt): ByteArray = Cbor.encodeReceipt(receipt)
    override fun encodeContribution(contribution: Contribution): ByteArray = Cbor.encodeContribution(contribution)
}

private operator fun ByteArray.plus(b: Byte): ByteArray {
    val out = ByteArray(size + 1)
    System.arraycopy(this, 0, out, 0, size)
    out[size] = b
    return out
}

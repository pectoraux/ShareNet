package net.sharenet.wallet.nfc

import android.nfc.tech.IsoDep
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Abstraction over [IsoDep] so the payment flow is testable without NFC hardware.
 */
interface CardChannel {
    suspend fun transceive(apdu: ByteArray): ApduResponse
    fun isConnected(): Boolean
}

data class ApduResponse(val data: ByteArray, val sw: Int) {
    val isSuccess: Boolean get() = sw == ApduCommands.SW_SUCCESS
    val isRevoked: Boolean get() = sw == ApduCommands.SW_REVOKED
}

/** Real channel wrapping [IsoDep]. */
class IsoDepCardChannel(private val isoDep: IsoDep) : CardChannel {
    override suspend fun transceive(apdu: ByteArray): ApduResponse = withContext(Dispatchers.IO) {
        val raw = isoDep.transceive(apdu)
        require(raw.size >= 2) { "Short APDU response" }
        val sw = ((raw[raw.size - 2].toInt() and 0xFF) shl 8) or (raw[raw.size - 1].toInt() and 0xFF)
        val data = raw.copyOfRange(0, raw.size - 2)
        ApduResponse(data, sw)
    }
    override fun isConnected(): Boolean = isoDep.isConnected
}

/** Fake for tests — program expected responses in order. */
class FakeCardChannel(
    private val responses: MutableList<ApduResponse> = mutableListOf(),
    var balance: Int = 10_000,
    var revoked: Boolean = false,
) : CardChannel {
    val sentApdus = mutableListOf<ByteArray>()
    override suspend fun transceive(apdu: ByteArray): ApduResponse {
        sentApdus += apdu
        if (responses.isNotEmpty()) return responses.removeAt(0)
        // Default behavior when no queued responses
        if (revoked) return ApduResponse(ByteArray(0), ApduCommands.SW_REVOKED)
        return ApduResponse(ApduCommands.intToBytes(balance), ApduCommands.SW_SUCCESS)
    }
    override fun isConnected(): Boolean = true
    fun queue(response: ApduResponse) { responses += response }
}

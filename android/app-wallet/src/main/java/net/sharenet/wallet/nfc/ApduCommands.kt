package net.sharenet.wallet.nfc

/**
 * ISO 7816-4 APDU command definitions for the ShareNet card applet.
 *
 * CLA=0x00, P1/P2 per command. All amounts are big-endian 4-byte ints (minor units).
 */
object ApduCommands {

    // ShareNet applet AID — must match card-applet/src/main/java/net/sharenet/card/*.java
    val AID = hex("A000000632536E6574")

    /** SELECT by AID */
    fun select(): ByteArray = buildApdu(cla = 0x00, ins = 0xA4, p1 = 0x04, p2 = 0x00, data = AID)

    /** MUTUAL_AUTH — host challenge → card challenge+proof */
    fun mutualAuth(hostChallenge: ByteArray): ByteArray =
        buildApdu(cla = 0x00, ins = 0x82, p1 = 0x00, p2 = 0x00, data = hostChallenge)

    /** GET_BALANCE → 4-byte BE balance */
    fun getBalance(): ByteArray = buildApdu(cla = 0x00, ins = 0x50, p1 = 0x00, p2 = 0x00, le = 4)

    /** DEBIT amount → 4-byte BE new balance or error 0x6A84 (insufficient) */
    fun debit(amount: Int): ByteArray =
        buildApdu(cla = 0x00, ins = 0x51, p1 = 0x00, p2 = 0x00, data = intToBytes(amount), le = 4)

    /** CREDIT amount → 4-byte BE new balance */
    fun credit(amount: Int): ByteArray =
        buildApdu(cla = 0x00, ins = 0x52, p1 = 0x00, p2 = 0x00, data = intToBytes(amount), le = 4)

    /** GET_TX_LOG → TLV-encoded log */
    fun getTxLog(): ByteArray = buildApdu(cla = 0x00, ins = 0x53, p1 = 0x00, p2 = 0x00, le = 0x00)

    /** GET_OFFLINE_STATE → cap + counter */
    fun getOfflineState(): ByteArray = buildApdu(cla = 0x00, ins = 0x54, p1 = 0x00, p2 = 0x00, le = 8)

    // SW success
    const val SW_SUCCESS: Int = 0x9000
    const val SW_REVOKED: Int = 0x6A88
    const val SW_INSUFFICIENT: Int = 0x6A84
    const val SW_AUTH_FAILED: Int = 0x6300

    internal fun buildApdu(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray? = null, le: Int? = null): ByteArray {
        val out = mutableListOf<Byte>(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte())
        if (data != null) {
            out += data.size.toByte()
            out += data.toList()
        }
        if (le != null) out += le.toByte()
        return out.toByteArray()
    }

    internal fun intToBytes(v: Int): ByteArray =
        byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    internal fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

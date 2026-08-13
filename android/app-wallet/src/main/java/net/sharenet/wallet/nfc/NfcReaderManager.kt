package net.sharenet.wallet.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * NFC reader-mode helper. Delegates tag discovery to [onCard].
 *
 * Usage in Activity:
 * ```
 * nfcReader = NfcReaderManager(this, lifecycleScope) { tag -> handleTag(tag) }
 * override fun onResume() { super.onResume(); nfcReader.enable() }
 * override fun onPause() { nfcReader.disable(); super.onPause() }
 * ```
 */
class NfcReaderManager(
    private val activity: android.app.Activity,
    private val onCard: suspend (Tag) -> Unit,
) {
    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    fun isAvailable(): Boolean = adapter != null && adapter.isEnabled

    fun enable() {
        val a = adapter ?: run { Log.w(TAG, "NFC not available"); return }
        val opts = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500) }
        a.enableReaderMode(
            activity,
            { tag -> CoroutineScope(Dispatchers.Main).launchWithTag(tag) },
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            opts,
        )
        Log.i(TAG, "Reader mode enabled")
    }

    fun disable() {
        adapter?.disableReaderMode(activity)
        Log.i(TAG, "Reader mode disabled")
    }

    private fun CoroutineScope.launchWithTag(tag: Tag) = launch {
        try {
            val isoDep = IsoDep.get(tag) ?: run { Log.w(TAG, "Tag is not IsoDep"); return@launch }
            isoDep.connect()
            // Hand the connected channel to caller — caller must handle SELECT + auth + ops
            // For simple flows, wrap tag in IsoDepCardChannel and transceive directly.
            onCard(tag)
            // Note: caller is responsible for closing isoDep when done or letting it timeout.
        } catch (e: Exception) {
            Log.e(TAG, "Tag handling failed", e)
        }
    }

    companion object {
        private const val TAG = "NfcReaderManager"
    }
}

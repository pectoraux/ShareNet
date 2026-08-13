package net.sharenet.transport

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/**
 * Keypad Phone Gateway.
 * 
 * Listens for structured SMS messages from non-smartphones and converts them
 * into mesh intents.
 * 
 * Protocol: SN <ACTION> <TARGET_HEX>
 * Example: SN LIKE a1b2c3d4
 */
class SmsGateway(
    private val onActionReceived: (action: String, target: String) -> Unit
) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        for (sms in messages) {
            val body = sms.messageBody ?: continue
            if (body.startsWith("SN ", ignoreCase = true)) {
                val parts = body.split(" ")
                if (parts.size >= 3) {
                    val action = parts[1].uppercase()
                    val target = parts[2]
                    
                    // Basic command logic
                    when (action) {
                        "LIKE" -> Log.i(TAG, "SMS: Optimistic Like on $target")
                        "POINTS" -> Log.i(TAG, "SMS: Balance inquiry for $target")
                        "BRIDGING" -> Log.i(TAG, "SMS: Toggle bridging for $target")
                    }
                    
                    Log.i(TAG, "Keypad action received via SMS: $action on $target")
                    onActionReceived(action, target)
                }
            }
        }
    }

    companion object {
        private const val TAG = "SmsGateway"
    }
}

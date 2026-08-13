package net.sharenet.transport

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Battery + network governor per M3 acceptance:
 * - Halts transfer below 20% battery unless device is charging.
 * - When Wi-Fi-only toggle is on, blocks transfers on metered connections.
 */

data class GovernorSnapshot(
    val batteryPercent: Int,
    val isCharging: Boolean,
    val isMetered: Boolean,
    val isWifiConnected: Boolean,
)

/** Result of a governor check. */
sealed interface GovernorDecision {
    data object Allowed : GovernorDecision
    data class Blocked(val reason: String) : GovernorDecision
}

/**
 * Priority for data transfers.
 * - CRITICAL: Always allowed if battery > 5%, even if metered. (e.g. Revocations)
 * - HIGH: Allowed if battery > 15%, even if metered. (e.g. Manifests)
 * - LOW: Subject to all restrictions. (e.g. Blobs/Models)
 */
enum class TransferPriority {
    LOW, HIGH, CRITICAL
}

interface Governor {
    /** Current decision — [GovernorDecision.Allowed] or [GovernorDecision.Blocked]. */
    fun canTransfer(priority: TransferPriority = TransferPriority.LOW): GovernorDecision
    /** Whether Wi-Fi-only mode is enabled. */
    val wifiOnly: StateFlow<Boolean>
    /** Update Wi-Fi-only toggle (persisted via DataStore in real impl). */
    suspend fun setWifiOnly(enabled: Boolean)
    /** Latest battery/network snapshot for UI. */
    val snapshot: StateFlow<GovernorSnapshot>
}

/**
 * Real Android implementation using [BatteryManager] and [ConnectivityManager].
 *
 * @param context application context.
 */
class DefaultGovernor(
    private val context: Context,
) : Governor {

    private val _wifiOnly = MutableStateFlow(false)
    override val wifiOnly: StateFlow<Boolean> = _wifiOnly.asStateFlow()

    private val _snapshot = MutableStateFlow(
        GovernorSnapshot(batteryPercent = 100, isCharging = true, isMetered = false, isWifiConnected = true)
    )
    override val snapshot: StateFlow<GovernorSnapshot> = _snapshot.asStateFlow()

    override fun canTransfer(priority: TransferPriority): GovernorDecision {
        val s = readSnapshot()
        _snapshot.value = s

        val batteryThreshold = when (priority) {
            TransferPriority.CRITICAL -> 5
            TransferPriority.HIGH -> 15
            TransferPriority.LOW -> 20
        }

        if (s.batteryPercent < batteryThreshold && !s.isCharging) {
            return GovernorDecision.Blocked("Battery ${s.batteryPercent}% < $batteryThreshold% and not charging")
        }

        if (_wifiOnly.value && s.isMetered && priority == TransferPriority.LOW) {
            return GovernorDecision.Blocked("Wi-Fi-only enabled but connection is metered")
        }

        return GovernorDecision.Allowed
    }

    override suspend fun setWifiOnly(enabled: Boolean) {
        _wifiOnly.value = enabled
        // Real impl persists to DataStore:
        // context.dataStore.edit { it[WIFI_ONLY_KEY] = enabled }
    }

    private fun readSnapshot(): GovernorSnapshot {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val batteryPct = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            .let { if (it == Integer.MIN_VALUE) 100 else it }
        val isCharging = run {
            val intent = context.registerReceiver(null, android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
            val status = intent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
            status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        }
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val caps = cm.getNetworkCapabilities(network)
        val isMetered = cm.isActiveNetworkMetered
        val isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        return GovernorSnapshot(
            batteryPercent = batteryPct.coerceIn(0, 100),
            isCharging = isCharging,
            isMetered = isMetered,
            isWifiConnected = isWifi,
        )
    }
}

/**
 * Fake/test governor with controllable snapshot.
 * Used by `FakeTransport` in `:testing` and unit tests.
 */
class FakeGovernor(
    initialSnapshot: GovernorSnapshot = GovernorSnapshot(80, true, false, true),
    initialWifiOnly: Boolean = false,
) : Governor {
    private val _wifiOnly = MutableStateFlow(initialWifiOnly)
    override val wifiOnly: StateFlow<Boolean> = _wifiOnly.asStateFlow()

    private val _snapshot = MutableStateFlow(initialSnapshot)
    override val snapshot: StateFlow<GovernorSnapshot> = _snapshot.asStateFlow()

    var snapshotOverride: GovernorSnapshot
        get() = _snapshot.value
        set(value) { _snapshot.value = value }

    override fun canTransfer(priority: TransferPriority): GovernorDecision {
        val s = _snapshot.value
        val batteryThreshold = when (priority) {
            TransferPriority.CRITICAL -> 5
            TransferPriority.HIGH -> 15
            TransferPriority.LOW -> 20
        }
        if (s.batteryPercent < batteryThreshold && !s.isCharging) return GovernorDecision.Blocked("Battery low")
        if (_wifiOnly.value && s.isMetered && priority == TransferPriority.LOW) return GovernorDecision.Blocked("Metered + Wi-Fi-only")
        return GovernorDecision.Allowed
    }

    override suspend fun setWifiOnly(enabled: Boolean) { _wifiOnly.value = enabled }
}

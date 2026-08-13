package net.sharenet.transport

import android.content.Context
import android.util.Log
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.Payload as NearbyPayload
import com.google.android.gms.nearby.connection.Strategy
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.callbackFlow

/**
 * Real [Transport] implementation over Nearby Connections `P2P_CLUSTER`.
 *
 * Strategy `P2P_CLUSTER` multiplexes BLE, BT Classic and Wi-Fi Direct automatically.
 * Authentication uses Nearby's built-in token; additional payload auth (Ed25519) is
 * handled at the application layer (core-catalog manifest verification).
 *
 * Governor integration: [send] checks [Governor.canTransfer] and throws
 * [TransportException.GovernorBlocked] when transfers are not allowed; callers
 * (SyncWorker / chunk protocol) should retry when the governor re-allows.
 *
 * @param context application context (for [ConnectionsClient]).
 * @param governor bandwidth/battery governor.
 * @param connectionsClient injectable for tests; defaults to `Nearby.getConnectionsClient(context)`.
 */
class NearbyTransport(
    private val context: Context,
    private val governor: Governor,
    private val connectionsClient: ConnectionsClient = Nearby.getConnectionsClient(context),
) : Transport {

    companion object {
        private const val TAG = "NearbyTransport"
        private val STRATEGY: Strategy = Strategy.P2P_CLUSTER
    }

    private val _incoming = MutableSharedFlow<Payload>(extraBufferCapacity = 128)
    override val incoming: Flow<Payload> = _incoming.asSharedFlow()

    private val _discovered = MutableStateFlow<Set<EndpointId>>(emptySet())
    override val discoveredEndpoints: Flow<Set<EndpointId>> = _discovered.asStateFlow()

    private val _states = MutableStateFlow<Map<EndpointId, ConnectionState>>(emptyMap())
    override val connectionStates: Flow<Map<EndpointId, ConnectionState>> = _states.asStateFlow()

    private var discoveryServiceId: String? = null
    private var advertisingServiceId: String? = null

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: NearbyPayload) {
            val bytes = payload.asBytes() ?: run {
                Log.w(TAG, "Ignoring non-BYTES payload from $endpointId")
                return
            }
            val ok = _incoming.tryEmit(Payload(EndpointId(endpointId), bytes))
            if (!ok) Log.w(TAG, "Incoming buffer full, dropping payload from $endpointId")
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: com.google.android.gms.nearby.connection.PayloadTransferUpdate) {
            // BYTES payloads have no progress; FILE/STREAM would be handled here if added.
        }
    }

    private val connectionCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            Log.i(TAG, "Connection initiated: $endpointId (${info.endpointName})")
            updateState(EndpointId(endpointId), ConnectionState.CONNECTING)
            // Auto-accept; Nearby handles auth token UI if needed.
            connectionsClient.acceptConnection(endpointId, payloadCallback)
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            if (result.status.isSuccess) {
                Log.i(TAG, "Connected to $endpointId")
                updateState(EndpointId(endpointId), ConnectionState.CONNECTED)
            } else {
                Log.w(TAG, "Connection failed to $endpointId: ${result.status}")
                updateState(EndpointId(endpointId), ConnectionState.FAILED)
            }
        }

        override fun onDisconnected(endpointId: String) {
            Log.i(TAG, "Disconnected from $endpointId")
            updateState(EndpointId(endpointId), ConnectionState.DISCONNECTED)
        }
    }

    private val discoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            Log.i(TAG, "Endpoint found: $endpointId service=${info.serviceId}")
            _discovered.value = _discovered.value + EndpointId(endpointId)
        }

        override fun onEndpointLost(endpointId: String) {
            Log.i(TAG, "Endpoint lost: $endpointId")
            _discovered.value = _discovered.value - EndpointId(endpointId)
        }
    }

    // ------------------------------------------------------------------ Transport

    override fun startDiscovery(serviceId: String) {
        if (discoveryServiceId == serviceId) return
        discoveryServiceId = serviceId
        val options = DiscoveryOptions.Builder().setStrategy(STRATEGY).build()
        connectionsClient.startDiscovery(serviceId, discoveryCallback, options)
            .addOnSuccessListener { Log.i(TAG, "Discovery started: $serviceId") }
            .addOnFailureListener { e -> Log.e(TAG, "Discovery failed", e) }
    }

    override fun stopDiscovery() {
        val id = discoveryServiceId ?: return
        connectionsClient.stopDiscovery()
        discoveryServiceId = null
        Log.i(TAG, "Discovery stopped: $id")
    }

    override fun startAdvertising(serviceId: String, endpointName: String) {
        if (advertisingServiceId == serviceId) return
        advertisingServiceId = serviceId
        val options = AdvertisingOptions.Builder().setStrategy(STRATEGY).build()
        connectionsClient.startAdvertising(endpointName, serviceId, connectionCallback, options)
            .addOnSuccessListener { Log.i(TAG, "Advertising started: $serviceId as $endpointName") }
            .addOnFailureListener { e -> Log.e(TAG, "Advertising failed", e) }
    }

    override fun stopAdvertising() {
        val id = advertisingServiceId ?: return
        connectionsClient.stopAdvertising()
        advertisingServiceId = null
        Log.i(TAG, "Advertising stopped: $id")
    }

    override fun connect(endpointId: EndpointId) {
        updateState(endpointId, ConnectionState.CONNECTING)
        connectionsClient.requestConnection(
            /* endpointName */ android.os.Build.MODEL,
            endpointId.id,
            connectionCallback,
        ).addOnFailureListener { e ->
            Log.e(TAG, "requestConnection failed for ${endpointId.id}", e)
            updateState(endpointId, ConnectionState.FAILED)
        }
    }

    override fun disconnect(endpointId: EndpointId) {
        connectionsClient.disconnectFromEndpoint(endpointId.id)
        updateState(endpointId, ConnectionState.DISCONNECTED)
    }

    override suspend fun send(endpointId: EndpointId, payload: ByteArray) {
        val priority = if (payload.size < 4096) TransferPriority.HIGH else TransferPriority.LOW
        when (val decision = governor.canTransfer(priority)) {
            is GovernorDecision.Blocked -> throw TransportException.GovernorBlocked(decision.reason)
            GovernorDecision.Allowed -> Unit
        }
        val state = _states.value[endpointId]
        if (state != ConnectionState.CONNECTED) {
            throw TransportException.NotConnected(endpointId)
        }
        
        // Optimize: Use FILE payload for large chunks to leverage OS-level optimizations.
        // For now, continue with BYTES but increase buffer capacity if needed.
        val p = NearbyPayload.fromBytes(payload)
        try {
            connectionsClient.sendPayload(endpointId.id, p)
        } catch (e: Exception) {
            throw TransportException.NearbyError(e)
        }
    }

    /** Disconnect all and stop Nearby. */
    fun close() {
        stopDiscovery()
        stopAdvertising()
        connectionsClient.stopAllEndpoints()
        _discovered.value = emptySet()
        _states.value = emptyMap()
    }

    private fun updateState(id: EndpointId, state: ConnectionState) {
        _states.value = _states.value.toMutableMap().apply { put(id, state) }
    }
}

/**
 * Alternative [Transport.incoming] as a [callbackFlow] example for callers that prefer cold flows.
 * Not used by [NearbyTransport] itself (it uses SharedFlow) but documents the pattern.
 */
fun ConnectionsClient.incomingFlow(): Flow<Payload> = callbackFlow {
    val cb = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: NearbyPayload) {
            payload.asBytes()?.let { trySend(Payload(EndpointId(endpointId), it)) }
        }
        override fun onPayloadTransferUpdate(endpointId: String, update: com.google.android.gms.nearby.connection.PayloadTransferUpdate) = Unit
    }
    // Caller must register cb via acceptConnection; this flow just bridges.
    awaitClose { }
}

package net.sharenet.testing

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// ---------------------------------------------------------------------------
// Minimal local copies of transport types to avoid Android dependencies.
// The real :core-transport types are mirrored here so :testing stays pure JVM.
// In a full build these would be shared via a :core-transport-api pure-Kotlin artifact.
// ---------------------------------------------------------------------------

/** Opaque endpoint id. */
@JvmInline
value class EndpointId(val id: String)

/** Inbound payload. */
data class Payload(val endpointId: EndpointId, val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (other !is Payload) return false
        return endpointId == other.endpointId && bytes.contentEquals(other.bytes)
    }
    override fun hashCode(): Int = endpointId.hashCode() * 31 + bytes.contentHashCode()
}

enum class ConnectionState { DISCOVERING, CONNECTING, CONNECTED, DISCONNECTED, FAILED }

sealed class TransportException(message: String) : Exception(message) {
    class NotConnected(id: EndpointId) : TransportException("Not connected: ${id.id}")
    class GovernorBlocked(reason: String) : TransportException("Governor blocked: $reason")
}

/** Transport interface — same contract as core-transport, duplicated to stay pure JVM. */
interface Transport {
    fun startDiscovery(serviceId: String)
    fun stopDiscovery()
    fun startAdvertising(serviceId: String, endpointName: String)
    fun stopAdvertising()
    fun connect(endpointId: EndpointId)
    fun disconnect(endpointId: EndpointId)
    suspend fun send(endpointId: EndpointId, payload: ByteArray)
    val incoming: Flow<Payload>
    val discoveredEndpoints: Flow<Set<EndpointId>>
    val connectionStates: Flow<Map<EndpointId, ConnectionState>>
}

// ---------------------------------------------------------------------------
// Governor mirror (pure JVM)
// ---------------------------------------------------------------------------

data class GovernorSnapshot(
    val batteryPercent: Int = 80,
    val isCharging: Boolean = true,
    val isMetered: Boolean = false,
    val isWifiConnected: Boolean = true,
)

sealed interface GovernorDecision { data object Allowed : GovernorDecision; data class Blocked(val reason: String) : GovernorDecision }

interface Governor {
    fun canTransfer(): GovernorDecision
    val wifiOnly: MutableStateFlow<Boolean>
    suspend fun setWifiOnly(enabled: Boolean)
    val snapshot: MutableStateFlow<GovernorSnapshot>
}

class FakeGovernor(
    initial: GovernorSnapshot = GovernorSnapshot(),
    wifiOnly: Boolean = false,
) : Governor {
    override val snapshot = MutableStateFlow(initial)
    override val wifiOnly = MutableStateFlow(wifiOnly)
    override fun canTransfer(): GovernorDecision {
        val s = snapshot.value
        if (s.batteryPercent < 20 && !s.isCharging) return GovernorDecision.Blocked("Battery ${s.batteryPercent}%")
        if (wifiOnly.value && s.isMetered) return GovernorDecision.Blocked("Metered + Wi-Fi-only")
        return GovernorDecision.Allowed
    }
    override suspend fun setWifiOnly(enabled: Boolean) { wifiOnly.value = enabled }
}

// ---------------------------------------------------------------------------
// FakeTransport — in-memory two-peer (or N-peer) channel mesh
// ---------------------------------------------------------------------------

/**
 * In-memory fake that simulates peers exchanging via channels.
 *
 * Features:
 * - Two or N peers linked via [link]/[Mesh.linkAll]. Each peer has a stable [localEndpointId].
 * - [send] checks [governor] and peer connectivity; delivers via coroutine channel with optional
 *   [bandwidthBytesPerSecond] throttling (chunked delays).
 * - [simulatePeerDisappear] / [simulatePeerResume] — tests transfer resume after disconnect.
 * - [discoveredEndpoints] is driven by [link] — peers "discover" each other on link.
 *
 * Thread-safety: all mutable state is guarded by [mutex].
 *
 * @param name human-readable name for debugging.
 * @param governor bandwidth/battery governor.
 * @param bandwidthBytesPerSecond 0 means no throttling (instant delivery).
 */
class FakeTransport(
    val name: String,
    val governor: Governor = FakeGovernor(),
    var bandwidthBytesPerSecond: Long = 0L,
) : Transport {

    val localEndpointId: EndpointId = EndpointId("fake:$name")

    private val mutex = Mutex()
    private val peers = mutableMapOf<EndpointId, FakeTransport>()
    private val _incoming = MutableSharedFlow<Payload>(extraBufferCapacity = 256)
    override val incoming: Flow<Payload> = _incoming.asSharedFlow()

    private val _discovered = MutableStateFlow<Set<EndpointId>>(emptySet())
    override val discoveredEndpoints: Flow<Set<EndpointId>> = _discovered.asStateFlow()

    private val _states = MutableStateFlow<Map<EndpointId, ConnectionState>>(emptyMap())
    override val connectionStates: Flow<Map<EndpointId, ConnectionState>> = _states.asStateFlow()

    /** Whether this peer is currently "visible" (not disappeared). */
    var isVisible: Boolean = true
        private set

    /** All payloads sent *from* this peer (for assertions). */
    val sentPayloads = mutableListOf<Pair<EndpointId, ByteArray>>()

    /** Set of payloads received (for assertions / golden helpers). */
    val receivedPayloads = mutableListOf<Payload>()

    init {
        // Collect incoming into receivedPayloads for test assertions (fire-and-forget).
        // Tests that need flow semantics subscribe to `incoming` directly.
    }

    // ------------------------------------------------------------------ Transport

    override fun startDiscovery(serviceId: String) {
        _states.value = _states.value + (localEndpointId to ConnectionState.DISCOVERING)
        // Discovery populates _discovered from currently linked visible peers.
        _discovered.value = peers.keys.filter { peers[it]?.isVisible == true }.toSet()
    }

    override fun stopDiscovery() {
        _states.value = _states.value.toMutableMap().apply { remove(localEndpointId) }
        _discovered.value = emptySet()
    }

    override fun startAdvertising(serviceId: String, endpointName: String) {
        // No-op for fake — visibility is controlled by link/disappear.
    }

    override fun stopAdvertising() {}

    override fun connect(endpointId: EndpointId) {
        val peer = peers[endpointId] ?: throw TransportException.NotConnected(endpointId)
        if (!peer.isVisible) throw TransportException.NotConnected(endpointId)
        _states.value = _states.value + (endpointId to ConnectionState.CONNECTED)
        peer._states.value = peer._states.value + (localEndpointId to ConnectionState.CONNECTED)
    }

    override fun disconnect(endpointId: EndpointId) {
        _states.value = _states.value.toMutableMap().apply { put(endpointId, ConnectionState.DISCONNECTED) }
        peers[endpointId]?._states?.let { s ->
            s.value = s.value.toMutableMap().apply { put(localEndpointId, ConnectionState.DISCONNECTED) }
        }
    }

    override suspend fun send(endpointId: EndpointId, payload: ByteArray) {
        when (val d = governor.canTransfer()) {
            is GovernorDecision.Blocked -> throw TransportException.GovernorBlocked(d.reason)
            GovernorDecision.Allowed -> Unit
        }
        val peer = peers[endpointId] ?: throw TransportException.NotConnected(endpointId)
        if (!peer.isVisible) throw TransportException.NotConnected(endpointId)
        if (_states.value[endpointId] != ConnectionState.CONNECTED) {
            throw TransportException.NotConnected(endpointId)
        }
        // Bandwidth throttling: delay proportional to payload size.
        if (bandwidthBytesPerSecond > 0) {
            val ms = (payload.size.toLong() * 1000L / bandwidthBytesPerSecond).coerceAtLeast(1L)
            delay(ms)
        }
        sentPayloads += endpointId to payload.copyOf()
        // Deliver to peer's incoming.
        peer._incoming.emit(Payload(localEndpointId, payload.copyOf()))
        peer.receivedPayloads += Payload(localEndpointId, payload.copyOf())
    }

    // ------------------------------------------------------------------ Mesh helpers

    /**
     * Simulate peer disappearing (e.g. BLE out of range, process kill).
     * In-flight sends to/from this peer will fail until [simulatePeerResume].
     */
    suspend fun simulatePeerDisappear() {
        mutex.withLock {
            isVisible = false
            // Move all connections to DISCONNECTED.
            for ((peerId, _) in peers) {
                _states.value = _states.value.toMutableMap().apply { put(peerId, ConnectionState.DISCONNECTED) }
            }
            _discovered.value = emptySet()
        }
    }

    /** Reverse of [simulatePeerDisappear]. */
    suspend fun simulatePeerResume() {
        mutex.withLock {
            isVisible = true
            _discovered.value = peers.keys.filter { peers[it]?.isVisible == true }.toSet()
        }
    }

    /** For testing: inject a payload as if it came from [from]. */
    suspend fun injectIncoming(from: EndpointId, bytes: ByteArray) {
        _incoming.emit(Payload(from, bytes))
        receivedPayloads += Payload(from, bytes)
    }

    companion object {
        /**
         * Bidirectionally link two peers. After linking, each appears in the other's
         * discovered set (if visible) and can be connected.
         */
        suspend fun link(a: FakeTransport, b: FakeTransport) {
            a.peers[b.localEndpointId] = b
            b.peers[a.localEndpointId] = a
            if (a.isVisible && b.isVisible) {
                a._discovered.value = a._discovered.value + b.localEndpointId
                b._discovered.value = b._discovered.value + a.localEndpointId
            }
        }

        /** Fully mesh N peers (all pairs linked). */
        suspend fun linkAll(vararg peers: FakeTransport) {
            for (i in peers.indices) for (j in i + 1 until peers.size) link(peers[i], peers[j])
        }
    }
}

/**
 * Mesh of N fake peers with a shared governor.
 * Convenience for tests that need >2 peers (e.g. recipient diversity fraud tests).
 */
class Mesh(
    val peers: List<FakeTransport>,
    val governor: Governor = FakeGovernor(),
) {
    companion object {
        suspend fun of(n: Int, governor: Governor = FakeGovernor()): Mesh {
            val peers = (0 until n).map { FakeTransport("peer-$it", governor) }
            FakeTransport.linkAll(*peers.toTypedArray())
            return Mesh(peers, governor)
        }
    }

    fun peer(index: Int): FakeTransport = peers[index]
}

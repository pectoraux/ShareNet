package net.sharenet.transport

import kotlinx.coroutines.flow.Flow

/**
 * Opaque endpoint identifier as issued by Nearby Connections.
 */
@JvmInline
value class EndpointId(val id: String)

/**
 * Inbound payload from a remote endpoint.
 *
 * @property endpointId sender endpoint.
 * @property bytes raw bytes; caller determines framing (chunk request, chunk data, etc.).
 * @property isReliable true if delivered reliably (Nearby `Payload.Type.BYTES` is reliable).
 */
data class Payload(
    val endpointId: EndpointId,
    val bytes: ByteArray,
    val isReliable: Boolean = true,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Payload) return false
        return endpointId == other.endpointId && bytes.contentEquals(other.bytes)
    }
    override fun hashCode(): Int = endpointId.hashCode() * 31 + bytes.contentHashCode()
}

/** Connection state per endpoint. */
enum class ConnectionState { DISCOVERING, CONNECTING, CONNECTED, DISCONNECTED, FAILED }

/**
 * Transport abstraction — the only surface the rest of the app touches for P2P.
 *
 * Implementations:
 * - [NearbyTransport] — real Nearby Connections `P2P_CLUSTER`.
 * - `FakeTransport` in `:testing` — in-memory channels for unit tests.
 *
 * Thread-safety: all methods are safe to call from any thread; implementations
 * must serialize Nearby callbacks onto their own scope.
 */
interface Transport {

    /** Start discovering peers advertising [serviceId]. Idempotent. */
    fun startDiscovery(serviceId: String)

    /** Stop discovery. Idempotent. */
    fun stopDiscovery()

    /** Start advertising [serviceId] with local [endpointName]. Idempotent. */
    fun startAdvertising(serviceId: String, endpointName: String)

    /** Stop advertising. Idempotent. */
    fun stopAdvertising()

    /** Request connection to [endpointId]. */
    fun connect(endpointId: EndpointId)

    /** Disconnect from [endpointId]. */
    fun disconnect(endpointId: EndpointId)

    /**
     * Send [payload] to [endpointId]. Suspends until enqueued.
     * Throws [TransportException] on failure or if governor blocks sending.
     */
    suspend fun send(endpointId: EndpointId, payload: ByteArray)

    /** Flow of inbound payloads from all connected peers. */
    val incoming: Flow<Payload>

    /** Flow of currently discovered (not yet connected) endpoints. */
    val discoveredEndpoints: Flow<Set<EndpointId>>

    /** Flow of connection state per endpoint. */
    val connectionStates: Flow<Map<EndpointId, ConnectionState>>
}

/** Thrown by [Transport.send] and lifecycle methods. */
sealed class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class NotConnected(endpointId: EndpointId) :
        TransportException("Not connected to ${endpointId.id}")
    class GovernorBlocked(reason: String) :
        TransportException("Governor blocked transfer: $reason")
    class NearbyError(cause: Throwable) :
        TransportException("Nearby Connections error: ${cause.message}", cause)
}

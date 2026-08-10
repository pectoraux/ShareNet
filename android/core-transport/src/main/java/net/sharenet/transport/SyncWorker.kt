package net.sharenet.transport

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.flow.first
import java.util.concurrent.TimeUnit

/**
 * Chunk request/response framing used between peers.
 * Kept here (transport layer) so both sides can codec without depending on higher layers.
 *
 * All payloads are length-prefixed CBOR maps with a `type` discriminator.
 */
object ChunkProtocol {
    const val TYPE_REQUEST = "chunk_req"
    const val TYPE_RESPONSE = "chunk_resp"
    const val TYPE_HAVE = "have" // advertise available blob ids

    data class Request(val blobIdHex: String, val chunkIndex: Int)
    data class Response(val blobIdHex: String, val chunkIndex: Int, val data: ByteArray)
    data class Have(val blobIdsHex: List<String>)
}

/**
 * Background sync worker — opportunistic content exchange via [Transport].
 *
 * Constraints:
 * - Requires battery not low (WorkManager handles this; Governor does the precise 20% check).
 * - Retries with exponential backoff.
 *
 * Scheduling: call [ShareNetSyncWorker.enqueue] from Application.onCreate and after settings changes.
 * The worker itself is intentionally thin: it resolves dependencies via [SyncDependencies] so that
 * unit tests can inject fakes without Android.
 */
class ShareNetSyncWorker(
    appContext: Context,
    params: WorkerParameters,
    private val deps: SyncDependencies = RealSyncDependencies(appContext),
) : CoroutineWorker(appContext, params) {

    companion object {
        const val WORK_NAME = "sharenet-sync"
        private const val TAG = "ShareNetSyncWorker"

        /** Enqueue periodic sync (15 min minimum interval per WorkManager). */
        fun enqueue(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val request = PeriodicWorkRequestBuilder<ShareNetSyncWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .addTag(WORK_NAME)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
            Log.i(TAG, "Enqueued periodic sync")
        }

        /** Cancel periodic sync (e.g. on logout). */
        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }

    override suspend fun doWork(): Result {
        Log.i(TAG, "Sync worker running")
        // Governor check before any transfer. Use HIGH priority for sync discovery.
        when (val d = deps.governor.canTransfer(TransferPriority.HIGH)) {
            is GovernorDecision.Blocked -> {
                Log.i(TAG, "Governor blocked sync: ${d.reason} — retrying later")
                return Result.retry()
            }
            GovernorDecision.Allowed -> Unit
        }

        return try {
            // 1. Discover + connect (NearbyTransport handles lifecycle; worker just triggers).
            deps.transport.startDiscovery(deps.serviceId)
            
            // 2. Exchange "HAVE" vectors and fetch needed items.
            val peers = deps.transport.discoveredEndpoints.first()
            for (peer in peers) {
                val vector = deps.getHaveVector()
                val payload = "HAVE:${vector.joinToString(",")}".encodeToByteArray()
                deps.transport.send(peer, payload)
            }

            val snapshot = deps.governor.snapshot.first()
            Log.i(TAG, "Sync tick snapshot=$snapshot")
            deps.onSyncTick()
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Sync failed", e)
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        } finally {
            // Do not leave discovery running indefinitely; NearbyTransport is long-lived elsewhere.
            // Worker only ensures at least one discovery window happened.
        }
    }
}

/** Dependencies for [ShareNetSyncWorker] — allows injection in tests. */
interface SyncDependencies {
    val transport: Transport
    val governor: Governor
    val serviceId: String
    suspend fun onSyncTick()
    suspend fun getHaveVector(): List<String>
}

/** Real dependencies resolved from app singletons. Replace with Hilt entry point if Hilt is used. */
class RealSyncDependencies(private val context: Context) : SyncDependencies {
    override val governor: Governor by lazy { DefaultGovernor(context) }
    override val transport: Transport by lazy { NearbyTransport(context, governor) }
    override val serviceId: String = "net.sharenet.catalog"
    override suspend fun onSyncTick() {
        // Real: CatalogStore.wantList() → request chunks from first available peer.
    }
    override suspend fun getHaveVector(): List<String> {
        // Real: List all Manifest IDs from CatalogStore
        return emptyList()
    }
}

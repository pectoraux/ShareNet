package net.sharenet.feed.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.flow.first
import net.sharenet.feed.domain.OfflineQueue
import net.sharenet.transport.Transport
import android.util.Log

class FeedSyncWorker(
    appContext: Context,
    params: WorkerParameters,
    private val offlineQueue: OfflineQueue,
    private val transport: Transport,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        Log.i("FeedSyncWorker", "Checking for peers to drain offline queue")
        
        val peers = transport.discoveredEndpoints.first()
        if (peers.isEmpty()) {
            return Result.retry()
        }

        // Connect to first peer and drain
        val peer = peers.first()
        transport.connect(peer)
        
        // Wait for connection (simplified)
        // Real: Observe transport.connectionStates
        
        offlineQueue.drain(peer)
        
        return Result.success()
    }
}

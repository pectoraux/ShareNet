package net.sharenet.feed.domain

import net.sharenet.feed.data.ActionDao
import net.sharenet.transport.Transport
import net.sharenet.transport.EndpointId
import net.sharenet.crypto.NodeId
import android.util.Log

class OfflineQueue(
    private val actionDao: ActionDao,
    private val transport: Transport,
) {
    suspend fun drain(peerId: EndpointId) {
        val pending = actionDao.getPending()
        if (pending.isEmpty()) return

        Log.i("OfflineQueue", "Draining ${pending.size} actions to peer $peerId")
        
        for (action in pending) {
            try {
                actionDao.updateStatus(action.id, "SYNCING")
                
                // Real: In a mesh, we'd package this action as a Manifest or Receipt
                // For now, simulate transport send
                transport.send(peerId, "FEED_ACTION:${action.type}:${action.targetBlobIdHex}".encodeToByteArray())
                
                actionDao.updateStatus(action.id, "SYNCED")
                // In a real system, we might delete synced actions or keep them for history
            } catch (e: Exception) {
                Log.e("OfflineQueue", "Failed to sync action ${action.id}", e)
                actionDao.updateStatus(action.id, "PENDING")
            }
        }
    }
}

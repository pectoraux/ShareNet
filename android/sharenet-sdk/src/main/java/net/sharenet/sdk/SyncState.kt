package net.sharenet.sdk

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/**
 * Sync state observed by apps via [ShareNetSdk.observeSyncState].
 */
enum class SyncStatus { IDLE, DISCOVERING, SYNCING, PAUSED_GOVERNOR, ERROR }

data class SyncState(
    val status: SyncStatus,
    val discoveredPeers: Int = 0,
    val queuedReceipts: Int = 0,
    val pendingBytes: Long = 0L,
    val lastSyncAt: Long? = null,
    val error: String? = null,
)

/** Local availability of a blob. */
data class Availability(
    val blobIdHex: String,
    val isComplete: Boolean,
    val availableBytes: Long,
    val totalBytes: Long,
)

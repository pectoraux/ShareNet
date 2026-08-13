package net.sharenet.assistant.llm

import android.app.ActivityManager
import android.content.Context

/**
 * Tiered model selection based on available RAM.
 *
 * Policy (matches spec):
 *  - 1B model if device has < 4 GB total RAM  (low-end devices)
 *  - 3–4B model otherwise
 *
 * Model weights are delivered via ShareNet catalog category [MODEL_WEIGHTS].
 * This selector only decides *which* model to request; fetching is done by
 * the SDK catalog/blob layer.
 */
enum class ModelTier(val displayName: String, val catalogQuery: String) {
    SMALL_1B("Gemma 1B", "MODEL_WEIGHTS:gemma-1b"),
    LARGE_4B("Gemma 4B", "MODEL_WEIGHTS:gemma-4b"),
}

object TieredModelSelector {

    private const val THRESHOLD_BYTES = 4L * 1024 * 1024 * 1024 // 4 GB

    fun select(context: Context): ModelTier {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        // totalMem may be 0 on some emulators — fall back to LARGE_4B when unknown
        if (info.totalMem == 0L) return ModelTier.LARGE_4B
        return if (info.totalMem < THRESHOLD_BYTES) ModelTier.SMALL_1B else ModelTier.LARGE_4B
    }

    /** Testable overload. */
    fun selectForTest(totalMemBytes: Long): ModelTier =
        if (totalMemBytes < THRESHOLD_BYTES) ModelTier.SMALL_1B else ModelTier.LARGE_4B

    /** Resolve local file path for the selected tier (weights fetched via ShareNet). */
    fun modelPathForTier(tier: ModelTier, filesDir: java.io.File): java.io.File =
        java.io.File(filesDir, "models/${tier.name.lowercase()}/model.bin")
}

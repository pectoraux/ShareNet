package net.sharenet.assistant.llm

import android.app.ActivityManager
import android.content.Context
import android.os.Build

/**
 * Utility to optimize model selection based on device hardware.
 *
 * M6 Decision: pick Gemma 1B for < 4GB RAM, Gemma 4B above.
 * Future: Check for Hexagon NPU / GPU capabilities via MediaPipe.
 */
object ModelOptimizer {

    enum class ModelTier {
        TINY, // < 1B params, high compression
        SMALL, // 1B-2B params (Gemma 2B / 3 1B)
        MEDIUM // 4B+ params
    }

    /** Determine the best model tier for this device. */
    fun getRecommendedTier(context: Context): ModelTier {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)

        val totalRamGb = mi.totalMem / (1024 * 1024 * 1024)

        return when {
            totalRamGb < 2 -> ModelTier.TINY
            totalRamGb < 6 -> ModelTier.SMALL
            else -> ModelTier.MEDIUM
        }
    }

    /** Whether the device likely has a high-performance NPU (qualitative heuristic). */
    fun hasPerformanceNpu(): Boolean {
        // Simple heuristic: higher-end SoCs from last ~3 years
        return Build.VERSION.SDK_INT >= 31 && (
            Build.HARDWARE.contains("qcom", ignoreCase = true) ||
            Build.HARDWARE.contains("tensor", ignoreCase = true)
        )
    }
}

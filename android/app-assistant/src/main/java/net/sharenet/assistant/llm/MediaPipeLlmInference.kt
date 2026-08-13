package net.sharenet.assistant.llm

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/**
 * MediaPipe LLM Inference wrapper.
 *
 * Real implementation delegates to `com.google.mediapipe.tasks.genai.llminference.LlmInference`
 * (MediaPipe Tasks GenAI 0.10.14). This **stub** compiles without the native dependency
 * and logs a clear error if invoked before the real binding is wired.
 *
 * To enable on-device inference:
 *  1. Add `implementation("com.google.mediapipe:tasks-genai:0.10.14")`
 *  2. Replace the body of [generate] with:
 * ```
 * val options = LlmInferenceOptions.builder()
 *     .setModelPath(modelPath)
 *     .setMaxTokens(1024)
 *     .build()
 * val mp = com.google.mediapipe.tasks.genai.llminference.LlmInference.createFromOptions(context, options)
 * // then mp.generateResponseAsync(prompt) with streaming callback
 * ```
 *  3. Provide `modelPath` from ShareNet catalog `MODEL_WEIGHTS` (see [TieredModelSelector]).
 */
class MediaPipeLlmInference(
    private val context: Context,
    private val modelPath: String,
) : LlmInference {

    private var isClosed = false

    override fun generate(prompt: String): Flow<String> = flow {
        if (isClosed) {
            Log.e(TAG, "generate called after close()")
            return@flow
        }
        Log.w(TAG, "MediaPipeLlmInference stub — no native binding. prompt='$prompt', modelPath='$modelPath'")
        // Graceful fallback: emit a canned response so the UI pipeline remains testable on CI
        // without the .tflite/.bin weights present.
        val stub = "[on-device model not bundled — stub response for: $prompt]"
        // Stream word-by-word to exercise streaming UI.
        stub.split(" ").forEach { word ->
            kotlinx.coroutines.delay(40)
            emit("$word ")
        }
    }.flowOn(Dispatchers.Default)

    override fun close() {
        if (isClosed) return
        isClosed = true
        Log.i(TAG, "MediaPipeLlmInference.close() (stub) - Releasing native resources")
        // Real: mp.close()
    }

    companion object {
        private const val TAG = "MediaPipeLlmInference"
    }
}

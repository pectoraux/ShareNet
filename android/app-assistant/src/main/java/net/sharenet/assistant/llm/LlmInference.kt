package net.sharenet.assistant.llm

import kotlinx.coroutines.flow.Flow

/**
 * LLM inference abstraction. Used everywhere except the single real MediaPipe binding.
 *
 * Contract: [generate] streams tokens as they become available. Completing the flow
 * means generation finished; throwing means the model failed.
 */
interface LlmInference {
    fun generate(prompt: String): Flow<String>
    fun close()
}

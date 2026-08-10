package net.sharenet.assistant.llm

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Fake for tests and previews. Deterministic and fast.
 */
class FakeLlmInference(
    private val response: String = "Hello from FakeLlmInference — this is a deterministic test response.",
    private val chunkDelayMs: Long = 10,
) : LlmInference {

    val prompts = mutableListOf<String>()
    var closed = false
        private set

    override fun generate(prompt: String): Flow<String> = flow {
        prompts += prompt
        // Stream by words
        val words = response.split(" ")
        for (w in words) {
            delay(chunkDelayMs)
            emit("$w ")
        }
    }

    override fun close() {
        closed = true
    }
}

/**
 * Fake that throws — for error-path tests.
 */
class ThrowingFakeLlmInference(private val error: Throwable = IllegalStateException("model failed")) : LlmInference {
    override fun generate(prompt: String): Flow<String> = flow { throw error }
    override fun close() {}
}

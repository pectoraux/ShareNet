package net.sharenet.assistant.pipeline

import kotlinx.coroutines.flow.Flow

// ---------------------------------------------------------------------------
// Step interfaces — each stage of the language pipeline is swappable.
// v1: EN/FR ASR + NLLB translation; fakes for every stage for tests.
// Pipeline: speech → ASR → translate → LLM → translate → TTS
// ---------------------------------------------------------------------------

/** Automatic Speech Recognition: audio bytes → text + streaming partial transcripts. */
interface AsrStep {
    /** One-shot transcription. */
    suspend fun transcribe(audio: ByteArray, languageHint: String = "en"): String

    /** Streaming transcription — emits partial results. */
    fun transcribeStreaming(audioChunks: Flow<ByteArray>, languageHint: String = "en"): Flow<String>
}

/** Translation step (NLLB-distilled via ONNX in production). */
interface TranslateStep {
    suspend fun translate(text: String, sourceLang: String, targetLang: String): String
}

/** LLM step — delegates to [net.sharenet.assistant.llm.LlmInference]. */
interface LlmStep {
    fun generate(prompt: String): Flow<String>
}

/** Text-to-Speech: text → audio bytes (placeholder in v1). */
interface TtsStep {
    suspend fun synthesize(text: String, language: String = "en"): ByteArray
    val isPlaceholder: Boolean get() = true
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class FakeAsrStep(private val transcript: String = "hello world") : AsrStep {
    var lastLanguageHint: String? = null
    override suspend fun transcribe(audio: ByteArray, languageHint: String): String {
        lastLanguageHint = languageHint
        return transcript
    }
    override fun transcribeStreaming(audioChunks: Flow<ByteArray>, languageHint: String): Flow<String> {
        return kotlinx.coroutines.flow.flow {
            emit(transcript.take(transcript.length / 2))
            kotlinx.coroutines.delay(80)
            emit(transcript)
        }
    }
}

class FakeTranslateStep : TranslateStep {
    data class Call(val text: String, val from: String, val to: String)
    val calls = mutableListOf<Call>()
    override suspend fun translate(text: String, sourceLang: String, targetLang: String): String {
        calls += Call(text, sourceLang, targetLang)
        // Identity for EN↔EN, tag otherwise so tests can assert translation happened
        return if (sourceLang == targetLang) text else "[$targetLang]$text"
    }
}

class FakeTtsStep : TtsStep {
    var lastText: String? = null
    override suspend fun synthesize(text: String, language: String): ByteArray {
        lastText = text
        // Return empty placeholder — real TTS would write a wav file
        return ByteArray(0)
    }
}

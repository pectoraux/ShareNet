package net.sharenet.assistant.pipeline

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow

/**
 * Orchestrates the full language pipeline:
 *
 *   speech bytes → [AsrStep] → [TranslateStep] (to EN) → [LlmStep] → [TranslateStep] (back) → [TtsStep]
 *
 * v1 supports EN/FR ASR + NLLB translation. Local languages use the same pipeline
 * with different model weights (delivered via ShareNet MODEL_WEIGHTS).
 *
 * All steps are interfaces — fakes exist for each stage so the pipeline is
 * testable without models, mic, or TTS engine.
 */
class LanguagePipeline(
    private val asr: AsrStep,
    private val translateToEnglish: TranslateStep,
    private val llm: LlmStep,
    private val translateFromEnglish: TranslateStep,
    private val tts: TtsStep,
) {

    /**
     * Text-only path (no audio). Used when user types.
     * Still runs translate→LLM→translate→TTS so that non-EN users get localized responses.
     */
    fun chat(
        text: String,
        uiLanguage: String = "en",
        llmLanguage: String = "en",
    ): Flow<PipelineEvent> = flow {
        // 1. Translate user input to LLM language if needed
        val promptForLlm = if (uiLanguage != llmLanguage) {
            emit(PipelineEvent.Translating)
            translateToEnglish.translate(text, uiLanguage, llmLanguage)
        } else text

        // 2. LLM streaming
        emit(PipelineEvent.LlmStarted)
        val buffer = StringBuilder()
        llm.generate(promptForLlm).collect { token ->
            buffer.append(token)
            emit(PipelineEvent.LlmToken(token))
        }
        val llmText = buffer.toString()

        // 3. Translate back
        val localized = if (llmLanguage != uiLanguage) {
            emit(PipelineEvent.Translating)
            translateFromEnglish.translate(llmText, llmLanguage, uiLanguage)
        } else llmText

        emit(PipelineEvent.LlmComplete(localized))

        // 4. TTS (placeholder — emits event with empty audio in v1)
        emit(PipelineEvent.Synthesizing)
        val audio = tts.synthesize(localized, uiLanguage)
        emit(PipelineEvent.AudioReady(audio, localized))
    }

    /**
     * Voice path: audio bytes → ASR → … → TTS
     * Emits [PipelineEvent.TranscriptionPartial] during streaming ASR.
     */
    fun voice(
        audioChunks: Flow<ByteArray>,
        uiLanguage: String = "en",
        llmLanguage: String = "en",
    ): Flow<PipelineEvent> = flow {
        emit(PipelineEvent.Listening)
        // Collect streaming ASR partials
        var finalTranscript = ""
        asr.transcribeStreaming(audioChunks, uiLanguage).collect { partial ->
            finalTranscript = partial
            emit(PipelineEvent.TranscriptionPartial(partial))
        }
        emit(PipelineEvent.TranscriptionFinal(finalTranscript))
        // Continue through chat pipeline
        emitAll(chat(finalTranscript, uiLanguage, llmLanguage))
    }

    /** One-shot voice helper for tests (non-streaming ASR). */
    suspend fun voiceOneShot(audio: ByteArray, uiLanguage: String = "en"): String {
        val transcript = asr.transcribe(audio, uiLanguage)
        return translateToEnglish.translate(transcript, uiLanguage, "en")
    }
}

sealed interface PipelineEvent {
    data object Listening : PipelineEvent
    data class TranscriptionPartial(val text: String) : PipelineEvent
    data class TranscriptionFinal(val text: String) : PipelineEvent
    data object Translating : PipelineEvent
    data object LlmStarted : PipelineEvent
    data class LlmToken(val token: String) : PipelineEvent
    data class LlmComplete(val text: String) : PipelineEvent
    data object Synthesizing : PipelineEvent
    data class AudioReady(val audio: ByteArray, val text: String) : PipelineEvent
}

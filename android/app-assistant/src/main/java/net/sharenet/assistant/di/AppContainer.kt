package net.sharenet.assistant.di

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.room.Room
import net.sharenet.assistant.contribution.ContributionQueue
import net.sharenet.assistant.data.AssistantDatabase
import net.sharenet.assistant.data.ConversationRepository
import net.sharenet.assistant.llm.FakeLlmInference
import net.sharenet.assistant.llm.LlmInference
import net.sharenet.assistant.pipeline.FakeAsrStep
import net.sharenet.assistant.pipeline.FakeTranslateStep
import net.sharenet.assistant.pipeline.FakeTtsStep
import net.sharenet.assistant.pipeline.LanguagePipeline

private val Context.dataStore by preferencesDataStore(name = "assistant_prefs")

/**
 * Manual DI container (Hilt-less, matching app-wallet convention).
 * Swap fakes for real implementations when models are bundled.
 */
class AssistantAppContainer(context: Context) {

    private val appContext = context.applicationContext

    val dataStore get() = appContext.dataStore

    val database: AssistantDatabase by lazy {
        Room.databaseBuilder(appContext, AssistantDatabase::class.java, "assistant.db")
            .fallbackToDestructiveMigration()
            .build()
    }

    val conversationRepository: ConversationRepository by lazy {
        ConversationRepository(database.conversationDao(), database.messageDao())
    }

    // LLM — replace with MediaPipeLlmInference when weights are available
    val llmInference: LlmInference by lazy { FakeLlmInference() }

    // Pipeline stages
    val asrStep get() = FakeAsrStep()
    val translateStep get() = FakeTranslateStep()
    val ttsStep get() = FakeTtsStep()

    val languagePipeline: LanguagePipeline by lazy {
        LanguagePipeline(
            asr = asrStep,
            translateToEnglish = translateStep,
            llm = object : net.sharenet.assistant.pipeline.LlmStep {
                override fun generate(prompt: String) = llmInference.generate(prompt)
            },
            translateFromEnglish = translateStep,
            tts = ttsStep,
        )
    }

    val contributionQueue: ContributionQueue by lazy { ContributionQueue() }

    // Preference keys
    object Prefs {
        val CONSENT = booleanPreferencesKey("consent_granted")
        val UI_LANGUAGE = stringPreferencesKey("ui_language") // "en" | "fr"
        val MODEL_TIER = stringPreferencesKey("model_tier")
    }
}

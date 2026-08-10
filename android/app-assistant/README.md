# app-assistant — ShareNet Assistant (Offline AI)

**Package** `net.sharenet.assistant` · **App name** *ShareNet Assistant*  
**minSdk 26 · compileSdk 34 · targetSdk 34** · Compose BOM · Room · DataStore

## What it is

Offline AI assistant. Runs a quantized LLM on-device (MediaPipe LLM Inference), supports voice interaction in EN/FR (v1) and local languages via additional model weights delivered over ShareNet.

## Architecture

```
UI (Compose) ──▶ ViewModel ──▶ LanguagePipeline ──▶ steps
                                    │
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
                  AsrStep    TranslateStep    LlmInference    TtsStep
                  (Whisper)    (NLLB/ONNX)   (MediaPipe)    (TTS/Piper)
                     │              │              │             │
                     └──────────────┴──────────────┘
                                    │
                              ContributionQueue ──▶ ShareNet transport (when online)
```

### LLM — `llm/`

| File | Role |
|---|---|
| `LlmInference.kt` | `interface LlmInference { generate(prompt): Flow<String>; close() }` |
| `MediaPipeLlmInference.kt` | Real MediaPipe wrapper — **stub** that compiles without native `.so`; logs and streams a placeholder so CI/UI stay green. Swap in `com.google.mediapipe:tasks-genai` when weights land. |
| `FakeLlmInference.kt` | Deterministic fake for tests/previews + `ThrowingFakeLlmInference` for error paths |
| `TieredModelSelector.kt` | `select(context): ModelTier` — `1B` if `<4GB RAM`, `3–4B` otherwise. `modelPathForTier()` points under `filesDir/models/`. Weights fetched via ShareNet catalog `MODEL_WEIGHTS`. |

### Language pipeline — `pipeline/`

Interfaces + orchestrator + fakes for *every* stage:

- `AsrStep` — `transcribe()` + `transcribeStreaming(): Flow<String>` (streaming transcription). Fake emits half then full transcript.
- `TranslateStep` — `translate(text, sourceLang, targetLang)`. Fake is identity for same-lang, tagged otherwise. Real is NLLB-distilled via ONNX Runtime.
- `LlmStep` — delegates to `LlmInference`.
- `TtsStep` — `synthesize(): ByteArray`, `isPlaceholder = true` in v1 (Android `TextToSpeech` for EN/FR, Piper/VITS via ONNX for local langs later).

`LanguagePipeline` orchestrates `speech → ASR → translate → LLM → translate → TTS`, emitting `PipelineEvent` (Listening, TranscriptionPartial/Final, Translating, LlmToken, LlmComplete, AudioReady). Voice path uses streaming ASR; text path skips ASR.

### Conversation store — `data/`

Room `AssistantDatabase` with `Conversation` + `Message` entities, `ConversationDao`/`MessageDao`, `ConversationRepository`. Observed as `Flow`.

### Contribution — `contribution/`

- `Contribution` (signed) mirrors backend shape; signed with Ed25519 in prod.
- `ContributionQueue` — in-memory `StateFlow` queue + consent `StateFlow`; `enqueue()` requires consent, `drainAndUpload()` called by transport when online.
- `ContributorDashboard` stats (pending/delivered).

### UI — `ui/`

| Screen | Features |
|---|---|
| `ChatScreen` | Message list, streaming LLM tokens, streaming transcription overlay, type + **hold-to-talk** (long-press scaffold, `pointerInput` in prod), audio response placeholder (`🔊 Audio…`). `ChatViewModel` wires pipeline + repo. |
| `SettingsScreen` | Model tier radio (auto/1B/4B), language EN/FR, note that weights come via `MODEL_WEIGHTS`. |
| `ContributionScreen` | Consent `Switch`, correction `TextField` + lang pickers, signed `Contribution` enqueue, pending queue, contributor dashboard list. |

`navigation/AssistantNavGraph.kt` (`Chat ↔ Settings ↔ Contribution`) via `navigation-compose`.

### DI

`di/AppContainer.kt` — **Hilt-less manual DI**. Lazily builds `Room`, `ConversationRepository`, `FakeLlmInference` (swap to `MediaPipeLlmInference`), pipeline fakes, `ContributionQueue`, and `DataStore` prefs (`consent`, `ui_language`, `model_tier`).

## Model delivery

No weights are bundled. On first launch the app queries `sharenet-sdk` catalog for `MODEL_WEIGHTS`; `TieredModelSelector` picks the tier, then `sdk.blobs.fetch()` pulls the blob over Nearby mesh. Until weights arrive the stub response keeps the UI testable.

## Build

```bash
./gradlew :app-assistant:assembleDebug
```

Add the real MediaPipe dep when ready:

```kotlin
implementation("com.google.mediapipe:tasks-genai:0.10.14")
```

And ONNX for translation/ASR:

```kotlin
implementation("com.microsoft.onnxruntime:onnxruntime:1.19.0")
```

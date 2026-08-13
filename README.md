# ShareNet — Offline-First Mesh Platform

> **Status:** M0-M5 implemented, M6-M13 scaffolded with interfaces + fakes. Open in Android Studio to build.

ShareNet is an offline-first content distribution and value-transfer platform for Android (minSdk 26).
Content propagates device-to-device over Nearby Connections (BLE + BT + Wi-Fi Direct), signed with Ed25519, content-addressed with Merkle trees. No internet required on the receiving device.

Companion specs: `sharenetimplementationroadmap.md` (execution spec), offline telecom roadmap.

## Monorepo layout

```
ShareNet/
├── android/
│   ├── core-crypto/        Identity, signing, Keystore, CBOR
│   ├── core-content/       Chunking, Merkle, blob store
│   ├── core-catalog/       Manifests, revocation, publisher trust
│   ├── core-transport/     Nearby Connections abstraction + fakes
│   ├── core-attest/        Delivery receipts, points ledger
│   ├── sharenet-sdk/       Public SDK for apps
│   ├── app-demo/           Reference consumer (proves SDK)
│   ├── app-assistant/      Offline AI assistant (MediaPipe + language pipeline)
│   ├── app-wallet/         NFC value transfer terminal
│   └── testing/            FakeTransport, FakeClock, fixtures
├── card-applet/            JavaCard applet + jCardSim harness
├── backend/                FastAPI + Postgres (catalog, attest, corpus, settlement)
└── docs/
```

## Locked stack

Kotlin + Jetpack Compose, Room + SQLCipher, Google Tink (Ed25519/AES-GCM), Nearby `P2P_CLUSTER`, MediaPipe LLM Inference, ONNX Runtime, FastAPI + PostgreSQL, JavaCard 3.x on NXP JCOP, jCardSim.

## Quick start

### Android (all apps)

```bash
export JAVA_HOME=/home/tetevi/Downloads/android-studio/jbr
export ANDROID_HOME=~/Android/Sdk

# Open in Android Studio
# File → Open → ShareNet/android

# Or command line (first sync downloads dependencies)
cd android
./gradlew assembleDebug
./gradlew :app-demo:installDebug
./gradlew :app-assistant:installDebug
./gradlew :app-wallet:installDebug

# Run unit tests
./gradlew test
./gradlew connectedAndroidTest   # needs device/emulator
./gradlew lint detekt
```

### Backend

```bash
cd backend
uv sync          # or pip install -e .
uv run uvicorn backend.main:app --reload
pytest
```

### Card applet (no hardware)

```bash
cd card-applet
./gradlew jCardSimTest
```

## M0 Golden vector

Kotlin and Python produce byte-identical CBOR + Ed25519 signatures for 20 fixtures. See `android/core-crypto/src/test/resources/golden-vectors.json` and `backend/common/golden_vectors.py`.

## Human-blocked

See roadmap §7: Play Services audit, card procurement/HSM, payment licence, corpora partnerships, etc. — tracked as GitHub issues, not faked.

## License

TBD — pending dataset governance agreement.

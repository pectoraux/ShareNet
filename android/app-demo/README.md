# app-demo — ShareNet Demo (Reference Consumer)

**Package** `net.sharenet.demo` · **App name** *ShareNet Demo*  
**Module type** `com.android.application` · **minSdk 26 · compileSdk 34 · targetSdk 34**

## Purpose — SDK isolation proof

`app-demo` is the **reference consumer** that proves the public SDK (`:sharenet-sdk`) is self-sufficient. It is deliberately **Room-less** and must not depend on any internal `core-*` modules.

```
app-demo  ──depends on──▶  sharenet-sdk   (only)
     ╳ core-crypto, core-content, core-catalog, core-transport, core-attest
```

If this app builds and runs, the SDK's public surface is complete enough for third-party apps. Any import of `net.sharenet.crypto.*`, `net.sharenet.content.*`, etc. inside `app-demo` is a violation — CI should fail on it (see `lint` custom check).

## What it demonstrates

| Screen | SDK capability exercised |
|---|---|
| **CatalogScreen** | `sdk.catalog.list()` filtered by `Category` (`EDUCATION / HEALTH / APP_UPDATE / MODEL_WEIGHTS / DATASET`) with priority badges. |
| **BlobDetailScreen** | `sdk.blobs.fetch(blobId)` streaming progress → `sdk.blobs.verify(blobId)` (Merkle + Ed25519) → render. Progress bar + verified/failed states. |
| **PublishScreen** | SAF file picker (`ActivityResultContracts.GetContent`) → `sdk.content.publish(uri, category)` → signed `Manifest` + `BlobId`. |

## Navigation

```
Catalog  ──tap blob──▶  BlobDetail (fetch + verify + render, progress)
   │
   └─FAB─▶  Publish (pick file → publish → navigate to BlobDetail)
```

Implemented with `navigation-compose` + `DemoNavGraph` (`navigation/DemoNavGraph.kt`) and serializable `DemoDestination`s.

## SDK init

`MainActivity.onCreate` calls `ShareNetSdkInitializer.init(context)` exactly once (idempotent). The initializer is a thin shim over `net.sharenet.sdk.ShareNetSdk.init()` — kept behind an object so tests can `resetForTest()` and inject fakes.

Real wiring when SDK is ready:

```kotlin
net.sharenet.sdk.ShareNetSdk.init(applicationContext)
```

## Build

```bash
./gradlew :app-demo:assembleDebug
./gradlew :app-demo:installDebug
```

No Room, no SQLCipher, no MediaPipe, no NFC — just `sharenet-sdk` + Compose BOM + `navigation-compose` + `DataStore` + `coroutines`.

## Invariants

- **No direct `core-*` imports.** Only `net.sharenet.sdk.*` and AndroidX/Compose.
- **Offline-first.** Catalog fetch works over Nearby mesh; Internet permission is opportunistic only.
- **Deterministic verify.** `BlobDetailScreen` shows a real Merkle/signature check, not a mock success.

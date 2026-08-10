# sharenet-sdk

Public SDK surface — the **only** entry point for apps (`app-demo`, `app-assistant`, `app-wallet`). No app may depend on `core-*` directly.

## Surface

```kotlin
interface ShareNetSdk {
  suspend fun publish(bytes: ByteArray, mimeType: String, category: Category): Manifest
  fun subscribe(category: Category): Flow<List<CatalogEntry>>
  suspend fun fetchBlob(blobId: BlobId): ByteArray
  suspend fun queryLocalAvailability(blobId: BlobId): Availability?
  suspend fun listLocalAvailability(): List<Availability>
  suspend fun submitContribution(contribution: Contribution)
  fun observeSyncState(): StateFlow<SyncState>
}
```

| Method | Notes |
|---|---|
| `publish` | Chunks via `core-content`, signs via `core-crypto`, pins blob, inserts `CatalogEntry` with priority (REVOCATION > APP_UPDATE > MODEL_WEIGHTS > rest). |
| `subscribe` | Cold `Flow` from `CatalogStore.observe` — emits immediately then on every change. |
| `fetchBlob` | Local hit returns instantly; miss requests chunks over `Transport` (chunk protocol + resume). Throws `BlobNotFoundException` when no peer serves it. |
| `queryLocalAvailability` / `listLocalAvailability` | Delegates to `LocalAvailability` (backed by `BlobStore`). |
| `submitContribution` | Signs and queues for opportunistic upload; caller must have recorded consent. |
| `observeSyncState` | `StateFlow<SyncState>` with `status ∈ {IDLE, DISCOVERING, SYNCING, PAUSED_GOVERNOR, ERROR}` |

All public symbols have KDoc. See `ShareNetSdk.kt`.

## Wiring

`SdkModule` (`SdkModule.kt`) is the DI/factory:

```kotlin
// Production (needs Context — creates NearbyTransport + Room DB)
val sdk: ShareNetSdk = SdkModule.create(context)

// Unit test / Preview — no Android, in-memory fakes
val sdk: ShareNetSdk = SdkModule.createFake()
```

Production `create` builds:

- `DefaultGovernor` + `NearbyTransport`
- `AttestDatabase` (Room, `inMemoryDatabaseBuilder` in scaffold — swap to SQLCipher `SupportFactory` at app layer)
- `ReceiptManager` + `PointsLedger` + `DefaultFraudControls`
- `FakeCryptoProvider` by default — inject the real Tink `CryptoProvider` at the app layer.

For Hilt:

```kotlin
@Module @InstallIn(SingletonComponent::class)
object ShareNetModule {
  @Provides @Singleton
  fun provideSdk(@ApplicationContext ctx: Context): ShareNetSdk = SdkModule.create(ctx)
}
```

## Module boundaries

`sharenet-sdk` `api`-depends on all `core-*` and `testing` so apps get a single dependency:

```gradle
implementation(project(":sharenet-sdk"))
```

A dependency-constraint test (M5 acceptance) asserts `app-demo` compiles with **zero** direct `core-*` imports.

## Dependencies

All `core-*` + `testing`, `room-runtime`, `room-ktx`, `work-runtime-ktx`, `coroutines`, `datastore`.

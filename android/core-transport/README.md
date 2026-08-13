# core-transport

Nearby Connections abstraction, battery/network governor, and background sync worker. This is the only module that touches Play Services `Nearby`.

## Contract

```
Transport (interface)
  ├── NearbyTransport  — P2P_CLUSTER (BLE + BT Classic + Wi-Fi Direct auto-selected)
  └── FakeTransport    — in `:testing` (in-memory channels, no Android)
```

**`Transport` surface** (`Transport.kt`):

```kotlin
interface Transport {
  fun startDiscovery(serviceId: String)
  fun stopDiscovery()
  fun startAdvertising(serviceId: String, endpointName: String)
  fun stopAdvertising()
  fun connect(endpointId: EndpointId)
  fun disconnect(endpointId: EndpointId)
  suspend fun send(endpointId: EndpointId, payload: ByteArray)
  val incoming: Flow<Payload>
  val discoveredEndpoints: Flow<Set<EndpointId>>
  val connectionStates: Flow<Map<EndpointId, ConnectionState>>
}
```

`send` throws `TransportException.GovernorBlocked` when the governor disallows transfers and `NotConnected` when the peer is not in `CONNECTED` state.

## Governor

`Governor` (`Governor.kt`) gates every `send` and every `SyncWorker` tick:

| Condition | Result |
|---|---|
| Battery < 20% **and** not charging | `Blocked("Battery …")` |
| `wifiOnly == true` **and** active network is metered | `Blocked("Metered + Wi-Fi-only")` |
| Otherwise | `Allowed` |

- `DefaultGovernor` reads `BatteryManager` + `ConnectivityManager`. `FakeGovernor` (also defined in this module for convenience) exposes a mutable `snapshotOverride` for tests.
- The Wi-Fi-only toggle is exposed as `StateFlow<Boolean>` and persisted via DataStore (real persistence wired at app layer).

## WorkManager sync

`ShareNetSyncWorker` (`SyncWorker.kt`) is a `CoroutineWorker`:

- Constraints: `NetworkType.CONNECTED` + `RequiresBatteryNotLow`.
- Checks `Governor.canTransfer()` first; returns `Result.retry()` when blocked.
- `enqueue()` registers a 15-minute `PeriodicWorkRequest` with `ExistingPeriodicWorkPolicy.KEEP`.
- Dependencies are behind `SyncDependencies` so tests inject a `FakeTransport` without Android.

## Chunk protocol

`ChunkProtocol` in `SyncWorker.kt` documents the framing used between peers (`chunk_req` / `chunk_resp` / `have`). Payloads are Nearby `BYTES` (reliable). FILE/STREAM payloads can be added for >32 KB chunks; the current framing leaves that choice to the caller.

## Invariants

- `P2P_CLUSTER` strategy — do not change without also updating discovery/advertising options.
- No transfer when governor says `Blocked` — enforced at `send` call site, not just UI.
- Discovery/advertising are idempotent (`start` with same `serviceId` is a no-op).
- `FakeTransport` lives in `:testing`, never here — this module has zero test fakes.

## Dependencies

`core-crypto`, `core-content`, `play-services-nearby`, `work-runtime-ktx`, `kotlinx-coroutines-android`.

## Testing

```kotlin
val gov = FakeGovernor(snapshotOverride = GovernorSnapshot(10, false, false, true))
val a = FakeTransport("A", governor = gov)
val b = FakeTransport("B", governor = gov)
FakeTransport.link(a, b)
// a.send(bId, bytes) now throws GovernorBlocked
gov.snapshotOverride = GovernorSnapshot(80, true, false, true)
// retries succeed
```

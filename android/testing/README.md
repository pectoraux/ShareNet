# testing

Pure Kotlin JVM test-support library. **No Android dependencies** — runs on the JVM without an emulator.

## Modules

| File | Purpose |
|---|---|
| `FakeTransport.kt` | In-memory `Transport` fake with N-peer mesh, governor checks, bandwidth throttling, disappear/resume |
| `FakeClock.kt` | Controllable clock (`advanceBy`) for deterministic time |
| `Fixtures.kt` | 20 seeded keypairs + sample manifests, blobs, contributions |
| `GoldenVectors.kt` | Generate/verify golden JSON for M0 CBOR+Ed25519 interop |

## FakeTransport

```kotlin
val gov = FakeGovernor(GovernorSnapshot(batteryPercent = 80, isCharging = true))
val a = FakeTransport("A", gov)
val b = FakeTransport("B", gov)
FakeTransport.link(a, b)
a.startDiscovery("svc"); b.startDiscovery("svc")
a.connect(b.localEndpointId)
a.send(b.localEndpointId, "hello".toByteArray()) // arrives on b.incoming

// Bandwidth throttling
a.bandwidthBytesPerSecond = 64 * 1024 // 64 KB/s — send now delays

// Peer disappear / resume (tests resumable transfers)
a.simulatePeerDisappear()
assertFailsWith<TransportException.NotConnected> { a.send(b.localEndpointId, bytes) }
a.simulatePeerResume()
a.connect(b.localEndpointId) // re-establish

// N-peer mesh (fraud diversity tests)
val mesh = Mesh.of(5)
FakeTransport.linkAll(a, b, mesh.peer(0))
```

Governor is enforced on every `send` — low battery or metered+wifiOnly throws `GovernorBlocked`.

`sentPayloads` / `receivedPayloads` are kept for assertions; `injectIncoming` allows direct injection.

## FakeClock

```kotlin
val clock = FakeClock() // 2025-01-01T00:00:00Z
clock.advanceBy(24 * 60 * 60 * 1000L) // +1 day, no real delay
clock.setTo(Instant.parse("2025-06-01T00:00:00Z").toEpochMilli())
clock.nowFlow // StateFlow<Long> for reactive code
```

Production code takes `clock: () -> Long` (defaults to `System.currentTimeMillis`). Pass `clock::now` in tests.

## Fixtures

```kotlin
Fixtures.keypairs // 20 deterministic Ed25519-ish pairs (HMAC-SHA256 derived)
Fixtures.publisher // keypairs[0]
Fixtures.blobBytes(i, sizeBytes)
Fixtures.manifests // 5 sample manifests (EDUCATION, HEALTH, REVOCATION, …)
Fixtures.contributions // 3 sample contributions (en↔twi, ewe→en)
```

Seed for pair `i` is `SHA256("sharenet-fixture-$i")` — identical in Kotlin and Python. No `SecureRandom` in fixtures.

## GoldenVectors

```kotlin
val vectors = GoldenVectors.generate(File("golden-vectors.json"))
val failures = GoldenVectors.verify(vectors) // [] if all pass
val loaded = GoldenVectors.readFrom(File("golden-vectors.json"))
```

Vectors are `{name, cbor_hex, signature_hex, public_key_hex}`. The placeholder CBOR is `SHA256("sharenet-golden:$i:$pubHex")`; replace with the real deterministic CBOR codec at M0 without changing the JSON shape. The file is byte-identical on Kotlin and Python when both sides finalize the codec — this is the M0 acceptance gate.

## Build

```kotlin
// testing/build.gradle.kts — pure JVM, no Android
plugins { kotlin("jvm") }
dependencies {
  api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
  implementation("junit:junit:4.13.2")
}
```

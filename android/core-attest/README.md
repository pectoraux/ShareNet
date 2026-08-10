# core-attest

Delivery attestation: receipt generation, verification, queuing, upload, fraud controls, points ledger.

## Contract

### Receipt generation — recipient signs, sender cannot forge

```kotlin
val receipt = receiptManager.generateReceipt(
  blobId, bytesDelivered, senderId, recipientKeypair, nonce
)
receiptManager.verify(receipt) // Ed25519 verify via core-crypto
```

`generateReceipt` **must** run on the recipient device. The signature is Ed25519 over the canonical CBOR of `(blobId, bytesDelivered, senderId, recipientId, timestamp, nonce)` signed with the recipient's private key. An adversarial test asserts a sender cannot produce a valid receipt without the recipient's key.

### Queueing

```kotlin
receiptManager.queue(receipt)  // Room INSERT OR IGNORE (replay protection via nonce)
receiptManager.queuedCount()
```

- Replays (same `receiptId = hex(blobId):hex(recipientId):hex(nonce)`) collide on `insertOrIgnore` and return `null`.
- `FraudControls.evaluate` runs before insert; `Blocked` throws `FraudBlockedException`, `AllowedWithWeight(0.0)` is queued but credited 0 points.

### Upload

```kotlin
receiptManager.upload(integrityVerifier)  // opportunistic; retries on failure
receiptManager.startPeriodicUpload(intervalMs, integrityVerifier)
```

- Survives 30 days offline — `ReceiptEntity.queuedAt` is FIFO, `pruneUploaded` only after successful ack.
- `ReceiptUploader` is the backend ingest client; `InMemoryUploader` is provided for tests.

### Room

| Entity | Table | Notes |
|---|---|---|
| `ReceiptEntity` | `receipts` | `receiptId` is PK (blobId:recipientId:nonce). `status` in `QUEUED/UPLOADING/UPLOADED/FAILED`. |
| `PointsEntry` | `points_ledger` | Integer minor units only (never floating point). `availableAt = createdAt + 30d` holdback. |

`AttestDatabase` is a `RoomDatabase` with DAOs `ReceiptDao` / `PointsLedgerDao`. Exported schema under `schemas/`.

### Fraud controls (`FraudControls.kt`)

All roadmap M4 controls are stubbed with real interfaces:

| Control | Local stub | Backend (authoritative) |
|---|---|---|
| Recipient diversity | `pairCounts[(sender:recipient:day)] >= 10` → `AllowedWithWeight(0.0)` | Weighted to zero beyond N/day |
| Rate caps | `senderCounts[sender:day] >= 100` → `Blocked(RATE_CAP)` | Hard ceiling |
| Geographic plausibility | Always `Allowed` locally (needs location) | `max 120 km/h` plausibility |
| Play Integrity | `StubPlayIntegrityVerifier → Unavailable`; `PlayIntegrityVerifierImpl` calls real API | Token verified server-side |
| Payout holdback | `PointsLedger` — `availableAt = now + 30d` | Clawback within window |

`DefaultFraudControls` is in-memory and resettable; swap for a Room-backed impl in prod.

### Points ledger (`PointsLedger.kt`)

```kotlin
pointsLedger.available()  // sum where availableAt <= now, not clawed back
pointsLedger.pending()    // sum where still in holdback
pointsLedger.clawBack(receiptId)
```

- Points are `1 per MB` in minor units (`1 point = 1000`); replace with backend-provided value when synced.
- Integer arithmetic only — `shares sum to 1.0` is enforced with rational arithmetic on the backend.
- `availablePoints` / `pendingPoints` are exposed as `StateFlow<Long>` for UI.

## Dependencies

`core-crypto`, `core-content`, `room-runtime`, `room-ktx`, `work-runtime-ktx`, `datastore`, `coroutines`.

## Testing

```kotlin
val crypto = FakeCryptoProvider
val dao = InMemoryReceiptDao() // or Room.inMemoryDatabaseBuilder
val ledger = PointsLedger(fakePointsDao, clock = fakeClock::now)
val fraud = DefaultFraudControls()
val uploader = InMemoryUploader()
val mgr = ReceiptManager(crypto, dao, ledger, fraud, uploader, clock = fakeClock::now)

val receipt = mgr.generateReceipt(blobId, 1_048_576, senderId, recipientKeypair)
assert(mgr.verify(receipt))
mgr.queue(receipt) // 1st insert
assertEquals(null, mgr.queue(receipt)) // replay → null
```

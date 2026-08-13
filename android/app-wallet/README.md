# ShareNet Wallet — NFC terminal

Android NFC reader-mode terminal. The phone **never holds value** — cards hold value in tamper-resistant SE; the phone just mediates `DEBIT → CREDIT`.

## Stack

- `NfcAdapter.enableReaderMode` + `IsoDep`
- `ApduCommands` / `CardChannel` / `NfcReaderManager`
- `PaymentFlow` (invariants: no double credit, balance non-negative, offline cap, revocation)
- Room `WalletDatabase` for tx log (queue+settle on reconnect)
- Material 3 Compose (no purple gradients, no AI slop)

## Flow

1. Tap payer → `SELECT` → `MUTUAL_AUTH` → `GET_BALANCE` → `DEBIT(amount, nonce)` → signed record
2. Tap payee → `SELECT` → `MUTUAL_AUTH` → `CREDIT(record)` → verify counterpart signature
3. Store record → settlement queue → `SettlementScreen` → `POST /settlement/settle` (idempotent, double-spend detection)

Removing a card mid-transaction leaves no value destroyed/duplicated (JCSystem transaction on-card; adversarial test runs this 50×).

## Revocation

`RevocationList` synced via ShareNet catalog `REVOCATION` category (max priority, propagates before content). Revoked card → refused immediately.

## Build

```bash
./gradlew :app-wallet:installDebug
```

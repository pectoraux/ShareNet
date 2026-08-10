# card-applet

JavaCard 3.x applet on NXP JCOP-class SE. Tested with jCardSim — no hardware required.

## APDU

| CLA | INS | P1 | P2 | Lc | Data | Le | Behaviour |
|-----|-----|----|----|----|------|----|-----------|
| 80 | A4 | 04 | 00 | aid | — | SELECT |
| 80 | 10 | 00 | 00 | 8 | challenge | 8 | MUTUAL_AUTH |
| 80 | 20 | 00 | 00 | — | — | 2 | GET_BALANCE |
| 80 | 30 | 00 | 00 | 6 | amount(2)+nonce(4) | 16 | DEBIT → signed record |
| 80 | 31 | 00 | 00 | 8 | amount(2)+nonce(4)+padding | 2 | CREDIT |
| 80 | 40 | n | 00 | — | — | n*4 | GET_TX_LOG |
| 80 | 50 | 00 | 00 | — | — | 5 | GET_OFFLINE_STATE |

## Invariants (applet-enforced, the security model)

- Balance never negative
- Monotonic counter; never reused
- Cumulative offline value cap (50k minor units) until settlement
- Max transactions since settlement (100)
- Keys never leave SE
- Power-loss atomicity via `JCSystem.beginTransaction/commitTransaction`

## Test

```bash
./gradlew jCardSimTest  # or ./gradlew test
```

See `src/test/java/net/sharenet/card/AppletTest.java` — covers replay, forgery, underflow, offline cap, atomicity.

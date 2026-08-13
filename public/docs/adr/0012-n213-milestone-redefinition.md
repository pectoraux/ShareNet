# ADR-0012: N2.1.3 Milestone Redefinition — Circuit Cryptographic Setup

- Status: ACCEPTED
- Date: 2026-08-13
- Decider: ShareNet Architecture (frozen v1.0)

## Context

The frozen architecture (spec §38, N2.1.1 ADR §26) defined:

```text
N2.1.3 — Circuit Establishment
    CommittedRoute
        ↓
    Circuit establishment
        ↓
    Session keys
        ↓
    Forwarding state
```

During implementation, it became clear that **true circuit establishment is inherently distributed**: for A → B → C → G, after `establish_circuit()` executes on A, B/C/G know nothing. No relay receives the handshake, verifies it, derives its key, or acknowledges establishment. There is no distributed forwarding state.

Faking a distributed handshake locally (e.g. a mock relay registry) would be worse than being honest about the scope.

## Decision

**Redefine N2.1.3 as "Circuit Cryptographic Setup" — local source-side preparation only.**

```text
N2.1.3 — Circuit Cryptographic Setup (LOCAL)
    CommittedRoute
        ↓
    CircuitHandshake (signed by source, bound to commitment)
        ↓
    Per-hop X25519 DH + HKDF key derivation
        ↓
    CircuitSetup (source-side cryptographic preparation artifact)
        ↓
    [NOT: live forwarding state, NOT: distributed circuit]

N2.2+ — Distributed Circuit Establishment (FUTURE)
    CircuitSetup
        ↓
    Send handshake to each relay
        ↓
    Each relay verifies + derives key + installs forwarding state
        ↓
    Each relay acknowledges
        ↓
    ActiveCircuit (live distributed forwarding state)
```

### Naming changes

| Old | New |
|---|---|
| `ActiveCircuit` | `CircuitSetup` |
| `establish_circuit()` | `prepare_circuit_setup()` |
| `active: bool` | removed (no distributed state to be "active") |
| "live circuit state" | "source-side cryptographic preparation" |
| "established circuit" | "cryptographic preparation artifact" |

### What CircuitSetup is NOT

- NOT a live circuit
- NOT forwarding state
- NOT an established session
- NOT installed on any relay

### What CircuitSetup IS

- Source-side cryptographic preparation
- Per-hop forwarding keys (derived locally via X25519 DH + HKDF)
- Binding to a CommittedRoute (via commitment hash)
- Unique circuit_id (for instance identification — NOT replay prevention)
- Handshake + teardown messages (ready to be sent, but not yet sent)

## Consequences

1. The spec/roadmap must be updated to reflect the new milestone definition.
2. The `CircuitSetup` struct documentation must not describe itself as "live" or "active."
3. `circuit_id` documentation must not claim randomness provides replay protection.
4. Distributed circuit establishment is explicitly deferred to N2.2+.
5. The `CircuitReplayState` type is defined but not yet used (future distributed establishment).

## Conformance

- `circuit_handshake.rs` module docs explicitly say "LOCAL preparation, NOT distributed establishment."
- `CircuitSetup` struct docs say "source-side cryptographic preparation artifact."
- No test claims distributed establishment occurred.
- 17 N2.1.3 tests verify the local cryptographic setup, not distributed state.

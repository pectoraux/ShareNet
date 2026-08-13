# ShareNet Spec — Circuits

**Normative.** RFC 2119 keywords. This document defines the circuit layer independently of any platform.

---

## N2.1.3 — Circuit Cryptographic Setup

**Status: FROZEN (per ADR-0012)**

N2.1.3 is **source-side cryptographic preparation only**. It does NOT establish a distributed circuit. No relay receives the handshake, verifies it, derives its key, or acknowledges establishment. No forwarding state is installed on any remote participant.

### Pipeline

```text
CommittedRoute (agreement + evidence)
        ↓
CircuitHandshake (signed by source, bound to commitment hash)
        ↓
Per-hop X25519 DH + HKDF-SHA256 key derivation
        ↓
CircuitSetup (source-side cryptographic preparation artifact)
```

### CircuitSetup is NOT

- A live circuit
- Forwarding state
- An established session
- Installed on any relay

### CircuitSetup IS

- Source-side cryptographic preparation
- Per-hop forwarding keys (derived locally via X25519 DH + HKDF)
- Binding to a CommittedRoute (via commitment hash)
- A unique `circuit_id` (for instance identification — NOT replay prevention)
- Handshake + teardown messages (ready to be sent, but not yet sent)

### `circuit_id`

`circuit_id` uniquely identifies a circuit instance. Random uniqueness helps distinguish circuit instances. It is **NOT** replay protection. Replay protection requires receiver-side acceptance state (`CircuitReplayState` — future distributed use, N2.2+).

### X25519 Circuit Key Requirement (per ADR-0013)

```text
INTERNET_GATEWAY capability
    → X25519 circuit public key REQUIRED

RELAY capability (participating in circuits)
    → X25519 circuit public key REQUIRED

Other nodes
    → X25519 circuit public key OPTIONAL
```

A relay without an X25519 circuit key cannot participate in circuits. `prepare_circuit_setup()` rejects such hops with `HopMissingCircuitKey`.

### Fail-closed principle

- All CBOR encoding uses `map_err` (no `unwrap_or_default`).
- OS randomness (`circuit_id`, `nonce`) is checked (no `let _ =`).
- `RouteSerializationError` propagates through all creation paths.

---

## N2.2+ — Distributed Circuit Establishment & Forwarding State (FUTURE)

**Status: NOT YET IMPLEMENTED**

```text
CircuitSetup
        ↓
Send handshake to each relay
        ↓
Each relay verifies handshake + proves X25519 key possession
        ↓
Each relay derives its key + installs forwarding state
        ↓
Each relay acknowledges establishment
        ↓
ActiveCircuit (live distributed forwarding state)
```

### N2.2 requirements

- Each relay must receive the `CircuitHandshake` and independently verify it.
- Each relay must prove possession of its X25519 private key (not just the advertised public key).
- Each relay must install forwarding state (predecessor/successor + forwarding key).
- Each relay must acknowledge establishment.
- `CircuitReplayState` must be maintained per-relay to reject duplicate handshakes.
- An `ActiveCircuit` (live distributed state) is only produced after ALL required relays acknowledge.

### NOT in N2.2

- TCP connection migration (N2.1.4+, spec §39).
- Route failure / recovery (N2.1.4, spec §39).
- Key rotation within a live circuit (N2.1.4+).
- Internet gateway traffic forwarding (N2.3+).

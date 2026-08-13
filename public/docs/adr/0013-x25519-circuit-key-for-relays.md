# ADR-0013: X25519 Circuit Key Required for Circuit-Participating Relays

- Status: ACCEPTED
- Date: 2026-08-13
- Decider: ShareNet Architecture (frozen v1.0)

## Context

The original protocol invariant (N2.0.7.3) was:

```text
INTERNET_GATEWAY → X25519 circuit public key REQUIRED
non-gateway      → X25519 circuit public key ABSENT
```

This was enforced by:
- `NodeAdvertisement::verify_into_verified()` rejecting non-gateway nodes with X25519 keys.
- `Route::validate()` rejecting relay hops with X25519 keys (`RelayHasCircuitKey`).

N2.1.3's circuit cryptographic setup requires **every non-source forwarding hop** to have an X25519 circuit public key for per-hop DH key derivation. This means relays participating in circuits MUST have X25519 keys — the old invariant is incompatible with the new circuit architecture.

## Decision

**Remove the old invariant. Replace with:**

```text
INTERNET_GATEWAY capability
    → X25519 circuit public key REQUIRED

RELAY capability (participating in circuits)
    → X25519 circuit public key REQUIRED

Other nodes
    → X25519 circuit public key OPTIONAL
```

### Simpler formulation (chosen for N2.1.3)

Rather than introducing a separate `CIRCUIT_PARTICIPANT` capability (which would require advertisement schema changes and backward-compat migration), we use the simpler rule:

```text
Gateway → X25519 key required (unchanged)
Relay   → X25519 key permitted (was: forbidden)
```

A relay that wants to participate in circuits MUST advertise an X25519 key. A relay without one cannot be part of a circuit (rejected by `prepare_circuit_setup()` with `HopMissingCircuitKey`).

### Code changes

- `node_advert.rs`: `verify_into_verified()` no longer rejects non-gateway nodes with X25519 keys. Gateways still require X25519.
- `route.rs`: `RelayHasCircuitKey` error variant and check REMOVED from `Route::validate()`.
- `circuit_handshake.rs`: `prepare_circuit_setup()` requires every non-source hop to have an X25519 key (`HopMissingCircuitKey` if missing).

### Future consideration

If we later need to distinguish "relay that participates in circuits" from "relay that only forwards link-layer frames," a `CIRCUIT_PARTICIPANT` capability can be introduced. For now, the simpler rule (relay MAY have X25519, circuit requires it) is sufficient.

## Consequences

1. Relay advertisements with X25519 keys are now valid (previously rejected).
2. Route validation no longer rejects relay hops with X25519 keys.
3. Circuit preparation requires every non-source hop to have an X25519 key.
4. The N2.0.7.3 `RelayHasCircuitKey` error variant is removed.
5. Tests that expected relays to be rejected for having X25519 keys are updated to expect acceptance.

## Conformance

- `n210_node_advert.rs`: `relay_with_x25519_key_rejected` test updated to expect acceptance.
- `n207_north_star.rs`: `RelayHasCircuitKey` meta-test inverted (verifies the check is GONE).
- `n213_circuits.rs`: `intermediate_relay_missing_circuit_key_rejected` verifies `HopMissingCircuitKey`.

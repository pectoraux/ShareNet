# ADR-0014: N2.4 Bidirectional Circuit Traffic & Flow Lifecycle

**Date:** 2026-08-14
**Status:** PROPOSED
**Supersedes:** None
**Superseded by:** None

## Context

N2.3 (frozen at `0efaaac`) proves forward-only traffic: A → B → C → G. The real Internet requires bidirectional communication: A ⇄ B ⇄ C ⇄ G ⇄ Internet. Before adding gateway egress (N2.6), the circuit must be a genuinely bidirectional authenticated transport channel.

## Decision

### 0. Protocol version boundary (P0)

N2.3 is frozen with **circuit packet profile v1**. N2.4 introduces **profile v2** — a new, non-backward-compatible packet format. The v2 AAD domain includes a versioned prefix: `"SNP/0.1/circuit/packet/v2"` (v1 had no domain prefix). v1 and v2 packets are cryptographically non-equivalent. The reference implementation has migrated to v2; N2.3 tests now exercise v2-forward traffic, not v1.

### 1. Reverse traffic uses the Tor add-layer model

Forward traffic (N2.3): the source creates nested AEAD layers; each relay **peels** (decrypts) one layer.

Reverse traffic (N2.4): each relay **adds** (encrypts) one AEAD layer as the packet passes through; the source **peels all layers** (decrypts) at the end.

**Rationale:** This model does not require sharing keys between relays. Each relay only uses its own `forwarding_key` (derived from X25519 DH with the source's ephemeral key). The gateway (G) originates reverse traffic with plaintext; each relay adds one layer of encryption; the source (A) peels all layers to recover plaintext.

This is the proven Tor reverse model. It avoids the complexity of a second key exchange or pre-sharing reverse keys during establishment.

### 1a. Same key for both directions (normative)

Forward and reverse traffic use the **SAME** per-hop `forwarding_key`. No second DH exchange, no separate reverse key. The direction is separated by:
- Direction byte in the AAD (Forward=0, Reverse=1).
- Direction XOR in the nonce derivation (`fid[0] ^= direction`).

This is a frozen decision: a future agent MUST NOT invent a second key exchange or derive a different reverse key.

### 2. Traffic direction is cryptographically bound

A `TrafficDirection` field (Forward=0, Reverse=1) is included in the packet and bound into the AEAD AAD. A forward packet cannot be replayed as a reverse packet, and vice versa.

### 3. Independent sequence namespaces per direction

Forward and reverse each have their own sequence allocator, starting at `FIRST_PACKET_SEQ=1`. Forward seq=1 and reverse seq=1 are both valid because the direction is cryptographically bound. This preserves the AEAD nonce-safety property: the nonce is derived from `(circuit_id, direction, seq)`, so forward seq=1 and reverse seq=1 produce different nonces.

### 3a. Reverse sequence ownership (normative)

`ActiveCircuit` MUST own both `forward_seq_state` and `reverse_seq_state`. Both are `pub(crate)`, `!Clone`. The gateway obtains its reverse allocator from the circuit — no independent production allocator may be constructible from `circuit_id + hops` alone. This preserves the N2.3 no-nonce-reuse invariant for both directions.

### 4. Independent replay windows per direction

Each relay maintains separate forward and reverse replay windows. A forward packet's seq does not mutate the reverse replay window, and vice versa.

### 5. Flow identity (`flow_id`)

An 8-byte `flow_id` is introduced to distinguish logical traffic flows on one circuit. A circuit is not synonymous with one application connection. For N2.4, `flow_id` is cryptographically bound in the AAD and validated by the relay, but TCP stream multiplexing is deferred.

### 6. Domain-separated AAD

The AAD includes a versioned domain-separation prefix `"SNP/0.1/circuit/packet/v2"` to prevent cross-protocol and cross-version confusion. The full AAD is:

```text
"SNP/0.1/circuit/packet/v2" ‖ circuit_id ‖ direction ‖ flow_id ‖ seq ‖ ttl ‖ final_dst
```

### 6. Relay state refactored to directional

The relay's forwarding state is split into `CircuitDirectionState` (forward + reverse), each with its own ingress/egress/replay-window, sharing the same `forwarding_key`. This avoids duplicating security logic while maintaining independent replay state.

### 7. Domain-separated AAD

The AAD includes a domain-separation prefix `"SNP/0.1/circuit/packet"` to prevent cross-protocol confusion. The full AAD is:

```text
"SNP/0.1/circuit/packet" ‖ circuit_id ‖ direction ‖ flow_id ‖ seq ‖ ttl ‖ final_dst
```

## Consequences

- The `CircuitPacket` wire format gains `direction` and `flow_id` fields.
- `RelayForwardingState` is refactored (breaking change from N2.3, but N2.3 is internal to this branch).
- `forward_packet` handles both directions (peel for forward, add for reverse).
- The source (A) gains a reverse-receive path (peel all layers).
- The gateway (G) gains a reverse-send path (originate reverse packets with plaintext).
- `ActiveCircuit` gains a reverse sequence allocator.
- All N2.3 security guarantees are preserved for both directions.

## NOT decided (deferred)

- Internet gateway egress, SOCKS, TUN/VPN, Android, TCP migration, route recovery, congestion control, Civic Points, content transfer, UI, TCP stream multiplexing.

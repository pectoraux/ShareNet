# ADR-0007: Transport Endpoint Model — Advertised vs Observed vs Reachability

**Status:** Recorded (N2.1.2.5)
**Date:** 2025-08-13
**Supersedes:** None
**Superseded by:** None

## Context

N2.1.2.5 introduced `TransportBinding` in `snp-link` and requires
`AuthenticatedLink::from_verified_handshake()` to verify that the
`LinkKey.endpoint` exactly matches the `VerifiedHandshake`'s transport
binding (obtained from `TcpStream::peer_addr()`).

This strict equality works for the simple direct-TCP reference case:

```text
B advertises 203.0.113.10:4000
A connects to 203.0.113.10:4000
A sees peer_addr() = 203.0.113.10:4000
→ match
```

But real-world deployments will encounter cases where the advertised
endpoint and the observed socket peer address are different
representations of the same logical reachable endpoint:

- **DNS/hostnames:** B advertises `relay.example.com:4000`, but
  `peer_addr()` returns `198.51.100.24:53172` (resolved IP + ephemeral
  source port).
- **NAT/port mapping:** B is behind NAT. B advertises a public
  mapped address, but the connection is established through a
  rendezvous/STUN mechanism.
- **Rendezvous servers:** B is reachable through a relay/rendezvous
  server, not directly at the advertised address.
- **Dynamic addresses:** B's address changes (DHCP, mobile network
  handoff), but the logical endpoint identity is stable.

The current strict equality check would reject these legitimate
connections.

## Decision

**Do NOT weaken the strict equality check in N2.1.2.x.** The current
strict behavior is safer than inventing an insecure equivalence rule
without a proper design.

Instead, when we implement the actual transport-discovery layer
(future milestone), we should distinguish three concepts:

### 1. NodeEndpoint (advertised)

The authenticated endpoint the node advertises in its
`NodeAdvertisement`. This is what the remote node claims is reachable.

```text
NodeEndpoint
    = TransportEndpoint in VerifiedNodeAdvertisement
    = "relay.example.com:4000"
```

### 2. ConnectionBinding (observed)

The actual transport connection observed by the local node. This is
what `TcpStream::peer_addr()` (or the equivalent for other transports)
returns.

```text
ConnectionBinding
    = TransportBinding in VerifiedHandshake
    = "198.51.100.24:53172"
```

### 3. ReachabilityBinding (proven)

An authenticated/proven relationship between the `NodeEndpoint` and
the `ConnectionBinding`. This is the new concept that needs to be
designed.

For straightforward TCP, `NodeEndpoint == ConnectionBinding`, and
the `ReachabilityBinding` is trivial (identity).

For NAT/rendezvous, the `ReachabilityBinding` would carry proof that
the observed connection address is a valid way to reach the advertised
endpoint. This could involve:

- DNS resolution proof (the hostname resolves to the observed IP).
- NAT mapping proof (the advertised address maps to the observed
  address via a verified STUN/rendezvous exchange).
- Rendezvous server attestation (a trusted rendezvous server
  attests that the observed address reaches the advertised endpoint).

## Consequences

### Current behavior (N2.1.2.5)

- Strict equality between `TransportEndpoint` and `TransportBinding`.
- Works for direct TCP with IP:port addresses.
- Rejects NAT/rendezvous/hostname scenarios.
- This is **intentionally strict** — safer than an insecure equivalence.

### Future behavior (transport-discovery layer)

- A `ReachabilityBinding` abstraction will mediate between
  `NodeEndpoint` and `ConnectionBinding`.
- The `AuthenticatedLink` constructor will check the
  `ReachabilityBinding` instead of requiring exact equality.
- Different transport types (TCP, BLE, Wi-Fi Direct, Nearby Connections)
  will have different `ReachabilityBinding` semantics.

### What does NOT change

- `VerifiedHandshake` remains unforgeable (private fields, private
  constructor, minted only by the handshake implementation).
- `TransportBinding` remains the observed connection address.
- `AuthenticatedLink` retains the proof.
- The route engine consumes `&AuthenticatedLink`.

## Implementation status

- **N2.1.2.5:** Strict equality implemented. This ADR recorded.
- **Future:** `ReachabilityBinding` design deferred to the
  transport-discovery layer milestone.

## Related

- N2.1.2.4: Unforgeable `VerifiedHandshake` proof.
- N2.1.2.5: Transport binding (actual endpoint used by handshake).
- `snp-link/src/lib.rs`: `TransportBinding`, `VerifiedHandshake`.
- `snp-node/src/node/link.rs`: `AuthenticatedLink::from_verified_handshake`.

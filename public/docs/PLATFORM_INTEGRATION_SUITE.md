# ShareNet 2.0 — Platform Integration Suite

**Status:** normative for platform implementations (Android, iOS, Linux, etc.)  
**Date:** 2026-08-12

---

## Purpose

Protocol conformance vectors (138/138) prove encoding/crypto agreement.
This suite proves a platform implementation can actually FUNCTION as a
ShareNet node — discovering peers, establishing sessions, routing traffic,
and recovering from failures.

---

## Required Tests

Every platform implementation MUST pass all of the following:

### 1. Two-Peer Handshake
- Two nodes discover each other
- Perform SNP-IK/0.1 handshake
- Verify fresh directional keys
- Verify peer identity (NodeId == SHA-256(publicKey))

### 2. Route Creation
- Client discovers a gateway via signed advertisement
- Client constructs a Route with explicit hop list
- Route validates (no loops, hop count ≤ 16, not expired)

### 3. Multi-Hop Forwarding
- Traffic flows: Client → Relay → Gateway
- Relay forwards without inspecting the body (I8)
- Gateway receives the intact circuit ciphertext

### 4. Gateway Selection
- Multiple gateways advertised
- Client selects via GatewaySelector (not first-available blindly)
- Selected gateway's advertisement is valid (signed, not expired)

### 5. Gateway Failure
- Active gateway disappears
- Failure detected (NACK or timeout)
- Client selects alternate gateway
- Traffic resumes via alternate gateway
- No process restart

### 6. Relay Failure
- Active relay disappears
- Failure detected
- Alternate route constructed (if available)
- Traffic resumes via alternate path
- No process restart

### 7. Recovery
- After any failure, the system reaches a stable state
- Old routes are invalidated
- Stale routes are rejected
- New sessions use fresh keys

### 8. Concurrent Flows
- Multiple simultaneous circuits
- Multiple simultaneous transit requests
- No cross-talk between circuits
- No session confusion

### 9. Local Internet Gateway
- Client with no direct Internet access
- Gateway fetches from a local HTTP server
- Client receives the real HTTP response
- Gateway signature verified
- Body integrity verified (objectId = SHA-256(body))

### 10. Conformance
- 138/138 protocol conformance vectors pass
- 0 disagreements with the reference implementation

---

## Android-Specific Requirements

In addition to the above:
- VpnService establishes a TUN interface
- Unmodified Chrome can browse through ShareNet
- BLE/Wi-Fi Direct discovery works (at least one Play-free transport)
- Foreground service maintains relay/gateway operation
- Android lifecycle (Doze, App Standby) handled gracefully

---

## Reference Implementation

The Rust reference implementation passes all 10 tests in the
`reference/snp-node/tests/` directory:
- n203_mesh_failure.rs (tests 1-7)
- n203_local_http.rs (test 9)
- n204_runtime.rs (test 8: concurrent connections)
- snp-conformance (test 10: 138/138 vectors)

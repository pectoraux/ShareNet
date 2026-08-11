# ShareNet — Revised Architectural Thesis & System Architecture

**Supersedes:** `docs/system_architecture_review.md` v1.1 (delete on merge)
**Status:** normative. Implementation agents may not deviate without an ADR.

---

## 1. Revised thesis

> **ShareNet is a delay-tolerant mesh network that redistributes Internet reachability.**
>
> Connectivity is treated as a **transferable resource** rather than a property of a device. A node without an Internet connection reaches the real Internet by routing through peers that have one. The user runs ordinary applications — Chrome, WhatsApp, an email client, any API — and ShareNet supplies the network path beneath them.

Three consequences follow, and they are binding:

1. **ShareNet is a bearer, not a destination.** The network's product is *reachability*. Content distribution, application distribution, model distribution, and value transfer are **capabilities layered on the bearer** — first-class, but not definitional. A change that improves content distribution by compromising the bearer is rejected.

2. **Degraded reachability is still reachability.** Minutes or hours of latency is a valid operating point, not a failure. The architecture is built for it from the bottom (Mode A) rather than treating it as a fallback from the top.

3. **The mesh must not understand transit payloads.** For Internet transit, relays forward ciphertext they cannot read. This is a security requirement *and* a scaling requirement: a relay that must parse payloads cannot be a dumb, cheap, battery-friendly forwarder.

### 1.1 What ShareNet is explicitly not

| Not | Because |
|---|---|
| An offline clone of the Internet | The user reaches the *real* origin server. |
| A collection of cloned apps | `app-feed`'s HTML5 `snr://` clones are demoted to an offline *fallback* capability, not the model. |
| An offline App Store | One `CONTENT_SEED` capability among several. |
| A file-sharing application | File sharing is `core-content` riding the bearer. |
| An LLM product | `app-assistant` is one Application Capability consumer. |
| A VPN | A VPN is one client, one operator, one tunnel to a trusted server. ShareNet has many mutually-distrusting relays, no operator, and no trusted server. |
| A centralised proxy | No node is privileged. Gateways are volunteered, discovered, and interchangeable. |

### 1.2 The invariant that keeps this honest

**Protocol capability and platform capability are separate concepts and are never conflated.** The protocol defines what a `MESH_RELAY` or `INTERNET_GATEWAY` *is*. Whether a given iPhone can *be* one is a platform question answered in the Platform Capability Matrix. Every architectural statement is of the form "the protocol supports X; platforms P, Q permit it; platform R does not, and degrades to Y."

---

## 2. Canonical architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  UNMODIFIED APPLICATIONS   Chrome · WhatsApp · Telegram · YouTube · mail  │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │  ordinary sockets / OS networking
┌────────────────────────────────────▼─────────────────────────────────────┐
│  L9  VIRTUAL NETWORK / PROXY        Mode C: TUN·VpnService·NE·WinTun      │
│      platform-specific adapters     Mode B: SOCKS5/HTTP local proxy       │
│      ── the ONLY layer that is      Mode A: store-and-forward job API     │
│         allowed to be OS-specific   TCP/UDP/DNS → ShareNet streams        │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼─────────────────────────────────────┐
│  L7  INTERNET GATEWAY               egress policy · NAT · DNS · fetch     │
│      (client half + gateway half)   circuit termination · fair queueing   │
├──────────────────────────────────────────────────────────────────────────┤
│  L10 APPLICATION CAPABILITY  │ L11 CIVIC CONTRIBUTION │ L12 SETTLEMENT    │
│  content·apps·models·catalog │ proofs · verification  │ points · payout   │
├──────────────────────────────────────────────────────────────────────────┤
│                          ═══ TRAFFIC CLASS SPLIT ═══                     │
│         CLASS A: CONTENT (mesh-understood)  │  CLASS B: TRANSIT (opaque)  │
├──────────────────────────────────────────────────────────────────────────┤
│  L6  ROUTING          route discovery · metric · selection · migration    │
│  L5  MESH SYNC        delay-tolerant store-carry-forward · anti-entropy   │
│  L4  DISCOVERY        peer discovery · capability advertisement           │
│  L3  TRUST            attestation · reputation · revocation               │
│  L2  OBJECT/CONTENT   CAS · chunking · Merkle · manifests                 │
│  L1  IDENTITY         node · device · user · economic (separated)         │
├──────────────────────────────────────────────────────────────────────────┤
│  L8  TRANSPORT ABSTRACTION      Link interface — one hop, no semantics    │
│      BLE · BT Classic · Wi-Fi Direct · Wi-Fi LAN/mDNS · TCP · QUIC · LoRa │
└──────────────────────────────────────────────────────────────────────────┘
```

Numbering follows the brief's list, not stack order. Stack order bottom-to-top is **L8 → L1 → L2 → L3 → L4 → L5 → L6 → {L7, L10, L11, L12} → L9**.

### 2.1 Layer contracts

| L | Layer | Owns | Must not |
|---|---|---|---|
| L1 | Identity | Key hierarchy, four identity classes, rotation, revocation | Assume one key per person |
| L2 | Object/Content | CAS, chunking, Merkle, manifests | Know about routes or gateways |
| L3 | Trust | Attestations, reputation, revocation propagation | Be authoritative for economic state |
| L4 | Discovery | Peer + capability advertisement, freshness | Imply reachability beyond one hop |
| L5 | Mesh Sync | Anti-entropy, store-carry-forward, bundle custody | Interpret transit payloads |
| L6 | Routing | Route discovery, metrics, selection, migration, repair | Terminate circuits |
| L7 | Gateway | Egress, DNS, NAT, policy, quotas | See beyond one circuit's endpoints |
| L8 | Transport | One-hop framing, MTU, link liveness | Define node addresses |
| L9 | Virtual Net | OS integration, packet capture, flow mapping | Contain protocol logic |
| L10 | App Capability | Catalog, apps, models, datasets | Bypass L6 |
| L11 | Civic | Contribution proof + verification | Mint points locally |
| L12 | Settlement | Authoritative points/wallet state | Be eventually consistent |

**Forbidden dependency:** L8 must never import L6, and L6 must never import a platform SDK. If a `Link` implementation needs to know what a route is, the abstraction has failed.

---

## 3. The traffic class split

This is the most important structural decision in the redesign, and it is why the existing `Transport` interface cannot be extended in place.

Every ShareNet frame carries a `class` discriminator. The two classes share links, routing, discovery, and scheduling — and share nothing else.

| | **Class A — Content** | **Class B — Transit** |
|---|---|---|
| ShareNet's role | Owner and distributor | Blind carrier |
| Payload | Chunks, manifests, catalog, revocations | Opaque ciphertext |
| Relay may read | Yes — must, to dedupe and verify | **No** |
| Addressing | Content-addressed (`BlobId`) | Endpoint-addressed (circuit) |
| Caching | Yes, aggressively | **Never** |
| Verification | Merkle root vs manifest signature | E2E AEAD; relay verifies nothing but the frame MAC |
| Duplication | Encouraged (seeding) | Forbidden (replay) |
| Latency | Irrelevant; hours are fine | Mode-dependent |
| Reward | Delivery receipt (recipient-signed) | Transit receipt (client-signed) |
| Failure | Retry from any peer | Circuit migration |

**Why this must be structural.** Content and transit have *opposite* correctness properties. Content wants replication, caching, and content-addressing; transit wants exactly-once, no caching, and endpoint-addressing. Any component that treats them uniformly will be wrong for one of them. The current codebase has only Class A, and its `Payload(endpointId, bytes)` type has no room for the distinction.

**The one place they meet:** a gateway fetching a *manifest* or *blob* from the origin Internet on the mesh's behalf performs a Class B transit that produces a Class A object. This is the correct reading of the existing `pointsForBridging` concept — and it must be modelled as an explicit **ingest** operation at L10, not as a special case inside routing.

---

## 4. Internet connectivity — three modes

The modes are a **capability ladder, not alternatives**. Every node implements Mode A. Modes B and C are added where the platform permits. A node advertises the highest mode it supports; a client negotiates down.

```
Mode A  ⊂  Mode B  ⊂  Mode C
delay-tolerant   proxied      transparent
```

### 4.1 Mode A — Delay-tolerant Internet

**Model:** the unit of work is a **signed, self-contained request bundle** that survives disconnection and is carried by whatever nodes happen to move between the client and a gateway. Store-and-forward, DTN-style custody transfer.

```
Client                mesh (hours)              Gateway            Origin
  │ build Request bundle                            │                 │
  │   {method, url, headers, body, deadline,        │                 │
  │    replyTo, maxResponseBytes}                   │                 │
  │ seal to gateway pubkey ────────────────────────►│                 │
  │        (custody hops, opportunistic)            │ execute ───────►│
  │                                                 │◄── response ────│
  │◄──── Response bundle (chunked, Merkle-verified) │                 │
```

- Request and response are **content-addressed objects**, so they reuse `core-content` chunking, Merkle verification, and resumable transfer directly. This is the highest-leverage reuse of existing code in the whole redesign.
- **Any** gateway can serve the request; the bundle is sealed to a *set* of acceptable gateway keys, not one.
- Responses are addressed to the client's **rendezvous identity**, not its node ID, so a response can be picked up by any device the user owns.
- Deadline and `maxResponseBytes` are mandatory — they bound relay storage and prevent a gateway being tricked into fetching a 10 GB file for a client that vanished.

**Works on every platform, including iOS.** No packet capture, no background sockets, no privileged APIs. This is why Mode A is the floor: it is the only mode with universal platform support, so the network is useful on day one everywhere.

**Suits:** email sync, messaging queues, feed pulls, software updates, form submissions, API calls with no interactive deadline, large downloads.
**Does not suit:** anything with a TLS handshake to the origin (see §4.4), interactive browsing, real-time media.

### 4.2 Mode B — Proxied Internet

**Model:** the gateway holds a live TCP/UDP socket to the origin on the client's behalf; the mesh carries a **circuit** between client and gateway. The client exposes a local SOCKS5/HTTP proxy that applications are pointed at.

```
App ──► localhost:1080 (SOCKS5) ──► ShareNet circuit ──► Gateway ──► Origin
        [Mode B adapter, L9]        [L6 routed, E2E]     [L7]
```

- **Circuit** = a routed, sequenced, flow-controlled, E2E-encrypted bidirectional stream between client and gateway, identified by a `CircuitId` that is meaningless to relays.
- The gateway sees `CONNECT host:port` and the ciphertext of the stream. If the app speaks TLS, the gateway sees only SNI/IP — the same as any ISP.
- Requires a **persistent connection** across the mesh, so it needs background execution on relays and on the client.

**Suits:** browsers via proxy config, anything honouring `HTTP_PROXY`, Telegram (native SOCKS5 support), curl, package managers.
**Does not suit:** apps that ignore proxy settings — which is most mobile apps, including WhatsApp.

### 4.3 Mode C — Transparent Internet

**Model:** ShareNet presents a **virtual network interface**. The OS routes traffic to it; unmodified applications use ordinary sockets and are unaware. This is the mode that delivers the thesis' promise.

```
App ──► OS socket ──► routing table ──► tun0 / VpnService / WinTun
                                             │
                                    L9 packet handler
                                    IP packet → flow demux → ShareNet stream
                                             │
                                       L6 → mesh → L7 gateway
                                             │
                                    userspace NAT → real socket → Origin
```

**The gateway is a userspace NAT.** It does not forward IP packets; it terminates flows and re-originates them from its own stack. This matters: it means the gateway needs **no root, no kernel module, and no special OS support** — an ordinary Android phone can be a gateway, which is the whole point.

**Platform mechanisms** (detail in the Platform Capability Matrix):

| Platform | Mechanism | Privilege | Verdict |
|---|---|---|---|
| Android | `VpnService` + `ProtectedFileDescriptor` | User consent dialog, no root | **Full** |
| Linux / RPi | `/dev/net/tun` | `CAP_NET_ADMIN` | **Full** |
| Windows | WinTun / WFP callout | Admin install, service | **Full** |
| macOS | `utun` + NetworkExtension | Signed, entitlement | **Full** |
| iOS/iPadOS | `NEPacketTunnelProvider` | Paid entitlement, App Store review | **Client only — see §5** |

**The critical Android constraint:** `VpnService` is **exclusive**. Only one app may hold it. A user running ShareNet cannot simultaneously run a commercial VPN. This must be surfaced in UX, and it means Mode C cannot be silently enabled.

**DNS is the classic leak.** In Mode C, DNS must be captured (UDP/53 and DoH bootstrap) and resolved **at the gateway**, never locally. A Mode C implementation that leaves DNS on the local resolver has failed, because the local resolver is unreachable — the device has no Internet.

### 4.4 The TLS reality, stated plainly

In Modes B and C the client performs the TLS handshake **end-to-end with the origin server**. The gateway carries ciphertext. This is correct and is what "the REAL Internet" requires.

In **Mode A this is impossible.** TLS is an interactive protocol; you cannot store-and-forward a handshake with hours of latency. Mode A therefore has exactly two honest options:

1. **Gateway-terminated TLS.** The gateway makes the HTTPS request and returns the response body. The gateway sees plaintext. This must be **explicit, per-request, and consented to**, and the response must be signed by the gateway so the client knows who saw it. Suitable for public content (news, updates, public APIs).
2. **Application-layer E2E.** The payload is already encrypted for the destination *above* HTTP (Signal protocol, PGP mail, an API with its own encryption). The gateway carries an opaque body.

**A Mode A request MUST carry a `tlsTermination` field with value `GATEWAY_PLAINTEXT` or `PAYLOAD_E2E`, and clients MUST refuse to send credentials over `GATEWAY_PLAINTEXT`.** Any design that hides this from the user is dishonest. This is the single most important privacy decision in the architecture and it must not be buried.

### 4.5 Mode negotiation and graceful degradation

```
Client capability ∧ Gateway capability ∧ Route quality → selected mode
```

- Client advertises the highest mode its platform permits; gateway advertises the highest it will serve.
- Selection is per-flow, not per-session. A Mode C client on a route whose RTT exceeds the interactive threshold **downgrades that flow to Mode A** if the application traffic is tolerant (a background sync), or fails it fast if not (a video call).
- **Degradation is visible.** The UI must show which mode is active and what it means for privacy. Silent degradation from `PAYLOAD_E2E` to `GATEWAY_PLAINTEXT` is a forbidden architectural change.

---

## 5. iOS/iPadOS — honest limitations

Stated separately because it is the platform most likely to be misrepresented.

**What is possible:**
- `NEPacketTunnelProvider` gives a real Mode C **client**. Apps on the device use ShareNet transparently. This requires the Network Extension entitlement, App Store review, and a per-app VPN profile.
- `MultipeerConnectivity` provides local peer discovery and transport over Bluetooth/Wi-Fi with real, though limited, background operation.
- Mode A works fully.

**What is not possible, and must never be claimed:**
- **iOS cannot be a reliable `INTERNET_GATEWAY`.** A backgrounded app cannot hold arbitrary outbound sockets on behalf of others; `NEPacketTunnelProvider` is designed to *send* the device's traffic to a remote server, not to *receive* and egress others' traffic. Even where technically coaxed, it will not survive App Store review or iOS background scheduling.
- **iOS cannot be a reliable `MESH_RELAY`.** Background execution is scheduler-controlled; there is no equivalent of a foreground service.
- `MultipeerConnectivity` background operation is materially restricted and unreliable for sustained relaying.

**Therefore the iOS node profile is:**

```
iOS  :  MESH_CLIENT, CONTENT_SEED (foreground), DISCOVERY (opportunistic)
        NOT INTERNET_GATEWAY, NOT reliable MESH_RELAY
```

**Design implication, and it is a real one:** an all-iOS neighbourhood is a non-functional ShareNet. The network requires Android, desktop, Raspberry Pi, or community-relay nodes to carry it. iOS is a **consumer** of the mesh. Deployment planning must account for this — a target community needs a viable ratio of relay-capable devices, and the Civic Points system should weight relay contribution accordingly.

---

## 6. Where the existing repository maps in

| New layer | Existing code | Disposition |
|---|---|---|
| L1 Identity | `core-crypto/Models.kt` `NodeId`, `IdentityStore.kt` | **Refactor** — split four identity classes |
| L1 Identity | `core-crypto/Crypto.kt` providers | **Replace** — non-functional |
| L1 Identity | `core-crypto/Cbor.kt` | **Refactor** — RFC 8949 ordering fix |
| L2 Object | `core-content/Chunking.kt` | **Preserve** + streaming API |
| L2 Object | `core-content/MerkleTree.kt` | **Refactor** — RFC 6962 + leaf-count binding |
| L2 Object | `core-content/BlobStore.kt` | **Preserve** |
| L3 Trust | `core-catalog/PublisherRegistry.kt`, `RevocationList.kt` | **Preserve design**, retarget onto real crypto |
| L4 Discovery | — | **New** (`core-discovery`) |
| L5 Mesh Sync | `core-transport/SyncWorker.kt` | **Replace** (`core-sync`) |
| L6 Routing | — | **New** (`core-routing`) |
| L7 Gateway | `core-attest/pointsForBridging` (concept only) | **New** (`core-gateway`) |
| L8 Transport | `core-transport/Transport.kt`, `NearbyTransport.kt` | **Replace** — becomes `Link` |
| L8 Transport | `core-transport/Governor.kt` | **Refactor** — generalise to policy engine |
| L9 Virtual Net | — | **New**, per-platform |
| L10 App Capability | `core-catalog`, `app-feed`, `app-assistant` | **Preserve**, demote to capability |
| L11 Civic | `core-attest/ReceiptManager.kt` | **Refactor** — generalise receipt → contribution proof |
| L11 Civic | `core-attest/FraudControls.kt` | **Replace** — in-memory, resettable |
| L12 Settlement | `backend/settlement`, `backend/attest` | **Replace** — in-memory, unauthenticated, broken |

The load-bearing observation: **the redesign preserves the entire content stack and replaces the entire network stack.** That is a clean seam, and it is why this is a viable evolution of the repository rather than a rewrite.

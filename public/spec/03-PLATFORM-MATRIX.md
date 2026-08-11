# ShareNet — Platform Capability Matrix

**Principle:** the protocol defines what a capability *is*. This document defines what each platform *permits*. No implementation may advertise a capability its platform cannot sustain.

**Rule for implementation agents:** if you cannot cite a specific API that provides a capability, the answer is "not supported." Do not infer capability from the fact that another platform has it.

---

## 1. Master matrix

Legend: ✅ full · ⚠️ conditional · ❌ not available

| | Android | iOS/iPadOS | Windows | macOS | Linux | RPi/embedded |
|---|---|---|---|---|---|---|
| **Background execution** | ⚠️ FGS + notification | ❌ scheduler-controlled | ✅ service | ✅ daemon | ✅ systemd | ✅ systemd |
| **Virtual network iface** | ✅ `VpnService` | ⚠️ `NEPacketTunnelProvider` | ✅ WinTun | ✅ `utun`+NE | ✅ `/dev/net/tun` | ✅ |
| **Packet interception** | ✅ via TUN | ⚠️ own device only | ✅ WinTun/WFP | ✅ NE | ✅ TUN/netfilter | ✅ |
| **Packet forwarding (relay)** | ✅ userspace | ❌ | ✅ | ✅ | ✅ | ✅ |
| **Internet egress for others** | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **BLE central+peripheral** | ✅ | ⚠️ bg restricted | ⚠️ WinRT | ✅ CoreBT | ✅ BlueZ | ✅ |
| **Wi-Fi Direct / P2P** | ✅ | ❌ (MPC only) | ⚠️ Wi-Fi Direct API | ❌ (AWDL via MPC) | ⚠️ `wpa_supplicant` | ⚠️ |
| **Local TCP/UDP listen** | ✅ | ⚠️ fg only | ✅ | ✅ | ✅ | ✅ |
| **mDNS discovery** | ✅ NSD | ✅ Bonjour | ✅ | ✅ | ✅ Avahi | ✅ |
| **Internet sharing / hotspot** | ⚠️ needs user action | ❌ | ✅ ICS | ✅ | ✅ | ✅ |
| **Hardware key storage** | ✅ Keystore/StrongBox | ✅ Secure Enclave | ⚠️ TPM/CNG | ✅ Secure Enclave | ⚠️ TPM2 | ⚠️ optional |
| **App-store restrictions** | ⚠️ Play policy | ❌ severe | ✅ none | ⚠️ notarisation | ✅ none | ✅ none |
| **System privileges needed** | user consent | entitlement | admin | admin+signing | `CAP_NET_ADMIN` | root |

---

## 2. Capability profiles (normative)

```
Android          MESH_CLIENT ✅  MESH_RELAY ⚠️  INTERNET_GATEWAY ✅
                 CONTENT_SEED ✅  STORAGE ✅  DISCOVERY ✅  SYNC ✅  CUSTODY ✅
                 COMPUTE ⚠️  COMMUNITY_RELAY ❌

iOS/iPadOS       MESH_CLIENT ✅  MESH_RELAY ❌  INTERNET_GATEWAY ❌
                 CONTENT_SEED ⚠️(fg)  STORAGE ⚠️  DISCOVERY ⚠️  SYNC ⚠️
                 CUSTODY ❌  COMPUTE ⚠️  COMMUNITY_RELAY ❌

Windows/macOS    all except COMMUNITY_RELAY (⚠️ — laptops sleep)

Linux            all ✅

RPi/embedded     all ✅ — the reference COMMUNITY_RELAY platform
```

---

## 3. Android

**Modes:** A ✅ · B ✅ · C ✅ — the most capable mobile platform, and the backbone of the network.

**Background execution.** A relay or gateway requires a **foreground service** with a persistent notification (`FOREGROUND_SERVICE_DATA_SYNC` on Android 14+, plus `FOREGROUND_SERVICE_CONNECTED_DEVICE` for the mesh links). Doze and App Standby otherwise suspend the process. There is no way to run a silent background relay on modern Android, and attempting one will fail in the field even if it works on a test device.

**The current repo gets this wrong.** `ShareNetSyncWorker` uses a 15-minute `PeriodicWorkRequest` — WorkManager's floor. That is adequate for Mode A only. Modes B and C require a persistent foreground service. Worse, the worker sets `setRequiredNetworkType(NetworkType.CONNECTED)`, so sync **only runs when the device already has a network** — precisely inverting the offline-first premise. Both must change.

**Mode C via `VpnService`:**
- `Builder().addAddress()/addRoute()/addDnsServer()` → `establish()` returns a TUN fd.
- Requires a user consent dialog (`VpnService.prepare()`), shown once.
- **`VpnService` is exclusive** — ShareNet cannot coexist with any other VPN app. Must be surfaced in UX.
- `addDisallowedApplication()` allows split-tunnel; **ShareNet's own sockets must be protected with `protect(socket)`** or traffic loops back into the tunnel.
- DNS MUST be captured and resolved at the gateway.

**Gateway role:** ordinary outbound sockets, no privilege. Metered-network detection via `ConnectivityManager.isActiveNetworkMetered()` MUST gate gateway advertisement and feed `remainingQuota`.

**Transport.** `NearbyTransport` requires Play Services, excluding AOSP, GrapheneOS, and Huawei. `docs` §5 claims a "secondary Pure Offline WifiDirect stack"; **no such code exists**. A Play-free link (Wi-Fi Direct via `WifiP2pManager` + BLE GATT + TCP over local Wi-Fi) is required, not optional — community-relay operators are exactly the people running de-Googled devices.

**Permissions by API level:**
| API | Required |
|---|---|
| 26+ | `ACCESS_COARSE_LOCATION` (BLE scan) |
| 31+ | `BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` |
| 33+ | `NEARBY_WIFI_DEVICES`, `POST_NOTIFICATIONS` |
| 34+ | FGS type declarations |

**Play Store risk.** A VPN-category app with mesh networking will attract scrutiny. Prepare for review, and plan an APK/F-Droid distribution path as a hedge.

---

## 4. iOS / iPadOS

**Modes:** A ✅ · B ⚠️ (foreground) · C ⚠️ (client only)

This is the platform where honesty matters most, because the temptation to over-claim is highest.

**What works:**
- `NEPacketTunnelProvider` gives genuine Mode C **for this device's own traffic**. Apps on the phone use ShareNet transparently. Requires the Network Extension entitlement (paid developer account) and App Store review.
- `MultipeerConnectivity` provides peer discovery and transport over Bluetooth/peer-to-peer Wi-Fi (AWDL), with limited background operation.
- Mode A works fully — no special capability needed.
- Secure Enclave provides excellent key storage.

**What does not work, and must never be claimed:**

| Claim | Reality |
|---|---|
| iPhone as `INTERNET_GATEWAY` | ❌ `NEPacketTunnelProvider` is architected to send *this device's* traffic to a remote server. It is not a mechanism for accepting and egressing others' traffic. Background sockets serving other nodes will be suspended, and the design will not survive App Store review. |
| iPhone as reliable `MESH_RELAY` | ❌ No foreground-service equivalent. Background execution is scheduler-controlled and may be terminated at any time. |
| Sustained background MPC relaying | ❌ Materially restricted; unreliable for continuous forwarding. |
| Wi-Fi Direct | ❌ Not exposed. AWDL only via MultipeerConnectivity. |
| Raw BLE peripheral in background | ⚠️ Severely restricted advertisement; slow discovery. |

**Consequence, stated as a deployment fact:** an all-iOS neighbourhood is a non-functional ShareNet. iOS nodes are **consumers** of mesh connectivity. Every deployment plan must include a viable population of Android, desktop, or Raspberry Pi relay-capable nodes. This should be surfaced in the product — an iOS user in a region with no relays should be told the network is unavailable, not left wondering why nothing works.

**Graceful degradation:** iOS advertises `MESH_CLIENT` only, negotiates Mode A by default, and upgrades to Mode C when a relay/gateway is in range and the app can hold the tunnel.

---

## 5. Windows

**Modes:** A ✅ · B ✅ · C ✅

- **WinTun** (WireGuard's driver) is the recommended TUN. Requires an admin-privileged installer; the running service can then be non-admin.
- Alternative: WFP callout driver — more powerful, requires kernel driver signing. **Not recommended.**
- Windows Service for background operation; survives logoff.
- Wi-Fi Direct via `Windows.Devices.WiFiDirect` is functional but historically fragile. Prefer local TCP + mDNS on infrastructure Wi-Fi.
- Bluetooth via WinRT; BLE peripheral mode is limited.
- Windows Firewall requires an explicit inbound rule for relay listening — installer must create it.
- ICS available for gateway-adjacent scenarios.

**Recommended relay/gateway posture:** Windows service + WinTun + local TCP/mDNS. Treat Bluetooth as a bonus link, not a primary one.

---

## 6. macOS

**Modes:** A ✅ · B ✅ · C ✅

- `NEPacketTunnelProvider` (system extension) or direct `utun` with elevated privileges.
- Network Extension requires entitlement, Developer ID signing, and notarisation.
- LaunchDaemon for background; **App Nap and sleep are the practical constraint** — a laptop is a poor `COMMUNITY_RELAY`.
- `MultipeerConnectivity` and CoreBluetooth (both central and peripheral) available.
- Distribute outside the Mac App Store — MAS sandboxing makes the required entitlements impractical.

---

## 7. Linux / Raspberry Pi

**Modes:** A ✅ · B ✅ · C ✅ — the reference platform. Fewest restrictions, so **implement here first.**

- `/dev/net/tun` with `CAP_NET_ADMIN`. No app store, no review, no vendor policy.
- systemd unit; full background control, restart policy, resource limits.
- BlueZ for BLE (central and peripheral). Wi-Fi P2P via `wpa_supplicant` — workable but driver-dependent; prefer infrastructure Wi-Fi + Avahi.
- Full `iptables`/`nftables` control for gateway NAT, or userspace NAT for portability. **Prefer userspace NAT** so the same gateway code runs on Android.
- TPM2 where present; software keystore otherwise.

**Raspberry Pi is the ideal `COMMUNITY_RELAY`:** mains powered, always on, cheap, stable identity, high metric bonus. A deployment strategy should treat Pi relays as the network's skeleton and mobile nodes as the flesh.

**Recommendation: build the reference implementation on Linux.** It has no platform obstacles, so protocol bugs surface as protocol bugs rather than as platform quirks. Everything else is then a port with a known-good target.

---

## 8. Graceful degradation ladder

When a capability is unavailable, the node degrades along this ladder rather than failing:

```
Mode C transparent
   ↓ no TUN permission / VpnService denied / iOS background
Mode B proxied (app must honour proxy settings)
   ↓ no persistent connection / no background execution
Mode A delay-tolerant (works everywhere)
   ↓ no gateway reachable at all
Class A content only — cached objects, offline catalog, local apps
   ↓ no peers
Fully offline — local storage only
```

**Every level MUST be reachable and MUST be honestly labelled in the UI.** A user on Mode A must know their traffic is delayed and, if `GATEWAY_PLAINTEXT`, that a named gateway operator can read it. Silent degradation across the `PAYLOAD_E2E` → `GATEWAY_PLAINTEXT` boundary is a forbidden architectural change.

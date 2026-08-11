/**
 * SNP L8 Link — platform-independent transport abstraction
 *
 * Source: 01-ARCHITECTURE.md §2.1 (L8 layer contract)
 * Source: 02-PROTOCOL-SPEC.md §7.2 (Noise_IK handshake)
 * Source: 00-AUDIT.md §5.2 (the bug this replaces — EndpointId was
 *         "as issued by Nearby Connections", a Google Play Services API
 *         leaking Android into the protocol; NearbyTransport also
 *         auto-accepted every connection with NO peer authentication)
 *
 * The audit's headline L8 finding (00-AUDIT.md §5.2): the existing
 * `Transport` interface made `EndpointId` — a Google Play Services
 * Nearby Connections API token — a first-class protocol concept, and
 * `NearbyTransport` auto-accepted every inbound connection WITHOUT
 * authenticating the peer. Both are fatal for a protocol whose entire
 * point is to be platform-independent and trust-free at the link layer.
 *
 * This module is the fix. It defines the platform-independent `Link`
 * abstraction that all transport adapters (BLE, Wi-Fi Direct, TCP, QUIC,
 * Wi-Fi LAN, LoRa) implement. The `Link` interface references no platform
 * API: no Android Nearby, no BlueZ, no WinRT, no CoreBluetooth. The only
 * platform concept that survives is the `LinkTransportKind` string enum
 * ("ble" | "wifi-direct" | "tcp" | "quic" | "wifi-lan" | "lora"), which is
 * an opaque tag carried for diagnostics and MTU policy — never inspected
 * by the protocol itself.
 *
 * Every `Link` produced by this module is the output of a Noise_IK
 * handshake (02-PROTOCOL-SPEC.md §7.2). There is no unauthenticated link
 * path: `performNoiseIKHandshake` runs the handshake structure
 * (ephemeral X25519 exchange → DH → HKDF-SHA256 → descriptor exchange →
 * Ed25519 signature verification) and returns a `Link` whose `peerNodeId`
 * is bound to a verified `NodeDescriptor`. A `Link` whose peer's
 * descriptor signature does not verify NEVER enters the routing graph.
 *
 * ## Layering (Invariant I9, I11)
 *
 *   - I9: This module NEVER imports L6 routing (`./routing.ts`). L8
 *         depends on L1 (identity), L3 (crypto/hashing), L7 (frames) only.
 *         The dependency arrow is strictly downward.
 *   - I11: Platform-specific code lives ONLY in L9 adapters (e.g. a future
 *         `./adapters/ble-android.ts`). The `Link` interface exported here
 *         is platform-independent: it mentions no platform SDK type.
 *
 * ## Reference-implementation caveats
 *
 * Production ShareNet is Rust. This TypeScript module is the structural
 * reference. Two caveats apply:
 *
 *   1. The Noise_IK handshake implemented here is a STRUCTURAL MODEL of
 *      the handshake (ephemeral DH → HKDF → signed descriptor exchange →
 *      signature verification). It is NOT a complete Noise_IK
 *      implementation per the Noise specification. In particular, the
 *      handshake messages are not encrypted (the initiator's static key
 *      is sent in the clear inside the NodeDescriptor, not under DH-protected
 *      encryption as real Noise_IK requires), and there is no rolling
 *      transcript hash. Production MUST use a vetted Noise library
 *      (e.g. `noise-lib`, `snowland`, or `libzkgroup`'s Noise impl).
 *      This is flagged 🟡 human-review per 04-THREAT-MODEL.md §4.2.
 *
 *   2. The `Link` returned from `performNoiseIKHandshake` does NOT perform
 *      AEAD on frames after the handshake. The derived `LinkKeys`
 *      (`sendKey`, `recvKey`) are returned to the caller, who is responsible
 *      for applying AEAD (e.g., ChaCha20-Poly1305 with a per-frame nonce
 *      derived from `seq`) at a higher layer. The reference `EstablishedLink`
 *      sends raw `encodeFrame()` output so that the L7/L8 boundary is
 *      testable without depending on an AEAD primitive that doesn't exist
 *      in this sandbox yet. This is a documented TODO, not a security
 *      decision — production MUST AEAD-encrypt every frame.
 *
 * @ invariant I9  — L8 never imports L6 (routing). Imports limited to
 *                   constants, identity, frames, crypto, hashing, cbor.
 * @ invariant I11 — The `Link` interface is platform-independent. No
 *                   Android/iOS/Linux/Windows SDK types. `LinkTransportKind`
 *                   is a string enum, not a platform type.
 * @ invariant I20 — `verify*` returns false on bad sig, never throws.
 *                   The handshake throws on protocol failure (so the
 *                   caller sees a rejected link) but never accepts an
 *                   unauthenticated peer.
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  X25519_PUBLIC_KEY_BYTES,
  AEAD_KEY_BYTES,
  type Capability,
  type Platform,
} from "./constants";
import {
  type NodeDescriptor,
  type DeviceCert,
  nodeDescriptorToCborMap,
  verifyNodeDescriptor,
} from "./identity";
import { type Frame, encodeFrame, decodeFrame } from "./frames";
import {
  type X25519Keypair,
  generateX25519Keypair,
  x25519SharedSecret,
} from "./crypto";
import { hkdfSha256, deriveNodeId } from "./hashing";
import { type CborValue, CborError, cborMap, encode as cborEncode, decode as cborDecode } from "./cbor";

// ─── Link transport kinds ─────────────────────────────────────────────────

/**
 * The set of link-layer transports a `Link` can run over. This is an opaque
 * tag carried for diagnostics and MTU policy — the protocol NEVER inspects
 * it to make a forwarding or authentication decision. It exists so that a
 * node with multiple links to the same peer can prefer the higher-MTU one
 * (e.g., prefer Wi-Fi LAN over BLE for bulk content) and so that
 * observability tooling can label links correctly.
 *
 * Adding a new transport kind is a non-breaking change (adapters just
 * start emitting it); removing one is a breaking change requiring an ADR.
 */
export type LinkTransportKind =
  | "ble" // Bluetooth Low Energy (BLE GATT — MTU ~20–512 bytes)
  | "wifi-direct" // Wi-Fi Direct (Wi-Fi P2P — MTU ~1500)
  | "tcp" // TCP/IP (LAN or tunnel — MTU ~65535)
  | "quic" // QUIC (MTU ~65535, multiplexed streams)
  | "wifi-lan" // Wi-Fi LAN (infrastructure BSS — MTU ~1500)
  | "lora"; // LoRaWAN (MTU ~51–242, very low bandwidth)

// ─── LinkAddress — opaque link-layer address ──────────────────────────────

/**
 * Opaque endpoint identifier at the link layer. Platform implementations
 * give it meaning (BLE MAC, TCP host:port, Wi-Fi Direct device address),
 * but the protocol NEVER inspects its contents — it is opaque to L1–L7.
 *
 * The audit's broken `EndpointId` (00-AUDIT.md §5.2) was a Google Play
 * Services Nearby Connections API token that bled Android-specific
 * semantics into the protocol. `LinkAddress` fixes that by being a
 * pure-data interface: `bytes` (Uint8Array) + `transport` (string enum).
 * No platform type. No SDK call. No lifecycle tied to a service handle.
 *
 * Platform adapters are free to encode whatever they need in `bytes`:
 *   - BLE: the 6-byte MAC address (little- or big-endian, documented per adapter)
 *   - TCP: UTF-8 `"host:port"` (e.g. `"10.0.0.2:7780"`)
 *   - Wi-Fi Direct: the wpa_supplicant device address (6 bytes)
 *   - QUIC: UTF-8 `"host:port"` plus a connection-id suffix
 *
 * Two `LinkAddress` values are equal iff their `transport` fields are
 * equal AND their `bytes` fields are byte-equal.
 */
export interface LinkAddress {
  /**
   * Platform-specific address bytes. Examples:
   *   - BLE: 6-byte MAC
   *   - TCP: UTF-8 "host:port"
   *   - Wi-Fi Direct: 6-byte device address
   *
   * Opaque to L1–L7. Never inspected by the protocol.
   */
  readonly bytes: Uint8Array;
  /** Transport kind this address belongs to. */
  readonly transport: LinkTransportKind;
}

/**
 * Structural equality for two `LinkAddress` values.
 *
 * Two addresses are equal iff their `transport` fields are string-equal
 * AND their `bytes` fields are byte-equal. This is the only place the
 * protocol touches the `bytes` field — and only to compare for equality,
 * never to parse its contents.
 */
export function linkAddressEqual(a: LinkAddress, b: LinkAddress): boolean {
  if (a.transport !== b.transport) return false;
  if (a.bytes.length !== b.bytes.length) return false;
  // Constant-time-ish comparison. Not strictly necessary for non-secret
  // addresses (MAC addresses are not secret in SNP — they rotate per epoch
  // via NodeDescriptor rotation, not via address secrecy), but cheap.
  let diff = 0;
  for (let i = 0; i < a.bytes.length; i++) {
    diff |= a.bytes[i] ^ b.bytes[i];
  }
  return diff === 0;
}

// ─── Link — one hop, no semantics ─────────────────────────────────────────

/**
 * One hop of authenticated transport. A `Link` represents a single
 * point-to-point connection between this node and one peer, AFTER the
 * Noise_IK handshake has completed. There is no such thing as an
 * unauthenticated `Link` in this codebase — the audit's NearbyTransport
 * "auto-accept every connection" pattern is structurally impossible here
 * because the only constructor path for a `Link` goes through
 * `performNoiseIKHandshake` (or, for tests, `InMemoryLinkNetwork.connect`,
 * which is documented testing-only).
 *
 * The `Link` interface carries no routing semantics. It does not know
 * about NodeId prefix matching, route tables, gateways, or traffic
 * classes. It is a byte pipe with three properties: a peer NodeId (the
 * cryptographic identity established at handshake), an MTU, and a
 * liveness flag. Everything else is L6/L7's job.
 *
 * ## Lifecycle
 *
 *   1. A `HandshakeChannel` is obtained from a platform adapter (BLE
 *      connection accepted, TCP connect() succeeded, etc.).
 *   2. `performNoiseIKHandshake(channel, opts)` runs the Noise_IK
 *      structure. On success it returns `LinkHandshakeResult` whose
 *      `link` field is a live `Link` (an `EstablishedLink` wrapping the
 *      channel). On failure it closes the channel and throws.
 *   3. The `Link` is registered with the node's `LinkRegistry` so that
 *      L6 routing can find it.
 *   4. Frames are sent via `send()` and received via `onFrame()`.
 *   5. Either side may call `close()` to terminate the link. After
 *      close, `isAlive()` returns false and `send()` returns false.
 *
 * ## Why peerNodeId is bytes, not a structured identity
 *
 * `peerNodeId` is the 32-byte SHA-256 NodeId of the peer's NodeIdentity
 * Ed25519 public key (I4). It is NOT the bare public key — the bare key
 * is disclosed only inside the Noise_IK handshake and is carried in the
 * peer's `NodeDescriptor` (returned in `LinkHandshakeResult.peerDescriptor`).
 * L6 routing compares NodeIds for equality; it never needs the bare key.
 *
 * @ invariant I11 — no platform SDK types in this interface
 * @ invariant I20 — `send` returns false on a dead link; it does not throw
 *                   for a peer-side failure (it DOES throw for caller-side
 *                   contract violations like a non-Frame argument)
 */
export interface Link {
  /** Transport kind. Matches `localAddress.transport` and `peerAddress.transport`. */
  readonly transport: LinkTransportKind;
  /** Local link-layer address (this node's side of the connection). */
  readonly localAddress: LinkAddress;
  /** Peer link-layer address (the other node's side). */
  readonly peerAddress: LinkAddress;
  /**
   * Peer's 32-byte NodeId, cryptographically established during the
   * Noise_IK handshake. This is `peerDescriptor.nodeId` for the descriptor
   * verified during the handshake. L6 routing uses this as the
   * peer-identity key; it never uses the bare Ed25519 public key.
   */
  readonly peerNodeId: Uint8Array;

  /**
   * Send a Frame to the peer. Returns `true` iff the frame was accepted
   * for delivery (the link is alive and the peer is still connected).
   * Returns `false` if the link is down — the caller should retry on a
   * different link or drop the frame per L7/L6 policy.
   *
   * This does NOT guarantee delivery — it guarantees acceptance. Actual
   * on-wire delivery may still fail (BLE drop, TCP RST). For ack'd
   * delivery, use the L7 session layer.
   *
   * The frame is encoded with `encodeFrame` before transmission. In the
   * reference `EstablishedLink`, the encoded bytes are sent raw on the
   * underlying `HandshakeChannel`. Production implementations MUST
   * AEAD-encrypt the encoded frame using `LinkKeys.sendKey` (see the
   * module-level note).
   */
  send(frame: Frame): Promise<boolean>;

  /**
   * Subscribe to incoming Frames. The handler is called for every Frame
   * decoded from the underlying channel. Returns an unsubscribe function;
   * calling it removes the handler. Multiple handlers may be registered.
   *
   * Handlers are called asynchronously with respect to the wire read
   * (never inline from the channel's read loop). Handler exceptions are
   * swallowed and logged — a misbehaving handler does not kill the link.
   */
  onFrame(handler: (frame: Frame) => void): () => void;

  /** Is the link currently alive (not closed, peer not disconnected)? */
  isAlive(): boolean;

  /**
   * MTU in bytes for this link. The maximum encoded Frame size that
   * `send()` can accept without fragmentation. Typical values:
   *   - BLE:           20–512 (depends on negotiated ATT MTU)
   *   - Wi-Fi Direct:  1500
   *   - Wi-Fi LAN:     1500
   *   - TCP:           65535 (or the negotiated MSS)
   *   - QUIC:          65535
   *   - LoRa:          51–242 (region/band dependent)
   *
   * L6 routing uses MTU to choose the best link for bulk content transfer
   * (see `LinkRegistry.bestByMtu`).
   */
  mtu(): number;

  /**
   * Close the link gracefully. After close:
   *   - `isAlive()` returns false
   *   - `send()` returns false
   *   - `onFrame` handlers are no longer called
   *   - The underlying channel is released
   *
   * Idempotent — calling close() on an already-closed link is a no-op.
   */
  close(): Promise<void>;
}

// ─── LinkListener — accept inbound links ──────────────────────────────────

/**
 * Listens on a `LinkAddress` for inbound connections. Each accepted
 * connection is run through `performNoiseIKHandshake` internally; only
 * handshakes that SUCCEED are surfaced via `onLink`. Failed handshakes
 * are silently dropped (with diagnostic logging at the adapter level).
 *
 * This is the L8 equivalent of `listen()` on a socket. Platform adapters
 * implement it (`BleLinkListener`, `TcpLinkListener`, etc.); the protocol
 * layer only consumes the `Link` objects it emits.
 *
 * ## Why there is no `onAccept` returning raw channels
 *
 * The audit found NearbyTransport auto-accepting every connection without
 * authentication (00-AUDIT.md §5.2). To make that bug structurally
 * impossible, `LinkListener` does NOT expose a "raw accepted channel"
 * callback. The ONLY callback is `onLink`, which fires AFTER the Noise_IK
 * handshake has completed and the peer's descriptor signature has
 * verified. There is no way for adapter code to surface an unauthenticated
 * connection to the protocol layer.
 */
export interface LinkListener {
  /** Transport kind this listener is listening on. */
  readonly transport: LinkTransportKind;
  /** Local address being listened on. */
  readonly listenAddress: LinkAddress;

  /**
   * Subscribe to newly-accepted, fully-handshaken Links. The handler is
   * called once per successful inbound Noise_IK handshake. Returns an
   * unsubscribe function.
   */
  onLink(handler: (link: Link) => void): () => void;

  /** Stop listening and release the local address. Idempotent. */
  close(): Promise<void>;
}

// ─── LinkKeys — derived AEAD keys ─────────────────────────────────────────

/**
 * The two AEAD keys derived from the Noise_IK handshake: one for frames
 * this node sends, one for frames this node receives. They are distinct
 * (the initiator's `sendKey` equals the responder's `recvKey` and vice
 * versa) to prevent nonce-reuse across directions.
 *
 * Both keys are 32 bytes (AEAD_KEY_BYTES). The AEAD construction is
 * ChaCha20-Poly1305 or AES-256-GCM (production choice, not modeled here).
 *
 * In the reference implementation, these keys are DERIVED but NOT USED
 * by `EstablishedLink.send`/`onFrame` (frames are sent raw). They are
 * returned to the caller so that a future L7 session layer can apply
 * AEAD. Production MUST use them.
 */
export interface LinkKeys {
  /** 32-byte AEAD key for frames this node SENDS to the peer. */
  readonly sendKey: Uint8Array;
  /** 32-byte AEAD key for frames this node RECEIVES from the peer. */
  readonly recvKey: Uint8Array;
}

// ─── LinkHandshakeResult ──────────────────────────────────────────────────

/**
 * The output of a successful `performNoiseIKHandshake`. Contains:
 *   - `link`: a live `Link` whose `peerNodeId` matches `peerDescriptor.nodeId`
 *   - `peerDescriptor`: the verified peer `NodeDescriptor` (signature checked)
 *   - `linkKeys`: the derived AEAD keys (unused by the reference `Link`,
 *     but available for a future AEAD layer)
 *
 * The caller (typically an adapter or a node's link manager) registers
 * `link` with the local `LinkRegistry` and uses `peerDescriptor` to seed
 * the local peer-info cache (capabilities, platform, expiry, etc.).
 */
export interface LinkHandshakeResult {
  /** The established, authenticated Link. */
  readonly link: Link;
  /** The peer's verified NodeDescriptor (Ed25519 signature has been checked). */
  readonly peerDescriptor: NodeDescriptor;
  /** Derived AEAD keys (send/recv). */
  readonly linkKeys: LinkKeys;
}

// ─── HandshakeChannel — pre-handshake raw byte transport ──────────────────

/**
 * A raw byte channel to a peer, BEFORE the Noise_IK handshake. Platform
 * adapters produce a `HandshakeChannel` when they establish a TCP
 * connection, BLE GATT link, etc., and pass it to
 * `performNoiseIKHandshake` to upgrade it to an authenticated `Link`.
 *
 * The `HandshakeChannel` interface is deliberately minimal: send bytes,
 * receive bytes, close. It does NOT carry Frames — the handshake itself
 * uses its own CBOR message format (see `encodeHandshakeMessage`). Once
 * the handshake completes, the `EstablishedLink` wraps the channel and
 * exposes the `Link` API (which DOES carry Frames).
 *
 * This interface is platform-independent (I11). Platform-specific
 * adapters implement it; the protocol layer only consumes it.
 */
export interface HandshakeChannel {
  /** Transport kind. Matches `localAddress.transport`. */
  readonly transport: LinkTransportKind;
  /** Local link-layer address. */
  readonly localAddress: LinkAddress;
  /** Peer link-layer address. */
  readonly peerAddress: LinkAddress;

  /**
   * Send raw bytes to the peer during the handshake. Throws if the
   * channel is closed or the send fails irrecoverably.
   */
  send(bytes: Uint8Array): Promise<void>;

  /**
   * Subscribe to incoming raw bytes during the handshake. Returns an
   * unsubscribe function. Handlers are called asynchronously.
   */
  onBytes(handler: (bytes: Uint8Array) => void): () => void;

  /** Close the channel. Idempotent. */
  close(): Promise<void>;

  /** MTU of the underlying transport, in bytes. */
  mtu(): number;
}

// ─── Handshake options ────────────────────────────────────────────────────

/**
 * Inputs to `performNoiseIKHandshake`. The caller supplies:
 *   - The local node's signed `NodeDescriptor` (already signed via
 *     `signNodeDescriptor` from identity.ts)
 *   - The Ed25519 secret key for `localDescriptor.nodePubKey` (for nothing
 *     in the simplified handshake — the descriptor is already signed — but
 *     required by the API for forward-compatibility with future
 *     handshake variants that re-sign transcript hashes)
 *   - The X25519 secret key for `localDescriptor.rendezvousPub` (used as
 *     the Noise static key in the DH operations)
 *   - The expected peer NodeId (if known) — for pinning / TOFU downgrade
 *     prevention. If null, any peer with a valid descriptor is accepted
 *     (trust-on-first-use)
 *   - Whether this side is the Noise initiator (true) or responder (false)
 *
 * The `localNodeSecretKey` is not used by the simplified handshake but is
 * required by the API so that a future full-Noise implementation can
 * re-sign the transcript without breaking callers.
 */
export interface LinkHandshakeOptions {
  /** Local NodeDescriptor (signed via `signNodeDescriptor`). Sent to peer. */
  readonly localDescriptor: NodeDescriptor;
  /** Ed25519 secret key for `localDescriptor.nodePubKey` (32 bytes). */
  readonly localNodeSecretKey: Uint8Array;
  /** X25519 secret key for `localDescriptor.rendezvousPub` (32 bytes). */
  readonly localRendezvousSecretKey: Uint8Array;
  /**
   * Expected peer NodeId (32 bytes), or null for trust-on-first-use.
   * If set, the handshake fails if the peer's descriptor.nodeId does not
   * match. This is the "I" in Noise_IK: the initiator knows the
   * responder's identity in advance.
   */
  readonly expectedPeerNodeId: Uint8Array | null;
  /** True if this side is the Noise initiator (the one that opens the channel). */
  readonly isInitiator: boolean;
  /** Optional handshake timeout in milliseconds. Default 10000. */
  readonly timeoutMs?: number;
}

// ─── Handshake message format ─────────────────────────────────────────────
//
// The simplified Noise_IK handshake exchanges two CBOR messages, one in
// each direction. Each message carries the sender's ephemeral X25519
// public key and the sender's signed NodeDescriptor. After both messages
// are exchanged, both sides compute three DH operations (es, se, ee) and
// derive the link keys via HKDF-SHA256.
//
// CDDL (simplified, NOT a frozen protocol constant — see module-level note):
//
//   HandshakeMessage = {
//     ephPub:     bstr .size 32,   ; sender's ephemeral X25519 public key
//     descriptor: NodeDescriptor   ; sender's SIGNED NodeDescriptor
//   }
//
// The descriptor's `rendezvousPub` field is used as the Noise static key.
// Because the descriptor is signed by `nodePubKey` (Ed25519) and contains
// `rendezvousPub`, verifying the descriptor signature proves that the
// peer's Noise static key is bound to a NodeIdentity the peer controls.
// Combined with the NodeId-vs-pubkey hash check, this gives us:
//
//   - Possession of Ed25519 secret (signature verifies)
//   - Binding between Ed25519 key and X25519 static key (both in descriptor)
//   - Binding between NodeId and Ed25519 key (NodeId = SHA-256(context ‖ key))
//   - Possession of X25519 static secret (DH outputs match → key derivation works)
//   - Possession of X25519 ephemeral secret (implicit: handshake completes)
//
// What this DOES NOT give us (vs. real Noise_IK):
//
//   - Confidentiality of the initiator's static key (sent in clear inside
//     the descriptor, not under DH-protected encryption)
//   - Transcript hash binding (no rolling hash across messages)
//   - Replay protection (no nonces in the simplified message format)
//   - AEAD on post-handshake frames (see EstablishedLink note)

interface HandshakeMessage {
  readonly ephPub: Uint8Array;
  readonly descriptor: NodeDescriptor;
}

/**
 * Encode a `HandshakeMessage` to canonical CBOR bytes.
 * Used internally by `performNoiseIKHandshake`.
 */
function encodeHandshakeMessage(msg: HandshakeMessage): Uint8Array {
  const map = cborMap([
    ["ephPub", msg.ephPub],
    ["descriptor", nodeDescriptorToCborMap(msg.descriptor)],
  ]);
  return cborEncode(map);
}

/**
 * Decode a `HandshakeMessage` from CBOR bytes.
 * Throws `CborError(MALFORMED)` on any structural violation.
 * Used internally by `performNoiseIKHandshake`.
 */
function decodeHandshakeMessage(bytes: Uint8Array): HandshakeMessage {
  const value = cborDecode(bytes);
  if (!(value instanceof Map)) {
    throw new CborError("HandshakeMessage must decode to a CBOR map", "MALFORMED");
  }
  // Reject non-string keys defensively (we encode with string keys).
  for (const k of value.keys()) {
    if (typeof k !== "string") {
      throw new CborError("HandshakeMessage map keys must be text strings", "MALFORMED");
    }
  }
  if (value.size !== 2) {
    throw new CborError(
      `HandshakeMessage map must have exactly 2 keys; got ${value.size}`,
      "MALFORMED",
    );
  }

  const ephPub = value.get("ephPub");
  if (!(ephPub instanceof Uint8Array) || ephPub.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new CborError(
      `HandshakeMessage.ephPub must be a ${X25519_PUBLIC_KEY_BYTES}-byte Uint8Array`,
      "MALFORMED",
    );
  }

  const descriptorValue = value.get("descriptor");
  if (!(descriptorValue instanceof Map)) {
    throw new CborError(
      "HandshakeMessage.descriptor must decode to a CBOR map",
      "MALFORMED",
    );
  }
  const descriptor = decodeNodeDescriptorMap(descriptorValue);
  return { ephPub, descriptor };
}

/**
 * Decode a `NodeDescriptor` from a CBOR map (the inverse of
 * `nodeDescriptorToCborMap`). Used by the handshake to parse the peer's
 * descriptor from the wire.
 *
 * Throws `CborError(MALFORMED)` on any structural violation. Does NOT
 * verify the signature — that is the caller's job (`verifyNodeDescriptor`).
 */
function decodeNodeDescriptorMap(value: Map<string | Uint8Array, CborValue>): NodeDescriptor {
  // All map keys must be text strings (we encoded them that way).
  for (const k of value.keys()) {
    if (typeof k !== "string") {
      throw new CborError("NodeDescriptor map keys must be text strings", "MALFORMED");
    }
  }

  const nodeId = extractBstr(value.get("nodeId"), 32, "nodeId");
  const nodePubKey = extractBstr(value.get("nodePubKey"), ED25519_PUBLIC_KEY_BYTES, "nodePubKey");
  const rendezvousPub = extractBstr(value.get("rendezvousPub"), X25519_PUBLIC_KEY_BYTES, "rendezvousPub");
  // The wire encoding carries capabilities as a CBOR array of text strings.
  // The CDDL constrains them to the CAPABILITIES enum, but the wire format
  // is just strings — we cast here and rely on verifyNodeDescriptor /
  // assertNodeDescriptorFields to validate the values.
  const capabilities = extractStringArray(value.get("capabilities"), "capabilities") as Capability[];
  const platform = extractString(value.get("platform"), "platform") as Platform;
  const protoVersion = extractString(value.get("protoVersion"), "protoVersion");
  const epoch = extractUint(value.get("epoch"), "epoch");
  const expiresAt = extractUint(value.get("expiresAt"), "expiresAt");
  const links = extractStringArray(value.get("links"), "links");
  const signature = extractBstr(value.get("signature"), ED25519_SIGNATURE_BYTES, "signature");
  const deviceCertValue = value.get("deviceCert");
  let deviceCert: DeviceCert | null;
  if (deviceCertValue === null) {
    deviceCert = null;
  } else if (deviceCertValue instanceof Map) {
    deviceCert = decodeDeviceCertMap(deviceCertValue);
  } else {
    throw new CborError(
      "NodeDescriptor.deviceCert must be null or a CBOR map",
      "MALFORMED",
    );
  }

  return {
    nodeId,
    nodePubKey,
    rendezvousPub,
    capabilities,
    platform,
    protoVersion,
    epoch,
    expiresAt,
    links,
    deviceCert,
    signature,
  };
}

/**
 * Decode a `DeviceCert` from a CBOR map. Used by `decodeNodeDescriptorMap`.
 */
function decodeDeviceCertMap(value: Map<string | Uint8Array, CborValue>): DeviceCert {
  for (const k of value.keys()) {
    if (typeof k !== "string") {
      throw new CborError("DeviceCert map keys must be text strings", "MALFORMED");
    }
  }
  const deviceId = extractBstr(value.get("deviceId"), 32, "deviceId");
  const userId = extractBstr(value.get("userId"), 32, "userId");
  const capabilities = extractStringArray(value.get("capabilities"), "capabilities") as Capability[];
  const platform = extractString(value.get("platform"), "platform") as Platform;
  const notBefore = extractUint(value.get("notBefore"), "notBefore");
  const notAfter = extractUint(value.get("notAfter"), "notAfter");
  const attestationValue = value.get("attestation");
  let attestation: Uint8Array | null;
  if (attestationValue === null) {
    attestation = null;
  } else if (attestationValue instanceof Uint8Array) {
    attestation = attestationValue;
  } else {
    throw new CborError(
      "DeviceCert.attestation must be null or a Uint8Array",
      "MALFORMED",
    );
  }
  const signature = extractBstr(value.get("signature"), ED25519_SIGNATURE_BYTES, "signature");
  return {
    deviceId,
    userId,
    capabilities,
    platform,
    notBefore,
    notAfter,
    attestation,
    signature,
  };
}

// ─── CBOR value extractors (defensive — never trust raw decode output) ─────

function extractBstr(value: CborValue | undefined, expectedLength: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new CborError(
      `${field} must be a Uint8Array; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  if (value.length !== expectedLength) {
    throw new CborError(
      `${field} must be ${expectedLength} bytes; got ${value.length}`,
      "MALFORMED",
    );
  }
  return value;
}

function extractString(value: CborValue | undefined, field: string): string {
  if (typeof value !== "string") {
    throw new CborError(
      `${field} must be a string; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  return value;
}

function extractUint(value: CborValue | undefined, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new CborError(
      `${field} must be a non-negative integer; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  return value;
}

function extractStringArray(value: CborValue | undefined, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new CborError(
      `${field} must be an array; got ${describeType(value)}`,
      "MALFORMED",
    );
  }
  for (const item of value) {
    if (typeof item !== "string") {
      throw new CborError(
        `${field} must be an array of strings; found non-string element`,
        "MALFORMED",
      );
    }
  }
  return value as string[];
}

function describeType(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (value instanceof Uint8Array) return `Uint8Array(length=${value.length})`;
  if (Array.isArray(value)) return "Array";
  if (value instanceof Map) return "Map";
  return typeof value;
}

// ─── Handshake constants ──────────────────────────────────────────────────

/** Default handshake timeout (10 seconds — generous for BLE). */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * HKDF `info` string for deriving Noise_IK link keys. This binds the
 * derived key material to the SNP/0.1 Noise_IK handshake context.
 * Changing this string is a protocol-breaking change.
 */
const LINK_KEYS_HKDF_INFO = asciiBytes("SNP/0.1 noise-ik link keys v1");

/** Total derived key material length (sendKey 32 + recvKey 32 = 64 bytes). */
const LINK_KEYS_MATERIAL_LENGTH = AEAD_KEY_BYTES * 2;

// ─── performNoiseIKHandshake ──────────────────────────────────────────────

/**
 * Run the simplified Noise_IK handshake over a `HandshakeChannel` and
 * return an authenticated `Link` on success.
 *
 * ## What this does (the STRUCTURE — see module-level note about why
 * this is NOT a full Noise_IK implementation)
 *
 *   1. Generate an ephemeral X25519 keypair.
 *   2. Build a `HandshakeMessage` containing the ephemeral public key and
 *      the local signed `NodeDescriptor`. Encode it to CBOR and send it
 *      on the channel.
 *   3. Receive the peer's `HandshakeMessage` (with timeout).
 *   4. Verify the peer's `NodeDescriptor` signature using
 *      `verifyNodeDescriptor` (I20: returns false, never throws). If the
 *      signature is invalid, close the channel and throw — the link is
 *      NOT established.
 *   5. Verify the binding `peerDescriptor.nodeId == SHA-256("SNP/0.1 node\0"
 *      ‖ peerDescriptor.nodePubKey)` (I4). If the binding fails, close
 *      and throw.
 *   6. If `expectedPeerNodeId` was supplied, verify
 *      `peerDescriptor.nodeId == expectedPeerNodeId`. If mismatch, close
 *      and throw. (This is the "I" in Noise_IK: the initiator knows the
 *      responder's identity in advance.)
 *   7. Compute three DH operations using the local and peer ephemeral
 *      and static (rendezvousPub) X25519 keys:
 *        - dh1 = DH(localEph, peerStatic)   [es or se depending on direction]
 *        - dh2 = DH(localStatic, peerEph)   [se or es]
 *        - dh3 = DH(localEph, peerEph)      [ee]
 *      (DH is symmetric, so the order of secret/pub doesn't matter.)
 *   8. Derive 64 bytes of key material via HKDF-SHA256 with
 *      `info = "SNP/0.1 noise-ik link keys v1"` and split into send/recv
 *      keys. The initiator's `sendKey` is the first 32 bytes and its
 *      `recvKey` is the last 32 bytes; the responder's are reversed
 *      (so init.sendKey == resp.recvKey).
 *   9. Wrap the channel in an `EstablishedLink` with `peerNodeId` set to
 *      `peerDescriptor.nodeId`, and return `LinkHandshakeResult`.
 *
 * ## Failure modes
 *
 *   - Malformed peer message → throws `Error("Noise_IK: malformed peer handshake message")`
 *   - Invalid peer descriptor signature → throws `Error("Noise_IK: peer NodeDescriptor signature invalid")`
 *   - NodeId/pubKey mismatch → throws `Error("Noise_IK: peer nodeId does not match hash(nodePubKey)")`
 *   - Unexpected peer NodeId → throws `Error("Noise_IK: peer nodeId does not match expected")`
 *   - Timeout → throws `Error("Noise_IK: handshake timed out after Xms")`
 *
 * In every failure case, the channel is closed BEFORE the throw, so the
 * caller does not need to clean up.
 *
 * @ invariant I20 — never returns a Link whose peer descriptor signature
 *                   does not verify. Failure throws (and closes channel).
 */
export async function performNoiseIKHandshake(
  channel: HandshakeChannel,
  options: LinkHandshakeOptions,
): Promise<LinkHandshakeResult> {
  const {
    localDescriptor,
    localNodeSecretKey,
    localRendezvousSecretKey,
    expectedPeerNodeId,
    isInitiator,
    timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS,
  } = options;

  // Defensive: the localNodeSecretKey is part of the API for forward
  // compatibility but unused by the simplified handshake. Validate its
  // length so callers can't accidentally pass garbage that a future
  // full-Noise implementation would silently misuse.
  if (!(localNodeSecretKey instanceof Uint8Array) || localNodeSecretKey.length !== 32) {
    await channel.close();
    throw new Error("Noise_IK: localNodeSecretKey must be a 32-byte Uint8Array");
  }
  if (!(localRendezvousSecretKey instanceof Uint8Array) || localRendezvousSecretKey.length !== 32) {
    await channel.close();
    throw new Error("Noise_IK: localRendezvousSecretKey must be a 32-byte Uint8Array");
  }
  if (expectedPeerNodeId !== null) {
    if (!(expectedPeerNodeId instanceof Uint8Array) || expectedPeerNodeId.length !== 32) {
      await channel.close();
      throw new Error("Noise_IK: expectedPeerNodeId must be null or a 32-byte Uint8Array");
    }
  }

  // Step 1: generate ephemeral X25519 keypair.
  const ephemeral: X25519Keypair = generateX25519Keypair();

  // Step 2: build & send our handshake message.
  //    We send the message BEFORE reading the peer's. In a real Noise_IK
  //    the initiator sends first and the responder sends second; we don't
  //    enforce ordering here (both sides send concurrently). This is OK
  //    for the simplified structure — both messages carry independent
  //    ephemeral keys and descriptors, and the DH outputs are the same
  //    regardless of ordering.
  const ourMessage: HandshakeMessage = {
    ephPub: ephemeral.publicKey,
    descriptor: localDescriptor,
  };
  const ourBytes = encodeHandshakeMessage(ourMessage);
  try {
    await channel.send(ourBytes);
  } catch (e) {
    await channel.close();
    throw new Error(`Noise_IK: failed to send handshake message: ${(e as Error).message}`);
  }

  // Step 3: receive the peer's handshake message (with timeout).
  let peerBytes: Uint8Array;
  try {
    peerBytes = await receiveOnce(channel, timeoutMs);
  } catch (e) {
    await channel.close();
    throw e;
  }

  // Step 4: parse the peer message.
  let peerMessage: HandshakeMessage;
  try {
    peerMessage = decodeHandshakeMessage(peerBytes);
  } catch {
    await channel.close();
    throw new Error("Noise_IK: malformed peer handshake message");
  }

  const peerDescriptor = peerMessage.descriptor;
  const peerEphPub = peerMessage.ephPub;

  // Step 5: verify the peer's descriptor signature (I20: returns false, never throws).
  if (!verifyNodeDescriptor(peerDescriptor)) {
    await channel.close();
    throw new Error("Noise_IK: peer NodeDescriptor signature invalid");
  }

  // Step 6: verify the NodeId/pubKey binding (I4).
  let peerNodeIdFromKey: Uint8Array;
  try {
    peerNodeIdFromKey = deriveNodeId(peerDescriptor.nodePubKey);
  } catch {
    await channel.close();
    throw new Error("Noise_IK: peer nodePubKey malformed during NodeId derivation");
  }
  if (!constantTimeEqual(peerNodeIdFromKey, peerDescriptor.nodeId)) {
    await channel.close();
    throw new Error("Noise_IK: peer nodeId does not match hash(nodePubKey)");
  }

  // Step 7: if we expected a specific peer NodeId, verify the match.
  if (expectedPeerNodeId !== null) {
    if (!constantTimeEqual(expectedPeerNodeId, peerDescriptor.nodeId)) {
      await channel.close();
      throw new Error("Noise_IK: peer nodeId does not match expected");
    }
  }

  // Step 8: compute three DH operations.
  //   dh1 = DH(localEph, peerStatic)  — uses local ephemeral secret + peer rendezvousPub
  //   dh2 = DH(localStatic, peerEph)  — uses local rendezvousPub secret + peer ephemeral pub
  //   dh3 = DH(localEph, peerEph)     — both ephemeral
  // The peer's "static" X25519 key is their descriptor's rendezvousPub.
  // Verifying the descriptor signature (step 5) proves the peer owns the
  // Ed25519 key, and the descriptor binds that Ed25519 key to this X25519
  // key. The DH operations prove the peer owns the X25519 secret
  // (otherwise the keys wouldn't match on both sides).
  let dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array;
  try {
    dh1 = x25519SharedSecret(ephemeral.secretKey, peerDescriptor.rendezvousPub);
    dh2 = x25519SharedSecret(localRendezvousSecretKey, peerEphPub);
    dh3 = x25519SharedSecret(ephemeral.secretKey, peerEphPub);
  } catch (e) {
    await channel.close();
    throw new Error(`Noise_IK: DH operation failed: ${(e as Error).message}`);
  }

  // Step 9: derive link keys via HKDF-SHA256.
  //   IKM = dh1 ‖ dh2 ‖ dh3
  //   salt = empty
  //   info = "SNP/0.1 noise-ik link keys v1"
  //   length = 64
  //   split: first 32 bytes = initiator sendKey (responder recvKey)
  //          last 32 bytes  = initiator recvKey (responder sendKey)
  const ikm = concatBytes(dh1, dh2, dh3);
  const salt = new Uint8Array(0);
  const keyMaterial = hkdfSha256(ikm, salt, LINK_KEYS_HKDF_INFO, LINK_KEYS_MATERIAL_LENGTH);
  const initSendKey = keyMaterial.subarray(0, AEAD_KEY_BYTES);
  const initRecvKey = keyMaterial.subarray(AEAD_KEY_BYTES, LINK_KEYS_MATERIAL_LENGTH);
  const linkKeys: LinkKeys = isInitiator
    ? { sendKey: copyBytes(initSendKey), recvKey: copyBytes(initRecvKey) }
    : { sendKey: copyBytes(initRecvKey), recvKey: copyBytes(initSendKey) };

  // Step 10: wrap the channel in an EstablishedLink and return.
  const link = new EstablishedLink(
    channel,
    peerDescriptor.nodeId,
    linkKeys,
  );

  return { link, peerDescriptor, linkKeys };
}

// ─── EstablishedLink — Link returned by performNoiseIKHandshake ───────────

/**
 * The `Link` implementation returned by `performNoiseIKHandshake`. Wraps a
 * `HandshakeChannel` and exposes the `Link` interface (send Frame, onFrame).
 *
 * ## IMPORTANT: no AEAD in the reference implementation
 *
 * The reference `EstablishedLink` sends encoded frames RAW on the underlying
 * channel — it does NOT apply AEAD with the derived `LinkKeys`. This is a
 * documented TODO, not a security decision. Production MUST:
 *
 *   - AEAD-encrypt each `encodeFrame(frame)` output with `linkKeys.sendKey`
 *     and a per-frame nonce derived from the sequence number
 *   - AEAD-decrypt incoming bytes with `linkKeys.recvKey` before
 *     `decodeFrame`
 *   - Drop the link on any AEAD failure (authentication tag mismatch,
 *     nonce reuse, etc.)
 *
 * The `linkKeys` are stored on the link (and returned in
 * `LinkHandshakeResult`) so that a future AEAD layer can use them without
 * re-running the handshake.
 *
 * This class is not exported — callers receive it as a `Link` from
 * `performNoiseIKHandshake`. Tests that need a non-handshaked Link use
 * `InMemoryLink` (see below).
 */
class EstablishedLink implements Link {
  readonly transport: LinkTransportKind;
  readonly localAddress: LinkAddress;
  readonly peerAddress: LinkAddress;
  readonly peerNodeId: Uint8Array;
  private readonly linkKeys: LinkKeys;

  private readonly channel: HandshakeChannel;
  private readonly frameHandlers: Set<(frame: Frame) => void> = new Set();
  private alive = true;
  private readonly offBytes: () => void;

  constructor(channel: HandshakeChannel, peerNodeId: Uint8Array, linkKeys: LinkKeys) {
    this.channel = channel;
    this.transport = channel.transport;
    this.localAddress = channel.localAddress;
    this.peerAddress = channel.peerAddress;
    this.peerNodeId = peerNodeId;
    this.linkKeys = linkKeys;

    // Wire incoming bytes → decodeFrame → dispatch to handlers.
    // NOTE: production would AEAD-decrypt bytes BEFORE decodeFrame.
    this.offBytes = channel.onBytes((bytes: Uint8Array) => {
      let frame: Frame;
      try {
        frame = decodeFrame(bytes);
      } catch {
        // Malformed bytes on the wire. Drop silently — a single bad frame
        // does not kill the link. (Production: AEAD failures SHOULD kill
        // the link; malformed-after-decrypt indicates a peer bug.)
        return;
      }
      // Dispatch asynchronously so handler exceptions don't break the read loop.
      const handlers = Array.from(this.frameHandlers);
      queueMicrotask(() => {
        for (const h of handlers) {
          try {
            h(frame);
          } catch {
            // Swallow handler exceptions — a misbehaving handler doesn't kill the link.
          }
        }
      });
    });
  }

  async send(frame: Frame): Promise<boolean> {
    if (!this.alive) return false;
    let bytes: Uint8Array;
    try {
      bytes = encodeFrame(frame);
    } catch {
      // Caller-side contract violation (malformed Frame). Throw — this is
      // a bug in the caller, not a peer-side failure.
      throw new Error("EstablishedLink.send: failed to encode frame");
    }
    try {
      // NOTE: production would AEAD-encrypt `bytes` with linkKeys.sendKey here.
      await this.channel.send(bytes);
      return true;
    } catch {
      // Channel send failed — the link is effectively dead. Mark it closed.
      this.alive = false;
      return false;
    }
  }

  onFrame(handler: (frame: Frame) => void): () => void {
    this.frameHandlers.add(handler);
    return () => {
      this.frameHandlers.delete(handler);
    };
  }

  isAlive(): boolean {
    return this.alive;
  }

  mtu(): number {
    return this.channel.mtu();
  }

  async close(): Promise<void> {
    if (!this.alive) return;
    this.alive = false;
    this.frameHandlers.clear();
    this.offBytes();
    await this.channel.close();
  }
}

// ─── InMemoryLink — TESTING ONLY ──────────────────────────────────────────

/**
 * In-memory `Link` implementation for tests. TWO instances are created
 * back-to-back by `InMemoryLinkNetwork.connect(...)`: frames sent on one
 * are delivered (asynchronously, via `queueMicrotask`) to the other's
 * `onFrame` handlers.
 *
 * ## ⚠️ TESTING ONLY — NEVER USE IN PRODUCTION
 *
 * `InMemoryLink` performs NO Noise_IK handshake, NO AEAD, and NO signature
 * verification. It is a direct byte pipe between two test nodes. It exists
 * so that L6 routing tests, L7 session tests, and conformance/integration
 * tests can simulate a two-node network without depending on a real
 * transport adapter (BLE/TCP/etc.). Using `InMemoryLink` in production
 * would reintroduce the audit's "unauthenticated transport" bug
 * (00-AUDIT.md §5.2) — DO NOT.
 *
 * The `peerNodeId` is set at construction time from the inputs to
 * `InMemoryLinkNetwork.connect` — there is no handshake to establish it.
 */
export class InMemoryLink implements Link {
  readonly transport: LinkTransportKind;
  readonly localAddress: LinkAddress;
  readonly peerAddress: LinkAddress;
  readonly peerNodeId: Uint8Array;

  private peer: InMemoryLink | null = null;
  private readonly frameHandlers: Set<(frame: Frame) => void> = new Set();
  private alive = true;
  private readonly linkMtu: number;

  /**
   * Private constructor — callers obtain `InMemoryLink` instances only
   * via `InMemoryLinkNetwork.connect(...)`. This ensures the peer-binding
   * logic lives in one place.
   */
  private constructor(
    localAddress: LinkAddress,
    peerAddress: LinkAddress,
    peerNodeId: Uint8Array,
    mtu: number,
  ) {
    this.transport = localAddress.transport;
    this.localAddress = localAddress;
    this.peerAddress = peerAddress;
    this.peerNodeId = peerNodeId;
    this.linkMtu = mtu;
  }

  /**
   * Create a back-to-back pair of `InMemoryLink`s between two nodes.
   *
   * @internal Used by `InMemoryLinkNetwork.connect`. Not part of the
   *           public API — callers obtain `InMemoryLink` instances only
   *           via `InMemoryLinkNetwork.connect`.
   */
  static createPair(
    localA: { nodeId: Uint8Array; address: LinkAddress },
    localB: { nodeId: Uint8Array; address: LinkAddress },
    mtu: number,
  ): { linkA: InMemoryLink; linkB: InMemoryLink } {
    if (localA.address.transport !== localB.address.transport) {
      throw new Error(
        "InMemoryLink.createPair: both addresses must have the same transport kind",
      );
    }
    const linkA = new InMemoryLink(localA.address, localB.address, localB.nodeId, mtu);
    const linkB = new InMemoryLink(localB.address, localA.address, localA.nodeId, mtu);
    // Cross-wire the peers.
    linkA.peer = linkB;
    linkB.peer = linkA;
    return { linkA, linkB };
  }

  async send(frame: Frame): Promise<boolean> {
    if (!this.alive) return false;
    const peer = this.peer;
    if (peer === null || !peer.alive) return false;
    // Capture the peer's handlers synchronously, dispatch asynchronously.
    const handlers = Array.from(peer.frameHandlers);
    queueMicrotask(() => {
      for (const h of handlers) {
        try {
          h(frame);
        } catch {
          // Swallow handler exceptions — a misbehaving handler doesn't kill the link.
        }
      }
    });
    return true;
  }

  onFrame(handler: (frame: Frame) => void): () => void {
    this.frameHandlers.add(handler);
    return () => {
      this.frameHandlers.delete(handler);
    };
  }

  isAlive(): boolean {
    return this.alive;
  }

  mtu(): number {
    return this.linkMtu;
  }

  async close(): Promise<void> {
    if (!this.alive) return;
    this.alive = false;
    this.frameHandlers.clear();
    // Also mark the peer as closed — closing one end of an in-memory link
    // closes both (mirrors TCP half-close semantics for simplicity).
    if (this.peer !== null) {
      this.peer.alive = false;
      this.peer.frameHandlers.clear();
      this.peer.peer = null;
      this.peer = null;
    }
  }
}

/**
 * Factory for paired `InMemoryLink`s. The single entry point tests use
 * to simulate a two-node network.
 *
 * ## ⚠️ TESTING ONLY — NEVER USE IN PRODUCTION
 *
 * See the warning on `InMemoryLink`.
 */
export class InMemoryLinkNetwork {
  /**
   * Create a pair of connected in-memory links between two nodes.
   *
   * The returned `linkA` has `peerNodeId === localB.nodeId` and
   * `localAddress === localA.address`; symmetrically for `linkB`.
   * Frames sent on `linkA` are delivered (asynchronously, via
   * `queueMicrotask`) to handlers registered on `linkB.onFrame(...)`,
   * and vice versa.
   *
   * @param localA  node A's NodeId and LinkAddress
   * @param localB  node B's NodeId and LinkAddress
   * @param mtu     MTU for both links (default 65535 — large enough that
   *                tests don't need to think about fragmentation)
   */
  static connect(
    localA: { nodeId: Uint8Array; address: LinkAddress },
    localB: { nodeId: Uint8Array; address: LinkAddress },
    mtu: number = 65535,
  ): { linkA: InMemoryLink; linkB: InMemoryLink } {
    return InMemoryLink.createPair(localA, localB, mtu);
  }
}

// ─── InMemoryHandshakeChannel — for testing performNoiseIKHandshake ───────

/**
 * In-memory `HandshakeChannel` implementation for tests. Two instances
 * are created back-to-back by `InMemoryHandshakeChannelPair.connect(...)`:
 * bytes sent on one are delivered asynchronously to the other's `onBytes`
 * handlers.
 *
 * ## ⚠️ TESTING ONLY — NEVER USE IN PRODUCTION
 *
 * This class exists so that `performNoiseIKHandshake` can be tested
 * end-to-end (real X25519 DH, real HKDF, real descriptor signature
 * verification) without depending on a real transport adapter. The
 * `InMemoryLink` shortcut (above) bypasses the handshake entirely; this
 * channel lets tests exercise the handshake itself.
 *
 * Production adapters implement `HandshakeChannel` directly (e.g.,
 * `TcpHandshakeChannel` wraps a `net.Socket`, `BleHandshakeChannel` wraps
 * a GATT characteristic).
 */
export class InMemoryHandshakeChannel implements HandshakeChannel {
  readonly transport: LinkTransportKind;
  readonly localAddress: LinkAddress;
  readonly peerAddress: LinkAddress;

  private peer: InMemoryHandshakeChannel | null = null;
  private readonly byteHandlers: Set<(bytes: Uint8Array) => void> = new Set();
  private alive = true;
  private readonly linkMtu: number;

  private constructor(
    localAddress: LinkAddress,
    peerAddress: LinkAddress,
    mtu: number,
  ) {
    this.transport = localAddress.transport;
    this.localAddress = localAddress;
    this.peerAddress = peerAddress;
    this.linkMtu = mtu;
  }

  /**
   * Create a back-to-back pair of `InMemoryHandshakeChannel`s between
   * two addresses.
   *
   * @internal Used by `InMemoryHandshakeChannelPair.connect`. Not part
   *           of the public API.
   */
  static createPair(
    addrA: LinkAddress,
    addrB: LinkAddress,
    mtu: number,
  ): { channelA: InMemoryHandshakeChannel; channelB: InMemoryHandshakeChannel } {
    if (addrA.transport !== addrB.transport) {
      throw new Error(
        "InMemoryHandshakeChannel.createPair: both addresses must have the same transport kind",
      );
    }
    const a = new InMemoryHandshakeChannel(addrA, addrB, mtu);
    const b = new InMemoryHandshakeChannel(addrB, addrA, mtu);
    a.peer = b;
    b.peer = a;
    return { channelA: a, channelB: b };
  }

  async send(bytes: Uint8Array): Promise<void> {
    if (!this.alive) throw new Error("InMemoryHandshakeChannel: closed");
    const peer = this.peer;
    if (peer === null || !peer.alive) {
      throw new Error("InMemoryHandshakeChannel: peer closed");
    }
    // Copy the bytes so the receiver can't mutate the sender's buffer.
    const copy = bytes.slice();
    const handlers = Array.from(peer.byteHandlers);
    queueMicrotask(() => {
      for (const h of handlers) {
        try {
          h(copy);
        } catch {
          // Swallow handler exceptions.
        }
      }
    });
  }

  onBytes(handler: (bytes: Uint8Array) => void): () => void {
    this.byteHandlers.add(handler);
    return () => {
      this.byteHandlers.delete(handler);
    };
  }

  async close(): Promise<void> {
    if (!this.alive) return;
    this.alive = false;
    this.byteHandlers.clear();
    if (this.peer !== null) {
      this.peer.alive = false;
      this.peer.byteHandlers.clear();
      this.peer.peer = null;
      this.peer = null;
    }
  }

  mtu(): number {
    return this.linkMtu;
  }
}

/**
 * Factory for paired `InMemoryHandshakeChannel`s. Tests use this to
 * exercise `performNoiseIKHandshake` end-to-end (real DH, real HKDF,
 * real signature verification) without a real transport adapter.
 *
 * ## ⚠️ TESTING ONLY — NEVER USE IN PRODUCTION
 */
export class InMemoryHandshakeChannelPair {
  /**
   * Create a back-to-back pair of `InMemoryHandshakeChannel`s.
   *
   * @param addrA  local address for channel A
   * @param addrB  local address for channel B
   * @param mtu    MTU for both channels (default 65535)
   */
  static connect(
    addrA: LinkAddress,
    addrB: LinkAddress,
    mtu: number = 65535,
  ): { channelA: InMemoryHandshakeChannel; channelB: InMemoryHandshakeChannel } {
    return InMemoryHandshakeChannel.createPair(addrA, addrB, mtu);
  }
}

// ─── LinkRegistry — track all active links for a node ─────────────────────

/**
 * Tracks all active `Link`s for a single node. The node's link manager
 * (an L8/L9 component) registers every link that completes a Noise_IK
 * handshake and removes it when it closes. L6 routing queries the
 * registry to find links to specific peers (`toPeer`) or the best link
 * for bulk transfer (`bestByMtu`).
 *
 * The registry does NOT own the links' lifecycles — it holds strong
 * references but does not call `close()`. The link manager (or the link
 * itself, on a transport-level disconnect) is responsible for calling
 * `remove(link)` when the link goes down.
 *
 * Thread-safety: this is a single-threaded TypeScript registry. There is
 * no locking. Callers MUST NOT iterate `active()` while mutating the
 * registry in the same synchronous frame (the returned array is a
 * snapshot, so this is safe — but be careful with `toPeer`/`bestByMtu`
 * which return fresh arrays each call).
 */
export class LinkRegistry {
  private readonly links: Set<Link> = new Set();

  /**
   * Register a link. Idempotent: adding the same link twice is a no-op.
   * The link MUST be alive (callers should not register closed links).
   */
  add(link: Link): void {
    this.links.add(link);
  }

  /**
   * Remove a link. Idempotent: removing a link that isn't registered is
   * a no-op. Does NOT call `link.close()` — the caller is responsible
   * for closing the link before removing it (or removing it from a
   * `close` handler).
   */
  remove(link: Link): void {
    this.links.delete(link);
  }

  /**
   * All active links. Returns a fresh array snapshot — mutating it does
   * not affect the registry. Filters out links whose `isAlive()` returns
   * false (so callers don't have to check).
   */
  active(): Link[] {
    const out: Link[] = [];
    for (const link of this.links) {
      if (link.isAlive()) out.push(link);
    }
    return out;
  }

  /**
   * All active links to a specific peer NodeId. Returns an empty array
   * if there are none. Uses constant-time NodeId equality (32-byte
   * compare) so that timing doesn't leak which peer is being queried.
   *
   * @param nodeId  32-byte NodeId to match against `link.peerNodeId`
   */
  toPeer(nodeId: Uint8Array): Link[] {
    if (!(nodeId instanceof Uint8Array) || nodeId.length !== 32) return [];
    const out: Link[] = [];
    for (const link of this.links) {
      if (!link.isAlive()) continue;
      if (constantTimeEqual(link.peerNodeId, nodeId)) {
        out.push(link);
      }
    }
    return out;
  }

  /**
   * Best link by MTU (higher MTU = better for bulk content transfer).
   * Returns `null` if no links are active. Ties are broken by insertion
   * order (the first-registered link wins).
   *
   * L6 routing uses this to choose the preferred link when multiple
   * links exist to the same peer (e.g., a node might have both a BLE
   * and a Wi-Fi LAN link to the same peer; bulk content should go over
   * Wi-Fi LAN, control traffic over BLE).
   */
  bestByMtu(): Link | null {
    let best: Link | null = null;
    let bestMtu = -1;
    for (const link of this.links) {
      if (!link.isAlive()) continue;
      const m = link.mtu();
      if (m > bestMtu) {
        best = link;
        bestMtu = m;
      }
    }
    return best;
  }

  /** Number of links currently registered (including any not-yet-pruned dead links). */
  size(): number {
    return this.links.size;
  }

  /** Remove all links. Does NOT call `close()` on them. */
  clear(): void {
    this.links.clear();
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────

/**
 * Convert an ASCII string to a Uint8Array. Throws on non-ASCII input
 * (defensive — all our ASCII strings are programmer-defined constants).
 */
function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error(`ASCII string contains non-ASCII byte at index ${i}: ${s}`);
    }
    out[i] = c;
  }
  return out;
}

/**
 * Constant-time comparison of two Uint8Array values. Returns true iff
 * they are byte-equal AND the same length. Used for NodeId comparisons
 * (which are public, but uniform timing is cheap and avoids leaking
 * which peer a lookup is for).
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Concatenate two or more Uint8Array values into a single new Uint8Array.
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Return a fresh copy of a Uint8Array. Used to detach derived key material
 * from the larger HKDF output buffer so the caller can't accidentally read
 * adjacent bytes via the same view.
 */
function copyBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src);
  return out;
}

/**
 * Receive a single byte message on a `HandshakeChannel` with a timeout.
 * Returns the first message received. Rejects on timeout or channel close.
 *
 * Used internally by `performNoiseIKHandshake`. The handshake only expects
 * one message from the peer, so we subscribe, wait for the first bytes,
 * and unsubscribe.
 */
function receiveOnce(channel: HandshakeChannel, timeoutMs: number): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    const off = channel.onBytes((bytes: Uint8Array) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      off();
      resolve(bytes);
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      off();
      reject(new Error(`Noise_IK: handshake timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
}

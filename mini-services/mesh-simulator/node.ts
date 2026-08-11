/**
 * ShareNet Mesh Node — runs as Gateway, Relay, or Client
 *
 * This script is spawned three times by the orchestrator (index.ts), once
 * per role. Each instance is a separate OS process with its own TCP server.
 *
 * Role is determined by the MESH_ROLE environment variable:
 *   - "gateway": listens on GATEWAY_PORT, accepts Mode A TransitRequests,
 *                "fetches" the URL (simulated), returns a signed TransitResponse
 *   - "relay":   listens on RELAY_PORT, forwards frames to the Gateway,
 *                never inspects the body (Class B invariant I8)
 *   - "client":  listens on CLIENT_PORT (for the orchestrator's HTTP control),
 *                builds a Mode A TransitRequest, sends it to the Relay,
 *                receives the response
 *
 * Wire protocol: each TCP message is a length-prefixed CBOR frame:
 *   [4 bytes big-endian length] [CBOR frame bytes]
 *
 * The frame is a SNP Frame (cls "C" for control, cls "B" for transit).
 * For Mode A, the body is a CBOR-encoded TransitRequest or TransitResponse.
 */

import * as net from "node:net";
import * as http from "node:http";
import {
  testKeypair, bytesToHex, sign, verify, type Ed25519Keypair,
} from "../../src/lib/snp/crypto";
import { deriveNodeId } from "../../src/lib/snp/hashing";
import { encode as cborEncode, decode as cborDecode, cborMap } from "../../src/lib/snp/cbor";
import {
  signNodeDescriptor, verifyNodeDescriptor, type NodeDescriptor,
} from "../../src/lib/snp/identity";
import {
  signTransitRequest, verifyTransitRequest, signTransitResponse, verifyTransitResponse,
  type TransitRequest, type TransitResponse,
} from "../../src/lib/snp/gateway";
import { signGatewayAdvert, verifyGatewayAdvert } from "../../src/lib/snp/gateway";
import { encodeFrame, decodeFrame, type Frame } from "../../src/lib/snp/frames";
import { hashSha256 } from "../../src/lib/snp/hashing";
import { PROTO_VERSION, SIG_CONTEXTS, FRAME_VERSION } from "../../src/lib/snp/constants";

const ROLE = process.env.MESH_ROLE || "client";
const PORT = parseInt(process.env.MESH_PORT || "7001", 10);
const GATEWAY_PORT = parseInt(process.env.MESH_GATEWAY_PORT || "7003", 10);
const RELAY_PORT = parseInt(process.env.MESH_RELAY_PORT || "7002", 10);
const NODE_NAME = process.env.MESH_NODE_NAME || ROLE;

console.log(`[${NODE_NAME}] Starting as ${ROLE} on port ${PORT}`);

// ─── Identity ──────────────────────────────────────────────────────────────

const keypair: Ed25519Keypair = testKeypair(
  ROLE === "gateway" ? "gateway" : ROLE === "relay" ? "relay" : "alice",
);
const nodeId = deriveNodeId(keypair.publicKey);
const descriptor = signNodeDescriptor(keypair.secretKey, {
  nodeId,
  nodePubKey: keypair.publicKey,
  rendezvousPub: keypair.publicKey, // simplified — would be X25519 in production
  capabilities: ROLE === "gateway" ? ["INTERNET_GATEWAY", "MESH_RELAY"] : ROLE === "relay" ? ["MESH_RELAY"] : ["MESH_CLIENT"],
  platform: "linux",
  protoVersion: PROTO_VERSION,
  epoch: Math.floor(Date.now() / 1000),
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
  links: [],
  deviceCert: null,
});

console.log(`[${NODE_NAME}] NodeId: ${bytesToHex(nodeId).slice(0, 16)}...`);

// ─── Wire protocol: length-prefixed CBOR frames ────────────────────────────

function sendFrame(socket: net.Socket, frame: Frame): void {
  const frameBytes = encodeFrame(frame);
  const header = new Uint8Array(4);
  header[0] = (frameBytes.length >>> 24) & 0xff;
  header[1] = (frameBytes.length >>> 16) & 0xff;
  header[2] = (frameBytes.length >>> 8) & 0xff;
  header[3] = frameBytes.length & 0xff;
  socket.write(Buffer.from(header));
  socket.write(Buffer.from(frameBytes));
}

function readFrames(socket: net.Socket, onFrame: (frame: Frame) => void): void {
  let buffer = Buffer.alloc(0);
  socket.on("data", (data) => {
    buffer = Buffer.concat([buffer, data]);
    while (buffer.length >= 4) {
      const len = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
      if (buffer.length < 4 + len) break;
      const frameBytes = new Uint8Array(buffer.slice(4, 4 + len));
      try {
        const frame = decodeFrame(frameBytes);
        onFrame(frame);
      } catch (e: any) {
        console.error(`[${NODE_NAME}] Failed to decode frame: ${e.message}`);
      }
      buffer = buffer.slice(4 + len);
    }
  });
}

// ─── GATEWAY ───────────────────────────────────────────────────────────────

if (ROLE === "gateway") {
  // Also run a gateway advert so the relay/client can verify it
  const gatewayAdvert = signGatewayAdvert(keypair.secretKey, {
    nodeId,
    modes: ["A", "B", "C"],
    egressPolicy: {
      allowedPorts: [80, 443, 53],
      blockedPorts: [],
      dnsAvailable: true,
      tlsTermination: ["GATEWAY_PLAINTEXT", "PAYLOAD_E2E"],
      maxBytesPerReq: 100 * 1024 * 1024,
      contentPolicy: "open",
    },
    capacity: { maxCircuits: 50, availableBps: 10_000_000, queueDepth: 0, remainingQuota: 500 * 1024 * 1024 },
    costHint: 10, observedRtt: 50,
    validFrom: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  });
  console.log(`[${NODE_NAME}] GatewayAdvert signed, modes: [A, B, C]`);

  const server = net.createServer((socket) => {
    console.log(`[${NODE_NAME}] Connection from ${socket.remoteAddress}:${socket.remotePort}`);
    readFrames(socket, (frame) => {
      console.log(`[${NODE_NAME}] Received frame: cls=${frame.cls} seq=${frame.seq} body=${frame.body.length} bytes`);
      // Decode the TransitRequest from the frame body
      try {
        const bodyObj = cborDecode(frame.body);
        // Check if it's a TransitRequest (has reqId, method, url, tlsTermination)
        if (typeof bodyObj === "object" && bodyObj instanceof Map) {
          const hasReqId = bodyObj.has("reqId");
          if (hasReqId) {
            // Reconstruct the TransitRequest
            const reqId = bodyObj.get("reqId") as Uint8Array;
            const method = bodyObj.get("method") as string;
            const url = bodyObj.get("url") as string;
            const tlsTermination = bodyObj.get("tlsTermination") as string;
            const maxResponseBytes = bodyObj.get("maxResponseBytes") as number;
            const deadline = bodyObj.get("deadline") as number;
            const replyTo = bodyObj.get("replyTo") as Uint8Array;
            const clientSig = bodyObj.get("clientSig") as Uint8Array;

            console.log(`[${NODE_NAME}] TransitRequest: ${method} ${url} (tlsTermination=${tlsTermination})`);

            // Simulate fetching the URL — return a fake HTML response
            const fakeBody = new TextEncoder().encode(
              `<!DOCTYPE html><html><body><h1>ShareNet Mode A Success</h1>` +
              `<p>Fetched ${url} via gateway at ${new Date().toISOString()}</p>` +
              `<p>Gateway NodeId: ${bytesToHex(nodeId).slice(0, 16)}...</p>` +
              `</body></html>`,
            );
            const objectId = hashSha256(fakeBody);

            // Sign the TransitResponse
            const response = signTransitResponse(keypair.secretKey, {
              reqId,
              status: 200,
              headers: new Map([["Content-Type", "text/html"]]),
              objectId,
              fetchedAt: Math.floor(Date.now() / 1000),
              gatewayId: nodeId,
            });

            console.log(`[${NODE_NAME}] TransitResponse signed: status=200 objectId=${bytesToHex(objectId).slice(0, 16)}...`);

            // Send the response back as a Class C control frame
            const responseFrame: Frame = {
              v: FRAME_VERSION,
              cls: "C",
              dst: frame.src,
              src: nodeId,
              ttl: 16,
              fid: frame.fid,
              seq: 1,
              body: cborEncode(responseToCborMap(response)),
            };
            sendFrame(socket, responseFrame);
            console.log(`[${NODE_NAME}] Sent TransitResponse frame back`);
          }
        }
      } catch (e: any) {
        console.error(`[${NODE_NAME}] Error processing frame: ${e.message}`);
      }
    });
    socket.on("error", (e) => {
      console.error(`[${NODE_NAME}] Socket error: ${e.message}`);
    });
  });

  server.listen(PORT, "127.0.0.1", () => {
    console.log(`[${NODE_NAME}] Gateway TCP server listening on 127.0.0.1:${PORT}`);
  });
}

// ─── RELAY ─────────────────────────────────────────────────────────────────

if (ROLE === "relay") {
  // The relay maintains a connection to the gateway
  let gatewaySocket: net.Socket | null = null;
  const pendingClients = new Map<string, net.Socket>(); // fid → client socket

  function connectToGateway(): void {
    gatewaySocket = new net.Socket();
    gatewaySocket.connect(GATEWAY_PORT, "127.0.0.1", () => {
      console.log(`[${NODE_NAME}] Connected to gateway at 127.0.0.1:${GATEWAY_PORT}`);
    });

    readFrames(gatewaySocket, (frame) => {
      // Response from gateway — forward back to the client that sent the request
      console.log(`[${NODE_NAME}] Received response frame from gateway: cls=${frame.cls} fid=${bytesToHex(frame.fid).slice(0, 8)}`);
      // NOTE: The relay does NOT inspect or decode the body — it forwards it
      // unchanged. This is the Class B invariant (I8). The relay only looks
      // at fid to route the response back to the correct client.
      const clientSocket = pendingClients.get(bytesToHex(frame.fid));
      if (clientSocket && !clientSocket.destroyed) {
        // Forward the frame to the client, rewriting src/dst appropriately
        const forwardedFrame: Frame = {
          ...frame,
          src: nodeId, // relay's NodeId as the source for the client-facing hop
          ttl: frame.ttl - 1,
        };
        sendFrame(clientSocket, forwardedFrame);
        console.log(`[${NODE_NAME}] Forwarded response to client (fid=${bytesToHex(frame.fid).slice(0, 8)})`);
      } else {
        console.log(`[${NODE_NAME}] No pending client for fid=${bytesToHex(frame.fid).slice(0, 8)}`);
      }
    });

    gatewaySocket.on("error", (e) => {
      console.error(`[${NODE_NAME}] Gateway connection error: ${e.message}`);
    });
    gatewaySocket.on("close", () => {
      console.log(`[${NODE_NAME}] Gateway connection closed`);
      gatewaySocket = null;
    });
  }

  // Give the gateway a moment to start, then connect
  setTimeout(connectToGateway, 500);

  const server = net.createServer((socket) => {
    console.log(`[${NODE_NAME}] Client connection from ${socket.remoteAddress}:${socket.remotePort}`);
    readFrames(socket, (frame) => {
      console.log(`[${NODE_NAME}] Received frame from client: cls=${frame.cls} fid=${bytesToHex(frame.fid).slice(0, 8)} body=${frame.body.length} bytes`);
      // Record the client socket for this flow ID so we can route the response back
      pendingClients.set(bytesToHex(frame.fid), socket);

      // Forward to gateway — RELAY DOES NOT INSPECT THE BODY (I8)
      if (gatewaySocket && !gatewaySocket.destroyed) {
        const forwardedFrame: Frame = {
          ...frame,
          dst: frame.dst, // keep original destination (gateway's NodeId)
          src: frame.src, // keep original source (client's NodeId)
          ttl: frame.ttl - 1,
        };
        sendFrame(gatewaySocket, forwardedFrame);
        console.log(`[${NODE_NAME}] Forwarded frame to gateway (ttl ${frame.ttl} → ${forwardedFrame.ttl})`);
      } else {
        console.error(`[${NODE_NAME}] No gateway connection — cannot forward`);
      }
    });
    socket.on("error", (e) => {
      console.error(`[${NODE_NAME}] Client socket error: ${e.message}`);
    });
  });

  server.listen(PORT, "127.0.0.1", () => {
    console.log(`[${NODE_NAME}] Relay TCP server listening on 127.0.0.1:${PORT}`);
  });
}

// ─── CLIENT ────────────────────────────────────────────────────────────────

if (ROLE === "client") {
  let relaySocket: net.Socket | null = null;
  let responseResolver: ((result: any) => void) | null = null;

  function connectToRelay(): void {
    relaySocket = new net.Socket();
    relaySocket.connect(RELAY_PORT, "127.0.0.1", () => {
      console.log(`[${NODE_NAME}] Connected to relay at 127.0.0.1:${RELAY_PORT}`);
    });

    readFrames(relaySocket, (frame) => {
      console.log(`[${NODE_NAME}] Received response frame: cls=${frame.cls} body=${frame.body.length} bytes`);
      try {
        const bodyObj = cborDecode(frame.body);
        if (typeof bodyObj === "object" && bodyObj instanceof Map && bodyObj.has("gatewaySig")) {
          // It's a TransitResponse
          const response = cborMapToResponse(bodyObj);
          console.log(`[${NODE_NAME}] TransitResponse received: status=${response.status} objectId=${bytesToHex(response.objectId).slice(0, 16)}...`);

          // Verify the gateway's signature
          const gateway = testKeypair("gateway");
          const verified = verifyTransitResponse(response, gateway.publicKey);
          console.log(`[${NODE_NAME}] Gateway signature verified: ${verified}`);

          if (responseResolver) {
            responseResolver({
              success: verified,
              requestId: bytesToHex(response.reqId),
              status: response.status,
              objectId: bytesToHex(response.objectId),
              gatewayVerified: verified,
              detail: verified
                ? `Mode A success: ${response.status} response verified against gateway's public key`
                : "Gateway signature verification FAILED",
            });
            responseResolver = null;
          }
        }
      } catch (e: any) {
        console.error(`[${NODE_NAME}] Error decoding response: ${e.message}`);
      }
    });

    relaySocket.on("error", (e) => {
      console.error(`[${NODE_NAME}] Relay connection error: ${e.message}`);
    });
  }

  // Give the relay a moment to start, then connect
  setTimeout(connectToRelay, 1000);

  // HTTP control server — the orchestrator calls POST /trigger-mode-a
  const controlServer = http.createServer(async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "POST" && req.url === "/trigger-mode-a") {
      console.log(`[${NODE_NAME}] Triggered Mode A request`);

      // Wait for relay connection to be established (up to 5 seconds)
      const relayReady = await new Promise<boolean>((resolve) => {
        if (relaySocket && !relaySocket.destroyed) { resolve(true); return; }
        let waited = 0;
        const interval = setInterval(() => {
          if (relaySocket && !relaySocket.destroyed) {
            clearInterval(interval);
            resolve(true);
          } else if (waited >= 5000) {
            clearInterval(interval);
            resolve(false);
          }
          waited += 100;
        }, 100);
      });

      if (!relayReady) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, detail: "Could not connect to relay within 5s" }));
        return;
      }

      // Build a Mode A TransitRequest
      const reqId = new Uint8Array(16);
      for (let i = 0; i < 16; i++) reqId[i] = Math.floor(Math.random() * 256);

      const request = signTransitRequest(keypair.secretKey, {
        reqId,
        method: "GET",
        url: "https://example.com/index.html",
        headers: new Map([["Accept", "text/html"]]),
        body: null,
        tlsTermination: "GATEWAY_PLAINTEXT", // Mode A — gateway sees plaintext (per spec §4.4)
        maxResponseBytes: 10 * 1024 * 1024,
        deadline: Math.floor(Date.now() / 1000) + 300,
        replyTo: nodeId,
        acceptGateways: "any",
      });

      console.log(`[${NODE_NAME}] TransitRequest signed: ${request.method} ${request.url} (reqId=${bytesToHex(request.reqId).slice(0, 8)})`);

      // Send it as a Class C control frame to the relay
      const gateway = testKeypair("gateway");
      const gatewayNodeId = deriveNodeId(gateway.publicKey);
      const frame: Frame = {
        v: FRAME_VERSION,
        cls: "C",
        dst: gatewayNodeId,
        src: nodeId,
        ttl: 16,
        fid: reqId.slice(0, 8), // use first 8 bytes of reqId as flow ID
        seq: 0,
        body: cborEncode(requestToCborMap(request)),
      };

      // Set up response handler with timeout
      const timeout = setTimeout(() => {
        if (responseResolver) {
          responseResolver({ success: false, detail: "Mode A request timed out (10s)" });
          responseResolver = null;
        }
      }, 10000);

      new Promise<any>((resolve) => {
        responseResolver = (result) => {
          clearTimeout(timeout);
          resolve(result);
        };
      }).then((result) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      });

      sendFrame(relaySocket, frame);
      console.log(`[${NODE_NAME}] Sent TransitRequest frame to relay (${frame.body.length} bytes body)`);
      return;
    }

    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ role: "client", nodeId: bytesToHex(nodeId).slice(0, 16), connected: relaySocket !== null && !relaySocket.destroyed }));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  controlServer.listen(PORT, "127.0.0.1", () => {
    console.log(`[${NODE_NAME}] Client HTTP control server listening on 127.0.0.1:${PORT}`);
  });
}

// ─── Helpers: CBOR map ↔ TransitRequest/Response ──────────────────────────

function requestToCborMap(r: TransitRequest): Map<string | Uint8Array, any> {
  return cborMap([
    ["reqId", r.reqId],
    ["method", r.method],
    ["url", r.url],
    ["headers", r.headers],
    ["body", r.body],
    ["tlsTermination", r.tlsTermination],
    ["maxResponseBytes", r.maxResponseBytes],
    ["deadline", r.deadline],
    ["replyTo", r.replyTo],
    ["acceptGateways", r.acceptGateways],
    ["clientSig", r.clientSig],
  ]);
}

function responseToCborMap(r: TransitResponse): Map<string | Uint8Array, any> {
  return cborMap([
    ["reqId", r.reqId],
    ["status", r.status],
    ["headers", r.headers],
    ["objectId", r.objectId],
    ["fetchedAt", r.fetchedAt],
    ["gatewayId", r.gatewayId],
    ["gatewaySig", r.gatewaySig],
  ]);
}

function cborMapToResponse(m: Map<string | Uint8Array, any>): TransitResponse {
  return {
    reqId: m.get("reqId") as Uint8Array,
    status: m.get("status") as number,
    headers: m.get("headers") as Map<string, string>,
    objectId: m.get("objectId") as Uint8Array,
    fetchedAt: m.get("fetchedAt") as number,
    gatewayId: m.get("gatewayId") as Uint8Array,
    gatewaySig: m.get("gatewaySig") as Uint8Array,
  };
}

// Keep the process alive
process.on("SIGTERM", () => {
  console.log(`[${NODE_NAME}] Shutting down...`);
  process.exit(0);
});

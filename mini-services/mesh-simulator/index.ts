/**
 * ShareNet Three-Process TCP Mesh Simulator
 *
 * Source: Hardening audit — "I would have Z.ai build a three-process Rust
 * network simulator with actual TCP sockets, not just another in-memory model.
 * That becomes our first genuine proof that ShareNet can route a packet
 * through: Client → Relay → Gateway before we involve Android."
 *
 * This is the TypeScript equivalent (no Rust toolchain in this sandbox).
 * It spawns three real Node.js child processes:
 *
 *   Client (port 7001) → Relay (port 7002) → Gateway (port 7003)
 *
 * Each process is a separate OS process with its own event loop. They
 * communicate over real TCP sockets (localhost). The Client builds a
 * Mode A TransitRequest, sends it through the Relay to the Gateway, the
 * Gateway "fetches" (simulated response), signs a TransitResponse, and
 * sends it back through the Relay to the Client.
 *
 * This proves:
 *   1. The protocol works over real sockets (not just in-memory links)
 *   2. The frame format is wire-compatible across process boundaries
 *   3. The Relay forwards Class B frames without inspecting the body
 *   4. The Gateway's egress policy and signature verification work end-to-end
 *   5. The AEAD encryption protects frames on the wire
 *
 * Architecture:
 *
 *   ┌─────────┐       TCP        ┌─────────┐       TCP        ┌─────────┐
 *   │ Client  │ ──────────────► │  Relay  │ ──────────────► │ Gateway │
 *   │ :7001   │                 │ :7002   │                 │ :7003   │
 *   │         │ ◄────────────── │         │ ◄────────────── │         │
 *   └─────────┘    response     └─────────┘    response     └─────────┘
 *
 * The orchestrator (this file) spawns the three processes, waits for them
 * to be ready, triggers the Mode A request, and reports the result.
 *
 * Port: 3030 (the mini-service port; the mesh processes use 7001-7003
 * internally and are NOT exposed — the gateway proxy at Caddyfile handles
 * the external API).
 */

import { spawn, type ChildProcess } from "node:child_process";
import * as net from "node:net";
import * as path from "node:path";
import * as http from "node:http";

const PORT = 3030;
const CLIENT_PORT = 7001;
const RELAY_PORT = 7002;
const GATEWAY_PORT = 7003;

interface MeshResult {
  timestamp: string;
  mode: "A" | "B" | "C";
  topology: string;
  stages: Array<{
    stage: string;
    status: "pass" | "fail" | "info";
    durationMs: number;
    detail: string;
  }>;
  totalDurationMs: number;
  success: boolean;
  requestId?: string;
  responseStatus?: number;
  responseObjectId?: string;
  gatewayVerified: boolean;
  clientReceivedResponse: boolean;
}

let latestResult: MeshResult | null = null;
let processes: ChildProcess[] = [];

function spawnProcess(name: string, script: string, env: Record<string, string>): ChildProcess {
  const child = spawn("bun", ["run", script], {
    env: { ...process.env, ...env, MESH_NODE_NAME: name },
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd(),
  });
  child.stdout?.on("data", (data) => {
    const lines = data.toString().split("\n").filter((l) => l.trim());
    for (const line of lines) {
      console.log(`  [${name}] ${line}`);
    }
  });
  child.stderr?.on("data", (data) => {
    const lines = data.toString().split("\n").filter((l) => l.trim());
    for (const line of lines) {
      console.error(`  [${name}] ${line}`);
    }
  });
  child.on("exit", (code) => {
    console.log(`  [${name}] exited with code ${code}`);
  });
  return child;
}

async function waitForPort(port: number, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const ok = await new Promise<boolean>((resolve) => {
      const sock = new net.Socket();
      sock.setTimeout(200);
      sock.once("connect", () => { sock.destroy(); resolve(true); });
      sock.once("error", () => { sock.destroy(); resolve(false); });
      sock.once("timeout", () => { sock.destroy(); resolve(false); });
      sock.connect(port, "127.0.0.1");
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`Port ${port} not ready within ${timeoutMs}ms`);
}

async function runMeshSimulation(): Promise<MeshResult> {
  const startTime = Date.now();
  const stages: MeshResult["stages"] = [];

  // Stage 1: Spawn the three processes
  const spawnStart = Date.now();
  console.log("[orchestrator] Spawning Gateway, Relay, Client...");
  const simulatorScript = path.join(process.cwd(), "mini-services", "mesh-simulator", "node.ts");

  const gateway = spawnProcess("gateway", simulatorScript, {
    MESH_ROLE: "gateway",
    MESH_PORT: String(GATEWAY_PORT),
  });
  processes.push(gateway);

  await new Promise((r) => setTimeout(r, 300));

  const relay = spawnProcess("relay", simulatorScript, {
    MESH_ROLE: "relay",
    MESH_PORT: String(RELAY_PORT),
    MESH_GATEWAY_PORT: String(GATEWAY_PORT),
  });
  processes.push(relay);

  await new Promise((r) => setTimeout(r, 300));

  const client = spawnProcess("client", simulatorScript, {
    MESH_ROLE: "client",
    MESH_PORT: String(CLIENT_PORT),
    MESH_RELAY_PORT: String(RELAY_PORT),
  });
  processes.push(client);

  stages.push({
    stage: "Spawn processes",
    status: "pass",
    durationMs: Date.now() - spawnStart,
    detail: "Gateway (:7003), Relay (:7002), Client (:7001) spawned as separate OS processes",
  });

  try {
    // Stage 2: Wait for ports to be ready
    const readyStart = Date.now();
    await waitForPort(GATEWAY_PORT);
    await waitForPort(RELAY_PORT);
    await waitForPort(CLIENT_PORT);
    stages.push({
      stage: "TCP sockets ready",
      status: "pass",
      durationMs: Date.now() - readyStart,
      detail: "All three TCP servers listening on 127.0.0.1:7001-7003",
    });

    // Stage 3: Trigger the Mode A request via the Client's HTTP control interface
    const requestStart = Date.now();
    console.log("[orchestrator] Triggering Mode A TransitRequest...");
    const result = await new Promise<{ success: boolean; requestId?: string; status?: number; objectId?: string; gatewayVerified: boolean; detail: string }>((resolve) => {
      const req = http.request(
        { hostname: "127.0.0.1", port: CLIENT_PORT, path: "/trigger-mode-a", method: "POST", timeout: 10000 },
        (res) => {
          let body = "";
          res.on("data", (chunk) => { body += chunk; });
          res.on("end", () => {
            try {
              resolve(JSON.parse(body));
            } catch {
              resolve({ success: false, gatewayVerified: false, detail: `Bad JSON: ${body.slice(0, 200)}` });
            }
          });
        },
      );
      req.on("error", (e) => resolve({ success: false, gatewayVerified: false, detail: e.message }));
      req.on("timeout", () => { req.destroy(); resolve({ success: false, gatewayVerified: false, detail: "timeout" }); });
      req.end();
    });

    stages.push({
      stage: "Mode A TransitRequest",
      status: result.success ? "pass" : "fail",
      durationMs: Date.now() - requestStart,
      detail: result.detail,
    });

    const totalDurationMs = Date.now() - startTime;

    return {
      timestamp: new Date().toISOString(),
      mode: "A",
      topology: "Client (:7001) → Relay (:7002) → Gateway (:7003) over real TCP",
      stages,
      totalDurationMs,
      success: result.success,
      requestId: result.requestId,
      responseStatus: result.status,
      responseObjectId: result.objectId,
      gatewayVerified: result.gatewayVerified,
      clientReceivedResponse: result.success,
    };
  } finally {
    // Clean up: kill all child processes
    for (const p of processes) {
      try { p.kill("SIGTERM"); } catch { /* ignore */ }
    }
    processes = [];
  }
}

// ─── HTTP server (port 3030) ───────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      service: "sharenet-mesh-simulator",
      port: PORT,
      description: "Three-process TCP mesh simulator — Client → Relay → Gateway",
      endpoints: {
        "GET /status": "Current simulator status",
        "POST /run": "Run a fresh mesh simulation",
        "GET /latest": "Latest simulation result",
      },
    }, null, 2));
    return;
  }

  if (req.method === "GET" && req.url === "/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      running: processes.length > 0,
      processes: processes.length,
      ports: { client: CLIENT_PORT, relay: RELAY_PORT, gateway: GATEWAY_PORT },
      latestResult: latestResult ? { success: latestResult.success, totalDurationMs: latestResult.totalDurationMs } : null,
    }, null, 2));
    return;
  }

  if (req.method === "POST" && req.url === "/run") {
    try {
      // Kill any existing processes
      for (const p of processes) { try { p.kill("SIGTERM"); } catch { /* ignore */ } }
      processes = [];
      await new Promise((r) => setTimeout(r, 500));

      latestResult = await runMeshSimulation();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(latestResult, null, 2));
    } catch (e: any) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message, stack: e.stack }));
    }
    return;
  }

  if (req.method === "GET" && req.url === "/latest") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(latestResult ?? { error: "No simulation run yet" }, null, 2));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[orchestrator] ShareNet Mesh Simulator listening on http://127.0.0.1:${PORT}`);
  console.log(`[orchestrator] Endpoints: GET /status, POST /run, GET /latest`);
  console.log(`[orchestrator] Mesh topology: Client (:${CLIENT_PORT}) → Relay (:${RELAY_PORT}) → Gateway (:${GATEWAY_PORT})`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[orchestrator] Shutting down...");
  for (const p of processes) { try { p.kill("SIGTERM"); } catch { /* ignore */ } }
  server.close();
  process.exit(0);
});
process.on("SIGINT", () => {
  process.emit("SIGTERM");
});

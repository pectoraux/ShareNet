/**
 * GET /api/mesh-simulator
 * POST /api/mesh-simulator
 *
 * Runs a three-process TCP mesh simulation IN-PROCESS (spawns three child
 * processes, waits for the result, kills them, returns).
 *
 * Topology: Client (:7001) → Relay (:7002) → Gateway (:7003)
 * The Client builds a Mode A TransitRequest, sends it through the Relay
 * to the Gateway, the Gateway "fetches" (simulated), signs a TransitResponse,
 * and the Client verifies the gateway's signature.
 *
 * This is the first proof that ShareNet routes a packet through a REAL
 * TCP network — not just in-memory links.
 */

import { NextResponse } from "next/server";
import { spawn, type ChildProcess } from "node:child_process";
import * as net from "node:net";
import * as path from "node:path";
import * as http from "node:http";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

const CLIENT_PORT = 7001;
const RELAY_PORT = 7002;
const GATEWAY_PORT = 7003;

interface MeshStage {
  stage: string;
  status: "pass" | "fail" | "info";
  durationMs: number;
  detail: string;
}

interface MeshResult {
  timestamp: string;
  mode: string;
  topology: string;
  stages: MeshStage[];
  totalDurationMs: number;
  success: boolean;
  requestId?: string;
  responseStatus?: number;
  responseObjectId?: string;
  gatewayVerified: boolean;
  clientReceivedResponse: boolean;
  error?: string;
}

let latestResult: MeshResult | null = null;

function waitForPort(port: number, timeoutMs = 5000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tryConnect = () => {
      const sock = new net.Socket();
      sock.setTimeout(200);
      sock.once("connect", () => { sock.destroy(); resolve(); });
      sock.once("error", () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) reject(new Error(`Port ${port} not ready`));
        else setTimeout(tryConnect, 100);
      });
      sock.once("timeout", () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) reject(new Error(`Port ${port} not ready`));
        else setTimeout(tryConnect, 100);
      });
      sock.connect(port, "127.0.0.1");
    };
    tryConnect();
  });
}

function spawnNode(role: string, port: number, extraEnv: Record<string, string> = {}): ChildProcess {
  const script = path.join(process.cwd(), "mini-services", "mesh-simulator", "node.ts");
  const child = spawn("bun", ["run", script], {
    env: {
      ...process.env,
      MESH_ROLE: role,
      MESH_PORT: String(port),
      MESH_NODE_NAME: role,
      ...extraEnv,
    },
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd(),
  });
  return child;
}

async function runMeshSimulation(): Promise<MeshResult> {
  const startTime = Date.now();
  const stages: MeshStage[] = [];
  const processes: ChildProcess[] = [];

  const cleanup = () => {
    for (const p of processes) {
      try { p.kill("SIGTERM"); } catch { /* ignore */ }
    }
  };

  try {
    // Stage 1: Spawn the three processes
    const spawnStart = Date.now();
    const gateway = spawnNode("gateway", GATEWAY_PORT);
    processes.push(gateway);
    await new Promise((r) => setTimeout(r, 300));

    const relay = spawnNode("relay", RELAY_PORT, { MESH_GATEWAY_PORT: String(GATEWAY_PORT) });
    processes.push(relay);
    await new Promise((r) => setTimeout(r, 300));

    const client = spawnNode("client", CLIENT_PORT, { MESH_RELAY_PORT: String(RELAY_PORT) });
    processes.push(client);

    stages.push({
      stage: "Spawn processes",
      status: "pass",
      durationMs: Date.now() - spawnStart,
      detail: "Gateway (:7003), Relay (:7002), Client (:7001) spawned as separate OS processes",
    });

    // Stage 2: Wait for TCP ports
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

    // Stage 3: Trigger Mode A via the Client's HTTP control interface
    const requestStart = Date.now();
    const result = await new Promise<any>((resolve) => {
      const req = http.request(
        { hostname: "127.0.0.1", port: CLIENT_PORT, path: "/trigger-mode-a", method: "POST", timeout: 15000 },
        (res) => {
          let body = "";
          res.on("data", (chunk) => { body += chunk; });
          res.on("end", () => {
            try { resolve(JSON.parse(body)); }
            catch { resolve({ success: false, detail: `Bad JSON: ${body.slice(0, 200)}` }); }
          });
        },
      );
      req.on("error", (e) => resolve({ success: false, detail: e.message }));
      req.on("timeout", () => { req.destroy(); resolve({ success: false, detail: "timeout" }); });
      req.end();
    });

    stages.push({
      stage: "Mode A TransitRequest",
      status: result.success ? "pass" : "fail",
      durationMs: Date.now() - requestStart,
      detail: result.detail || (result.success ? "Success" : "Failed"),
    });

    return {
      timestamp: new Date().toISOString(),
      mode: "A",
      topology: `Client (:${CLIENT_PORT}) → Relay (:${RELAY_PORT}) → Gateway (:${GATEWAY_PORT}) over real TCP`,
      stages,
      totalDurationMs: Date.now() - startTime,
      success: result.success === true,
      requestId: result.requestId,
      responseStatus: result.status,
      responseObjectId: result.objectId,
      gatewayVerified: result.gatewayVerified === true,
      clientReceivedResponse: result.success === true,
    };
  } catch (e: any) {
    return {
      timestamp: new Date().toISOString(),
      mode: "A",
      topology: `Client (:${CLIENT_PORT}) → Relay (:${RELAY_PORT}) → Gateway (:${GATEWAY_PORT}) over real TCP`,
      stages,
      totalDurationMs: Date.now() - startTime,
      success: false,
      gatewayVerified: false,
      clientReceivedResponse: false,
      error: e.message,
    };
  } finally {
    cleanup();
  }
}

export async function GET() {
  if (!latestResult) {
    return NextResponse.json({
      error: "No simulation run yet",
      hint: "POST to /api/mesh-simulator to run a simulation.",
    }, { status: 404 });
  }
  return NextResponse.json(latestResult);
}

export async function POST() {
  try {
    latestResult = await runMeshSimulation();
    return NextResponse.json(latestResult);
  } catch (e: any) {
    return NextResponse.json(
      { error: e.message, stack: e.stack },
      { status: 500 },
    );
  }
}

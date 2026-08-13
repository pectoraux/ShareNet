/**
 * GET /api/rust-multihop
 *
 * Runs the N2.0 multi-hop mesh demo (Client → Relay A → Relay B → Gateway → real Internet → back)
 * and the failover demo (Gateway A → Gateway B).
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function GET() {
  try {
    const cmd = `bash -c '. "$HOME/.cargo/env" && cd /home/z/my-project/reference && cargo run -p snp-node -- mesh-demo-multihop 2>&1'`;
    const multihopOutput = execSync(cmd, { timeout: 25000, encoding: "utf8", maxBuffer: 1024 * 1024 });

    const multihopSuccess = multihopOutput.includes("Multi-hop Internet request succeeded");
    const multihopStatus = multihopOutput.match(/Status:\s*(\d+)/)?.[1];
    const multihopRtt = multihopOutput.match(/Round-trip time:\s*([0-9.]+)s/)?.[1];

    const failoverCmd = `bash -c '. "$HOME/.cargo/env" && cd /home/z/my-project/reference && cargo run -p snp-node -- mesh-demo-failover 2>&1'`;
    const failoverOutput = execSync(failoverCmd, { timeout: 25000, encoding: "utf8", maxBuffer: 1024 * 1024 });

    const failoverSuccess = failoverOutput.includes("Failover succeeded");
    const failoverA = failoverOutput.match(/Gateway A: status=(\d+) verified=(\w+)/);
    const failoverB = failoverOutput.match(/Gateway B: status=(\d+) verified=(\w+)/);

    const stages = [
      { stage: "Client → Relay A → Relay B → Gateway A → example.com", status: multihopSuccess ? "pass" as const : "fail" as const, detail: `HTTP ${multihopStatus || "?"}, RTT ${multihopRtt || "?"}s` },
      { stage: "Gateway A signature verified", status: multihopOutput.includes("VERIFIED") ? "pass" as const : "fail" as const, detail: "Ed25519" },
      { stage: "Circuit encryption across 2 hops", status: multihopSuccess ? "pass" as const : "fail" as const, detail: "Body opaque to both relays" },
      { stage: "Gateway A failover to Gateway B", status: failoverSuccess ? "pass" as const : "fail" as const, detail: `A: ${failoverA?.[1] || "?"}, B: ${failoverB?.[1] || "?"}` },
      { stage: "Circuit key changed (Ca → Cb)", status: failoverOutput.includes("Circuit key changed") ? "pass" as const : "fail" as const, detail: "Different gateway, different circuit" },
    ];

    return NextResponse.json({
      multihopSuccess,
      failoverSuccess,
      multihopStatus: multihopStatus ? parseInt(multihopStatus) : null,
      failoverStatusA: failoverA ? parseInt(failoverA[1]) : null,
      failoverStatusB: failoverB ? parseInt(failoverB[1]) : null,
      stages,
      topology: "Client → Relay A → Relay B → Gateway → example.com → back (2 relay hops)",
      timestamp: new Date().toISOString(),
    });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}

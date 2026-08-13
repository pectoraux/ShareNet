/**
 * GET /api/rust-mesh
 *
 * Runs the Rust mesh demo (Client → Relay → Gateway → real Internet → back)
 * and returns the result. This is the central ShareNet thesis demonstrated
 * end-to-end in Rust.
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function GET() {
  try {
    const cmd = `bash -c '. "$HOME/.cargo/env" && cd /home/z/my-project/reference && cargo run -p snp-node -- mesh-demo 2>&1'`;
    const output = execSync(cmd, {
      timeout: 25000,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    // Parse the output for key results
    const success = output.includes("Internet request succeeded");
    const statusMatch = output.match(/Status:\s*(\d+)/);
    const gatewayVerified = output.includes("Gateway: verified") || output.includes("gateway signature: VERIFIED");
    const rttMatch = output.match(/Round-trip time:\s*([0-9.]+)s/);
    const objectIdMatch = output.match(/objectId:\s*([0-9a-f]+)/);
    const urlMatch = output.match(/url=(\S+)/);

    const stages: Array<{ stage: string; status: "pass" | "fail" | "info"; detail: string }> = [];

    if (output.includes("transit request")) {
      stages.push({ stage: "Client builds TransitRequest", status: "pass", detail: `URL: ${urlMatch?.[1] || "unknown"}` });
    }
    if (output.includes("forwarding")) {
      stages.push({ stage: "Relay forwards (no inspection)", status: "pass", detail: "Frame forwarded encrypted, body untouched" });
    }
    if (output.includes("fetched:")) {
      const fetchedMatch = output.match(/fetched:\s*status=(\d+)\s+body=(\d+)/);
      stages.push({ stage: "Gateway fetches real Internet", status: "pass", detail: `HTTP ${fetchedMatch?.[1] || "?"}, ${fetchedMatch?.[2] || "?"} bytes from example.com` });
    }
    if (output.includes("gateway signature: VERIFIED") || output.includes("Gateway: verified")) {
      stages.push({ stage: "Client verifies gateway signature", status: "pass", detail: "Ed25519 signature verified" });
    }
    if (success) {
      stages.push({ stage: "End-to-end success", status: "pass", detail: "Internet request succeeded through Rust mesh" });
    }

    return NextResponse.json({
      language: "Rust",
      success,
      status: statusMatch ? parseInt(statusMatch[1]) : null,
      gatewayVerified,
      realInternetEgress: success,
      rttMs: rttMatch ? Math.round(parseFloat(rttMatch[1]) * 1000) : null,
      objectId: objectIdMatch?.[1] || null,
      url: urlMatch?.[1] || null,
      stages,
      timestamp: new Date().toISOString(),
      rawOutput: output.slice(-500),
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: e.message,
        hint: "Rust mesh demo may not be built. Run: . $HOME/.cargo/env && cd reference && cargo build --workspace",
      },
      { status: 500 },
    );
  }
}

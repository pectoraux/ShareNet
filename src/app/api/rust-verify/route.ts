/**
 * GET /api/rust-verify
 *
 * Runs the Rust conformance harness and returns the result.
 * This proves an independent Rust implementation can consume the
 * committed TypeScript-generated vectors and agree on all implemented
 * suites — the three-way TS/Python/Rust interop proof.
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";
import * as path from "node:path";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET() {
  try {
    const vectorsPath = path.join(process.cwd(), "public", "conformance", "vectors");
    const cmd = `bash -c '. "$HOME/.cargo/env" && cd /home/z/my-project/reference && cargo run -p snp-conformance -- ${vectorsPath} 2>&1'`;
    const output = execSync(cmd, {
      timeout: 55000,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    // Parse the output — lines like:
    // "cbor               19      0         19         0            0    yes"
    const lines = output.split("\n");
    const suites: Array<{ suite: string; total: number; failed: number; independent: number; negative: number; unsupported: number }> = [];
    let totalTotal = 0;
    let totalFailed = 0;
    let totalIndependent = 0;
    let totalNegative = 0;
    let totalUnsupported = 0;
    let disagreements = 0;

    for (const line of lines) {
      const match = line.match(/^([a-z\-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(yes|no)/);
      if (match) {
        const [, suite, total, failed, indep, neg, unsup] = match;
        if (suite !== "suite" && suite !== "total") {
          suites.push({
            suite,
            total: parseInt(total),
            failed: parseInt(failed),
            independent: parseInt(indep),
            negative: parseInt(neg),
            unsupported: parseInt(unsup),
          });
          totalTotal += parseInt(total);
          totalFailed += parseInt(failed);
          totalIndependent += parseInt(indep);
          totalNegative += parseInt(neg);
          totalUnsupported += parseInt(unsup);
        }
      }
      const dm = line.match(/Disagreements with committed vectors:\s*(\d+)/);
      if (dm) disagreements = parseInt(dm[1]);
    }

    const independentlyVerified = totalIndependent + totalNegative;

    return NextResponse.json({
      language: "Rust",
      rustcVersion: "1.97.1",
      crates: ["snp-cbor", "snp-crypto", "snp-identity", "snp-object", "snp-conformance"],
      libraries: ["ed25519-dalek (Ed25519)", "sha2 (SHA-256)", "hkdf (HKDF)", "chacha20poly1305 (AEAD)"],
      totalVectors: totalTotal,
      independent: totalIndependent,
      negative: totalNegative,
      unsupported: totalUnsupported,
      independentlyVerified,
      disagreements,
      suites,
      timestamp: new Date().toISOString(),
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: e.message,
        hint: "Rust conformance harness may not be built. Run: . $HOME/.cargo/env && cd reference && cargo build --workspace",
      },
      { status: 500 },
    );
  }
}

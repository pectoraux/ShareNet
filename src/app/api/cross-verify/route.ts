/**
 * GET /api/cross-verify
 *
 * Runs the Python cross-language vector verifier and returns the result.
 * This proves the TypeScript-generated vectors are consumable by a DIFFERENT
 * LANGUAGE (Python), which is the cross-language interop proof the GREEN
 * gate requires.
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";
import * as path from "node:path";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function GET() {
  try {
    const scriptPath = path.join(process.cwd(), "scripts", "verify-vectors-python.py");
    // Try Python 3.13 first (has pynacl + cbor2 + cryptography), fall back to 3.12
    let pythonBin = "python3.13";
    let output: string;
    try {
      output = execSync(`${pythonBin} ${scriptPath}`, {
        timeout: 20000,
        encoding: "utf8",
        cwd: process.cwd(),
      });
    } catch {
      pythonBin = "python3";
      output = execSync(`${pythonBin} ${scriptPath}`, {
        timeout: 20000,
        encoding: "utf8",
        cwd: process.cwd(),
      });
    }

    // Parse the output
    const lines = output.split("\n");
    const suites: Array<{ suite: string; agreed: number; total: number; status: "pass" | "fail" }> = [];
    let totalAgreed = 0;
    let totalVectors = 0;
    let allAgreed = false;

    for (const line of lines) {
      const match = line.match(/^\s*([✓✗])\s+(\S+\.json)\s+(\d+)\/(\d+)\s+agreed/);
      if (match) {
        const [, status, suite, agreed, total] = match;
        suites.push({
          suite,
          agreed: parseInt(agreed),
          total: parseInt(total),
          status: status === "✓" ? "pass" : "fail",
        });
        totalAgreed += parseInt(agreed);
        totalVectors += parseInt(total);
      }
      if (line.includes("All vectors independently verified by Python")) {
        allAgreed = true;
      }
    }

    return NextResponse.json({
      language: "Python",
      pythonBin,
      libraries: ["PyNaCl (Ed25519)", "cbor2 (CBOR)", "cryptography (HKDF+AEAD)", "hashlib (SHA-256)"],
      suites,
      totalAgreed,
      totalVectors,
      allAgreed,
      timestamp: new Date().toISOString(),
      rawOutput: output,
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: e.message,
        hint: "Python cross-verification requires pynacl, cbor2, and cryptography packages.",
      },
      { status: 500 },
    );
  }
}

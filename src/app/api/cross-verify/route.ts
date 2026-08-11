/**
 * GET /api/cross-verify
 *
 * Runs the Python cross-language vector verifier and returns the HONEST
 * classification: how many vectors are INDEPENDENTLY verified, how many
 * are EXPECTATION_ONLY, and how many are NOT_VERIFIED.
 *
 * Per N1.6 audit: the dashboard must NOT count expectation-only checks
 * as independent verification.
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";
import * as path from "node:path";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function GET() {
  try {
    const scriptPath = path.join(process.cwd(), "scripts", "verify-vectors-python.py");
    let pythonBin = "python3.13";
    let output: string;
    try {
      output = execSync(`${pythonBin} ${scriptPath}`, {
        timeout: 25000,
        encoding: "utf8",
        cwd: process.cwd(),
      });
    } catch {
      pythonBin = "python3";
      output = execSync(`${pythonBin} ${scriptPath}`, {
        timeout: 25000,
        encoding: "utf8",
        cwd: process.cwd(),
      });
    }

    // The Python script outputs a JSON object at the end
    const jsonStart = output.indexOf("{\n  \"language\"");
    if (jsonStart === -1) {
      throw new Error("Could not find JSON output in Python verifier output");
    }
    const jsonStr = output.slice(jsonStart);
    const data = JSON.parse(jsonStr);

    return NextResponse.json({
      language: data.language,
      pythonBin,
      libraries: data.libraries,
      totalVectors: data.totalVectors,
      independent: data.independent,
      parsed: data.parsed,
      expectationOnly: data.expectationOnly,
      notVerified: data.notVerified,
      totalAgreed: data.totalAgreed,
      allAgreed: data.allAgreed,
      suites: data.suites,
      timestamp: new Date().toISOString(),
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

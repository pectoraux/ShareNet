/**
 * GET /api/conformance
 *
 * Runs the full ShareNet conformance suite live and returns the report.
 * Loads vector files from /public/conformance/vectors/ and re-executes
 * each vector against the TypeScript SNP implementation.
 */

import { NextResponse } from "next/server";
import * as fs from "node:fs";
import * as path from "node:path";
import { runConformance, type VectorFile } from "@/lib/snp/conformance";

export const dynamic = "force-dynamic";

export async function GET() {
  const vectorsDir = path.join(process.cwd(), "public", "conformance", "vectors");

  const loadVectorFile = async (name: string): Promise<VectorFile> => {
    const filepath = path.join(vectorsDir, `${name}.json`);
    const content = fs.readFileSync(filepath, "utf8");
    return JSON.parse(content) as VectorFile;
  };

  try {
    const report = await runConformance(loadVectorFile);
    return NextResponse.json(report);
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message, stack: err.stack },
      { status: 500 },
    );
  }
}

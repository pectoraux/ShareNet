/**
 * GET /api/integration-tests
 *
 * Runs the full ShareNet 2.0 integration test harness (14 scenarios that
 * exercise multiple SNP modules together) and returns the report as JSON.
 *
 * Each test is independent — no shared state, no implicit ordering. The
 * dashboard can display results in any order; running them sequentially here
 * just makes the first-failure easy to spot in logs.
 *
 * The response shape:
 *   {
 *     totalTests:   14,
 *     passed:       <count>,
 *     failed:       <count>,
 *     tests:        IntegrationTestResult[],
 *     generatedAt:  ISO timestamp
 *   }
 *
 * Tests are NOT Jest tests — they are plain async functions exported from
 * `@/lib/snp/integration-tests`. See the module JSDoc there for what each
 * test exercises.
 */

import { NextResponse } from "next/server";
import { runAllIntegrationTests } from "@/lib/snp/integration-tests";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const results = await runAllIntegrationTests();
    return NextResponse.json({
      totalTests: results.length,
      passed: results.filter((r) => r.passed).length,
      failed: results.filter((r) => !r.passed).length,
      tests: results,
      generatedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: err?.message ?? String(err),
        stack: err?.stack,
        generatedAt: new Date().toISOString(),
      },
      { status: 500 },
    );
  }
}

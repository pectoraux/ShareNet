/**
 * GET /api/rust-security
 *
 * Runs the N1.9 security tests and returns the results.
 * These tests prove:
 * 1. Directional AEAD keys prevent nonce reuse
 * 2. Relay cannot decrypt circuit payload (no circuit key)
 * 3. Tampering is detected (AEAD auth failure)
 * 4. DNS pinning connects to validated IP
 * 5. Redirect SSRF is rejected
 */

import { NextResponse } from "next/server";
import { execSync } from "node:child_process";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

export async function GET() {
  try {
    const cmd = `bash -c '. "$HOME/.cargo/env" && cd /home/z/my-project/reference && cargo test --test n19_security 2>&1'`;
    const output = execSync(cmd, {
      timeout: 25000,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    // Parse the test output
    const tests: Array<{ name: string; passed: boolean }> = [];
    const testPattern = /test (test_\w+) \.\.\. (ok|FAILED)/g;
    let match;
    while ((match = testPattern.exec(output)) !== null) {
      tests.push({
        name: match[1],
        passed: match[2] === "ok",
      });
    }

    const allPassed = tests.length > 0 && tests.every(t => t.passed);
    const passedCount = tests.filter(t => t.passed).length;
    const failedCount = tests.length - passedCount;

    // Map test names to descriptions
    const testDescriptions: Record<string, string> = {
      test_1_nonce_collision_directional_keys: "Nonce collision — directional keys prevent reuse",
      test_2_malicious_relay_cannot_decrypt_circuit_payload: "Malicious relay — cannot decrypt circuit payload",
      test_3_tampering_relay_gateway_rejects: "Tampering relay — gateway rejects modified ciphertext",
      test_4_dns_pinning_connects_to_validated_ip: "DNS pinning — connects to validated IP, not re-resolved",
      test_5_redirect_to_private_ip_not_followed: "Redirect SSRF — redirect to private IP not followed",
    };

    return NextResponse.json({
      allPassed,
      totalTests: tests.length,
      passed: passedCount,
      failed: failedCount,
      tests: tests.map(t => ({
        ...t,
        description: testDescriptions[t.name] || t.name,
      })),
      timestamp: new Date().toISOString(),
    });
  } catch (e: any) {
    return NextResponse.json(
      {
        error: e.message,
        hint: "Rust security tests may not be built. Run: . $HOME/.cargo/env && cd reference && cargo test --test n19_security",
      },
      { status: 500 },
    );
  }
}

#!/usr/bin/env bash
# ShareNet — CI architectural guard for N2.1.1.1 review-gate fixes #7 and #9.
#
# This script statically checks that production source code does NOT use:
#   - `TopologySnapshot` (deprecated — bundles remote_hints, unsafe for routing)
#   - `TopologyGraph::snapshot()` (deprecated — use snapshot_knowledge/executable)
#   - `TopologyGraph::new()` (private — use new_for_testing() in tests, open() in prod)
#   - `TopologyGraph::default()` / `Default::default::<TopologyGraph>()` (removed)
#
# Allowed locations:
#   - tests/ directories (test code may use deprecated APIs for migration)
#   - src/node/topology.rs (the definition itself)
#   - This script file
#
# Exit codes:
#   0 = no violations (clean)
#   1 = violations found (lists them)
#
# Run locally:  bash reference/scripts/architectural-guard.sh
# CI:          add as a `cargo test` prerequisite or a separate lint step.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIR="$REPO_ROOT/reference/snp-node/src"
TESTS_DIR="$REPO_ROOT/reference/snp-node/tests"

# Patterns that MUST NOT appear in production source (src/).
# (Test code in tests/ is allowed to use them for backward-compat migration.)
FORBIDDEN_IN_SRC=(
    # Deprecated snapshot types/methods (review-gate fix #7)
    'TopologySnapshot'
    '\.snapshot()'
    'snapshot\b.*TopologySnapshot'
    # Removed Default impl (review-gate fix #9)
    'TopologyGraph::default()'
    'Default::default::<TopologyGraph>'
    # Private constructor (review-gate fix #9) — only new_for_testing() is public
    'TopologyGraph::new()'
)

VIOLATIONS=0
REPORT=""

for pattern in "${FORBIDDEN_IN_SRC[@]}"; do
    # Search src/ (production code), excluding:
    #   - src/node/topology.rs (the definition itself — contains the deprecated
    #     impl + doc comments)
    #   - src/node/mod.rs (re-exports — the deprecated type is re-exported for
    #     backward compat; tests and migration code may still import it)
    #   - comment-only lines (// ...)
    matches=$(grep -rnE "$pattern" "$SRC_DIR" \
        --include="*.rs" \
        | grep -v "src/node/topology.rs:" \
        | grep -v "src/node/mod.rs:" \
        | grep -vE "^\s*[^:]*(\/\/|\*).*" \
        || true)
    if [ -n "$matches" ]; then
        VIOLATIONS=$((VIOLATIONS + 1))
        REPORT+=$'\n'"[VIOLATION] pattern '$pattern' in production source:"
        REPORT+=$'\n'"$matches"$'\n'
    fi
done

# Also check that new_for_testing() does NOT appear in production source
# (it's testing-only — review-gate fix #8). Allow the definition file itself.
matches=$(grep -rn "new_for_testing" "$SRC_DIR" --include="*.rs" \
    | grep -v "src/node/topology.rs:" \
    || true)
if [ -n "$matches" ]; then
    VIOLATIONS=$((VIOLATIONS + 1))
    REPORT+=$'\n'"[VIOLATION] new_for_testing() in production source (testing-only):"$'\n'"$matches"$'\n'
fi

# ───────────────────────────────────────────────────────────────────────
# N2.3 security gate: forbid unbounded snp_cbor::decode() in production
# source.
#
# Every network-facing CBOR decoder MUST use snp_cbor::decode_with_limits()
# with an explicit CborLimits profile, so an attacker-controlled wire message
# cannot force unbounded allocation at the CBOR head. The bare
# snp_cbor::decode() (which internally uses CborLimits::NONE = unbounded) is
# forbidden in production source.
#
# The pattern 'snp_cbor::decode(' (with the open paren) precisely matches the
# unbounded invocation and NOT 'snp_cbor::decode_with_limits('.
#
# Allowed locations (excluded from the scan):
#   - snp-cbor/src/         — the definition crate itself
#   - snp-conformance/src/  — golden-vector test harness (uses aliased decode)
#   - tests/ directories    — test code
#
# Inline #[cfg(test)] modules inside src/ must use
# decode_with_limits(.., &CborLimits::NONE) for trusted-local bytes.
# ───────────────────────────────────────────────────────────────────────
ALL_REFERENCE_SRC="$REPO_ROOT/reference"
WIRE_DECODE_MATCHES=$(grep -rnE 'snp_cbor::decode\(' "$ALL_REFERENCE_SRC" \
    --include="*.rs" \
    --exclude-dir="target" \
    | grep -v '/snp-cbor/src/' \
    | grep -v '/snp-conformance/src/' \
    | grep -v '/tests/' \
    || true)
if [ -n "$WIRE_DECODE_MATCHES" ]; then
    VIOLATIONS=$((VIOLATIONS + 1))
    REPORT+=$'\n'"[VIOLATION] unbounded snp_cbor::decode() in production source (N2.3 wire-decode gate):"$'\n'"$WIRE_DECODE_MATCHES"$'\n'
fi

# ───────────────────────────────────────────────────────────────────────
# N2.3 guard hardening: forbid importing snp_cbor::decode into scope.
#
# The textual rule above ('snp_cbor::decode(') catches direct invocations,
# but a future agent could bypass it with an import alias:
#
#     use snp_cbor::decode as unbounded_decode;
#     unbounded_decode(bytes)   // not caught by the 'snp_cbor::decode(' rule
#
# Once `decode` is imported into scope (aliased or not), every subsequent
# call is unbounded and invisible to the textual call-site check. So the
# import itself is forbidden, regardless of whether the imported name is
# ever called. The safe patterns `use snp_cbor::CborValue;`,
# `use snp_cbor::decode_with_limits;`, and
# `use snp_cbor::{CborValue, decode_with_limits};` are NOT matched.
#
# Matched forms (all forbidden in production src):
#   use snp_cbor::decode;
#   use snp_cbor::decode as <name>;
#   use snp_cbor::{decode};
#   use snp_cbor::{decode as <name>, ...};
#   use snp_cbor::{..., decode, ...};
#
# Same allowlist as above (snp-cbor definition, snp-conformance harness,
# tests/).
# ───────────────────────────────────────────────────────────────────────
DECODE_IMPORT_MATCHES=$(grep -rnE 'use[[:space:]]+snp_cbor::(\{[^}]*\bsnp_cbor)?\bdecode\b' "$ALL_REFERENCE_SRC" \
    --include="*.rs" \
    --exclude-dir="target" \
    | grep -vE 'decode_with_limits' \
    | grep -v '/snp-cbor/src/' \
    | grep -v '/snp-conformance/src/' \
    | grep -v '/tests/' \
    || true)
# The regex above may over-match `use snp_cbor::CborValue;`-style lines that
# happen to contain the substring 'decode' elsewhere; refine to lines whose
# imported path item is exactly 'decode' (optionally aliased). Use a precise
# second pass.
DECODE_IMPORT_MATCHES=$(grep -rnE 'use[[:space:]]+snp_cbor::' "$ALL_REFERENCE_SRC" \
    --include="*.rs" \
    --exclude-dir="target" \
    | grep -v '/snp-cbor/src/' \
    | grep -v '/snp-conformance/src/' \
    | grep -v '/tests/' \
    | grep -E '(::|\{|\s)[[:space:]]*decode[[:space:]]*(;|,|\}|[[:space:]]+as[[:space:]])' \
    | grep -vE 'decode_with_limits' \
    || true)
if [ -n "$DECODE_IMPORT_MATCHES" ]; then
    VIOLATIONS=$((VIOLATIONS + 1))
    REPORT+=$'\n'"[VIOLATION] import of snp_cbor::decode into scope (N2.3 wire-decode gate — would bypass the call-site check):"$'\n'"$DECODE_IMPORT_MATCHES"$'\n'
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "========================================" >&2
    echo "ARCHITECTURAL GUARD: $VIOLATIONS violation(s) found" >&2
    echo "========================================" >&2
    echo "$REPORT" >&2
    echo "" >&2
    echo "Production source (src/) must not use:" >&2
    echo "  - TopologySnapshot (deprecated — use TopologyKnowledgeSnapshot or ExecutableNetworkSnapshot)" >&2
    echo "  - TopologyGraph::snapshot() (deprecated — use snapshot_knowledge() or snapshot_executable())" >&2
    echo "  - TopologyGraph::default() (removed — use open(path))" >&2
    echo "  - TopologyGraph::new() (private — use new_for_testing() in tests, open() in prod)" >&2
    echo "  - new_for_testing() (testing-only — production uses open(path))" >&2
    echo "  - snp_cbor::decode() (N2.3 gate — network decoders must use decode_with_limits())" >&2
    echo "  - importing snp_cbor::decode into scope, aliased or not (N2.3 gate hardening)" >&2
    exit 1
fi

echo "[OK] architectural-guard: no forbidden API usage in production source."
exit 0

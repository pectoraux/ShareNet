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
    exit 1
fi

echo "[OK] architectural-guard: no forbidden API usage in production source."
exit 0

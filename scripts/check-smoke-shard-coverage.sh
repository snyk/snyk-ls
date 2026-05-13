#!/usr/bin/env bash
# Pre-push hook: verify that every smoke test function in application/server/
# is matched by at least one shard pattern in .github/workflows/build.yaml.
#
# Run manually: bash scripts/check-smoke-shard-coverage.sh
# Installed via: make hooks  (pre-commit install --hook-type pre-push)
set -e

# Combined regex of all named-shard run-patterns.
# Keep in sync with the smoke-tests matrix in .github/workflows/build.yaml.
# The 'other' shard is intentionally omitted — it catches the remainder.
PATTERNS='Test_SmokeWorkspaceScan|Test_SmokeIssueCaching|Test_SmokeScanUnmanaged|Test_SmokeLegacyRoutingUnmanagedWithRiskScore|Test_SmokeSnykCode|Test_SmokePreScanCommand|Test_SmokeExecuteCLICommand|Test_SmokeInstanceTest|Test_SmokeUncFilePath|Test_SmokePrecedence|Test_SmokeScanPrecedence|Test_SmokeOrgSelection|Test_SmokeLdxSync|Test_SmokeSecrets|Test_Invalid|TestUnifiedTestApiSmokeTest|Test_SmokeConfig|Test_SmokeTreeView'

# Extract every test function name from smoke test files.
# smoke_main_test.go is excluded — it contains shared-state helpers, not feature tests.
TESTS=$(grep -rh 'func Test' application/server/ --include='*_smoke_test.go' \
        | grep -v smoke_main_test \
        | grep -oE 'Test[A-Za-z0-9_]+' || true)

if [ -z "$TESTS" ]; then
    echo "ℹ️  No smoke test functions found — skipping shard coverage check."
    exit 0
fi

UNCOVERED=()
while IFS= read -r test; do
    echo "$test" | grep -qE "$PATTERNS" || UNCOVERED+=("$test")
done <<< "$TESTS"

if [ ${#UNCOVERED[@]} -gt 0 ]; then
    echo "❌ Smoke tests not covered by any named shard in .github/workflows/build.yaml:"
    printf '   %s\n' "${UNCOVERED[@]}"
    echo ""
    echo "   Add them to a shard pattern, or they will only run in the 'other' catch-all shard."
    echo "   Update PATTERNS in scripts/check-smoke-shard-coverage.sh to match."
    # Exit 0: the 'other' shard will still run them. This is a warning, not a blocker.
    exit 0
fi

COUNT=$(echo "$TESTS" | grep -c .)
echo "✅ All $COUNT smoke tests are covered by named shard patterns."

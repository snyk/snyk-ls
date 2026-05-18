#!/usr/bin/env bash
# Pre-push hook: verify that the required test stages have been recorded for
# the current HEAD commit. Adapted from ldx-sync/scripts/tests-run-commit-hook.sh.
#
# Stage list coupling: REQUIRED_STAGES and smoke shard stage names here must stay
# in sync with the Makefile _save-test-hash targets (make test, make test-all,
# _smoke-shard-N, test-smoke-parallel). Update both files when adding a new stage.
set -e

HASH_FILE=".tests-hash"
REQUIRED_STAGES=("test" "test-integ")   # block push if stale
SMOKE_STAGE="test-smoke"
SMOKE_SHARD_STAGES=("test-smoke-shard-1" "test-smoke-shard-2" "test-smoke-shard-3" "test-smoke-shard-4")
ADVISORY_STAGES=()                     # warn only — takes 30-90 min

stored_hash_for_stage() {
    grep "^${1}=" "$HASH_FILE" 2>/dev/null | cut -d'=' -f2 | head -1 || true
}

# Smoke is satisfied when the full suite was recorded, or each shard passed at HEAD.
smoke_satisfied() {
    local stored
    stored=$(stored_hash_for_stage "$SMOKE_STAGE")
    if [ -n "$stored" ] && [ "$stored" = "$current_hash" ]; then
        return 0
    fi
    for shard in "${SMOKE_SHARD_STAGES[@]}"; do
        stored=$(stored_hash_for_stage "$shard")
        if [ -z "$stored" ] || [ "$stored" != "$current_hash" ]; then
            return 1
        fi
    done
    return 0
}

# Determine upstream ref; default to origin/<current-branch> if the tracking branch is unset.
UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || echo "origin/$(git branch --show-current)")

# If the upstream ref is not reachable locally (e.g. first push on a new branch),
# enforce rather than skip — that is the riskiest push moment.
if ! git rev-parse --verify "$UPSTREAM" >/dev/null 2>&1; then
    RELEVANT_CHANGED=1
else
    # Include JS/JSON (test-js suite), Makefile, and CI/pre-commit config alongside Go source and modules.
    RELEVANT_CHANGED=$(git diff --name-only "$UPSTREAM"...HEAD 2>/dev/null | grep -cE '\.go$|^go\.(mod|sum)$|\.js$|\.json$|^Makefile$|\.ya?ml$|\.xml$|\.gradle(\.kts)?$|\.html$' || true)
fi

if [ "${RELEVANT_CHANGED:-1}" -eq 0 ]; then
    echo "ℹ️  No Go source files changed in unpushed commits. Skipping test requirements."
    exit 0
fi

current_hash=$(git rev-parse HEAD)

if [ ! -f "$HASH_FILE" ]; then
    echo "❌ No test stages have been recorded for the current commit."
    echo "   Run the following before pushing:"
    echo "   make test"
    echo "   INTEG_TESTS=1 make test   (or: make test-all)"
    exit 1
fi

missing=()
outdated=()

for stage in "${REQUIRED_STAGES[@]}"; do
    # head -1 guards against duplicate entries left by an interrupted _save-test-hash
    stored=$(stored_hash_for_stage "$stage")
    if [ -z "$stored" ]; then
        missing+=("$stage")
    elif [ "$stored" != "$current_hash" ]; then
        outdated+=("$stage")
    fi
done

blocked=0

if [ ${#missing[@]} -gt 0 ]; then
    echo "❌ Test stages not yet run at current commit:"
    for s in "${missing[@]}"; do
        echo "   make $s"
    done
    blocked=1
fi

if [ ${#outdated[@]} -gt 0 ]; then
    echo "❌ Commits since these stages last ran:"
    for s in "${outdated[@]}"; do
        echo "   make $s"
    done
    blocked=1
fi

if ! smoke_satisfied; then
    echo "❌ Smoke tests not recorded for current commit:"
    stored=$(stored_hash_for_stage "$SMOKE_STAGE")
    if [ -n "$stored" ] && [ "$stored" != "$current_hash" ]; then
        echo "   make test-smoke-parallel   (or: make test-smoke / make test-smoke-serial)"
    elif [ -z "$stored" ]; then
        shard_issues=0
        for i in 1 2 3 4; do
            shard_stage="test-smoke-shard-${i}"
            shard_stored=$(stored_hash_for_stage "$shard_stage")
            if [ -z "$shard_stored" ]; then
                echo "   make _smoke-shard-${i}"
                shard_issues=1
            elif [ "$shard_stored" != "$current_hash" ]; then
                echo "   make _smoke-shard-${i}   (outdated since last commit)"
                shard_issues=1
            fi
        done
        if [ "$shard_issues" -eq 0 ]; then
            echo "   make test-smoke-parallel   (or: make test-smoke / make test-smoke-serial)"
        else
            echo "   Or run all shards: make test-smoke-parallel"
        fi
    fi
    blocked=1
fi

for stage in "${ADVISORY_STAGES[@]}"; do
    stored=$(stored_hash_for_stage "$stage")
    if [ -z "$stored" ] || [ "$stored" != "$current_hash" ]; then
        echo "⚠️  Smoke tests not recorded for current commit (advisory — not blocking)."
        echo "   To record: SMOKE_TESTS=1 make test   (or: make test-all)"
    fi
done

[ "$blocked" -eq 1 ] && exit 1

echo "✅ All required test stages passed at commit $(git rev-parse --short HEAD)."

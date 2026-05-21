#!/usr/bin/env bash
# Pre-push hook: verify that the required test stages have been recorded for
# the current HEAD commit. Adapted from ldx-sync/scripts/tests-run-commit-hook.sh.
#
# Stage list coupling: REQUIRED_STAGES and ADVISORY_STAGES here must stay in sync
# with the stages written by the Makefile _save-test-hash target (make test,
# make test-all). Update both files when adding a new stage.
set -e

HASH_FILE=".tests-hash"
REQUIRED_STAGES=("test")                                          # block push if stale
ADVISORY_STAGES=("test-integ" "test-smoke")                       # warn only — takes 30-90 min

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
    stored=$(grep "^${stage}=" "$HASH_FILE" 2>/dev/null | cut -d'=' -f2 | head -1 || true)
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

for stage in "${ADVISORY_STAGES[@]}"; do
    stored=$(grep "^${stage}=" "$HASH_FILE" 2>/dev/null | cut -d'=' -f2 | head -1 || true)
    if [ -z "$stored" ] || [ "$stored" != "$current_hash" ]; then
        echo "⚠️  $stage not recorded for current commit (advisory — not blocking)."
        echo "   To record: make $stage"
    fi
done

[ "$blocked" -eq 1 ] && exit 1

echo "✅ All required test stages passed at commit $(git rev-parse --short HEAD)."

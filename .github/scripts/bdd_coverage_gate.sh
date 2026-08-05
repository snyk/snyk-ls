#!/usr/bin/env bash
#
# bdd_coverage_gate.sh
#
# Enforces that PRs introducing behaviour also update the BDD suite under
# features/*.feature. See CONTRIBUTING.md's BDD section for the `# maps:`
# anchor convention and when a scenario is expected.
#
#   feat: commits with no features/*.feature change -> hard fail.
#   fix:  commits with no features/*.feature change -> warning only.
#
# Scoped to feat:/fix: only, not every conventional-commit type. Hard-failing
# every commit type would impose a repo-wide policy off the back of one
# ticket; that is the team's call to widen later, not this gate's.
set -euo pipefail

BASE_REF="${BDD_GATE_BASE_REF:-origin/main}"
HEAD_REF="${BDD_GATE_HEAD_REF:-HEAD}"

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  echo "bdd_coverage_gate: cannot resolve base ref '$BASE_REF' (shallow checkout?) — skipping."
  exit 0
fi

changed_files="$(git diff --name-only "$BASE_REF...$HEAD_REF")"
feature_changed=false
if echo "$changed_files" | grep -q '^features/.*\.feature$'; then
  feature_changed=true
fi

commit_subjects="$(git log --format=%s "$BASE_REF..$HEAD_REF")"

hard_fail=false
while IFS= read -r subject; do
  [ -z "$subject" ] && continue
  if echo "$subject" | grep -qE '^feat(\(.+\))?!?:'; then
    if [ "$feature_changed" = false ]; then
      echo "ERROR: commit \"$subject\" is feat: but this PR changes no features/*.feature file."
      hard_fail=true
    fi
  elif echo "$subject" | grep -qE '^fix(\(.+\))?!?:'; then
    if [ "$feature_changed" = false ]; then
      echo "WARNING: commit \"$subject\" is fix: with no features/*.feature change. Consider adding a scenario."
    fi
  fi
done <<< "$commit_subjects"

if [ "$hard_fail" = true ]; then
  echo "bdd_coverage_gate: at least one feat: commit adds no feature-file coverage."
  exit 1
fi

echo "bdd_coverage_gate: OK"

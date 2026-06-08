#!/bin/bash
#
# © 2024 Snyk Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Distributes shared_ide_resources/ui/html/settings-fallback.html from snyk-ls
# to all configured IDE repositories by opening a PR in each target repo.
#
# Each IDE repo already has a resource-check CI workflow that verifies this file
# matches the snyk-ls main branch copy. This script keeps them in sync proactively.
#
# Required env vars:
#   GH_TOKEN - GitHub PAT with write access to all target repos (use TEAM_IDE_PAT)
#              Minimum required scopes: contents:write, pull_requests:write
#
# Usage: Run from the snyk-ls repository root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SOURCE_FILE="$REPO_ROOT/shared_ide_resources/ui/html/settings-fallback.html"
[[ -f "$SOURCE_FILE" ]] || { echo "ERROR: source file not found: $SOURCE_FILE"; exit 1; }

LS_SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
LS_SHA_FULL=$(git -C "$REPO_ROOT" rev-parse HEAD)

BRANCH="chore/sync-settings-fallback-html"
COMMIT_MSG="chore: sync settings-fallback.html from snyk-ls@${LS_SHA}"
PR_TITLE="chore: sync settings-fallback.html from snyk-ls"

# Map: "owner/repo" -> "path/in/repo"
# Destination paths are taken from each repo's .github/workflows/resource-check.yml
declare -A TARGETS
TARGETS["snyk/vscode-extension"]="media/views/common/configuration/settings-fallback.html"
TARGETS["snyk/snyk-intellij-plugin"]="src/main/resources/html/settings-fallback.html"
TARGETS["snyk/snyk-eclipse-plugin"]="plugin/src/main/resources/ui/html/settings-fallback.html"
TARGETS["snyk/snyk-visual-studio-plugin"]="Snyk.VisualStudio.Extension.2022/Resources/settings-fallback.html"

FAILED=()

# Single parent temp dir — one EXIT trap covers all per-repo clones.
PARENT_WORK=$(mktemp -d)
trap "rm -rf '$PARENT_WORK'" EXIT

gh auth setup-git

# process_repo clones the target repo, copies the file, and opens/updates a PR.
# Called as: process_repo "$REPO" "$DEST_PATH" || FAILED+=("$REPO")
# Any unguarded failure inside causes the function to exit non-zero, which the
# caller catches via ||. This gives consistent error collection across all repos.
process_repo() {
  local REPO="$1"
  local DEST_PATH="$2"

  echo ""
  echo "==> $REPO : $DEST_PATH"

  local REPO_SLUG
  REPO_SLUG="$(echo "$REPO" | tr '/' '_')"
  local WORK_DIR="$PARENT_WORK/$REPO_SLUG"

  gh repo clone "$REPO" "$WORK_DIR" -- --depth=1 --quiet

  local DEST_FULL="$WORK_DIR/$DEST_PATH"
  mkdir -p "$(dirname "$DEST_FULL")"
  # Abort early if the destination path is git-ignored in the target repo.
  if git -C "$WORK_DIR" check-ignore -q "$DEST_PATH" 2>/dev/null; then
    echo "    ERROR: $DEST_PATH is git-ignored in $REPO — distribution cannot proceed"
    return 1
  fi

  cp "$SOURCE_FILE" "$DEST_FULL"

  # Detect changes (covers both modified and new files)
  if [[ -z "$(git -C "$WORK_DIR" status --porcelain "$DEST_PATH")" ]]; then
    echo "    No changes — already up to date, skipping."
    return 0
  fi

  git -C "$WORK_DIR" config user.email "team-ide@snyk.io"
  git -C "$WORK_DIR" config user.name "Snyk Team IDE"
  git -C "$WORK_DIR" checkout -B "$BRANCH"
  git -C "$WORK_DIR" add "$DEST_PATH"
  git -C "$WORK_DIR" commit -m "$COMMIT_MSG"
  # Design decision: this branch is exclusively owned by this automation.
  # Force-push is intentional — any human commits on the sync branch will be
  # overwritten. Reviewers should not push changes directly to this branch.
  git -C "$WORK_DIR" push -f -u origin "$BRANCH"

  local PR_BODY
  PR_BODY="Automatic sync of \`settings-fallback.html\` triggered by [snyk/snyk-ls@${LS_SHA}](https://github.com/snyk/snyk-ls/commit/${LS_SHA_FULL}).

This PR was opened by the [distribute-fallback-html](https://github.com/snyk/snyk-ls/blob/main/.github/workflows/distribute-fallback-html.yaml) workflow in snyk-ls.

## What changed

\`settings-fallback.html\` is the settings page displayed before the Language Server binary is available. It is maintained in [snyk/snyk-ls](https://github.com/snyk/snyk-ls) and must be kept in sync with the copy in each IDE plugin. This repo's \`resource-check\` CI workflow verifies that the local copy matches the snyk-ls main branch; this PR restores that sync.

## Merge instructions

Review and merge when ready. No manual testing is required beyond confirming that \`resource-check\` passes on this PR."

  # jq '// empty' converts a JSON null (no results) to empty string without
  # masking real errors — a non-zero exit from gh pr list still propagates.
  local EXISTING_PR
  EXISTING_PR=$(gh pr list --repo "$REPO" --head "$BRANCH" --state open --json number --jq '.[0].number // empty')
  if [[ -z "$EXISTING_PR" ]]; then
    echo "    Creating PR in $REPO"
    gh pr create \
      --repo "$REPO" \
      --base main \
      --head "$BRANCH" \
      --title "$PR_TITLE" \
      --body "$PR_BODY"
  else
    echo "    Updating existing PR #$EXISTING_PR in $REPO"
    gh pr edit "$EXISTING_PR" --repo "$REPO" --body "$PR_BODY"
  fi

  echo "    Done."
}

for REPO in "${!TARGETS[@]}"; do
  DEST_PATH="${TARGETS[$REPO]}"
  process_repo "$REPO" "$DEST_PATH" || FAILED+=("$REPO")
done

echo ""
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "ERROR: the following targets failed:"
  for f in "${FAILED[@]}"; do
    echo "  - $f"
  done
  exit 1
fi

echo "All targets processed successfully."

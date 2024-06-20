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

set -ex

CLI_DIR=$(mktemp -d)
gh repo clone git@github.com:snyk/cli.git $CLI_DIR -- --depth=1
pushd "$CLI_DIR/cliv2"
  LS_COMMIT_HASH=$(grep snyk-ls go.mod| cut -d "-" -f 4)
popd

WHAT_CHANGED=$(git whatchanged "$LS_COMMIT_HASH"...HEAD)
BODY=$(printf "## Changes since last integration of Language Server\n\n\`\`\`\n%s\n\`\`\`" "$WHAT_CHANGED")

pushd $CLI_DIR
  UPGRADE=$(go run scripts/upgrade-snyk-go-dependencies.go --name=snyk-ls)
  LS_VERSION=$(echo $UPGRADE | sed 's/.*Sha: \(.*\) URL.*/\1/')
  BRANCH=feat/automatic-upgrade-of-ls
  git checkout -b $BRANCH

  git config --global user.email "team-ide@snyk.io"
  git config --global user.name "Snyk Team IDE"
  git config --global gpg.format ssh
  git config --global commit.gpgsign true

  echo $PUB_SIGNING_KEY > signingkey.pub
  git config --global user.signingkey ./signingkey.pub

  git commit -am "feat: automatic integration of language server $LS_VERSION"
  git push -f --set-upstream origin $BRANCH

  TITLE="feat(language-server): integrate LS"
  PR=$(gh pr list --search "$TITLE" 2>&1 | grep -e "$TITLE" | cut -f1)
  if [[ ! $PR  ]]; then
    echo "Creating new PR"
    gh pr create --repo github.com/snyk/cli --base main --head $BRANCH --title "$TITLE" --body "$BODY"
  elif
    gh pr edit $PR --repo github.com/snyk/cli --body "$BODY"
  fi
  gh pr merge -m --auto
popd

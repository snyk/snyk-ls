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

#!/bin/bash
set -ex

CLI_DIR=$(mktemp -d)
git clone --depth 1 https://github.com/snyk/cli $CLI_DIR
pushd $CLI_DIR
  UPGRADE=$(go run scripts/upgrade-snyk-go-dependencies.go --name=snyk-ls)
  LS_VERSION=$(echo $UPGRADE | sed 's/.*Sha: \(.*\) URL.*/\1/')
  BRANCH=feat/automatic-upgrade-of-ls-to-$LS_VERSION
  git checkout -b $BRANCH

  git config --global user.email "team-ide-user@snyk.io"
  git config --global user.name "Snyk Team IDE User"

  git commit -am "feat: automatic integration of language server $LS_VERSION"
#  git push --set-upstream origin $BRANCH
  COMMIT_HASH=$(git log --pretty=tformat:"%h" -n1 .)
  gh pr create --repo github.com/snyk/cli --dry-run --base main --fill-verbose --head $COMMIT_HASH --title "feat(language-server): integrate LS (automatic PR) ($LS_VERSION)" --body "$(echo $UPGRADE | sed 's/.*Message: \(.*\) URL.*$/\1/')"
popd

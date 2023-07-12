#!/usr/bin/env bash
#
# © 2023 Snyk Limited
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

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# shellcheck disable=SC2002
VERSION=${VERSION:-$(cat "$SCRIPT_DIR/../build/metadata.json" | jq -r .version)}
PROTOCOL_VERSION=$(grep "LS_PROTOCOL_VERSION" "$SCRIPT_DIR/../.goreleaser.yaml" | tail -1 | cut -f2 -d "=" | xargs)
BASE_URL="https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION"


AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_S3_BUCKET_NAME="${AWS_S3_BUCKET_NAME:-snyk-test}"
if [ -z "$VERSION" ]; then
  echo "VERSION is not set"
  exit 1
fi

DRY_RUN=
if [ $# -gt 0 ]; then
  DRY_RUN=--dryrun
fi

function copyOrDownloadToTemp() {
  FILENAME_SRC=$1
  FILENAME_DST=$2
  DRY_RUN=${3:-}

  if [ -z "$DRY_RUN" ] ; then
      curl --compressed --output "/tmp/$FILENAME_DST" "$BASE_URL/$FILENAME_DST"
    else
      cp "$FILENAME_SRC" "/tmp/$FILENAME_DST"
    fi
}

function uploadFile() {
  FILENAME_SRC=$1
  FILENAME_DST=$2
  DRY_RUN=${3:-}
  # shellcheck disable=SC2086
  aws s3 cp $DRY_RUN "$FILENAME_SRC" "s3://$AWS_S3_BUCKET_NAME/snyk-ls/$PROTOCOL_VERSION/$FILENAME_DST"
}

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_windows_amd64_v1/snyk-ls.exe"
  FILENAME_DST="snyk-ls_${VERSION}_windows_amd64.exe"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_linux_amd64_v1/snyk-ls"
  FILENAME_DST="snyk-ls_${VERSION}_linux_amd64"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_darwin_arm64/snyk-ls"
  FILENAME_DST="snyk-ls_${VERSION}_darwin_arm64"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_darwin_amd64_v1/snyk-ls"
  FILENAME_DST="snyk-ls_${VERSION}_darwin_amd64"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_linux_386/snyk-ls"
  FILENAME_DST="snyk-ls_${VERSION}_linux_386"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_linux_arm64/snyk-ls"
  FILENAME_DST="snyk-ls_${VERSION}_linux_arm64"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_windows_386/snyk-ls.exe"
  FILENAME_DST="snyk-ls_${VERSION}_windows_386.exe"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp $FILENAME_SRC "$FILENAME_DST" $DRY_RUN

  # publish shasums
  FILENAME_SRC="$SCRIPT_DIR/../build/snyk-ls_${VERSION}_SHA256SUMS"
  FILENAME_DST="snyk-ls_${VERSION}_SHA256SUMS"
  # shellcheck disable=SC2086
  uploadFile $FILENAME_SRC $FILENAME_DST $DRY_RUN
  copyOrDownloadToTemp "$FILENAME_SRC" "$FILENAME_DST" $DRY_RUN

  # check shasums against downloaded/copied files
  pushd /tmp
    sha256sum -c "$FILENAME_DST"
  popd

  # publish metadata
  # shellcheck disable=SC2086
  FILENAME_SRC="$SCRIPT_DIR/../build/metadata.json"
  FILENAME_DST=metadata.json
  uploadFile "$FILENAME_SRC" "$FILENAME_DST" $DRY_RUN
  copyOrDownloadToTemp "$FILENAME_SRC" "$FILENAME_DST" $DRY_RUN
  diff "$FILENAME_SRC" "/tmp/$FILENAME_DST"

#!/bin/bash
#
# © 2022 Snyk Limited All rights reserved.
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

# This file allows to download the latest language server, which is helpful for integration into non-managed Editors and IDEs.
# Currently, these might be NeoVIM, Sublime Text or Atom, but any editor that hasn't got a downloader built by us needs to download
# and update the language server regularly, and this script allows this for system administrators and users.

set -e
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
if [[ $ARCH == "x86_64" ]]; then
  ARCH="amd64"
elif [[ $ARCH == "aarch64" ]] || [[ $ARCH == "arm64" ]]; then
  ARCH="arm64"
else
  ARCH="386"
fi

PROTOCOL_VERSION=$(grep "LS_PROTOCOL_VERSION" .goreleaser.yaml | tail -1 | cut -f2 -d "=" |xargs)
VERSION=$(curl -sSL --compressed https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/metadata.json | jq .version | sed -e s/\"//g)
DESTINATION="/usr/local/bin/snyk-ls"
DOWNLOAD_URL="https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/snyk-ls_${VERSION}_${OS}_${ARCH}"

set +e
if [[ -f $DESTINATION ]]; then
  LS_VERSION=$($DESTINATION -v | xargs)
  echo "Snyk Language Server ($LS_VERSION) is already installed at $DESTINATION"
  mv -f $DESTINATION "$DESTINATION.$LS_VERSION"
else
  touch $DESTINATION
fi

# shellcheck disable=SC2181
if [[ $? -gt 0 ]]; then
  echo "$DESTINATION not writable, using $PWD as destination path"
  DESTINATION="$PWD/snyk-ls"
fi
set -e

echo
echo "OS: $OS"
echo "Architecture: $ARCH"
echo "Protocol Version: $PROTOCOL_VERSION"
echo "Language Server version: $VERSION"
echo "Destination Path: $DESTINATION"
echo
echo "Downloading from $DOWNLOAD_URL and installing to $DESTINATION"
echo
curl -L --compressed "$DOWNLOAD_URL" > "$DESTINATION"
chmod +x "$DESTINATION"
echo
echo "✨🎉 Snyk Language Server $VERSION installed to $DESTINATION."


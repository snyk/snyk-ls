#!/bin/bash
#
# Copyright 2022 Snyk Ltd.
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

set -ex
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
if [[ $ARCH == "x86_64" ]]; then
  ARCH="amd64"
fi
if [[ $ARCH == "aarch64" ]]; then
  ARCH="arm64"
fi
PROTOCOL_VERSION=$(grep "LS_PROTOCOL_VERSION" .goreleaser.yaml | tail -1 | cut -f2 -d "=" |xargs)
VERSION=$(curl https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/metadata.json | jq .version | sed -e s/\"//g)
wget -O /usr/local/bin/snyk-ls "https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/snyk-ls_${VERSION}_${OS}_${ARCH}"

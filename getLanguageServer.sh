#!/bin/bash
# This file allows to download the latest language server, which is helpful for integration into non-managed Editors and IDEs.
# Currently, these might be NeoVIM, Sublime Text or Atom, but any editor that hasn't got a downloader built by us needs to download
# and update the language server regularly, and this script allows this for system administrators and users.

set -ex
ARCH=darwin_arm64
PROTOCOL_VERSION=$(grep "LS_PROTOCOL_VERSION" .goreleaser.yaml | tail -1 | cut -f2 -d "=" |xargs)
VERSION=$(curl https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/metadata.json | jq .version | sed -e s/\"//g)
wget -O /usr/local/bin/snyk-ls "https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/snyk-ls_${VERSION}_${ARCH}"

#!/bin/bash
set -ex
ARCH=darwin_arm64
PROTOCOL_VERSION=$(grep "LS_PROTOCOL_VERSION" .goreleaser.yaml | tail -1 | cut -f2 -d "=" |xargs)
VERSION=$(curl https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/metadata.json | jq .version | sed -e s/\"//g)
wget -O /usr/local/bin/snyk-ls "https://static.snyk.io/snyk-ls/$PROTOCOL_VERSION/snyk-ls_${VERSION}_${ARCH}"

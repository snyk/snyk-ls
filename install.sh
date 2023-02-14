#!/bin/bash -e
#
# Usage:
#   $ curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh | bash
# or
#   $ wget -q https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh -O- | bash
#

case $(uname -sm) in
  'Linux x86_64')
    os='linux-x86_64'
    ;;
  'Darwin x86' | 'Darwin x86_64' | 'Darwin arm64')
    os='osx'
    ;;
  *)
  echo "Sorry, you'll need to install the pact-ruby-standalone manually."
  exit 1
    ;;
esac

tag=$(basename $(curl -fs -o/dev/null -w %{redirect_url} https://github.com/pact-foundation/pact-ruby-standalone/releases/latest))
filename="pact-${tag#v}-${os}.tar.gz"

curl -LO https://github.com/pact-foundation/pact-ruby-standalone/releases/download/${tag}/${filename}
tar xzf ${filename}
rm ${filename}


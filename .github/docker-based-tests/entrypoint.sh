#!/bin/bash
set -ex

echo "Starting squid..."
sudo squid -f /etc/squid/squid.conf -NYCd 1 &
## configure firewall to only work through proxy
sudo iptables -A OUTPUT -m owner --uid-owner root -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j REJECT
sudo iptables -A OUTPUT -p tcp --dport 443 -j REJECT
sleep 5 # wait for squid to startup
make tools
export PATH=$PATH:$PWD/.bin/pact/bin:$PWD/.bin/
exec "$@"

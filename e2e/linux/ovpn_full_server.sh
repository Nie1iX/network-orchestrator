#!/bin/sh
# Second OpenVPN peer, sharing synthetic PKI with ovpn_server.sh.
set -eu
umask 077
cd /run/ovpn-e2e

cat >server-full.conf <<'EOF'
local 198.18.0.2
port 1195
proto udp4
dev ovpn-full
dev-type tun
topology subnet
server 10.79.0.0 255.255.255.0
ca /run/ovpn-e2e/ca.crt
cert /run/ovpn-e2e/server.crt
key /run/ovpn-e2e/server.key
dh none
data-ciphers AES-256-GCM
keepalive 2 10
persist-tun
push "redirect-gateway def1"
push "dhcp-option DNS 10.79.0.1"
verb 3
EOF

ip addr add 198.18.0.2/32 dev lo
openvpn --config server-full.conf --disable-dco \
    --log /run/ovpn-e2e/server-full.log --daemon

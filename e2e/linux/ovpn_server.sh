#!/bin/sh
# Synthetic OpenVPN peer for the disposable E2E server container.
set -eu
umask 077
mkdir -p /run/ovpn-e2e
cd /run/ovpn-e2e

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj /CN=netorch-e2e-ca -keyout ca.key -out ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj /CN=netorch-e2e-server -keyout server.key -out server.csr >/dev/null 2>&1
printf '%s\n' 'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' >server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -sha256 -extfile server.ext -out server.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj /CN=netorch-e2e-client -keyout client.key -out client.csr >/dev/null 2>&1
printf '%s\n' 'keyUsage=digitalSignature' \
    'extendedKeyUsage=clientAuth' >client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 1 -sha256 -extfile client.ext -out client.crt >/dev/null 2>&1

cat >server.conf <<'EOF'
port 1194
proto udp4
dev ovpn-srv
dev-type tun
topology subnet
server 10.78.0.0 255.255.255.0
ca /run/ovpn-e2e/ca.crt
cert /run/ovpn-e2e/server.crt
key /run/ovpn-e2e/server.key
dh none
data-ciphers AES-256-GCM
keepalive 2 10
persist-tun
push "route 192.168.77.0 255.255.255.0"
verb 3
EOF

ip addr add 192.168.77.1/32 dev lo
openvpn --config server.conf --disable-dco --log /run/ovpn-e2e/server.log --daemon

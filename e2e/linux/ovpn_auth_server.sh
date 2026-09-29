#!/bin/sh
# Start a separate auth-required peer using the CA from ovpn_server.sh.
set -eu
umask 077
cd /run/ovpn-e2e

printf '%s\n' 'correct-key' > client-key-pass
openssl pkey -in client.key -aes-256-cbc \
    -passout file:client-key-pass -out client-encrypted.key >/dev/null 2>&1

cat > server-auth.conf <<'EOF'
port 1196
proto udp4
dev ovpn-auth
dev-type tun
topology subnet
server 10.80.0.0 255.255.255.0
ca /run/ovpn-e2e/ca.crt
cert /run/ovpn-e2e/server.crt
key /run/ovpn-e2e/server.key
dh none
data-ciphers AES-256-GCM
script-security 2
auth-user-pass-verify /opt/netorch/e2e/ovpn_auth_verify.sh via-file
keepalive 2 10
persist-tun
push "route 192.168.77.0 255.255.255.0"
verb 3
EOF

openvpn --config server-auth.conf --disable-dco --log /run/ovpn-e2e/server-auth.log --daemon

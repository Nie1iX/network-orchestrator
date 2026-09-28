#!/bin/sh
# Linux E2E harness (S2). Builds the daemon, boots disposable Ubuntu 26.04
# client/server containers on a private Docker network, installs the daemon
# as a package would and runs scenarios.sh in the client. Network mutations
# happen only in the containers' own namespaces.
#
# Requirements: docker. Needs CAP_SYS_ADMIN + apparmor=unconfined for systemd
# (cgroup remount) — dev machine / CI only.
#
# Usage: e2e/linux/run.sh [--keep]   (--keep leaves the container running)
#        E2E_DISTRO=fedora e2e/linux/run.sh   (Fedora 44 client, Ubuntu peer)
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_IMAGE=netorch-e2e-client
case "${E2E_DISTRO:-ubuntu}" in
    ubuntu) IMAGE=$SERVER_IMAGE; DOCKERFILE=Dockerfile ;;
    fedora) IMAGE=netorch-e2e-client-fedora; DOCKERFILE=Dockerfile.fedora ;;
    *) echo "unknown E2E_DISTRO: $E2E_DISTRO" >&2; exit 2 ;;
esac
NAME=netorch-e2e-$$
SERVER=netorch-e2e-server-$$
NETWORK=netorch-e2e-net-$$
KEEP=${1:-}

echo "==> Building daemon (release)"
(cd "$REPO_ROOT" && cargo build --release -p network-orchestrator-daemon)

echo "==> Building images $SERVER_IMAGE, $IMAGE"
docker build -q -t "$SERVER_IMAGE" "$REPO_ROOT/e2e/linux" >/dev/null
docker build -q -t "$IMAGE" -f "$REPO_ROOT/e2e/linux/$DOCKERFILE" "$REPO_ROOT/e2e/linux" >/dev/null

cleanup() {
    if [ "$KEEP" = "--keep" ]; then
        echo "containers kept: docker exec -it $NAME bash"
        echo "remove with: docker rm -f $NAME $SERVER; docker network rm $NETWORK"
    else
        docker rm -f "$NAME" >/dev/null 2>&1 || true
        docker rm -f "$SERVER" >/dev/null 2>&1 || true
        docker network rm "$NETWORK" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Starting isolated peer on $NETWORK"
docker network create "$NETWORK" >/dev/null
docker run -d --name "$SERVER" --network "$NETWORK" --network-alias wg-server \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$REPO_ROOT/e2e/linux:/opt/netorch/e2e:ro" \
    --entrypoint python3 "$SERVER_IMAGE" \
    -m http.server 8765 --bind 0.0.0.0 --directory /opt/netorch/e2e >/dev/null

echo "==> Starting $NAME"
docker run -d --name "$NAME" --network "$NETWORK" -e container=docker \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --device /dev/net/tun --tmpfs /run --tmpfs /run/lock --cgroupns=private \
    -v "$REPO_ROOT/target/release/network-orchestrator-daemon:/opt/netorch/bin/network-orchestrator-daemon:ro" \
    -v "$REPO_ROOT/packaging/linux:/opt/netorch/packaging:ro" \
    -v "$REPO_ROOT/e2e/linux:/opt/netorch/e2e:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 60); do
    state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 0.5
done
echo "    systemd: $state"

echo "==> Installing daemon as a package would"
docker exec "$NAME" sh -eu -c '
    install -D -m 0755 /opt/netorch/bin/network-orchestrator-daemon \
        /usr/bin/network-orchestrator-daemon
    install -m 0644 /opt/netorch/packaging/network-orchestrator.service /usr/lib/systemd/system/
    install -m 0644 /opt/netorch/packaging/com.netmanager.app.policy /usr/share/polkit-1/actions/
    systemctl daemon-reload
    systemctl enable --now network-orchestrator.service
'

echo "==> Running scenarios"
docker exec "$NAME" bash /opt/netorch/e2e/scenarios.sh

echo "==> Running WireGuard split scenarios"
python3 "$REPO_ROOT/e2e/linux/wg_scenarios.py" "$NAME" "$SERVER"

echo "==> Running OpenVPN split scenarios"
python3 "$REPO_ROOT/e2e/linux/ovpn_scenarios.py" "$NAME" "$SERVER"

echo "==> Running OpenVPN management auth scenarios"
python3 "$REPO_ROOT/e2e/linux/ovpn_auth_scenarios.py" "$NAME" "$SERVER"

echo "==> Running Xray proxy scenarios"
python3 "$REPO_ROOT/e2e/linux/xray_scenarios.py" "$NAME" "$SERVER"

echo "==> Running Xray TUN scenarios"
python3 "$REPO_ROOT/e2e/linux/xray_tun_scenarios.py" "$NAME" "$SERVER"

echo "==> Running always-on lifecycle scenarios"
docker exec "$NAME" bash /opt/netorch/e2e/always_on_scenarios.sh

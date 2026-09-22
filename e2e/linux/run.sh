#!/bin/sh
# Linux E2E harness (S2). Builds the daemon, boots a disposable Ubuntu 26.04
# container with systemd, installs the daemon exactly as a package would and
# runs scenarios.sh inside it. The container gets its own network namespace;
# the host's routes and links are never touched.
#
# Requirements: docker. Needs CAP_SYS_ADMIN + apparmor=unconfined for systemd
# (cgroup remount) — dev machine / CI only.
#
# Usage: e2e/linux/run.sh [--keep]   (--keep leaves the container running)
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE=netorch-e2e-client
NAME=netorch-e2e-$$
KEEP=${1:-}

echo "==> Building daemon (release)"
(cd "$REPO_ROOT" && cargo build --release -p network-orchestrator-daemon)

echo "==> Building image $IMAGE"
docker build -q -t "$IMAGE" "$REPO_ROOT/e2e/linux" >/dev/null

cleanup() {
    if [ "$KEEP" = "--keep" ]; then
        echo "container kept: docker exec -it $NAME bash; docker rm -f $NAME"
    else
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Starting $NAME"
docker run -d --name "$NAME" -e container=docker \
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
        /usr/lib/network-orchestrator/network-orchestrator-daemon
    install -m 0644 /opt/netorch/packaging/network-orchestrator.service /usr/lib/systemd/system/
    install -m 0644 /opt/netorch/packaging/com.netmanager.app.policy /usr/share/polkit-1/actions/
    systemctl daemon-reload
    systemctl enable --now network-orchestrator.service
'

echo "==> Running scenarios"
docker exec "$NAME" bash /opt/netorch/e2e/scenarios.sh

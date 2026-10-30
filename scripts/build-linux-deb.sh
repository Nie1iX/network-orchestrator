#!/bin/sh
# Build local packages without installing or starting any host service.
#
#   deb (default): three packages in target/release/packages and the app's
#                  bundle in target/release/bundle/deb:
#                    network-orchestrator-daemon  the daemon, systemd unit, polkit, Xray
#                    netorch                      the command line client
#                    network-orchestrator         the app (depends on the daemon)
#                  Install them together with
#                    apt install ./network-orchestrator-daemon_*.deb ./netorch_*.deb ./network-orchestrator_*.deb
#                  or only the daemon and netorch on a server without a desktop.
#   rpm:           the former single package (app and daemon); the split into
#                  separate rpm packages is not done yet.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
# The rpm bundler copies file modes from disk (the deb one normalizes them),
# so build outputs must not inherit a group-writable umask.
umask 022

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "error: the pinned Xray bundle supports Linux x86_64 only" >&2
    exit 1
fi

XRAY_URL="$(cargo run -q --release -p net-manager-core --example package_linux_xray -- url)"
XRAY_SHA256="$(cargo run -q --release -p net-manager-core --example package_linux_xray -- sha256)"
XRAY_VERSION="$(cargo run -q --release -p net-manager-core --example package_linux_xray -- version)"
if [ "$XRAY_VERSION" != v26.3.27 ]; then
    echo "error: update the .deb Xray file mappings for $XRAY_VERSION" >&2
    exit 1
fi
DOWNLOAD_DIR="$(mktemp -d)"
trap 'rm -rf -- "$DOWNLOAD_DIR"' EXIT
XRAY_ARCHIVE="$DOWNLOAD_DIR/Xray-linux-64.zip"
curl --fail --location --proto '=https' --proto-redir '=https' \
    --max-filesize 67108864 --output "$XRAY_ARCHIVE" "$XRAY_URL"
printf '%s  %s\n' "$XRAY_SHA256" "$XRAY_ARCHIVE" | sha256sum --check --status
cargo run -q --release -p net-manager-core --example package_linux_xray -- \
    install "$XRAY_ARCHIVE" "$REPO_ROOT/target/release/xray-package"

cargo build --release -p network-orchestrator-daemon
chmod 0755 target/release/network-orchestrator-daemon \
    target/release/xray-package/v26.3.27/xray
chmod 0644 target/release/xray-package/v26.3.27/*.dat \
    target/release/xray-package/v26.3.27/LICENSE \
    target/release/xray-package/v26.3.27/README.md \
    packaging/linux/network-orchestrator.service \
    packaging/linux/com.netmanager.app.policy packaging/linux/xray-NOTICES
test -x target/release/network-orchestrator-daemon
# An up-to-date app binary is not relinked, so fix a mode left by an old umask.
if [ -f target/release/net-manager-app ]; then chmod 0755 target/release/net-manager-app; fi
if [ "${1:-deb}" = deb ]; then
    cargo build --release -p net-manager-cli
    chmod 0755 target/release/netorch
    sh scripts/package-linux-deb.sh
    # The app needs the daemon of its own major.minor line or newer. Tauri
    # replaces an array from a --config override, so the whole list is given.
    LINE="$(python3 scripts/versions.py get linux | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')"
    npm run tauri build -- --bundles deb --no-sign --config \
        "{\"bundle\":{\"linux\":{\"deb\":{\"depends\":[\"network-orchestrator-daemon (>= ${LINE}.0)\"]}}}}"
else
    npm run tauri build -- --bundles "$1" --no-sign
fi

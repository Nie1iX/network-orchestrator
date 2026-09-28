#!/bin/sh
# Build a local .deb (default) or .rpm (`rpm` argument) without installing
# or starting any host service.
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
npm run tauri build -- --bundles "${1:-deb}" --no-sign

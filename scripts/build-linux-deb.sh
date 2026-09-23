#!/bin/sh
# Build a local .deb without installing or starting any host service.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

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
test -x target/release/network-orchestrator-daemon
npm run tauri build -- --bundles deb --no-sign

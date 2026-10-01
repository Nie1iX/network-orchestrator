#!/bin/bash
# Build the Rust bridge static library with the given cargo profile and stage
# it where macos/Package.swift links from (target/macos-bridge).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-release}"
cd "$REPO_ROOT"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-27.0}"
cargo build --profile "$PROFILE" -p net-manager-macos-bridge
mkdir -p target/macos-bridge
# cp -c clones on APFS: no extra disk until one side changes.
cp -c "target/$PROFILE/libnet_manager_macos_bridge.a" target/macos-bridge/ 2>/dev/null \
    || cp "target/$PROFILE/libnet_manager_macos_bridge.a" target/macos-bridge/

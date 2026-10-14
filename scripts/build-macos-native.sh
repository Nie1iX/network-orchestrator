#!/bin/bash
set -euo pipefail
# Usage: build-macos-native.sh [--dev]
#   default  release bridge (LTO) + Swift release: the distributable bundle.
#   --dev    release-fast bridge (no LTO, incremental) + Swift debug: fast local
#            iteration with symbols; same bundle path, not for distribution.
CARGO_PROFILE=release
SWIFT_CONFIG=release
if [[ "${1:-}" == --dev ]]; then
    CARGO_PROFILE=release-fast
    SWIFT_CONFIG=debug
elif [[ -n "${1:-}" ]]; then
    echo "Unknown option: $1" >&2
    exit 2
fi
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$REPO_ROOT/target/macos/Network Orchestrator.app"
if [[ "$(uname -s)" != Darwin ]]; then
    echo "The native macOS build requires macOS and Xcode 27." >&2
    exit 1
fi
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
if [[ "${SDK_VERSION%%.*}" -lt 27 ]]; then
    echo "Xcode 27 or later is required to build the macOS 27 client." >&2
    exit 1
fi
export MACOSX_DEPLOYMENT_TARGET=27.0
cd "$REPO_ROOT"
python3 scripts/generate-ui-theme.py --check
python3 scripts/generate-localizations.py --check
bash "$REPO_ROOT/scripts/stage-macos-bridge.sh" "$CARGO_PROFILE"
# The helper runs a pinned, self-contained OpenVPN shipped in the bundle. Its
# SHA-256 is compiled into the helper (crates/macos-helper/backends.json), so
# the pin is written before the helper is built.
OPENVPN_BIN="$(bash "$REPO_ROOT/scripts/build-macos-openvpn.sh")"
python3 - "$OPENVPN_BIN" "$REPO_ROOT/crates/macos-helper/backends.json" <<'PY'
import hashlib, json, os, re, sys
binary, target = sys.argv[1], sys.argv[2]
version = re.search(r'openvpn-(\d+\.\d+\.\d+)$', os.path.basename(binary)).group(1)
digest = hashlib.sha256(open(binary, 'rb').read()).hexdigest()
document = {"backends": [{"name": "openvpn", "version": version, "file": "openvpn", "sha256": digest}]}
text = json.dumps(document, indent=2) + "\n"
if not os.path.exists(target) or open(target).read() != text:
    open(target, 'w').write(text)
PY
cargo build --profile "$CARGO_PROFILE" -p network-orchestrator-macos-helper
swift build --package-path macos --configuration "$SWIFT_CONFIG" --scratch-path target/macos-swift
VERSION="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "net-manager-macos-bridge"))')"
BIN_DIR="$(swift build --package-path macos --configuration "$SWIFT_CONFIG" --scratch-path target/macos-swift --show-bin-path)"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
install -m 0755 "$BIN_DIR/NetworkOrchestrator" "$APP_DIR/Contents/MacOS/NetworkOrchestrator"
# Privileged helper: a launchd daemon the app registers through SMAppService.
# It lives next to the app executable, which is how it finds the one client
# process it serves.
HELPER_LABEL="com.netmanager.app.helper"
install -m 0755 "$REPO_ROOT/target/$CARGO_PROFILE/network-orchestrator-helper" "$APP_DIR/Contents/MacOS/network-orchestrator-helper"
# Pinned backend binaries live in Contents/Helpers; the helper verifies each
# against the hash compiled into it and only runs a private copy.
mkdir -p "$APP_DIR/Contents/Helpers"
install -m 0755 "$OPENVPN_BIN" "$APP_DIR/Contents/Helpers/openvpn"
mkdir -p "$APP_DIR/Contents/Library/LaunchDaemons"
python3 - "$APP_DIR/Contents/Library/LaunchDaemons/$HELPER_LABEL.plist" "$HELPER_LABEL" <<'PY'
import plistlib, sys
daemon = {
    'Label': sys.argv[2],
    'BundleProgram': 'Contents/MacOS/network-orchestrator-helper',
    'AssociatedBundleIdentifiers': ['com.netmanager.app.macos'],
    'RunAtLoad': True,
    'KeepAlive': True,
    'ProcessType': 'Interactive',
    'StandardErrorPath': '/var/log/network-orchestrator-helper.log',
}
with open(sys.argv[1], 'wb') as output:
    plistlib.dump(daemon, output)
PY
cp "$REPO_ROOT/src-tauri/icons/icon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
RESOURCE_BUNDLE="NetworkOrchestratorMac_NetworkOrchestrator.bundle"
ditto "$BIN_DIR/$RESOURCE_BUNDLE" "$APP_DIR/Contents/Resources/$RESOURCE_BUNDLE"
python3 - "$APP_DIR/Contents/Info.plist" "$VERSION" "$APP_DIR/Contents/Resources/$RESOURCE_BUNDLE/Contents/Resources/Localizations.json" <<'PY'
import json, plistlib, sys
with open(sys.argv[3]) as catalog_file:
    language_tags = sorted(json.load(catalog_file))
info = {
    'CFBundleExecutable': 'NetworkOrchestrator',
    'CFBundleIdentifier': 'com.netmanager.app.macos',
    'CFBundleName': 'Network Orchestrator',
    'CFBundleDisplayName': 'Network Orchestrator',
    'CFBundlePackageType': 'APPL',
    'CFBundleShortVersionString': sys.argv[2],
    'CFBundleVersion': sys.argv[2],
    'CFBundleIconFile': 'AppIcon',
    'CFBundleDevelopmentRegion': 'en',
    'CFBundleLocalizations': language_tags,
    'LSMinimumSystemVersion': '27.0',
    'LSApplicationCategoryType': 'public.app-category.utilities',
    'NSHighResolutionCapable': True,
    'NSSupportsAutomaticGraphicsSwitching': True,
}
with open(sys.argv[1], 'wb') as output:
    plistlib.dump(info, output)
PY
# Default: local ad-hoc signature. macOS does not let SMAppService find a
# daemon in an ad-hoc signed bundle (status "not found"), so the privileged
# helper needs a real identity: CODESIGN_IDENTITY="Apple Development: ..." (or a
# Developer ID). Notarization is a separate release step.
SIGN_ID="${CODESIGN_IDENTITY:--}"
codesign --force --sign "$SIGN_ID" "$APP_DIR/Contents/MacOS/network-orchestrator-helper"
codesign --force --sign "$SIGN_ID" "$APP_DIR"
codesign --verify --strict "$APP_DIR"
echo "$APP_DIR"

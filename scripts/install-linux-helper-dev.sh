#!/bin/sh
# Build the linux-helper binary in release mode and install it, plus its
# polkit policy, at the fixed paths the app and the policy both expect.
#
# This is a LOCAL DEV convenience, not a packaging story: a real Linux
# package (deb/rpm/AUR) would do the equivalent of steps 2-3 as part of its
# own install, at the same paths, so nothing else has to change.
#
# Safe to re-run: it always rebuilds and overwrites in place.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_DIR="/usr/local/libexec/network-orchestrator"
HELPER_PATH="$HELPER_DIR/linux-helper"
POLICY_SRC="$REPO_ROOT/crates/linux-helper/resources/com.netmanager.app.linux-helper.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.netmanager.app.linux-helper.policy"

echo "==> Building linux-helper (release)"
(cd "$REPO_ROOT" && cargo build --release -p network-orchestrator-linux-helper)

BUILT_BIN="$REPO_ROOT/target/release/linux-helper"
if [ ! -f "$BUILT_BIN" ]; then
    echo "error: build did not produce $BUILT_BIN" >&2
    exit 1
fi

echo "==> Installing helper to $HELPER_PATH (requires root)"
sudo install -d -m 0755 "$HELPER_DIR"
sudo install -m 0755 "$BUILT_BIN" "$HELPER_PATH"

echo "==> Installing polkit policy to $POLICY_DST (requires root)"
sudo install -m 0644 "$POLICY_SRC" "$POLICY_DST"

cat <<EOF

Done.

  Helper:  $HELPER_PATH
  Policy:  $POLICY_DST

The policy's exec.path annotation MUST equal the helper's real path exactly
(see the comment at the top of the .policy file for why) — they are kept
in lockstep by this script, so re-run it after every change to either.

polkit picks up new/changed action files without a restart. If routes still
prompt on every call instead of once per session, verify with:
  pkexec $HELPER_PATH route-add 203.0.113.0/32 lo 0 ; echo exit=\$?
and check that no "unknown action" or path-mismatch warning appears in
'journalctl -u polkit' around the same time.
EOF

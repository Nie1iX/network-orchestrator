#!/bin/sh
# Build the Network Orchestrator daemon in release mode and install it as a
# systemd service, together with its polkit policy.
#
# This is a LOCAL DEV convenience, not a packaging story: a real Linux
# package installs the same files, but the binary goes to /usr/lib
# (the path in packaging/linux/network-orchestrator.service). Here it goes
# to /usr/local/lib and ExecStart is rewritten to match.
#
# Usage:
#   scripts/install-linux-daemon-dev.sh              build, install, (re)start
#   scripts/install-linux-daemon-dev.sh --uninstall  stop, disable, remove all
#
# Safe to re-run: it always rebuilds, overwrites in place and restarts.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_NAME="network-orchestrator.service"
UNIT_SRC="$REPO_ROOT/packaging/linux/$UNIT_NAME"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
POLICY_SRC="$REPO_ROOT/packaging/linux/com.netmanager.app.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.netmanager.app.policy"
DAEMON_DIR="/usr/local/lib/network-orchestrator"
DAEMON_PATH="$DAEMON_DIR/network-orchestrator-daemon"
STATE_DIR="/var/lib/network-orchestrator"
OLD_HELPER_PATH="/usr/local/libexec/network-orchestrator/linux-helper"
OLD_POLICY_PATH="/usr/share/polkit-1/actions/com.netmanager.app.linux-helper.policy"

remove_old_helper() {
    for old in "$OLD_HELPER_PATH" "$OLD_POLICY_PATH"; do
        if [ -e "$old" ]; then
            echo "==> Removing old helper leftover $old (requires root)"
            sudo rm -f "$old"
        fi
    done
}

uninstall() {
    echo "==> Stopping and disabling $UNIT_NAME (requires root)"
    sudo systemctl disable --now "$UNIT_NAME" 2>/dev/null || true

    echo "==> Removing unit, binary, policy and state (requires root)"
    sudo rm -f "$UNIT_DST" "$DAEMON_PATH" "$POLICY_DST"
    remove_old_helper
    sudo rmdir "$DAEMON_DIR" 2>/dev/null || true
    sudo rm -rf "$STATE_DIR"
    sudo systemctl daemon-reload

    echo "Done: daemon uninstalled."
}

case "${1:-}" in
    "") ;;
    --uninstall)
        uninstall
        exit 0
        ;;
    *)
        echo "usage: $0 [--uninstall]" >&2
        exit 2
        ;;
esac

echo "==> Building network-orchestrator-daemon (release)"
(cd "$REPO_ROOT" && cargo build --release -p network-orchestrator-daemon)

BUILT_BIN="$REPO_ROOT/target/release/network-orchestrator-daemon"
if [ ! -f "$BUILT_BIN" ]; then
    echo "error: build did not produce $BUILT_BIN" >&2
    exit 1
fi

echo "==> Installing daemon to $DAEMON_PATH (requires root)"
sudo install -d -m 0755 "$DAEMON_DIR"
sudo install -m 0755 "$BUILT_BIN" "$DAEMON_PATH"

echo "==> Installing unit to $UNIT_DST (requires root)"
UNIT_TMP="$(mktemp)"
trap 'rm -f "$UNIT_TMP"' EXIT
sed "s|^ExecStart=/usr/lib/network-orchestrator/network-orchestrator-daemon\$|ExecStart=$DAEMON_PATH|" \
    "$UNIT_SRC" >"$UNIT_TMP"
if ! grep -qx "ExecStart=$DAEMON_PATH" "$UNIT_TMP"; then
    echo "error: failed to rewrite ExecStart in $UNIT_SRC" >&2
    exit 1
fi
sudo install -m 0644 "$UNIT_TMP" "$UNIT_DST"

echo "==> Installing polkit policy to $POLICY_DST (requires root)"
sudo install -m 0644 "$POLICY_SRC" "$POLICY_DST"

remove_old_helper

echo "==> Starting $UNIT_NAME (requires root)"
sudo systemctl daemon-reload
sudo systemctl enable "$UNIT_NAME"
if systemctl is-active --quiet "$UNIT_NAME"; then
    sudo systemctl restart "$UNIT_NAME"
else
    sudo systemctl start "$UNIT_NAME"
fi

cat <<EOF

Done.

  Daemon:  $DAEMON_PATH
  Unit:    $UNIT_DST
  Policy:  $POLICY_DST
  State:   $STATE_DIR

Check status with:
  systemctl status $UNIT_NAME
  journalctl -u $UNIT_NAME -e
EOF

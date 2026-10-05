#!/bin/sh
# Build the Network Orchestrator daemon in release mode and install it as a
# SECOND systemd service (network-orchestrator-dev.service) next to the
# packaged one.
#
# The dev instance is fully isolated from the production daemon:
#   socket      /run/network-orchestrator-dev/daemon.sock   (not .../daemon.sock)
#   state dir   /var/lib/network-orchestrator-dev           (journal, always-on)
#   runtime dir /run/network-orchestrator-dev               (staging, mgmt socks)
#   binary      /usr/local/bin/network-orchestrator-daemon  (package uses /usr/bin)
#
# Point the dev app at it with `npm run dev:app` — it sets
# NETWORK_ORCHESTRATOR_SOCKET and a dev Tauri identifier (separate
# ~/.local/share data dir, "(Dev)" window title).
#
# Usage:
#   scripts/install-linux-daemon-dev.sh              build, install, (re)start
#   scripts/install-linux-daemon-dev.sh --uninstall  stop, disable, remove all
#
# Safe to re-run: it always rebuilds, overwrites in place and restarts.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_NAME="network-orchestrator-dev.service"
UNIT_SRC="$REPO_ROOT/packaging/linux/network-orchestrator.service"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
TMPFILES_SRC="$REPO_ROOT/packaging/linux/tmpfiles.conf"
TMPFILES_DST="/usr/lib/tmpfiles.d/network-orchestrator.conf"
POLICY_SRC="$REPO_ROOT/packaging/linux/com.netmanager.app.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.netmanager.app.policy"
PROD_UNIT_DST="/etc/systemd/system/network-orchestrator.service"
DAEMON_DIR="/usr/local/bin"
DAEMON_PATH="$DAEMON_DIR/network-orchestrator-daemon"
OLD_DAEMON_PATH="/usr/local/lib/network-orchestrator/network-orchestrator-daemon"
STATE_DIR="/var/lib/network-orchestrator-dev"
RUNTIME_DIR="/run/network-orchestrator-dev"
PACKAGE_DIR="/usr/lib/network-orchestrator"
OLD_HELPER_PATH="/usr/local/libexec/network-orchestrator/linux-helper"
OLD_POLICY_PATH="/usr/share/polkit-1/actions/com.netmanager.app.linux-helper.policy"

remove_old_helper() {
    for old in "$OLD_HELPER_PATH" "$OLD_POLICY_PATH" "$OLD_DAEMON_PATH"; do
        if [ -e "$old" ]; then
            echo "==> Removing old helper leftover $old (requires root)"
            sudo rm -f "$old"
        fi
    done
}

uninstall() {
    echo "==> Stopping and disabling $UNIT_NAME (requires root)"
    sudo systemctl disable --now "$UNIT_NAME" 2>/dev/null || true

    echo "==> Removing dev unit, binary and state (requires root)"
    sudo rm -f "$UNIT_DST" "$DAEMON_PATH"
    remove_old_helper
    sudo rmdir "$(dirname "$OLD_DAEMON_PATH")" 2>/dev/null || true
    sudo rm -rf "$STATE_DIR"

    # tmpfiles/polkit policy are shared with the packaged install; drop them
    # only when the production unit is absent.
    if [ ! -e "$PROD_UNIT_DST" ]; then
        sudo rm -f "$POLICY_DST" "$TMPFILES_DST"
        sudo rm -rf "$PACKAGE_DIR"
    fi
    sudo systemctl daemon-reload

    echo "Done: dev daemon uninstalled."
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

# Earlier revisions installed the dev build under the production unit name
# (network-orchestrator.service, ExecStart=/usr/local/bin/...). Migrate: a
# unit whose ExecStart points at the dev binary was dev-installed — stop it,
# free the production slot, and keep its journal/always-on state for the
# dev instance.
if [ -f "$PROD_UNIT_DST" ] && grep -qx "ExecStart=$DAEMON_PATH.*" "$PROD_UNIT_DST"; then
    echo "==> Migrating dev install out of the production unit slot"
    sudo systemctl disable --now network-orchestrator.service 2>/dev/null || true
    sudo rm -f "$PROD_UNIT_DST"
    if [ -d /var/lib/network-orchestrator ] && [ ! -d "$STATE_DIR" ]; then
        sudo mv /var/lib/network-orchestrator "$STATE_DIR"
    fi
    sudo systemctl daemon-reload
fi

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

echo "==> Generating dev unit from $UNIT_SRC (requires root)"
UNIT_TMP="$(mktemp)"
trap 'rm -f "$UNIT_TMP"' EXIT
sed \
    -e "s|^Description=.*|Description=Network Orchestrator privileged daemon (dev instance)|" \
    -e "s|^ExecStart=.*|ExecStart=$DAEMON_PATH --socket $RUNTIME_DIR/daemon.sock --state-dir $STATE_DIR|" \
    -e "s|^RuntimeDirectory=.*|RuntimeDirectory=network-orchestrator-dev|" \
    -e "s|^StateDirectory=.*|StateDirectory=network-orchestrator-dev|" \
    -e "/^UMask=0077$/a Environment=NETWORK_ORCHESTRATOR_RUNTIME_DIR=$RUNTIME_DIR" \
    "$UNIT_SRC" >"$UNIT_TMP"
for needle in \
    "ExecStart=$DAEMON_PATH --socket $RUNTIME_DIR/daemon.sock --state-dir $STATE_DIR" \
    "RuntimeDirectory=network-orchestrator-dev" \
    "StateDirectory=network-orchestrator-dev" \
    "Environment=NETWORK_ORCHESTRATOR_RUNTIME_DIR=$RUNTIME_DIR"; do
    if ! grep -qx "$needle" "$UNIT_TMP"; then
        echo "error: failed to generate dev unit (missing: $needle)" >&2
        exit 1
    fi
done
sudo install -m 0644 "$UNIT_TMP" "$UNIT_DST"

echo "==> Installing polkit policy to $POLICY_DST (requires root)"
sudo install -m 0644 "$POLICY_SRC" "$POLICY_DST"

# The managed package root must exist before the service starts:
# ReadWritePaths is ignored for paths that do not exist yet. Shared with
# the production install — both instances verify the same pinned content.
echo "==> Installing tmpfiles config to $TMPFILES_DST (requires root)"
sudo install -m 0644 "$TMPFILES_SRC" "$TMPFILES_DST"
sudo systemd-tmpfiles --create "$(basename "$TMPFILES_DST")"

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

Done — dev daemon is isolated from any packaged install.

  Daemon:  $DAEMON_PATH
  Unit:    $UNIT_DST
  Socket:  $RUNTIME_DIR/daemon.sock
  State:   $STATE_DIR
  Policy:  $POLICY_DST (shared with production)

Run the dev app against it with:

  npm run dev:app

Check status with:
  systemctl status $UNIT_NAME
  journalctl -u $UNIT_NAME -e
EOF

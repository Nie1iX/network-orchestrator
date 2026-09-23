#!/bin/bash
# Run only inside the disposable client created by e2e/linux/run.sh.
set -euo pipefail

CLIENT=/opt/netorch/e2e/client.py
SOCK=/run/network-orchestrator/daemon.sock
UNIT=network-orchestrator.service

step() { printf '\n=== %s\n' "$*"; }
ok() { printf 'ok   %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }
wait_socket() {
    for _ in $(seq 50); do [ -S "$SOCK" ] && return 0; sleep 0.1; done
    fail "daemon socket did not appear"
}
wait_route() {
    local destination=$1 interface=$2
    for _ in $(seq 40); do
        ip -4 route show "$destination" | grep -q "dev $interface .*proto 79 .*metric 5" && return 0
        sleep 0.5
    done
    fail "always-on route $destination did not appear on $interface"
}

step "static always-on survives daemon crash before UI login"
ip link add ao0 type dummy
ip link set ao0 up
definition='{"definition":{"kind":"staticRoutes","profile":{"profileId":"ao-static","interfaceName":"ao0","routes":[{"destination":"198.18.88.0/24","metric":5}]}}}'
result=$(python3 "$CLIENT" alwaysOn.set "$definition")
echo "$result" | python3 -c 'import json,sys; assert json.load(sys.stdin)["active"]' \
    && ok "root registered and activated static always-on" || fail "alwaysOn.set: $result"
wait_route 198.18.88.0/24 ao0

step "second uid cannot inspect or remove root definition"
result=$(runuser -u bob -- python3 "$CLIENT" alwaysOn.list)
echo "$result" | python3 -c 'import json,sys; assert json.load(sys.stdin)["profiles"]==[]' \
    && ok "bob sees only own definitions" || fail "bob list: $result"
result=$(runuser -u bob -- python3 "$CLIENT" alwaysOn.remove '{"kind":"staticRoutes","profileId":"ao-static"}')
echo "$result" | python3 -c 'import json,sys; assert not json.load(sys.stdin)["removed"]' \
    && ok "authorized bob cannot remove root definition" || fail "bob remove: $result"

systemctl kill -s KILL "$UNIT"
sleep 3
systemctl is-active --quiet "$UNIT" || fail "daemon did not restart"
wait_socket
wait_route 198.18.88.0/24 ao0
ok "journal cleanup then always-on replay restored route"

step "Disconnect all pause persists across daemon SIGKILL"
python3 "$CLIENT" recovery.cleanup >/dev/null
result=$(python3 "$CLIENT" alwaysOn.list)
echo "$result" | python3 -c 'import json,sys; assert json.load(sys.stdin)["paused"]' \
    && ok "recovery cleanup persisted pause" || fail "pause missing: $result"
systemctl kill -s KILL "$UNIT"
sleep 3
systemctl is-active --quiet "$UNIT" || fail "daemon did not restart after pause"
wait_socket
ip -4 route show 198.18.88.0/24 | grep -q 'proto 79' \
    && fail "paused definition unexpectedly replayed" || ok "paused definition did not replay"
python3 "$CLIENT" alwaysOn.resume >/dev/null
wait_route 198.18.88.0/24 ao0
ok "explicit resume restored always-on route"

step "interface flap repairs only the owned route"
ip link set ao0 down
ip link set ao0 up
ip -4 route add 198.18.88.0/24 dev ao0 metric 9 proto static
wait_route 198.18.88.0/24 ao0
result=$(python3 "$CLIENT" alwaysOn.remove '{"kind":"staticRoutes","profileId":"ao-static"}')
echo "$result" | python3 -c 'import json,sys; assert json.load(sys.stdin)["removed"]' \
    && ok "disable removed definition and active owner" || fail "remove: $result"
ip -4 route show 198.18.88.0/24 | grep -q 'proto static .*metric 9' \
    && ok "foreign route survived owned teardown" || fail "foreign route was removed"
ip -4 route show 198.18.88.0/24 | grep -q 'proto 79' \
    && fail "owned route remained after disable" || ok "owned route removed"
ip -4 route del 198.18.88.0/24 dev ao0 metric 9 proto static

step "late interface is retried without another client connection"
definition='{"definition":{"kind":"staticRoutes","profile":{"profileId":"late-static","interfaceName":"late0","routes":[{"destination":"198.18.89.0/24","metric":5}]}}}'
result=$(python3 "$CLIENT" alwaysOn.set "$definition")
echo "$result" | python3 -c 'import json,sys; assert not json.load(sys.stdin)["active"]' \
    && ok "definition stored while interface is absent" || fail "late set: $result"
ip link add late0 type dummy
ip link set late0 up
wait_route 198.18.89.0/24 late0
ok "periodic replay applied route after interface appeared"
python3 "$CLIENT" alwaysOn.remove '{"kind":"staticRoutes","profileId":"late-static"}' >/dev/null
ip link del late0
ip link del ao0

printf '\nALL ALWAYS-ON STATIC CHECKS PASSED\n'

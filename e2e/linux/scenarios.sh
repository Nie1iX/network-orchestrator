#!/bin/bash
# S1 daemon scenarios. Runs INSIDE the disposable client container as root
# (see run.sh); every mutation happens in the container's own network
# namespace. Exits non-zero on the first failed check.
set -euo pipefail

CLIENT=/opt/netorch/e2e/client.py
SOCK=/run/network-orchestrator/daemon.sock
STATE=/var/lib/network-orchestrator/state.json
UNIT=network-orchestrator.service
PASS=0

step() { printf '\n=== %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }
expect_eq() { [ "$1" = "$2" ] && ok "$3" || fail "$3: expected '$2', got '$1'"; }
as() { local user=$1; shift; runuser -u "$user" -- "$@"; }
ours() { ip "$@" route show proto 79; }
wait_socket() {
    for _ in $(seq 50); do [ -S "$SOCK" ] && return 0; sleep 0.1; done
    fail "daemon socket did not appear"
}

step "service under systemd hardening"
systemctl is-active --quiet "$UNIT" || fail "unit not active: $(systemctl status "$UNIT" --no-pager)"
wait_socket
expect_eq "$(stat -c %a "$SOCK")" 666 "socket mode 0666 despite UMask=0077"
expect_eq "$(stat -c %a /var/lib/network-orchestrator)" 700 "state dir mode 0700"

step "isolated peer container"
peer=$(python3 -c 'from urllib.request import urlopen; print(urlopen("http://wg-server:8765/server-health.txt", timeout=3).read().decode().strip())' 2>/dev/null) || fail "peer container unreachable"
expect_eq "$peer" "netorch-e2e-server" "peer reachable over private Docker network"

step "test interfaces"
ip link add dum0 type dummy
ip addr add 192.0.2.1/24 dev dum0
ip -6 addr add 2001:db8:1::1/64 dev dum0 nodad
ip link set dum0 up
IDX=$(cat /sys/class/net/dum0/ifindex)
ok "dum0 index $IDX"

step "policy rule selects a non-main table for fibmatch lookup"
ip -4 route add 198.18.77.0/24 dev dum0 table 22379 proto 79
ip -4 rule add pref 21000 to 198.18.77.0/24 lookup 22379
lookup=$(ip -j -4 route get fibmatch 198.18.77.7)
python3 -c 'import json,sys; rows=json.loads(sys.argv[1]); assert len(rows)==1; route=rows[0]; assert route["dst"]=="198.18.77.0/24"; assert route["dev"]=="dum0"; assert str(route["table"])=="22379"' "$lookup" \
    && ok "fibmatch follows policy rule into table 22379" || fail "policy lookup: $lookup"
ip -4 rule del pref 21000 to 198.18.77.0/24 lookup 22379
ip -4 route del 198.18.77.0/24 dev dum0 table 22379

step "hello reports peer uid"
expect_eq "$(python3 "$CLIENT" owned.list)" '{"owners": []}' "root owned.list empty"
uid=$(python3 - <<EOF
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect("$SOCK"); f = s.makefile("rwb")
f.write(b'{"id":1,"method":"hello","params":{"protocol":1,"client":"e2e"}}\n'); f.flush()
print(json.loads(f.readline())["result"]["uid"])
EOF
)
expect_eq "$uid" 0 "hello uid for root"

step "routes.apply: on-link v4, via v4, via v6"
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[
  {\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5},
  {\"destination\":\"198.51.100.0/24\",\"interfaceIndex\":$IDX,\"gateway\":\"192.0.2.254\",\"metric\":6},
  {\"destination\":\"2001:db8:2::/48\",\"interfaceIndex\":$IDX,\"gateway\":\"2001:db8:1::fe\",\"metric\":7}]}" >/dev/null \
    || fail "routes.apply"
ours -4 | grep -q "^203.0.113.0/24 dev dum0 .*scope link .*metric 5" && ok "on-link v4 installed with proto 79" || fail "on-link v4: $(ours -4)"
ours -4 | grep -q "^198.51.100.0/24 via 192.0.2.254 dev dum0 .*metric 6" && ok "v4 via gateway installed" || fail "via v4: $(ours -4)"
ours -6 | grep -q "^2001:db8:2::/48 via 2001:db8:1::fe dev dum0 .*metric 7" && ok "v6 via gateway installed" || fail "via v6: $(ours -6)"
python3 -c "import json,sys; d=json.load(open('$STATE')); assert d['entries'][0]['state']=='applied'" \
    && ok "journal records owner as applied" || fail "journal: $(cat $STATE)"
expect_eq "$(stat -c %a $STATE)" 600 "journal mode 0600"

step "EXCL: an identical foreign route conflicts and survives"
ip route add 192.0.2.128/25 dev dum0 metric 9 proto static
out=$(python3 "$CLIENT" routes.apply "{\"owner\":\"clash\",\"routes\":[{\"destination\":\"192.0.2.128/25\",\"interfaceIndex\":$IDX,\"metric\":9}]}" || true)
echo "$out" | grep -q '"conflict"' && ok "conflict reported" || fail "expected conflict, got $out"
ip route show 192.0.2.128/25 | grep -q "proto static" && ok "foreign route untouched" || fail "foreign route gone"
expect_eq "$(python3 "$CLIENT" owned.list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["owners"]))')" 1 "failed apply left no owner"

step "uid isolation and polkit without an agent"
expect_eq "$(as alice python3 "$CLIENT" owned.list)" '{"owners": []}' "alice does not see root owners"
out=$(as alice python3 "$CLIENT" routes.remove '{"owner":"static"}' || true)
echo "$out" | grep -q '"notAuthorized"' && ok "unauthorized alice cannot remove root owner" || fail "expected notAuthorized, got $out"
out=$(as alice python3 "$CLIENT" routes.apply "{\"owner\":\"a\",\"routes\":[{\"destination\":\"10.66.0.0/16\",\"interfaceIndex\":$IDX,\"metric\":5}]}" || true)
echo "$out" | grep -qE '"notAuthorized"|"authorizationDismissed"' && ok "alice denied without polkit agent ($out)" || fail "expected denial, got $out"
ip route show 10.66.0.0/16 | grep -q . && fail "denied route was installed" || ok "denied route not installed"
out=$(as alice python3 "$CLIENT" routes.apply '{"owner":"a","routes":[{"destination":"10.66.0.1/16","interfaceIndex":1,"metric":5}]}' || true)
echo "$out" | grep -q '"invalidParams"' && ok "invalid params rejected before polkit" || fail "expected invalidParams, got $out"

step "polkit rule grants bob system-network"
cat >/etc/polkit-1/rules.d/50-netorch-e2e.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("com.netmanager.app.") == 0 && subject.user == "bob") {
        return polkit.Result.YES;
    }
});
EOF
sleep 1
as bob python3 "$CLIENT" routes.apply "{\"owner\":\"b\",\"routes\":[{\"destination\":\"10.77.0.0/16\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null \
    && ok "bob authorized by rule (pidfd subject accepted)" || fail "bob apply failed"
ours -4 | grep -q "^10.77.0.0/16" && ok "bob route installed" || fail "bob route missing"
out=$(as bob python3 "$CLIENT" routes.remove '{"owner":"static"}' || true)
echo "$out" | grep -q '"notFound"' && ok "authorized bob still cannot remove root owner (notFound)" || fail "expected notFound, got $out"
ours -4 | grep -q "^203.0.113.0/24" && ok "root route intact" || fail "root route removed by bob"
as bob python3 "$CLIENT" routes.remove '{"owner":"b"}' >/dev/null && ok "bob removed own owner" || fail "bob remove"
ours -4 | grep -q "^10.77.0.0/16" && fail "bob route still present" || ok "bob route removed"

step "link.set_state"
python3 "$CLIENT" link.set_state '{"name":"dum0","up":false}' >/dev/null || fail "link down"
ip -br link show dum0 | grep -q DOWN && ok "dum0 down" || fail "dum0 not down: $(ip -br link show dum0)"
python3 "$CLIENT" link.set_state '{"name":"dum0","up":true}' >/dev/null || fail "link up"
ip -br link show dum0 | grep -qE "UNKNOWN|UP" && ok "dum0 up" || fail "dum0 not up"
# Routes vanish with the link going down; re-add for the recovery checks.
python3 "$CLIENT" routes.remove '{"owner":"static"}' >/dev/null || true
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[{\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null \
    || fail "re-apply after link flap"

step "kill -9 → systemd restart → startup recovery"
systemctl kill -s KILL "$UNIT"
sleep 3
systemctl is-active --quiet "$UNIT" && ok "restarted by systemd" || fail "not restarted"
wait_socket
ours -4 | grep -q "^203.0.113.0/24" && fail "leftover route survived recovery" || ok "leftover route removed on startup"
expect_eq "$(python3 -c "import json; print(len(json.load(open('$STATE'))['entries']))")" 0 "journal empty after recovery"

step "SIGTERM teardown"
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[{\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null
systemctl stop "$UNIT"
ours -4 | grep -q "^203.0.113.0/24" && fail "route survived stop" || ok "stop removed routes"
[ -e "$SOCK" ] && fail "socket left behind" || ok "socket removed on stop"
systemctl start "$UNIT"; wait_socket

step "batch of 1000 routes"
routes=$(python3 -c "
import json
print(json.dumps({'owner':'bulk','routes':[{'destination':f'100.{64 + i // 256}.{i % 256}.0/24','interfaceIndex':$IDX,'metric':5} for i in range(1000)]}))")
start=$(date +%s%N)
python3 "$CLIENT" routes.apply "$routes" >/dev/null || fail "bulk apply"
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))
expect_eq "$(ours -4 | grep -c '^100\.')" 1000 "1000 routes installed"
[ "$elapsed_ms" -le 2000 ] && ok "bulk apply in ${elapsed_ms} ms (<= 2000)" || fail "bulk apply too slow: ${elapsed_ms} ms"
python3 "$CLIENT" routes.remove '{"owner":"bulk"}' >/dev/null
expect_eq "$(ours -4 | grep -c '^100\.' || true)" 0 "bulk removed"

step "corrupt journal blocks startup without losing ownership data"
systemctl stop "$UNIT"
printf '%s' '{broken journal' >"$STATE"
systemctl start "$UNIT" >/dev/null 2>&1 || true
sleep 2
systemctl is-active --quiet "$UNIT" && fail "daemon started with corrupt journal" || ok "daemon refused corrupt journal"
expect_eq "$(cat "$STATE")" '{broken journal' "corrupt journal preserved"
systemctl stop "$UNIT" >/dev/null 2>&1 || true
printf '%s\n' '{"version":1,"entries":[]}' >"$STATE"
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
systemctl start "$UNIT"
wait_socket
ok "daemon starts after journal recovery"

printf '\nALL %d CHECKS PASSED\n' "$PASS"

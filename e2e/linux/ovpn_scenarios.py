#!/usr/bin/env python3
"""Exercise daemon-owned OpenVPN against a synthetic peer container.

All certificates and private keys are generated inside the disposable server.
The client key is held only in this process and sent to the daemon over stdin;
it is never printed or passed as a command argument.
"""

import json
import re
import subprocess
import sys
import time


client_name, server_name = sys.argv[1:3]


def run(*args, input_text=None):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"E2E command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def docker_exec(container, *args, input_text=None):
    return run("docker", "exec", "-i", container, *args, input_text=input_text)


def rpc(method, params):
    code = (
        "import json,sys; "
        "sys.path.insert(0, '/opt/netorch/e2e'); "
        "from client import call; "
        "print(json.dumps(call(sys.argv[1], json.load(sys.stdin))))"
    )
    response = json.loads(
        docker_exec(
            client_name,
            "python3",
            "-c",
            code,
            method,
            input_text=json.dumps(params),
        )
    )
    if not response.get("ok"):
        raise RuntimeError(f"{method} failed: {response.get('error', {}).get('code')}")
    return response["result"]


print("\n=== OpenVPN split tunnel across two containers", flush=True)
docker_exec(server_name, "sh", "/opt/netorch/e2e/ovpn_server.sh")
for _ in range(30):
    try:
        docker_exec(server_name, "ip", "link", "show", "ovpn-srv")
        break
    except RuntimeError:
        time.sleep(0.2)
else:
    raise RuntimeError("OpenVPN test server did not create its TUN link")
print("ok   synthetic OpenVPN server is running", flush=True)

server_ip = docker_exec(
    client_name,
    "python3",
    "-c",
    'import socket; print(socket.gethostbyname("wg-server"))',
)
ca = docker_exec(server_name, "cat", "/run/ovpn-e2e/ca.crt")
cert = docker_exec(server_name, "cat", "/run/ovpn-e2e/client.crt")
key = docker_exec(server_name, "cat", "/run/ovpn-e2e/client.key")
config = (
    "client\n"
    "dev tun\n"
    "proto udp4\n"
    f"remote {server_ip} 1194\n"
    "nobind\n"
    "remote-cert-tls server\n"
    f"<ca>\n{ca}\n</ca>\n"
    f"<cert>\n{cert}\n</cert>\n"
    f"<key>\n{key}\n</key>\n"
)
try:
    rpc(
        "openvpn.connect",
        {
            "profileId": "ovpn-unsafe",
            "config": config + "up /bin/true\n",
            "assets": {},
            "routes": [],
        },
    )
except RuntimeError as error:
    assert "invalidParams" in str(error), "unsafe directive had the wrong error"
else:
    raise RuntimeError("daemon accepted an OpenVPN script directive")
assert not any(
    entry["owner"].endswith("ovpn-unsafe")
    for entry in rpc("owned.list", None)["owners"]
)
print("ok   script directive rejected before ownership", flush=True)

probe = rpc(
    "openvpn.probe",
    {"profileId": "ovpn-probe-e2e", "config": config, "assets": {}, "routes": []},
)
assert any(route["destination"] == "192.168.77.0/24" for route in probe["routes"])
assert not any(
    entry["owner"] == "ovpn-probe:ovpn-probe-e2e"
    for entry in rpc("owned.list", None)["owners"]
)
assert "192.168.77.0/24" not in docker_exec(client_name, "ip", "route", "show", "proto", "79")
try:
    docker_exec(client_name, "pgrep", "-x", "openvpn")
except RuntimeError:
    pass
else:
    raise RuntimeError("OpenVPN probe child survived cleanup")
print("ok   disconnected probe returned pushed route without OS route or child", flush=True)

params = {
    "profileId": "ovpn-e2e",
    "config": config,
    "assets": {},
    "routes": [],
    "interfaceName": "OVPN E2E",
}
predicted = rpc("openvpn.plan", params)
assert predicted["owner"] == "ovpn:ovpn-e2e"
assert predicted["interfaceName"] == "ovpn-e2e", "hint was not slugged"
assert predicted["fallbackInterfaceName"].startswith("ovpn-e2e-")
assert predicted["stagingDir"].startswith("/run/network-orchestrator/")
assert predicted["configPath"].endswith("/config.ovpn")
assert predicted["managementSocket"].endswith("/management.sock")
assert predicted["conflicts"] == []
print("ok   openvpn.plan predicted paths before connect", flush=True)
initial = rpc("openvpn.connect", params)["status"]
assert initial["state"] in ("connecting", "connected")
for _ in range(60):
    status = rpc("openvpn.status", {"profileId": "ovpn-e2e"})
    if status["state"] == "connected":
        break
    if status["state"] == "failed":
        raise RuntimeError("OpenVPN daemon reported failed state")
    time.sleep(0.5)
else:
    raise RuntimeError("OpenVPN client did not connect to the test server")
interface = status["interfaceName"]
assert interface and interface.startswith("ovpn-"), "unexpected OpenVPN interface"
assert interface == predicted["interfaceName"], "plan predicted a different interface name"
conflicted = rpc("openvpn.plan", params)
assert "activeConnection" in conflicted["conflicts"]
assert "interfaceOccupied" in conflicted["conflicts"]
print("ok   openvpn.plan reported conflicts for the active profile", flush=True)
print("ok   daemon connected the OpenVPN client", flush=True)

alice_status = json.loads(
    docker_exec(
        client_name,
        "runuser",
        "-u",
        "alice",
        "--",
        "python3",
        "/opt/netorch/e2e/client.py",
        "openvpn.status",
        '{"profileId":"ovpn-e2e"}',
    )
)
assert alice_status["state"] == "stopped", "another uid saw the tunnel"
print("ok   another uid cannot see the OpenVPN client", flush=True)

for _ in range(20):
    status = rpc("openvpn.status", {"profileId": "ovpn-e2e"})
    if "192.168.77.0/24" in status["appliedRoutes"]:
        break
    time.sleep(0.5)
else:
    raise RuntimeError("OpenVPN pushed split route was not applied")
for _ in range(10):
    route = docker_exec(client_name, "ip", "-4", "route", "get", "192.168.77.1")
    if f"dev {interface}" in route:
        break
    time.sleep(0.5)
else:
    raise RuntimeError(f"pushed route bypasses OpenVPN: {route}")
print("ok   pushed split route selects the OpenVPN link", flush=True)

probe = (
    'from urllib.request import urlopen; '
    'print(urlopen("http://192.168.77.1:8765/server-health.txt", timeout=3).read().decode().strip())'
)
assert docker_exec(client_name, "python3", "-c", probe) == "netorch-e2e-server"
print("ok   HTTP reached the peer over OpenVPN", flush=True)

assert rpc("openvpn.disconnect", {"profileId": "ovpn-e2e"}) == {"stopped": True}
assert rpc("openvpn.status", {"profileId": "ovpn-e2e"})["state"] == "stopped"
assert not any(
    entry["owner"].endswith("ovpn-e2e")
    for entry in rpc("owned.list", None)["owners"]
)
route = docker_exec(client_name, "ip", "-4", "route", "show", "proto", "79")
assert "192.168.77.0/24" not in route, "OpenVPN route survived disconnect"
print("ok   disconnect removed the OpenVPN route and ownership", flush=True)

again = rpc("openvpn.connect", params)["status"]
assert again["state"] in ("connecting", "connected")
for _ in range(60):
    status = rpc("openvpn.status", {"profileId": "ovpn-e2e"})
    if status["state"] == "connected":
        break
    if status["state"] == "failed":
        raise RuntimeError("OpenVPN reconnect failed before crash test")
    time.sleep(0.5)
else:
    raise RuntimeError("OpenVPN reconnect timed out before crash test")
crash_interface = status["interfaceName"]
docker_exec(
    client_name,
    "systemctl",
    "kill",
    "-s",
    "KILL",
    "network-orchestrator.service",
)
for _ in range(30):
    time.sleep(0.5)
    try:
        owners = rpc("owned.list", None)["owners"]
    except RuntimeError:
        continue
    if not any(entry["owner"].endswith("ovpn-e2e") for entry in owners):
        break
else:
    raise RuntimeError("daemon did not recover crashed OpenVPN owner")
print("ok   daemon restarted and removed crashed OpenVPN owner", flush=True)

try:
    docker_exec(client_name, "ip", "link", "show", crash_interface)
except RuntimeError:
    pass
else:
    raise RuntimeError("OpenVPN link survived daemon crash")
route = docker_exec(client_name, "ip", "-4", "route", "show", "proto", "79")
assert "192.168.77.0/24" not in route, "OpenVPN route survived daemon crash"
try:
    docker_exec(client_name, "pgrep", "openvpn")
except RuntimeError:
    pass
else:
    raise RuntimeError("OpenVPN child survived daemon crash")
print("ok   crash recovery removed OpenVPN child, link, and route", flush=True)

print("ALL 10 OPENVPN SPLIT CHECKS PASSED", flush=True)

print("\n=== OpenVPN full tunnel keeps endpoint on underlay and applies DNS", flush=True)
docker_exec(server_name, "sh", "/opt/netorch/e2e/ovpn_full_server.sh")
for _ in range(30):
    try:
        docker_exec(server_name, "ip", "link", "show", "ovpn-full")
        break
    except RuntimeError:
        time.sleep(0.2)
else:
    raise RuntimeError("OpenVPN full server did not create its TUN link")
print("ok   synthetic OpenVPN full server is running", flush=True)

original_default = docker_exec(
    client_name, "ip", "-4", "route", "show", "default"
).splitlines()[0].split()
docker_exec(
    client_name,
    "ip",
    "-4",
    "route",
    "replace",
    "default",
    "via",
    server_ip,
    "dev",
    "eth0",
)
underlay_probe = (
    'from urllib.request import urlopen; '
    'print(urlopen("http://198.18.0.2:8765/server-health.txt", timeout=3).read().decode().strip())'
)
assert docker_exec(client_name, "python3", "-c", underlay_probe) == "netorch-e2e-server"
print("ok   OpenVPN endpoint reachable through underlay default", flush=True)

full_config = config.replace(
    f"remote {server_ip} 1194", "remote 198.18.0.2 1195"
)
full_params = {
    "profileId": "ovpn-full",
    "config": full_config,
    "assets": {},
    "routes": [],
}
initial = rpc("openvpn.connect", full_params)["status"]
assert initial["state"] in ("connecting", "connected")
for _ in range(60):
    full_status = rpc("openvpn.status", {"profileId": "ovpn-full"})
    if full_status["state"] == "connected":
        break
    if full_status["state"] == "failed":
        raise RuntimeError("OpenVPN full client reported failed state")
    time.sleep(0.5)
else:
    raise RuntimeError("OpenVPN full client did not connect")
full_interface = full_status["interfaceName"]
assert full_interface and full_interface.startswith("ovpn-")
print("ok   daemon connected OpenVPN full client", flush=True)

rules = docker_exec(client_name, "ip", "-4", "rule", "show")
match = re.search(r"fwmark (0x[0-9a-f]+) lookup ([0-9]+) proto 79", rules)
assert match, "full tunnel has no owned fwmark policy rule"
mark, table = match.groups()
marked_endpoint = docker_exec(
    client_name, "ip", "-4", "route", "get", "198.18.0.2", "mark", mark
)
plain_endpoint = docker_exec(client_name, "ip", "-4", "route", "get", "198.18.0.2")
payload_route = docker_exec(client_name, "ip", "-4", "route", "get", "192.168.77.1")
assert f"via {server_ip}" in marked_endpoint and "dev eth0" in marked_endpoint
assert f"dev {full_interface}" in plain_endpoint
assert f"dev {full_interface}" in payload_route
print("ok   marked transport uses underlay, payload uses OpenVPN", flush=True)

payload_probe = (
    'from urllib.request import urlopen; '
    'print(urlopen("http://192.168.77.1:8765/server-health.txt", timeout=3).read().decode().strip())'
)
assert docker_exec(client_name, "python3", "-c", payload_probe) == "netorch-e2e-server"
print("ok   HTTP crossed OpenVPN full tunnel", flush=True)

run(
    "docker",
    "exec",
    "-d",
    server_name,
    "python3",
    "/opt/netorch/e2e/dns_peer.py",
    "10.79.0.1",
    "192.168.77.1",
    "/run/ovpn-e2e-dns-count",
    "/run/ovpn-e2e-dns-ready",
)
for _ in range(20):
    try:
        docker_exec(server_name, "cat", "/run/ovpn-e2e-dns-ready")
        break
    except RuntimeError:
        time.sleep(0.1)
else:
    raise RuntimeError("OpenVPN test DNS peer did not start")
for _ in range(20):
    full_status = rpc("openvpn.status", {"profileId": "ovpn-full"})
    if "dnsNotApplied" not in full_status["warnings"]:
        break
    time.sleep(0.5)
resolved = docker_exec(client_name, "resolvectl", "status", full_interface)
assert "10.79.0.1" in resolved and "~." in resolved
answer = docker_exec(client_name, "resolvectl", "query", "ovpn-e2e.test")
assert "192.168.77.1" in answer
assert int(docker_exec(server_name, "cat", "/run/ovpn-e2e-dns-count")) > 0
print("ok   pushed DNS query reached peer through OpenVPN", flush=True)

assert rpc("openvpn.disconnect", {"profileId": "ovpn-full"}) == {"stopped": True}
docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
rules = docker_exec(client_name, "ip", "-4", "rule", "show")
assert f"lookup {table}" not in rules
table_routes = docker_exec(client_name, "ip", "-4", "route", "show", "table", table)
assert not table_routes.strip(), "OpenVPN full table survived disconnect"
print("ok   full disconnect removed OpenVPN rules, routes, and DNS link", flush=True)

docker_exec(
    client_name,
    "ip",
    "-4",
    "route",
    "replace",
    "default",
    "via",
    server_ip,
    "dev",
    "eth0",
)
again = rpc("openvpn.connect", full_params)["status"]
assert again["state"] in ("connecting", "connected")
for _ in range(60):
    status = rpc("openvpn.status", {"profileId": "ovpn-full"})
    if status["state"] == "connected":
        break
    if status["state"] == "failed":
        raise RuntimeError("OpenVPN full reconnect failed before crash test")
    time.sleep(0.5)
else:
    raise RuntimeError("OpenVPN full reconnect timed out before crash test")
crash_interface = status["interfaceName"]
docker_exec(
    client_name,
    "systemctl",
    "kill",
    "-s",
    "KILL",
    "network-orchestrator.service",
)
for _ in range(30):
    time.sleep(0.5)
    try:
        owners = rpc("owned.list", None)["owners"]
    except RuntimeError:
        continue
    if not any(entry["owner"].endswith("ovpn-full") for entry in owners):
        break
else:
    raise RuntimeError("daemon did not recover crashed OpenVPN full owner")
print("ok   daemon restarted and removed crashed full OpenVPN owner", flush=True)

try:
    docker_exec(client_name, "ip", "link", "show", crash_interface)
except RuntimeError:
    pass
else:
    raise RuntimeError("OpenVPN full link survived daemon crash")
rules = docker_exec(client_name, "ip", "-4", "rule", "show")
assert f"lookup {table}" not in rules, "OpenVPN full rule survived daemon crash"
table_routes = docker_exec(client_name, "ip", "-4", "route", "show", "table", table)
assert not table_routes.strip(), "OpenVPN full routes survived daemon crash"
try:
    docker_exec(client_name, "pgrep", "openvpn")
except RuntimeError:
    pass
else:
    raise RuntimeError("OpenVPN full child survived daemon crash")
docker_exec(client_name, "ip", "-4", "route", "replace", *original_default)
print("ok   crash recovery removed full child, link, rules, routes, and DNS link", flush=True)

print("ALL 19 OPENVPN CHECKS PASSED", flush=True)

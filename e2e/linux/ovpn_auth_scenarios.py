#!/usr/bin/env python3
"""OpenVPN management credentials against a disposable auth-required peer."""

import json
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
            client_name, "python3", "-c", code, method, input_text=json.dumps(params)
        )
    )
    if not response.get("ok"):
        raise RuntimeError(f"{method} failed: {response.get('error', {}).get('code')}")
    return response["result"]


def wait_state(profile_id, expected):
    for _ in range(60):
        status = rpc("openvpn.status", {"profileId": profile_id})
        if status["state"] == expected:
            return status
        if status["state"] == "failed" and expected != "failed":
            raise RuntimeError("OpenVPN auth client failed")
        time.sleep(0.5)
    raise RuntimeError(f"OpenVPN auth client did not reach {expected}")


print("\n=== OpenVPN management credentials in disposable containers", flush=True)
docker_exec(server_name, "sh", "/opt/netorch/e2e/ovpn_auth_server.sh")
for _ in range(30):
    try:
        docker_exec(server_name, "ip", "link", "show", "ovpn-auth")
        break
    except RuntimeError:
        time.sleep(0.2)
else:
    raise RuntimeError("OpenVPN auth server did not start")

server_ip = docker_exec(
    client_name,
    "python3",
    "-c",
    'import socket; print(socket.gethostbyname("wg-server"))',
)
ca = docker_exec(server_name, "cat", "/run/ovpn-e2e/ca.crt")
cert = docker_exec(server_name, "cat", "/run/ovpn-e2e/client.crt")
key = docker_exec(server_name, "cat", "/run/ovpn-e2e/client-encrypted.key")
config = (
    "client\n"
    "dev tun\n"
    "proto udp4\n"
    f"remote {server_ip} 1196\n"
    "nobind\n"
    "remote-cert-tls server\n"
    "auth-user-pass\n"
    f"<ca>\n{ca}\n</ca>\n"
    f"<cert>\n{cert}\n</cert>\n"
    f"<key>\n{key}\n</key>\n"
)
credentials = {
    "authUserPass": {"username": "alice", "password": "correct-horse"},
    "privateKeyPassphrase": "correct-key",
}
params = {
    "profileId": "ovpn-auth-e2e",
    "config": config,
    "assets": {},
    "routes": [],
    "credentials": credentials,
}
probe_params = dict(params)
probe_params["profileId"] = "ovpn-auth-probe"
probe = rpc("openvpn.probe", probe_params)
assert any(route["destination"] == "10.89.0.0/24" for route in probe["routes"])
assert not any(
    entry["owner"] == "ovpn-probe:ovpn-auth-probe"
    for entry in rpc("owned.list", None)["owners"]
)
print("ok   credentialed probe returned pushed route and cleaned owner", flush=True)

initial = rpc("openvpn.connect", params)["status"]
assert initial["state"] in ("connecting", "connected")
connected = wait_state("ovpn-auth-e2e", "connected")
interface = connected["interfaceName"]
assert interface and interface.startswith("ovpn-")
print("ok   auth-user-pass and encrypted key connected over management", flush=True)

assert rpc("openvpn.disconnect", {"profileId": "ovpn-auth-e2e"}) == {
    "stopped": True
}
assert rpc("openvpn.status", {"profileId": "ovpn-auth-e2e"})["state"] == "stopped"
print("ok   credentialed connection disconnected cleanly", flush=True)

bad = dict(params)
bad["profileId"] = "ovpn-auth-bad"
bad["credentials"] = {
    **credentials,
    "authUserPass": {"username": "alice", "password": "incorrect-horse"},
}
initial = rpc("openvpn.connect", bad)["status"]
assert initial["state"] in ("connecting", "failed")
failed = wait_state("ovpn-auth-bad", "failed")
assert "authenticationFailed" in failed["warnings"], "auth rejection had no typed warning"
assert not any(
    entry["owner"] == "ovpn:ovpn-auth-bad"
    for entry in rpc("owned.list", None)["owners"]
)
name = initial["interfaceName"]
assert name and name.startswith("ovpn-")
result = subprocess.run(
    ["docker", "exec", client_name, "test", "-e", f"/run/network-orchestrator/0/{name}"],
    capture_output=True,
    check=False,
)
assert result.returncode != 0, "failed auth staging survived"
assert rpc("openvpn.disconnect", {"profileId": "ovpn-auth-bad"}) == {"stopped": True}
cleared = rpc("openvpn.status", {"profileId": "ovpn-auth-bad"})
assert cleared["state"] == "stopped" and not cleared["warnings"]
print("ok   rejected password had typed warning, no leftovers, and clearable status", flush=True)
print("ALL 4 OPENVPN AUTH CHECKS PASSED", flush=True)

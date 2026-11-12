#!/usr/bin/env python3
"""Native Mihomo CLI/daemon/TUN acceptance; only disposable harness containers."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import xray_scenarios as fixture


def rpc(client, method, params, user=None):
    command = ["python3", "-c", "import json,sys;sys.path.insert(0,'/opt/netorch/e2e');from client import call;print(json.dumps(call(sys.argv[1],json.load(sys.stdin))))", method]
    if user:
        command = ["runuser", "-u", user, "--", *command]
    response = json.loads(fixture.docker_exec(client, *command, input_text=json.dumps(params)))
    return response


def require_rpc(client, method, params, user=None):
    response = rpc(client, method, params, user)
    if not response.get("ok"):
        raise RuntimeError(f"{method} rejected: {response.get('error', {}).get('code')}")
    return response["result"]


def cli(client, *args):
    result = fixture.docker_exec(client, "runuser", "-u", "alice", "--", "env", "HOME=/home/alice", "XDG_RUNTIME_DIR=/run/user/1001", "/usr/bin/netorch", "--data-dir", "/home/alice/mihomo-e2e", "--json", *args)
    return json.loads(result)


def wait_until(check, message, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (RuntimeError, OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError(message)


def state(client, profile):
    return require_rpc(client, "mihomo.status", {"profileId": profile}, "alice")


def link_absent(client, name):
    return fixture.docker_exec(client, "python3", "-c", "from pathlib import Path;import sys;print(not Path('/sys/class/net',sys.argv[1]).exists())", name) == "True"


def network_snapshot(client):
    return tuple(
        tuple(sorted(json.dumps(row, sort_keys=True) for row in json.loads(
            fixture.docker_exec(client, "ip", "-j", family, kind, "show", *extra)
        )))
        for family in ("-4", "-6")
        for kind, extra in (("rule", []), ("route", ["table", "all"]))
    )


def mihomo_processes(client):
    return json.loads(fixture.docker_exec(client, "python3", "-c", """
import json,os
from pathlib import Path
found=[]
for path in Path('/proc').iterdir():
    if path.name.isdigit():
        try:
            if os.readlink(path/'exe').startswith('/usr/lib/network-orchestrator/mihomo/'):
                found.append(int(path.name))
        except OSError:
            pass
print(json.dumps(sorted(found)))
"""))


def start_marker(server):
    script = """
import http.server,json,socket
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'marker':'mihomo-e2e','client':self.client_address[0].removeprefix('::ffff:')}).encode()
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args): pass
class Server(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        super().server_bind()
Server(('::',8766),Handler).serve_forever()
"""
    fixture.docker_exec(server, "python3", "-c", "import sys;open('/tmp/mihomo-marker.py','w').write(sys.stdin.read())", input_text=script)
    fixture.docker_exec(server, "sh", "-c", "python3 /tmp/mihomo-marker.py >/dev/null 2>&1 &")
    fixture.wait_tcp(server, 8766)


def start_split_observer(client, interface):
    script = """
import socket,sys,time
from pathlib import Path
sock=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(3))
sock.bind((sys.argv[1],0))
sock.settimeout(0.25)
Path('/run/mihomo-split-ready').write_text('ready')
count=0
deadline=time.monotonic()+8
while time.monotonic()<deadline:
    try:
        packet=sock.recv(65535)
    except socket.timeout:
        continue
    if len(packet)>=24 and packet[0]>>4==4 and packet[9]==6 and packet[16:20]==socket.inet_aton('10.75.0.1'):
        offset=(packet[0]&15)*4
        if len(packet)>=offset+4 and int.from_bytes(packet[offset+2:offset+4],'big')==8766:
            count+=1
Path('/run/mihomo-split-packets').write_text(str(count))
"""
    fixture.docker_exec(client,"python3","-c","import sys;open('/tmp/mihomo-split-observer.py','w').write(sys.stdin.read())",input_text=script)
    fixture.docker_exec(client,"python3","-c","import subprocess,sys;subprocess.Popen(['python3','/tmp/mihomo-split-observer.py',sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)",interface)
    wait_until(lambda: fixture.docker_exec(client,"test","-f","/run/mihomo-split-ready")=="","split packet observer did not start")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: mihomo_scenarios.py CLIENT SERVER (disposable harness only)")
    client, server = sys.argv[1:]
    archive_path = Path(os.environ["MIHOMO_E2E_ARCHIVE"])
    cli_path = Path(os.environ.get("NETORCH_E2E_CLI", str(fixture.ROOT / "target/debug/netorch")))
    archive = archive_path.read_bytes()
    if len(archive) > 32 * 1024 * 1024:
        raise AssertionError("Mihomo fixture archive exceeds its bound")
    fixture.run("docker", "cp", str(cli_path), f"{client}:/usr/bin/netorch")
    fixture.docker_exec(client, "chmod", "0755", "/usr/bin/netorch")
    bad = bytearray(archive)
    bad[-1] ^= 1
    rejected = rpc(client, "mihomo.install", {"archiveB64": base64.b64encode(bad).decode()})
    assert not rejected.get("ok"), "tampered optional component must be rejected"
    require_rpc(client, "mihomo.install", {"archiveB64": base64.b64encode(archive).decode()})
    print("ok   optional component installation rejects tamper and accepts pinned archive", flush=True)

    fixture.docker_exec(client, "install", "-d", "-m", "0700", "-o", "1001", "-g", "1001", "/home/alice/mihomo-inputs", "/run/user/1001")
    policy = "polkit.addRule(function(action,subject){if(subject.user==='alice' && action.id.indexOf('com.netmanager.app.')===0)return polkit.Result.YES;});\n"
    fixture.docker_exec(client, "python3", "-c", "import sys;open('/etc/polkit-1/rules.d/00-mihomo-e2e.rules','w').write(sys.stdin.read())", input_text=policy)
    fixture.docker_exec(client, "systemctl", "restart", "polkit.service")
    fixture.docker_exec(server, "install", "-d", "-m", "0755", "/opt/netorch/bin")
    fixture.run("docker", "cp", str(fixture.XRAY), f"{server}:{fixture.CLIENT_XRAY}")
    server_ip = fixture.docker_exec(client, "python3", "-c", "import socket,sys;print(socket.gethostbyname(sys.argv[1]))", server)
    fixture.docker_exec(server, "ip", "addr", "add", "10.75.0.1/32", "dev", "lo")
    fixture.docker_exec(server, "ip", "addr", "add", "10.76.0.1/32", "dev", "lo")
    fixture.docker_exec(server, "ip", "-6", "addr", "add", "fd00:75::1/128", "dev", "lo")
    fixture.docker_exec(client, "ip", "route", "add", "10.75.0.0/24", "via", server_ip, "dev", "eth0")
    client_ip = fixture.docker_exec(client, "python3", "-c", "import json,subprocess;print(next(a['local'] for a in json.loads(subprocess.check_output(['ip','-j','-4','addr','show','dev','eth0']))[0]['addr_info'] if a['family']=='inet'))")
    start_marker(server)
    vless_id = str(uuid.uuid4())
    peer = {
        "log": {"loglevel": "none"},
        "dns": {"hosts": {"xray-e2e.test": "10.76.0.1"}},
        "inbounds": [{"listen": "0.0.0.0", "port": 11001, "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": vless_id}]}, "streamSettings": {"network": "raw", "security": "none"}}],
        "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP", "finalRules": [{"action": "allow", "ip": [server_ip, "10.75.0.0/24", "10.76.0.0/24", "fd00:75::/64"]}]}}],
    }
    fixture.write_container_json(server, "/tmp/mihomo-peer.json", peer)
    fixture.start_xray(server, "/tmp/mihomo-peer.json", "mihomo-peer")
    fixture.docker_exec(server, "sh", "-c", f"python3 /opt/netorch/e2e/dns_peer.py {server_ip} 10.76.0.1 /run/mihomo-dns-count /run/mihomo-dns-ready >/dev/null 2>&1 &")
    profile_id = "mihomo-e2e"
    split_id = "mihomo-split-e2e"
    try:
        fixture.wait_tcp(server, 11001)
        wait_until(lambda: fixture.docker_exec(server, "test", "-f", "/run/mihomo-dns-ready") == "", "fixture DNS did not start")
        working = {"name": "Working", "type": "vless", "server": server_ip, "port": 11001, "uuid": vless_id, "network": "tcp", "tls": False, "udp": True}
        unreachable = {**working, "name": "Unreachable", "port": 1}
        native = {
            "proxies": [unreachable],
            "proxy-providers": {"Fixture": {"type": "inline", "payload": [working], "exclude-filter": "^via-", "override": {"additional-prefix": "via-"}}},
            "proxy-groups": [
                {"name": "Pool", "type": "fallback", "use": ["Fixture"], "proxies": [], "url": "http://10.76.0.1:8765/server-health.txt", "interval": 60},
                {"name": "Selected", "type": "select", "proxies": ["Unreachable", "Pool"]},
            ],
            "rules": ["MATCH,Selected"],
            "dns": {"enable": True, "enhanced-mode": "redir-host", "nameserver": [server_ip], "default-nameserver": [server_ip]},
        }
        profile = {"id": profile_id, "name": "Mihomo E2E", "backend": "mihomo", "configPath": "", "interfaceName": "mh-e2e", "routes": [], "autoConnect": False, "mihomo": {"mode": "tun", "entryGroup": "Selected", "groupSelections": {"Selected": "Pool"}}}
        for filename, value in [("source.json", native), ("profile.json", profile)]:
            path = f"/home/alice/mihomo-inputs/{filename}"
            fixture.write_container_json(client, path, value)
            fixture.docker_exec(client, "chown", "1001:1001", path)
        cli(client, "profile", "create", "--file", "/home/alice/mihomo-inputs/profile.json", "--source", "/home/alice/mihomo-inputs/source.json")
        cli(client, "profile", "mihomo", "groups", profile_id)
        baseline_network = network_snapshot(client)
        before_processes = mihomo_processes(client)
        validation = require_rpc(client, "mihomo.validate", {"profileId": profile_id, "config": json.dumps(native), "routes": [{"destination":"0.0.0.0/0","metric":5}], "groupSelections":{"Selected":"Pool"}}, "alice")
        assert validation["valid"] is True
        assert network_snapshot(client) == baseline_network and mihomo_processes(client) == before_processes, "preview validation mutated network or spawned a backend"
        direct_v6 = subprocess.run(["docker","exec",client,"curl","--silent","--show-error","--fail","--max-time","2","--noproxy","*","http://[fd00:75::1]:8766/"],capture_output=True,timeout=5)
        assert direct_v6.returncode != 0, "IPv6 target unexpectedly reachable without the tunnel"
        direct_v4 = subprocess.run(["docker","exec",client,"curl","--silent","--show-error","--fail","--max-time","2","--noproxy","*","http://10.76.0.1:8765/server-health.txt"],capture_output=True,timeout=5)
        assert direct_v4.returncode != 0, "IPv4 payload unexpectedly reachable without the tunnel"
        cli(client, "up", profile_id)
        running = state(client, profile_id)
        assert running["state"] == "running", "daemon must own the connection after CLI exits"
        interface = running["interfaceName"]
        resolved = fixture.docker_exec(client, "resolvectl", "query", "--cache=no", "--legend=no", "xray-e2e.test")
        assert "10.76.0.1" in resolved, "system resolver did not use the native TUN DNS policy"
        body = fixture.docker_exec(client, "curl", "--silent", "--show-error", "--fail", "--max-time", "10", "--noproxy", "*", "--resolve", "xray-e2e.test:8765:10.76.0.1", "http://xray-e2e.test:8765/server-health.txt")
        assert body == "netorch-e2e-server", "native selected provider group did not carry TUN payload"
        assert int(fixture.docker_exec(server, "cat", "/run/mihomo-dns-count")) > 0, "configured native DNS resolver was not used"
        ipv6 = json.loads(fixture.docker_exec(client, "curl", "--silent", "--show-error", "--fail", "--max-time", "10", "--noproxy", "*", "http://[fd00:75::1]:8766/"))
        assert ipv6["marker"] == "mihomo-e2e", "native TUN did not carry IPv6 through the VLESS peer"
        print("ok   read-only preview; native provider selection, IPv4/IPv6 TUN HTTP and DNS pass", flush=True)
        rpc(client, "mihomo.disconnect", {"profileId": profile_id}, "bob")
        assert state(client, profile_id)["state"] == "running", "another UID must not disconnect the owner"
        cli(client, "down", profile_id)
        assert state(client, profile_id)["state"] == "stopped"
        assert link_absent(client, interface), "explicit down must remove the owned TUN"
        assert network_snapshot(client) == baseline_network, "down left kernel routes or policy rules"
        assert not mihomo_processes(client), "down left a managed Mihomo child"
        print("ok   connection survives client exit; other UID cannot stop it; explicit down removes resources", flush=True)
        split_native = {**native, "rules":["IP-CIDR,10.75.0.0/24,DIRECT,no-resolve",*native["rules"]]}
        split_profile = {**profile, "id":split_id, "name":"Mihomo split E2E", "interfaceName":"mh-split", "tunnelRole":"secondary", "routes":[], "tunnelNetworks":["10.75.0.0/24"]}
        for filename, value in [("source-split.json",split_native),("profile-split.json",split_profile)]:
            path = f"/home/alice/mihomo-inputs/{filename}"
            fixture.write_container_json(client,path,value)
            fixture.docker_exec(client,"chown","1001:1001",path)
        cli(client,"profile","create","--file","/home/alice/mihomo-inputs/profile-split.json","--source","/home/alice/mihomo-inputs/source-split.json")
        cli(client,"up",profile_id)
        primary_network = network_snapshot(client)
        cli(client,"up",split_id)
        start_split_observer(client,state(client,split_id)["interfaceName"])
        direct = json.loads(fixture.docker_exec(client,"curl","--silent","--show-error","--fail","--max-time","10","--noproxy","*","http://10.75.0.1:8766/"))
        assert direct["client"] == client_ip, "native DIRECT did not use the marked physical path inside split capture"
        wait_until(lambda: fixture.docker_exec(client,"test","-f","/run/mihomo-split-packets")=="","split packet observer did not finish",seconds=12)
        assert int(fixture.docker_exec(client,"cat","/run/mihomo-split-packets"))>0, "scoped payload bypassed the TUN; physical success alone is not proof"
        cli(client,"down",split_id)
        assert network_snapshot(client) == primary_network and len(mihomo_processes(client))==1, "split disconnect disturbed the primary or left owned resources"
        assert state(client,profile_id)["state"]=="running", "secondary lifecycle stopped the primary"
        body = fixture.docker_exec(client,"curl","--silent","--show-error","--fail","--max-time","10","--noproxy","*","http://10.76.0.1:8765/server-health.txt")
        assert body=="netorch-e2e-server", "primary traffic stopped after secondary teardown"
        cli(client,"down",profile_id)
        assert network_snapshot(client)==baseline_network and not mihomo_processes(client), "teardown left resources"
        print("ok   secondary captured packets; marked DIRECT escapes its TUN; primary and foreign routes survive",flush=True)
        cli(client, "up", profile_id)
        interface = state(client, profile_id)["interfaceName"]
        fixture.docker_exec(client, "systemctl", "kill", "--kill-whom=main", "--signal=KILL", "network-orchestrator.service")
        wait_until(lambda: state(client, profile_id)["state"] == "stopped" and link_absent(client, interface), "daemon crash recovery left owned Mihomo resources", seconds=40)
        assert network_snapshot(client) == baseline_network, "crash recovery left kernel routes or policy rules"
        assert not mihomo_processes(client), "crash recovery left the managed process alive"
        print("ok   daemon crash recovery removes journaled process, interface, policy routes and DNS", flush=True)
    finally:
        for owned_id in (split_id,profile_id):
            try:
                cli(client, "down", owned_id)
            except (RuntimeError, ValueError):
                pass
        fixture.stop_xray(server, "mihomo-peer")
    cli(client,"backend","mihomo","remove")
    print("ALL MIHOMO TUN/CLI CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()

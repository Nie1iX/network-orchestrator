#!/usr/bin/env python3
"""Minimal NDJSON client for network-orchestrator-daemon (E2E only).

usage: client.py METHOD [PARAMS_JSON]
Prints the response `result` as JSON and exits 0, or prints the error
object and exits 1. Performs the mandatory hello first.
"""
import json
import os
import socket
import sys

SOCKET = os.environ.get("NETWORK_ORCHESTRATOR_SOCKET", "/run/network-orchestrator/daemon.sock")


def call(method, params=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        stream = sock.makefile("rwb")

        def request(req_id, name, body):
            frame = {"id": req_id, "method": name}
            if body is not None:
                frame["params"] = body
            stream.write(json.dumps(frame).encode() + b"\n")
            stream.flush()
            line = stream.readline()
            if not line:
                raise SystemExit("daemon closed the connection")
            return json.loads(line)

        hello = request(1, "hello", {"protocol": 1, "client": "e2e-client"})
        if not hello.get("ok"):
            return hello
        return request(2, method, params)


def main():
    method = sys.argv[1]
    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    response = call(method, params)
    if response.get("ok"):
        print(json.dumps(response.get("result")))
        return 0
    print(json.dumps(response.get("error")))
    return 1


if __name__ == "__main__":
    sys.exit(main())

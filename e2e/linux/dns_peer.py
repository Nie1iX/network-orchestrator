#!/usr/bin/env python3
"""Fixture DNS server for the disposable WireGuard peer container."""

import socket
import struct
import sys
from ipaddress import IPv4Address
from pathlib import Path


def build_response(packet: bytes, answer_ip: bytes = b"\x0a\x58\x00\x01") -> bytes | None:
    if len(packet) < 17:
        return None
    question_count = struct.unpack_from("!H", packet, 4)[0]
    if question_count != 1:
        return None
    offset = 12
    labels = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            return None
        try:
            labels.append(packet[offset : offset + length].decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        offset += length
    else:
        return None
    if offset + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    question = packet[12 : offset + 4]
    answer = labels in (
        ["wg-e2e", "test"],
        ["ovpn-e2e", "test"],
        ["xray-e2e", "test"],
    ) and qtype == 1 and qclass == 1
    header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(answer), 0, 0)
    if not answer:
        return header + question
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + answer_ip
    return header + question + record


def main():
    if len(sys.argv) not in (1, 5):
        raise SystemExit("usage: dns_peer.py [bind-ip answer-ip counter-file ready-file]")
    bind_ip, answer_ip, counter_name, ready_name = (
        sys.argv[1:]
        if len(sys.argv) == 5
        else (
            "10.77.0.1",
            "10.76.0.1",
            "/run/wg-e2e-dns-count",
            "/run/wg-e2e-dns-ready",
        )
    )
    counter = Path(counter_name)
    answer = IPv4Address(answer_ip).packed
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((bind_ip, 53))
        Path(ready_name).touch()
        while True:
            packet, address = server.recvfrom(4096)
            response = build_response(packet, answer)
            if response is None:
                continue
            count += 1
            counter.write_text(str(count))
            server.sendto(response, address)


if __name__ == "__main__":
    main()

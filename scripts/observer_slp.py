#!/usr/bin/env python3
"""Server List Ping observer: compare mcvpn's answer to a real public
Minecraft server's. Usage: observer_slp.py host:port [host:port ...]"""
import json
import socket
import struct
import sys
import time


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def slp(host, port, timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    hostb = host.encode()
    hs = varint(0) + varint(47) + varint(len(hostb)) + hostb + struct.pack(">H", port) + varint(1)
    s.sendall(varint(len(hs)) + hs)
    s.sendall(varint(1) + b"\x00")
    body = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        body += chunk
        if len(body) > 65536:
            break
    def rv(buf, off):
        val = 0
        for i in range(5):
            b = buf[off]
            off += 1
            val |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                return val, off
        raise ValueError("varint too big")
    n, off = rv(body, 0)
    frame = body[off : off + n]
    slen, off2 = rv(frame, 1)
    js = frame[off2 : off2 + slen]
    ping = struct.pack(">q", int(time.time() * 1000))
    pkt = b"\x01" + ping
    t1 = time.time()
    s.sendall(varint(len(pkt)) + pkt)
    pong = b""
    while len(pong) < 3 + 8:
        chunk = s.recv(64)
        if not chunk:
            break
        pong += chunk
    rtt = (time.time() - t1) * 1000
    s.close()
    return json.loads(js), rtt


for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    try:
        js, rtt = slp(host, int(port))
        print(f"== {target} ==")
        print(json.dumps(js, indent=2, sort_keys=False))
        print(f"ping/pong rtt: {rtt:.1f} ms")
    except Exception as e:
        print(f"== {target} == FAILED: {e}")

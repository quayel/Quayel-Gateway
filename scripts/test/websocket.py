#!/usr/bin/env python3
"""Live check of WebSocket proxying.

Usage: BIN=path/to/quayel-gateway scripts/test/websocket.py

Starts a small WebSocket echo origin (stdlib only) and gateways in front of
it, then checks the upgrade, echo, ping/pong, server push, a firewall block
on the upgrade, and the two settings that matter for long-lived sockets:
  - traffic after the upgrade never counts against server.limits.max_body_bytes
  - an idle socket outlives body_read_secs / upstream_read_secs and is only
    closed by server.timeouts.websocket_idle_secs (0, the default → never)
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module asyncio imports.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import asyncio
import base64
import hashlib
import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))
ORIGIN_PORT = 18411
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


# ── WebSocket framing ────────────────────────────────────────────────────────

def frame(op, payload, mask):
    head = bytes([0x80 | op])
    n = len(payload)
    m = 0x80 if mask else 0
    if n < 126:
        head += bytes([m | n])
    elif n < 65536:
        head += bytes([m | 126]) + struct.pack(">H", n)
    else:
        head += bytes([m | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


async def read_frame(r):
    b0, b1 = await r.readexactly(2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", await r.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", await r.readexactly(8))[0]
    key = await r.readexactly(4) if b1 & 0x80 else None
    p = await r.readexactly(n)
    if key:
        p = bytes(b ^ key[i % 4] for i, b in enumerate(p))
    return b0 & 0x0F, p


# ── Echo origin ──────────────────────────────────────────────────────────────

async def origin(r, w):
    try:
        head = (await r.readuntil(b"\r\n\r\n")).decode()
        lines = head.split("\r\n")
        path = lines[0].split(" ")[1]
        hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        if "sec-websocket-key" not in hdrs:  # plain HTTP: read the body, answer 200
            n = int(hdrs.get("content-length", "0"))
            await r.readexactly(n)
            w.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(str(n))}\r\nConnection: close\r\n\r\n{n}".encode())
            await w.drain(); w.close(); return
        acc = base64.b64encode(hashlib.sha1(hdrs["sec-websocket-key"].encode() + GUID).digest()).decode()
        w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
        await w.drain()
        if path == "/push":
            for i in range(3):
                w.write(frame(1, f"push {i}".encode(), False))
            await w.drain()
        while True:
            op, p = await read_frame(r)
            if op == 8:
                w.write(frame(8, p, False)); await w.drain(); break
            w.write(frame(10 if op == 9 else op, p, False)); await w.drain()
    except Exception:
        pass
    w.close()


# ── Client helpers ───────────────────────────────────────────────────────────

async def connect(port, path="/ws"):
    r, w = await asyncio.open_connection("127.0.0.1", port, limit=1 << 24)
    key = base64.b64encode(os.urandom(16)).decode()
    w.write((f"GET {path} HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    resp = (await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)).decode()
    acc = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    return r, w, resp, acc


async def echo(r, w, data, op=1):
    w.write(frame(op, data, True)); await w.drain()
    o, p = await asyncio.wait_for(read_frame(r), 10)
    return p == data


async def echo_after_idle(port, secs):
    r, w, _, _ = await connect(port)
    await asyncio.sleep(secs)
    try:
        ok = await echo(r, w, b"after idle")
    except Exception:
        ok = False
    w.close()
    return ok


def start_gateway(port, server, log_path):
    cfg = {
        "gateway_id": "ws-test", "gateway_name": "ws-test", "server_name": "ws-test",
        "config_version": "1",
        "listen": {"http": f"127.0.0.1:{port}"},
        "server": server,
        "plugins": {
            "firewall": {"enabled": True, "rules": [{
                "id": "block-admin", "name": "b", "enabled": True,
                "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/admin"}],
                "action": {"type": "block", "status": 403}}]},
            "load_balancer": {"enabled": True, "load_balancers": [{
                "id": "lb", "name": "lb", "conditions": [], "algorithm": {"type": "round_robin"},
                "targets": [{"id": "o", "host": "127.0.0.1", "port": ORIGIN_PORT}],
                "health_check": {"mode": "off"}}]},
            "logging": {"enabled": True, "file": {"path": log_path, "flush_interval_ms": 100}},
        },
    }
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(cfg, f); f.close()
    p = subprocess.Popen([BINARY, "--config", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # A TCP connect, not an HTTP request: the origin runs on this thread's
    # event loop, which is blocked here.
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.1)
    return p


def post(port, size):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/upload", data=b"x" * size, method="POST")
    try:
        return urllib.request.urlopen(req, timeout=10).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return type(e).__name__


async def main():
    srv = await asyncio.start_server(origin, "127.0.0.1", ORIGIN_PORT, limit=1 << 24)
    tmp = tempfile.mkdtemp()
    gws = []
    try:
        # 1. Defaults: no body limit, no WebSocket idle limit.
        print("── defaults ──")
        gws.append(start_gateway(18410, {}, os.path.join(tmp, "a.log")))
        st = await asyncio.to_thread(post, 18410, 5 * 1024 * 1024)
        check("5 MB POST with default config is proxied", st == 200, str(st))

        # 2. Tight read timeouts and a 1000-byte body limit, websocket_idle_secs unset.
        print("── tight limits, websocket_idle_secs unset ──")
        log = os.path.join(tmp, "b.log")
        tight = {"timeouts": {"body_read_secs": 2, "upstream_read_secs": 2},
                 "limits": {"max_body_bytes": 1000},
                 "protection": {"exempt_ips": [], "ban": {"strikes": 1, "window_secs": 60, "duration_secs": 60}}}
        gws.append(start_gateway(18412, tight, log))

        r, w, resp, acc = await connect(18412)
        check("upgrade answered 101", " 101 " in resp.split("\r\n")[0], resp.split("\r\n")[0])
        check("Sec-WebSocket-Accept passed through", acc in resp)
        check("X-QG-Request-Id on the 101", "x-qg-request-id" in resp.lower())
        check("text echo", await echo(r, w, b"hello"))
        check("64 KB binary echo", await echo(r, w, os.urandom(65536), 2))
        w.write(frame(9, b"pingdata", True)); await w.drain()
        o, p = await asyncio.wait_for(read_frame(r), 5)
        check("ping -> pong", o == 10 and p == b"pingdata")
        sent = 0
        try:
            for _ in range(80):  # 80 × 64 KB = 5 MB through a 1000-byte body limit
                if not await echo(r, w, os.urandom(65536), 2):
                    break
                sent += 65536
        except Exception:
            pass
        check("5 MB over one socket ignores max_body_bytes", sent == 80 * 65536, f"{sent // 1024} KB echoed")
        w.close()

        r, w, _, _ = await connect(18412, "/push")
        got = [(await asyncio.wait_for(read_frame(r), 5))[1].decode() for _ in range(3)]
        check("server push reaches the client", got == ["push 0", "push 1", "push 2"], str(got))
        w.close()

        r, w, resp, _ = await connect(18412, "/admin/ws")
        check("firewall still blocks the upgrade", " 403 " in resp.split("\r\n")[0], resp.split("\r\n")[0])
        w.close()

        ok = await echo_after_idle(18412, 5)
        check("idle 5 s (> body_read_secs and upstream_read_secs) stays open", ok)

        st = await asyncio.to_thread(post, 18412, 5000)
        check("plain POST over max_body_bytes still gets 413", st == 413, str(st))

        await asyncio.sleep(0.5)
        lines = [json.loads(l) for l in open(log)]
        ws = [l for l in lines if l["status"] == 101]
        check("WebSocket sessions logged as 101 without a block",
              len(ws) >= 3 and all(l["block"]["type"] == "" for l in ws), f"{len(ws)} lines")
        big = max((l["req_bytes"] for l in ws), default=0)
        check("req_bytes counts the whole session", big >= 80 * 65536, str(big))

        # 3. websocket_idle_secs set: an idle socket is closed after it.
        print("── websocket_idle_secs: 2 ──")
        gws.append(start_gateway(18413, {"timeouts": {"websocket_idle_secs": 2}}, os.path.join(tmp, "c.log")))
        short, long_ = await asyncio.gather(echo_after_idle(18413, 1), echo_after_idle(18413, 4))
        check("idle 1 s stays open", short)
        check("idle 4 s is closed", not long_)
    finally:
        for g in gws:
            g.terminate()
            try:
                g.wait(5)
            except subprocess.TimeoutExpired:
                g.kill()
        srv.close()

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

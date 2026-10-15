#!/usr/bin/env python3
"""Live check of the UDP stream proxy (`protocol: "udp"`).

Usage: BIN=path/to/quayel-gateway scripts/test/udp-proxy.py

Starts UDP echo origins (stdlib only) and a gateway with several UDP
streams, then checks: forwarding both ways, one session per client address
(same target for all its datagrams, round robin across clients), a 60 KB
datagram, `responses: 1` (DNS-style), the idle timeout, a block rule, the
session cap, a TCP and a UDP stream on the same port number, hot reload,
the log line per session, and real DNS queries through the proxy (needs
`dig` and outbound DNS to 1.1.1.1; skipped otherwise).
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module asyncio imports.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import asyncio
import json
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))

HTTP = 18560
ECHO_A, ECHO_B, TCP_ECHO = 18561, 18562, 18563
S_RR, S_ONE, S_IDLE, S_RULES, S_CAP, S_SAME, S_RELOAD, S_DNS = range(18570, 18578)

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


class Echo(asyncio.DatagramProtocol):
    def __init__(self, tag):
        self.tag = tag.encode()

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(self.tag + b":" + data, addr)


async def tcp_echo(r, w):
    w.write(b"T:" + await r.read(100))
    await w.drain()
    w.close()


def client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    return s


def ask(sock, port, data=b"hi"):
    sock.sendto(data, ("127.0.0.1", port))
    try:
        return sock.recv(70000)
    except socket.timeout:
        return b""


def stream(sid, port, targets, **extra):
    s = {"id": sid, "protocol": "udp", "listen": f"127.0.0.1:{port}",
         "targets": [{"id": f"t{p}", "host": h, "port": p} for h, p in targets]}
    s.update(extra)
    return s


def config(log, reload_target=ECHO_A):
    lo = "127.0.0.1"
    streams = [
        stream("rr", S_RR, [(lo, ECHO_A), (lo, ECHO_B)]),
        stream("one", S_ONE, [(lo, ECHO_A), (lo, ECHO_B)], responses=1),
        stream("idle", S_IDLE, [(lo, ECHO_A)], idle_secs=1),
        stream("rules", S_RULES, [(lo, ECHO_A)], rules=[
            {"id": "no-local", "action": "block",
             "conditions": [{"left": "req.ip", "operator": "equals", "value": "127.0.0.1"}]}]),
        stream("cap", S_CAP, [(lo, ECHO_A)], max_sessions=2),
        stream("same-udp", S_SAME, [(lo, ECHO_B)]),
        {"id": "same-tcp", "listen": f"127.0.0.1:{S_SAME}",
         "targets": [{"id": "tcp", "host": lo, "port": TCP_ECHO}]},
        stream("reload", S_RELOAD, [(lo, reload_target)]),
        stream("dns", S_DNS, [("1.1.1.1", 53), ("1.0.0.1", 53)], responses=1),
    ]
    return {
        "gateway_id": "udp-test", "gateway_name": "udp-test", "server_name": "udp-test",
        "config_version": str(time.time()),
        "listen": {"http": f"127.0.0.1:{HTTP}"},
        "server": {"protection": {"exempt_ips": []}},
        "streams": streams,
        "plugins": {"logging": {"enabled": True, "file": {"path": log, "flush_interval_ms": 100}}},
    }


async def main():
    loop = asyncio.get_running_loop()
    a, _ = await loop.create_datagram_endpoint(lambda: Echo("A"), local_addr=("127.0.0.1", ECHO_A))
    b, _ = await loop.create_datagram_endpoint(lambda: Echo("B"), local_addr=("127.0.0.1", ECHO_B))
    tcp = await asyncio.start_server(tcp_echo, "127.0.0.1", TCP_ECHO)
    tmp = tempfile.mkdtemp()
    log = os.path.join(tmp, "access.log")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(config(log), f)
    gw = subprocess.Popen([BINARY, cfg_path], stdout=subprocess.DEVNULL,
                          stderr=open(os.path.join(tmp, "gw.err"), "w"))
    run = lambda f, *args: asyncio.to_thread(f, *args)
    try:
        ok = False
        for _ in range(50):
            if await run(ask, client(), S_RELOAD):
                ok = True
                break
            await asyncio.sleep(0.2)
        check("gateway starts with UDP listeners", ok)

        print("── sessions ──")
        c1, c2 = client(), client()
        r1 = [await run(ask, c1, S_RR, b"x") for _ in range(3)]
        r2 = await run(ask, c2, S_RR, b"x")
        check("datagrams forwarded both ways", r1[0] in (b"A:x", b"B:x"), repr(r1[0]))
        check("one client keeps its target", len(set(r1)) == 1, str(r1))
        check("next client gets the other target", r2 and r2 != r1[0], f"{r1[0]} {r2}")
        big = os.urandom(60000)
        got = await run(ask, c1, S_RR, big)
        check("60 KB datagram", got[2:] == big, f"{len(got)} bytes")

        c3 = client()
        first, second = await run(ask, c3, S_ONE), await run(ask, c3, S_ONE)
        check("responses: 1 ends the session after the reply (next datagram → new session)",
              first and second and first[:1] != second[:1], f"{first} {second}")

        c4 = client()
        r = await run(ask, c4, S_IDLE, b"1")
        await asyncio.sleep(2.5)
        check("idle session expires and the client can start again", r == b"A:1" and
              await run(ask, c4, S_IDLE, b"2") == b"A:2")

        print("── rules, cap, shared port number ──")
        c5 = client()
        got = [await run(ask, c5, S_RULES) for _ in range(3)]
        check("block rule: no reply", got == [b"", b"", b""], str(got))
        caps = [client() for _ in range(3)]
        got = [await run(ask, c, S_CAP) for c in caps]
        check("max_sessions 2: third client dropped", got[:2] == [b"A:hi", b"A:hi"] and got[2] == b"", str(got))
        got_udp = await run(ask, client(), S_SAME, b"u")
        r, w = await asyncio.open_connection("127.0.0.1", S_SAME)
        w.write(b"t"); await w.drain()
        got_tcp = await asyncio.wait_for(r.read(100), 3)
        w.close()
        check("TCP and UDP streams on the same port number", got_udp == b"B:u" and got_tcp == b"T:t",
              f"{got_udp} {got_tcp}")

        print("── real DNS ──")
        if shutil.which("dig") and subprocess.run(["dig", "+short", "+time=2", "+tries=1", "@1.1.1.1",
                                                    "example.com"], capture_output=True).returncode == 0:
            outs = [subprocess.run(["dig", "+short", "+time=3", "+tries=1", "-p", str(S_DNS), "@127.0.0.1",
                                    name], capture_output=True, text=True).stdout.strip()
                    for name in ("example.com", "cloudflare.com", "quayel.com")]
            check("dig through the proxy answers", all(o and "timed out" not in o for o in outs),
                  " | ".join(o.replace("\n", ",")[:40] for o in outs))
        else:
            print("  (skipped: dig or outbound DNS not available)")

        print("── hot reload ──")
        with open(cfg_path, "w") as f:
            json.dump(config(log, reload_target=ECHO_B), f)
        got = b""
        for _ in range(30):
            got = await run(ask, client(), S_RELOAD)
            if got.startswith(b"B:"):
                break
            await asyncio.sleep(0.5)
        check("reload switches the target for new sessions", got == b"B:hi", repr(got))

        print("── access log ──")
        gw.terminate()
        gw.wait(10)  # shutdown ends the open sessions, so every one is logged
        lines = [json.loads(l) for l in open(log) if l.strip()]
        udp = [l for l in lines if l["method"] == "UDP"]
        check("one line per session: method UDP, scheme udp",
              udp and all(l["scheme"] == "udp" for l in udp), f"{len(udp)} lines")
        big_line = max((l for l in udp if l["path"] == "rr"), key=lambda l: l["req_bytes"], default={})
        check("bytes counted per session", big_line.get("req_bytes") == 3 + 60000
              and big_line.get("bytes") == 3 * 3 + 60002, f"{big_line.get('req_bytes')}/{big_line.get('bytes')}")
        one = [l for l in udp if l["path"] == "one"]
        check("responses: 1 sessions logged at once with no error",
              len(one) == 2 and all(l["error"] == "" and l["status"] == 200 for l in one), str(len(one)))
        blocked = [l for l in udp if l["path"] == "rules"]
        check("blocked client logged once (403) for 3 datagrams",
              len(blocked) == 1 and blocked[0]["status"] == 403 and blocked[0]["block"]["rule"] == "no-local",
              json.dumps([l["status"] for l in blocked]))
        idle = [l for l in udp if l["path"] == "idle"]
        check("idle session logged when it expired", len(idle) == 2 and idle[0]["dur_us"] >= 1_000_000,
              str([l["dur_us"] for l in idle]))
        check("no panics", "panicked" not in open(os.path.join(tmp, "gw.err")).read())
    finally:
        if gw.poll() is None:
            gw.kill()
        a.close()
        b.close()
        tcp.close()

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

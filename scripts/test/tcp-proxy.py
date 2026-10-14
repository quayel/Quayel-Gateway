#!/usr/bin/env python3
"""Live check of the TCP stream proxy (`streams` in config.json).

Usage: BIN=path/to/quayel-gateway scripts/test/tcp-proxy.py

Starts small TCP origins (stdlib only) and one gateway with several streams,
then checks: forwarding and byte counts, round robin, a 20 MB transfer,
half-close, a server-speaks-first protocol, fallback to the next target,
502 / 503 when no target works, health checks, allow / block rules, PROXY
protocol v1 and v2, the idle timeout (off by default), per-IP connection
limits, hot reload of targets, and the access-log line per connection.

With Docker it also runs real Redis and PostgreSQL clients through the proxy.
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module asyncio imports.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import asyncio
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))

HTTP = 18500
ORIGIN_A, ORIGIN_B, BANNER, PROXYLINE, HTTP_ORIGIN, DEAD = 18501, 18502, 18503, 18504, 18505, 18509
S_RR, S_IDLE, S_FALLBACK, S_DEAD, S_HEALTH, S_RULES, S_PP1, S_PP2, S_BANNER, S_LIMIT, S_RELOAD = range(18510, 18521)
S_REDIS, S_PG = 18525, 18526
REDIS_PORT, PG_PORT = 18527, 18528

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


# ── Origins ──────────────────────────────────────────────────────────────────

def echo_origin(tag):
    """Answers each chunk with `tag:` + chunk; at EOF sends `tag:bye` and closes."""
    async def handle(r, w):
        try:
            first = True
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write((tag + ":").encode() + data if first else data)
                first = False
                await w.drain()
            w.write(f"{tag}:bye".encode())
            await w.drain()
        except Exception:
            pass
        w.close()
    return handle


async def banner_origin(r, w):
    """Talks first, like SMTP / MySQL / SSH."""
    w.write(b"220 banner ready\r\n")
    await w.drain()
    line = await r.readline()
    w.write(b"echo " + line)
    await w.drain()
    w.close()


async def http_origin(r, w):
    await r.readuntil(b"\r\n\r\n")
    w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    await w.drain()
    w.close()


async def proxyline_origin(r, w):
    """Sends back whatever PROXY header arrived before any client data."""
    head = await r.read(108)
    w.write(head)
    await w.drain()
    await asyncio.sleep(0.2)
    w.close()


# ── Client helpers ───────────────────────────────────────────────────────────

async def talk(port, data=b"hello", half_close=True, timeout=5):
    """Send data, optionally half-close, return everything received."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout)
        w.write(data)
        await w.drain()
        if half_close:
            w.write_eof()
        out = b""
        while True:
            chunk = await asyncio.wait_for(r.read(1 << 20), timeout)
            if not chunk:
                break
            out += chunk
        w.close()
        return out
    except Exception as e:
        return type(e).__name__.encode()


def closed(got):
    """Refused by the gateway: EOF or a reset (we were still sending)."""
    return got in (b"", b"ConnectionResetError", b"OSError", b"BrokenPipeError")


async def wait_port(port, secs=10):
    end = time.time() + secs
    while time.time() < end:
        try:
            _, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            return True
        except OSError:
            await asyncio.sleep(0.1)
    return False


def stream(sid, port, targets, **extra):
    s = {"id": sid, "listen": f"127.0.0.1:{port}",
         "targets": [{"id": f"t{p}", "host": "127.0.0.1", "port": p} for p in targets]}
    s.update(extra)
    return s


def config(log_path, streams):
    return {
        "gateway_id": "tcp-test", "gateway_name": "tcp-test", "server_name": "tcp-test",
        "config_version": str(time.time()),
        "listen": {"http": f"127.0.0.1:{HTTP}"},
        "server": {"protection": {"exempt_ips": [], "max_connections_per_ip": 20,
                                  "ban": {"enabled": False}}},
        "streams": streams,
        "plugins": {
            "load_balancer": {"enabled": True, "load_balancers": [{
                "id": "lb", "name": "lb", "conditions": [], "algorithm": {"type": "round_robin"},
                "targets": [{"id": "http-origin", "host": "127.0.0.1", "port": HTTP_ORIGIN}],
                "health_check": {"mode": "off"}}]},
            "logging": {"enabled": True, "file": {"path": log_path, "flush_interval_ms": 100}},
        },
    }


def log_lines(path):
    try:
        return [json.loads(l) for l in open(path) if l.strip()]
    except FileNotFoundError:
        return []


def docker_ok():
    return shutil.which("docker") and subprocess.run(
        ["docker", "info"], capture_output=True).returncode == 0


async def main():
    servers = [
        await asyncio.start_server(echo_origin("A"), "127.0.0.1", ORIGIN_A),
        await asyncio.start_server(echo_origin("B"), "127.0.0.1", ORIGIN_B),
        await asyncio.start_server(banner_origin, "127.0.0.1", BANNER),
        await asyncio.start_server(proxyline_origin, "127.0.0.1", PROXYLINE),
        await asyncio.start_server(http_origin, "127.0.0.1", HTTP_ORIGIN),
    ]
    tmp = tempfile.mkdtemp()
    log = os.path.join(tmp, "access.log")
    cfg_path = os.path.join(tmp, "config.json")
    use_docker = docker_ok()
    containers = []

    streams = [
        stream("rr", S_RR, [ORIGIN_A, ORIGIN_B]),
        stream("idle", S_IDLE, [ORIGIN_A], idle_secs=2),
        stream("fallback", S_FALLBACK, [DEAD, ORIGIN_A], connect_timeout_secs=2),
        stream("dead", S_DEAD, [DEAD]),
        stream("health", S_HEALTH, [DEAD],
               health_check={"mode": "accepts_connections", "interval_seconds": 1,
                             "timeout_ms": 300, "unhealthy_threshold": 1}),
        stream("rules", S_RULES, [ORIGIN_A], rules=[
            {"id": "allow-none", "conditions": [{"left": "req.ip", "operator": "equals", "value": "192.0.2.1"}],
             "action": "allow"},
            {"id": "block-local", "conditions": [{"left": "req.ip", "operator": "equals", "value": "127.0.0.1"}],
             "action": "block"}]),
        stream("pp1", S_PP1, [PROXYLINE], proxy_protocol="v1"),
        stream("pp2", S_PP2, [PROXYLINE], proxy_protocol="v2"),
        stream("banner", S_BANNER, [BANNER]),
        stream("limit", S_LIMIT, [ORIGIN_A]),
        stream("reload", S_RELOAD, [ORIGIN_A]),
    ]
    if use_docker:
        streams.append(stream("redis", S_REDIS, [REDIS_PORT]))
        streams.append(stream("pg", S_PG, [PG_PORT]))
        for name, args in [
            ("qg-tcp-redis", ["-p", f"127.0.0.1:{REDIS_PORT}:6379", "redis:7-alpine"]),
            ("qg-tcp-pg", ["-p", f"127.0.0.1:{PG_PORT}:5432", "-e", "POSTGRES_PASSWORD=pw", "postgres:16-alpine"]),
        ]:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            subprocess.run(["docker", "run", "-d", "--name", name] + args, capture_output=True, check=True)
            containers.append(name)

    with open(cfg_path, "w") as f:
        json.dump(config(log, streams), f)
    gw = subprocess.Popen([BINARY, cfg_path], stdout=subprocess.DEVNULL,
                          stderr=open(os.path.join(tmp, "gw.err"), "w"))
    try:
        ready = all([await wait_port(HTTP)] + [await wait_port(s) for s in (S_RR, S_RELOAD)])
        check("gateway starts with stream listeners", ready)
        # The readiness probes are proxied too; let them finish so they don't
        # take a round-robin turn in the middle of the checks below.
        await asyncio.sleep(0.5)

        print("── forwarding ──")
        got = [await talk(S_RR, b"x") for _ in range(4)]
        a = got[0]
        check("bytes forwarded both ways, EOF passed on", a.endswith(b":bye") and b":x" in a, a.decode())
        tags = [g[:1].decode() for g in got]
        check("round robin alternates targets",
              set(tags) == {"A", "B"} and all(x != y for x, y in zip(tags, tags[1:])), " ".join(tags))
        big = os.urandom(20 * 1024 * 1024)
        got = await talk(S_RR, big, timeout=30)
        body = got[2:-len(b"A:bye")]
        check("20 MB transfer arrives intact",
              hashlib.sha256(body).digest() == hashlib.sha256(big).digest(), f"{len(body)} bytes")
        st = await asyncio.to_thread(lambda: urllib.request.urlopen(f"http://127.0.0.1:{HTTP}/", timeout=5).status)
        check("HTTP listener still serves HTTP", st == 200, str(st))

        r, w = await asyncio.open_connection("127.0.0.1", S_BANNER)
        first = await asyncio.wait_for(r.readline(), 3)
        w.write(b"hi\r\n"); await w.drain()
        second = await asyncio.wait_for(r.readline(), 3)
        w.close()
        check("server-speaks-first protocol works (no peeking)",
              first == b"220 banner ready\r\n" and second == b"echo hi\r\n", repr(first + second))

        print("── targets ──")
        got = await talk(S_FALLBACK, b"x")
        check("refused target → next target used", got.startswith(b"A:x"), got.decode())
        got = await talk(S_DEAD, b"x")
        check("no target accepts → connection closed", closed(got), repr(got))
        await asyncio.sleep(2.5)
        got = await talk(S_HEALTH, b"x")
        check("health check marks a dead target down → closed", closed(got), repr(got))

        print("── rules, PROXY protocol, limits ──")
        got = await talk(S_RULES, b"x")
        check("block rule closes the connection", closed(got), repr(got))
        got = await talk(S_PP1, b"", half_close=False, timeout=3)
        check("PROXY v1 header sent first",
              got.startswith(b"PROXY TCP4 127.0.0.1 127.0.0.1 ") and got.endswith(f" {S_PP1}\r\n".encode()),
              got.decode(errors="replace").strip())
        got = await talk(S_PP2, b"", half_close=False, timeout=3)
        sig = b"\r\n\r\n\x00\r\nQUIT\n"
        ok = got[:12] == sig and got[12:14] == b"\x21\x11" and got[16:20] == bytes([127, 0, 0, 1]) \
            and int.from_bytes(got[26:28], "big") == S_PP2
        check("PROXY v2 header sent first", ok, got[:28].hex())

        held = []
        for _ in range(20):
            held.append(await asyncio.open_connection("127.0.0.1", S_LIMIT))
        await asyncio.sleep(0.5)  # let the gateway take all 20 in
        got = await talk(S_LIMIT, b"x", timeout=3)
        check("max_connections_per_ip applies to streams", closed(got), repr(got))
        for _, w in held:
            w.close()
        await asyncio.sleep(0.3)
        got = await talk(S_LIMIT, b"x")
        check("connections accepted again once others close", got.startswith(b"A:x"), got.decode())

        print("── idle timeout ──")
        async def idle_then_send(port, secs):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(secs)
            try:
                w.write(b"late"); await w.drain()
                return await asyncio.wait_for(r.read(100), 3)
            except Exception:
                return b""
            finally:
                w.close()
        short, long_, default = await asyncio.gather(
            idle_then_send(S_IDLE, 1), idle_then_send(S_IDLE, 4), idle_then_send(S_RR, 6))
        check("idle_secs 2: idle 1 s stays open", short.startswith(b"A:late"), repr(short))
        check("idle_secs 2: idle 4 s is closed", long_ == b"", repr(long_))
        check("default: idle 6 s stays open", default.endswith(b":late"), repr(default))

        if use_docker:
            print("── real Redis and PostgreSQL ──")
            subprocess.run(
                ["docker", "exec", "qg-tcp-redis", "sh", "-c",
                 f"for i in $(seq 50); do redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1 && break; sleep 0.2; done"],
                capture_output=True)
            out = subprocess.run(
                ["docker", "run", "--rm", "--network", "host", "redis:7-alpine", "sh", "-c",
                 f"redis-cli -p {S_REDIS} set k quayel && redis-cli -p {S_REDIS} get k && "
                 f"redis-cli -p {S_REDIS} ping"],
                capture_output=True, text=True, timeout=60).stdout.split()
            check("redis-cli SET / GET / PING through the proxy", out[:2] == ["OK", "quayel"] and out[-1] == "PONG",
                  " ".join(out))
            pg = ""
            for _ in range(60):
                pg = subprocess.run(
                    ["docker", "run", "--rm", "--network", "host", "-e", "PGPASSWORD=pw", "postgres:16-alpine",
                     "psql", "-h", "127.0.0.1", "-p", str(S_PG), "-U", "postgres", "-tAc",
                     "select count(*) from generate_series(1,100000)"],
                    capture_output=True, text=True, timeout=60).stdout.strip()
                if pg:
                    break
                time.sleep(1)
            check("psql query through the proxy", pg == "100000", pg)

        print("── hot reload ──")
        streams[-3 if use_docker else -1] = stream("reload", S_RELOAD, [ORIGIN_B])
        with open(cfg_path, "w") as f:
            json.dump(config(log, streams), f)
        got = b""
        for _ in range(30):
            got = await talk(S_RELOAD, b"x")
            if got.startswith(b"B:"):
                break
            await asyncio.sleep(0.5)
        check("reload switches targets without a restart", got.startswith(b"B:x"), got.decode())

        print("── access log ──")
        await asyncio.sleep(0.5)
        lines = [l for l in log_lines(log) if l["method"] == "TCP"]
        rr = [l for l in lines if l["path"] == "rr" and l["status"] == 200]
        check("one line per connection, method TCP, scheme tcp",
              len(rr) >= 4 and all(l["scheme"] == "tcp" for l in rr), f"{len(rr)} rr lines")
        bigl = max(rr, key=lambda l: l["req_bytes"], default={})
        check("req_bytes / bytes count the client side",
              bigl.get("req_bytes") == len(big) and bigl.get("bytes") == len(big) + 2 + 5,
              f"{bigl.get('req_bytes')} / {bigl.get('bytes')}")
        check("upstream id and address logged",
              bigl.get("upstream", "").startswith("t") and bigl.get("upstream_addr", "").startswith("127.0.0.1:"),
              f"{bigl.get('upstream')} {bigl.get('upstream_addr')}")
        by = lambda p: [l for l in lines if l["path"] == p]
        dead = by("dead")
        check("dead target logged as 502 with the error",
              dead and dead[0]["status"] == 502 and "connect" in dead[0]["error"], json.dumps(dead[:1]))
        health = by("health")
        check("unhealthy target logged as 503", health and health[-1]["status"] == 503,
              str([l["status"] for l in health]))
        rules = by("rules")
        check("block logged as 403 with block.type stream",
              rules and rules[0]["status"] == 403 and rules[0]["block"]["type"] == "stream"
              and rules[0]["block"]["rule"] == "block-local", json.dumps(rules[0]["block"]) if rules else "")
        idle = [l for l in by("idle") if l["error"] == "idle timeout"]
        check("idle close logged with error \"idle timeout\"", len(idle) == 1, str(len(idle)))
        fb = by("fallback")
        check("fallback logged as 200 on the live target",
              fb and fb[0]["status"] == 200 and fb[0]["upstream_addr"].endswith(str(ORIGIN_A)), json.dumps(fb[:1]))

        gw.terminate()
        gw.wait(10)
        err = open(os.path.join(tmp, "gw.err")).read()
        check("no panics in the gateway log", "panicked" not in err)
    finally:
        if gw.poll() is None:
            gw.kill()
        for s in servers:
            s.close()
        for c in containers:
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

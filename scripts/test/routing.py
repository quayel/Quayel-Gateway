#!/usr/bin/env python3
"""Live check of request routing: the host over HTTP/2 (#14), requests that
match no load balancer, and targets whose hostname doesn't resolve (#13).

Usage: BIN=path/to/quayel-gateway scripts/test/routing.py

No Docker needed: the origin is a small asyncio server and the client is curl
(with HTTP/2). Runs a gateway with Auto-SSL on but no ACME server, so HTTPS
uses the fallback certificate.

Host: HTTP/2 over TLS and h2c both match a pool on `req.host`, a firewall rule
on `req.host` fires for HTTP/2 too, and each request is proxied once (one
access-log line with the real host). No route: a host no load balancer matches
gets the gateway's own `404 {"error":"no_route"}` instead of being proxied to
127.0.0.1:80. DNS: a target whose name doesn't resolve answers 502 instead of
panicking the gateway, the gateway keeps serving every other route, and with
an `accepts_connections` health check the target is taken out so every
request succeeds.
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module asyncio imports.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import asyncio
import json
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))

HTTP, HTTPS = 18700, 18701
GOOD = 18711
MISSING = "app-b.invalid"  # .invalid never resolves (RFC 6761)

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


async def origin(r, w):
    """HTTP/1.1 origin answering 200 `good` to everything."""
    try:
        while True:
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ngood")
            await w.drain()
    except Exception:
        pass
    w.close()


def curl(host, path, *args, https=False):
    """Returns (status, body) for one request to `host` via 127.0.0.1."""
    port = HTTPS if https else HTTP
    url = f"{'https' if https else 'http'}://{host}:{port}{path}"
    out = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "--resolve", f"{host}:{port}:127.0.0.1",
         "-o", "-", "-w", "\n%{http_code} %{http_version}", *args, url],
        capture_output=True, text=True)
    body, _, tail = out.stdout.rpartition("\n")
    code, _, version = tail.partition(" ")
    return int(code or 0), body, version


def wait_port(port, secs=10):
    end = time.time() + secs
    while time.time() < end:
        r = subprocess.run(["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}"], capture_output=True)
        if r.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def pool(pid, host, targets, hc=None):
    return {
        "id": pid, "name": pid, "enabled": True,
        # :port is part of req.host when the client sends one
        "conditions": [{"left": "req.host", "operator": "starts_with", "value": host}],
        "algorithm": {"type": "round_robin"},
        "targets": [{"id": f"{pid}-{i}", "host": h, "port": p, "protocol": "http",
                     "weight": 100, "enabled": True} for i, (h, p) in enumerate(targets)],
        "host_header": {"mode": "visitor"},
        "health_check": hc or {"mode": "off"},
    }


def config(tmp, log):
    return {
        "gateway_id": "routing", "gateway_name": "routing", "server_name": "routing",
        "config_version": "1",
        "listen": {"http": f"127.0.0.1:{HTTP}", "https": f"127.0.0.1:{HTTPS}"},
        "plugins": {
            "firewall": {"enabled": True, "rules": [{
                "id": "block-host", "name": "block-host", "enabled": True,
                "conditions": [{"left": "req.host", "operator": "starts_with", "value": "blocked.route.test"}],
                "action": {"type": "block", "status": 403}}]},
            "auto_ssl": {"enabled": True, "email": "t@example.com", "domains": [],
                         "cert_storage_path": os.path.join(tmp, "certs"),
                         "directory_url": "https://127.0.0.1:1/dir"},
            "load_balancer": {"enabled": True, "load_balancers": [
                pool("app", "app.route.test", [("127.0.0.1", GOOD)]),
                pool("blocked", "blocked.route.test", [("127.0.0.1", GOOD)]),
                pool("dns", "dns.route.test", [("127.0.0.1", GOOD), (MISSING, GOOD)]),
                pool("dns-hc", "dnshc.route.test", [("127.0.0.1", GOOD), (MISSING, GOOD)],
                     {"mode": "accepts_connections", "interval_seconds": 1, "timeout_ms": 300,
                      "healthy_threshold": 1, "unhealthy_threshold": 1}),
            ]},
            "logging": {"enabled": True, "file": {"path": log, "flush_interval_ms": 100}},
        },
    }


def log_lines(log):
    time.sleep(0.5)
    return [json.loads(l) for l in open(log) if l.strip()]


async def main():
    tmp = tempfile.mkdtemp()
    server = await asyncio.start_server(origin, "127.0.0.1", GOOD)
    log = os.path.join(tmp, "access.log")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(config(tmp, log), f)
    gw_err = os.path.join(tmp, "gw.err")
    gw = subprocess.Popen([BINARY, cfg_path], stdout=open(gw_err, "w"), stderr=subprocess.STDOUT)

    def run(*a, **k):
        return asyncio.to_thread(curl, *a, **k)

    try:
        ready = await asyncio.to_thread(lambda: wait_port(HTTP) and wait_port(HTTPS))
        check("gateway starts", ready)

        print("── host over HTTP/2 (#14) ──")
        s, b, v = await run("app.route.test", "/h2-tls", "--http2", https=True)
        check("HTTP/2 over TLS matches the pool by host", s == 200 and b == "good" and v == "2", f"{s} {b!r} h{v}")
        s, b, v = await run("app.route.test", "/h2c", "--http2-prior-knowledge")
        check("h2c matches the pool by host", s == 200 and b == "good" and v == "2", f"{s} {b!r} h{v}")
        s, b, v = await run("app.route.test", "/h1", "--http1.1", https=True)
        check("HTTP/1.1 still matches by host", s == 200 and b == "good" and v == "1.1", f"{s} {b!r} h{v}")
        s, _, v = await run("blocked.route.test", "/", "--http2", https=True)
        check("req.host firewall rule fires over HTTP/2", s == 403 and v == "2", f"{s} h{v}")
        lines = log_lines(log)
        h2 = [l for l in lines if l["path"] == "/h2-tls"]
        check("HTTP/2 request proxied once: one log line, real host",
              len(h2) == 1 and h2[0]["host"].startswith("app.route.test"),
              f"{len(h2)} line(s) {[l['host'] for l in h2]}")
        check("no request logged as coming from the gateway's own loopback hop",
              not any(l["path"] in ("/h2-tls", "/h2c") and l["host"] in ("", None) for l in lines))

        print("── no matching route ──")
        for args, name in ((["--http1.1"], "HTTP/1.1"), (["--http2"], "HTTP/2")):
            s, b, _ = await run("nobody.route.test", "/x", *args, https=True)
            check(f"{name}: unknown host → 404 no_route from the gateway",
                  s == 404 and "no_route" in b, f"{s} {b[:60]!r}")

        print("── unresolvable target (#13) ──")
        statuses = [(await run("dns.route.test", f"/d{i}"))[0] for i in range(10)]
        check("pool with one unresolvable target: 200s and 502s, no crash",
              set(statuses) == {200, 502} and gw.poll() is None, str(statuses))
        s, b, _ = await run("app.route.test", "/after")
        check("other routes keep working", s == 200 and b == "good", f"{s} {b!r}")
        err = open(gw_err).read()
        check("no panic in the gateway output", "panicked" not in err)
        check("lookup failure logged", f"cannot resolve upstream {MISSING}" in err)
        await asyncio.sleep(3)
        statuses = [(await run("dnshc.route.test", f"/h{i}"))[0] for i in range(10)]
        check("with accepts_connections health check: target taken out, 10/10 succeed",
              statuses == [200] * 10, str(statuses))
        check("gateway still running", gw.poll() is None)
    finally:
        gw.terminate()
        try:
            gw.wait(15)
        except subprocess.TimeoutExpired:
            gw.kill()
        server.close()

    passed = sum(results)
    print(f"\nrouting: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

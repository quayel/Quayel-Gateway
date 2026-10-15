#!/usr/bin/env python3
"""Live check of load-balancer health checks and the request scheme.

Usage: BIN=path/to/quayel-gateway scripts/test/lb-health.py

No Docker needed: the origins are small asyncio servers. Runs a gateway with
Auto-SSL on but no ACME server, so HTTPS uses the fallback certificate.

Health checks: a dead target is taken out of a pool after
`unhealthy_threshold` failures, so every request then succeeds; a pool whose
only target is down answers 503 no_healthy_upstream; `expected_statuses` is
honoured (a 302 health endpoint is down with [200] and up without a list);
with `mode: off` nothing is checked; and a target that comes back is used
again. Scheme: `req.scheme` is https on the HTTPS port (an HTTP → HTTPS
redirect rule doesn't loop), backends get the right X-Forwarded-Proto, and
X-Forwarded-Proto from a client outside `trusted_proxies` is ignored.
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module asyncio imports.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import asyncio
import json
import ssl
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))

HTTP, HTTPS = 18600, 18601
GOOD, REDIRECT, DEAD, FLAKY = 18611, 18612, 18613, 18614

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


# ── Origins ──────────────────────────────────────────────────────────────────

def origin(tag, healthz_status=200):
    """HTTP/1.1 origin: /healthz answers `healthz_status`, everything else 200
    with a body of `<tag> <X-Forwarded-Proto>`."""
    async def handle(r, w):
        try:
            while True:
                head = (await r.readuntil(b"\r\n\r\n")).decode("latin1")
                lines = head.split("\r\n")
                path = lines[0].split(" ")[1]
                proto = next((l.split(":", 1)[1].strip() for l in lines[1:]
                              if l.lower().startswith("x-forwarded-proto:")), "-")
                if path == "/healthz" and healthz_status != 200:
                    w.write(f"HTTP/1.1 {healthz_status} X\r\nLocation: /\r\nContent-Length: 0\r\n\r\n".encode())
                else:
                    body = f"{tag} {proto}".encode()
                    w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
                await w.drain()
        except Exception:
            pass
        w.close()
    return handle


# ── Client helpers ───────────────────────────────────────────────────────────

async def get(path, https=False, headers=None):
    """One HTTP/1.1 GET. Returns (status, headers dict, body)."""
    ctx = None
    if https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
    r, w = await asyncio.wait_for(asyncio.open_connection(
        "127.0.0.1", HTTPS if https else HTTP, ssl=ctx,
        server_hostname="app.lb.test" if https else None), 5)
    extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    w.write(f"GET {path} HTTP/1.1\r\nHost: app.lb.test\r\nConnection: close\r\n{extra}\r\n".encode())
    await w.drain()
    raw = await asyncio.wait_for(r.read(), 10)
    w.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    return int(lines[0].split(" ")[1]), hdrs, body


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


def pool(pid, path, ports, hc):
    return {
        "id": pid, "name": pid, "enabled": True,
        "conditions": [{"left": "req.path", "operator": "starts_with", "value": path}],
        "algorithm": {"type": "round_robin"},
        "targets": [{"id": f"{pid}-{p}", "host": "127.0.0.1", "port": p, "protocol": "http",
                     "weight": 100, "enabled": True} for p in ports],
        "host_header": {"mode": "visitor"},
        "health_check": hc,
    }


def checked(**extra):
    return {"mode": "https", "path": "/healthz", "interval_seconds": 1, "timeout_ms": 300,
            "healthy_threshold": 1, "unhealthy_threshold": 2, **extra}


def config(tmp, log):
    return {
        "gateway_id": "lb-health", "gateway_name": "lb-health", "server_name": "lb-health",
        "config_version": "1",
        "listen": {"http": f"127.0.0.1:{HTTP}", "https": f"127.0.0.1:{HTTPS}"},
        # Loopback isn't trusted here, so this test's own X-Forwarded-Proto is ignored.
        "client_ip": {"source": "peer_ip", "trusted_proxies": ["192.0.2.1/32"]},
        "plugins": {
            "firewall": {"enabled": True, "rules": [{
                "id": "to-https", "name": "to-https", "enabled": True,
                "conditions": [
                    {"left": "req.path", "operator": "starts_with", "value": "/secure"},
                    {"left": "req.scheme", "operator": "equals", "value": "http"}],
                "action": {"type": "redirect", "status": 301, "location": "https://app.lb.test/secure"}}]},
            "auto_ssl": {"enabled": True, "email": "t@example.com", "domains": [],
                         "cert_storage_path": os.path.join(tmp, "certs"),
                         "directory_url": "https://127.0.0.1:1/dir"},
            "load_balancer": {"enabled": True, "load_balancers": [
                pool("mixed", "/mixed/", [GOOD, DEAD], checked()),
                pool("dead", "/dead/", [DEAD], checked()),
                pool("redir-200", "/redir-200/", [REDIRECT], checked(expected_statuses=[200])),
                pool("redir-any", "/redir-any/", [REDIRECT], checked()),
                pool("off", "/off/", [DEAD], {"mode": "off"}),
                pool("flaky", "/flaky/", [FLAKY], checked()),
                {**pool("default", "/", [GOOD], {"mode": "off"}), "conditions": []},
            ]},
            "logging": {"enabled": True, "file": {"path": log, "flush_interval_ms": 100}},
        },
    }


async def main():
    tmp = tempfile.mkdtemp()
    servers = [
        await asyncio.start_server(origin("good"), "127.0.0.1", GOOD),
        await asyncio.start_server(origin("redirect", healthz_status=302), "127.0.0.1", REDIRECT),
    ]
    log = os.path.join(tmp, "access.log")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(config(tmp, log), f)
    gw_err = os.path.join(tmp, "gw.err")
    gw = subprocess.Popen([BINARY, cfg_path], stdout=open(gw_err, "w"), stderr=subprocess.STDOUT)
    try:
        ready = await wait_port(HTTP) and await wait_port(HTTPS)
        check("gateway starts", ready)

        print("── health checks ──")
        # 2 failures at 1 s intervals, plus the 300 ms timeouts.
        await asyncio.sleep(4.5)
        statuses = [(await get("/mixed/x"))[0] for _ in range(20)]
        check("dead target taken out: 20/20 requests to a mixed pool succeed",
              statuses == [200] * 20, str(sorted(set(statuses))))
        s, _, b = await get("/dead/x")
        check("pool with every target down → 503 no_healthy_upstream",
              s == 503 and b"no_healthy_upstream" in b, f"{s} {b[:60]!r}")
        s, _, b = await get("/redir-200/x")
        check("expected_statuses [200]: a 302 health endpoint counts as down", s == 503, f"{s} {b[:40]!r}")
        s, _, b = await get("/redir-any/x")
        check("no expected_statuses: a 302 health endpoint counts as up", s == 200, f"{s} {b[:40]!r}")
        s, _, _ = await get("/off/x")
        check("mode off: target not checked, request goes to it (502)", s == 502, str(s))
        err = open(gw_err).read()
        check("transition logged ('is now unhealthy')", "is now unhealthy" in err)

        s, _, _ = await get("/flaky/x")
        check("target that never answered is down", s == 503, str(s))
        servers.append(await asyncio.start_server(origin("flaky"), "127.0.0.1", FLAKY))
        await asyncio.sleep(2.5)
        s, _, b = await get("/flaky/x")
        check("target comes back after healthy_threshold successes", s == 200 and b.startswith(b"flaky"),
              f"{s} {b[:40]!r}")

        print("── request scheme ──")
        s, h, _ = await get("/secure")
        check("HTTP → HTTPS redirect rule fires on plain HTTP", s == 301, f"{s} {h.get('location')}")
        s, _, b = await get("/secure", https=True)
        check("same rule doesn't fire on the HTTPS port (no loop)", s == 200, f"{s} {b[:40]!r}")
        check("backend gets X-Forwarded-Proto: https over HTTPS", b == b"good https", repr(b))
        s, _, b = await get("/plain")
        check("backend gets X-Forwarded-Proto: http over HTTP", b == b"good http", repr(b))
        s, _, b = await get("/secure", headers={"X-Forwarded-Proto": "https"})
        check("X-Forwarded-Proto from an untrusted client is ignored", s == 301, str(s))
        await asyncio.sleep(0.5)
        lines = [json.loads(l) for l in open(log) if l.strip()]
        schemes = {l["path"]: l["scheme"] for l in lines if l["path"] in ("/plain",)}
        https_lines = [l for l in lines if l["path"] == "/secure" and l["status"] == 200]
        check("access log: scheme https for HTTPS, http for HTTP",
              schemes.get("/plain") == "http" and https_lines and https_lines[0]["scheme"] == "https",
              f"{schemes} {[l['scheme'] for l in https_lines]}")
    finally:
        gw.terminate()
        try:
            gw.wait(15)
        except subprocess.TimeoutExpired:
            gw.kill()
        for s in servers:
            s.close()

    passed = sum(results)
    print(f"\nlb-health: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

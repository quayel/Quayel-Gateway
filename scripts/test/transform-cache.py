#!/usr/bin/env python3
"""End-to-end test: request/response transforms + cache revalidation.

Starts a scripted origin and the gateway, then checks:
  - request_transform (path, query, headers) reaches the origin
  - firewall sees the original path; blocks get no response transform
  - response_transform applies to MISS and HIT; cache stores the raw response
  - origin status is stored (404 stays 404 on HIT)
  - 304 revalidation (REVALIDATED), stale-if-error on 5xx and on connect error
  - revalidation lock: one request refreshes, concurrent ones get REVALIDATING,
    the lock is released after 304, 200 and 5xx
  - EXPIRED (past SWR, inside stale-if-error) falls back on 5xx, revalidates on 304
  - Vary, Accept-Encoding buckets, client validators stripped, HEAD never stores

Usage:  python3 scripts/test/transform-cache.py
Env:    BIN=./target/debug/quayel-gateway (default)
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GW_PORT, ORIGIN_PORT = 18190, 18191
GW = f"http://127.0.0.1:{GW_PORT}"
BIN = os.environ.get("BIN", "./target/debug/quayel-gateway")

state = {"mode": "normal", "hits": {}, "last": {}, "ver": {}}


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if status != 304:
            self.send_header("content-length", str(len(body)))
        self.end_headers()
        if status != 304 and self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        state["hits"][path] = state["hits"].get(path, 0) + 1
        state["last"][path] = {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
        if state["mode"] == "down":
            self.close_connection = True
            return

        if state["mode"] == "error500" and path.startswith("/etag"):
            return self._send(500, b"origin broke", {"cache-control": "no-store"})
        if path.startswith("/etag"):
            # /etag-exp has a 1s SWR window, so it reaches EXPIRED quickly.
            swr = 1 if path == "/etag-exp" else 30
            cc = f"public, max-age=1, stale-while-revalidate={swr}, stale-if-error=60"
            ver = state["ver"].get(path, "v1")
            etag = f'"{ver}"'
            if self.headers.get("if-none-match") == etag:
                if path == "/etag-slow":
                    time.sleep(1.0)  # hold the revalidation lock
                return self._send(304, headers={"etag": etag, "cache-control": cc})
            return self._send(200, f"etag body {ver}".encode(), {"etag": etag, "cache-control": cc})
        if path == "/status404":
            return self._send(404, b"nope", {"cache-control": "public, max-age=60"})
        if path == "/vary-cookie":
            return self._send(200, b"v", {"cache-control": "public, max-age=60", "vary": "Cookie"})
        if path == "/enc":
            ae = self.headers.get("accept-encoding", "none")
            return self._send(200, ae.encode(), {"cache-control": "public, max-age=60", "vary": "Accept-Encoding"})
        body = json.dumps(state["last"][path]).encode()
        return self._send(200, body, {"cache-control": "public, max-age=60", "content-type": "application/json"})

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


CONFIG = {
    "gateway_id": "gw-test", "gateway_name": "test", "server_name": "test", "config_version": "1",
    "listen": {"http": f"127.0.0.1:{GW_PORT}"},
    "client_ip": {"source": "peer_ip"},
    "plugins": {
        "firewall": {"enabled": True, "rules": [{
            "id": "fw-req-hdr", "name": "request header", "enabled": True,
            "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/api/fwh"}],
            "action": {"type": "set_request_header", "headers": {"X-From-Firewall": "1"}},
        }, {
            "id": "fw-resp-hdr", "name": "response header", "enabled": True,
            "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/api/fwh"}],
            "action": {"type": "set_response_header", "headers": {"X-Fw-Resp": "yes"}},
        }, {
            "id": "fw-hdr-block", "name": "block after header rules", "enabled": True,
            "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/api/fwh/blocked"}],
            "action": {"type": "block", "status": 403},
        }, {
            "id": "fw-block", "name": "block original path", "enabled": True,
            "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/api/blocked"}],
            "action": {"type": "block", "status": 403},
        }]},
        "request_transform": {"enabled": True, "rules": [
            {"id": "rt-api", "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/api/"}],
             "actions": [
                 {"type": "path", "operation": "replace_prefix", "from": "/api", "to": "/echo"},
                 {"type": "query", "operation": "remove", "name": "secret"},
                 {"type": "query", "operation": "set", "name": "added", "value": "1"},
                 {"type": "header", "operation": "set", "name": "X-Service", "value": "quayel"},
                 {"type": "header", "operation": "remove", "name": "X-Strip-Me"},
             ]},
        ]},
        "cache": {"enabled": True, "rules": [{
            "id": "c-all", "name": "all", "enabled": True, "conditions": [],
            "edge_ttl": {"mode": "origin"},
        }]},
        "response_transform": {"enabled": True, "rules": [
            {"id": "rs-all", "actions": [{"type": "header", "operation": "set", "name": "X-Powered-By", "value": "Quayel"}]},
            {"id": "rs-404", "conditions": [{"left": "resp.status", "operator": "equals", "value": 404}],
             "actions": [{"type": "header", "operation": "set", "name": "X-Not-Found", "value": "yes"}]},
            {"id": "rs-teapot", "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/echo/teapot"}],
             "actions": [{"type": "status", "operation": "set", "value": 418}]},
        ]},
        "load_balancer": {"enabled": True, "load_balancers": [{
            "id": "lb", "name": "lb", "enabled": True, "conditions": [],
            "algorithm": {"type": "round_robin"},
            "targets": [{"id": "o", "host": "127.0.0.1", "port": ORIGIN_PORT, "protocol": "http", "weight": 1, "enabled": True}],
        }]},
    },
}

class QuietServer(ThreadingHTTPServer):
    # Connection resets from the gateway at shutdown aren't test failures.
    def handle_error(self, request, client_address):
        pass


PASS, FAIL = [], []


def check(name, cond, detail=""):
    """Print each result as it runs, in the same format as all-rules.sh."""
    (PASS if cond else FAIL).append(name)
    tag = "\033[0;32mPASS\033[0m" if cond else "\033[0;31mFAIL\033[0m"
    detail = str(detail)
    if cond and len(detail) > 60:
        detail = detail[:57] + "..."
    print(f"  {tag}  {name:<44} {detail}", flush=True)


def section(title):
    print(f"\n── {title} " + "─" * max(0, 64 - len(title)))


def req(path, method="GET", headers=None):
    r = urllib.request.Request(GW + path, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def main():
    origin = QuietServer(("127.0.0.1", ORIGIN_PORT), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    cfg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(CONFIG, cfg)
    cfg.close()
    gw = subprocess.Popen([BIN, cfg.name], stdout=open("/tmp/quayel-transform-cache-gw.log", "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(GW + "/__ready", timeout=1)
                break
            except urllib.error.HTTPError:
                break
            except Exception:
                time.sleep(0.1)
        run()
    finally:
        gw.terminate()
        os.unlink(cfg.name)
    print("────────────────────────────────────────────────────────────────────")
    print(f"  TOTAL: {len(PASS) + len(FAIL)}   PASS: \033[0;32m{len(PASS)}\033[0m   FAIL: \033[0;31m{len(FAIL)}\033[0m")
    for name in FAIL:
        print(f"  \033[0;31mFAILED\033[0m  {name}")
    sys.exit(1 if FAIL else 0)


def run():
    section("request_transform")
    s, h, b = req("/api/hello?secret=x&keep=1", headers={"X-Strip-Me": "1", "Host": "client.example"})
    seen = json.loads(b)
    check("path rewritten upstream", seen["path"] == "/echo/hello?keep=1&added=1", seen["path"])
    check("header set upstream", seen["headers"].get("x-service") == "quayel", seen["headers"])
    check("header removed upstream", "x-strip-me" not in seen["headers"], seen["headers"])
    check("X-Forwarded-Host is the client host", seen["headers"].get("x-forwarded-host") == "client.example", seen["headers"])
    check("MISS has response transform", h.get("x-powered-by") == "Quayel" and h.get("quayel-cache-status") == "MISS", h)
    s, h, b = req("/api/hello?secret=x&keep=1", headers={"Host": "client.example"})
    check("HIT keyed on rewritten request", h.get("quayel-cache-status") == "HIT" and state["hits"]["/echo/hello"] == 1, h)
    check("HIT has response transform", h.get("x-powered-by") == "Quayel", h)
    s, h, b = req("/api/blocked")
    check("firewall sees original path", s == 403, s)
    check("block not transformed", "x-powered-by" not in h, h)

    section("firewall header actions")
    s, h, b = req("/api/fwh/one")
    seen = json.loads(b)
    check("set_request_header reaches the origin", seen["headers"].get("x-from-firewall") == "1", seen["headers"])
    check("set_response_header on MISS", h.get("x-fw-resp") == "yes", h)
    s, h, b = req("/api/fwh/one")
    check("set_response_header on HIT", h.get("x-fw-resp") == "yes" and h.get("quayel-cache-status") == "HIT", h)
    s, h, b = req("/api/fwh/blocked")
    check("later block rule still runs after header rules", s == 403, s)
    check("set_response_header on the block response", h.get("x-fw-resp") == "yes", h)

    section("response_transform")
    s, h, _ = req("/status404")
    s2, h2, _ = req("/status404")
    check("404 stored as 404", s == 404 and s2 == 404 and h2.get("quayel-cache-status") == "HIT", (s, s2, h2))
    check("resp.status condition on MISS and HIT", h.get("x-not-found") == "yes" and h2.get("x-not-found") == "yes", (h, h2))
    s, h, _ = req("/api/teapot")
    s2, h2, _ = req("/api/teapot")
    check("status override on MISS and HIT", s == 418 and s2 == 418 and h2.get("quayel-cache-status") == "HIT", (s, s2))

    section("revalidation")
    s, h, b = req("/etag")
    check("etag MISS", s == 200 and h.get("quayel-cache-status") == "MISS", h)
    time.sleep(1.3)
    s, h, b = req("/etag")
    last = state["last"]["/etag"]["headers"]
    check("conditional request sent", last.get("if-none-match") == '"v1"', last)
    check("304 -> REVALIDATED with stored body", s == 200 and b == b"etag body v1" and h.get("quayel-cache-status") == "REVALIDATED", (s, h, b))
    check("REVALIDATED has response transform", h.get("x-powered-by") == "Quayel", h)
    s, h, b = req("/etag")
    check("fresh again after 304", h.get("quayel-cache-status") == "HIT", h)

    state["mode"] = "error500"
    time.sleep(1.3)
    s, h, b = req("/etag")
    check("5xx inside stale-if-error -> STALE", s == 200 and b == b"etag body v1" and h.get("quayel-cache-status") == "STALE", (s, h, b))
    check("STALE has response transform", h.get("x-powered-by") == "Quayel", h)
    state["mode"] = "normal"
    s, h, b = req("/etag")
    check("lock released after failed revalidation", h.get("quayel-cache-status") == "REVALIDATED", h)

    section("revalidation lock")
    req("/etag-slow")
    time.sleep(1.3)
    holder = {}
    t = threading.Thread(target=lambda: holder.update(r=req("/etag-slow")))
    t.start()
    time.sleep(0.3)
    started = time.time()
    s, h, b = req("/etag-slow")
    waited = time.time() - started
    t.join()
    hs, hh, hb = holder["r"]
    check("lock holder -> REVALIDATED", hh.get("quayel-cache-status") == "REVALIDATED" and hb == b"etag body v1", hh)
    check("concurrent request -> REVALIDATING without waiting",
          h.get("quayel-cache-status") == "REVALIDATING" and b == b"etag body v1" and waited < 0.5, (h, waited))
    check("REVALIDATING has response transform", h.get("x-powered-by") == "Quayel", h)
    check("only the lock holder reached the origin", state["hits"]["/etag-slow"] == 2, state["hits"])
    time.sleep(1.3)
    t0 = time.time()
    _, h, _ = req("/etag-slow")
    check("lock released after 304", h.get("quayel-cache-status") == "REVALIDATED" and time.time() - t0 >= 0.9, h)

    section("revalidation with a new version")
    req("/etag-change")
    state["ver"]["/etag-change"] = "v2"
    time.sleep(1.3)
    s, h, b = req("/etag-change")
    check("changed origin -> new body served", s == 200 and b == b"etag body v2", (s, h, b))
    s, h, b = req("/etag-change")
    check("new body stored", b == b"etag body v2" and h.get("quayel-cache-status") == "HIT", (h, b))

    section("expired (past SWR, inside stale-if-error)")
    req("/etag-exp")
    time.sleep(2.4)
    state["mode"] = "error500"
    s, h, b = req("/etag-exp")
    check("EXPIRED + 5xx -> STALE", s == 200 and b == b"etag body v1" and h.get("quayel-cache-status") == "STALE", (s, h, b))
    state["mode"] = "normal"
    s, h, b = req("/etag-exp")
    check("EXPIRED sends conditional request", state["last"]["/etag-exp"]["headers"].get("if-none-match") == '"v1"', state["last"]["/etag-exp"])
    check("EXPIRED + 304 -> REVALIDATED", b == b"etag body v1" and h.get("quayel-cache-status") == "REVALIDATED", (h, b))

    section("cache correctness")
    req("/vary-cookie"); req("/vary-cookie")
    check("Vary: Cookie not stored", state["hits"]["/vary-cookie"] == 2, state["hits"])
    _, _, b1 = req("/enc", headers={"Accept-Encoding": "gzip"})
    _, _, b2 = req("/enc", headers={"Accept-Encoding": "identity"})
    _, h3, b3 = req("/enc", headers={"Accept-Encoding": "deflate, gzip;q=0.8"})
    check("gzip bucket sent upstream", b1 == b"gzip", b1)
    check("identity bucket strips Accept-Encoding", b2 == b"none", b2)
    check("same bucket shares the entry", b3 == b"gzip" and h3.get("quayel-cache-status") == "HIT", (b3, h3))
    req("/echo/inm", headers={"If-None-Match": '"client"'})
    check("client validator stripped on MISS", "if-none-match" not in state["last"]["/echo/inm"]["headers"], state["last"]["/echo/inm"])
    req("/echo/head", method="HEAD")
    _, h, _ = req("/echo/head")
    check("HEAD MISS does not fill cache", h.get("quayel-cache-status") == "MISS", h)

    section("stale-if-error on connect error")
    req("/etag-down")
    time.sleep(1.3)
    origin_down()
    s, h, b = req("/etag-down")
    check("origin down -> STALE", s == 200 and b == b"etag body v1" and h.get("quayel-cache-status") == "STALE", (s, h, b))
    s, h, b = req("/echo/never-cached")
    check("origin down, nothing stored -> 502", s == 502, s)


def origin_down():
    # Drop requests on already-open (pooled) connections, and close the
    # listening socket so new connects are refused.
    state["mode"] = "down"
    import gc
    for o in gc.get_objects():
        if isinstance(o, ThreadingHTTPServer):
            o.shutdown()
            o.server_close()


if __name__ == "__main__":
    main()

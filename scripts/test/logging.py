#!/usr/bin/env python3
"""End-to-end test: access log and X-QG-Request-Id.

Starts an origin and a gateway with logging on, then checks:
  - X-QG-Request-Id: generated (32 hex), unique, the same in the response,
    at the origin and in the log; a valid incoming ID is reused, a bad one is
    replaced; 502s and firewall blocks carry it too; accept_incoming=false
  - new log fields: http_version, user_agent, referer, upstream_status
    (before response_transform), error, protection, jwt
  - rotation: the file is reopened after `mv` and after `rm`, and straight
    away on SIGHUP (the gateway keeps running)
  - hot reload: a new log path, logging switched off, a bad mode refused
    without stopping logging
  - an unsupported `mode` is refused at startup

Usage:  python3 scripts/test/logging.py
Env:    BIN=./target/debug/quayel-gateway (default)
Needs:  python3 with PyJWT
"""
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt as pyjwt

GW_PORT, ORIGIN_PORT, DEAD_PORT = 18300, 18301, 18302
BIN = os.environ.get("BIN", "./target/debug/quayel-gateway")
SECRET = "logging-test-secret"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
RELOAD_WAIT = 7  # the config watcher checks every 5 s

origin_seen = {}  # path → X-QG-Request-Id the origin received


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        origin_seen[self.path] = self.headers.get("x-qg-request-id")
        body = b"origin ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def cond(left, op, value=None, nxt=None):
    c = {"left": left, "operator": op}
    if value is not None:
        c["value"] = value
    if nxt:
        c["next"] = nxt
    return c


def lb(lid, port, conditions):
    return {"id": lid, "name": lid, "enabled": True, "conditions": conditions,
            "algorithm": {"type": "round_robin"},
            "targets": [{"id": lid, "host": "127.0.0.1", "port": port, "protocol": "http",
                         "weight": 1, "enabled": True}]}


def config(log_path, logging_on=True, mode="file", accept_incoming=True):
    return {
        "gateway_id": "gw-log", "gateway_name": "log", "server_name": "log", "config_version": "1",
        "listen": {"http": f"127.0.0.1:{GW_PORT}"}, "client_ip": {"source": "peer_ip"},
        "server": {"limits": {"max_body_bytes": 100},
                   "request_id": {"accept_incoming": accept_incoming}},
        "jwt": {"keys": [{"id": "hs", "algorithms": ["HS256"], "secret": SECRET}], "required_claims": []},
        "plugins": {
            "firewall": {"enabled": True, "rules": [
                {"id": "blocked", "name": "blocked", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/blocked")],
                 "action": {"type": "block", "status": 403}},
                {"id": "api-jwt", "name": "api needs jwt", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/api", "and"),
                                cond("header.authorization.jwt_valid", "not_equals", True)],
                 "action": {"type": "block", "status": 401}},
            ]},
            "response_transform": {"enabled": True, "rules": [
                {"id": "status-203", "conditions": [cond("req.path", "starts_with", "/rewritten")],
                 "actions": [{"type": "status", "operation": "set", "value": 203}]},
            ]},
            "load_balancer": {"enabled": True, "load_balancers": [
                lb("dead", DEAD_PORT, [cond("req.path", "starts_with", "/down")]),
                lb("origin", ORIGIN_PORT, []),
            ]},
            "logging": {"enabled": logging_on, "mode": mode,
                        "file": {"path": log_path, "flush_interval_ms": 100}},
        },
    }


PASS, FAIL = [], []


def check(name, cond_, detail=""):
    """Print each result as it runs, in the same format as all-rules.sh."""
    (PASS if cond_ else FAIL).append(name)
    tag = "\033[0;32mPASS\033[0m" if cond_ else "\033[0;31mFAIL\033[0m"
    detail = str(detail)
    if cond_ and len(detail) > 60:
        detail = detail[:57] + "..."
    print(f"  {tag}  {name:<50} {detail}", flush=True)


def section(title):
    print(f"\n── {title} " + "─" * max(0, 64 - len(title)))


def req(path, headers=None, method="GET", data=None):
    r = urllib.request.Request(f"http://127.0.0.1:{GW_PORT}{path}", headers=headers or {},
                               method=method, data=data)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            resp.read()
            return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers
    except Exception as e:
        return 0, {"error": str(e)}


def rid(headers):
    return headers.get("x-qg-request-id") if hasattr(headers, "get") else None


def read_log(path):
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def log_entry(path, request_id, timeout=3.0):
    """The log line for this request ID, waiting for the writer to flush it."""
    end = time.time() + timeout
    while time.time() < end:
        for e in read_log(path):
            if e.get("request_id") == request_id:
                return e
        time.sleep(0.05)
    return None


def write_cfg(path, c):
    with open(path, "w") as f:
        json.dump(c, f)


def start(cfg_path, log):
    p = subprocess.Popen([BIN, cfg_path], stdout=open(log, "w"), stderr=subprocess.STDOUT)
    for _ in range(80):
        if req("/__ready")[0]:
            return p
        time.sleep(0.1)
    p.terminate()
    sys.exit(f"gateway did not start; see {log}")


def main():
    srv = QuietServer(("127.0.0.1", ORIGIN_PORT), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp(prefix="qg-log-")
    cfg = os.path.join(tmp, "config.json")
    log = os.path.join(tmp, "access.jsonl")
    write_cfg(cfg, config(log))
    gw_out = "/tmp/quayel-logging-gw.log"
    gw = start(cfg, gw_out)
    try:
        request_ids(log)
        fields(log)
        rotation(log, gw)
        reload(cfg, log, tmp, gw_out)
    finally:
        gw.terminate()
        gw.wait(timeout=15)
    rejected(tmp)

    print("────────────────────────────────────────────────────────────────────")
    print(f"  TOTAL: {len(PASS) + len(FAIL)}   PASS: \033[0;32m{len(PASS)}\033[0m   FAIL: \033[0;31m{len(FAIL)}\033[0m")
    for name in FAIL:
        print(f"  \033[0;31mFAILED\033[0m  {name}")
    sys.exit(1 if FAIL else 0)


def request_ids(log):
    section("X-QG-Request-Id")
    s, h = req("/rid/a")
    a = rid(h)
    check("response has a 32-hex request ID", s == 200 and a and HEX32.match(a), a)
    check("origin received the same ID", origin_seen.get("/rid/a") == a, origin_seen.get("/rid/a"))
    e = log_entry(log, a)
    check("log line has the same request_id", e is not None, a)
    s, h = req("/rid/b")
    check("next request gets a different ID", rid(h) and rid(h) != a, rid(h))

    incoming = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    s, h = req("/rid/in", {"X-QG-Request-Id": incoming})
    check("valid incoming ID returned to the client", rid(h) == incoming, rid(h))
    check("valid incoming ID sent to the origin", origin_seen.get("/rid/in") == incoming)
    check("valid incoming ID logged", log_entry(log, incoming) is not None)

    s, h = req("/rid/bad", {"X-QG-Request-Id": "bad id; drop table"})
    check("malformed incoming ID replaced", rid(h) and HEX32.match(rid(h)), rid(h))
    check("origin got the replacement, not the bad one",
          origin_seen.get("/rid/bad") == rid(h), origin_seen.get("/rid/bad"))

    s, h = req("/blocked")
    check("firewall block (403) carries the ID", s == 403 and rid(h) and HEX32.match(rid(h)), f"{s} {rid(h)}")
    s, h = req("/down")
    check("origin down (502) carries the ID", s == 502 and rid(h) and HEX32.match(rid(h)), f"{s} {rid(h)}")
    e = log_entry(log, rid(h))
    check("502 logged with an error and no upstream_status",
          e is not None and e["error"] and e["upstream_status"] is None,
          (e or {}).get("error"))


def fields(log):
    section("New log fields")
    s, h = req("/f", {"User-Agent": "qg-test/1.0", "Referer": "https://ref.example/page"})
    e = log_entry(log, rid(h)) or {}
    check("http_version", e.get("http_version") == "HTTP/1.1", e.get("http_version"))
    check("user_agent", e.get("user_agent") == "qg-test/1.0", e.get("user_agent"))
    check("referer", e.get("referer") == "https://ref.example/page", e.get("referer"))
    check("upstream_status 200, error null", e.get("upstream_status") == 200 and e.get("error") is None)
    check("no jwt when no rule read a token", e.get("jwt") is None, e.get("jwt"))
    check("protection null on a normal request", "protection" in e and e["protection"] is None)

    s, h = req("/rewritten")
    e = log_entry(log, rid(h)) or {}
    check("status rewrite: upstream 200, client 203",
          s == 203 and e.get("upstream_status") == 200 and e.get("response_status") == 203,
          f"{e.get('upstream_status')} → {e.get('response_status')}")

    s, h = req("/upload", {"Content-Type": "text/plain"}, method="POST", data=b"x" * 1000)
    e = log_entry(log, rid(h)) or {}
    check("oversized body: 413, protection=body_too_large",
          s == 413 and e.get("protection") == "body_too_large", f"{s} {e.get('protection')}")

    good = pyjwt.encode({"sub": "user-7", "exp": int(time.time()) + 600}, SECRET, algorithm="HS256")
    s, h = req("/api/x", {"Authorization": f"Bearer {good}"})
    e = log_entry(log, rid(h)) or {}
    check("valid token: jwt.valid, jwt.sub logged",
          s == 200 and e.get("jwt") == {"valid": True, "error": None, "sub": "user-7"}, e.get("jwt"))
    forged = pyjwt.encode({"sub": "admin", "exp": int(time.time()) + 600}, "wrong", algorithm="HS256")
    s, h = req("/api/x", {"Authorization": f"Bearer {forged}"})
    e = log_entry(log, rid(h)) or {}
    check("forged token: 401, jwt.error=bad_signature, no sub",
          s == 401 and e.get("jwt") == {"valid": False, "error": "bad_signature", "sub": None}, e.get("jwt"))
    s, h = req("/plain", {"Authorization": f"Bearer {good}"})
    e = log_entry(log, rid(h)) or {}
    check("token not read by any rule: jwt null", s == 200 and e.get("jwt") is None, e.get("jwt"))


def rotation(log, gw):
    section("Rotation")
    rotated = log + ".1"
    os.rename(log, rotated)
    time.sleep(0.4)  # a few flush intervals: the writer notices the move
    s, h = req("/rot/mv")
    check("after mv: new file gets the next event", log_entry(log, rid(h)) is not None)
    check("after mv: rotated file not written to",
          all(e["request_id"] != rid(h) for e in read_log(rotated)))

    os.remove(log)
    time.sleep(0.4)
    s, h = req("/rot/rm")
    check("after rm: file recreated with the event", log_entry(log, rid(h)) is not None)

    # SIGHUP: reopen immediately, gateway keeps serving.
    os.rename(log, log + ".2")
    gw.send_signal(signal.SIGHUP)
    time.sleep(0.2)
    s, h = req("/rot/hup")
    check("SIGHUP: gateway still running", gw.poll() is None and s == 200, s)
    check("SIGHUP: event goes to the new file", log_entry(log, rid(h)) is not None)


def reload(cfg, log, tmp, gw_out):
    section("Hot reload")
    log2 = os.path.join(tmp, "moved", "access2.jsonl")
    write_cfg(cfg, config(log2))
    time.sleep(RELOAD_WAIT)
    s, h = req("/reload/path")
    check("new path: event in the new file", log_entry(log2, rid(h)) is not None, log2)
    check("new path: old file not written to", all(e["request_id"] != rid(h) for e in read_log(log)))

    write_cfg(cfg, config(log2, mode="stdout"))
    time.sleep(RELOAD_WAIT)
    s, h = req("/reload/badmode")
    check("bad mode on reload: old config kept, still logging", log_entry(log2, rid(h)) is not None)
    with open(gw_out) as f:
        out = f.read()
    check("bad mode on reload: error explains it", "mode 'stdout' is not supported" in out)

    write_cfg(cfg, config(log2, accept_incoming=False))
    time.sleep(RELOAD_WAIT)
    s, h = req("/reload/noaccept", {"X-QG-Request-Id": "client-chosen-id"})
    check("accept_incoming=false: incoming ID ignored",
          rid(h) and HEX32.match(rid(h)) and origin_seen.get("/reload/noaccept") == rid(h), rid(h))

    write_cfg(cfg, config(log2, logging_on=False))
    time.sleep(RELOAD_WAIT)
    before = len(read_log(log2))
    s, h = req("/reload/off")
    time.sleep(0.5)
    check("logging off: no new lines", s == 200 and len(read_log(log2)) == before)
    check("logging off: request ID still sent", rid(h) and HEX32.match(rid(h)), rid(h))


def rejected(tmp):
    section("Bad logging configs are refused at startup")
    for name, c, want in [
        ("mode 'stdout'", config("/tmp/x.jsonl", mode="stdout"), "is not supported"),
        ("queue_size 0", None, "queue_size"),
    ]:
        if c is None:
            c = config("/tmp/x.jsonl")
            c["plugins"]["logging"]["queue_size"] = 0
        path = os.path.join(tmp, "bad.json")
        write_cfg(path, c)
        try:
            out = subprocess.run([BIN, path], capture_output=True, text=True, timeout=10)
            text = out.stdout + out.stderr
            check(f"{name} → refused", out.returncode != 0 and want in text, f"exit {out.returncode}")
        except subprocess.TimeoutExpired:
            check(f"{name} → refused", False, "gateway started instead of refusing")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""End-to-end test: access log and X-QG-Request-Id.

Starts an origin and a gateway with logging on, then checks:
  - X-QG-Request-Id: a UUIDv7 whose time matches `ts`, unique, the same in
    the response, at the origin and in the log; an incoming UUID is reused,
    anything else is replaced; 502s and firewall blocks carry it too;
    accept_incoming=false
  - the fixed schema (schema_version 1): every key on every line, in order,
    no nulls; block {type, action, rule, key} for firewall block/redirect,
    rate limit and DoS protection; allow_rule; upstream fields; user_field;
    req_bytes/bytes; 499 when the client gives up; no query string anywhere
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
UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
KEYS = ["schema_version", "gateway_id", "ts", "request_id", "client_ip", "method", "scheme",
        "host", "path", "user_agent", "status", "bytes", "req_bytes", "dur_us", "country",
        "region", "asn", "provider", "datacenter", "vpn", "proxy", "tor", "risk", "block",
        "allow_rule", "cache", "upstream", "upstream_addr", "upstream_status", "upstream_us",
        "error", "user", "sample_rate"]
RELOAD_WAIT = 7  # the config watcher checks every 5 s

origin_seen = {}  # path → X-QG-Request-Id the origin received


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        origin_seen[self.path] = self.headers.get("x-qg-request-id")
        if self.path.startswith("/slow"):
            time.sleep(1.5)
        body = b"origin ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.do_GET()

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
                {"id": "office", "name": "office", "enabled": True,
                 "conditions": [cond("header.x-office", "equals", "yes")],
                 "action": {"type": "allow"}},
                {"id": "old-site", "name": "old", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/old")],
                 "action": {"type": "redirect", "location": "/new", "status": 301}},
                {"id": "blocked", "name": "blocked", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/blocked")],
                 "action": {"type": "block", "status": 403}},
                {"id": "api-jwt", "name": "api needs jwt", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/api", "and"),
                                cond("header.authorization.jwt_valid", "not_equals", True)],
                 "action": {"type": "block", "status": 401}},
            ]},
            "rate_limiting": {"enabled": True, "rules": [
                {"id": "per-user", "name": "per user", "enabled": True,
                 "conditions": [cond("req.path", "starts_with", "/rl")],
                 "key": ["header.x-user", "req.query.api_key"], "limit": 1, "window_seconds": 60,
                 "action": {"type": "block", "status": 429}},
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
                        "user_field": "header.authorization.jwt.sub",
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def req(path, headers=None, method="GET", data=None):
    """One request; redirects are returned, not followed."""
    r = urllib.request.Request(f"http://127.0.0.1:{GW_PORT}{path}", headers=headers or {},
                               method=method, data=data)
    try:
        with OPENER.open(r, timeout=5) as resp:
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
    before_ms = int(time.time() * 1000)
    s, h = req("/rid/a")
    a = rid(h)
    check("response has a UUIDv7 request ID", s == 200 and a and UUID7.match(a), a)
    check("origin received the same ID", origin_seen.get("/rid/a") == a, origin_seen.get("/rid/a"))
    e = log_entry(log, a)
    check("log line has the same request_id", e is not None, a)
    if e:
        id_ms = int(a.replace("-", "")[:12], 16)
        check("ID time part == ts", id_ms == e["ts"], f"{id_ms} vs {e['ts']}")
        check("ts is the arrival time (Unix ms)", before_ms - 5 <= e["ts"] <= before_ms + 5000, e["ts"])
    s, h = req("/rid/b")
    check("next request gets a different ID", rid(h) and rid(h) != a, rid(h))

    incoming = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    s, h = req("/rid/in", {"X-QG-Request-Id": incoming})
    check("incoming UUID returned to the client", rid(h) == incoming, rid(h))
    check("incoming UUID sent to the origin", origin_seen.get("/rid/in") == incoming)
    check("incoming UUID logged", log_entry(log, incoming) is not None)

    for bad in ["client-chosen-id", "bad id; drop table"]:
        s, h = req("/rid/bad", {"X-QG-Request-Id": bad})
        check(f"non-UUID incoming ID replaced ({bad[:12]})", rid(h) and UUID7.match(rid(h)), rid(h))
        check("origin got the replacement", origin_seen.get("/rid/bad") == rid(h))

    s, h = req("/blocked")
    check("firewall block (403) carries the ID", s == 403 and rid(h) and UUID7.match(rid(h)), f"{s} {rid(h)}")
    s, h = req("/down")
    check("origin down (502) carries the ID", s == 502 and rid(h) and UUID7.match(rid(h)), f"{s} {rid(h)}")
    e = log_entry(log, rid(h)) or {}
    check("502: error set, upstream_status 0, upstream_addr set",
          e.get("error") and e.get("upstream_status") == 0
          and e.get("upstream_addr") == f"127.0.0.1:{DEAD_PORT}", e.get("error"))


def raw_lines(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def keys_in_order(line):
    pairs = []
    json.loads(line, object_pairs_hook=lambda p: pairs.append([k for k, _ in p]) or dict(p))
    return pairs[-1]  # the outer object is built last


def fields(log):
    section("Fixed schema")
    s, h = req("/f?token=supersecret&page=2", {"User-Agent": "qg-test/1.0"})
    e = log_entry(log, rid(h)) or {}
    line = next((l for l in raw_lines(log).splitlines() if rid(h) in l), "{}")
    check("every key, in order", keys_in_order(line) == KEYS, len(keys_in_order(line)))
    check("no null values", "null" not in line)
    check("schema_version 1, gateway_id", e.get("schema_version") == 1 and e.get("gateway_id") == "gw-log")
    check("path has no query string", e.get("path") == "/f", e.get("path"))
    check("query value never written", "supersecret" not in raw_lines(log))
    check("method, scheme, host, client_ip",
          (e.get("method"), e.get("scheme"), e.get("host"), e.get("client_ip"))
          == ("GET", "http", f"127.0.0.1:{GW_PORT}", "127.0.0.1"))
    check("user_agent", e.get("user_agent") == "qg-test/1.0", e.get("user_agent"))
    check("status 200, bytes = body size", e.get("status") == 200 and e.get("bytes") == 9,
          f"{e.get('status')} {e.get('bytes')}")
    check("upstream id, addr, status",
          (e.get("upstream"), e.get("upstream_addr"), e.get("upstream_status"))
          == ("origin", f"127.0.0.1:{ORIGIN_PORT}", 200))
    check("upstream_us > 0 and <= dur_us", 0 < e.get("upstream_us", 0) <= e.get("dur_us", 0),
          f"{e.get('upstream_us')} / {e.get('dur_us')}")
    check("not blocked: block all empty",
          e.get("block") == {"type": "", "action": "", "rule": "", "key": ""}, e.get("block"))
    check("defaults: cache NONE, error '', user '', sample_rate 1",
          (e.get("cache"), e.get("error"), e.get("user"), e.get("sample_rate")) == ("NONE", "", "", 1))

    s, h = req("/rewritten")
    e = log_entry(log, rid(h)) or {}
    check("status rewrite: upstream 200, client 203",
          s == 203 and e.get("upstream_status") == 200 and e.get("status") == 203,
          f"{e.get('upstream_status')} → {e.get('status')}")

    s, h = req("/post", {"Content-Type": "text/plain"}, method="POST", data=b"y" * 50)
    e = log_entry(log, rid(h)) or {}
    check("req_bytes = request body size", s == 200 and e.get("req_bytes") == 50, e.get("req_bytes"))

    section("block / allow_rule")
    s, h = req("/blocked/x?k=v")
    e = log_entry(log, rid(h)) or {}
    check("firewall block", s == 403 and e.get("block") ==
          {"type": "fw", "action": "block", "rule": "blocked", "key": "req.path=/blocked/x"},
          e.get("block"))
    check("blocked: no upstream fields",
          (e.get("upstream"), e.get("upstream_addr"), e.get("upstream_status")) == ("", "", 0))

    s, h = req("/old/page")
    e = log_entry(log, rid(h)) or {}
    check("firewall redirect", s == 301 and e.get("block") ==
          {"type": "fw", "action": "redirect", "rule": "old-site", "key": "req.path=/old/page"},
          e.get("block"))

    s, h = req("/blocked", {"X-Office": "yes"})
    e = log_entry(log, rid(h)) or {}
    check("allow rule: passes, allow_rule logged",
          s == 200 and e.get("allow_rule") == "office" and e.get("block", {}).get("type") == "",
          e.get("allow_rule"))

    forged = pyjwt.encode({"sub": "admin", "exp": int(time.time()) + 600}, "wrong", algorithm="HS256")
    s, h = req("/api/x", {"Authorization": f"Bearer {forged}"})
    e = log_entry(log, rid(h)) or {}
    check("JWT rejected by a firewall rule: key has the deciding conditions",
          s == 401 and e.get("block") == {"type": "fw", "action": "block", "rule": "api-jwt",
                                          "key": "req.path=/api/x&header.authorization.jwt_valid=false"},
          e.get("block"))
    check("forged token: user stays ''", e.get("user") == "", e.get("user"))

    good = pyjwt.encode({"sub": "user-7", "exp": int(time.time()) + 600}, SECRET, algorithm="HS256")
    s, h = req("/api/x", {"Authorization": f"Bearer {good}"})
    e = log_entry(log, rid(h)) or {}
    check("valid token: user = sub (user_field)", s == 200 and e.get("user") == "user-7", e.get("user"))

    req("/rl/a?api_key=k-secret-1", {"X-User": "u1"})
    s, h = req("/rl/a?api_key=k-secret-1", {"X-User": "u1"})
    e = log_entry(log, rid(h)) or {}
    b = e.get("block") or {}
    check("rate limit: type rl, rule per-user",
          s == 429 and (b.get("type"), b.get("action"), b.get("rule")) == ("rl", "block", "per-user"), b)
    check("rate limit key: field=value pairs, query value hashed",
          re.fullmatch(r"header\.x-user=u1&req\.query\.api_key=#[0-9a-f]{6}", b.get("key", "")) is not None,
          b.get("key"))
    check("rate-limit query value never written", "k-secret-1" not in raw_lines(log))

    s, h = req("/upload", {"Content-Type": "text/plain"}, method="POST", data=b"x" * 1000)
    e = log_entry(log, rid(h)) or {}
    check("oversized body: 413, block dos/body_too_large", s == 413 and e.get("block") ==
          {"type": "dos", "action": "block", "rule": "body_too_large", "key": "client_ip=127.0.0.1"},
          e.get("block"))

    section("Client gives up (499)")
    import socket
    before = len(read_log(log))
    sock = socket.create_connection(("127.0.0.1", GW_PORT))
    sock.sendall(f"GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{GW_PORT}\r\n\r\n".encode())
    time.sleep(0.3)
    sock.close()
    e = None
    end = time.time() + 5
    while time.time() < end and e is None:
        e = next((x for x in read_log(log)[before:] if x["path"] == "/slow"), None)
        time.sleep(0.1)
    e = e or {}
    check("status 499, error 'client closed'",
          e.get("status") == 499 and e.get("error") == "client closed",
          f"{e.get('status')} {e.get('error')}")


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
    incoming = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    s, h = req("/reload/noaccept", {"X-QG-Request-Id": incoming})
    check("accept_incoming=false: incoming UUID ignored",
          rid(h) and rid(h) != incoming and UUID7.match(rid(h))
          and origin_seen.get("/reload/noaccept") == rid(h), rid(h))

    write_cfg(cfg, config(log2, logging_on=False))
    time.sleep(RELOAD_WAIT)
    before = len(read_log(log2))
    s, h = req("/reload/off")
    time.sleep(0.5)
    check("logging off: no new lines", s == 200 and len(read_log(log2)) == before)
    check("logging off: request ID still sent", rid(h) and UUID7.match(rid(h)), rid(h))


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

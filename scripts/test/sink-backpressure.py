#!/usr/bin/env python3
"""End-to-end test: a slow log destination under load.

A local mock destination that takes its time answering, and wrk sending
traffic through the gateway. Checks:
  - `concurrency` batches are in flight at once (4 by default, 1 when set)
  - with a spool, a destination that can't keep up fills the spool instead
    of dropping lines; everything arrives once it speeds up again
  - without a spool, lines past max_buffer_bytes are dropped, counted and
    logged

Usage:  python3 scripts/test/sink-backpressure.py
Env:    BIN=./target/release/quayel-gateway (default)
Needs:  wrk
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))
GW_PORT, ORIGIN_PORT, MOCK_PORT, METRICS_PORT = 18330, 18331, 18332, 18333

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


lock = threading.Lock()
state = {"delay": 0.0, "active": 0, "max_active": 0, "lines": 0, "requests": 0}


class Mock(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        with lock:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            delay = state["delay"]
        time.sleep(delay)
        with lock:
            state["active"] -= 1
            state["lines"] += raw.count(b"\n")
            state["requests"] += 1
        self.send_response(200)
        self.send_header("content-length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def reset(delay):
    with lock:
        state.update(delay=delay, active=0, max_active=0, lines=0, requests=0)


def metrics():
    with urllib.request.urlopen(f"http://127.0.0.1:{METRICS_PORT}/metrics", timeout=5) as r:
        return r.read().decode()


def metric(text, name, **labels):
    total = 0.0
    for line in text.splitlines():
        if line.startswith(name) and all(f'{k}="{v}"' in line for k, v in labels.items()):
            total += float(line.rsplit(" ", 1)[1])
    return total


def until(fn, secs):
    end = time.time() + secs
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.25)
    return fn()


def start(tmp, sink):
    sink = {"type": "http", "name": "slow", "url": f"http://127.0.0.1:{MOCK_PORT}/",
            "compression": "none", "flush_interval_ms": 100, **sink}
    cfg = {
        "gateway_id": "gw-bp", "gateway_name": "bp", "server_name": "bp", "config_version": "1",
        "listen": {"http": f"127.0.0.1:{GW_PORT}"},
        "server": {"protection": {"enabled": False}},
        "metrics": {"listen": f"127.0.0.1:{METRICS_PORT}"},
        "plugins": {
            # The gateway answers /x itself (still one log line per request),
            # so the load isn't capped by the Python origin.
            "firewall": {"enabled": True, "rules": [{
                "id": "gen", "name": "answer in the gateway", "enabled": True,
                "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/x"}],
                "action": {"type": "block", "status": 403}}]},
            "load_balancer": {"enabled": True, "load_balancers": [
                {"id": "o", "name": "o", "enabled": True, "conditions": [],
                 "algorithm": {"type": "round_robin"},
                 "targets": [{"id": "o1", "host": "127.0.0.1", "port": ORIGIN_PORT, "protocol": "http",
                              "weight": 1, "enabled": True}]}]},
            "logging": {"enabled": True, "mode": "file",
                        "file": {"path": os.path.join(tmp, "access.jsonl"), "flush_interval_ms": 100},
                        "sinks": [sink]},
        },
    }
    path = os.path.join(tmp, "config.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    out = open(os.path.join(tmp, "gateway.log"), "wb")
    p = subprocess.Popen([BIN, path], stdout=out, stderr=subprocess.STDOUT,
                         env=dict(os.environ, RUST_LOG="info"))
    if not until(lambda: _up(), 20):
        raise RuntimeError("gateway didn't start; see " + out.name)
    return p


def _up():
    # The metrics listener can come up before the proxy port: wait for both.
    try:
        metrics()
        socket.create_connection(("127.0.0.1", GW_PORT), timeout=1).close()
        return True
    except Exception:
        return False


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(20)
    except subprocess.TimeoutExpired:
        p.kill()


def load(secs, conns=32):
    r = subprocess.run(["wrk", "-t2", f"-c{conns}", f"-d{secs}s", f"http://127.0.0.1:{GW_PORT}/x"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"wrk failed ({r.returncode}): {r.stdout[-300:]} {r.stderr[-300:]}")


def logged(tmp):
    time.sleep(0.5)  # access file flushes every 100 ms
    with open(os.path.join(tmp, "access.jsonl"), "rb") as f:
        return sum(1 for _ in f)


def run_case(name, sink, fn):
    tmp = tempfile.mkdtemp(prefix="qg-bp-")
    p = start(tmp, sink)
    try:
        print(f"\n── {name}")
        fn(tmp)
    finally:
        stop(p)
        shutil.rmtree(tmp, ignore_errors=True)


def concurrency_default(tmp):
    reset(0.3)
    load(3)
    check("4 batches in flight at once (default)", state["max_active"] == 4, f"max {state['max_active']}")
    reset_delay(0)
    total = logged(tmp)
    check("every line delivered", until(lambda: state_lines_total() >= total, 30),
          f"{state_lines_total()} of {total}")


def concurrency_one(tmp):
    reset(0.3)
    load(2)
    check("1 batch in flight with concurrency: 1", state["max_active"] == 1, f"max {state['max_active']}")


def reset_delay(d):
    with lock:
        state["delay"] = d


def state_lines_total():
    with lock:
        return state["lines"]


def spool_not_drop(tmp):
    reset(2.0)
    peak = {"spool": 0}
    stop_watch = threading.Event()

    def watch():
        while not stop_watch.is_set():
            try:
                peak["spool"] = max(peak["spool"], metric(metrics(), "qg_log_sink_spool_bytes", sink="slow"))
            except Exception:
                pass
            time.sleep(0.2)

    t = threading.Thread(target=watch, daemon=True)
    t.start()
    load(5)
    m = metrics()
    stop_watch.set()
    t.join()
    total = logged(tmp)
    dropped = metric(m, "qg_log_sink_lines_total", sink="slow", result="dropped")
    check("load produced more than the 8 MiB buffer holds", total > 40000, f"{total} lines")
    check("slow destination fills the spool", peak["spool"] > 8 << 20, f"peak {int(peak['spool'])} bytes")
    check("no lines dropped", dropped == 0, f"{int(dropped)} dropped")
    reset_delay(0)
    ok = until(lambda: state_lines_total() >= total, 60)
    check("everything arrives once the destination speeds up", ok and state_lines_total() == total,
          f"{state_lines_total()} of {total}")
    check("spool emptied", until(lambda: metric(metrics(), "qg_log_sink_spool_bytes", sink="slow") == 0, 10))


def drop_without_spool(tmp):
    reset(2.0)
    load(5)
    m = metrics()
    dropped = metric(m, "qg_log_sink_lines_total", sink="slow", result="dropped")
    check("without a spool, lines past the buffer are dropped and counted", dropped > 0, f"{int(dropped)} dropped")
    reset_delay(0)
    time.sleep(1)
    with open(os.path.join(tmp, "gateway.log"), errors="replace") as f:
        text = f.read()
    check("the drop is logged", "memory buffer full" in text)


def main():
    if not shutil.which("wrk"):
        print("wrk not found")
        sys.exit(1)
    for port, h in ((ORIGIN_PORT, Origin), (MOCK_PORT, Mock)):
        threading.Thread(target=Quiet(("127.0.0.1", port), h).serve_forever, daemon=True).start()

    small = {"batch_size": 200}
    run_case("default concurrency", small, concurrency_default)
    run_case("concurrency: 1", {**small, "concurrency": 1}, concurrency_one)
    # Smaller than two of the writer's hand-overs (up to 8192 lines, ~5 MB):
    # the spool has to start well before 3/4 of the buffer.
    tight = {"batch_size": 500, "concurrency": 1, "max_buffer_bytes": 8 << 20}
    run_case("slow destination with a spool",
             {**tight, "spool_dir": os.path.join(tempfile.gettempdir(), f"qg-bp-spool-{os.getpid()}")},
             spool_not_drop)
    run_case("slow destination without a spool", tight, drop_without_spool)

    shutil.rmtree(os.path.join(tempfile.gettempdir(), f"qg-bp-spool-{os.getpid()}"), ignore_errors=True)
    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} passed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

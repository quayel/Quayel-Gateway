#!/usr/bin/env python3
"""Live check of the `server` timeouts, limits and protection settings.

Usage: scripts/test/dos-protection.py [path/to/quayel-gateway]

Starts the echo origin and a gateway on 127.0.0.1 with tight limits, then
runs Slowloris, slow POST, oversized request, connection flood and request
flood attacks against it. Each test connects from its own loopback address
(127.0.0.x) so one test's ban doesn't affect the next. Linux only (the whole
127.0.0.0/8 range must be routable to lo, which it is by default).
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target/release/quayel-gateway")
GW_PORT = 18190
ORIGIN_PORT = 18191

CONFIG = {
    "gateway_id": "dos-test",
    "gateway_name": "dos-test",
    "server_name": "dos-test",
    "config_version": "1",
    "listen": {"http": f"127.0.0.1:{GW_PORT}"},
    "server": {
        "timeouts": {"header_secs": 2, "keepalive_secs": 6, "body_read_secs": 2},
        "limits": {"max_header_bytes": 4096, "max_body_bytes": 1000},
        "protection": {
            "exempt_ips": [],
            "max_connections_per_ip": 20,
            "max_new_connections_per_ip_per_sec": 1000,
            "max_requests_per_ip_per_sec": 50,
            "ban": {"strikes": 5, "window_secs": 60, "duration_secs": 5},
        },
    },
    "plugins": {
        "load_balancer": {
            "enabled": True,
            "load_balancers": [{
                "id": "lb", "name": "lb", "conditions": [],
                "algorithm": {"type": "round_robin"},
                "targets": [{"id": "o", "host": "127.0.0.1", "port": ORIGIN_PORT}],
                "health_check": {"mode": "off"},
            }],
        },
    },
}

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def conn(src):
    s = socket.create_connection(("127.0.0.1", GW_PORT), timeout=10, source_address=(src, 0))
    return s


def closed_within(s, seconds):
    """Seconds until the server closes the socket, or None if it stays open."""
    start = time.time()
    s.settimeout(0.2)
    while time.time() - start < seconds:
        try:
            if s.recv(65536) == b"":
                return time.time() - start
        except socket.timeout:
            continue
        except (ConnectionResetError, BrokenPipeError):
            return time.time() - start
    return None


def status_of(raw):
    line = raw.split(b"\r\n", 1)[0].split()
    return int(line[1]) if len(line) > 1 and line[1].isdigit() else None


def http_conn(src):
    return http.client.HTTPConnection("127.0.0.1", GW_PORT, timeout=10, source_address=(src, 0))


def main():
    tmp = tempfile.mkdtemp(prefix="qg-dos-")
    cfg = os.path.join(tmp, "config.json")
    with open(cfg, "w") as f:
        json.dump(CONFIG, f)
    origin = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "scripts/test/echo-origin.py"), str(ORIGIN_PORT), "o"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = open(os.path.join(tmp, "gateway.out"), "w")
    gw = subprocess.Popen([BINARY, "--workers", "2", cfg], stdout=log, stderr=subprocess.STDOUT,
                          env={**os.environ, "RUST_LOG": "info"})
    try:
        # Wait for the origin too: if the gateway is up first, the first
        # checks get 502s from a refused upstream connection.
        for port in (ORIGIN_PORT, GW_PORT):
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
        run_tests()
        keepalive_rate_check(tmp)
    finally:
        gw.terminate()
        origin.terminate()
        gw.wait(10)
        log.close()
    with open(os.path.join(tmp, "gateway.out")) as f:
        bans = [l for l in f if "IP banned" in l]
    check("ban is logged as a warning", len(bans) >= 1, f"{len(bans)} ban line(s)")
    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed  (gateway log: {tmp}/gateway.out)")
    sys.exit(0 if passed == len(results) else 1)


def keepalive_rate_check(tmp):
    """Requests on one kept-alive connection are not new connections.

    A second gateway with max_new_connections_per_ip_per_sec: 5 and no
    request-rate limit. 30 quick requests on one connection must all pass.
    (Holds because Pingora serves the whole keep-alive loop inside one
    process_new call; this guards against that changing in an upgrade.)
    """
    print("Keep-alive vs new-connection rate")
    port = GW_PORT + 2
    cfg = json.loads(json.dumps(CONFIG))
    cfg["listen"]["http"] = f"127.0.0.1:{port}"
    cfg["server"]["protection"]["max_new_connections_per_ip_per_sec"] = 5
    cfg["server"]["protection"]["max_requests_per_ip_per_sec"] = 0
    path = os.path.join(tmp, "config-rate.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    gw = subprocess.Popen([BINARY, "--workers", "2", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        time.sleep(1.1)  # the readiness probe used one of this second's 5
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10, source_address=("127.0.0.11", 0))
        ok = 0
        try:
            for _ in range(30):
                c.request("GET", "/")
                r = c.getresponse()
                r.read()
                ok += r.status == 200
        except Exception:
            pass
        check("30 keep-alive requests on one connection (new-connection limit 5/s)", ok == 30, f"{ok}/30 answered")
        c.close()
        socks = [conn_to(port, "127.0.0.12") for _ in range(8)]
        time.sleep(0.3)
        dropped = sum(closed_within(x, 0.3) is not None for x in socks)
        check("8 new connections in one second (limit 5/s): extra ones are dropped", dropped >= 3, f"{dropped} dropped")
        for x in socks:
            x.close()
    finally:
        gw.terminate()
        gw.wait(10)


def conn_to(port, src):
    return socket.create_connection(("127.0.0.1", port), timeout=10, source_address=(src, 0))


def run_tests():
    print("Normal traffic")
    c = http_conn("127.0.0.2")
    codes = []
    for _ in range(3):
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        codes.append(r.status)
    check("3 keep-alive requests on one connection", codes == [200, 200, 200], str(codes))
    time.sleep(3)  # longer than header_secs, shorter than keepalive_secs
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    check("idle keep-alive gap longer than header_secs is fine", r.status == 200, str(r.status))
    c.request("POST", "/", body=b"x" * 900, headers={"content-type": "text/plain"})
    r = c.getresponse()
    r.read()
    check("POST under max_body_bytes is proxied", r.status == 200, str(r.status))
    c.close()

    print("Slowloris")
    s = conn("127.0.0.3")
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
    start = time.time()
    s.settimeout(0.5)
    closed = None
    while time.time() - start < 8:
        try:
            s.sendall(b"X")
            if s.recv(1) == b"":
                closed = time.time() - start
                break
        except socket.timeout:
            continue
        except (BrokenPipeError, ConnectionResetError):
            closed = time.time() - start
            break
    check("header dribbled 1 byte / 0.5 s is cut off near header_secs (2 s)",
          closed is not None and closed < 3.5, f"closed after {closed and round(closed, 1)} s")
    s.close()

    s = conn("127.0.0.4")
    t = closed_within(s, 6)
    check("connection that sends nothing is closed near header_secs", t is not None and t < 3.5,
          f"closed after {t and round(t, 1)} s")
    s.close()

    print("Oversized and slow requests")
    s = conn("127.0.0.5")
    try:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 9000 + b"\r\n\r\n")
    except OSError:
        pass
    t = closed_within(s, 3)
    check("9 KB header (limit 4 KB) is refused", t is not None, f"closed after {t and round(t, 2)} s")
    s.close()

    c = http_conn("127.0.0.6")
    c.putrequest("POST", "/")
    c.putheader("Content-Length", "5000")
    c.endheaders()
    r = c.getresponse()
    check("Content-Length over max_body_bytes → 413", r.status == 413, str(r.status))
    c.close()

    s = conn("127.0.0.7")
    s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
    for _ in range(4):
        s.sendall(b"200\r\n" + b"y" * 512 + b"\r\n")
    s.sendall(b"0\r\n\r\n")
    s.settimeout(3)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError):
        pass  # the gateway may reset after the 413 while body bytes are still unread
    check("2 KB chunked body (limit 1000 B) → 413", status_of(data) == 413, str(status_of(data)))
    s.close()

    s = conn("127.0.0.8")
    s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n" + b"z" * 10)
    t = closed_within(s, 6)
    check("slow POST that stalls is cut off near body_read_secs (2 s)", t is not None and t < 4,
          f"closed after {t and round(t, 1)} s")
    s.close()

    print("Connection flood")
    socks = [conn("127.0.0.9") for _ in range(23)]
    time.sleep(0.3)
    refused = 0
    for s in socks:
        s.setblocking(False)
        try:
            if s.recv(1) == b"":
                refused += 1
        except BlockingIOError:
            pass
        except ConnectionResetError:
            refused += 1
    check("23 connections from one IP (limit 20): extra ones are dropped", refused == 3, f"{refused} dropped")
    for s in socks:
        s.close()
    time.sleep(0.3)
    c = http_conn("127.0.0.9")
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    check("the IP can connect again once its connections close (3 strikes, below the ban)", r.status == 200, str(r.status))
    c.close()


    print("Request flood")
    codes = []
    reasons = set()
    c = http_conn("127.0.0.10")
    for _ in range(120):
        try:
            c.request("GET", "/")
            r = c.getresponse()
            r.read()
            codes.append(r.status)
            if r.getheader("X-Quayel-Block-Reason"):
                reasons.add(r.getheader("X-Quayel-Block-Reason"))
            if r.status == 429:
                c.close()
                c = http_conn("127.0.0.10")
        except (OSError, http.client.HTTPException):
            codes.append(0)
            c.close()
            c = http_conn("127.0.0.10")
    ok200 = codes.count(200)
    check("flood is cut off (limit 50/s)", codes.count(429) >= 1 and ok200 <= 100,
          f"{ok200}×200, {codes.count(429)}×429, {codes.count(0)} dropped")
    check("429s carry the block reason", "request_rate" in reasons, ", ".join(sorted(reasons)))
    time.sleep(1.2)
    try:
        c = http_conn("127.0.0.10")
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        banned_status = r.status
    except (OSError, http.client.HTTPException):
        banned_status = 0
    check("after 5 strikes the IP is banned (connection dropped)", banned_status == 0, str(banned_status))
    other = http_conn("127.0.0.11")
    other.request("GET", "/")
    r = other.getresponse()
    r.read()
    check("other IPs are unaffected", r.status == 200, str(r.status))
    time.sleep(5)
    c = http_conn("127.0.0.10")
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    check("ban expires after duration_secs (5 s)", r.status == 200, str(r.status))


if __name__ == "__main__":
    main()

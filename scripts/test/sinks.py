#!/usr/bin/env python3
"""End-to-end test: log sinks and Prometheus metrics.

Runs real ClickHouse, Loki, an OpenTelemetry Collector and Prometheus in
Docker, plus a local mock for Datadog, Splunk, Elasticsearch and the generic
HTTP sink (checks body format, gzip and auth headers). Then checks:
  - every sink receives every line, in the destination's format
  - ClickHouse: rows match the request IDs, scripts/clickhouse/access_log.sql
    loads lines as they are, `time` is right
  - /metrics: request, block and per-sink counters; Prometheus scrapes it
  - ClickHouse down: batches are retried and spooled, nothing lost or
    duplicated once it's back
  - spool survives a gateway restart
  - a destination answering 400 has its batch dropped and counted, not
    retried forever
  - stdout sink writes the same lines

Usage:  python3 scripts/test/sinks.py
Env:    BIN=./target/debug/quayel-gateway (default)
Needs:  Docker with clickhouse/clickhouse-server, grafana/loki,
        otel/opentelemetry-collector-contrib, prom/prometheus
"""
import gzip
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GW_PORT, ORIGIN_PORT, MOCK_PORT, METRICS_PORT = 18320, 18321, 18322, 18323
CH_PORT, LOKI_PORT, OTLP_PORT, PROM_PORT = 18324, 18325, 18326, 18327
BIN = os.environ.get("BIN", "./target/debug/quayel-gateway")
HERE = os.path.dirname(os.path.abspath(__file__))
SQL = os.path.join(HERE, "..", "clickhouse", "access_log.sql")
CONTAINERS = ["qg-test-ch", "qg-test-loki", "qg-test-otel", "qg-test-prom"]

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


# ── Origin and mock destination ─────────────────────────────────────────────

class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


mock_lock = threading.Lock()
mock_reqs = []           # (path, headers dict, decoded body bytes)
mock_fail = {}           # path prefix → status to answer


class Mock(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.headers.get("content-encoding") == "gzip":
            raw = gzip.decompress(raw)
        with mock_lock:
            status = next((s for p, s in mock_fail.items() if self.path.startswith(p)), 200)
            mock_reqs.append((self.path, {k.lower(): v for k, v in self.headers.items()}, raw, status))
        body = b'{"errors":false,"items":[]}' if self.path.startswith("/es") else b"{}"
        self.send_response(status)
        self.send_header("content-length", str(len(body)))
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def mock_bodies(prefix):
    with mock_lock:
        return [(h, b) for p, h, b, s in mock_reqs if p.startswith(prefix) and s == 200]


# ── Docker ───────────────────────────────────────────────────────────────────

def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout


def http(url, data=None, method=None, timeout=5):
    req = urllib.request.Request(url, data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def wait_http(url, secs=60):
    end = time.time() + secs
    while time.time() < end:
        try:
            if http(url, timeout=2)[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def ch(query):
    return http(f"http://127.0.0.1:{CH_PORT}/", data=query.encode())[1].decode().strip()


def start_containers(tmp):
    sh(f"docker rm -f {' '.join(CONTAINERS)}", check_rc=False)
    sh(f"docker run -d --name qg-test-ch -p {CH_PORT}:8123 --ulimit nofile=262144:262144 "
       "-e CLICKHOUSE_SKIP_USER_SETUP=1 clickhouse/clickhouse-server:latest")
    sh(f"docker run -d --name qg-test-loki -p {LOKI_PORT}:3100 grafana/loki:latest "
       "-config.file=/etc/loki/local-config.yaml")
    otel_dir = os.path.join(tmp, "otel")
    os.makedirs(otel_dir)
    os.chmod(otel_dir, 0o777)
    with open(os.path.join(otel_dir, "config.yaml"), "w") as f:
        f.write("receivers:\n  otlp:\n    protocols:\n      http:\n        endpoint: 0.0.0.0:4318\n"
                "exporters:\n  file:\n    path: /out/logs.json\n    flush_interval: 200ms\n"
                "service:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [file]\n")
    sh(f"docker run -d --name qg-test-otel -p {OTLP_PORT}:4318 -v {otel_dir}:/out "
       "otel/opentelemetry-collector-contrib:latest --config=/out/config.yaml")
    prom_dir = os.path.join(tmp, "prom")
    os.makedirs(prom_dir)
    with open(os.path.join(prom_dir, "prometheus.yml"), "w") as f:
        f.write(f"global:\n  scrape_interval: 1s\nscrape_configs:\n  - job_name: qg\n"
                f"    static_configs:\n      - targets: ['127.0.0.1:{METRICS_PORT}']\n")
    sh(f"docker run -d --name qg-test-prom --network host -v {prom_dir}:/etc/prometheus "
       f"prom/prometheus:latest --config.file=/etc/prometheus/prometheus.yml "
       f"--web.listen-address=127.0.0.1:{PROM_PORT}")
    ok = (wait_http(f"http://127.0.0.1:{CH_PORT}/ping")
          and wait_http(f"http://127.0.0.1:{LOKI_PORT}/ready", 90)
          and wait_http(f"http://127.0.0.1:{PROM_PORT}/-/ready"))
    if not ok:
        raise RuntimeError("containers didn't become ready")
    sh(f"docker exec -i qg-test-ch clickhouse-client --multiquery < {SQL}")
    return otel_dir


# ── Gateway ──────────────────────────────────────────────────────────────────

def config(tmp, mock_http_status_path="/http"):
    m = f"http://127.0.0.1:{MOCK_PORT}"
    fast = {"flush_interval_ms": 200}
    return {
        "gateway_id": "gw-sinks", "gateway_name": "sinks", "server_name": "sinks", "config_version": "1",
        "listen": {"http": f"127.0.0.1:{GW_PORT}"}, "client_ip": {"source": "peer_ip"},
        "metrics": {"listen": f"127.0.0.1:{METRICS_PORT}"},
        "plugins": {
            "firewall": {"enabled": True, "rules": [
                {"id": "blocked", "name": "blocked", "enabled": True,
                 "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/blocked"}],
                 "action": {"type": "block", "status": 403}}]},
            "load_balancer": {"enabled": True, "load_balancers": [
                {"id": "origin", "name": "origin", "enabled": True, "conditions": [],
                 "algorithm": {"type": "round_robin"},
                 "targets": [{"id": "o1", "host": "127.0.0.1", "port": ORIGIN_PORT, "protocol": "http",
                              "weight": 1, "enabled": True}]}]},
            "logging": {"enabled": True, "mode": "file",
                        "file": {"path": os.path.join(tmp, "access.jsonl"), "flush_interval_ms": 100},
                        "sinks": [
                            {"type": "stdout"},
                            {"type": "clickhouse", "url": f"http://127.0.0.1:{CH_PORT}", "database": "qg",
                             "spool_dir": os.path.join(tmp, "spool"), "timeout_ms": 2000, **fast},
                            {"type": "loki", "url": f"http://127.0.0.1:{LOKI_PORT}",
                             "labels": {"job": "qg-test"}, **fast},
                            {"type": "otlp", "url": f"http://127.0.0.1:{OTLP_PORT}",
                             "resource_attributes": {"deployment.environment": "test"}, **fast},
                            {"type": "datadog", "url": f"{m}/dd", "api_key": "dd-key", "tags": "env:test", **fast},
                            {"type": "splunk", "url": f"{m}/splunk", "token_env": "QG_TEST_SPLUNK", **fast},
                            {"type": "elasticsearch", "url": f"{m}/es", "user": "elastic", "password": "pw", **fast},
                            {"type": "http", "name": "webhook", "url": f"{m}{mock_http_status_path}",
                             "token": "tok", "compression": "none", **fast},
                        ]},
        },
    }


def start_gateway(tmp):
    path = os.path.join(tmp, "config.json")
    with open(path, "w") as f:
        json.dump(config(tmp), f)
    out = open(os.path.join(tmp, "stdout.log"), "ab")
    env = dict(os.environ, QG_TEST_SPLUNK="splunk-token", RUST_LOG="info")
    p = subprocess.Popen([BIN, path], stdout=out, stderr=subprocess.STDOUT, env=env)
    if not wait_http(f"http://127.0.0.1:{METRICS_PORT}/metrics", 20):
        raise RuntimeError("gateway didn't start; see " + out.name)
    return p


def stop_gateway(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(20)
    except subprocess.TimeoutExpired:
        p.kill()


def send(paths):
    ids = []
    for path in paths:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{GW_PORT}{path}", timeout=5) as r:
                ids.append(r.headers["x-qg-request-id"])
        except urllib.error.HTTPError as e:
            ids.append(e.headers["x-qg-request-id"])
    return ids


def until(fn, secs=30):
    end = time.time() + secs
    v = fn()
    while not v and time.time() < end:
        time.sleep(0.5)
        v = fn()
    return v


def metrics():
    return http(f"http://127.0.0.1:{METRICS_PORT}/metrics")[1].decode()


def metric(text, name, **labels):
    total = 0.0
    for line in text.splitlines():
        if not line.startswith(name + "{") and not line.startswith(name + " "):
            continue
        if all(f'{k}="{v}"' in line for k, v in labels.items()):
            total += float(line.rsplit(" ", 1)[1])
    return total


# ── Tests ────────────────────────────────────────────────────────────────────

def main():
    tmp = tempfile.mkdtemp(prefix="qg-sinks-")
    for port, h in [(ORIGIN_PORT, Origin), (MOCK_PORT, Mock)]:
        threading.Thread(target=Quiet(("127.0.0.1", port), h).serve_forever, daemon=True).start()
    print("Starting ClickHouse, Loki, OTel Collector, Prometheus...")
    otel_dir = start_containers(tmp)
    gw = start_gateway(tmp)
    try:
        run(tmp, otel_dir, gw)
    finally:
        gw_now = globals().get("GW")
        for p in (gw, gw_now):
            if p and p.poll() is None:
                stop_gateway(p)
        sh(f"docker rm -f {' '.join(CONTAINERS)}", check_rc=False)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print("  FAIL", f)
    sys.exit(1 if FAIL else 0)


def run(tmp, otel_dir, gw):
    global GW
    paths = [f"/ok/{i}?secret=s{i}" for i in range(40)] + [f"/blocked/{i}" for i in range(10)]
    ids = send(paths)
    n = len(ids)
    print(f"\n── delivery ({n} requests)")

    rows = until(lambda: (r := ch("SELECT count() FROM qg.access_log")) == str(n) and r, 20)
    check("clickhouse: every line is a row", rows == str(n), f"rows={ch('SELECT count() FROM qg.access_log')}")
    got = set(ch("SELECT toString(request_id) FROM qg.access_log").split())
    check("clickhouse: request IDs match X-QG-Request-Id", got == set(ids))
    check("clickhouse: blocks by rule",
          ch("SELECT count() FROM qg.access_log WHERE block.type='fw' AND block.rule='blocked'") == "10")
    drift = ch("SELECT max(abs(toUnixTimestamp64Milli(time) - ts)) FROM qg.access_log")
    check("clickhouse: time built from ts", drift == "0", drift)
    check("clickhouse: no query string stored",
          ch("SELECT count() FROM qg.access_log WHERE position(path, '?') > 0") == "0")
    check("clickhouse: client_ip is IPv6-mapped",
          ch("SELECT any(toString(client_ip)) FROM qg.access_log") == "::ffff:127.0.0.1")

    def loki_lines():
        q = urllib.parse.urlencode({"query": '{job="qg-test"}', "limit": 1000,
                                    "start": str(int((time.time() - 600) * 1e9))})
        try:
            body = json.loads(http(f"http://127.0.0.1:{LOKI_PORT}/loki/api/v1/query_range?{q}")[1])
        except Exception:
            return []
        out = []
        for s in body["data"]["result"]:
            out += [(s["stream"], v) for v in s["values"]]
        return out
    ll = until(lambda: (l := loki_lines()) and len(l) >= n and l, 20) or loki_lines()
    check("loki: every line pushed", len(ll) == n, f"{len(ll)}")
    if ll:
        stream, (ts_ns, text) = ll[0]
        line = json.loads(text)
        check("loki: gateway_id label added", stream.get("gateway_id") == "gw-sinks", str(stream))
        check("loki: entry time is the line's ts", int(ts_ns) == line["ts"] * 1_000_000)

    def otel_records():
        recs = []
        try:
            with open(os.path.join(otel_dir, "logs.json")) as f:
                for l in f:
                    for rl in json.loads(l)["resourceLogs"]:
                        res = {a["key"]: a["value"].get("stringValue") for a in rl["resource"]["attributes"]}
                        for sl in rl["scopeLogs"]:
                            recs += [(res, r) for r in sl["logRecords"]]
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return recs
    recs = until(lambda: (r := otel_records()) and len(r) >= n and r, 20) or otel_records()
    check("otlp: collector received every record", len(recs) == n, f"{len(recs)}")
    if recs:
        res, rec = next(((r, x) for r, x in recs
                         if any(a["key"] == "block.rule" and a["value"].get("stringValue") == "blocked"
                                for a in x["attributes"])), recs[0])
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        check("otlp: resource has service.name and custom attributes",
              res.get("service.name") == "quayel-gateway" and res.get("deployment.environment") == "test", str(res))
        check("otlp: block.rule attribute + WARN severity",
              attrs.get("block.rule", {}).get("stringValue") == "blocked" and rec.get("severityText") == "WARN")
        check("otlp: status is an int attribute", attrs.get("status", {}).get("intValue") == "403")

    def count(prefix, fn):
        return sum(fn(b) for _, b in mock_bodies(prefix))
    until(lambda: count("/dd", lambda b: len(json.loads(b))) >= n, 10)
    dd = mock_bodies("/dd")
    dd_items = [i for _, b in dd for i in json.loads(b)]
    check("datadog: every line, gzip, DD-API-KEY",
          len(dd_items) == n and all(h.get("dd-api-key") == "dd-key" and h.get("content-encoding") == "gzip"
                                     for h, _ in dd), f"{len(dd_items)}")
    if dd_items:
        it = dd_items[0]
        check("datadog: envelope (ddsource, service, ddtags, hostname, qg)",
              it["ddsource"] == "quayel-gateway" and it["ddtags"] == "env:test"
              and it["hostname"] == "gw-sinks" and "status" in it["qg"])

    until(lambda: count("/splunk", lambda b: len(b.splitlines())) >= n, 10)
    sp = mock_bodies("/splunk")
    sp_ev = [json.loads(l) for _, b in sp for l in b.splitlines() if l]
    check("splunk: every event, Authorization: Splunk <token from env>",
          len(sp_ev) == n and all(h.get("authorization") == "Splunk splunk-token" for h, _ in sp), f"{len(sp_ev)}")
    if sp_ev:
        check("splunk: time is seconds.millis of ts",
              abs(sp_ev[0]["time"] * 1000 - sp_ev[0]["event"]["ts"]) < 1)

    until(lambda: count("/es", lambda b: len(b.splitlines()) // 2) >= n, 10)
    es = mock_bodies("/es")
    es_lines = [json.loads(l) for _, b in es for l in b.splitlines() if l]
    check("elasticsearch: _bulk action + document pairs, basic auth",
          len(es_lines) == 2 * n and all("index" in a for a in es_lines[0::2])
          and all(h.get("authorization", "").startswith("Basic ") for h, _ in es), f"{len(es_lines)}")
    check("elasticsearch: @timestamp on every document", all("@timestamp" in d for d in es_lines[1::2]))
    check("elasticsearch: posted to /es/_bulk", all(p == "/es/_bulk" for p, _, _, _ in mock_reqs if p.startswith("/es")))

    until(lambda: count("/http", lambda b: len(b.splitlines())) >= n, 10)
    wh = mock_bodies("/http")
    wh_lines = [json.loads(l) for _, b in wh for l in b.splitlines() if l]
    check("http: NDJSON lines as they are, bearer token, no gzip",
          len(wh_lines) == n and all(h.get("authorization") == "Bearer tok" and "content-encoding" not in h
                                     for h, _ in wh), f"{len(wh_lines)}")

    with open(os.path.join(tmp, "stdout.log")) as f:
        so = [l for l in f if l.startswith('{"schema_version"')]
    check("stdout: same lines on stdout", len(so) == n, f"{len(so)}")
    with open(os.path.join(tmp, "access.jsonl")) as f:
        check("file: still written alongside sinks", len(f.readlines()) == n)

    print("\n── metrics")
    m = metrics()
    check("metrics: requests by code",
          metric(m, "qg_http_requests_total", code="200") == 40 and metric(m, "qg_http_requests_total", code="403") == 10,
          f"200={metric(m, 'qg_http_requests_total', code='200')}")
    check("metrics: blocks by rule", metric(m, "qg_blocks_total", type="fw", rule="blocked") == 10)
    check("metrics: duration histogram count", metric(m, "qg_http_request_duration_seconds_count") == n)
    check("metrics: upstream responses", metric(m, "qg_upstream_responses_total", upstream="o1", code="200") == 40)
    sinks = ["clickhouse", "loki", "otlp", "datadog", "splunk", "elasticsearch", "webhook"]
    sent = {s: metric(m, "qg_log_sink_lines_total", sink=s, result="sent") for s in sinks}
    check("metrics: every sink reports all lines sent", all(v == n for v in sent.values()), str(sent))
    check("metrics: 404 for other paths", _status(f"http://127.0.0.1:{METRICS_PORT}/other") == 404)

    def prom():
        try:
            q = urllib.parse.urlencode({"query": "sum(qg_http_requests_total)"})
            r = json.loads(http(f"http://127.0.0.1:{PROM_PORT}/api/v1/query?{q}")[1])
            return float(r["data"]["result"][0]["value"][1]) if r["data"]["result"] else 0
        except Exception:
            return 0
    check("prometheus: scrapes the endpoint", until(lambda: prom() == n, 20), f"{prom()}")

    print("\n── ClickHouse down: retry and spool")
    sh("docker stop qg-test-ch")
    ids2 = send([f"/ok/down/{i}" for i in range(30)])
    spool = os.path.join(tmp, "spool", "clickhouse")
    time.sleep(3)
    m = metrics()
    check("failed requests counted while down",
          metric(m, "qg_log_sink_requests_total", sink="clickhouse", result="failed") > 0)
    check("other sinks unaffected",
          metric(m, "qg_log_sink_lines_total", sink="loki", result="sent") == n + 30)
    sh("docker start qg-test-ch")
    wait_http(f"http://127.0.0.1:{CH_PORT}/ping")
    total = n + 30
    rows = until(lambda: (r := ch("SELECT count() FROM qg.access_log")) == str(total) and r, 45)
    check("all lines arrive once ClickHouse is back", rows == str(total),
          ch("SELECT count() FROM qg.access_log"))
    check("no duplicate rows",
          ch("SELECT count() - uniqExact(request_id) FROM qg.access_log") == "0")
    check("recovered batches include the outage", set(ids2) <= set(ch("SELECT toString(request_id) FROM qg.access_log").split()))

    print("\n── spool survives a restart")
    sh("docker stop qg-test-ch")
    ids3 = send([f"/ok/restart/{i}" for i in range(20)])
    time.sleep(1)
    stop_gateway(gw)
    spooled = [f for f in os.listdir(spool) if f.endswith(".jsonl")] if os.path.isdir(spool) else []
    lines = sum(int(f.rsplit("-", 1)[1].split(".")[0]) for f in spooled)
    check("unsent lines are in the spool after shutdown", lines >= 20, f"{lines} lines in {len(spooled)} files")
    sh("docker start qg-test-ch")
    wait_http(f"http://127.0.0.1:{CH_PORT}/ping")
    GW = start_gateway(tmp)
    total += 20
    rows = until(lambda: (r := ch("SELECT count() FROM qg.access_log")) == str(total) and r, 45)
    check("spooled lines sent by the next run", rows == str(total), ch("SELECT count() FROM qg.access_log"))
    check("spool emptied", until(lambda: not [f for f in os.listdir(spool) if f.endswith(".jsonl")], 10))
    check("still no duplicates", ch("SELECT count() - uniqExact(request_id) FROM qg.access_log") == "0")
    check("restart batch present", set(ids3) <= set(ch("SELECT toString(request_id) FROM qg.access_log").split()))

    print("\n── destination refuses (HTTP 400)")
    with mock_lock:
        mock_fail["/http"] = 400
        before = len([1 for p, _, _, _ in mock_reqs if p.startswith("/http")])
    send([f"/ok/refused/{i}" for i in range(5)])
    time.sleep(3)
    m = metrics()
    with mock_lock:
        tries = len([1 for p, _, _, _ in mock_reqs if p.startswith("/http")]) - before
    time.sleep(3)
    with mock_lock:
        later = len([1 for p, _, _, _ in mock_reqs if p.startswith("/http")]) - before - tries
        mock_fail.clear()
    check("refused batch dropped and counted", metric(m, "qg_log_sink_lines_total", sink="webhook", result="dropped") == 5,
          str(metric(m, "qg_log_sink_lines_total", sink="webhook", result="dropped")))
    check("refused batch not retried", tries >= 1 and later == 0, f"{tries} then {later} more")
    with open(os.path.join(tmp, "stdout.log")) as f:
        logtext = f.read()
    check("gateway log names the sink and status", "Log sink webhook" in logtext and "HTTP 400" in logtext)
    check("secrets never in the gateway log",
          not any(s in logtext for s in ["dd-key", "splunk-token", "Bearer tok", "pw\""]))


def _status(url):
    try:
        return http(url)[0]
    except urllib.error.HTTPError as e:
        return e.code


if __name__ == "__main__":
    main()

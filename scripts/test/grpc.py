#!/usr/bin/env python3
"""Live check of HTTP/2 and gRPC proxying.

Usage: BIN=path/to/quayel-gateway scripts/test/grpc.py

Needs Docker: runs moul/grpcbin as the gRPC origin (h2c), nginx in front of it
as an HTTP/2-over-TLS origin (grpcbin's own TLS port uses an X.509 v1 test
certificate that rustls rejects), and fullstorydev/grpcurl as the client.
Checks:
  - h2c on the HTTP port, while HTTP/1.1 (including short and keep-alive
    requests) keeps working and slow/silent connections are still cut off
  - unary, server-streaming and bidi calls to an h2c target and an h2 (TLS)
    target, with grpc-status trailers passed through
  - gateway errors (firewall block, unreachable origin) sent as gRPC statuses
  - access log lines for gRPC calls
"""
import os
import sys

# scripts/test/logging.py would shadow the stdlib module.
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != os.path.dirname(os.path.abspath(__file__))]

import json
import socket
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = os.environ.get("BIN", os.path.join(ROOT, "target/release/quayel-gateway"))
GRPCBIN = "qg-test-grpcbin"
NGINX = "qg-test-grpc-tls"
H2C_PORT, TLS_PORT = 18421, 18422
GW, GW_DOWN = 18420, 18423

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def sh(*args, timeout=30, input=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, "timeout"


def grpcurl(port, method, data=None, extra=()):
    args = ["docker", "run", "--rm", "-i", "--network", "host", "fullstorydev/grpcurl",
            "-plaintext", "-max-time", "30", *extra]
    if data is not None:
        args += ["-d", "@"]
    args += [f"127.0.0.1:{port}"]
    if method:
        args += [method]
    return sh(*args, input=data)


def wait_port(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def start_gateway(port, targets, log_path, server=None):
    cfg = {
        "gateway_id": "grpc-test", "gateway_name": "grpc-test", "server_name": "grpc-test",
        "config_version": "1",
        "listen": {"http": f"127.0.0.1:{port}"},
        "server": server or {},
        "plugins": {
            "firewall": {"enabled": True, "rules": [{
                "id": "block-empty", "name": "b", "enabled": True,
                "conditions": [{"left": "req.path", "operator": "equals",
                                "value": "/grpcbin.GRPCBin/Empty"}],
                "action": {"type": "block", "status": 403}}]},
            "load_balancer": {"enabled": True, "load_balancers": [
                {"id": f"lb-{i}", "name": f"lb-{i}", "conditions": conds,
                 "algorithm": {"type": "round_robin"},
                 "targets": [t], "health_check": {"mode": "off"}}
                for i, (conds, t) in enumerate(targets)]},
            "logging": {"enabled": True, "file": {"path": log_path, "flush_interval_ms": 100}},
        },
    }
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(cfg, f); f.close()
    p = subprocess.Popen([BINARY, "--config", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(port)
    return p


def raw(port, data, wait=2.0):
    """Send raw bytes, return (bytes received, seconds until the server closed)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=wait + 5)
    t0 = time.time()
    if data:
        s.sendall(data)
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
            if wait == 0:
                break
    except socket.timeout:
        pass
    s.close()
    return out, time.time() - t0


def main():
    sh("docker", "rm", "-f", GRPCBIN)
    sh("docker", "rm", "-f", NGINX)
    rc, out = sh("docker", "run", "-d", "--name", GRPCBIN, "-p", f"127.0.0.1:{H2C_PORT}:9000", "moul/grpcbin")
    if rc != 0:
        print(out); sys.exit(1)

    tmp = tempfile.mkdtemp()
    os.chmod(tmp, 0o755)
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=grpc.test",
       "-keyout", f"{tmp}/key.pem", "-out", f"{tmp}/cert.pem")
    with open(f"{tmp}/nginx.conf", "w") as f:
        f.write(f"""events {{}}
http {{ server {{
  listen 127.0.0.1:{TLS_PORT} ssl; http2 on;
  ssl_certificate /t/cert.pem; ssl_certificate_key /t/key.pem;
  location / {{ grpc_pass grpc://127.0.0.1:{H2C_PORT}; }}
}} }}
""")
    for n in ("key.pem", "cert.pem", "nginx.conf"):
        os.chmod(f"{tmp}/{n}", 0o644)
    rc, out = sh("docker", "run", "-d", "--name", NGINX, "--network", "host", "-v", f"{tmp}:/t:ro",
                 "nginx:alpine", "nginx", "-c", "/t/nginx.conf", "-g", "daemon off;")
    if rc != 0:
        print(out); sys.exit(1)
    wait_port(H2C_PORT); wait_port(TLS_PORT)
    time.sleep(1)

    log = os.path.join(tmp, "a.log")
    gws = []
    try:
        # hello.* and /grpcbin.GRPCBin/Index go to the TLS (h2) target,
        # everything else to h2c.
        gws.append(start_gateway(GW, [
            ([{"left": "req.path", "operator": "starts_with", "value": "/hello."}],
             {"id": "tls", "host": "127.0.0.1", "port": TLS_PORT, "protocol": "h2"}),
            ([], {"id": "h2c", "host": "127.0.0.1", "port": H2C_PORT, "protocol": "h2c"}),
        ], log, {"timeouts": {"header_secs": 2}}))

        print("── HTTP/2 and HTTP/1.1 on the same port ──")
        rc, out = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_version}",
                     "--http2-prior-knowledge", f"http://127.0.0.1:{GW}/x")
        check("h2c (prior knowledge) accepted", out.strip() == "2", out.strip())
        rc, out = sh("curl", "-s", "-o", "/dev/null", "-o", "/dev/null", "-w", "%{http_version} %{num_connects}\\n",
                     f"http://127.0.0.1:{GW}/grpcbin.GRPCBin/Empty", f"http://127.0.0.1:{GW}/grpcbin.GRPCBin/Empty")
        check("HTTP/1.1 keep-alive: two requests, one connection",
              out.split("\n")[:2] == ["1.1 1", "1.1 0"], out.strip().replace("\n", " | "))
        resp, secs = raw(GW, b"GET / HTTP/1.0\r\n\r\n", wait=3)
        check("18-byte HTTP/1.0 request answered without waiting",
              resp.startswith(b"HTTP/1.") and secs < 1.5, f"{secs:.2f}s")
        _, secs = raw(GW, b"", wait=6)
        check("silent connection closed by header_secs", 1.5 < secs < 4, f"{secs:.2f}s")
        _, secs = raw(GW, b"PRI * HT", wait=6)
        check("partial h2 preface closed by header_secs", 1.5 < secs < 4, f"{secs:.2f}s")

        print("── gRPC to an h2c target ──")
        rc, out = grpcurl(GW, "list")
        check("reflection: list services", rc == 0 and "grpcbin.GRPCBin" in out, out.strip()[:80])
        rc, out = grpcurl(GW, "grpcbin.GRPCBin/DummyUnary", '{"f_string":"hi","f_int32":7}')
        check("unary call", rc == 0 and '"fString": "hi"' in out, out.strip()[:80])
        rc, out = grpcurl(GW, "grpcbin.GRPCBin/DummyServerStream", '{"f_string":"s"}')
        n = out.count('"fString"')
        check("server streaming", rc == 0 and n == 10, f"{n} messages")
        msgs = "".join(json.dumps({"f_string": f"m{i}"}) for i in range(5))
        rc, out = grpcurl(GW, "grpcbin.GRPCBin/DummyBidirectionalStreamStream", msgs)
        n = out.count('"fString"')
        check("bidi streaming", rc == 0 and n == 5, f"{n} messages")
        rc, out = grpcurl(GW, "grpcbin.GRPCBin/SpecificError", '{"code":5,"reason":"no such thing"}')
        check("origin grpc-status trailer passed through", "NotFound" in out and "no such thing" in out,
              out.strip().replace("\n", " ")[:80])

        print("── gRPC to an h2 (TLS) target ──")
        rc, out = grpcurl(GW, "hello.HelloService/SayHello", '{"greeting":"quayel"}')
        check("unary over TLS upstream", rc == 0 and "hello quayel" in out, out.strip()[:80])
        rc, out = grpcurl(GW, "hello.HelloService/LotsOfReplies", '{"greeting":"q"}')
        n = out.count('"reply"')
        check("server streaming over TLS upstream", rc == 0 and n >= 2, f"{n} messages")

        print("── gateway errors as gRPC statuses ──")
        rc, out = grpcurl(GW, "grpcbin.GRPCBin/Empty", "{}")
        check("firewall block -> PermissionDenied", "PermissionDenied" in out, out.strip().replace("\n", " ")[:80])
        gws.append(start_gateway(GW_DOWN, [([], {"id": "dead", "host": "127.0.0.1", "port": 1, "protocol": "h2c"})],
                                 os.path.join(tmp, "b.log")))
        rc, out = grpcurl(GW_DOWN, "grpcbin.GRPCBin/DummyUnary", "{}")
        check("unreachable origin -> Unavailable", "Unavailable" in out, out.strip().replace("\n", " ")[:80])

        time.sleep(0.5)
        lines = [json.loads(l) for l in open(log)]
        calls = [l for l in lines if l["path"].startswith("/grpcbin.GRPCBin/DummyUnary")]
        check("gRPC call logged with status 200", calls and calls[-1]["status"] == 200,
              str(calls[-1]["status"]) if calls else "none")
        # grpcurl ends reflection streams with RST_STREAM(NO_ERROR) after the
        # server's response: a normal end, not "client closed".
        closed = [l["path"] for l in lines if l["status"] == 499]
        check("normally ended streams not logged as 499", not closed, ", ".join(closed[:2]))
        blocked = [l for l in lines if l["path"] == "/grpcbin.GRPCBin/Empty"]
        check("blocked call logged as 403 firewall block",
              blocked and blocked[-1]["status"] == 403 and blocked[-1]["block"]["type"] == "fw",
              json.dumps(blocked[-1]["block"]) if blocked else "none")
    finally:
        for g in gws:
            g.terminate()
            try:
                g.wait(5)
            except subprocess.TimeoutExpired:
                g.kill()
        sh("docker", "rm", "-f", GRPCBIN)
        sh("docker", "rm", "-f", NGINX)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


main()

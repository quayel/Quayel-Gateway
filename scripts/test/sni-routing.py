#!/usr/bin/env python3
"""Live check of SNI routing for streams (`sni`, `tls`, streams without `listen`).

Usage: BIN=path/to/quayel-gateway scripts/test/sni-routing.py

Needs `openssl` (for a backend certificate). Runs a gateway with Auto-SSL on
but no ACME server, so terminated TLS uses the gateway's fallback
certificate; clients don't verify certificates here, they compare them.

Checks, on the shared HTTPS port: passthrough (client sees the backend's
own certificate), terminate (client sees the gateway's), a wildcard name,
fallback to HTTPS for every other name and for no SNI, h2 still offered,
keep-alive, and the handshake deadline. On a separate port: several streams
by name plus a default for non-TLS clients, and 421 for an unknown name when
there is no default. Then the access-log lines and a hot reload that adds a
name.
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

HTTP, HTTPS, PORT_DEF, PORT_ONLY = 18540, 18541, 18542, 18543
ECHO_A, ECHO_B, TLS_C, HTTP_ORIGIN = 18551, 18552, 18553, 18554

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


# ── Origins ──────────────────────────────────────────────────────────────────

def echo(tag):
    async def handle(r, w):
        try:
            data = await r.read(65536)
            w.write(f"{tag}:".encode() + data)
            await w.drain()
        except Exception:
            pass
        w.close()
    return handle


async def http_origin(r, w):
    try:
        while True:
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin")
            await w.drain()
    except Exception:
        pass
    w.close()


# ── Client helpers ───────────────────────────────────────────────────────────

def client_ctx(alpn=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


async def tls_talk(port, sni, data=b"hello", alpn=None):
    """TLS connect with `sni` ('' = none). Returns (reply, peer cert DER, alpn)."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ctx(alpn), server_hostname=sni), 5)
        obj = w.get_extra_info("ssl_object")
        cert, proto = obj.getpeercert(True), obj.selected_alpn_protocol()
        w.write(data)
        await w.drain()
        out = await asyncio.wait_for(r.read(65536), 5)
        w.close()
        return out, cert, proto
    except Exception as e:
        return type(e).__name__.encode(), None, None


async def https_get(sni, requests=1):
    """HTTP/1.1 GETs over one TLS connection; returns the status lines."""
    r, w = await asyncio.open_connection("127.0.0.1", HTTPS, ssl=client_ctx(["http/1.1"]),
                                         server_hostname=sni)
    statuses = []
    for _ in range(requests):
        w.write(f"GET / HTTP/1.1\r\nHost: {sni or 'x'}\r\n\r\n".encode())
        await w.drain()
        head = (await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)).decode()
        n = int([l for l in head.split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
        await r.readexactly(n)
        statuses.append(head.split("\r\n")[0])
    w.close()
    return statuses


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


def tgt(port):
    return [{"id": f"t{port}", "host": "127.0.0.1", "port": port}]


def config(tmp, log, extra_names=()):
    streams = [
        {"id": "pass", "sni": ["db1.sni.test"], "targets": tgt(TLS_C)},
        {"id": "term", "sni": ["db2.sni.test", *extra_names], "tls": "terminate", "targets": tgt(ECHO_A)},
        {"id": "wild", "sni": ["*.wild.sni.test"], "targets": tgt(TLS_C)},
        {"id": "p-a", "listen": f"127.0.0.1:{PORT_DEF}", "sni": ["a.sni.test"], "tls": "terminate",
         "targets": tgt(ECHO_A)},
        {"id": "p-def", "listen": f"127.0.0.1:{PORT_DEF}", "targets": tgt(ECHO_B)},
        {"id": "p-only", "listen": f"127.0.0.1:{PORT_ONLY}", "sni": ["x.sni.test"], "targets": tgt(TLS_C)},
    ]
    return {
        "gateway_id": "sni-test", "gateway_name": "sni-test", "server_name": "sni-test",
        "config_version": str(time.time()),
        "listen": {"http": f"127.0.0.1:{HTTP}", "https": f"127.0.0.1:{HTTPS}"},
        "server": {"timeouts": {"header_secs": 2}},
        "streams": streams,
        "plugins": {
            "auto_ssl": {"enabled": True, "email": "t@example.com", "domains": [],
                         "cert_storage_path": os.path.join(tmp, "certs"),
                         "directory_url": "https://127.0.0.1:1/dir"},
            "load_balancer": {"enabled": True, "load_balancers": [{
                "id": "lb", "name": "lb", "conditions": [], "algorithm": {"type": "round_robin"},
                "targets": [{"id": "web", "host": "127.0.0.1", "port": HTTP_ORIGIN}],
                "health_check": {"mode": "off"}}]},
            "logging": {"enabled": True, "file": {"path": log, "flush_interval_ms": 100}},
        },
    }


async def main():
    tmp = tempfile.mkdtemp()
    key, crt = os.path.join(tmp, "c.key"), os.path.join(tmp, "c.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=backend-c",
                    "-keyout", key, "-out", crt, "-days", "1"], capture_output=True, check=True)
    backend_der = ssl.PEM_cert_to_DER_cert(open(crt).read())
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(crt, key)
    servers = [
        await asyncio.start_server(echo("A"), "127.0.0.1", ECHO_A),
        await asyncio.start_server(echo("B"), "127.0.0.1", ECHO_B),
        await asyncio.start_server(echo("C"), "127.0.0.1", TLS_C, ssl=sctx),
        await asyncio.start_server(http_origin, "127.0.0.1", HTTP_ORIGIN),
    ]
    log = os.path.join(tmp, "access.log")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(config(tmp, log), f)
    gw = subprocess.Popen([BINARY, cfg_path], stdout=subprocess.DEVNULL,
                          stderr=open(os.path.join(tmp, "gw.err"), "w"))
    try:
        ready = all([await wait_port(p) for p in (HTTP, HTTPS, PORT_DEF, PORT_ONLY)])
        check("gateway starts (HTTPS port + two SNI ports)", ready)
        await asyncio.sleep(0.3)

        print("── shared HTTPS port ──")
        out, cert, _ = await tls_talk(HTTPS, "db1.sni.test")
        check("passthrough: reaches the TLS backend", out == b"C:hello", repr(out))
        check("passthrough: client sees the backend's own certificate", cert == backend_der)
        out, cert, _ = await tls_talk(HTTPS, "DB2.sni.test")
        check("terminate: plain backend gets the bytes (name matched case-insensitively)",
              out == b"A:hello", repr(out))
        check("terminate: client sees the gateway's certificate", cert is not None and cert != backend_der)
        out, cert, _ = await tls_talk(HTTPS, "node7.wild.sni.test")
        check("wildcard *.wild.sni.test matches one label", out == b"C:hello", repr(out))
        st = await https_get("deep.node7.wild.sni.test")
        check("two labels under the wildcard → HTTPS instead", st == ["HTTP/1.1 200 OK"], str(st))
        st = await https_get("www.site.test", requests=3)
        check("other names → HTTPS, keep-alive works", st == ["HTTP/1.1 200 OK"] * 3, str(st))
        try:
            st = str(await https_get(""))
        except ssl.SSLError as e:
            st = str(e)
        # Same as before streams existed: Auto-SSL has no certificate to pick
        # without a name, so the HTTPS handshake is refused.
        check("no SNI → HTTPS path (refused as in 0.5.0)", "ACCESS_DENIED" in st, st[:60])
        _, _, proto = await tls_talk(HTTPS, "www.site.test", alpn=["h2", "http/1.1"])
        check("h2 still negotiated on the HTTPS port", proto == "h2", str(proto))
        r, w = await asyncio.open_connection("127.0.0.1", HTTP)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        line = (await asyncio.wait_for(r.readline(), 5)).decode().strip()
        w.close()
        check("plain HTTP port unchanged", line == "HTTP/1.1 200 OK", line)

        r, w = await asyncio.open_connection("127.0.0.1", HTTPS)
        t0 = time.time()
        got = await asyncio.wait_for(r.read(10), 6)
        check("silent client on the HTTPS port closed by header_secs",
              got == b"" and 1.5 < time.time() - t0 < 4, f"{time.time() - t0:.1f} s")
        w.close()

        print("── own port with SNI routes ──")
        out, _, _ = await tls_talk(PORT_DEF, "a.sni.test")
        check("name on own port → terminate stream", out == b"A:hello", repr(out))
        r, w = await asyncio.open_connection("127.0.0.1", PORT_DEF)
        w.write(b"plain hello"); await w.drain()
        out = await asyncio.wait_for(r.read(100), 5)
        w.close()
        check("non-TLS client → the port's default stream", out == b"B:plain hello", repr(out))
        out, _, _ = await tls_talk(PORT_ONLY, "x.sni.test")
        check("passthrough on own port", out == b"C:hello", repr(out))
        out, _, _ = await tls_talk(PORT_ONLY, "nope.sni.test")
        check("unknown name, no default → closed", out != b"C:hello", repr(out))

        print("── hot reload ──")
        with open(cfg_path, "w") as f:
            json.dump(config(tmp, log, extra_names=["db3.sni.test"]), f)
        out = b""
        for _ in range(30):
            out, _, _ = await tls_talk(HTTPS, "db3.sni.test")
            if out == b"A:hello":
                break
            await asyncio.sleep(0.5)
        check("new sni name works after reload, no restart", out == b"A:hello", repr(out))

        print("── access log ──")
        await asyncio.sleep(0.5)
        lines = [json.loads(l) for l in open(log) if l.strip()]
        tcp = [l for l in lines if l["method"] == "TCP"]
        p = [l for l in tcp if l["path"] == "pass"]
        check("stream line: scheme tls, host = server name",
              p and p[0]["scheme"] == "tls" and p[0]["host"] == "db1.sni.test" and p[0]["status"] == 200,
              json.dumps({k: p[0][k] for k in ("scheme", "host", "status")}) if p else "none")
        t = [l for l in tcp if l["path"] == "term"]
        check("terminate line counts decrypted bytes", t and t[0]["req_bytes"] == 5 and t[0]["bytes"] == 7,
              f"{t[0]['req_bytes']}/{t[0]['bytes']}" if t else "none")
        u = [l for l in tcp if l["status"] == 421]
        check("unknown name logged as 421 with the name",
              u and u[0]["host"] == "nope.sni.test" and u[0]["error"] != "", json.dumps(u[:1]))
        web = [l for l in lines if l["method"] == "GET"]
        check("HTTPS requests still logged as HTTP", len(web) >= 4, str(len(web)))

        gw.terminate()
        gw.wait(10)
        check("no panics", "panicked" not in open(os.path.join(tmp, "gw.err")).read())
    finally:
        if gw.poll() is None:
            gw.kill()
        for s in servers:
            s.close()

    passed = sum(results)
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) else 1)


asyncio.run(main())

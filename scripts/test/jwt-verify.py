#!/usr/bin/env python3
"""End-to-end test: JWT verification in condition fields.

Starts an origin, a JWKS server and two gateways, then checks:
  - with `jwt` keys: valid tokens pass, missing / forged / expired / wrong-alg
    tokens are blocked by firewall rules on `jwt_valid` and `jwt_error`
  - claims (`jwt.data.role`, `jwt.sub`) only resolve for verified tokens, so a
    forged "admin" claim can't pass and rate limits count real users only
  - keys from an inline public key and from a JWKS URL; a rotated JWKS key
    (new kid) is picked up without a restart
  - without `jwt` keys: claims are decoded unchecked (old behaviour),
    `jwt_valid` is false and a startup warning is logged
  - a hot reload that adds keys switches verification on
  - bad key configs (private key, missing env var) are refused at startup

Usage:  python3 scripts/test/jwt-verify.py
Env:    BIN=./target/debug/quayel-gateway (default)
Needs:  python3 with PyJWT and cryptography
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

import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

GW_PORT, ORIGIN_PORT, JWKS_PORT, GW2_PORT = 18290, 18291, 18292, 18293
BIN = os.environ.get("BIN", "./target/debug/quayel-gateway")
FIX = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "fixtures", "jwt")


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


RSA_PRIV, RSA_PUB = fixture("rsa_private.pem"), fixture("rsa_public.pem")
RSA2_PRIV, RSA2_PUB = fixture("rsa2_private.pem"), fixture("rsa2_public.pem")


def jwk(pub_pem, kid):
    k = json.loads(RSAAlgorithm.to_jwk(RSAAlgorithm(RSAAlgorithm.SHA256).prepare_key(pub_pem)))
    k.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return k


jwks_state = {"keys": [jwk(RSA_PUB, "rot-1")], "fetches": 0}


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"origin ok"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Jwks(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        jwks_state["fetches"] += 1
        body = json.dumps({"keys": jwks_state["keys"]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def fw_rule(rid, conditions, status):
    return {"id": rid, "name": rid, "enabled": True, "conditions": conditions,
            "action": {"type": "block", "status": status}}


def cond(left, op, value=None, nxt=None):
    c = {"left": left, "operator": op}
    if value is not None:
        c["value"] = value
    if nxt:
        c["next"] = nxt
    return c


AUTH = "header.authorization"
PLUGINS = {
    "firewall": {"enabled": True, "rules": [
        fw_rule("jwt-expired", [cond("req.path", "starts_with", "/api", "and"),
                                cond(f"{AUTH}.jwt_error", "equals", "expired")], 401),
        fw_rule("jwt-invalid", [cond("req.path", "starts_with", "/api", "and"),
                                cond(f"{AUTH}.jwt_valid", "not_equals", True)], 401),
        fw_rule("admin-only", [cond("req.path", "starts_with", "/admin", "and"),
                               cond(f"{AUTH}.jwt.data.role", "not_equals", "admin")], 403),
    ]},
    "rate_limiting": {"enabled": True, "rules": [{
        "id": "rl-user", "name": "per user", "enabled": True,
        "conditions": [cond("req.path", "starts_with", "/api/rl")],
        "key": [f"{AUTH}.jwt.sub"], "limit": 3, "window_seconds": 60,
        "action": {"type": "block", "status": 429},
    }]},
    "load_balancer": {"enabled": True, "load_balancers": [{
        "id": "lb", "name": "lb", "enabled": True, "conditions": [],
        "algorithm": {"type": "round_robin"},
        "targets": [{"id": "o", "host": "127.0.0.1", "port": ORIGIN_PORT, "protocol": "http", "weight": 1, "enabled": True}],
    }]},
}

JWT_SECTION = {"keys": [
    {"id": "inline", "algorithms": ["RS256"], "public_key": RSA_PUB, "issuer": "https://auth.test", "audience": "api"},
    {"id": "idp", "algorithms": ["RS256"], "jwks_url": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
     "issuer": "https://other-idp", "audience": "x"},
]}


def config(port, with_jwt):
    c = {"gateway_id": "gw-jwt", "gateway_name": "jwt", "server_name": "jwt", "config_version": "1",
         "listen": {"http": f"127.0.0.1:{port}"}, "client_ip": {"source": "peer_ip"}, "plugins": PLUGINS}
    if with_jwt:
        c["jwt"] = JWT_SECTION
    return c


PASS, FAIL = [], []


def check(name, cond_, detail=""):
    """Print each result as it runs, in the same format as all-rules.sh."""
    (PASS if cond_ else FAIL).append(name)
    tag = "\033[0;32mPASS\033[0m" if cond_ else "\033[0;31mFAIL\033[0m"
    detail = str(detail)
    if cond_ and len(detail) > 60:
        detail = detail[:57] + "..."
    print(f"  {tag}  {name:<46} {detail}", flush=True)


def section(title):
    print(f"\n── {title} " + "─" * max(0, 64 - len(title)))


def req(port, path, token=None, raw_auth=None):
    headers = {}
    if token:
        headers["authorization"] = f"Bearer {token}"
    if raw_auth:
        headers["authorization"] = raw_auth
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def token(priv=RSA_PRIV, alg="RS256", kid=None, **claims):
    base = {"sub": "u1", "exp": int(time.time()) + 600, "iss": "https://auth.test", "aud": "api",
            "data": {"role": "user"}}
    base.update(claims)
    headers = {"kid": kid} if kid else None
    return pyjwt.encode(base, priv, algorithm=alg, headers=headers)


def wait_ready(port):
    for _ in range(80):
        s, _ = req(port, "/__ready")
        if s:
            return True
        time.sleep(0.1)
    return False


def start(cfg_path, port, log):
    p = subprocess.Popen([BIN, cfg_path], stdout=open(log, "w"), stderr=subprocess.STDOUT)
    if not wait_ready(port):
        p.terminate()
        sys.exit(f"gateway on {port} did not start; see {log}")
    return p


def write_cfg(path, c):
    with open(path, "w") as f:
        json.dump(c, f)


def main():
    for port, handler in ((ORIGIN_PORT, Origin), (JWKS_PORT, Jwks)):
        srv = QuietServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp(prefix="qg-jwt-")
    cfg1, cfg2 = os.path.join(tmp, "keys.json"), os.path.join(tmp, "nokeys.json")
    write_cfg(cfg1, config(GW_PORT, True))
    write_cfg(cfg2, config(GW2_PORT, False))
    gw1 = start(cfg1, GW_PORT, "/tmp/quayel-jwt-gw1.log")
    gw2 = start(cfg2, GW2_PORT, "/tmp/quayel-jwt-gw2.log")
    try:
        run(cfg2)
    finally:
        gw1.terminate()
        gw2.terminate()
    rejected_configs(tmp)

    print("────────────────────────────────────────────────────────────────────")
    print(f"  TOTAL: {len(PASS) + len(FAIL)}   PASS: \033[0;32m{len(PASS)}\033[0m   FAIL: \033[0;31m{len(FAIL)}\033[0m")
    for name in FAIL:
        print(f"  \033[0;31mFAILED\033[0m  {name}")
    sys.exit(1 if FAIL else 0)


def run(cfg2):
    G, G2 = GW_PORT, GW2_PORT

    section("With keys: who gets through")
    s, b = req(G, "/api/x", token())
    check("valid RS256 token (inline public key)", s == 200, s)
    s, b = req(G, "/api/x", raw_auth=f"bearer {token()}")
    check("lowercase 'bearer' prefix accepted", s == 200, s)
    s, b = req(G, "/api/x")
    check("no token → 401 jwt-invalid", s == 401 and "jwt-invalid" in b, f"{s} {b}")
    s, b = req(G, "/api/x", token(priv=RSA2_PRIV))
    check("token signed by another key → 401", s == 401 and "jwt-invalid" in b, f"{s} {b}")
    s, b = req(G, "/api/x", token(exp=int(time.time()) - 3600))
    check("expired token → 401 jwt-expired rule", s == 401 and "jwt-expired" in b, f"{s} {b}")
    s, b = req(G, "/api/x", token(iss="https://evil.test"))
    check("wrong issuer → 401", s == 401, s)
    s, b = req(G, "/api/x", token(aud="other"))
    check("wrong audience → 401", s == 401, s)
    s, b = req(G, "/api/x", forged_hs256())
    check("HS256 signed with the public key → 401", s == 401, s)
    s, b = req(G, "/api/x", unsigned())
    check("alg none → 401", s == 401, s)
    s, b = req(G, "/api/x", "garbage.token")
    check("malformed token → 401", s == 401, s)

    section("With keys: claims only from verified tokens")
    s, b = req(G, "/admin/panel", token(data={"role": "admin"}))
    check("verified admin claim → /admin allowed", s == 200, s)
    s, b = req(G, "/admin/panel", token(data={"role": "user"}))
    check("verified user claim → /admin 403", s == 403 and "admin-only" in b, f"{s} {b}")
    s, b = req(G, "/admin/panel", token(priv=RSA2_PRIV, data={"role": "admin"}))
    check("forged admin claim → /admin 403", s == 403, s)
    codes = [req(G, "/api/rl", token(sub="rl-user"))[0] for _ in range(4)]
    check("rate limit by verified sub: 4th → 429", codes == [200, 200, 200, 429], codes)
    codes = [req(G, "/api/rl", token(sub="rl-other"))[0] for _ in range(1)]
    check("another verified sub has its own limit", codes == [200], codes)

    section("With keys: JWKS URL")
    s, b = req(G, "/api/x", token(kid="rot-1", iss="https://other-idp", aud="x"))
    check("token for JWKS key rot-1 → 200", s == 200, s)
    fetches = jwks_state["fetches"]
    jwks_state["keys"] = [jwk(RSA_PUB, "rot-1"), jwk(RSA2_PUB, "rot-2")]
    rotated = token(priv=RSA2_PRIV, kid="rot-2", iss="https://other-idp", aud="x")
    s, b = req(G, "/api/x", rotated)
    check("new kid before refetch → 401", s == 401, s)
    ok = False
    for _ in range(30):
        time.sleep(0.1)
        if req(G, "/api/x", rotated)[0] == 200:
            ok = True
            break
    check("unknown kid triggers refetch, then 200", ok and jwks_state["fetches"] > fetches,
          f"fetches {fetches}→{jwks_state['fetches']}")
    s, b = req(G, "/api/x", token(priv=RSA2_PRIV, kid="rot-9", iss="https://other-idp", aud="x"))
    n = jwks_state["fetches"]
    for _ in range(5):
        req(G, "/api/x", token(priv=RSA2_PRIV, kid="rot-9", iss="https://other-idp", aud="x"))
    time.sleep(0.3)
    check("junk kids can't flood the IdP (≤1 refetch / 30s)", jwks_state["fetches"] == n, f"{n}→{jwks_state['fetches']}")

    section("Without keys: decode only (old behaviour)")
    s, b = req(G2, "/admin/panel", attacker_token())
    check("unchecked admin claim → /admin allowed", s == 200, s)
    s, b = req(G2, "/api/x", token())
    check("jwt_valid is false without keys", s == 401 and "jwt-invalid" in b, f"{s} {b}")
    with open("/tmp/quayel-jwt-gw2.log") as f:
        log = f.read()
    check("startup warns that claims aren't verified", "WITHOUT checking" in log)

    section("Hot reload adds keys")
    write_cfg(cfg2, config(GW2_PORT, True))
    ok = False
    for _ in range(100):
        time.sleep(0.1)
        if req(G2, "/admin/panel", attacker_token())[0] == 403:
            ok = True
            break
    check("after reload, forged admin claim → 403", ok)
    s, b = req(G2, "/api/x", token())
    check("after reload, valid token → 200", s == 200, s)


def attacker_token():
    """Signed with a secret the gateway doesn't know, claiming admin."""
    return pyjwt.encode({"sub": "x", "exp": int(time.time()) + 600, "data": {"role": "admin"}},
                        "attacker-secret-attacker-secret!", algorithm="HS256")


def forged_hs256():
    """HS256 token using the RSA public key bytes as the HMAC secret."""
    import base64
    import hashlib
    import hmac
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    msg = f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'sub': 'u1', 'exp': int(time.time()) + 60, 'iss': 'https://auth.test', 'aud': 'api'})}"
    sig = base64.urlsafe_b64encode(hmac.new(RSA_PUB.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{msg}.{sig}"


def unsigned():
    import base64
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc({'sub': 'u1', 'exp': int(time.time()) + 60})}."


def rejected_configs(tmp):
    section("Bad key configs are refused at startup")
    cases = [
        ("private key pasted", {"keys": [{"id": "k", "algorithms": ["RS256"], "public_key": RSA_PRIV}]}, "PRIVATE key"),
        ("secret_env not set", {"keys": [{"id": "k", "algorithms": ["HS256"], "secret_env": "QG_JWT_TEST_UNSET"}]}, "not set"),
        ("two key sources", {"keys": [{"id": "k", "algorithms": ["HS256"], "secret": "a", "secret_env": "B"}]}, "exactly one"),
    ]
    for name, section_, want in cases:
        c = config(GW_PORT, False)
        c["jwt"] = section_
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

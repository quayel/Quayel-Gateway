#!/usr/bin/env python3
"""End-to-end test: Auto-SSL against Pebble, Let's Encrypt's ACME test server.

Starts Pebble and pebble-challtestsrv in Docker (every name resolves to
127.0.0.1), then a gateway with `auto_ssl.directory_url` pointing at Pebble,
and checks:
  - an HTTPS request for an allowed domain triggers provisioning; the gateway
    answers the HTTP-01 challenge and then serves a certificate that verifies
    against Pebble's root CA for that hostname
  - the account is registered once and reused for a second domain
  - the account file and private keys are written owner-only (0600)
  - a domain not in `domains` never gets a certificate
  - a domain the CA refuses fails cleanly; the fallback cert is still served
  - after a restart: certs are served from disk at once (Pebble issues 6-day
    certs, which used to count as expired), aren't re-issued, and the stored
    account is loaded instead of registering a new one

Usage:  python3 scripts/test/auto-ssl.py
Env:    BIN=./target/debug/quayel-gateway (default)
        KEEP_TMP=1 keeps the temp dir (certs, account, config) for inspection
Needs:  docker, python3 with cryptography. Ports 5002 (Pebble validates
        HTTP-01 there), 8053, 8055, 14000, 15000 and 18443 must be free.
"""
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

from cryptography import x509

BIN = os.environ.get("BIN", "./target/debug/quayel-gateway")
HTTP_PORT, HTTPS_PORT = 5002, 18443
PEBBLE_DIR = "https://localhost:14000/dir"
PEBBLE_IMG = "ghcr.io/letsencrypt/pebble:latest"
CHALL_IMG = "ghcr.io/letsencrypt/pebble-challtestsrv:latest"
BLOCKED = "blocked-domain.example"  # in Pebble's default domainBlocklist

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


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)


# ── Pebble ───────────────────────────────────────────────────────────────────

def start_pebble(tmp):
    sh("docker", "rm", "-f", "qg-pebble", "qg-challtestsrv")
    r = sh("docker", "run", "-d", "--name", "qg-challtestsrv", "--network", "host", CHALL_IMG,
           "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "",
           "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
    if r.returncode:
        sys.exit(f"could not start challtestsrv: {r.stderr}")
    r = sh("docker", "run", "-d", "--name", "qg-pebble", "--network", "host",
           "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0", PEBBLE_IMG,
           "-config", "/test/config/pebble-config.json", "-dnsserver", "127.0.0.1:8053")
    if r.returncode:
        sys.exit(f"could not start pebble: {r.stderr}")
    # CA for Pebble's own HTTPS API (the gateway's `ca_root`).
    api_ca = os.path.join(tmp, "pebble.minica.pem")
    sh("docker", "cp", "qg-pebble:/test/certs/pebble.minica.pem", api_ca)
    api_ctx = ssl.create_default_context(cafile=api_ca)
    api_ctx.check_hostname = False
    for _ in range(50):
        try:
            urllib.request.urlopen(PEBBLE_DIR, context=api_ctx, timeout=2).read()
            break
        except Exception:
            time.sleep(0.2)
    else:
        sys.exit("pebble did not start")
    # Root that signs issued certificates (new on every Pebble start).
    issuing_root = os.path.join(tmp, "pebble-root.pem")
    with open(issuing_root, "wb") as f:
        f.write(urllib.request.urlopen("https://localhost:15000/roots/0", context=api_ctx).read())
    return api_ca, issuing_root


def stop_pebble():
    sh("docker", "rm", "-f", "qg-pebble", "qg-challtestsrv")


def pebble_new_accounts():
    logs = sh("docker", "logs", "qg-pebble")
    return (logs.stdout + logs.stderr).count("POST /sign-me-up")


# ── Gateway ──────────────────────────────────────────────────────────────────

def config(storage, api_ca, domains):
    return {
        "gateway_id": "gw-ssl", "gateway_name": "ssl", "server_name": "ssl", "config_version": "1",
        "listen": {"http": f"127.0.0.1:{HTTP_PORT}", "https": f"127.0.0.1:{HTTPS_PORT}"},
        "client_ip": {"source": "peer_ip"},
        "plugins": {
            "auto_ssl": {
                "enabled": True, "email": "ops@example.org", "domains": domains,
                "cert_storage_path": storage,
                "directory_url": PEBBLE_DIR, "ca_root": api_ca,
            },
        },
    }


def start_gateway(cfg_path, log):
    p = subprocess.Popen([BIN, cfg_path], stdout=open(log, "w"), stderr=subprocess.STDOUT)
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=0.5).close()
            return p
        except OSError:
            time.sleep(0.1)
    p.terminate()
    sys.exit(f"gateway did not start; see {log}")


def peer_cert(host):
    """Handshake with SNI=host without verifying; return the leaf certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                return x509.load_der_x509_certificate(t.getpeercert(binary_form=True))
    except Exception:
        return None


def issuer_cn(cert):
    if cert is None:
        return "no handshake"
    attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.issuer.rfc4514_string()


def is_pebble(cert):
    return cert is not None and issuer_cn(cert).startswith("Pebble")


def wait_for_pebble_cert(host, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        c = peer_cert(host)
        if is_pebble(c):
            return c
        time.sleep(0.5)
    return peer_cert(host)


def verified_https(host, root):
    """Full HTTPS handshake that must verify the chain and hostname against Pebble's root."""
    ctx = ssl.create_default_context(cafile=root)
    try:
        with socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True, "chain + hostname verified"
    except Exception as e:
        return False, str(e)


def mode(path):
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def log_text(path):
    with open(path) as f:
        return f.read()


# ── Test ─────────────────────────────────────────────────────────────────────

def main():
    if shutil.which("docker") is None:
        sys.exit("docker is required")
    tmp = tempfile.mkdtemp(prefix="qg-ssl-")
    storage = os.path.join(tmp, "certs")
    api_ca, root = start_pebble(tmp)
    cfg = os.path.join(tmp, "config.json")
    log1, log2 = "/tmp/quayel-ssl-gw1.log", "/tmp/quayel-ssl-gw2.log"
    gw = None
    try:
        domains = ["a.quayel.test", "b.quayel.test", BLOCKED]
        with open(cfg, "w") as f:
            json.dump(config(storage, api_ca, domains), f)
        gw = start_gateway(cfg, log1)

        section("First certificate")
        first = peer_cert("a.quayel.test")
        check("before issuance: fallback cert served", first is not None and not is_pebble(first),
              issuer_cn(first))
        c = wait_for_pebble_cert("a.quayel.test")
        check("certificate issued by the ACME CA", is_pebble(c), issuer_cn(c))
        sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.DNSName) if c else []
        check("certificate names only the domain", sans == ["a.quayel.test"], sans)
        ok, detail = verified_https("a.quayel.test", root)
        check("HTTPS verifies against the CA root", ok, detail)

        section("Account reuse")
        c = wait_for_pebble_cert("b.quayel.test")
        check("second domain issued", is_pebble(c), issuer_cn(c))
        ok, detail = verified_https("b.quayel.test", root)
        check("second domain verifies", ok, detail)
        accounts = [f for f in os.listdir(storage) if f.startswith("acme-account-")]
        check("one account file on disk", len(accounts) == 1, accounts)
        check("one account registered with the CA", pebble_new_accounts() == 1,
              f"{pebble_new_accounts()} newAccount calls")

        section("Files on disk")
        acct = os.path.join(storage, accounts[0]) if accounts else ""
        check("account file is 0600", mode(acct) == 0o600, oct(mode(acct) or 0))
        key = os.path.join(storage, "a.quayel.test", "key.pem")
        check("private key is 0600", mode(key) == 0o600, oct(mode(key) or 0))
        with open(os.path.join(storage, "a.quayel.test", "cert.pem")) as f:
            chain = f.read().count("BEGIN CERTIFICATE")
        check("cert.pem holds the full chain", chain >= 2, f"{chain} certificates")

        section("Domains that must not get a certificate")
        c = peer_cert("not-listed.quayel.test")
        time.sleep(3)
        c = peer_cert("not-listed.quayel.test")
        check("unlisted domain: fallback only", c is not None and not is_pebble(c), issuer_cn(c))
        check("unlisted domain: nothing stored",
              not os.path.exists(os.path.join(storage, "not-listed.quayel.test")))
        peer_cert(BLOCKED)
        deadline = time.time() + 30
        while time.time() < deadline and "ACME provisioning failed" not in log_text(log1):
            time.sleep(0.5)
        check("CA refusal is logged as a failure", "ACME provisioning failed" in log_text(log1))
        c = peer_cert(BLOCKED)
        check("refused domain still gets the fallback", c is not None and not is_pebble(c),
              issuer_cn(c))
        check("refused domain: nothing stored", not os.path.exists(os.path.join(storage, BLOCKED)))

        section("Restart")
        gw.terminate()
        gw.wait(timeout=10)
        with open(cfg, "w") as f:
            json.dump(config(storage, api_ca, domains + ["c.quayel.test"]), f)
        gw = start_gateway(cfg, log2)
        c = peer_cert("a.quayel.test")
        check("stored cert served straight away", is_pebble(c), issuer_cn(c))
        ok, detail = verified_https("a.quayel.test", root)
        check("stored cert still verifies", ok, detail)
        c = wait_for_pebble_cert("c.quayel.test")
        check("new domain issued after restart", is_pebble(c), issuer_cn(c))
        text = log_text(log2)
        check("stored account loaded", "Loaded ACME account" in text)
        check("valid stored certs not re-issued at startup", "triggering renewal" not in text)
        check("no new account registered", "ACME account registered" not in text
              and pebble_new_accounts() == 1, f"{pebble_new_accounts()} newAccount calls")
    finally:
        if gw:
            gw.terminate()
        stop_pebble()
        if os.environ.get("KEEP_TMP"):
            print(f"  kept {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    print("────────────────────────────────────────────────────────────────────")
    print(f"  TOTAL: {len(PASS) + len(FAIL)}   PASS: \033[0;32m{len(PASS)}\033[0m   FAIL: \033[0;31m{len(FAIL)}\033[0m")
    for name in FAIL:
        print(f"  \033[0;31mFAILED\033[0m  {name}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()

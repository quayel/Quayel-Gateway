#!/usr/bin/env python3
"""Build the four JWT bench configs and tokens from a base config.

Usage: make_configs.py [base_config.json] [out_dir]   (defaults: config.json, /tmp/qg-jwt-bench)

none   : no JWT rule (control)
decode : firewall rule reads a claim, no jwt section (decode only, unverified)
hs256  : jwt section with an HS256 secret, rule requires jwt_valid
rs256  : jwt section with an RS256 public key, rule requires jwt_valid
"""
import copy, json, os, sys, time
import jwt as pyjwt

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
FIX = os.path.join(REPO, "tests/fixtures/jwt")
BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "config.json")
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/qg-jwt-bench"
os.makedirs(OUT, exist_ok=True)
base = json.load(open(BASE))
if "auto_ssl" in base["plugins"]:
    base["plugins"]["auto_ssl"]["enabled"] = False  # never touch a real ACME CA from the bench
base["listen"].pop("https", None)

SECRET = "bench-secret-0123456789abcdef0123456789abcdef"
RSA_PRIV = open(f"{FIX}/rsa_private.pem").read()
RSA_PUB = open(f"{FIX}/rsa_public.pem").read()
claims = {"sub": "bench-user", "iss": "https://bench.local", "aud": "api",
          "exp": int(time.time()) + 30 * 86400, "data": {"role": "user"}}
tokens = {
    "hs256": pyjwt.encode(claims, SECRET, algorithm="HS256"),
    "rs256": pyjwt.encode(claims, RSA_PRIV, algorithm="RS256"),
}
tokens["none"] = tokens["rs256"]
tokens["decode"] = tokens["rs256"]

claim_rule = {
    "id": "deny-banned-role", "name": "Deny banned role", "enabled": True,
    "conditions": [{"left": "header.authorization.jwt.data.role", "operator": "equals", "value": "banned"}],
    "action": {"type": "block", "status": 403},
}
valid_rule = {
    "id": "require-jwt", "name": "Require valid JWT", "enabled": True,
    "conditions": [{"left": "header.authorization.jwt_valid", "operator": "not_equals", "value": True}],
    "action": {"type": "block", "status": 401},
}

ports = {"none": 8089, "decode": 8093, "hs256": 8094, "rs256": 8095}
for name, port in ports.items():
    c = copy.deepcopy(base)
    c["listen"]["http"] = f"0.0.0.0:{port}"
    rules = c["plugins"]["firewall"]["rules"]
    if name == "decode":
        rules.append(claim_rule)
    elif name in ("hs256", "rs256"):
        rules += [valid_rule, claim_rule]
        key = {"id": name, "algorithms": [name.upper()], "issuer": "https://bench.local", "audience": "api"}
        if name == "hs256":
            key["secret"] = SECRET
        else:
            key["public_key"] = RSA_PUB
        c["jwt"] = {"keys": [key]}
    json.dump(c, open(f"{OUT}/jwt-{name}.json", "w"), indent=2)
    open(f"{OUT}/jwt-{name}.token", "w").write(tokens[name])
print("ok", ports)

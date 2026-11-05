#!/usr/bin/env python3
"""Static checks on the Docker image's runtime stage.

These read the Dockerfile and the demo config; they do not build the image.
Run `docker build` and `docker run` to check that the gateway actually binds
80/443 as the non-root user. Comment lines are ignored so a commented-out
instruction cannot satisfy a check.
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")

with open(os.path.join(ROOT, "Dockerfile")) as f:
    dockerfile = f.read()

runtime = dockerfile.split("########## runtime ##########")[-1]
runtime = "\n".join(
    line for line in runtime.splitlines() if not line.lstrip().startswith("#")
)
users = re.findall(r"^USER\s+(\S+)", runtime, re.MULTILINE)
user = users[-1] if users else None

failures = []

if not (user and user.split(":")[0] not in ("root", "0")):
    failures.append(f"FAIL: runtime stage sets no non-root USER (last USER: {user})")

checks = [
    (r"useradd\s[^\n]*--uid\s+10001", "FAIL: runtime stage creates no UID 10001 user"),
    (r"setcap\s+cap_net_bind_service=\+ep\s+/usr/local/bin/quayel-gateway",
     "FAIL: binary gets no cap_net_bind_service capability"),
    (r"chown\s+-R\s+quayel:quayel\s+/var/lib/quayel\s+/var/log/quayel",
     "FAIL: /var/lib/quayel and /var/log/quayel are not chowned to quayel"),
    (r"sed -i 's/\"staging\": false/\"staging\": true/'",
     "FAIL: image default config does not switch auto_ssl to staging"),
]
for pattern, message in checks:
    if not re.search(pattern, runtime):
        failures.append(message)

# The Dockerfile's sed must match the demo config as shipped, or the image
# builds with production certificates. Apply the same substitution to the file.
with open(os.path.join(ROOT, "examples", "config.demo.json")) as f:
    demo_text = f.read()
patched = demo_text.replace('"staging": false', '"staging": true')
if patched == demo_text:
    failures.append("FAIL: examples/config.demo.json has no '\"staging\": false' for the image sed to change")
elif json.loads(patched)["plugins"]["auto_ssl"]["staging"] is not True:
    failures.append("FAIL: examples/config.demo.json auto_ssl.staging is not switched to true by the image sed")

if failures:
    for line in failures:
        print(line)
    sys.exit(1)

print(f"PASS: runtime stage runs as USER {user} with the capability, ownership and staging setup")
sys.exit(0)

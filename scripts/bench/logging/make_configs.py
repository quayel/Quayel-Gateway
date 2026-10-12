#!/usr/bin/env python3
"""Build the four logging bench configs from a base config.

Usage: make_configs.py [base_config.json] [out_dir]   (defaults: config.json, /tmp/qg-log-bench)

base-off / base-log : the baseline build, access log off / on
new-off  / new-log  : the build under test, access log off / on

Every config is the base with auto_ssl off, its own ports and its own log file
in out_dir. Logging uses the documented defaults (buffer 8192, flush 1000 ms).
"""
import copy, json, os, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "config.json")
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/qg-log-bench"
os.makedirs(OUT, exist_ok=True)
base = json.load(open(BASE))
PORTS = {"base-off": 8092, "base-log": 8094, "new-off": 8089, "new-log": 8095}

for name, port in PORTS.items():
    c = copy.deepcopy(base)
    c["listen"] = {"http": f"0.0.0.0:{port}", "https": f"0.0.0.0:{port + 1000}"}
    if "auto_ssl" in c["plugins"]:
        c["plugins"]["auto_ssl"]["enabled"] = False
    c["plugins"]["logging"] = {
        "enabled": name.endswith("-log"),
        "mode": "file",
        "file": {"path": f"{OUT}/{name}.jsonl", "buffer_size": 8192, "flush_interval_ms": 1000},
    }
    json.dump(c, open(f"{OUT}/{name}.json", "w"), indent=1)
    print(f"{OUT}/{name}.json  :{port}  logging {'on' if name.endswith('-log') else 'off'}")

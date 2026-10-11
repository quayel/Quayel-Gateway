# AGENTS.md — working on / with Quayel Gateway

**Read this first if you are an AI agent.** Quayel Gateway is a single-binary
Rust (Pingora) API gateway configured by one `config.json`. IP-intelligence data
is embedded in the binary; there are no external services.

## Documentation map (for agents)

| File | Use it for |
|---|---|
| **[docs/ai-guide.md](docs/ai-guide.md)** | **The agent contract: exact config tree, all enum values, defaults, condition paths (incl. JWT), validation loop, recipes, gotchas. Verified against source + release binary. Start here when generating or editing config.** |
| **[docs/config.schema.json](docs/config.schema.json)** | JSON Schema of `config.json` — validate generated configs before deploying. |
| **[skills/quayel-gateway/SKILL.md](skills/quayel-gateway/SKILL.md)** | Reusable skill package (condensed version of the ai-guide) for AI tools. |
| [docs/configuration.md](docs/configuration.md) | Human field-by-field reference. |
| [docs/conditions.md](docs/conditions.md) | Condition matching semantics and coercion. |
| [docs/api-reference.md](docs/api-reference.md) | Upstream headers, response bodies, variables. |
| [docs/logging.md](docs/logging.md) | JSONL access-log format. |
| [docs/plugins/](docs/plugins/) | Per-plugin internals (cache singleflight, ACME, LB algorithms). |

Precedence when docs disagree: `src/config/schema.rs` + `src/config/loader.rs`
(ground truth) → `docs/ai-guide.md` → the other docs.

## Project layout

```
setup.sh               # one-time: download embedded datasets into src/data/ + fetch crates
cargo build --release  # build (embeds src/data/* into the binary)
target/release/quayel-gateway   # the binary
examples/config.demo.json  # full-featured example config (valid, safe to copy from)
config.json            # live config (hot-reloaded on change)
src/config/schema.rs   # ← authoritative config schema (serde structs + enums)
src/config/loader.rs   # ← authoritative startup validation rules
src/plugins/           # firewall, rate_limit, cache, load_balancer, ip_intel
src/gateway/           # pipeline: ip_intel → firewall → rate_limiting → load_balancer → cache → logging
docs/                  # documentation (see map above)
skills/                # AI skill package
```

## Hard rules when changing the code

- Enum changes in `src/config/schema.rs` **must** be reflected in:
  `docs/config.schema.json`, `docs/ai-guide.md`, `skills/quayel-gateway/SKILL.md`,
  and `docs/configuration.md`. Keep all five in sync — agents rely on them.
- Keep `docs/config.schema.json` validating `examples/config.demo.json` and `config.json`
  (test with `python3` + `jsonschema`, see below).
- Do not document a field name that serde does not accept (e.g. redirect uses
  `location`, not `url`; health-check modes are `https`/`accepts_connections`/`off`).

## Hard rules when generating / editing config

1. Copy enum strings exactly — they are snake_case and case-sensitive.
2. Firewall rules need ≥1 condition; rate-limit/cache/LB rules may match all
   (empty `conditions`).
3. `limit`/`window_seconds` ≥ 1; every load balancer needs ≥1 target;
   `auto_ssl` needs `email` + non-empty `domains`.
4. Rules are evaluated in array order, first match wins — most specific first.
5. Bump `config_version` on every change (it is logged on hot reload).
6. Validate before declaring done:

```bash
# 1. syntax
python3 -c "import json; json.load(open('config.json')); print('OK')"

# 2. schema (if jsonschema is installed)
python3 - <<'EOF'
import json
from jsonschema import Draft7Validator
schema = json.load(open('docs/config.schema.json'))
errs = list(Draft7Validator(schema).iter_errors(json.load(open('config.json'))))
for e in errs: print(list(e.path), e.message[:160])
print('SCHEMA OK' if not errs else 'SCHEMA FAILED')
EOF

# 3. authoritative: the gateway's own parser (wrap in timeout — valid config starts a server)
timeout -k 2 3 ./target/release/quayel-gateway config.json
```

7. Smoke test: `curl -s -i http://localhost:8080/…` and inspect the last access-log
   line. On a running gateway the config hot-reloads when saved (watch stderr for
   `Config hot-reloaded successfully`; an invalid save keeps the old config live).

## Common failure modes (config will not load)

| Error | Cause |
|---|---|
| ``unknown variant `x`, expected one of `...` `` | wrong enum value |
| ``missing field `y` `` | required field absent |
| `Firewall rule '<id>' has no conditions` | firewall rules cannot be catch-all |
| `Rate limit rule '<id>' has zero limit / zero window` | values must be ≥1 |
| `Load balancer '<id>' has no targets` | add ≥1 target |
| `At least one of listen.http or listen.https` | set a listener |

## Using the skill from other AI tools

The skill package is `skills/quayel-gateway/` (standard `SKILL.md` format).
To install it for an agent on another machine, copy that folder into the agent's
skills directory, e.g. `~/.koder/skills/quayel-gateway/`,
`~/.claude/skills/quayel-gateway/`, or `.claude/skills/quayel-gateway/` inside a
project. It is self-contained; when the repo is present it defers to
`docs/ai-guide.md` and `docs/config.schema.json`.

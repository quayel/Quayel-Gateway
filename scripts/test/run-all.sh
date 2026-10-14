#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Quayel Gateway — run every test suite
#
#   1. cargo test                  unit tests
#   2. check-config.sh             examples/config.all-rules.json is valid
#   3. all-rules.sh                every plugin feature end to end
#   4. transform-cache.py          transforms + cache revalidation end to end
#   5. dos-protection.py           server timeouts, limits and protection
#   6. jwt-verify.py               JWT keys, verification and claim fields
#   7. logging.py                  access log, X-QG-Request-Id, rotation, reload
#   8. websocket.py                WebSocket proxying, body limit, idle timeout
#   9. sink-backpressure.py        slow sink: concurrency, spool instead of drop
#  10. tcp-proxy.py               TCP streams: balancing, failover, health, rules,
#                                  PROXY protocol, idle, logs (+ Redis/Postgres
#                                  with Docker)
#  11. auto-ssl.py                 ACME issuance against Pebble (needs Docker)
#  12. sinks.py                    log sinks + /metrics against ClickHouse, Loki,
#                                  OTel Collector, Prometheus (needs Docker)
#  13. grpc.py                     HTTP/2 + gRPC: h2c/h2 in and out, streaming,
#                                  gRPC error statuses (needs Docker)
#
# Each suite prints its own PASS/FAIL list; a summary per suite is at the end.
# Usage:  bash scripts/test/run-all.sh        (builds the release binary first)
# ─────────────────────────────────────────────────────────────────────────────
set -u
cd "$(dirname "$0")/../.."
BIN=./target/release/quayel-gateway

SUITES=(); STATUS=()
run() {  # run <name> <command...>
    local name="$1"; shift
    echo ""
    echo "════════════════════════ $name ════════════════════════"
    if "$@"; then SUITES+=("$name"); STATUS+=("PASS")
    else SUITES+=("$name"); STATUS+=("FAIL"); fi
}

echo "Building release binary..."
cargo build --release --quiet || { echo "build failed"; exit 1; }

run "cargo test"         cargo test --quiet
run "check-config"       bash scripts/test/check-config.sh examples/config.all-rules.json
run "all-rules"          bash scripts/test/all-rules.sh
run "transform-cache"    env BIN="$BIN" python3 scripts/test/transform-cache.py
run "dos-protection"     python3 scripts/test/dos-protection.py "$BIN"
run "jwt-verify"         env BIN="$BIN" python3 scripts/test/jwt-verify.py
run "logging"            env BIN="$BIN" python3 scripts/test/logging.py
run "websocket"          env BIN="$BIN" python3 scripts/test/websocket.py
run "sink-backpressure"  env BIN="$BIN" python3 scripts/test/sink-backpressure.py
run "tcp-proxy"          env BIN="$BIN" python3 scripts/test/tcp-proxy.py
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    run "auto-ssl"       env BIN="$BIN" python3 scripts/test/auto-ssl.py
    run "sinks"          env BIN="$BIN" python3 scripts/test/sinks.py
    run "grpc"           env BIN="$BIN" python3 scripts/test/grpc.py
else
    echo ""; echo "auto-ssl, sinks, grpc: skipped (Docker not available)"
fi

echo ""
echo "════════════════════════ SUMMARY ════════════════════════"
fail=0
for i in "${!SUITES[@]}"; do
    if [[ "${STATUS[$i]}" == "PASS" ]]; then printf '  \033[0;32mPASS\033[0m  %s\n' "${SUITES[$i]}"
    else printf '  \033[0;31mFAIL\033[0m  %s\n' "${SUITES[$i]}"; fail=1; fi
done
echo "═════════════════════════════════════════════════════════"
exit $fail

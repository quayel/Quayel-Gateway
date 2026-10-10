#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Quayel Gateway — ALL-RULES test harness
#
# Boots the gateway with config.all-rules.json plus two echo origins, then
# fires a request per operator / condition path / plugin feature and asserts
# the observable outcome:
#   - block/redirect  → status code + rule_id in the response body
#   - set_request_header / set_response_header / allow → firewall log event
#     (these actions do NOT reach the upstream request; the engine keeps them
#     in the request context for later plugins — verified via the RL-key probe)
#   - rate limiting   → 429 after N requests per key mode
#   - cache           → 200/200 + cache HIT events in the JSONL log
#   - load balancer   → routing behavior per algorithm
#   - logging         → JSONL events for every plugin
#
# Usage:   bash scripts/test-all-rules.sh
# Env:     KEEP=1   keep gateway + origins running after the tests
# ─────────────────────────────────────────────────────────────────────────────
set -u

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CONFIG="config.all-rules.json"
GW_URL="http://127.0.0.1:8099"
LOG=/tmp/quayel-all-rules-access.jsonl
BIN=./target/release/quayel-gateway

PASS=0; FAIL=0; RESULTS=(); EXPECTED_LOG=()

record() {  # record <ok?> <name> <detail>
    if [[ "$1" == "1" ]]; then PASS=$((PASS+1)); RESULTS+=("PASS|$2|$3");
    else FAIL=$((FAIL+1)); RESULTS+=("FAIL|$2|$3"); fi
}

expect_log() {  # expect_log <rule_id> <Action>  (checked against the JSONL at the end)
    EXPECTED_LOG+=("$1|$2")
}

cleanup() {
    if [[ "${KEEP:-0}" != "1" ]]; then
        [[ -n "${GW_PID:-}" ]] && kill -9 "$GW_PID" 2>/dev/null
        [[ -n "${ECHO_A_PID:-}" ]] && kill -9 "$ECHO_A_PID" 2>/dev/null
        [[ -n "${ECHO_B_PID:-}" ]] && kill -9 "$ECHO_B_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Boot echo origins + gateway ──────────────────────────────────────────────
rm -f "$LOG"
python3 scripts/all-rules-echo.py 9099 A >/dev/null 2>&1 & ECHO_A_PID=$!
python3 scripts/all-rules-echo.py 9100 B >/dev/null 2>&1 & ECHO_B_PID=$!
"$BIN" "$CONFIG" >/tmp/quayel-all-rules-gw.log 2>&1 & GW_PID=$!

for _ in $(seq 1 50); do
    curl -s -o /dev/null --max-time 1 "$GW_URL/lb/rr" && break
    sleep 0.2
done

# JWT for claim-based conditions/keys: {"user_id":"u-42","data":{"role":"admin"}}
JWT=$(python3 - <<'EOF'
import base64, json
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
print(f"{b({'alg':'HS256','typ':'JWT'})}.{b({'user_id':'u-42','data':{'role':'admin'}})}.sig")
EOF
)

req() {  # req <outvar_status> <outvar_body> <curl args...>
    local __s __b
    __b=$(curl -s -w '\n%{http_code}' --max-time 5 "$@")
    __s=${__b##*$'\n'}; __b=${__b%$'\n'*}
    printf -v "$1" '%s' "$__s"; printf -v "$2" '%s' "$__b"
}

assert_status() {  # assert_status <name> <want> <curl args...>
    local name="$1" want="$2"; shift 2
    local s b; req s b "$@"
    record "$([[ "$s" == "$want" ]] && echo 1 || echo 0)" "$name" "status=$s want=$want"
}

assert_block() {  # assert_block <name> <want_status> <want_rule_id> <curl args...>
    local name="$1" want="$2" rid="$3"; shift 3
    local s b; req s b "$@"
    local ok=0
    [[ "$s" == "$want" && "$b" == *"\"rule_id\":\"$rid\""* ]] && ok=1
    record "$ok" "$name" "status=$s want=$want rule_id=$rid"
}

assert_action() {  # assert_action <name> <rule_id> <Action> <curl args...>
    # set_request_header / set_response_header / allow: request must pass through
    # to the origin (200) and the firewall action must appear in the access log.
    local name="$1" rid="$2" act="$3"; shift 3
    local s b; req s b "$@"
    expect_log "$rid" "$act"
    record "$([[ "$s" == "200" ]] && echo 1 || echo 0)" "$name" "status=$s rule=$rid action=$act"
}

# ── 1. Firewall: all 15 operators ────────────────────────────────────────────
assert_block "op:equals(req.method)"        421 fw-op-equals        -X DEBUG "$GW_URL/test/fw/eq"
assert_action "op:not_equals(req.scheme)"   fw-op-not-equals        SetRequestHeader "$GW_URL/test/fw/req"
assert_block "op:contains(req.user_agent)"  403 fw-op-contains      "$GW_URL/test/fw/contains" -A "all-rules-probe/1.0"
assert_action "op:not_contains(req.header)" fw-op-not-contains      Allow "$GW_URL/test/fw/notcontains" -H "x-probe: danger"
rec_s=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 5 "$GW_URL/test/fw/starts")
record "$([[ "$rec_s" == 301\ */all-rules/hit* ]] && echo 1 || echo 0)" "op:starts_with(req.path)" "$rec_s"
assert_block "op:ends_with(req.header)"     403 fw-op-ends-with     "$GW_URL/test/fw/endswith" -H "x-probe: style.css"
assert_action "op:exists(req.cookie)"       fw-op-exists            SetResponseHeader "$GW_URL/test/fw/exists" -H "Cookie: session=abc"
assert_block "op:not_exists(req.cookie)"    403 fw-op-not-exists    "$GW_URL/test/fw/no-session"
assert_status "op:in(ip.country) negative"  200                    "$GW_URL/test/fw/in" -H "X-Forwarded-For: 8.8.8.8"
assert_block "op:not_in(req.query)"         451 fw-op-not-in        "$GW_URL/test/fw/notin?country=CN"
assert_status "op:greater_than(ip.risk_score) negative" 200        "$GW_URL/test/fw/gt-only" -H "X-Forwarded-For: 8.8.8.8"
assert_action "op:greater_than_or_equal(ip.asn)" fw-op-greater-than-or-equal SetRequestHeader "$GW_URL/test/fw/gte-only" -H "X-Forwarded-For: 8.8.8.8"
assert_status "op:less_than(ip.risk_score) negative" 200           "$GW_URL/test/fw/lt-only" -H "X-Forwarded-For: 8.8.8.8"
assert_action "op:less_than_or_equal(ip.asn)" fw-op-less-than-or-equal SetRequestHeader "$GW_URL/test/fw/lte-only" -H "X-Forwarded-For: 8.8.8.8"
assert_block "op:regex(req.user_agent)"     403 fw-op-regex         "$GW_URL/test/fw/regex" -A "all-rules-scanner/1.0"

# ── 2. Firewall: every left condition path ───────────────────────────────────
assert_action "left:req.host"               fw-left-req-host        SetRequestHeader "$GW_URL/probe" -H "Host: all-rules.test"
assert_block "left:req.ip"                  403 fw-left-req-ip      "$GW_URL/probe" -H "X-Forwarded-For: 198.51.100.7"
assert_action "left:req.peer_ip"            fw-left-req-peer-ip     SetRequestHeader "$GW_URL/probe"
assert_action "left:header.*.jwt.*"         fw-left-jwt             SetRequestHeader "$GW_URL/probe" -H "Authorization: Bearer $JWT"
assert_action "left:http.query alias"       fw-http-alias-query     SetRequestHeader "$GW_URL/probe?op=alias"
assert_block "left:ip.is_tor"               403 fw-left-tor         "$GW_URL/test/fw/left-tor" -H "X-Forwarded-For: 2.26.97.42"
assert_block "left:ip.is_vpn"               403 fw-left-vpn         "$GW_URL/test/fw/left-vpn" -H "X-Forwarded-For: 2.26.157.7"
assert_action "left:ip.country"             fw-left-country         SetRequestHeader "$GW_URL/test/fw/left-country" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.region (not_exists)" fw-left-region        SetRequestHeader "$GW_URL/test/fw/left-region" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.city"                fw-left-city            SetRequestHeader "$GW_URL/test/fw/left-city" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.asn"                 fw-left-asn             SetRequestHeader "$GW_URL/test/fw/left-asn" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.as_org"              fw-left-as-org          SetRequestHeader "$GW_URL/test/fw/left-as-org" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.provider"            fw-left-provider        SetRequestHeader "$GW_URL/test/fw/left-provider" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.is_datacenter"       fw-left-is-datacenter   SetRequestHeader "$GW_URL/test/fw/left-dc" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.is_mobile"           fw-left-is-mobile       SetRequestHeader "$GW_URL/test/fw/left-mobile" -H "X-Forwarded-For: 8.8.8.8"
assert_action "left:ip.network_type"        fw-left-network-type    SetRequestHeader "$GW_URL/test/fw/left-net" -H "X-Forwarded-For: 8.8.8.8"

# ── 3. Firewall: logical operators + actions ─────────────────────────────────
assert_block "logic:or chain (header branch)" 403 fw-logic-or        "$GW_URL/probe" -H "x-force: or-match"
assert_block "logic:or chain (UA branch)"     403 fw-logic-or        "$GW_URL/probe" -A "all-rules-or-probe/1.0"
assert_block "logic:or chain (TRACE branch)"  403 fw-logic-or        -X TRACE "$GW_URL/probe"
assert_block "logic:and/or mixed (AND branch)" 421 fw-logic-mixed    -X PUT "$GW_URL/test/fw/mixed"
assert_block "logic:and/or mixed (OR branch)"  421 fw-logic-mixed    "$GW_URL/probe" -A "all-rules-mixed-probe/1.0"
rec_s=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 5 "$GW_URL/test/fw/starts")
record "$([[ "$rec_s" == 301\ */all-rules/hit* ]] && echo 1 || echo 0)" "action:redirect" "$rec_s"

# ── 4. set_request_header visibility to later plugins (RL key probe) ─────────
# rl-probe-header-visibility keys on req.header.x-all-rules-probe (limit 1/60s).
# 1st inject request passes; 2nd (same key) is 429; inject-b has a DIFFERENT key
# so it passes again — proving the firewall-injected header is visible to the
# rate-limit key resolver with per-value buckets.
s1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/test/probe/inject")
s2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/test/probe/inject")
s3=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/test/probe/inject-b")
record "$([[ "$s1" == "200" && "$s2" == "429" && "$s3" == "200" ]] && echo 1 || echo 0)" \
    "set_request_header visible to RL keys" "statuses=$s1,$s2,$s3 want=200,429,200"

# ── 5. Rate limiting: key modes ──────────────────────────────────────────────
rl_burst() {  # rl_burst <name> <n> <curl args...>
    local name="$1" n="$2"; shift 2
    local last=""
    for _ in $(seq 1 "$n"); do
        last=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@")
    done
    record "$([[ "$last" == "429" ]] && echo 1 || echo 0)" "$name" "last_status=$last want=429"
}
rl_burst "rl:single key (req.ip)"           4 "$GW_URL/test/rl/single"
rl_burst "rl:composite key"                 6 "$GW_URL/test/rl/composite" -H "x-api-key: k1"
rl_burst "rl:jwt claim key"                 3 "$GW_URL/test/rl/jwt" -H "Authorization: Bearer $JWT"
rl_burst "rl:legacy template key"           3 "$GW_URL/test/rl/template" -H "x-api-key: k2"
rl_burst "rl:cookie+query composite key"    6 "$GW_URL/test/rl/cookie?tier=free" -H "Cookie: session=s1"
rl_burst "rl:ip-intel condition + ip key"   6 "$GW_URL/test/rl/intel" -H "X-Forwarded-For: 8.8.8.8"

# ── 6. Cache: TTL modes, keys, bypass ────────────────────────────────────────
rl_burst_200() {  # two identical requests must both be 200 (1st MISS, 2nd HIT)
    local name="$1"; shift
    local a b
    a=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@")
    b=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@")
    record "$([[ "$a" == "200" && "$b" == "200" ]] && echo 1 || echo 0)" "$name" "statuses=$a,$b"
}
rl_burst_200 "cache:custom TTL + SWR/SIE"   "$GW_URL/test/cache/static/app.css"
rl_burst_200 "cache:origin TTLs"            "$GW_URL/test/cache/origin/data"
rl_burst_200 "cache:custom variant key"     "$GW_URL/test/cache/variant" -H "x-variant: dark"
rl_burst_200 "cache:bypass (cookied)"       "$GW_URL/test/cache/private" -H "Cookie: session=x"
rl_burst_200 "cache:greater_than+not_in conds" "$GW_URL/test/cache/ops?other=1" -H "X-Forwarded-For: 8.8.8.8"

# ── 7. Load balancer: algorithms ─────────────────────────────────────────────
bodies=""
for _ in 1 2 3 4; do
    bodies+=$(curl -s --max-time 5 "$GW_URL/lb/rr")
done
record "$([[ "$bodies" == *'"origin": "A"'* && "$bodies" == *'"origin": "B"'* ]] && echo 1 || echo 0)" \
    "lb:round_robin alternates targets" "saw A and B"

bodies=""
for _ in 1 2 3 4 5 6; do
    bodies+=$(curl -s --max-time 5 "$GW_URL/lb/sticky" -H "x-session-id: sess-1")
done
a_count=$(grep -o '"origin": "A"' <<<"$bodies" | wc -l)
record "$([[ "$a_count" == "0" || "$a_count" == "6" ]] && echo 1 || echo 0)" \
    "lb:sticky_session pins to one target" "origin_a_count=$a_count/6"

s=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/lb/lc")
record "$([[ "$s" == "200" ]] && echo 1 || echo 0)" "lb:least_connections routes" "status=$s"
s=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/lb/fast")
record "$([[ "$s" == "200" ]] && echo 1 || echo 0)" "lb:fast_response routes" "status=$s"
s=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$GW_URL/lb/wrr")
record "$([[ "$s" == "200" ]] && echo 1 || echo 0)" "lb:weighted_round_robin routes" "status=$s"

# ── 8. Logging: JSONL events written ─────────────────────────────────────────
sleep 2.5
if [[ -s "$LOG" ]]; then
    hit=$(grep -c '"status":"HIT"' "$LOG" || true)
    rlevents=$(grep -c '"rule_id":"rl-' "$LOG" || true)
    record "$([[ "${hit:-0}" -gt 0 ]] && echo 1 || echo 0)" "logging:cache hit events" "hits=$hit"
    record "$([[ "${rlevents:-0}" -gt 0 ]] && echo 1 || echo 0)" "logging:rate-limit events" "events=$rlevents"

    missing=0
    for e in "${EXPECTED_LOG[@]}"; do
        IFS='|' read -r rid act <<<"$e"
        grep -q "\"rule_id\":\"$rid\",\"action\":\"$act\"" "$LOG" || missing=$((missing+1))
    done
    record "$([[ $missing -eq 0 ]] && echo 1 || echo 0)" \
        "logging:firewall action events for all rules" \
        "expected=${#EXPECTED_LOG[@]} missing=$missing"
else
    record 0 "logging:JSONL written" "$LOG missing or empty"
fi

# ── Report ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════ ALL-RULES RESULTS ════════════════════════"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r st name detail <<<"$r"
    if [[ "$st" == "PASS" ]]; then printf '  \033[0;32mPASS\033[0m  %-44s %s\n' "$name" "$detail"
    else printf '  \033[0;31mFAIL\033[0m  %-44s %s\n' "$name" "$detail"; fi
done
echo "────────────────────────────────────────────────────────────────────"
printf '  TOTAL: %d   PASS: \033[0;32m%d\033[0m   FAIL: \033[0;31m%d\033[0m\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
echo "════════════════════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1

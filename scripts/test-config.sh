#!/usr/bin/env bash
set -euo pipefail

RED="[0;31m"; GREEN="[0;32m"; YELLOW="[0;33m"; NC="[0m"
BINARY_TEST=false; CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY_TEST=true; shift ;;
        *) CONFIG_FILE="$1"; shift ;;
    esac
done
[[ -z "$CONFIG_FILE" ]] && CONFIG_FILE="config.json"

echo "Quayel Gateway - Config Tester"
echo -e "Config: ${YELLOW}${CONFIG_FILE}${NC}"
echo ""

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}File not found: $CONFIG_FILE${NC}"; exit 1
fi
echo -e "${GREEN}OK${NC}: File exists ($(wc -c < "$CONFIG_FILE") bytes)"

if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
    echo -e "${RED}Invalid JSON${NC}"; exit 1
fi
echo -e "${GREEN}OK${NC}: Valid JSON"
ERRORS=0

echo ""; echo "-- Required Fields --"
for f in ".gateway_id" ".gateway_name" ".config_version"; do
    if jq -e "$f" "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}: $f = $(jq -r "$f" "$CONFIG_FILE")"
    else
        echo -e "${RED}MISSING${NC}: $f"; ERRORS=$((ERRORS+1))
    fi
done

echo ""; echo "-- Listen Config --"
if jq -e ".listen.http" "$CONFIG_FILE" >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}: http = $(jq -r .listen.http "$CONFIG_FILE")"
else echo -e "${YELLOW}WARN${NC}: No http listener"; fi

echo ""; echo "-- Plugins --"
for p in firewall rate_limiting cache load_balancer logging ip_intel auto_ssl; do
    if jq -e ".plugins.$p" "$CONFIG_FILE" >/dev/null 2>&1; then
        en=$(jq -r ".plugins.$p.enabled // false" "$CONFIG_FILE")
        echo -e "${GREEN}OK${NC}: $p (enabled=$en)"
    else echo -e "${YELLOW}SKIP${NC}: $p (not configured)"; fi
done

echo ""; echo "-- LB Targets --"
lb_count=$(jq -r ".plugins.load_balancer.load_balancers // [] | length" "$CONFIG_FILE")
if [[ "$lb_count" -gt 0 ]]; then
    for i in $(seq 0 $((lb_count-1))); do
        id=$(jq -r ".plugins.load_balancer.load_balancers[$i].id" "$CONFIG_FILE")
        tc=$(jq -r ".plugins.load_balancer.load_balancers[$i].targets // [] | length" "$CONFIG_FILE")
        if [[ "$tc" -eq 0 ]]; then
            echo -e "${RED}ERR${NC}: LB $id has NO targets"; ERRORS=$((ERRORS+1))
        else
            echo -e "${GREEN}OK${NC}: LB $id ($tc targets)"
            for j in $(seq 0 $((tc-1))); do
                h=$(jq -r ".plugins.load_balancer.load_balancers[$i].targets[$j].host" "$CONFIG_FILE")
                p=$(jq -r ".plugins.load_balancer.load_balancers[$i].targets[$j].port" "$CONFIG_FILE")
                echo "      -> $h:$p"
            done
        fi
    done
else echo -e "${YELLOW}SKIP${NC}: No load balancers"; fi

echo ""; echo "-- Firewall Rules --"
fw=$(jq -r ".plugins.firewall.rules // [] | length" "$CONFIG_FILE")
if [[ "$fw" -gt 0 ]]; then
    for i in $(seq 0 $((fw-1))); do
        rid=$(jq -r ".plugins.firewall.rules[$i].id" "$CONFIG_FILE")
        cc=$(jq -r ".plugins.firewall.rules[$i].conditions // [] | length" "$CONFIG_FILE")
        act=$(jq -r ".plugins.firewall.rules[$i].action.type" "$CONFIG_FILE")
        if [[ "$cc" -eq 0 ]]; then
            echo -e "${RED}ERR${NC}: Rule $rid has NO conditions"; ERRORS=$((ERRORS+1))
        else echo -e "${GREEN}OK${NC}: $rid ($cc conds, action=$act)"; fi
    done
else echo -e "${YELLOW}SKIP${NC}: No firewall rules"; fi

echo ""; echo "-- Rate Limit Rules --"
rl=$(jq -r ".plugins.rate_limiting.rules // [] | length" "$CONFIG_FILE")
if [[ "$rl" -gt 0 ]]; then
    for i in $(seq 0 $((rl-1))); do
        rid=$(jq -r ".plugins.rate_limiting.rules[$i].id" "$CONFIG_FILE")
        lim=$(jq -r ".plugins.rate_limiting.rules[$i].limit" "$CONFIG_FILE")
        win=$(jq -r ".plugins.rate_limiting.rules[$i].window_seconds" "$CONFIG_FILE")
        if [[ "$lim" -eq 0 || "$win" -eq 0 ]]; then
            echo -e "${RED}ERR${NC}: Rule $rid bad values"; ERRORS=$((ERRORS+1))
        else echo -e "${GREEN}OK${NC}: $rid ($lim req/${win}s)"; fi
    done
else echo -e "${YELLOW}SKIP${NC}: No rate limit rules"; fi

echo ""; echo "-- Auto-SSL --"
if jq -e ".plugins.auto_ssl" "$CONFIG_FILE" >/dev/null 2>&1; then
    en=$(jq -r ".plugins.auto_ssl.enabled // false" "$CONFIG_FILE")
    email=$(jq -r ".plugins.auto_ssl.email // empty" "$CONFIG_FILE")
    dc=$(jq -r ".plugins.auto_ssl.domains // [] | length" "$CONFIG_FILE")
    staging=$(jq -r ".plugins.auto_ssl.staging // false" "$CONFIG_FILE")
    if [[ -z "$email" ]]; then
        echo -e "${RED}ERR${NC}: auto_ssl.email is missing"; ERRORS=$((ERRORS+1))
    else echo -e "${GREEN}OK${NC}: email = $email"; fi
    if [[ "$dc" -eq 0 ]]; then
        echo -e "${RED}ERR${NC}: auto_ssl.domains is empty"; ERRORS=$((ERRORS+1))
    else echo -e "${GREEN}OK${NC}: $dc domain(s) configured"; fi
    echo -e "${GREEN}OK${NC}: staging = $staging"
else echo -e "${YELLOW}SKIP${NC}: No auto_ssl"; fi

if [[ "$BINARY_TEST" == true ]]; then
    echo ""; echo "-- Binary Validation --"
    BIN="./target/release/quayel-gateway"
    [[ ! -x "$BIN" ]] && BIN="./target/debug/quayel-gateway"
    if [[ ! -x "$BIN" ]]; then
        echo -e "${YELLOW}WARN${NC}: Binary not found, skip"
    else
        if timeout 3 "$BIN" "$CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}: Binary accepted config"
        else
            ec=$?
            if [[ $ec -eq 124 ]]; then
                echo -e "${GREEN}OK${NC}: Binary started successfully"
            else
                echo -e "${RED}FAIL${NC}: Binary rejected config (exit $ec)"
                ERRORS=$((ERRORS+1))
            fi
        fi
    fi
fi

echo ""; echo "============================"
if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}INVALID${NC} - $ERRORS error(s) found"; exit 1
else
    echo -e "${GREEN}VALID${NC} - all checks passed"
    echo "SHA-256: $(sha256sum "$CONFIG_FILE" | cut -d" " -f1)"
fi
echo "============================"

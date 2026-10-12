#!/usr/bin/env bash
# Interleaved JWT cost bench: none vs decode vs hs256 vs rs256, same build.
# Usage: bench_jwt.sh [reps]   (configs and tokens from make_configs.py, in $JWT_BENCH_DIR)
# wrk -t12 -c1000 -d10s --latency, every target gets an Authorization header.
set -u
REPS="${1:-10}"
B="${JWT_BENCH_DIR:-/tmp/qg-jwt-bench}"
ROUTES=(${ROUTES_OVERRIDE:-/cache-test /no-cache})
declare -A URL=( [none]=http://127.0.0.1:8089 [decode]=http://127.0.0.1:8093 [hs256]=http://127.0.0.1:8094 [rs256]=http://127.0.0.1:8095 )
TARGETS=(${TARGETS_OVERRIDE:-none decode hs256 rs256})
declare -A TOK
for t in "${TARGETS[@]}"; do TOK[$t]=$(cat "$B/jwt-$t.token"); done
echo "=== JWT BENCH: wrk -t12 -c1000 -d10s --latency, $REPS interleaved reps/route ==="
echo "route,target,rep,rps,p50,p99,non2xx,errors"
for route in "${ROUTES[@]}"; do
  for t in "${TARGETS[@]}"; do wrk -t12 -c1000 -d2s -H "Authorization: Bearer ${TOK[$t]}" "${URL[$t]}$route" >/dev/null 2>&1; done
  for ((rep=0; rep<REPS; rep++)); do
    for ((k=0; k<${#TARGETS[@]}; k++)); do
      t="${TARGETS[$(( (rep + k) % ${#TARGETS[@]} ))]}"
      out=$(wrk -t12 -c1000 -d10s --latency -H "Authorization: Bearer ${TOK[$t]}" "${URL[$t]}$route" 2>/dev/null)
      rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
      p50=$(echo "$out" | awk '/^ *50%/ {print $2; exit}')
      p99=$(echo "$out" | awk '/^ *99%/ {print $2; exit}')
      non2xx=$(echo "$out" | awk '/Non-2xx/ {print $NF}'); non2xx=${non2xx:-0}
      errs=$(echo "$out" | awk '/Socket errors/ {gsub(",","");print $4+$6+$8+$10}'); errs=${errs:-0}
      echo "$route,$t,$((rep+1)),$rps,$p50,$p99,$non2xx,$errs"
    done
  done
done
echo "=== END JWT BENCH ==="

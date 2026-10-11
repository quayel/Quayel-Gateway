#!/usr/bin/env bash
# Interleaved A/B benchmark: quayel-gateway vs the nginx mirror (nginx-mirror/nginx.conf).
# Usage: bench_vs_nginx.sh [reps]
# Same routes, same origin, same params as docs/development/benchmark-protocol.md:
# wrk -t12 -c1000 -d10s --latency. Each rep alternates which target goes first so
# drift on the box hits both equally.
set -u
REPS="${1:-10}"
ROUTES=(/cache-test /cache-test-second /no-cache)
declare -A URL=( [gateway]=http://127.0.0.1:8089 [nginx]=http://127.0.0.1:8090 )
TARGETS=(gateway nginx)

echo "=== GATEWAY vs NGINX: wrk -t12 -c1000 -d10s --latency, $REPS interleaved reps/route ==="
echo "route,target,rep,rps,p50,p99,non2xx,errors"
for route in "${ROUTES[@]}"; do
  for t in "${TARGETS[@]}"; do
    wrk -t12 -c1000 -d2s "${URL[$t]}$route" >/dev/null 2>&1   # warmup, discarded
  done
  for ((rep=0; rep<REPS; rep++)); do
    for ((k=0; k<${#TARGETS[@]}; k++)); do
      t="${TARGETS[$(( (rep + k) % ${#TARGETS[@]} ))]}"
      out=$(wrk -t12 -c1000 -d10s --latency "${URL[$t]}$route" 2>/dev/null)
      rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
      p50=$(echo "$out" | awk '/^ *50%/ {print $2; exit}')
      p99=$(echo "$out" | awk '/^ *99%/ {print $2; exit}')
      non2xx=$(echo "$out" | awk '/Non-2xx/ {print $NF}'); non2xx=${non2xx:-0}
      errs=$(echo "$out" | awk '/Socket errors/ {gsub(",","");print $4+$6+$8+$10}'); errs=${errs:-0}
      echo "$route,$t,$((rep+1)),$rps,$p50,$p99,$non2xx,$errs"
    done
  done
done
echo "=== END ==="

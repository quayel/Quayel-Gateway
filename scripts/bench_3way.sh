#!/usr/bin/env bash
# Interleaved 3-way benchmark: APISIX mirror vs quayel-gateway vs nginx mirror.
# Usage: bench_3way.sh [reps]
# For each route, REPS rounds; each round runs the three targets in rotating
# order so slow drift/noise of the shared box hits every target equally.
# Every run: wrk -t12 -c1000 -d10s --latency (identical params for all).
set -u
REPS="${1:-10}"
ROUTES=(/cache-test /cache-test-second /no-cache)
declare -A URL=( [apisix]=http://127.0.0.1:8091 [gateway]=http://127.0.0.1:8089 [nginx]=http://127.0.0.1:8090 )
TARGETS=(apisix gateway nginx)

echo "=== 3WAY BENCH: wrk -t12 -c1000 -d10s --latency, $REPS interleaved reps/route ==="
echo "route,target,rep,rps,p99"

for route in "${ROUTES[@]}"; do
  for t in "${TARGETS[@]}"; do
    wrk -t12 -c1000 -d2s "${URL[$t]}$route" >/dev/null 2>&1   # warmup, discarded
  done
  for ((rep=0; rep<REPS; rep++)); do
    # rotate start target each rep: (apisix,gateway,nginx) -> (gateway,nginx,apisix) -> ...
    for ((k=0; k<3; k++)); do
      t="${TARGETS[$(( (rep + k) % 3 ))]}"
      out=$(wrk -t12 -c1000 -d10s --latency "${URL[$t]}$route" 2>/dev/null)
      rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
      p99=$(echo "$out" | awk '/^ *99%/ {print $2; exit}' | tr -d 'ms ')
      echo "$route,$t,$((rep+1)),$rps,${p99}ms"
    done
  done
done
echo "=== END 3WAY ==="

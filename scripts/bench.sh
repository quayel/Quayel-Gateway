#!/usr/bin/env bash
# Benchmark suite for quayel-gateway — fixed params per docs/BENCHMARK_PROTOCOL.md.
# Usage: bench.sh <label> [reps]
# Every run: wrk -t12 -c1000 -d10s --latency. 3 routes, REPS runs each, median reported.
set -u
LABEL="${1:-run}"
REPS="${2:-3}"
BASE="http://127.0.0.1:8089"
ROUTES=(/cache-test /cache-test-second /no-cache)

median() {
  printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}'
}

echo "=== BENCH: $LABEL  (wrk -t12 -c1000 -d10s, median-of-$REPS) ==="
echo "route,rps_median,rps_min,rps_max,p99_median"
for route in "${ROUTES[@]}"; do
  wrk -t12 -c1000 -d2s "$BASE$route" >/dev/null 2>&1   # warmup, discarded
  rpss=(); p99s=()
  for ((r=0;r<REPS;r++)); do
    out=$(wrk -t12 -c1000 -d10s --latency "$BASE$route" 2>/dev/null)
    rpss+=("$(echo "$out" | awk '/Requests\/sec/ {print $2}')")
    p99s+=("$(echo "$out" | awk '/^ *99%/ {print $2; exit}' | tr -d 'ms ' )")
  done
  med=$(median "${rpss[@]}")
  mn=$(printf '%s\n' "${rpss[@]}" | sort -n | head -1)
  mx=$(printf '%s\n' "${rpss[@]}" | sort -n | tail -1)
  p99med=$(median "${p99s[@]}")
  echo "$route,$med,$mn,$mx,${p99med}ms"
done
echo "=== END: $LABEL ==="

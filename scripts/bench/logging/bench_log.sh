#!/usr/bin/env bash
# Interleaved A/B: a baseline build vs the build under test, each with access logging off and on.
# wrk -t12 -c1000 -d10s --latency (benchmark-protocol.md). Log files are truncated
# after every run so the disk doesn't fill (~100 MB/s of JSONL at full load).
# Usage: bench_log.sh [reps]   (instances from start.sh; ROUTES_OVERRIDE / TARGETS_OVERRIDE to narrow)
set -u
REPS="${1:-10}"
ROUTES=(${ROUTES_OVERRIDE:-/cache-test /cache-test-second /no-cache})
declare -A URL=( [base-off]=http://127.0.0.1:8092 [base-log]=http://127.0.0.1:8094 [new-off]=http://127.0.0.1:8089 [new-log]=http://127.0.0.1:8095 )
TARGETS=(${TARGETS_OVERRIDE:-base-off new-off base-log new-log})
D="${LOG_BENCH_DIR:-/tmp/qg-log-bench}"
echo "route,target,rep,rps,p99,non2xx,errors,log_lines"
for route in "${ROUTES[@]}"; do
  for t in "${TARGETS[@]}"; do wrk -t12 -c1000 -d2s "${URL[$t]}$route" >/dev/null 2>&1; done
  sleep 2; for f in $D/*.jsonl; do : > "$f"; done
  for ((rep=0; rep<REPS; rep++)); do
    for ((k=0; k<${#TARGETS[@]}; k++)); do
      t="${TARGETS[$(( (rep + k) % ${#TARGETS[@]} ))]}"
      out=$(wrk -t12 -c1000 -d10s --latency "${URL[$t]}$route" 2>/dev/null)
      rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
      p99=$(echo "$out" | awk '/^ *99%/ {print $2; exit}')
      non2xx=$(echo "$out" | awk '/Non-2xx/ {print $NF}'); non2xx=${non2xx:-0}
      errs=$(echo "$out" | awk '/Socket errors/ {gsub(",","");print $4+$6+$8+$10}'); errs=${errs:-0}
      sleep 2  # let the writer flush
      lines=0; [[ -f $D/$t.jsonl ]] && lines=$(wc -l < $D/$t.jsonl)
      : > $D/$t.jsonl 2>/dev/null
      echo "$route,$t,$((rep+1)),$rps,$p99,$non2xx,$errs,$lines"
    done
  done
done
echo "=== END ==="

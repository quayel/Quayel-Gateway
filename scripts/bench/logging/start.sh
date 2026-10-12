#!/usr/bin/env bash
# Start the four logging bench instances and smoke-test them.
# Usage: start.sh <baseline-binary> <new-binary>   (configs from make_configs.py, in $LOG_BENCH_DIR)
# Run from the repo root so the gateway finds its data files.
set -u
D="${LOG_BENCH_DIR:-/tmp/qg-log-bench}"
cp "$1" "$D/qg-base"   # copies, so a rebuild can't swap a binary mid-run
cp "$2" "$D/qg-new"
ulimit -n 100000
for t in base-off base-log new-off new-log; do
  setsid nohup "$D/qg-${t%-*}" "$D/$t.json" > "$D/$t.out" 2>&1 &
done
sleep 6
declare -A PORT=( [base-off]=8092 [base-log]=8094 [new-off]=8089 [new-log]=8095 )
for t in base-off base-log new-off new-log; do
  p=${PORT[$t]}
  a=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/cache-test")
  c=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/no-cache")
  echo "$t:$p cache-test=$a no-cache=$c"
done

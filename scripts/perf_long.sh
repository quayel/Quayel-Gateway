#!/usr/bin/env bash
# perf_long.sh <label> <route>
# One long wrk run (60s) with perf counting the middle 45s. Gives a much
# more stable instructions-per-request number than short windows.
set -u
LABEL="${1:-perf}"
ROUTE="${2:-/cache-test}"
BASE="http://127.0.0.1:8089"
PID="${GW_PID:-$(ss -ltnp 2>/dev/null | grep ':8089' | grep -oP 'pid=\K[0-9]+' | head -1)}"
if [ -z "$PID" ]; then echo "gateway not running"; exit 1; fi

# warmup
wrk -t12 -c1000 -d3s "$BASE$ROUTE" >/dev/null 2>&1

wrk -t12 -c1000 -d60s "$BASE$ROUTE" > /tmp/wrk-out.txt 2>/dev/null &
WRK_PID=$!
sleep 7
perf stat -p "$PID" -e instructions,cycles,context-switches -- sleep 45 2>/tmp/perf-raw.txt
wait $WRK_PID 2>/dev/null

REQS=$(awk '/requests in/ {print $1}' /tmp/wrk-out.txt)
RPS=$(awk '/Requests\/sec/ {print $2}' /tmp/wrk-out.txt)
INSTR=$(grep -E "instructions" /tmp/perf-raw.txt | head -1 | awk '{print $1}' | tr -d ',')
# REQS over 60s; perf window 45s → requests in window ≈ REQS * 45/60
if [ -n "$INSTR" ] && [ "$REQS" -gt 0 ] 2>/dev/null; then
  IPR=$(awk "BEGIN{printf \"%.0f\", $INSTR / ($REQS * 45.0 / 60.0)}")
else
  IPR="n/a"
fi
echo "$LABEL,$ROUTE,rps=$RPS,instr_per_req=$IPR,instructions=$INSTR"
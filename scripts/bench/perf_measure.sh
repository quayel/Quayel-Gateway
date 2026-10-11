#!/usr/bin/env bash
# perf_measure.sh <label> <route> [reps]
# Runs wrk against the gateway while counting instructions/cycles on the
# gateway process via perf stat. Reports RPS and instructions-per-request —
# the latter is a stable metric that is robust against shared-host noise.
#
# Method: wrk runs 14s; perf counts the middle 10s (after connection ramp-up,
# before teardown) so both windows cover the same steady-state traffic.
set -u
LABEL="${1:-perf}"
ROUTE="${2:-/cache-test}"
REPS="${3:-1}"
BASE="http://127.0.0.1:8089"
PID="${GW_PID:-$(ss -ltnp 2>/dev/null | grep ':8089' | grep -oP 'pid=\K[0-9]+' | head -1)}"
if [ -z "$PID" ]; then echo "gateway not running"; exit 1; fi

for ((i=0;i<REPS;i++)); do
  # warmup
  wrk -t12 -c1000 -d3s "$BASE$ROUTE" >/dev/null 2>&1

  wrk -t12 -c1000 -d14s "$BASE$ROUTE" > /tmp/wrk-out.txt 2>/dev/null &
  WRK_PID=$!
  sleep 2
  perf stat -p "$PID" -e instructions,cycles,context-switches -- sleep 10 2>/tmp/perf-raw.txt
  wait $WRK_PID 2>/dev/null

  REQS=$(awk '/requests in/ {print $1}' /tmp/wrk-out.txt)
  RPS=$(awk '/Requests\/sec/ {print $2}' /tmp/wrk-out.txt)
  INSTR=$(grep -E "instructions" /tmp/perf-raw.txt | head -1 | awk '{print $1}' | tr -d ',')
  CYCLES=$(grep -E "^ *[0-9,]+ +cycles" /tmp/perf-raw.txt | head -1 | awk '{print $1}' | tr -d ',')
  if [ -n "$INSTR" ] && [ "$REQS" -gt 0 ] 2>/dev/null; then
    IPR=$(awk "BEGIN{printf \"%.0f\", $INSTR / ($REQS * 10 / 14)}")
  else
    IPR="n/a"
  fi
  echo "$LABEL,$ROUTE,run=$((i+1)),rps=$RPS,instr_per_req=$IPR,instructions=$INSTR,cycles=$CYCLES"
done

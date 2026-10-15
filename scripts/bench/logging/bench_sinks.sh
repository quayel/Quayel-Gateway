#!/usr/bin/env bash
# Cost of log sinks: one build, four instances, interleaved.
#   off        access log off
#   file       file only
#   clickhouse file + clickhouse sink (local ClickHouse in Docker)
#   http       file + http sink (local mock that answers 200 at once)
# wrk -t12 -c1000 -d10s --latency (benchmark-protocol.md). After each run the
# script waits for the sinks to drain and reports lines sent / dropped from
# /metrics, so a run that is fast because it drops lines shows up.
# Usage: bench_sinks.sh <binary> [reps]   (run from the repo root; needs Docker)
set -u
BIN="$1"
REPS="${2:-5}"
ROUTES=(${ROUTES_OVERRIDE:-/cache-test /no-cache})
D="${SINK_BENCH_DIR:-/tmp/qg-sink-bench}"
CH=qg-sink-bench-ch
CH_PORT=18123
MOCK_PORT=18124
TARGETS=(off file clickhouse http)
declare -A PORT=( [off]=8092 [file]=8094 [clickhouse]=8096 [http]=8098 )
declare -A METRICS=( [off]=9472 [file]=9474 [clickhouse]=9476 [http]=9478 )

mkdir -p "$D"
cp "$BIN" "$D/qg"   # a copy, so a rebuild can't swap the binary mid-run

docker rm -f "$CH" >/dev/null 2>&1
docker run -d --name "$CH" -p "127.0.0.1:$CH_PORT:8123" \
  -e CLICKHOUSE_SKIP_USER_SETUP=1 --ulimit nofile=262144:262144 \
  clickhouse/clickhouse-server:latest >/dev/null
for _ in $(seq 60); do curl -sf "http://127.0.0.1:$CH_PORT/ping" >/dev/null && break; sleep 1; done
docker exec -i "$CH" clickhouse-client --multiquery < scripts/clickhouse/access_log.sql

# Mock http sink: reads the body, answers 204.
python3 - "$MOCK_PORT" > "$D/mock.out" 2>&1 <<'EOF' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(204); self.send_header("content-length", "0"); self.end_headers()
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
MOCK_PID=$!

python3 - "$D" "$CH_PORT" "$MOCK_PORT" <<'EOF'
import copy, json, sys
d, ch, mock = sys.argv[1], sys.argv[2], sys.argv[3]
base = json.load(open("config.json"))
ports = {"off": 8092, "file": 8094, "clickhouse": 8096, "http": 8098}
for name, port in ports.items():
    c = copy.deepcopy(base)
    c["listen"] = {"http": f"0.0.0.0:{port}", "https": f"0.0.0.0:{port + 1000}"}
    c["metrics"] = {"listen": f"127.0.0.1:{port + 1380}"}
    if "auto_ssl" in c["plugins"]:
        c["plugins"]["auto_ssl"]["enabled"] = False
    log = {"enabled": name != "off", "file": {"path": f"{d}/{name}.jsonl"}}
    if name == "clickhouse":
        log["sinks"] = [{"type": "clickhouse", "url": f"http://127.0.0.1:{ch}", "database": "qg"}]
    if name == "http":
        log["sinks"] = [{"type": "http", "url": f"http://127.0.0.1:{mock}/"}]
    c["plugins"]["logging"] = log
    json.dump(c, open(f"{d}/{name}.json", "w"), indent=1)
EOF

ulimit -n 100000
PIDS=()
for t in "${TARGETS[@]}"; do
  setsid nohup "$D/qg" --config "$D/$t.json" > "$D/$t.out" 2>&1 &
  PIDS+=($!)
done
cleanup() { kill "${PIDS[@]}" "$MOCK_PID" 2>/dev/null; docker rm -f "$CH" >/dev/null 2>&1; }
trap cleanup EXIT
sleep 6
for t in "${TARGETS[@]}"; do
  echo "# $t :${PORT[$t]} cache-test=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT[$t]}/cache-test")" >&2
done

sink_lines() {  # sent dropped for one instance (0 0 without sinks)
  curl -s "http://127.0.0.1:${METRICS[$1]}/metrics" | awk '
    /^qg_log_sink_lines_total/ && /result="sent"/ {s += $NF}
    /^qg_log_sink_lines_total/ && /result="dropped"/ {d += $NF}
    END {printf "%d %d", s, d}'
}

echo "route,target,rep,rps,p99,non2xx,errors,file_lines,sink_sent,sink_dropped"
for route in "${ROUTES[@]}"; do
  for t in "${TARGETS[@]}"; do wrk -t12 -c1000 -d2s "http://127.0.0.1:${PORT[$t]}$route" >/dev/null 2>&1; done
  sleep 5; for f in "$D"/*.jsonl; do : > "$f"; done
  for ((rep=0; rep<REPS; rep++)); do
    for ((k=0; k<${#TARGETS[@]}; k++)); do
      t="${TARGETS[$(( (rep + k) % ${#TARGETS[@]} ))]}"
      read -r s0 d0 <<< "$(sink_lines "$t")"
      out=$(wrk -t12 -c1000 -d10s --latency "http://127.0.0.1:${PORT[$t]}$route" 2>/dev/null)
      rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
      p99=$(echo "$out" | awk '/^ *99%/ {print $2; exit}')
      non2xx=$(echo "$out" | awk '/Non-2xx/ {print $NF}'); non2xx=${non2xx:-0}
      errs=$(echo "$out" | awk '/Socket errors/ {gsub(",","");print $4+$6+$8+$10}'); errs=${errs:-0}
      sleep 8  # let the file writer and the sink catch up
      lines=0; [[ -f $D/$t.jsonl ]] && lines=$(wc -l < "$D/$t.jsonl")
      : > "$D/$t.jsonl" 2>/dev/null
      read -r s1 d1 <<< "$(sink_lines "$t")"
      echo "$route,$t,$((rep+1)),$rps,$p99,$non2xx,$errs,$lines,$((s1 - s0)),$((d1 - d0))"
    done
  done
done
echo "# clickhouse rows: $(curl -s "http://127.0.0.1:$CH_PORT/" --data 'SELECT count() FROM qg.access_log')" >&2
echo "=== END ==="

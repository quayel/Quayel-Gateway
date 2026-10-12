#!/usr/bin/env python3
"""Summarise a bench_log.sh CSV: medians per route/target and paired deltas."""
import csv, statistics, sys
from collections import defaultdict

def ms(v):
    v = v.strip()
    if v.endswith("us"): return float(v[:-2]) / 1000
    if v.endswith("ms"): return float(v[:-2])
    if v.endswith("s"): return float(v[:-1]) * 1000
    return float(v)

rows = [r for r in csv.reader(open(sys.argv[1])) if r and r[0].startswith("/")]
d = defaultdict(dict)  # (route,target) -> rep -> (rps,p99,non2xx,err,lines)
for route, t, rep, rps, p99, n2, err, lines in rows:
    d[(route, t)][int(rep)] = (float(rps), ms(p99), int(n2), int(err), int(lines))

routes = sorted({k[0] for k in d}, key=lambda r: (r != "/cache-test", r))
print(f"{'route':<20}{'target':<10}{'rps':>9}{'p99 ms':>8}{'non2xx':>8}{'err':>5}{'logged':>9}")
for route in routes:
    for t in ["base-off", "new-off", "base-log", "new-log"]:
        cur = d.get((route, t))
        if not cur: continue
        rps = statistics.median(v[0] for v in cur.values())
        p99 = statistics.median(v[1] for v in cur.values())
        n2 = sum(v[2] for v in cur.values()); er = sum(v[3] for v in cur.values())
        # lines written / requests served (wrk -d10s), to spot dropped events
        logged = "" if t.endswith("off") else f"{statistics.median(v[4] / (v[0] * 10) for v in cur.values()) * 100:.0f}%"
        print(f"{route:<20}{t:<10}{rps:>9,.0f}{p99:>8.1f}{n2:>8}{er:>5}{logged:>9}")

print()
print(f"{'route':<20}{'comparison':<24}{'paired Δ rps':>13}{'wins':>7}")
for route in routes:
    for a, b, label in [("new-off", "base-off", "new vs base (log off)"),
                        ("new-log", "base-log", "new vs base (log on)"),
                        ("base-log", "base-off", "logging cost (base)"),
                        ("new-log", "new-off", "logging cost (new)")]:
        A, B = d.get((route, a)), d.get((route, b))
        if not A or not B: continue
        pr = [A[r][0] / B[r][0] - 1 for r in A if r in B]
        print(f"{route:<20}{label:<24}{statistics.median(pr) * 100:>+12.1f}%{sum(1 for x in pr if x > 0):>4}/{len(pr)}")

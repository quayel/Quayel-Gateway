#!/usr/bin/env python3
"""Summarise a bench_jwt.sh CSV: medians per route/target and paired delta vs 'none'."""
import csv, statistics, sys
from collections import defaultdict

def ms(v):
    v = v.strip()
    if v.endswith("us"): return float(v[:-2]) / 1000
    if v.endswith("ms"): return float(v[:-2])
    if v.endswith("s"): return float(v[:-1]) * 1000
    return float(v)

rows = [r for r in csv.reader(open(sys.argv[1])) if r and r[0].startswith("/")]
d = defaultdict(dict)  # (route,target) -> rep -> (rps,p50,p99,non2xx,err)
for route, t, rep, rps, p50, p99, n2, err in rows:
    d[(route, t)][int(rep)] = (float(rps), ms(p50), ms(p99), int(n2), int(err))

routes = sorted({k[0] for k in d}, key=lambda r: r != "/cache-test")
targets = ["none", "decode", "hs256", "rs256"]
print(f"{'route':<12}{'target':<8}{'rps':>9}{'Δ vs none':>11}{'paired Δ':>10}{'p50 ms':>8}{'p99 ms':>8}{'wins':>6}{'non2xx':>8}{'err':>6}")
for route in routes:
    base = d[(route, "none")]
    for t in targets:
        cur = d.get((route, t))
        if not cur: continue
        rps = statistics.median(v[0] for v in cur.values())
        p50 = statistics.median(v[1] for v in cur.values())
        p99 = statistics.median(v[2] for v in cur.values())
        n2 = sum(v[3] for v in cur.values()); er = sum(v[4] for v in cur.values())
        if t == "none":
            delta = paired = "—"; wins = ""
        else:
            b = statistics.median(v[0] for v in base.values())
            delta = f"{(rps / b - 1) * 100:+.1f}%"
            pr = [cur[r][0] / base[r][0] - 1 for r in cur if r in base]
            paired = f"{statistics.median(pr) * 100:+.1f}%"
            wins = f"{sum(1 for x in pr if x > 0)}/{len(pr)}"
        print(f"{route:<12}{t:<8}{rps:>9,.0f}{delta:>11}{paired:>10}{p50:>8.1f}{p99:>8.1f}{wins:>6}{n2:>8}{er:>6}")

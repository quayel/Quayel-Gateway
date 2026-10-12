# Benchmark results

| File | Date | What it is |
|---|---|---|
| `gateway-vs-nginx-20261011.csv` | 2026-10-11 | **Current.** v0.3.0 vs Nginx 1.31.6, 10 interleaved reps per route. This is the run the README's "Performance vs Nginx" section quotes. |
| `jwt-cost-20261012-before-cache.csv` | 2026-10-12 | **Current.** Cost of JWT rules on one build: no rule vs decode-only vs HS256 vs RS256 verification, 10 interleaved reps per route, every token verified on every request. Run with `scripts/bench/jwt/`. |
| `jwt-cost-20261012-after-cache.csv` | 2026-10-12 | **Current.** Same run with the verified-token cache (`jwt.verified_cache_size`) on. |
| `apisix-vs-gateway-nginx.txt` | 2026-10-09 | Historical. Older build vs APISIX and Nginx on a busier box (~40k rps for everyone). Superseded by the run above. |
| `gateway-iter3-vs-nginx.txt` | 2026-10-09 | Historical. Older build ("iter3") vs Nginx, median of 10. Superseded. |
| `nginx-mirror.txt` | 2026-10-09 | Historical. Nginx side of the run above. |

Numbers from different dates aren't comparable: the box, its load and the
gateway build all changed. Compare only targets measured in the same run.

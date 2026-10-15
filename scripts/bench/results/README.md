# Benchmark results

| File | Date | What it is |
|---|---|---|
| `gateway-vs-nginx-20261011.csv` | 2026-10-11 | **Current.** v0.3.0 vs Nginx 1.31.6, 10 interleaved reps per route. This is the run the README's "Performance vs Nginx" section quotes. |
| `jwt-cost-20261012-before-cache.csv` | 2026-10-12 | **Current.** Cost of JWT rules on one build: no rule vs decode-only vs HS256 vs RS256 verification, 10 interleaved reps per route, every token verified on every request. Run with `scripts/bench/jwt/`. |
| `jwt-cost-20261012-after-cache.csv` | 2026-10-12 | **Current.** Same run with the verified-token cache (`jwt.verified_cache_size`) on. |
| `logging-cost-20261012.csv` | 2026-10-12 | **Current.** Logging rework (bounded queue, request IDs, new fields) vs the previous build (`8da7e68`), each with the access log off and on, 10 interleaved reps per route. Run with `scripts/bench/logging/`. |
| `logging-writer-thread-20261012.csv` | 2026-10-12 | **Current.** Dedicated writer thread + 1 MiB write buffer vs `5b90d72`, same method. New vs old with logging on: +3.9% / −5.2% / +2.2% (noise); write() calls per line ~100× fewer; logging still costs ~10–20% on cache hits because the CPU-bound part is building and serializing events, not writing them. |
| `logging-cost-20261012-confirm.csv` | 2026-10-12 | **Current.** 12-rep rerun of `/cache-test` with the access log off, to check the one route where the first run showed a gap. |
| `sinks-cost-8e5bbc5-20261015.csv` | 2026-10-15 | **Current.** Cost of log sinks on one build (`8e5bbc5`): access log off vs file only vs file + ClickHouse sink (local ClickHouse in Docker) vs file + `http` sink (local mock), 5 interleaved reps per route. Run with `scripts/bench/logging/bench_sinks.sh`. Delivery: 5,757,714 lines sent to the two sinks, 0 dropped. Throughput: the differences between the four (medians 39k–48k on `/cache-test`, 11.6k–13.5k on `/no-cache`) are inside the run-to-run noise (log off ranged 24k–62k), because wrk and ClickHouse share the box's 6 cores with the gateway. Measure from a separate load machine to put a number on the cost. |
| `apisix-vs-gateway-nginx.txt` | 2026-10-09 | Historical. Older build vs APISIX and Nginx on a busier box (~40k rps for everyone). Superseded by the run above. |
| `gateway-iter3-vs-nginx.txt` | 2026-10-09 | Historical. Older build ("iter3") vs Nginx, median of 10. Superseded. |
| `nginx-mirror.txt` | 2026-10-09 | Historical. Nginx side of the run above. |

Numbers from different dates aren't comparable: the box, its load and the
gateway build all changed. Compare only targets measured in the same run.

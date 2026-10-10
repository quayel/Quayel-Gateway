# Benchmark Protocol — quayel-gateway

Written BEFORE any optimization code changes. These rules decide whether a change
is kept (improved), discarded (regressed), or retried (neutral).

## Fixed test parameters (never change mid-experiment)

- Tool: `wrk 4.1.0 [epoll]`
- Command for every run: `wrk -t12 -c1000 -d10s --latency http://127.0.0.1:8089<route>`
  (12 threads, 1000 connections, 10 seconds — same for ALL runs)
- Routes tested every round:
  1. `/cache-test`       (cache hit path)
  2. `/cache-test-second` (cache hit path, second key — note the dash)
  3. `/no-cache`          (cache bypass / origin fetch path)
- Server: release build (`lto = "fat"`, `codegen-units = 1`), started with
  `ulimit -n 100000`, same `config.json`, same backend (94.136.185.15:4489).
- Machine: 6 vCPU, no other load during runs. Nothing else touches port 8089.

## Round procedure (identical for baseline and every iteration)

1. Build + restart the gateway fresh (cold cache).
2. Warm-up: 2s `wrk -t12 -c1000 -d2s` per route (results discarded — primes cache
   and connection pools).
3. Measure: one 10s run per route (3 measured runs per round).
4. Record Requests/sec (primary metric) and p99 latency (guard metric) per route.

## Acceptance rules (how we judge RPS deltas)

Let `Δ% = (new_rps − prev_rps) / prev_rps × 100` per route, compared against the
previous round's measured values (baseline round = the reference for iteration 1,
then chained).

- **Noise band: ±2%.** RPS changes smaller than 2% on a route are treated as noise,
  not signal. Same duration, same params, same machine state every run.
- **IMPROVED (keep the change):**
  - mean Δ% across the 3 routes ≥ +2%, AND
  - no single route regressed by more than −2%, AND
  - p99 latency did not get worse by more than 10% on any route.
- **REGRESSED (revert the change):**
  - mean Δ% ≤ −2%, or any single route ≤ −2%.
- **NEUTRAL (within ±2% on most routes):** treat as no-win; revert and try a
  different change (we don't stack unproven tweaks).
- Secondary guard: if RPS is flat but p99 latency worsens >10% on a route,
  the change is rejected.

## Reporting

After every measured run, report an RPS delta table: route, RPS this round,
RPS previous round, Δ%, verdict (improved / regressed / neutral). At the end,
a per-iteration table plus a clear statement of which changes helped or hurt.

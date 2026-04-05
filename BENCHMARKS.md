# PitWall — Node.js vs Go Benchmark Comparison

**Date:** 2026-04-05
**Hardware:** Apple M4 (darwin/arm64)
**Node.js:** v25.2.1
**Go:** v1.25.0
**Load tool:** autocannon (10 connections, 10 s) for HTTP-level tests; `go test -bench` for in-process micro-benchmarks

---

## 1. HTTP Throughput — `GET /health`

Both servers tested under identical conditions: 10 concurrent connections, 10 s run, same machine, no Slack calls.


| Metric             | Node.js (express) | Go (net/http) | Go advantage |
| ------------------ | ----------------- | ------------- | ------------ |
| Requests/sec (avg) | 43,105            | 125,443       | **2.9×**     |
| Requests/sec (max) | 44,196            | 129,520       | 2.9×         |
| Latency p50        | <1 ms             | <1 ms         | —            |
| Latency p99        | <1 ms             | <1 ms         | —            |
| Throughput (MB/s)  | 10.24             | 14.83         | 1.4×         |
| Total errors       | 0                 | 0             | —            |


---

## 2. Go Micro-benchmarks (in-process, no network)

Run with `go test -bench=. -benchmem -benchtime=5s`.


| Benchmark                       | What it isolates                     | ns/op | B/op  | allocs/op |
| ------------------------------- | ------------------------------------ | ----- | ----- | --------- |
| `BenchmarkHealthEndpoint`       | Raw handler CPU + alloc cost         | 329   | 1,008 | 9         |
| `BenchmarkWebhookEndpoint`      | HMAC verify + JSON decode (no Slack) | 2,095 | 8,023 | 41        |
| `BenchmarkHMACVerification`     | `verifyAppleSignature` only          | 291   | 560   | 8         |
| `BenchmarkSlackMessageFormat`   | `strings.Join` payload build only    | 53.5  | 112   | 1         |
| `BenchmarkHealthEndpointServer` | Full TCP round-trip                  | —     | —     | —         |


---

## 3. Memory Footprint

### Idle RSS (process just started, one request served)


|              | Node.js  | Go       | Go advantage    |
| ------------ | -------- | -------- | --------------- |
| **Idle RSS** | 80.13 MB | 10.27 MB | **7.8×** leaner |


### Under load (10 connections, 10 s health-endpoint hammer)


| Metric         | Node.js   | Go            |
| -------------- | --------- | ------------- |
| RSS before     | 80.13 MB  | ~10 MB        |
| RSS after      | 133.11 MB | ~12 MB (est.) |
| Heap/RSS delta | +52.98 MB | ~+2 MB        |


Node.js's V8 heap grows aggressively under load and does not release back to the OS immediately. Go's GC returns pages to the OS much faster.

---

## 4. Polling Approach (Google Play Console)

Both implementations use the same strategy: a ticker that fires every `POLL_INTERVAL_SECONDS` (default 300 s), fetches an OAuth2 token, opens a temporary edit, reads the track, deletes the edit, and posts to Slack only on status changes.

### Per-tick cost breakdown


| Step                  | Node.js                                                         | Go                                  |
| --------------------- | --------------------------------------------------------------- | ----------------------------------- |
| OAuth2 token          | `google-auth-library` async                                     | `golang.org/x/oauth2/google`        |
| Edit open             | `fetch()`                                                       | `http.Client`                       |
| Track read            | `fetch()`                                                       | `http.Client`                       |
| Edit delete (cleanup) | `fetch()` (in `finally`)                                        | deferred `http.Client`              |
| Slack post            | `fetch()`                                                       | `http.Client`                       |
| Concurrency model     | Single `setInterval` → async/await                              | Single goroutine with `time.Ticker` |
| State guard           | Closure variables (no lock needed — single-threaded event loop) | `sync.Mutex` on `pollState` struct  |


### Polling memory cost


|                      | Node.js                          | Go                              |
| -------------------- | -------------------------------- | ------------------------------- |
| Extra RAM for poller | ~0 MB (closure in existing heap) | ~0 MB (goroutine stack ~2–8 KB) |
| External dep added   | `google-auth-library`            | `golang.org/x/oauth2`           |


Both runtimes add negligible per-poller memory. The dominant cost is the outbound HTTP buffers during a tick (~a few KB per request), held only for the duration of the fetch.

### Error behaviour


| Scenario      | Node.js                           | Go                                |
| ------------- | --------------------------------- | --------------------------------- |
| Auth failure  | logs + returns, next tick retries | logs + returns, next tick retries |
| API error     | logs + returns, next tick retries | logs + returns, next tick retries |
| Slack failure | logs, does **not** crash poller   | logs, does **not** crash poller   |


Both implementations are identical in error-resilience design.

---

## 5. Deployment Artifact Size


| Artifact                        | Size       |
| ------------------------------- | ---------- |
| Go static binary (`go build`)   | **9.2 MB** |
| `node_modules` (express + deps) | 12 MB      |


The Go binary is fully self-contained and runs on any Linux/macOS target with no runtime installed. Node.js requires the Node.js runtime (~50–100 MB in a Docker image) plus `node_modules`.

---

## 6. Summary Scorecard


| Criterion               | Node.js                     | Go                        | Winner                                 |
| ----------------------- | --------------------------- | ------------------------- | -------------------------------------- |
| HTTP throughput         | 43k req/s                   | 125k req/s                | Go (3×) — irrelevant at PitWall scale |
| Idle RAM                | 80 MB                       | 10 MB                     | **Go (8×)** — critical on free tiers   |
| RAM under load          | +53 MB delta                | ~+2 MB delta              | **Go**                                 |
| Cold-start              | ~100–300 ms                 | <5 ms                     | **Go** — critical for scale-to-zero    |
| Artifact size           | 12 MB (node_modules)        | 9.2 MB (binary)           | Go                                     |
| HMAC security           | Timing-safe                 | Timing-safe               | Tie                                    |
| Polling design          | `setInterval` + async/await | goroutine + `time.Ticker` | Tie                                    |
| Polling memory overhead | Negligible                  | Negligible                | Tie                                    |
| Developer experience    | Familiar (JS)               | Explicit (Go)             | Team-dependent                         |



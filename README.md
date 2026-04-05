# PitWall

Automated push notifications for App Store and Google Play status changes, delivered to Slack.

When Apple approves or rejects your app, or when your Google Play release moves between tracks, PitWall fires a Slack message instantly — no more manually refreshing App Store Connect or the Play Console.

```
Apple App Store Connect  ──webhook──▶  PitWall  ──▶  Slack
Google Play Console      ──polling──▶  PitWall  ──▶  Slack
```

---

## How it works

**Apple (webhook):** App Store Connect sends a signed HTTP POST to your `/webhook` endpoint whenever a submission status changes. PitWall verifies the HMAC-SHA256 signature and forwards the event to Slack.

**Google Play (polling):** The Play Console does not support outbound webhooks, so PitWall polls the `androidpublisher` API on a configurable interval (default: every 60 minutes) and posts to Slack only when the release status changes.

---

## Prerequisites

- [Go 1.25+](https://go.dev/dl/) — that is the only thing you need installed. Go produces a single binary with no runtime dependencies.
- A Slack incoming webhook URL ([create one here](https://api.slack.com/messaging/webhooks)).
- For Apple: a shared webhook secret configured in App Store Connect.
- For Google Play: a Google service account JSON key with `androidpublisher` read access.

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/your-username/pitwall
cd pitwall

# 2. Copy the example env file and fill in your values
cp .env.example .env
# edit .env with your editor

# 3. Run
make run
```

The server starts on port `3000` by default. You should see:

```
[PitWall-go] listening on :3000
```

---

## Environment variables

Copy `.env.example` to `.env` and set these values:

| Variable | Required | Description |
|---|---|---|
| `APPLE_WEBHOOK_SECRET` | Yes (Apple) | Shared secret from App Store Connect — used to verify the HMAC signature on every incoming webhook |
| `SLACK_WEBHOOK_URL` | Yes | Your Slack incoming webhook URL |
| `GOOGLE_CREDENTIALS_FILE` | Only for Play | Path to your Google service account JSON key file (e.g. `./creds.json`) |
| `PLAY_PACKAGE_NAME` | Only for Play | Your app's package name, e.g. `com.example.myapp` |
| `PLAY_TRACK` | No | Which Play track to watch — defaults to `production` |
| `POLL_INTERVAL_SECONDS` | No | How often to poll the Play API — defaults to `300` (5 minutes) |
| `PORT` | No | Port to listen on — defaults to `3000` |

The Apple webhook and Google Play poller are independent — you can run either or both. The server will warn at startup if a variable is missing.

---

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/webhook` | Receives App Store Connect webhook events |
| `GET` | `/health` | Returns `{"status":"ok"}` — use this for uptime checks |

### Webhook security

Every request to `/webhook` must include an `X-Apple-Signature` header containing the HMAC-SHA256 hex digest of the raw request body, keyed with `APPLE_WEBHOOK_SECRET`. Requests with a missing or invalid signature are rejected with `401 Unauthorized`. This prevents anyone else from spoofing App Store events.

---

## Development commands

```bash
make run    # start the server (loads .env automatically)
make build  # compile a binary named `pitwall`
make test   # run all tests
make bench  # run benchmarks with memory stats
make clean  # remove the compiled binary
```

### Running tests directly

```bash
go test ./...
```

Go's test runner is built in — no test framework to install. The test file is `benchmark_test.go` and covers HMAC verification, the health handler, and all webhook handler edge cases.

---

## Deploying

PitWall compiles to a single static binary. There is no runtime to install on the server.

### Fly.io (recommended for scale-to-zero)

```bash
fly launch   # creates fly.toml
fly secrets set APPLE_WEBHOOK_SECRET=... SLACK_WEBHOOK_URL=...
fly deploy
```

### Docker

```dockerfile
FROM golang:1.25 AS builder
WORKDIR /app
COPY . .
RUN go build -o pitwall .

FROM scratch
COPY --from=builder /app/pitwall /pitwall
ENTRYPOINT ["/pitwall"]
```

Because Go compiles to a static binary, you can use `FROM scratch` — the resulting image is ~10 MB total with no OS layer.

### Any Linux server

```bash
GOOS=linux GOARCH=amd64 go build -o pitwall .
scp pitwall user@your-server:/usr/local/bin/pitwall
```

---

## Project structure

```
pitwall/
├── main.go            — HTTP server, HMAC verification, Apple webhook handler
├── play_poller.go     — Google Play Console polling loop
├── benchmark_test.go  — unit tests and benchmarks
├── go.mod             — Go module file (think of this as package.json for Go)
├── go.sum             — dependency checksums (committed, do not edit manually)
├── Makefile           — common dev commands
├── .env.example       — template for your .env file
├── BENCHMARKS.md      — Go vs Node.js benchmark results
└── LICENSE
```



---

## Benchmarks

See [BENCHMARKS.md](./BENCHMARKS.md) for a full comparison of the Go and Node.js prototypes. Short version: Go uses ~10 MB RAM at idle vs ~80 MB for Node.js, and cold-starts in under 5 ms vs 100–300 ms.

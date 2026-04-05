// Package main implements the PitWall webhook service.
//
// Endpoints:
//
//	POST /webhook  — verify Apple HMAC-SHA256, parse body, notify Slack
//	GET  /health   — returns {"status":"ok"}
//
// Required env vars:
//
//	APPLE_WEBHOOK_SECRET  — shared secret used for HMAC verification
//	SLACK_WEBHOOK_URL     — incoming webhook URL for Slack notifications
//
// Optional env vars:
//
//	PORT  — TCP port to listen on (default: 3000)
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	AppleWebhookSecret string
	SlackWebhookURL    string
	Port               string
}

func loadConfig() config {
	c := config{
		AppleWebhookSecret: os.Getenv("APPLE_WEBHOOK_SECRET"),
		SlackWebhookURL:    os.Getenv("SLACK_WEBHOOK_URL"),
		Port:               os.Getenv("PORT"),
	}
	if c.Port == "" {
		c.Port = "3000"
	}
	if c.AppleWebhookSecret == "" {
		log.Println("[warn] APPLE_WEBHOOK_SECRET is not set — all signatures will fail")
	}
	if c.SlackWebhookURL == "" {
		log.Println("[warn] SLACK_WEBHOOK_URL is not set — Slack notifications will be skipped")
	}
	return c
}

// ── Domain types ──────────────────────────────────────────────────────────────

// webhookPayload represents the JSON body Apple sends to the webhook endpoint.
type webhookPayload struct {
	AppName     string `json:"app_name"`
	Status      string `json:"status"`
	Environment string `json:"environment"`
}

// slackMessage is the payload sent to the Slack incoming webhook.
type slackMessage struct {
	Text string `json:"text"`
}

// apiResponse is the JSON shape returned from /webhook and /health.
type apiResponse struct {
	OK     bool   `json:"ok,omitempty"`
	Status string `json:"status,omitempty"`
	App    string `json:"app,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ── HMAC verification ─────────────────────────────────────────────────────────

// verifyAppleSignature returns true when the X-Apple-Signature header matches
// an HMAC-SHA256 over rawBody keyed with secret.
//
// Apple sends the digest as lowercase hex. The comparison uses hmac.Equal so
// it is inherently timing-safe.
func verifyAppleSignature(rawBody []byte, signatureHeader, secret string) bool {
	if secret == "" || signatureHeader == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	incoming := strings.TrimSpace(signatureHeader)

	// Decode from hex; fall through to a zero-length slice on error so the
	// timing-safe comparison still runs (and returns false) without branching.
	decoded, err := hex.DecodeString(incoming)
	if err != nil {
		// Header may be base64 — not Apple's documented format, but be lenient.
		decoded = []byte{}
	}

	return hmac.Equal(expected, decoded)
}

// ── Slack notification ────────────────────────────────────────────────────────

// A single shared HTTP client is reused across all Slack calls so that
// TCP connections are pooled rather than opened per request.
var slackClient = &http.Client{
	Timeout: 5 * time.Second,
}

// postToSlack sends a formatted message to the Slack incoming webhook.
func postToSlack(webhookURL, appName, status, environment string) error {
	if webhookURL == "" {
		return nil
	}

	text := fmt.Sprintf(
		"🚦 *PitWall* | App Store Update\n*App:* %s\n*Status:* %s\n*Environment:* %s",
		appName, status, environment,
	)

	payload, err := json.Marshal(slackMessage{Text: text})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	resp, err := slackClient.Post(webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack post: %w", err)
	}
	defer resp.Body.Close()
	// Drain so the connection can be reused by the pool.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// writeJSON encodes v as JSON and writes it with the given status code.
// It sets Content-Type so callers do not have to remember.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[error] writeJSON encode: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{Status: "ok"})
}

// newWebhookHandler closes over cfg so the handler is a plain function value —
// no global state, easy to test.
func newWebhookHandler(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		// Buffer the entire body so we can run HMAC over the exact bytes that
		// were transmitted, then also JSON-decode from the same buffer.
		// Cap at 1 MB to protect against runaway clients.
		const maxBodyBytes = 1 << 20
		rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			log.Printf("[error] read body: %v", err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "body read error"})
			return
		}

		sig := r.Header.Get("X-Apple-Signature")
		if !verifyAppleSignature(rawBody, sig, cfg.AppleWebhookSecret) {
			writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid signature"})
			return
		}

		var payload webhookPayload
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
			return
		}

		// Apply sensible defaults for optional fields.
		if payload.AppName == "" {
			payload.AppName = "unknown"
		}
		if payload.Status == "" {
			payload.Status = "unknown"
		}
		if payload.Environment == "" {
			payload.Environment = "production"
		}

		if err := postToSlack(cfg.SlackWebhookURL, payload.AppName, payload.Status, payload.Environment); err != nil {
			log.Printf("[error] Slack notification failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "slack notification failed"})
			return
		}

		writeJSON(w, http.StatusOK, apiResponse{OK: true, App: payload.AppName, Status: payload.Status})
	}
}

// ── Server bootstrap ──────────────────────────────────────────────────────────

// NewServer constructs and returns a configured *http.ServeMux so tests can
// create a server without binding a port.
func NewServer(cfg config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/webhook", newWebhookHandler(cfg))
	return mux
}

func main() {
	cfg := loadConfig()

	mux := NewServer(cfg)

	// Start the Google Play release status poller only when a credentials file
	// has been configured so the server stays functional in Apple-only deploys.
	if os.Getenv("GOOGLE_CREDENTIALS_FILE") != "" {
		startPlayPoller(cfg)
	}

	addr := ":" + cfg.Port
	log.Printf("[PitWall-go] listening on %s", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[fatal] server error: %v", err)
	}
}

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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
		slog.Warn("APPLE_WEBHOOK_SECRET not set — all signatures will fail")
	}
	if c.SlackWebhookURL == "" {
		slog.Warn("SLACK_WEBHOOK_URL not set — Slack notifications will be skipped")
	}
	return c
}

// ── Domain types ──────────────────────────────────────────────────────────────

// webhookPayload represents the JSON body Apple sends to the webhook endpoint.
// Shape reference: App Store Connect webhook notifications.
type webhookPayload struct {
	Data struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Version    int    `json:"version"`
		Attributes struct {
			// buildUploadStateUpdated fields
			OldState string `json:"oldState"`
			NewState string `json:"newState"`
			// appStoreVersionAppVersionStateUpdated fields
			OldValue string `json:"oldValue"`
			NewValue string `json:"newValue"`
		} `json:"attributes"`
		Relationships struct {
			Instance struct {
				Data struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
			} `json:"instance"`
		} `json:"relationships"`
	} `json:"data"`
}

// slackMessage is the payload sent to the Slack incoming webhook.
// Uses the attachments + Block Kit format so callers can set a color bar.
type slackMessage struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

// appleStateColor maps an Apple build/version state to a Slack attachment color.
func appleStateColor(state string) string {
	switch strings.ToUpper(state) {
	case "COMPLETE", "READY_FOR_DISTRIBUTION", "APPROVED":
		return "#2eb886" // green
	case "PROCESSING", "IN_REVIEW", "WAITING_FOR_REVIEW", "PENDING_DEVELOPER_RELEASE":
		return "#f2c744" // yellow
	case "FAILED", "REJECTED", "INVALID_BINARY", "DEVELOPER_REJECTED":
		return "#e01e5a" // red
	default:
		return "#a8a8a8" // grey
	}
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
	// Apple sends the value as "hmacsha256=<hex>", strip the prefix if present.
	incoming = strings.TrimPrefix(incoming, "hmacsha256=")

	// Try hex first (most common), then base64.
	// Both comparisons are timing-safe via hmac.Equal.
	if decoded, err := hex.DecodeString(incoming); err == nil {
		if hmac.Equal(expected, decoded) {
			return true
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(incoming); err == nil {
		if hmac.Equal(expected, decoded) {
			return true
		}
	}
	return false
}

// ── Slack notification ────────────────────────────────────────────────────────

// A single shared HTTP client is reused across all Slack calls so that
// TCP connections are pooled rather than opened per request.
var slackClient = &http.Client{
	Timeout: 5 * time.Second,
}

// postToSlack sends a formatted message to the Slack incoming webhook.
func postToSlack(webhookURL, eventType string, version int, oldState, newState, instanceID string) error {
	if webhookURL == "" {
		return nil
	}

	msg := slackMessage{
		Attachments: []slackAttachment{{
			Color: appleStateColor(newState),
			Blocks: []slackBlock{
				{
					Type: "header",
					Text: &slackText{Type: "plain_text", Text: "🚦 PitWall  |  App Store Connect", Emoji: true},
				},
				{
					Type: "section",
					Fields: []slackText{
						{Type: "mrkdwn", Text: fmt.Sprintf("*Event*\n%s  `v%d`", eventType, version)},
						{Type: "mrkdwn", Text: fmt.Sprintf("*State*\n%s  →  *%s*", oldState, newState)},
					},
				},
				{
					Type: "section",
					Fields: []slackText{
						{Type: "mrkdwn", Text: fmt.Sprintf("*Instance ID*\n`%s`", instanceID)},
					},
				},
			},
		}},
	}

	payload, err := json.Marshal(msg)
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
		slog.Error("writeJSON encode failed", "error", err)
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
		slog.Info("apple webhook: raw body", "rawBody", string(rawBody))
		if err != nil {
			slog.Error("apple webhook: failed to read request body", "error", err)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "body read error"})
			return
		}

		sig := r.Header.Get("X-Apple-Signature")
		slog.Info("apple webhook: incoming headers", "headers", r.Header)
		slog.Info("apple webhook: signature header", "X-Apple-Signature", sig)
		if !verifyAppleSignature(rawBody, sig, cfg.AppleWebhookSecret) {
			slog.Warn("apple webhook: invalid signature",
				"remote_addr", r.RemoteAddr,
				"sig_received", sig,
				"sig_empty", sig == "",
			)
			writeJSON(w, http.StatusUnauthorized, apiResponse{Error: "invalid signature"})
			return
		}

		var payload webhookPayload
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			slog.Error("apple webhook: invalid JSON body", "error", err)
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
			return
		}

		eventType := payload.Data.Type
		version := payload.Data.Version
		instanceID := payload.Data.Relationships.Instance.Data.ID

		// Normalize: buildUploadStateUpdated uses oldState/newState;
		// appStoreVersionAppVersionStateUpdated uses oldValue/newValue.
		oldState := payload.Data.Attributes.OldState
		newState := payload.Data.Attributes.NewState
		if oldState == "" {
			oldState = payload.Data.Attributes.OldValue
		}
		if newState == "" {
			newState = payload.Data.Attributes.NewValue
		}

		slog.Info("apple webhook received",
			"eventType", eventType,
			"version", version,
			"oldState", oldState,
			"newState", newState,
			"instanceID", instanceID,
		)

		if err := postToSlack(cfg.SlackWebhookURL, eventType, version, oldState, newState, instanceID); err != nil {
			slog.Error("apple webhook: Slack notification failed",
				"eventType", eventType,
				"newState", newState,
				"error", err,
			)
			writeJSON(w, http.StatusInternalServerError, apiResponse{Error: "slack notification failed"})
			return
		}

		slog.Info("apple webhook: Slack notification sent",
			"eventType", eventType,
			"newState", newState,
		)
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Status: newState})
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
	initLogger()
	cfg := loadConfig()

	mux := NewServer(cfg)

	// Start the Google Play release status poller when a credentials file and at
	// least one app config env var is present, so the server stays functional
	// in Apple-only deploys.
	if os.Getenv("GOOGLE_CREDENTIALS_FILE") != "" &&
		(os.Getenv("PLAY_APPS") != "" || os.Getenv("PLAY_PACKAGE_NAME") != "") {
		startPlayPoller(cfg)
	}

	addr := ":" + cfg.Port
	slog.Info("PitWall listening", "addr", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

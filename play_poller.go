package main

// play_poller.go — Google Play Console release status poller
//
// Polls the androidpublisher.tracks.get endpoint on a configurable ticker.
// On the first tick it silently seeds the in-memory state. On every subsequent
// tick it posts to Slack only when the release status has changed.
//
// Required fields in config (loaded from env by loadConfig):
//
//	GoogleCredentialsFile — path to a service-account JSON key file
//	PlayPackageName       — e.g. com.formuladream.app
//	PlayTrack             — e.g. production
//	PlayPollInterval      — polling cadence (parsed from POLL_INTERVAL_SECONDS)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
)

const (
	playAPIBase = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications"
	playScope   = "https://www.googleapis.com/auth/androidpublisher"
)

// ── Play API response types ───────────────────────────────────────────────────

type playRelease struct {
	VersionCodes []string `json:"versionCodes"`
	Status       string   `json:"status"`
	Name         string   `json:"name"`
}

type playTrackResponse struct {
	Track    string        `json:"track"`
	Releases []playRelease `json:"releases"`
}

// ── Config extension ─────────────────────────────────────────────────────────
// The fields below are added to the existing config struct via loadPlayConfig,
// which is called from loadConfig.

// playConfig holds the Google Play-specific configuration.
type playConfig struct {
	GoogleCredentialsFile string
	PlayPackageName       string
	PlayTrack             string
	PlayPollInterval      time.Duration
}

// loadPlayConfig reads the Play-related env vars and returns a playConfig.
func loadPlayConfig() playConfig {
	interval := 3600 * time.Second
	if raw := os.Getenv("POLL_INTERVAL_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}

	track := os.Getenv("PLAY_TRACK")
	if track == "" {
		track = "production"
	}

	return playConfig{
		GoogleCredentialsFile: os.Getenv("GOOGLE_CREDENTIALS_FILE"),
		PlayPackageName:       os.Getenv("PLAY_PACKAGE_NAME"),
		PlayTrack:             track,
		PlayPollInterval:      interval,
	}
}

// ── HTTP client (shared with Slack calls) ─────────────────────────────────────

var playHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ── Auth ──────────────────────────────────────────────────────────────────────

// getAccessToken reads the service-account JSON key at path and returns a
// short-lived OAuth2 Bearer token scoped to the Android Publisher API.
func getAccessToken(credentialsFile string) (string, error) {
	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return "", fmt.Errorf("read credentials file: %w", err)
	}

	cfg, err := google.JWTConfigFromJSON(data, playScope)
	if err != nil {
		return "", fmt.Errorf("parse service account JSON: %w", err)
	}

	token, err := cfg.TokenSource(context.Background()).Token()
	if err != nil {
		return "", fmt.Errorf("obtain access token: %w", err)
	}
	return token.AccessToken, nil
}

// ── API call ──────────────────────────────────────────────────────────────────

// fetchTrackStatus calls the Play tracks.get endpoint and returns the status
// and leading version code of the first release in the response.
func fetchTrackStatus(packageName, track, accessToken string) (status, versionCode string, err error) {
	base := fmt.Sprintf("%s/%s/edits", playAPIBase, packageName)
	authHdr := "Bearer " + accessToken

	// 1. Open a temporary edit to read track data.
	editReq, err := http.NewRequest(http.MethodPost, base, strings.NewReader("{}"))
	if err != nil {
		return "", "", fmt.Errorf("build edits.insert request: %w", err)
	}
	editReq.Header.Set("Authorization", authHdr)
	editReq.Header.Set("Content-Type", "application/json")

	editResp, err := playHTTPClient.Do(editReq)
	if err != nil {
		return "", "", fmt.Errorf("edits.insert: %w", err)
	}
	editBody, err := io.ReadAll(editResp.Body)
	editResp.Body.Close()
	if err != nil {
		return "", "", fmt.Errorf("read edits.insert response: %w", err)
	}

	if editResp.StatusCode >= 400 {
		return "", "", fmt.Errorf("edits.insert returned HTTP %d: %s", editResp.StatusCode, string(editBody))
	}

	var editResult struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(editBody, &editResult); err != nil {
		return "", "", fmt.Errorf("decode edit response: %w", err)
	}
	editID := editResult.ID

	// Always delete the edit when done — leaving it open consumes a slot.
	defer func() {
		delReq, _ := http.NewRequest(http.MethodDelete, base+"/"+editID, nil)
		if delReq != nil {
			delReq.Header.Set("Authorization", authHdr)
			resp, _ := playHTTPClient.Do(delReq)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}()

	// 2. Read the track within that edit.
	trackURL := fmt.Sprintf("%s/%s/tracks/%s", base, editID, track)
	trackReq, err := http.NewRequest(http.MethodGet, trackURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build tracks.get request: %w", err)
	}
	trackReq.Header.Set("Authorization", authHdr)

	trackResp, err := playHTTPClient.Do(trackReq)
	if err != nil {
		return "", "", fmt.Errorf("edits.tracks.get: %w", err)
	}
	trackBody, err := io.ReadAll(trackResp.Body)
	trackResp.Body.Close()
	if err != nil {
		return "", "", fmt.Errorf("read tracks.get response: %w", err)
	}

	if trackResp.StatusCode >= 400 {
		return "", "", fmt.Errorf("edits.tracks.get returned HTTP %d: %s", trackResp.StatusCode, string(trackBody))
	}

	var tr playTrackResponse
	if err := json.Unmarshal(trackBody, &tr); err != nil {
		return "", "", fmt.Errorf("decode track response: %w", err)
	}
	if len(tr.Releases) == 0 {
		return "", "", fmt.Errorf("track has no releases")
	}

	latest := tr.Releases[0]
	vc := "unknown"
	if len(latest.VersionCodes) > 0 {
		vc = latest.VersionCodes[0]
	}
	return latest.Status, vc, nil
}

// ── Slack notification ────────────────────────────────────────────────────────

// postPlayToSlack sends a Play Console status-transition message to Slack.
func postPlayToSlack(webhookURL, packageName, track, previousStatus, newStatus, versionCode string) error {
	if webhookURL == "" {
		return nil
	}

	text := fmt.Sprintf(
		"🏁 *PitWall* | Google Play Update\n*App:* %s\n*Track:* %s\n*Status:* %s → %s\n*Version:* %s",
		packageName, track, previousStatus, newStatus, versionCode,
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
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Poller ────────────────────────────────────────────────────────────────────

// pollState holds the in-memory state guarded by a mutex so the ticker
// goroutine and any future goroutines can access it safely.
type pollState struct {
	mu              sync.Mutex
	lastStatus      string // empty string means "not yet seeded"
	lastVersionCode string
	seeded          bool
}

// startPlayPoller spawns a goroutine that polls the Play Console on a ticker.
// It is a no-op (and logs a warning) if GOOGLE_CREDENTIALS_FILE is empty.
// The caller is expected to guard on that env var before calling, but the
// function is defensive as well.
func startPlayPoller(cfg config) {
	pc := loadPlayConfig()

	if pc.GoogleCredentialsFile == "" {
		// Caller should guard, but log clearly in case it reaches here.
		log.Println("[play] GOOGLE_CREDENTIALS_FILE not set — poller will not start")
		return
	}
	if pc.PlayPackageName == "" {
		log.Println("[play] PLAY_PACKAGE_NAME not set — poller will not start")
		return
	}

	state := &pollState{}

	tick := func() {
		accessToken, err := getAccessToken(pc.GoogleCredentialsFile)
		if err != nil {
			log.Printf("[play] auth error: %v", err)
			return
		}

		newStatus, versionCode, err := fetchTrackStatus(pc.PlayPackageName, pc.PlayTrack, accessToken)
		if err != nil {
			log.Printf("[play] API error: %v", err)
			return
		}

		state.mu.Lock()
		defer state.mu.Unlock()

		if !state.seeded {
			// First tick — seed state without notifying.
			state.lastStatus = newStatus
			state.lastVersionCode = versionCode
			state.seeded = true
			log.Printf("[play] initial state — %s (version %s)", newStatus, versionCode)
			return
		}

		if newStatus == state.lastStatus {
			log.Printf("[play] no change — %s", newStatus)
			return
		}

		// Status transition detected.
		previousStatus := state.lastStatus
		state.lastStatus = newStatus
		state.lastVersionCode = versionCode

		log.Printf("[play] status changed: %s → %s (version %s)", previousStatus, newStatus, versionCode)

		if err := postPlayToSlack(cfg.SlackWebhookURL, pc.PlayPackageName, pc.PlayTrack, previousStatus, newStatus, versionCode); err != nil {
			log.Printf("[play] Slack notification failed: %v", err)
			// Do not return an error — a Slack failure must never crash the poller.
		}
	}

	go func() {
		// Run the first tick immediately before the ticker fires.
		tick()

		ticker := time.NewTicker(pc.PlayPollInterval)
		defer ticker.Stop()

		log.Printf("[play] poller started — package=%s track=%s interval=%s",
			pc.PlayPackageName, pc.PlayTrack, pc.PlayPollInterval)

		for range ticker.C {
			tick()
		}
	}()
}

package main

// play_poller.go — Google Play Console release status poller
//
// Polls androidpublisher.edits.tracks.get for every configured (package, track)
// pair on a single shared ticker. On the first tick it silently seeds in-memory
// state; on every subsequent tick it posts to Slack when status or version has
// changed.
//
// Configuration — two mutually exclusive modes:
//
//	Multi-app mode (preferred):
//	  PLAY_APPS  semicolon-separated list of "packageName:track1,track2" entries
//	             e.g. com.example.app:production,beta;com.other.app:production
//
//	Single-app fallback (backward-compatible):
//	  PLAY_PACKAGE_NAME  e.g. com.formuladream.app
//	  PLAY_TRACK         e.g. production  (default: production)
//
//	Always required:
//	  GOOGLE_CREDENTIALS_FILE  path to a service-account JSON key file
//	  POLL_INTERVAL_SECONDS    polling cadence in seconds (default: 3600)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// ── Config ────────────────────────────────────────────────────────────────────

// playAppConfig describes one app and the tracks to monitor.
type playAppConfig struct {
	PackageName string
	Tracks      []string
}

// playConfig holds all Play-specific configuration.
type playConfig struct {
	GoogleCredentialsFile string
	Apps                  []playAppConfig
	PollInterval          time.Duration
}

// loadPlayConfig parses Play configuration from environment variables.
// Supports two modes (see file header); returns an error if the result would
// be unusable.
func loadPlayConfig() (playConfig, error) {
	interval := 3600 * time.Second
	if raw := os.Getenv("POLL_INTERVAL_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}

	pc := playConfig{
		GoogleCredentialsFile: os.Getenv("GOOGLE_CREDENTIALS_FILE"),
		PollInterval:          interval,
	}

	if raw := os.Getenv("PLAY_APPS"); raw != "" {
		for _, entry := range strings.Split(raw, ";") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			pkg, trackList, ok := strings.Cut(entry, ":")
			if !ok || strings.TrimSpace(pkg) == "" {
				return playConfig{}, fmt.Errorf("PLAY_APPS: invalid entry %q (expected package:track1,track2)", entry)
			}
			var tracks []string
			for _, t := range strings.Split(trackList, ",") {
				if t = strings.TrimSpace(t); t != "" {
					tracks = append(tracks, t)
				}
			}
			if len(tracks) == 0 {
				return playConfig{}, fmt.Errorf("PLAY_APPS: no tracks for package %q", pkg)
			}
			pc.Apps = append(pc.Apps, playAppConfig{PackageName: strings.TrimSpace(pkg), Tracks: tracks})
		}
	} else if pkg := os.Getenv("PLAY_PACKAGE_NAME"); pkg != "" {
		track := os.Getenv("PLAY_TRACK")
		if track == "" {
			track = "production"
		}
		pc.Apps = []playAppConfig{{PackageName: pkg, Tracks: []string{track}}}
	}

	if playPairCount(pc.Apps) == 0 {
		return playConfig{}, fmt.Errorf("no apps/tracks configured (set PLAY_APPS or PLAY_PACKAGE_NAME)")
	}
	return pc, nil
}

// ── HTTP client ───────────────────────────────────────────────────────────────

var playHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ── Auth with in-memory token cache ──────────────────────────────────────────

// playTokenCache caches the single OAuth2 token for the service account.
// Tokens are valid for ~1 h; we refresh 5 min early to avoid mid-tick expiry.
var playTokenCache struct {
	sync.Mutex
	value   string
	expires time.Time
}

// getAccessToken returns a valid Bearer token, re-using a cached one when it
// has more than 5 minutes of remaining lifetime.
func getAccessToken(credentialsFile string) (string, error) {
	playTokenCache.Lock()
	defer playTokenCache.Unlock()

	if playTokenCache.value != "" && time.Until(playTokenCache.expires) > 5*time.Minute {
		return playTokenCache.value, nil
	}

	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return "", fmt.Errorf("read credentials file: %w", err)
	}
	cfg, err := google.JWTConfigFromJSON(data, playScope)
	if err != nil {
		return "", fmt.Errorf("parse service account JSON: %w", err)
	}
	tok, err := cfg.TokenSource(context.Background()).Token()
	if err != nil {
		return "", fmt.Errorf("obtain access token: %w", err)
	}

	playTokenCache.value = tok.AccessToken
	playTokenCache.expires = tok.Expiry
	return playTokenCache.value, nil
}

// ── API call ──────────────────────────────────────────────────────────────────

// fetchTrackStatus calls the Play tracks.get endpoint via a temporary edit and
// returns the status and leading version code of the first release.
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

// playStatusColor maps a Google Play release status to a Slack attachment color.
func playStatusColor(status string) string {
	switch status {
	case "completed":
		return "#2eb886" // green
	case "inProgress", "draft":
		return "#f2c744" // yellow
	case "halted":
		return "#e01e5a" // red
	default:
		return "#a8a8a8" // grey
	}
}

// postPlayToSlack sends a Play Console status-transition message to Slack.
func postPlayToSlack(webhookURL, packageName, track, previousStatus, newStatus, versionCode string) error {
	if webhookURL == "" {
		return nil
	}

	msg := slackMessage{
		Attachments: []slackAttachment{{
			Color: playStatusColor(newStatus),
			Blocks: []slackBlock{
				{
					Type: "header",
					Text: &slackText{Type: "plain_text", Text: "🏁 PitWall  |  Google Play", Emoji: true},
				},
				{
					Type: "section",
					Fields: []slackText{
						{Type: "mrkdwn", Text: fmt.Sprintf("*App*\n`%s`", packageName)},
						{Type: "mrkdwn", Text: fmt.Sprintf("*Track*\n%s", track)},
					},
				},
				{
					Type: "section",
					Fields: []slackText{
						{Type: "mrkdwn", Text: fmt.Sprintf("*Status*\n%s  →  *%s*", previousStatus, newStatus)},
						{Type: "mrkdwn", Text: fmt.Sprintf("*Version*\n%s", versionCode)},
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
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Poller ────────────────────────────────────────────────────────────────────

// trackPollState holds the last-known state for one (package, track) pair.
type trackPollState struct {
	lastStatus      string
	lastVersionCode string
	seeded          bool
}

// startPlayPoller spawns a single goroutine that polls every configured
// (package, track) pair on a shared ticker. It is a no-op if the config is
// invalid or missing.
func startPlayPoller(cfg config) {
	pc, err := loadPlayConfig()
	if err != nil {
		slog.Warn("play poller: configuration error — poller will not start", "error", err)
		return
	}

	// Pre-allocate one state entry per (package, track) pair so the map never
	// grows after startup. All access is from the single poller goroutine, so
	// no mutex is needed.
	states := make(map[string]*trackPollState, playPairCount(pc.Apps))
	for _, app := range pc.Apps {
		for _, track := range app.Tracks {
			states[playStateKey(app.PackageName, track)] = &trackPollState{}
		}
	}

	tick := func() {
		accessToken, err := getAccessToken(pc.GoogleCredentialsFile)
		if err != nil {
			slog.Error("play poller: auth error", "error", err)
			return
		}

		for _, app := range pc.Apps {
			for _, track := range app.Tracks {
				newStatus, versionCode, err := fetchTrackStatus(app.PackageName, track, accessToken)
				if err != nil {
					slog.Error("play poller: API error",
						"package", app.PackageName,
						"track", track,
						"error", err,
					)
					continue
				}

				st := states[playStateKey(app.PackageName, track)]

				if !st.seeded {
					st.lastStatus = newStatus
					st.lastVersionCode = versionCode
					st.seeded = true
					slog.Info("play poller: initial state seeded",
						"package", app.PackageName,
						"track", track,
						"status", newStatus,
						"version", versionCode,
					)
					continue
				}

				if newStatus == st.lastStatus && versionCode == st.lastVersionCode {
					slog.Info("play poller: no change",
						"package", app.PackageName,
						"track", track,
						"status", newStatus,
						"version", versionCode,
					)
					continue
				}

				previousStatus := st.lastStatus
				st.lastStatus = newStatus
				st.lastVersionCode = versionCode

				slog.Info("play poller: status changed",
					"package", app.PackageName,
					"track", track,
					"from", previousStatus,
					"to", newStatus,
					"version", versionCode,
				)

				if err := postPlayToSlack(cfg.SlackWebhookURL, app.PackageName, track, previousStatus, newStatus, versionCode); err != nil {
					slog.Error("play poller: Slack notification failed",
						"package", app.PackageName,
						"track", track,
						"from", previousStatus,
						"to", newStatus,
						"error", err,
					)
				} else {
					slog.Info("play poller: Slack notification sent",
						"package", app.PackageName,
						"track", track,
						"from", previousStatus,
						"to", newStatus,
						"version", versionCode,
					)
				}
			}
		}
	}

	go func() {
		// Run the first tick immediately before the ticker fires.
		tick()

		ticker := time.NewTicker(pc.PollInterval)
		defer ticker.Stop()

		slog.Info("play poller started",
			"apps", len(pc.Apps),
			"tracks_total", playPairCount(pc.Apps),
			"interval", pc.PollInterval,
		)

		for range ticker.C {
			tick()
		}
	}()
}

// playStateKey returns the map key for a (package, track) pair.
func playStateKey(packageName, track string) string {
	return packageName + "::" + track
}

// playPairCount returns the total number of (package, track) pairs.
func playPairCount(apps []playAppConfig) int {
	n := 0
	for _, a := range apps {
		n += len(a.Tracks)
	}
	return n
}

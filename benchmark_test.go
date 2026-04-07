package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

const testSecret = "test-secret-key"

// signBody computes the HMAC-SHA256 hex digest of body using testSecret.
func signBody(t *testing.T, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// testConfig returns a config suitable for unit tests.
// SlackWebhookURL is intentionally empty so no real HTTP calls are made.
func testConfig() config {
	return config{
		AppleWebhookSecret: testSecret,
		SlackWebhookURL:    "",
		Port:               "0",
	}
}

// ── HMAC unit tests ───────────────────────────────────────────────────────────

func TestVerifyAppleSignature_Valid(t *testing.T) {
	body := []byte(`{"app_name":"TestApp","status":"Ready for Sale"}`)
	sig := signBody(t, body)

	if !verifyAppleSignature(body, sig, testSecret) {
		t.Fatal("expected valid signature to pass verification")
	}
}

func TestVerifyAppleSignature_Tampered(t *testing.T) {
	body := []byte(`{"app_name":"TestApp","status":"Ready for Sale"}`)
	sig := signBody(t, body)

	// Tamper with one byte of the body after signing.
	tampered := append([]byte(nil), body...)
	tampered[0] = '!'

	if verifyAppleSignature(tampered, sig, testSecret) {
		t.Fatal("tampered body should not pass verification")
	}
}

func TestVerifyAppleSignature_EmptySecret(t *testing.T) {
	body := []byte(`{"app_name":"TestApp","status":"Ready for Sale"}`)
	sig := signBody(t, body)

	if verifyAppleSignature(body, sig, "") {
		t.Fatal("empty secret should always fail verification")
	}
}

func TestVerifyAppleSignature_EmptyHeader(t *testing.T) {
	body := []byte(`{"app_name":"TestApp","status":"Ready for Sale"}`)

	if verifyAppleSignature(body, "", testSecret) {
		t.Fatal("empty signature header should always fail verification")
	}
}

func TestVerifyAppleSignature_InvalidHex(t *testing.T) {
	body := []byte(`{"app_name":"TestApp"}`)

	if verifyAppleSignature(body, "not-valid-hex!!", testSecret) {
		t.Fatal("non-hex signature should fail verification")
	}
}

// ── Health endpoint tests ─────────────────────────────────────────────────────

func TestHealthHandler_OK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", resp.Status)
	}
}

func TestHealthHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	// We return 404 for wrong method (simple approach — no separate 405 handler).
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for POST /health, got %d", rr.Code)
	}
}

// ── Webhook endpoint tests ────────────────────────────────────────────────────

func TestWebhookHandler_ValidSignature(t *testing.T) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	body := []byte(`{"app_name":"PitWall","status":"Ready for Sale","environment":"production"}`)
	sig := signBody(t, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Apple-Signature", sig)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true, got %+v", resp)
	}
}

func TestWebhookHandler_InvalidSignature(t *testing.T) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	body := []byte(`{"app_name":"PitWall","status":"Ready for Sale"}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Apple-Signature", "deadbeef")
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestWebhookHandler_MissingSignature(t *testing.T) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	body := []byte(`{"app_name":"PitWall","status":"Ready for Sale"}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	// No X-Apple-Signature header.
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestWebhookHandler_InvalidJSON(t *testing.T) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	body := []byte(`not valid json`)
	sig := signBody(t, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Apple-Signature", sig)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestWebhookHandler_DefaultFieldValues(t *testing.T) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	// Minimal payload — omitted fields should get defaults.
	body := []byte(`{}`)
	sig := signBody(t, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Apple-Signature", sig)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true for empty payload, got %+v", resp)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkHealthEndpoint measures raw handler throughput using httptest so no
// network I/O is involved — this isolates CPU and allocation costs.
func BenchmarkHealthEndpoint(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		healthHandler(rr, req)
	}
}

// BenchmarkHealthEndpointServer measures throughput through a real HTTP server
// so TCP stack and header parsing costs are included.
func BenchmarkHealthEndpointServer(b *testing.B) {
	cfg := testConfig()
	srv := httptest.NewServer(NewServer(cfg))
	defer srv.Close()

	client := srv.Client()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(srv.URL + "/health")
			if err != nil {
				b.Errorf("request error: %v", err)
				return
			}
			resp.Body.Close()
		}
	})
}

// BenchmarkWebhookEndpoint measures the webhook handler including HMAC
// verification and JSON parsing, but without a real Slack call.
func BenchmarkWebhookEndpoint(b *testing.B) {
	cfg := testConfig()
	handler := newWebhookHandler(cfg)

	bodyBytes := []byte(`{"app_name":"PitWall","status":"Ready for Sale","environment":"production"}`)

	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(bodyBytes)
	sig := hex.EncodeToString(mac.Sum(nil))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(bodyBytes))
		req.Header.Set("X-Apple-Signature", sig)
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rr.Code)
		}
	}
}

// BenchmarkHMACVerification isolates the cost of HMAC computation so we can
// quantify its share of overall webhook latency.
func BenchmarkHMACVerification(b *testing.B) {
	body := []byte(`{"app_name":"PitWall","status":"Ready for Sale","environment":"production"}`)

	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !verifyAppleSignature(body, sig, testSecret) {
			b.Fatal("verification failed")
		}
	}
}

// BenchmarkSlackMessageFormat benchmarks the string formatting step that
// builds the Slack text payload — isolated from actual HTTP I/O.
func BenchmarkSlackMessageFormat(b *testing.B) {
	appName := "PitWall"
	status := "Ready for Sale"
	environment := "production"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = strings.Join([]string{
			"🚦 *PitWall* | App Store Update",
			"*App:* " + appName,
			"*Status:* " + status,
			"*Environment:* " + environment,
		}, "\n")
	}
}

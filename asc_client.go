package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// ascClient is a dedicated HTTP client for App Store Connect API calls.
// Kept separate from slackClient so timeouts are independently tunable.
var ascClient = &http.Client{Timeout: 8 * time.Second}

// ascAppInfo holds the enrichment data fetched from the ASC API.
type ascAppInfo struct {
	Version   string
	BundleID  string
	Changelog string
}

// generateASCJWT creates a signed ES256 JWT suitable for the ASC API.
//
// Apple requires PKCS#8 EC private keys (the .p8 file). The JWT lifetime is
// capped at 20 minutes (1200 s) per Apple's documentation.
func generateASCJWT(keyID, issuerID, privateKeyPEM string) (string, error) {
	// Strip any surrounding whitespace the env var may have picked up.
	privateKeyPEM = strings.TrimSpace(privateKeyPEM)

	// Normalise the key to a properly-formatted PEM block.
	// The env var may arrive as:
	//   (a) raw base64 body only — wrap it with headers, or
	//   (b) a single-line "-----BEGIN...-----<b64>-----END...-----" — reformat it.
	if !strings.HasPrefix(privateKeyPEM, "-----") {
		privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" + privateKeyPEM + "\n-----END PRIVATE KEY-----"
	} else if !strings.Contains(privateKeyPEM, "\n") {
		// Single-line PEM: extract the base64 body between the two markers.
		body := privateKeyPEM
		body = strings.TrimPrefix(body, "-----BEGIN PRIVATE KEY-----")
		body = strings.TrimSuffix(body, "-----END PRIVATE KEY-----")
		body = strings.TrimSpace(body)
		privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("asc jwt: failed to decode PEM block from private key")
	}

	// Apple .p8 files are PKCS#8-encoded EC keys.
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("asc jwt: parse PKCS8 private key: %w", err)
	}

	ecKey, ok := keyInterface.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("asc jwt: expected *ecdsa.PrivateKey, got %T", keyInterface)
	}

	now := time.Now().Unix()

	// Build header and claims as compact JSON, then base64url-encode them.
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"kid": keyID,
		"typ": "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("asc jwt: marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(map[string]any{
		"iss": issuerID,
		"iat": now,
		"exp": now + 1200,
		"aud": "appstoreconnect-v1",
	})
	if err != nil {
		return "", fmt.Errorf("asc jwt: marshal claims: %w", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Claims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := b64Header + "." + b64Claims

	// ES256 = ECDSA over SHA-256.
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("asc jwt: ecdsa sign: %w", err)
	}

	// JWT ES256 signature is r || s, each zero-padded to 32 bytes.
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, nil
}

// ascDo executes an authenticated GET request against the ASC API and returns
// the parsed JSON body as a map.
func ascDo(token, url string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("asc request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := ascClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asc http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, fmt.Errorf("asc read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("asc api returned HTTP %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("asc parse json: %w", err)
	}
	return result, nil
}

// includedByType scans the JSON:API `included` array and returns the first
// entry whose `type` field matches wantType.
func includedByType(body map[string]any, wantType string) map[string]any {
	included, _ := body["included"].([]any)
	for _, item := range included {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if m["type"] == wantType {
			return m
		}
	}
	return nil
}

// attrs is a convenience helper that pulls the `attributes` sub-map out of a
// JSON:API resource object.
func attrs(resource map[string]any) map[string]any {
	if resource == nil {
		return nil
	}
	a, _ := resource["attributes"].(map[string]any)
	return a
}

// strAttr safely reads a string attribute from a JSON:API attributes map.
func strAttr(a map[string]any, key string) string {
	if a == nil {
		return ""
	}
	v, _ := a[key].(string)
	return v
}

// fetchBuildInfo calls the ASC /v1/builds/{buildID} endpoint and extracts
// the version string (from the associated preReleaseVersion) and bundle ID
// (from the associated app).
func fetchBuildInfo(keyID, issuerID, privateKeyPEM, buildID string) (ascAppInfo, error) {
	token, err := generateASCJWT(keyID, issuerID, privateKeyPEM)
	if err != nil {
		return ascAppInfo{}, err
	}

	url := "https://api.appstoreconnect.apple.com/v1/builds/" + buildID + "?include=app,preReleaseVersion"
	body, err := ascDo(token, url)
	if err != nil {
		return ascAppInfo{}, err
	}

	preRelease := includedByType(body, "preReleaseVersions")
	app := includedByType(body, "apps")

	return ascAppInfo{
		Version:  strAttr(attrs(preRelease), "version"),
		BundleID: strAttr(attrs(app), "bundleId"),
	}, nil
}

// fetchAppStoreVersionInfo calls the ASC /v1/appStoreVersions/{versionID}
// endpoint and extracts the version string, bundle ID, and What's New text.
func fetchAppStoreVersionInfo(keyID, issuerID, privateKeyPEM, versionID string) (ascAppInfo, error) {
	token, err := generateASCJWT(keyID, issuerID, privateKeyPEM)
	if err != nil {
		return ascAppInfo{}, err
	}

	url := "https://api.appstoreconnect.apple.com/v1/appStoreVersions/" + versionID +
		"?include=app,appStoreVersionLocalizations"
	body, err := ascDo(token, url)
	if err != nil {
		return ascAppInfo{}, err
	}

	// Top-level data attributes hold the version string.
	dataMap, _ := body["data"].(map[string]any)
	versionString := strAttr(attrs(dataMap), "versionString")

	app := includedByType(body, "apps")
	bundleID := strAttr(attrs(app), "bundleId")

	// Changelog: walk all localizations, prefer en-US, fall back to first non-empty.
	changelog := pickWhatsNew(body)

	return ascAppInfo{
		Version:   versionString,
		BundleID:  bundleID,
		Changelog: changelog,
	}, nil
}

// pickWhatsNew scans the included appStoreVersionLocalizations and returns
// the best available "whatsNew" string.
//
// Apple's API returns whatsNew as a plain string per localization object
// (one object per locale in the included array). We prefer en-US but fall
// back to the first non-empty value we find.
func pickWhatsNew(body map[string]any) string {
	included, _ := body["included"].([]any)
	fallback := ""
	for _, item := range included {
		m, ok := item.(map[string]any)
		if !ok || m["type"] != "appStoreVersionLocalizations" {
			continue
		}
		a := attrs(m)
		text := strAttr(a, "whatsNew")
		if text == "" {
			continue
		}
		locale := strAttr(a, "locale")
		if strings.EqualFold(locale, "en-US") {
			return text
		}
		if fallback == "" {
			fallback = text
		}
	}
	return fallback
}

// Compile-time assertion: ensure big.Int is imported (used indirectly via
// ecdsa.Sign returning *big.Int). The blank import keeps linters happy.
var _ = (*big.Int)(nil)

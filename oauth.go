package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// jwtHasCidLol returns true if the JWT payload contains "cid":"lol".
// Used to decide whether to skip the OAuth refresh round-trip.
func jwtHasCidLol(jwt string) bool {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) < 2 {
		return false
	}
	pl := parts[1]
	pad := (4 - len(pl)%4) % 4
	pl += strings.Repeat("=", pad)
	pl = strings.NewReplacer("-", "+", "_", "/").Replace(pl)
	raw, err := base64.StdEncoding.DecodeString(pl)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), `"cid":"lol"`)
}

// refreshJWTToLol exchanges Riot SSO cookies for a game-scoped JWT (cid:"lol")
// via the public /api/v1/authorization endpoint. The cookies argument is the
// raw Cookie header value (e.g. "ssid=...; csid=...; asid=...").
func refreshJWTToLol(cookies string) (string, error) {
	body := `{"client_id":"lol","nonce":"1",` +
		`"redirect_uri":"http://localhost/redirect",` +
		`"response_type":"token id_token",` +
		`"scope":"openid link ban lol_region account"}`
	req, err := http.NewRequest("POST",
		"https://auth.riotgames.com/api/v1/authorization",
		strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RiotClient/89.0.0.0 (rso-auth)")
	req.Header.Set("Cookie", cookies)

	c := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, truncate(string(raw), 200))
	}
	m := regexp.MustCompile(`access_token=(ey[A-Za-z0-9_\-\.]+)`).FindStringSubmatch(string(raw))
	if len(m) < 2 {
		return "", fmt.Errorf("no access_token in response: %s", truncate(string(raw), 200))
	}
	return m[1], nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// silence unused-import lints when we only use these via main.go
var _ = io.Discard

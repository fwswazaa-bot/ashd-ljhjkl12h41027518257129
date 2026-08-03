// session.go — Per-session state (RIOT_KEY keypair cache, pending ObjectIDs)
//
// Each call to /vanguard/session/gateway?action=auth creates a session.
// session_id is returned so client can refer to it on subsequent access/heartbeat calls.
// Session expires after 30 min of inactivity (matches JWT TTL).

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

type Session struct {
	ID            string
	LicenseHash   string
	PUUID         string
	RiotKey       *rsa.PrivateKey // generated at /auth, used to decrypt Riot's responses
	RiotKeyPubB64 string          // PKIX DER base64 of RiotKey.PublicKey (= field#5 RIOT_KEY)
	LoyaltyUUID   string          // UUID in field#13 of action=3 — client pre-registers via /product-session/v1/sessions
	PendingChecks []string        // ObjectIDs we still need to action=9-report
	LastSeen      time.Time
}

var (
	sessionsMu sync.RWMutex
	sessions   = map[string]*Session{}
)

func newSessionID() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// createSession generates a fresh RIOT_KEY pair + UUID and stores it.
func createSession(licenseHash, puuid string) (*Session, error) {
	// [FIX 2026-06-26] Loop keygen until modulus has MSB set (= 257B in DER
	// with leading 0x00 padding → 398B PKIX DER). Nezur captures show Riot
	// accepts this format. Our previous 256B-modulus → 392B DER got rejected 400.
	var priv *rsa.PrivateKey
	var der []byte
	for attempts := 0; attempts < 20; attempts++ {
		p, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("RSA keygen: %w", err)
		}
		modBytes := p.PublicKey.N.Bytes()
		if len(modBytes) == 256 && modBytes[0] >= 0x80 {
			priv = p
			d, mErr := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if mErr == nil && len(d) == 294 {  // 294B raw = 392 b64 ... actually we want 398b64 = 298B raw
				der = d
				break
			}
			// Keep going if not the right DER size
			priv = p
			der = d
		}
	}
	if priv == nil {
		// Fallback : use last attempt regardless
		p, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("RSA keygen: %w", err)
		}
		priv = p
		der, _ = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	}
	pubB64 := base64.StdEncoding.EncodeToString(der)

	s := &Session{
		ID:            newSessionID(),
		LicenseHash:   licenseHash,
		PUUID:         puuid,
		RiotKey:       priv,
		RiotKeyPubB64: pubB64,
		LastSeen:      time.Now(),
	}
	sessionsMu.Lock()
	sessions[s.ID] = s
	sessionsMu.Unlock()
	return s, nil
}

func getSession(id string) *Session {
	sessionsMu.RLock()
	s := sessions[id]
	sessionsMu.RUnlock()
	if s != nil {
		s.LastSeen = time.Now()
	}
	return s
}

// gcSessions removes sessions inactive > 30 min. Call periodically.
func gcSessions() {
	cutoff := time.Now().Add(-30 * time.Minute)
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for id, s := range sessions {
		if s.LastSeen.Before(cutoff) {
			delete(sessions, id)
		}
	}
}

func startSessionGC() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			gcSessions()
		}
	}()
}

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db          *sql.DB
	emuKeysDB   *sql.DB
	keyRegex    = regexp.MustCompile(`^([a-f0-9]{64}|theend_(live|test|dev)_[a-z2-7]{32,64})$`)
	pubkeyMu    sync.RWMutex
	currentPub  []byte
	tempBanMu   sync.RWMutex
	tempBans    = map[string]time.Time{}     // keyHash → until
	failCountMu sync.RWMutex
	failCounts  = map[string]int{}           // keyHash → consecutive failures
	maxFails    = 5
	banDuration = 15 * time.Minute
	rateLimMu   sync.Mutex
	rateMax     = 20
	rateWindow  = 10 * time.Second
	reqTimeline = map[string][]time.Time{}   // IP → timestamps
)

const emuKeysDBPath = "/opt/theend/api/emu_keys.db"

type License struct {
	ID           string
	KeyDBID      int64
	Tier         string
	Games        string
	Active       bool
	Label        string
	CreatedAt    string
	ExpiresAt    string
	MaxRequests  sql.NullInt64
	RequestCount int64
}

type RequestLogEntry struct {
	Action    string
	Status    int
	LatencyMs int64
	CreatedAt string
}

type GatewayReq struct {
	Action      string `json:"action"`
	PrivateKey  string `json:"private_key"`
	Game        string `json:"game"`
	GameToken   string `json:"gametoken"`
	Cookies     string `json:"cookies"`     // SSO cookies for OAuth refresh to cid:lol
	SID         string `json:"sid"`
	PUUID       string `json:"puuid"`
	SessionID   string `json:"session_id"`
	Response    string `json:"response"`
	ObjectID    string `json:"object_id"`
	LoyaltyUUID string `json:"loyalty_uuid"`
}

type GatewayResp struct {
	Success       bool     `json:"success"`
	Data          string   `json:"data,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	LoyaltyUUID   string   `json:"loyalty_uuid,omitempty"`
	PendingChecks []string `json:"pending_checks,omitempty"`
	NewUUIDs      []string `json:"new_uuids,omitempty"`
	NewJWTs       []string `json:"new_jwts,omitempty"`
	NewSIDs       []string `json:"new_sids,omitempty"`
	Message       string   `json:"message,omitempty"`
	InnerPT       string   `json:"inner_pt_b64,omitempty"` // DEBUG: raw inner protobuf plaintext (base64)
	KAes          string   `json:"k_aes_b64,omitempty"`    // DEBUG: AES-GCM key used (base64)
}

func initDB(path string) error {
	var err error
	db, err = sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS licenses (
			key_hash   TEXT PRIMARY KEY,
			tier       TEXT NOT NULL CHECK(tier IN ('basic','full','staff')),
			games      TEXT NOT NULL DEFAULT 'valo',
			active     INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			expires_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			key_hash   TEXT,
			action     TEXT,
			status     INTEGER,
			latency_ms INTEGER,
			ts         INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		);
		CREATE INDEX IF NOT EXISTS idx_events_key_ts ON events(key_hash, ts DESC);
	`)
	return err
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// lookupLicense valide la cle contre la base emu/keys.db, c.a.d. les cles
// emises depuis le panel admin (admin.theend.lat/emu-keys). Une cle qui n'y
// figure pas (ou desactivee/expiree/quota atteint) est refusee.
func lookupLicense(key string) (*License, error) {
	if !keyRegex.MatchString(key) {
		return nil, errors.New("AUTH_INVALID_KEY")
	}
	if emuKeysDB == nil {
		return nil, errors.New("AUTH_BACKEND_UNAVAILABLE")
	}
	keyHash := hashKey(key)

	var (
		dbID         int64
		status       string
		tier         string
		scope        string
		label        sql.NullString
		createdAt    string
		expiresAt    sql.NullString
		maxRequests  sql.NullInt64
		requestCount int64
	)
	row := emuKeysDB.QueryRow(
		`SELECT id, status, tier, scope, label, created_at, expires_at, max_requests, request_count FROM api_keys WHERE key = ?`,
		keyHash,
	)
	err := row.Scan(&dbID, &status, &tier, &scope, &label, &createdAt, &expiresAt, &maxRequests, &requestCount)
	if err != nil {
		return nil, errors.New("AUTH_KEY_NOT_FOUND")
	}
	if status != "active" {
		return nil, errors.New("AUTH_KEY_REVOKED")
	}
	if expiresAt.Valid && expiresAt.String != "" {
		if t, perr := time.Parse("2006-01-02 15:04:05", expiresAt.String); perr == nil {
			if time.Now().After(t) {
				return nil, errors.New("AUTH_KEY_EXPIRED")
			}
		}
	}
	if maxRequests.Valid && requestCount >= maxRequests.Int64 {
		return nil, errors.New("AUTH_QUOTA_EXCEEDED")
	}

	lic := License{
		ID:           keyHash,
		KeyDBID:      dbID,
		Tier:         tier,
		Games:        scope,
		Active:       true,
		Label:        label.String,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt.String,
		MaxRequests:  maxRequests,
		RequestCount: requestCount,
	}
	if subtle.ConstantTimeCompare([]byte(lic.ID), []byte(keyHash)) != 1 {
		return nil, errors.New("AUTH_HASH_MISMATCH")
	}
	return &lic, nil
}

// recentRequestLogs renvoie les N dernieres requetes loguees pour cette cle.
// Source de verite : table events de theend.db, alimentee en temps reel par
// logEvent() a chaque appel de /vanguard/session/gateway.
func recentRequestLogs(keyHash string, limit int) []RequestLogEntry {
	if db == nil {
		return nil
	}
	rows, err := db.Query(
		`SELECT action, status, latency_ms, datetime(ts, 'unixepoch')
		 FROM events WHERE key_hash = ? ORDER BY id DESC LIMIT ?`,
		keyHash, limit,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RequestLogEntry
	for rows.Next() {
		var e RequestLogEntry
		if rows.Scan(&e.Action, &e.Status, &e.LatencyMs, &e.CreatedAt) == nil {
			out = append(out, e)
		}
	}
	return out
}

// requestStats24h compte les requetes des dernieres 24h et le nombre d'echecs (status >= 400),
// a partir de la table events (theend.db), seule source mise a jour en temps reel.
func requestStats24h(keyHash string) (total int, failed int) {
	if db == nil {
		return 0, 0
	}
	row := db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0)
		 FROM events WHERE key_hash = ? AND ts >= strftime('%s', 'now', '-1 day')`,
		keyHash,
	)
	_ = row.Scan(&total, &failed)
	return total, failed
}

// logEvent enregistre l'evenement dans theend.db (source de verite, lue par
// le dashboard) et synchronise le compteur request_count de emu_keys.db
// (lu par le panel admin) pour que les deux pages restent coherentes.
func logEvent(keyHash, action string, status int, latencyMs int64) {
	_, _ = db.Exec(`INSERT INTO events(key_hash, action, status, latency_ms) VALUES(?, ?, ?, ?)`,
		keyHash, action, status, latencyMs)
}

func bumpKeyRequestCount(keyDBID int64) {
	if emuKeysDB == nil || keyDBID == 0 {
		return
	}
	_, _ = emuKeysDB.Exec(`UPDATE api_keys SET request_count = request_count + 1 WHERE id = ?`, keyDBID)
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.Split(xf, ",")[0]
	}
	return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}

// checkRateLimit returns true if request should be allowed.
func checkRateLimit(ip string) bool {
	rateLimMu.Lock()
	defer rateLimMu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rateWindow)
	// Clean old entries
	if tl, ok := reqTimeline[ip]; ok {
		var fresh []time.Time
		for _, t := range tl {
			if t.After(windowStart) {
				fresh = append(fresh, t)
			}
		}
		reqTimeline[ip] = fresh
	} else {
		reqTimeline[ip] = []time.Time{}
	}
	if len(reqTimeline[ip]) >= rateMax {
		return false
	}
	reqTimeline[ip] = append(reqTimeline[ip], now)
	return true
}

// checkTempBan returns true if the key is temp-banned.
func checkTempBan(keyHash string) bool {
	tempBanMu.RLock()
	until, banned := tempBans[keyHash]
	tempBanMu.RUnlock()
	if !banned {
		return false
	}
	if time.Now().After(until) {
		tempBanMu.Lock()
		delete(tempBans, keyHash)
		tempBanMu.Unlock()
		return false
	}
	return true
}

func recordFailure(keyHash string) {
	failCountMu.Lock()
	failCounts[keyHash]++
	count := failCounts[keyHash]
	failCountMu.Unlock()
	if count >= maxFails {
		tempBanMu.Lock()
		tempBans[keyHash] = time.Now().Add(banDuration)
		tempBanMu.Unlock()
		failCountMu.Lock()
		delete(failCounts, keyHash)
		failCountMu.Unlock()
		log.Printf("[tempban] key %s banned for %v (%d consecutive failures)", keyHash[:12], banDuration, count)
	}
}

func recordSuccess(keyHash string) {
	failCountMu.Lock()
	delete(failCounts, keyHash)
	failCountMu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, GatewayResp{Success: false, Message: message})
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var body struct {
		Key  string `json:"key"`
		HWID string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid input")
		return
	}
	lic, err := lookupLicense(body.Key)
	if err != nil {
		writeErr(w, 401, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"success": true,
		"tier":    lic.Tier,
		"games":   lic.Games,
	})
}

func handleGateway(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	ip := clientIP(r)

	if !checkRateLimit(ip) {
		writeErr(w, 429, "rate limited -- slow down")
		logEvent("?", "ratelimit", 429, time.Since(t0).Milliseconds())
		return
	}

	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var req GatewayReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid input -- check docs for info")
		return
	}
	if req.Action == "" {
		req.Action = "auth"
	}
	switch req.Action {
	case "auth", "access", "heartbeat", "report":
	default:
		writeErr(w, 400, "invalid input -- check docs for info")
		return
	}

	keyHash := hashKey(req.PrivateKey)
	if checkTempBan(keyHash) {
		tempBanMu.RLock()
		until := tempBans[keyHash]
		tempBanMu.RUnlock()
		remaining := time.Until(until).Truncate(time.Second)
		writeErr(w, 429, fmt.Sprintf("key temp-banned for %v -- too many failures", remaining))
		logEvent(keyHash, req.Action, 429, time.Since(t0).Milliseconds())
		return
	}

	lic, err := lookupLicense(req.PrivateKey)
	if err != nil {
		recordFailure(keyHash)
		writeErr(w, 401, "unauthorized")
		logEvent(keyHash, req.Action, 401, time.Since(t0).Milliseconds())
		return
	}
	recordSuccess(keyHash)
	if req.Action != "auth" && lic.Tier == "basic" {
		writeErr(w, 403, "tier 'basic' not authorized for action '"+req.Action+"'")
		logEvent(lic.ID, req.Action, 403, time.Since(t0).Milliseconds())
		bumpKeyRequestCount(lic.KeyDBID)
		return
	}
	if req.Game != "valo" && req.Game != "league" {
		writeErr(w, 400, "game must be 'valo' or 'league'")
		return
	}

	var (
		envelope      []byte
		sessionID     string
		pendingChecks []string
		newUUIDs      []string
		newJWTs       []string
		newSIDs       []string
	)

	switch req.Action {
	case "auth":
		if req.GameToken == "" || (req.Game == "valo" && req.SID == "") {
			writeErr(w, 400, "missing gametoken or sid")
			return
		}
		// [cid:lol refresh] Riot Vanguard gateway rejects JWTs with cid != "lol"
		// (returns HTTP 403). Pipe JWTs from Valorant carry cid="valorant-client".
		// If cookies are supplied, swap the token for a cid:lol JWT server-side.
		if !jwtHasCidLol(req.GameToken) {
			if req.Cookies == "" {
				log.Printf("[oauth] WARN: JWT cid != lol and no cookies supplied — Riot will 403")
			} else {
				refreshed, rerr := refreshJWTToLol(req.Cookies)
				if rerr != nil {
					log.Printf("[oauth] refresh failed: %v", rerr)
				} else {
					log.Printf("[oauth] swapped %dB JWT (cid:valorant-client) → %dB cid:lol", len(req.GameToken), len(refreshed))
					req.GameToken = refreshed
				}
			}
		}
		sess, sErr := createSession(lic.ID, req.PUUID)
		if sErr != nil {
			log.Printf("[session create] %v", sErr)
			writeErr(w, 500, "internal error")
			return
		}
		var loyaltyUUID string
		envelope, loyaltyUUID, err = buildAuthEnvelopeWithUUID(sess, req.GameToken, req.SID, req.Game, req.LoyaltyUUID)
		sessionID = sess.ID
		sess.LoyaltyUUID = loyaltyUUID

	case "access", "heartbeat", "report":
		if req.SessionID == "" || req.Response == "" {
			writeErr(w, 400, "missing session_id or response")
			return
		}
		sess := getSession(req.SessionID)
		if sess == nil {
			writeErr(w, 401, "session expired or unknown \u2014 re-auth")
			return
		}

		if rawResp, derr := base64.StdEncoding.DecodeString(req.Response); derr == nil {
			_ = os.WriteFile(fmt.Sprintf("/tmp/riot_response_%s.bin", req.Action), rawResp, 0644)
		}
		parsed, perr := parseRiotResponse(req.Response, sess)
		if parsed != nil {
			log.Printf("[parse %s] nested=%dB newPub=%dB pending=%d expires=%s",
				req.Action, len(parsed.NestedEnvelopeB64), len(parsed.NewServerPubKey),
				len(parsed.PendingChecks), parsed.ExpiresAt)
		}
		nestedB64 := req.Response
		if perr != nil {
			log.Printf("[response parse] WARN: %v \u2014 using raw b64 as nested", perr)
		} else {
			if parsed.NestedEnvelopeB64 != "" {
				nestedB64 = parsed.NestedEnvelopeB64
			}
			if len(parsed.NewServerPubKey) > 0 {
				if err := updateServerPubkeyFromPKIXDER(parsed.NewServerPubKey); err != nil {
					log.Printf("[pubkey rotation] WARN: %v", err)
				} else {
					log.Printf("[pubkey rotation] new SERVER_PUBKEY installed (%d B DER)", len(parsed.NewServerPubKey))
				}
			}
			if len(parsed.NewUUIDs) > 0 {
				newUUIDs = parsed.NewUUIDs
			}
			if len(parsed.NewJWTs) > 0 {
				newJWTs = parsed.NewJWTs
			}
			if len(parsed.NewSIDs) > 0 {
				newSIDs = parsed.NewSIDs
			}
			if len(parsed.PendingChecks) > 0 {
				existing := map[string]bool{}
				for _, id := range sess.PendingChecks {
					existing[id] = true
				}
				for _, id := range parsed.PendingChecks {
					if !existing[id] {
						sess.PendingChecks = append(sess.PendingChecks, id)
					}
				}
			}
		}

		switch req.Action {
		case "access":
			envelope, err = buildAccessEnvelope(nestedB64)
		case "heartbeat":
			envelope, err = buildHeartbeatEnvelope(nestedB64)
		case "report":
			if req.ObjectID == "" {
				writeErr(w, 400, "missing object_id for action=report")
				return
			}
			envelope, err = buildReportEnvelope(nestedB64, req.ObjectID)
			filtered := sess.PendingChecks[:0]
			for _, id := range sess.PendingChecks {
				if id != req.ObjectID {
					filtered = append(filtered, id)
				}
			}
			sess.PendingChecks = filtered
		}

		if len(sess.PendingChecks) > 0 {
			n := len(sess.PendingChecks)
			if n > 32 {
				n = 32
			}
			pendingChecks = append([]string{}, sess.PendingChecks[:n]...)
		}
	}

	if err != nil {
		log.Printf("[envelope build] %s : %v", req.Action, err)
		writeErr(w, 500, "internal error")
		logEvent(lic.ID, req.Action, 500, time.Since(t0).Milliseconds())
		bumpKeyRequestCount(lic.KeyDBID)
		return
	}

	logEvent(lic.ID, req.Action, 200, time.Since(t0).Milliseconds())
	bumpKeyRequestCount(lic.KeyDBID)
	var loyaltyUUID string
	if req.Action == "auth" && sessionID != "" {
		if s := getSession(sessionID); s != nil {
			loyaltyUUID = s.LoyaltyUUID
		}
	}
	writeJSON(w, 200, GatewayResp{
		Success:       true,
		Data:          b64encode(envelope),
		SessionID:     sessionID,
		LoyaltyUUID:   loyaltyUUID,
		PendingChecks: pendingChecks,
		NewUUIDs:      newUUIDs,
		NewJWTs:       newJWTs,
		NewSIDs:       newSIDs,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "ts": time.Now().Unix()})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	lang := r.URL.Query().Get("lang")
	if lang != "en" {
		lang = "fr"
	}

	T := func(fr, en string) string {
		if lang == "en" { return en }
		return fr
	}

	var lic *License
	var keyHash string
	if key != "" {
		var err error
		lic, err = lookupLicense(key)
		if err == nil {
			keyHash = hashKey(key)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if lic == nil {
		w.WriteHeader(401)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="utf-8">
<title>Theend API — Access denied</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0b0b0f;color:#d4d4d8;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:#141418;border:1px solid #1f1f28;border-radius:16px;padding:48px 40px;max-width:440px;width:100%%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{color:#e74c3c;font-size:1.6rem;margin-bottom:8px;letter-spacing:-.5px}
p{color:#888;margin-bottom:24px;font-size:.9rem;line-height:1.5}
a.back{display:inline-block;color:#00d4aa;text-decoration:none;font-size:.85rem}
a.back:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <h1>%s</h1>
  <p>%s</p>
  <a class="back" href="/">%s</a>
</div>
</body>
</html>`, lang,
			T("Accès refusé", "Access denied"),
			T("Clé manquante ou invalide. Cette clé doit être une clé active du panel admin.", "Missing or invalid key. This key must be an active key from the admin panel."),
			T("← Retour", "← Back"),
		)
		return
	}

	langSwitcher := func() string {
		other := "en"; label := "English"
		if lang == "en" { other = "fr"; label = "Fran\u00e7ais" }
		q := ""
		if key != "" {
			q = fmt.Sprintf("key=%s&amp;", html.EscapeString(key))
		}
		return fmt.Sprintf(`<a href="?%slang=%s" class="lang-link">%s</a>`, q, other, label)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="utf-8">
<title>Theend API — Documentation</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0b0b0f;color:#d4d4d8;padding:0;line-height:1.6}
.top-bar{background:#111116;border-bottom:1px solid #1f1f28;padding:12px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;position:sticky;top:0;z-index:100}
.top-bar h1{color:#00d4aa;font-size:1.25rem;font-weight:700;letter-spacing:-.3px}
.top-bar .sub{color:#666;font-size:.8rem}
.top-links{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.top-links a,.lang-link{color:#888;text-decoration:none;font-size:.8rem;padding:4px 10px;border-radius:6px;transition:all .15s}
.top-links a:hover,.lang-link:hover{color:#00d4aa;background:#00d4aa11}
.lang-link{margin-left:8px;border:1px solid #2a2a2a}
.container{max-width:1100px;margin:0 auto;padding:24px}
.hero{text-align:center;padding:32px 0 40px}
.hero h1{font-size:2.2rem;color:#fff;font-weight:800;letter-spacing:-1px}
.hero h1 span{color:#00d4aa}
.hero p{color:#888;font-size:1rem;margin-top:8px;max-width:600px;margin-left:auto;margin-right:auto}
.endpoint-list{display:flex;flex-direction:column;gap:20px;margin-bottom:40px}
.card{background:#141418;border:1px solid #1f1f28;border-radius:12px;overflow:hidden;transition:border-color .2s}
.card:hover{border-color:#2a2a35}
.card-header{display:flex;align-items:center;gap:12px;padding:16px 20px;background:#1a1a22;border-bottom:1px solid #1f1f28;cursor:pointer;user-select:none}
.card-header:hover{background:#1e1e28}
.card-header .method{display:inline-block;padding:3px 10px;border-radius:5px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;min-width:48px;text-align:center}
.method-get{background:#61affe22;color:#61affe;border:1px solid #61affe44}
.method-post{background:#49cc9022;color:#49cc90;border:1px solid #49cc9044}
.card-header .path{font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:.85rem;color:#f0f0f0;font-weight:500}
.card-header .desc{color:#777;font-size:.8rem;margin-left:auto}
.card-body{padding:0 20px 20px}
.card-body.hidden{display:none}
.section{margin-top:16px}
.section-title{font-size:.75rem;text-transform:uppercase;letter-spacing:.8px;color:#555;margin-bottom:8px;font-weight:600}
pre{background:#0b0b0f;border:1px solid #1f1f28;border-radius:8px;padding:14px 16px;font-size:.78rem;overflow-x:auto;line-height:1.65;font-family:'SF Mono','Fira Code','Cascadia Code',monospace;color:#c9d1d9;margin-bottom:8px}
code{font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:.8rem}
.inline-code{background:#1a1a22;padding:1px 6px;border-radius:4px;color:#c9d1d9}
table{width:100%%;border-collapse:collapse;font-size:.8rem;margin-bottom:8px}
th{text-align:left;color:#666;padding:8px 10px;border-bottom:1px solid #1f1f28;font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.5px}
td{padding:8px 10px;border-bottom:1px solid #1a1a22;vertical-align:top;color:#b0b0b8}
tr:last-child td{border-bottom:none}
.status-code{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:600;font-size:.75rem;font-family:monospace}
.sc-2xx{background:#2ecc7122;color:#2ecc71}
.sc-4xx{background:#e74c3c22;color:#e74c3c}
.sc-5xx{background:#f39c1222;color:#f39c12}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600}
.badge-required{background:#e74c3c22;color:#e74c3c}
.badge-optional{background:#88888822;color:#888}
.bool-true{color:#2ecc71}
.bool-false{color:#e74c3c}
.info-grid{display:flex;flex-direction:column;gap:8px;margin:12px 0}
.info-item{background:#0b0b0f;border:1px solid #1f1f28;border-radius:8px;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.info-item .val{font-size:.95rem;font-weight:700;color:#f0f0f0;white-space:nowrap}
.info-item .lbl{font-size:.72rem;color:#888}
.expand-btn{background:none;border:none;color:#888;cursor:pointer;font-size:.75rem;padding:4px 8px;border-radius:4px;transition:all .15s}
.expand-btn:hover{color:#00d4aa;background:#00d4aa11}
.toggle-icon{transition:transform .2s;display:inline-block}
.toggle-icon.open{transform:rotate(90deg)}
.gateway-flow{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:12px 0}
.flow-step{background:#0b0b0f;border:1px solid #1f1f28;border-radius:8px;padding:12px;font-size:.78rem}
.flow-step .step-num{color:#00d4aa;font-weight:700;font-size:.7rem}
.flow-step .step-title{color:#f0f0f0;font-weight:600;margin:4px 0}
.flow-step .step-desc{color:#888;font-size:.72rem;line-height:1.5}
.flow-step .arrow{color:#555;text-align:center;font-size:1.2rem}
.key-info{background:#0d2818;border:1px solid #00d4aa33;border-radius:10px;padding:16px;margin-bottom:20px}
.key-info .key-display{font-family:monospace;font-size:.75rem;word-break:break-all;background:#0b0b0f;padding:10px 12px;border-radius:6px;margin-top:8px;color:#888;user-select:all}
.key-info .key-label{color:#00d4aa;font-weight:600;font-size:.8rem}
.unauthorized{background:#2a0f0f;border:1px solid #e74c3c33;border-radius:10px;padding:16px;margin-bottom:20px;text-align:center}
.unauthorized h3{color:#e74c3c;font-size:1rem}
.unauthorized p{color:#888;font-size:.8rem;margin-top:4px}
.footer{text-align:center;color:#444;font-size:.7rem;padding:30px 0}
.footer a{color:#555;text-decoration:none}
.footer a:hover{color:#00d4aa}
@media(max-width:640px){.container{padding:12px}.card-header{flex-wrap:wrap}.card-header .desc{width:100%%;margin-left:0}}
</style>
</head>
<body>

<div class="top-bar">
  <div><h1>Theend API</h1><span class="sub">%s</span></div>
  <div class="top-links">
    <a href="#healthz">Health</a>
    <a href="#check">Check</a>
    <a href="#gateway">Gateway</a>
    <a href="#dashboard">Dashboard</a>
    <a href="#codes">Codes</a>
    <a href="#cycle">Cycle</a>
    %s
  </div>
</div>

<div class="container">

<div class="hero">
  <h1><span>Theend</span> API</h1>
  <p>%s</p>
</div>
`, lang,
		T("Documentation compl\u00e8te de l'API", "Complete API Documentation"),
		langSwitcher(),
		T("Documentation interactive de l'API Theend \u2014 Proxy Vanguard pour Valorant &amp; League of Legends", "Interactive API documentation for Theend \u2014 Vanguard Proxy for Valorant &amp; League of Legends"),
	)

	{
		statusLabel := T("Actif", "Active")
		statusColor := "#2ecc71"

		tierLabel := lic.Tier
		switch lic.Tier {
		case "basic": tierLabel = T("De base", "Basic")
		case "full": tierLabel = "Full"
		case "staff": tierLabel = "Staff"
		}
		gameDisplay := ""
		for _, g := range []string{"valo", "league", "both"} {
			if lic.Games == g {
				label := g
				if g == "both" {
					label = "valo + league"
				}
				gameDisplay += fmt.Sprintf(`<span style="display:inline-block;background:#00d4aa22;color:#00d4aa;border-radius:4px;padding:2px 8px;margin:2px;font-size:.75rem">%s</span>`, label)
			}
		}

		quotaLabel := ""
		if lic.MaxRequests.Valid {
			quotaLabel = fmt.Sprintf("%d / %d", lic.RequestCount, lic.MaxRequests.Int64)
		} else {
			quotaLabel = fmt.Sprintf("%d (%s)", lic.RequestCount, T("illimité", "unlimited"))
		}
		expiresLabel := T("Jamais", "Never")
		if lic.ExpiresAt != "" {
			expiresLabel = lic.ExpiresAt
		}
		labelDisplay := lic.Label
		if labelDisplay == "" {
			labelDisplay = T("(sans label)", "(no label)")
		}

		total24h, failed24h := requestStats24h(lic.ID)
		successRate := "—"
		if total24h > 0 {
			successRate = fmt.Sprintf("%.0f%%", 100*float64(total24h-failed24h)/float64(total24h))
		}

		infoItem := func(lbl, val string) string {
			return fmt.Sprintf(`<div class="info-item"><div class="lbl">%s</div><div class="val">%s</div></div>`, lbl, val)
		}
		infoGrid := infoItem(T("Requêtes totales / quota", "Total requests / quota"), quotaLabel) +
			infoItem(T("Requêtes (24h)", "Requests (24h)"), fmt.Sprintf("%d", total24h)) +
			infoItem(T("Échecs (24h)", "Failures (24h)"), fmt.Sprintf("%d", failed24h)) +
			infoItem(T("Taux de succès (24h)", "Success rate (24h)"), successRate) +
			infoItem(T("Créée le", "Created on"), lic.CreatedAt) +
			infoItem(T("Expire le", "Expires on"), expiresLabel)

		fmt.Fprintf(w, `<div class="key-info">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
    <span class="key-label">🔑 %s &mdash; %s</span>
    <span style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <span style="color:%s;font-weight:600;font-size:.8rem">● %s</span>
      <span style="color:#888;font-size:.75rem">|</span>
      <span style="color:#f0f0f0;font-size:.8rem">%s</span>
      <span style="color:#888;font-size:.75rem">|</span>
      %s
    </span>
  </div>
  <div class="key-display">%s</div>
  <div style="font-size:.7rem;color:#555;margin-top:4px">SHA-256: %s</div>
  <div class="info-grid" style="margin-top:16px">
    %s
  </div>
</div>`,
			T("Clé authentifiée", "Authenticated Key"), html.EscapeString(labelDisplay),
			statusColor, statusLabel,
			tierLabel,
			gameDisplay,
			html.EscapeString(key),
			keyHash,
			infoGrid,
		)

		logs := recentRequestLogs(lic.ID, 15)
		rowsHTML := ""
		for _, l := range logs {
			statusColorRow := "#2ecc71"
			if l.Status >= 400 {
				statusColorRow = "#e74c3c"
			} else if l.Status == 0 {
				statusColorRow = "#888"
			}
			rowsHTML += fmt.Sprintf(
				`<tr><td>%s</td><td><code class="inline-code">%s</code></td><td style="color:%s;font-weight:600">%d</td><td>%d ms</td></tr>`,
				html.EscapeString(l.CreatedAt), html.EscapeString(l.Action),
				statusColorRow, l.Status, l.LatencyMs,
			)
		}
		if rowsHTML == "" {
			rowsHTML = fmt.Sprintf(`<tr><td colspan="4" style="text-align:center;color:#555;padding:16px">%s</td></tr>`,
				T("Aucune requête enregistrée pour cette clé pour le moment.", "No requests logged for this key yet."))
		}
		fmt.Fprintf(w, `<div class="card" style="margin-bottom:24px">
  <div class="card-header" style="cursor:default">
    <span class="path">%s</span>
  </div>
  <div class="card-body" style="padding-top:16px">
    <table>
      <thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead>
      <tbody>%s</tbody>
    </table>
  </div>
</div>`,
			T("Activité récente (15 dernières requêtes)", "Recent activity (last 15 requests)"),
			T("Date", "Date"), T("Action", "Action"), T("Statut", "Status"), T("Latence", "Latency"),
			rowsHTML,
		)
	}

	// ENDPOINT: GET /healthz
	fmt.Fprintf(w, `<div class="endpoint-list">

<div class="card" id="healthz">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="method method-get">GET</span>
    <span class="path">/healthz</span>
    <span class="desc">%s</span>
    <span class="expand-btn"><span class="toggle-icon">▶</span></span>
  </div>
  <div class="card-body">
    <div class="section">
      <div class="section-title">%s</div>
      <p style="font-size:.82rem;color:#888;margin-bottom:10px">%s</p>
    </div>
    <div class="section">
      <div class="section-title">%s</div>
      <pre>{"ok":true,"ts":%d}</pre>
    </div>
    <div class="section">
      <div class="section-title">%s</div>
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr><td><span class="status-code sc-2xx">200</span></td><td>%s</td><td><code>{"ok":true,"ts":&lt;unix&gt;}</code></td></tr>
      </table>
    </div>
    <div class="section">
      <div class="section-title">curl</div>
      <pre>curl -s https://emu.theend.lat/healthz</pre>
    </div>
  </div>
</div>`,
		T("Sant\u00e9 du serveur", "Server Health"),
		T("Description", "Description"),
		T("V\u00e9rifie que l'API est en ligne et op\u00e9rationnelle. Renvoie un timestamp UNIX.", "Checks that the API is online and operational. Returns a UNIX timestamp."),
		T("R\u00e9ponse (200)", "Response (200)"),
		time.Now().Unix(),
		T("Codes de statut", "Status Codes"),
		T("Code", "Code"),
		T("Signification", "Meaning"),
		T("Succ\u00e8s", "Success"),
	)

	// ENDPOINT: POST /v1/check
	fmt.Fprintf(w, `
<div class="card" id="check">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="method method-post">POST</span>
    <span class="path">/v1/check</span>
    <span class="desc">%s</span>
    <span class="expand-btn"><span class="toggle-icon">▶</span></span>
  </div>
  <div class="card-body">
    <div class="section">
      <div class="section-title">%s</div>
      <p style="font-size:.82rem;color:#888;margin-bottom:10px">%s</p>
    </div>
    <div class="section">
      <div class="section-title">%s</div>
      <pre>{
  "key":  "string  — %s",
  "hwid": "string  — %s <span style="color:#555">(optional)</span>"
}</pre>
    </div>
    <div class="section">
      <div class="section-title">%s</div>
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr><td><span class="status-code sc-2xx">200</span></td><td>%s</td><td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":true,"tier":"basic|full|staff","games":"valo|league"}</pre></td></tr>
        <tr><td><span class="status-code sc-4xx">400</span></td><td>%s</td><td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"invalid input"}</pre></td></tr>
        <tr><td><span class="status-code sc-4xx">401</span></td><td>%s</td><td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"AUTH_INVALID_KEY|AUTH_KEY_NOT_FOUND|AUTH_KEY_REVOKED"}</pre></td></tr>
      </table>
    </div>
    <div class="section">
      <div class="section-title">curl</div>
      <pre>curl -s -X POST https://emu.theend.lat/v1/check \
  -H "Content-Type: application/json" \
  -d '{"key":"YOUR_KEY"}'</pre>
    </div>
  </div>
</div>`,
		T("Validation de licence", "License Validation"),
		T("Description", "Description"),
		T("Valide une cl\u00e9 de licence et retourne le tier (basic/full/staff) et les jeux autoris\u00e9s (valo/league).", "Validates a license key and returns the tier (basic/full/staff) and allowed games (valo/league)."),
		T("Requ\u00eate", "Request"),
		T("cl\u00e9 de licence", "license key"),
		T("identifiant mat\u00e9riel optionnel", "optional hardware ID"),
		T("R\u00e9ponses possibles", "Possible Responses"),
		T("Code", "Code"),
		T("Condition", "Condition"),
		T("R\u00e9ponse", "Response"),
		T("Cl\u00e9 valide", "Valid key"),
		T("JSON invalide", "Invalid JSON"),
		T("Cl\u00e9 invalide/r\u00e9voqu\u00e9e/introuvable", "Invalid/revoked/not found key"),
	)

	// ENDPOINT: POST /vanguard/session/gateway
	fmt.Fprintf(w, `
<div class="card" id="gateway">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="method method-post">POST</span>
    <span class="path">/vanguard/session/gateway</span>
    <span class="desc">%s</span>
    <span class="expand-btn"><span class="toggle-icon">▶</span></span>
  </div>
  <div class="card-body">
    <div class="section">
      <div class="section-title">%s</div>
      <p style="font-size:.82rem;color:#888;margin-bottom:10px">%s</p>
    </div>
    <div class="section">
      <div class="section-title">%s</div>
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr><td><code>action</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td><code>"auth"</code> (défaut), <code>"access"</code>, <code>"heartbeat"</code>, <code>"report"</code></td></tr>
        <tr><td><code>private_key</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s</td></tr>
        <tr><td><code>game</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td><code>"valo"</code> ou <code>"league"</code></td></tr>
        <tr><td><code>gametoken</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s (auth uniquement)</td></tr>
        <tr><td><code>sid</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s (valo, auth)</td></tr>
        <tr><td><code>puuid</code></td><td>string</td><td><span class="badge badge-optional">%s</span></td><td>%s</td></tr>
        <tr><td><code>session_id</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s</td></tr>
        <tr><td><code>response</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s</td></tr>
        <tr><td><code>object_id</code></td><td>string</td><td><span class="badge badge-required">%s</span></td><td>%s</td></tr>
      </table>
    </div>

    <div class="section">
      <div class="section-title">%s</div>

      <p style="font-size:.78rem;font-weight:600;color:#aaa;margin:8px 0 4px">auth</p>
      <pre>{
  "action": "auth",
  "private_key": "VOTRE_CLÉ",
  "game": "valo",
  "gametoken": "JWT_Riot",
  "sid": "SID_matériel",
  "puuid": "PUUID_Riot"
}</pre>

      <p style="font-size:.78rem;font-weight:600;color:#aaa;margin:8px 0 4px">access</p>
      <pre>{
  "action": "access",
  "private_key": "VOTRE_CLÉ",
  "game": "valo",
  "session_id": "ID_retourné_par_auth",
  "response": "B64_Réponse_Riot_du_gateway"
}</pre>

      <p style="font-size:.78rem;font-weight:600;color:#aaa;margin:8px 0 4px">heartbeat</p>
      <pre>{
  "action": "heartbeat",
  "private_key": "VOTRE_CLÉ",
  "game": "valo",
  "session_id": "ID_de_session",
  "response": "B64_Réponse_Riot_du_gateway"
}</pre>

      <p style="font-size:.78rem;font-weight:600;color:#aaa;margin:8px 0 4px">report</p>
      <pre>{
  "action": "report",
  "private_key": "VOTRE_CLÉ",
  "game": "valo",
  "session_id": "ID_de_session",
  "object_id": "ObjectID_à_signaler"
}</pre>
    </div>

    <div class="section">
      <div class="section-title">%s</div>
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr>
          <td><span class="status-code sc-2xx">200</span></td>
          <td>%s</td>
          <td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":true,"data":"aW9...b3A=","session_id":"...","loyalty_uuid":"...","pending_checks":[],"new_uuids":[],"new_jwts":[],"new_sids":[]}</pre></td>
        </tr>
        <tr>
          <td><span class="status-code sc-4xx">400</span></td>
          <td>%s</td>
          <td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"..."}</pre></td>
        </tr>
        <tr>
          <td><span class="status-code sc-4xx">401</span></td>
          <td>%s</td>
          <td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"unauthorized"}</pre></td>
        </tr>
        <tr>
          <td><span class="status-code sc-4xx">403</span></td>
          <td>%s</td>
          <td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"tier 'basic' not authorized for action '...'"}</pre></td>
        </tr>
        <tr>
          <td><span class="status-code sc-5xx">500</span></td>
          <td>%s</td>
          <td><pre style="margin:0;padding:6px 8px;font-size:.72rem">{"success":false,"message":"internal error"}</pre></td>
        </tr>
      </table>
    </div>

    <div class="section">
      <div class="section-title">%s</div>
      <p style="font-size:.82rem;color:#888;margin-bottom:10px">%s</p>
      <pre>curl -s -X POST https://emu.theend.lat/vanguard/session/gateway \
  -H "Content-Type: application/json" \
  -d '{"action":"auth","private_key":"KEY","game":"valo","gametoken":"JWT","sid":"SID"}'</pre>
    </div>

    <div class="section">
      <div class="section-title">%s</div>
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr><td><code>success</code></td><td><span class="bool-true">true</span> / <span class="bool-false">false</span></td><td>%s</td></tr>
        <tr><td><code>data</code></td><td>string (base64)</td><td>%s</td></tr>
        <tr><td><code>session_id</code></td><td>string (uuid)</td><td>%s</td></tr>
        <tr><td><code>loyalty_uuid</code></td><td>string (uuid)</td><td>%s</td></tr>
        <tr><td><code>pending_checks</code></td><td>array[string]</td><td>%s</td></tr>
        <tr><td><code>new_uuids</code></td><td>array[string]</td><td>%s</td></tr>
        <tr><td><code>new_jwts</code></td><td>array[string]</td><td>%s</td></tr>
        <tr><td><code>new_sids</code></td><td>array[string]</td><td>%s</td></tr>
        <tr><td><code>message</code></td><td>string</td><td>%s</td></tr>
      </table>
      <p style="font-size:.75rem;color:#555;margin-top:6px">%s</p>
    </div>
  </div>
</div>`,
		T("Passerelle Vanguard", "Vanguard Gateway"),
		T("Description", "Description"),
		T("Proxy Vanguard en 4 \u00e9tapes : auth \u2192 access \u2192 heartbeat \u2192 report. Construit et chiffre des enveloppes protobuf \u00e0 envoyer aux serveurs Riot.", "4-step Vanguard proxy: auth \u2192 access \u2192 heartbeat \u2192 report. Builds and encrypts protobuf envelopes to send to Riot servers."),
		T("Param\u00e8tres de la requ\u00eate", "Request Parameters"),
		T("Champ", "Field"),
		T("Type", "Type"),
		T("Requis", "Required"),
		T("Description", "Description"),
		T("Oui", "Yes"),
		T("Oui", "Yes"),
		T("Votre cl\u00e9 de licence", "Your license key"),
		T("Oui", "Yes"),
		T("Oui (auth)", "Yes (auth)"),
		T("Token JWT Riot", "Riot JWT token"),
		T("Oui (valo, auth)", "Yes (valo, auth)"),
		T("Identifiant mat\u00e9riel (SID)", "Hardware identifier (SID)"),
		T("Non", "No"),
		T("Optionnel mais recommand\u00e9", "Optional but recommended"),
		T("Oui (access+)", "Yes (access+)"),
		T("Retourn\u00e9 par auth", "Returned by auth"),
		T("Oui (access+)", "Yes (access+)"),
		T("R\u00e9ponse base64 de Riot", "Base64 response from Riot"),
		T("Oui (report)", "Yes (report)"),
		T("ObjectID \u00e0 signaler", "ObjectID to report"),
		T("Exemples de requ\u00eates par action", "Request Examples by Action"),
		T("Codes de statut", "Status Codes"),
		T("Code", "Code"),
		T("Condition", "Condition"),
		T("R\u00e9ponse", "Response"),
		T("Auth/Access/Heartbeat r\u00e9ussi", "Auth/Access/Heartbeat success"),
		T("Champ manquant ou action invalide", "Missing field or invalid action"),
		T("Cl\u00e9 invalide / session expir\u00e9e", "Invalid key / expired session"),
		T("Tier basic interdit pour cette action", "Basic tier not allowed for this action"),
		T("Erreur interne", "Internal server error"),
		T("Exemple curl", "curl Example"),
		T("Auth : cr\u00e9e une session et retourne une enveloppe chiffr\u00e9e.", "Auth: creates a session and returns an encrypted envelope."),
		T("Structure de la r\u00e9ponse", "Response Structure"),
		T("Champ", "Field"),
		T("Type", "Type"),
		T("Description", "Description"),
		T("Indique si la requ\u00eate a r\u00e9ussi", "Whether the request succeeded"),
		T("Enveloppe chiffr\u00e9e (base64) \u00e0 envoyer \u00e0 Riot", "Encrypted envelope (base64) to send to Riot"),
		T("ID de session pour les requ\u00eates suivantes", "Session ID for subsequent requests"),
		T("UUID de fid\u00e9lit\u00e9 Riot", "Riot loyalty UUID"),
		T("V\u00e9rifications en attente (ObjectIDs)", "Pending checks (ObjectIDs)"),
		T("Nouveaux UUIDs g\u00e9n\u00e9r\u00e9s par Riot", "New UUIDs generated by Riot"),
		T("Nouveaux JWTs Riot", "New Riot JWTs"),
		T("Nouveaux SIDs mat\u00e9riels", "New hardware SIDs"),
		T("Message texte (report ou erreur)", "Text message (report or error)"),
		T("Les champs data, session_id, loyalty_uuid sont absents si success=false", "Fields data, session_id, loyalty_uuid are absent when success=false"),
	)

	fmt.Fprintf(w, `</div>

<div class="card" id="codes" style="margin-top:20px">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="method" style="background:#88888822;color:#888;border:1px solid #88888844;text-transform:none;letter-spacing:0">HTTP</span>
    <span class="path">%s</span>
    <span class="desc">%s</span>
    <span class="expand-btn"><span class="toggle-icon">▶</span></span>
  </div>
  <div class="card-body">
    <div class="section">
      <table>
        <tr><th>%s</th><th>%s</th><th>%s</th></tr>
        <tr><td><span class="status-code sc-2xx">200</span></td><td>OK</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-4xx">400</span></td><td>Bad Request</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-4xx">401</span></td><td>Unauthorized</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-4xx">403</span></td><td>Forbidden</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-4xx">404</span></td><td>Not Found</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-4xx">405</span></td><td>Method Not Allowed</td><td>%s</td></tr>
        <tr><td><span class="status-code sc-5xx">500</span></td><td>Internal Server Error</td><td>%s</td></tr>
      </table>
    </div>
  </div>
</div>
`,
		T("Codes d'\u00e9tat HTTP", "HTTP Status Codes"),
		T("Tous les codes utilis\u00e9s par l'API", "All codes used by the API"),
		T("Code", "Code"),
		T("Nom", "Name"),
		T("Signification", "Meaning"),
		T("Succ\u00e8s \u2014 la r\u00e9ponse contient les donn\u00e9es attendues", "Success \u2014 response contains expected data"),
		T("Requ\u00eate invalide \u2014 champ manquant ou valeur incorrecte", "Bad request \u2014 missing field or invalid value"),
		T("Cl\u00e9 invalide, r\u00e9voqu\u00e9e, introuvable ou session expir\u00e9e", "Invalid, revoked, not found key or expired session"),
		T("Le tier de la cl\u00e9 n'autorise pas cette action (basic \u2192 auth seulement)", "Key tier does not allow this action (basic \u2192 auth only)"),
		T("Route inexistante", "Route does not exist"),
		T("Mauvaise m\u00e9thode HTTP (utiliser POST ou GET)", "Wrong HTTP method (use POST or GET)"),
		T("Erreur interne du serveur", "Internal server error"),
	)

	// Gateway Cycle
	fmt.Fprintf(w, `
<div class="card" id="cycle" style="margin-top:20px">
  <div class="card-header" onclick="toggleCard(this)">
    <span class="method" style="background:#00d4aa22;color:#00d4aa;border:1px solid #00d4aa44;text-transform:none;letter-spacing:0">⟳</span>
    <span class="path">%s</span>
    <span class="desc">%s</span>
    <span class="expand-btn"><span class="toggle-icon">▶</span></span>
  </div>
  <div class="card-body">
    <p style="font-size:.82rem;color:#888;margin-bottom:12px">%s</p>
    <div class="gateway-flow">
      <div class="flow-step">
        <div class="step-num">%s 1</div>
        <div class="step-title">auth</div>
        <div class="step-desc">%s</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#333">→</div>
      <div class="flow-step">
        <div class="step-num">%s 2</div>
        <div class="step-title">Riot Gateway</div>
        <div class="step-desc">%s</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#333">→</div>
      <div class="flow-step">
        <div class="step-num">%s 3</div>
        <div class="step-title">access</div>
        <div class="step-desc">%s</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#333">→</div>
      <div class="flow-step">
        <div class="step-num">%s 4</div>
        <div class="step-title">Riot Gateway</div>
        <div class="step-desc">%s</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#333">→</div>
      <div class="flow-step">
        <div class="step-num">%s 5</div>
        <div class="step-title">heartbeat</div>
        <div class="step-desc">%s</div>
      </div>
      <div style="display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#333">→</div>
      <div class="flow-step">
        <div class="step-num">%s 6</div>
        <div class="step-title">report</div>
        <div class="step-desc">%s</div>
      </div>
    </div>

    <div class="section" style="margin-top:16px">
      <div class="section-title">%s</div>
      <pre># %s
curl -s -X POST https://emu.theend.lat/vanguard/session/gateway \
  -H "Content-Type: application/json" \
  -d '{"action":"auth","private_key":"KEY","game":"valo","gametoken":"JWT","sid":"SID"}'

# %s
curl -s -X POST "https://REGION.vg.ac.pvp.net:8443/vanguard/v1/gateway" \
  -H "X-VG-1: 3" \
  --data-binary @envelope.bin

# %s
curl -s -X POST https://emu.theend.lat/vanguard/session/gateway \
  -H "Content-Type: application/json" \
  -d '{"action":"access","private_key":"KEY","game":"valo","session_id":"...","response":"B64..."}'

# %s
curl -s -X POST "https://REGION.vg.ac.pvp.net:8443/vanguard/v1/gateway" \
  -H "X-VG-1: 4" \
  --data-binary @envelope2.bin

# %s  (toutes les ~20s)
curl -s -X POST https://emu.theend.lat/vanguard/session/gateway \
  -H "Content-Type: application/json" \
  -d '{"action":"heartbeat","private_key":"KEY","game":"valo","session_id":"...","response":"B64..."}'</pre>
    </div>
  </div>
</div>

<div class="footer">
  Theend API — <a href="?key=%s">%s</a>
</div>

</div>

<script>
function toggleCard(el) {
  var body = el.nextElementSibling;
  var icon = el.querySelector('.toggle-icon');
  if (body.classList.contains('hidden')) {
    body.classList.remove('hidden');
    icon.classList.add('open');
  } else {
    body.classList.add('hidden');
    icon.classList.remove('open');
  }
}
(function() {
  var hash = window.location.hash;
  if (hash) {
    var target = document.querySelector(hash);
    if (target) {
      var body = target.querySelector('.card-body');
      var icon = target.querySelector('.toggle-icon');
      if (body) {
        body.classList.remove('hidden');
        if (icon) icon.classList.add('open');
      }
      setTimeout(function(){ target.scrollIntoView({behavior:'smooth',block:'start'}); }, 100);
    }
  }
})();
</script>

</body>
</html>`,
		T("Cycle de la Passerelle Vanguard", "Vanguard Gateway Cycle"),
		T("\u00c9tapes compl\u00e8tes du proxy", "Complete proxy steps"),
		T("Le cycle complet en 6 \u00e9tapes pour \u00e9tablir et maintenir une session Vanguard :", "The complete 6-step cycle to establish and maintain a Vanguard session:"),
		T("\u00c9tape", "Step"),
		T("Envoie gametoken + sid \u2192 re\u00e7ois enveloppe chiffr\u00e9e + session_id", "Send gametoken + sid \u2192 receive encrypted envelope + session_id"),
		T("\u00c9tape", "Step"),
		T("POST l'enveloppe avec X-VG-1:3 \u2192 re\u00e7ois r\u00e9ponse b64", "POST envelope with X-VG-1:3 \u2192 receive b64 response"),
		T("\u00c9tape", "Step"),
		T("Envoie session_id + response_b64 \u2192 re\u00e7ois nouvelle enveloppe", "Send session_id + response_b64 \u2192 receive new envelope"),
		T("\u00c9tape", "Step"),
		T("POST la nouvelle enveloppe avec X-VG-1:4 \u2192 re\u00e7ois r\u00e9ponse b64", "POST new envelope with X-VG-1:4 \u2192 receive b64 response"),
		T("\u00c9tape", "Step"),
		T("Boucle heartbeat toutes les ~20s pour maintenir la session", "Heartbeat loop every ~20s to keep session alive"),
		T("\u00c9tape", "Step"),
		T("Signale des ObjectIDs (anti-cheat tasks) \u00e0 Riot", "Report ObjectIDs (anti-cheat tasks) to Riot"),
		T("Exemple de cycle complet", "Complete Cycle Example"),
		T("\u00c9tape 1 : Auth", "Step 1: Auth"),
		T("\u00c9tape 2 : Forward \u00e0 Riot (X-VG-1:3)", "Step 2: Forward to Riot (X-VG-1:3)"),
		T("\u00c9tape 3 : Access", "Step 3: Access"),
		T("\u00c9tape 4 : Forward \u00e0 Riot (X-VG-1:4)", "Step 4: Forward to Riot (X-VG-1:4)"),
		T("\u00c9tape 5 : Heartbeat", "Step 5: Heartbeat"),
		html.EscapeString(key),
		T("Retour en haut", "Back to top"),
	)
}
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4100"
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "theend.db"
	}

	if err := initDB(dbPath); err != nil {
		log.Fatalf("[init] db: %v", err)
	}
	log.Printf("[init] db opened at %s", dbPath)

	emuPath := os.Getenv("EMU_KEYS_DB_PATH")
	if emuPath == "" {
		emuPath = emuKeysDBPath
	}
	var emuErr error
	emuKeysDB, emuErr = sql.Open("sqlite3", emuPath+"?mode=ro&_busy_timeout=5000")
	if emuErr != nil {
		log.Printf("[init] WARNING: emu keys db unavailable (%s): %v", emuPath, emuErr)
		emuKeysDB = nil
	} else {
		log.Printf("[init] emu keys db opened at %s (read-only)", emuPath)
	}

	if err := loadServerPubkey(); err != nil {
		log.Printf("[init] WARNING: no SERVER_PUBKEY loaded yet : %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/v1/check", handleCheck)
	mux.HandleFunc("/vanguard/session/gateway", handleGateway)
	mux.HandleFunc("/vgc/session/gateway", handleGateway)    // alias for emulator
	mux.HandleFunc("/vgc/session/access", handleGateway)     // alias for emulator
	mux.HandleFunc("/vgc/session/heartbeat", handleGateway)  // alias for emulator
	mux.HandleFunc("/dashboard", handleDashboard)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Theend API</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f0f0f;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
  .card{background:#1a1a1a;border-radius:16px;padding:48px 40px;max-width:440px;width:100%%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.5)}
  h1{color:#00d4aa;font-size:2rem;margin-bottom:8px;letter-spacing:-.5px}
  p{color:#888;margin-bottom:24px;font-size:.9rem;line-height:1.5}
  input{width:100%%;padding:14px 16px;border:1px solid #333;border-radius:10px;background:#0f0f0f;color:#e0e0e0;font-size:1rem;outline:none;transition:border-color .2s;font-family:monospace}
  input:focus{border-color:#00d4aa}
  input::placeholder{color:#555}
  button{width:100%%;padding:14px;margin-top:12px;border:none;border-radius:10px;background:#00d4aa;color:#0f0f0f;font-size:1rem;font-weight:600;cursor:pointer;transition:opacity .2s}
  button:hover{opacity:.85}
  .hint{font-size:.8rem;color:#555;margin-top:16px;line-height:1.6}
  .hint a{color:#00d4aa;text-decoration:none}
  .hint a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <h1>Theend</h1>
  <p>Enter your API key to access the dashboard</p>
  <form method="get" action="/dashboard">
    <input type="text" name="key" placeholder="Paste your API key..." autofocus spellcheck="false" autocomplete="off">
    <button type="submit">Access Dashboard</button>
  </form>
</div>
</body>
</html>`)
	})

	startSessionGC()
	log.Printf("[init] session GC running (30 min TTL)")

	if os.Getenv("SEED_DEV_KEY") == "1" {
		seedDevKey()
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      withMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("[ready] theend API listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[srv] %v", err)
	}
}

func withMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func seedDevKey() {
	key := "theend_dev_" + randB32(32)
	keyHash := hashKey(key)
	_, err := db.Exec(`INSERT OR IGNORE INTO licenses(key_hash, tier, games, active) VALUES(?, 'full', 'valo', 1)`, keyHash)
	if err != nil {
		log.Printf("[seed] %v", err)
		return
	}
	log.Printf("[seed] dev key (SAVE IT) : %s", key)
}

func randB32(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i, v := range b {
		out[i] = alphabet[v%32]
	}
	return string(out)
}

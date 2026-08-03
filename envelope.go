// envelope.go — Build Vanguard envelopes server-side
//
// Spec ref: VANGUARD_SPEC.md sections 2-9
//
// Implements 3 actions:
//   - auth      → action=3 attestation envelope
//   - access    → action=4 batch wrapper (echo nested from Riot's previous response)
//   - heartbeat → action=7 heartbeat (echo + HWID counter)
//
// Crypto:
//   inner_pt → AES-256-GCM(K_inner random, IV random) → inner_CT + inner_TAG
//   K_inner  → RSA-2048-OAEP-SHA512(SERVER_PUBKEY) → 256B blob
//   envelope = pb(field#1=action, field#2=("RG\x01\x00" + RSA + IV + CT + TAG))

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// ============ HWID counter (per-session) ============
// Random per session to prevent Riot fingerprinting all users.
func getHWIDCounter() []byte {
	b := make([]byte, 5)
	rand.Read(b)
	return b
}

// ============ SERVER pubkey state ============

func loadServerPubkey() error {
	pubkeyPath := os.Getenv("SERVER_PUBKEY_PATH")
	if pubkeyPath == "" {
		pubkeyPath = "server_pubkey.bin"
	}
	b, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return err
	}
	if len(b) < 24 {
		return fmt.Errorf("pubkey blob too short: %d bytes", len(b))
	}
	pubkeyMu.Lock()
	currentPub = b
	pubkeyMu.Unlock()
	return nil
}

// updateServerPubkeyFromPKIXDER parses a PKIX DER SubjectPublicKeyInfo (the format
// Riot sends in responses), converts it to BCRYPT_RSAPUBLICBLOB layout, and
// stores it as our current SERVER_PUBKEY.
func updateServerPubkeyFromPKIXDER(der []byte) error {
	pub, err := parsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("PKIX parse: %w", err)
	}
	blob, err := rsaPubKeyToBCRYPTBlob(pub)
	if err != nil {
		return fmt.Errorf("blob encode: %w", err)
	}
	pubkeyMu.Lock()
	currentPub = blob
	pubkeyMu.Unlock()
	return nil
}

// parsePKIXPublicKey wraps crypto/x509.ParsePKIXPublicKey but ensures we got RSA.
func parsePKIXPublicKey(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("PKIX key is not RSA")
	}
	return rsaPub, nil
}

// rsaPubKeyToBCRYPTBlob encodes a *rsa.PublicKey as BCRYPT_RSAKEY_BLOB (RSAPUBLICBLOB).
// Layout: Magic + BitLength + cbExp + cbMod + cbP1 + cbP2 + Exp + Modulus.
func rsaPubKeyToBCRYPTBlob(pub *rsa.PublicKey) ([]byte, error) {
	modBytes := pub.N.Bytes()
	bitLen := uint32(len(modBytes) * 8)

	// Encode exponent in minimal big-endian
	e := pub.E
	if e <= 0 {
		return nil, errors.New("invalid exponent")
	}
	var expBytes []byte
	for e > 0 {
		expBytes = append([]byte{byte(e & 0xff)}, expBytes...)
		e >>= 8
	}

	out := make([]byte, 0, 24+len(expBytes)+len(modBytes))
	out = appendU32LE(out, 0x31415352) // 'RSA1'
	out = appendU32LE(out, bitLen)
	out = appendU32LE(out, uint32(len(expBytes)))
	out = appendU32LE(out, uint32(len(modBytes)))
	out = appendU32LE(out, 0) // cbPrime1
	out = appendU32LE(out, 0) // cbPrime2
	out = append(out, expBytes...)
	out = append(out, modBytes...)
	return out, nil
}

func appendU32LE(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// ============ Protobuf helpers (spec §18) ============

func appendVarint(buf []byte, n uint64) []byte {
	for n >= 0x80 {
		buf = append(buf, byte(n)|0x80)
		n >>= 7
	}
	return append(buf, byte(n))
}

func pbVarint(field uint64, value uint64) []byte {
	out := appendVarint(nil, field<<3)
	return appendVarint(out, value)
}

func pbLenDelim(field uint64, data []byte) []byte {
	out := appendVarint(nil, field<<3|2)
	out = appendVarint(out, uint64(len(data)))
	return append(out, data...)
}

// ============ AES-256-GCM (spec §3) ============

func aesGcmEncrypt(key, iv, plaintext []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	// Go's Seal returns: ciphertext || tag
	return sealed[:len(sealed)-16], sealed[len(sealed)-16:], nil
}

func aesGcmDecrypt(key, iv, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(ciphertext, tag...), nil)
}

// ============ RSA-OAEP-SHA512 (spec §3) ============

// Parse Windows BCRYPT_RSAKEY_BLOB / BCRYPT_RSAPUBLIC_BLOB layout (spec §4)
//
//	ULONG Magic;       0x31415352 ('RSA1')
//	ULONG BitLength;
//	ULONG cbPublicExp;
//	ULONG cbModulus;
//	ULONG cbPrime1;
//	ULONG cbPrime2;
//	BYTE  PublicExp[cbPublicExp];
//	BYTE  Modulus[cbModulus];
func parseRSAPubBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < 24 {
		return nil, errors.New("RSA pub blob: too short")
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != 0x31415352 {
		return nil, fmt.Errorf("RSA pub blob: bad magic 0x%x (expected RSA1)", magic)
	}
	cbExp := binary.LittleEndian.Uint32(blob[8:12])
	cbMod := binary.LittleEndian.Uint32(blob[12:16])
	if 24+int(cbExp)+int(cbMod) > len(blob) {
		return nil, errors.New("RSA pub blob: truncated body")
	}

	off := 24
	expBytes := blob[off : off+int(cbExp)]
	off += int(cbExp)
	modBytes := blob[off : off+int(cbMod)]

	// Convert big-endian exp → int
	e := 0
	for _, b := range expBytes {
		e = e<<8 | int(b)
	}

	// Convert big-endian modulus → big.Int
	n := new(big.Int).SetBytes(modBytes)

	return &rsa.PublicKey{N: n, E: e}, nil
}

func currentServerPub() (*rsa.PublicKey, error) {
	pubkeyMu.RLock()
	blob := currentPub
	pubkeyMu.RUnlock()
	if len(blob) == 0 {
		return nil, errors.New("SERVER_PUBKEY not loaded yet")
	}
	return parseRSAPubBlob(blob)
}

// ============ Inner protobuf builders ============

// normalizeSID — if the incoming SID is shorter than 200 bytes (i.e. just a
// PUUID was sent instead of the full hardware SID), wrap it into the proper
// 807-byte Vanguard format with 5 null-padded chunks in field 6.
//
// Captured Vanguard envelope shows field#1 is ALWAYS 807 bytes with format:
//   ||1;<smbios b64 16B>||2;<cpu b64 32B>||3;<disk b64 32B>||4||5;<mac b64 6B>||6;<5 chunks of 97B each separated by ';'>||
// Vanguard backend matchmaking check requires this exact format.
// derivePerUser produces a stable per-account byte slice of `n` bytes by hashing
// SHA256(seed || tag). Same seed (e.g. PUUID) → same output → consistent
// fingerprint across sessions, but unique per account so Riot can't fingerprint
// a shared "dummy" SID across the userbase.
func derivePerUser(seed, tag string, n int) []byte {
	out := make([]byte, 0, n)
	counter := byte(0)
	for len(out) < n {
		h := sha256.Sum256([]byte(seed + ":" + tag + ":" + string(counter)))
		out = append(out, h[:]...)
		counter++
	}
	return out[:n]
}

func normalizeSID(sid, seed string) string {
	// If already in proper SID format, pass through
	if len(sid) > 200 && (sid[0] == '|' && sid[1] == '|') {
		return sid
	}
	// [VAL-5 FIX 2026-06-29] Hardcoded fingerprint = shared dummy → Riot 403.
	// Derive per-account from PUUID seed (stable across Valorant relaunches).
	// Sid changes per pipe session, but PUUID is account-stable → same fake
	// "machine" presented to Riot for the same account always.
	pad97b64 := func(b []byte) string {
		buf := make([]byte, 97)
		copy(buf, b)
		return base64.StdEncoding.EncodeToString(buf)
	}
	if seed == "" { seed = sid }
	smbios := base64.StdEncoding.EncodeToString(derivePerUser(seed, "smbios", 16))
	cpu    := base64.StdEncoding.EncodeToString(derivePerUser(seed, "cpu", 32))
	disk   := base64.StdEncoding.EncodeToString(derivePerUser(seed, "disk", 32))
	mac    := base64.StdEncoding.EncodeToString(derivePerUser(seed, "mac", 6))
	// diskInfo: keep plausible-looking text but vary serial per account.
	diskSerial := fmt.Sprintf("%X", derivePerUser(seed, "diskserial", 16))
	diskInfo := []byte("WD_BLACK SN850X 2000GB  " + diskSerial)
	f6 := pad97b64(diskInfo) + ";" + pad97b64(nil) + ";" + pad97b64(nil) + ";" + pad97b64(nil) + ";" + pad97b64(nil)
	return "||1;" + smbios + "||2;" + cpu + "||3;" + disk + "||4||5;" + mac + "||6;" + f6 + "||"
}

// buildInnerAction3 — assemble inner clear for action=3 attestation.
// Spec §6: 9 fields, ~2304B total.
// buildInnerAction3 — assemble inner clear for action=3 attestation.
// Returns (bytes, loyaltyUUID) — loyaltyUUID is the value put in field#13,
// which loyalty-v2 server uses for its RMS check on Valorant.
// Client must pre-register this UUID via /product-session/v1/sessions/<UUID>
// BEFORE the action=3 POST reaches Riot, otherwise loyalty-v2 Skip → VAL-5.
func buildInnerAction3WithUUID(jwt, sid, riotKey, providedLoyaltyUUID string) ([]byte, string) {
	loyaltyUUID := providedLoyaltyUUID
	if loyaltyUUID == "" { loyaltyUUID = newUUID() }
	bytes := buildInnerAction3Inner(jwt, sid, riotKey, loyaltyUUID)
	return bytes, loyaltyUUID
}

func buildInnerAction3Inner(jwt, sid, riotKey, loyaltyUUID string) []byte {
	return buildInnerAction3WithUUIDValue(jwt, sid, riotKey, loyaltyUUID)
}

func buildInnerAction3(jwt, sid, riotKey string) []byte {
	bytes, _ := buildInnerAction3WithUUID(jwt, sid, riotKey, "")
	return bytes
}

// extractJWTSub decodes a JWT and returns the "sub" claim (PUUID), or empty if not found.
func extractJWTSub(jwt string) string {
	parts := splitDot(jwt)
	if len(parts) < 2 { return "" }
	pl := parts[1]
	pad := (4 - len(pl)%4) % 4
	pl += strings.Repeat("=", pad)
	pl = strings.NewReplacer("-", "+", "_", "/").Replace(pl)
	raw, err := base64.StdEncoding.DecodeString(pl)
	if err != nil { return "" }
	const needle = `"sub":"`
	i := strings.Index(string(raw), needle)
	if i < 0 { return "" }
	s := string(raw)[i+len(needle):]
	end := strings.IndexByte(s, '"')
	if end < 0 { return "" }
	return s[:end]
}

func splitDot(s string) []string { return strings.SplitN(s, ".", 3) }

// internal renamed worker
func buildInnerAction3WithUUIDValue(jwt, sid, riotKey, loyaltyUUID string) []byte {
	// [HW STABILITY FIX 2026-06-29] Use PUUID (stable per account) as fingerprint
	// seed, NOT sid (= pipe UUID, changes each Valorant relaunch). Otherwise
	// Riot sees a "different machine" on every relaunch for the same account →
	// 403 after first session.
	fingerSeed := extractJWTSub(jwt)
	if fingerSeed == "" { fingerSeed = sid }
	sid = normalizeSID(sid, fingerSeed)
	var out []byte
	// field#1 STR : SID format
	out = append(out, pbLenDelim(1, []byte(sid))...)
	// field#2 nested : "08 01 10 02 22 0a" + OS version "10.0.26200"
	out = append(out, pbLenDelim(2, []byte{
		0x08, 0x01, 0x10, 0x02, 0x22, 0x0a,
		'1', '0', '.', '0', '.', '2', '6', '2', '0', '0',
	})...)
	// field#4 STR : JWT
	out = append(out, pbLenDelim(4, []byte(jwt))...)
	// field#5 STR : RIOT_KEY PKIX DER base64 with PEM-style newlines
	// [VAL-5 FIX 2026-06-26] Nezur wraps base64 in 64-char lines + trailing newline
	// (+6 bytes). Riot accepts both but Nezur format = pixel-identical envelope.
	out = append(out, pbLenDelim(5, []byte(pemWrap(riotKey)))...)
	// field#6 + #7 : constant `08 01 10 12 18 03 20 4a`
	const6or7 := []byte{0x08, 0x01, 0x10, 0x12, 0x18, 0x03, 0x20, 0x4a}
	out = append(out, pbLenDelim(6, const6or7)...)
	out = append(out, pbLenDelim(7, const6or7)...)
	// field#8 STR : "com.riotgames.valorant"
	out = append(out, pbLenDelim(8, []byte("com.riotgames.valorant"))...)
	// field#9 VARINT : action=3
	out = append(out, pbVarint(9, 3)...)
	// field#13 STR : UUIDv4 — used by Riot loyalty-v2 for RMS check on Valorant
	out = append(out, pbLenDelim(13, []byte(loyaltyUUID))...)
	return out
}

// buildInnerAction4 — batch wrapper. Spec §7: 1 field.
func buildInnerAction4(nestedB64 string) []byte {
	return pbLenDelim(1, []byte("{e}"+nestedB64))
}

// buildInnerAction7 — heartbeat. Spec §8: 3 fields.
func buildInnerAction7(nestedB64 string, hwidCounter []byte) []byte {
	out := pbLenDelim(1, []byte("{e}"+nestedB64))
	out = append(out, pbLenDelim(3, hwidCounter)...)
	out = append(out, pbVarint(6, 1)...)
	return out
}

// buildInnerAction9 — anti-cheat report. Spec §9.
func buildInnerAction9(nestedB64, objectID string) []byte {
	// field#2 nested
	// [VAL-5 FIX 2026-06-27] action=9 f#2 structure per Nezur capture:
	//   f#1 LEN=24 ObjectID
	//   f#2 LEN=14 `{"mc":{"0":1}}`
	//   f#3 LEN=10 (10 bytes, not 12 — removed trailing 0x32 0x00)
	//   f#6 LEN=0 empty marker
	innerReport := pbLenDelim(1, []byte(objectID))
	innerReport = append(innerReport, pbLenDelim(2, []byte(`{"mc":{"0":1}}`))...)
	innerReport = append(innerReport, pbLenDelim(3, []byte{
		0x1a, 0x04, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x40, 0x02,
	})...)
	innerReport = append(innerReport, pbLenDelim(6, []byte{})...)

	out := pbLenDelim(1, []byte("{e}"+nestedB64))
	out = append(out, pbLenDelim(2, innerReport)...)
	return out
}

// ============ Envelope assembly ============

// assembleEnvelope wraps the encrypted body into the outer protobuf.
// Spec §2:
//
//	field#1 VARINT  = action
//	field#2 LEN     = "RG\x01\x00" + RSA(256) + IV(12) + CT + TAG(16)
func assembleEnvelope(action uint64, rsaBlob, iv, innerCT, innerTAG []byte) []byte {
	body := []byte{'R', 'G', 0x01, 0x00}
	body = append(body, rsaBlob...)
	body = append(body, iv...)
	body = append(body, innerCT...)
	body = append(body, innerTAG...)

	out := pbVarint(1, action)
	out = append(out, pbLenDelim(2, body)...)
	return out
}

// encryptInnerToEnvelope does the full crypto pipeline:
//
//	inner_pt → AES-GCM(K_inner, IV) → CT + TAG
//	K_inner  → RSA-OAEP-SHA512(SERVER_PUBKEY) → RSA blob
//	→ assembleEnvelope(action, ...)
func encryptInnerToEnvelope(action uint64, innerPT []byte) ([]byte, error) {
	// [DEBUG 2026-06-26] dump latest inner PT to disk for byte-by-byte comparison
	_ = os.WriteFile(fmt.Sprintf("/tmp/inner_action%d.bin", action), innerPT, 0644)
	pub, err := currentServerPub()
	if err != nil {
		return nil, err
	}

	kInner := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(kInner); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	innerCT, innerTAG, err := aesGcmEncrypt(kInner, iv, innerPT)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt: %w", err)
	}

	rsaBlob, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pub, kInner, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP-SHA512: %w", err)
	}
	if len(rsaBlob) != 256 {
		return nil, fmt.Errorf("RSA blob size = %d, expected 256", len(rsaBlob))
	}

	return assembleEnvelope(action, rsaBlob, iv, innerCT, innerTAG), nil
}

// ============ Public envelope builders ============

func buildAuthEnvelope(sess *Session, jwt, sid, game string) ([]byte, error) {
	env, _, err := buildAuthEnvelopeWithUUID(sess, jwt, sid, game, "")
	return env, err
}

// buildAuthEnvelopeWithUUID — same as buildAuthEnvelope but also returns the
// UUID embedded in field#13 (the loyalty SID). Client should pre-register this.
func buildAuthEnvelopeWithUUID(sess *Session, jwt, sid, game, providedLoyaltyUUID string) ([]byte, string, error) {
	if jwt == "" {
		return nil, "", errors.New("missing jwt")
	}
	if game == "valo" && sid == "" {
		return nil, "", errors.New("missing sid for game=valo")
	}
	innerPT, loyaltyUUID := buildInnerAction3WithUUID(jwt, sid, sess.RiotKeyPubB64, providedLoyaltyUUID)
	env, err := encryptInnerToEnvelope(3, innerPT)
	return env, loyaltyUUID, err
}

func buildAccessEnvelope(b64RiotResponse string) ([]byte, error) {
	return encryptInnerToEnvelope(4, buildInnerAction4(b64RiotResponse))
}

func buildHeartbeatEnvelope(b64RiotResponse string) ([]byte, error) {
	return encryptInnerToEnvelope(7, buildInnerAction7(b64RiotResponse, getHWIDCounter()))
}

func buildReportEnvelope(b64RiotResponse, objectID string) ([]byte, error) {
	return encryptInnerToEnvelope(9, buildInnerAction9(b64RiotResponse, objectID))
}

// ============ Misc ============

func b64encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}


// pemWrap inserts \n every 64 chars + trailing \n (Nezur format).
func pemWrap(b64 string) string {
	if len(b64) <= 64 {
		return b64 + "\n"
	}
	var sb []byte
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb = append(sb, b64[i:end]...)
		sb = append(sb, '\n')
	}
	return string(sb)
}

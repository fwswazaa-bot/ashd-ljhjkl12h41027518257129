// response_parser.go — Parse Riot Vanguard responses to extract:
//   - The nested envelope (to echo back in next action=4/7)
//   - The rotating SERVER_PUBKEY (PKIX DER from inner field)
//   - Pending anti-cheat MongoDB ObjectIDs (to action=9 report)
//
// Spec ref: VANGUARD_SPEC.md §10
//
// Riot responses follow the same wire format as outbound envelopes:
//   field#1 VARINT  = action  (typically 5 for response to action=3)
//   field#2 LEN     = "RG\x01\x00" + RSA(256) + IV(12) + inner_CT + inner_TAG(16)
//
// The RSA blob in responses is encrypted with OUR RIOT_KEY pubkey (so only we can decrypt
// using the session's RIOT_KEY privkey).

package main

import (
	"crypto/rsa"
	"os"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

// ParsedResponse holds the meaningful bits extracted from a Riot response.
type ParsedResponse struct {
	Action          uint64    // field#1 of the response (typically 5)
	InnerCleartext  []byte    // AES-decrypted inner protobuf bytes
	NestedEnvelopeB64 string  // "{e}<b64>" — to echo back in next action=4/7
	NewServerPubKey []byte    // raw PKIX DER bytes (if a new rotative pubkey was present)
	ExpiresAt       string    // ISO 8601 expiration string (if found)
	PendingChecks   []string  // 24-hex MongoDB ObjectIDs to action=9 report
	NewUUIDs        []string  // UUIDv4-shaped strings from response (fresh loyalty/session UUIDs to re-attest with)
	NewJWTs         []string  // JWTs (eyJ...) from response — re-attest if rotated
	NewSIDs         []string  // Vanguard SIDs (||1;...) from response — re-attest if rotated
}

// parseRiotResponse decodes a base64-encoded raw Riot response and extracts
// the actionable bits. The session's RIOT_KEY privkey is used to RSA-OAEP-decrypt
// the inner K_aes, then AES-GCM-decrypt the inner protobuf.
func parseRiotResponse(b64Body string, sess *Session) (*ParsedResponse, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Body)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return parseRiotResponseBytes(raw, sess)
}

func parseRiotResponseBytes(raw []byte, sess *Session) (*ParsedResponse, error) {
	if sess == nil || sess.RiotKey == nil {
		return nil, errors.New("session missing RIOT_KEY private key")
	}
	if len(raw) < 5+4+256+12+16 { // outer hdr + magic + RSA + IV + tag
		return nil, fmt.Errorf("response too short: %d bytes", len(raw))
	}

	// Parse the outer protobuf
	i := 0
	tag, n := readVarint(raw, i)
	if n == 0 {
		return nil, errors.New("invalid outer tag")
	}
	i = n
	_ = tag // field#1 tag (action varint follows)
	action, n := readVarint(raw, i)
	if n == 0 {
		return nil, errors.New("invalid outer action varint")
	}
	i = n
	// field#2 tag
	_, n = readVarint(raw, i)
	if n == 0 {
		return nil, errors.New("invalid field#2 tag")
	}
	i = n
	// field#2 length
	bodyLen, n := readVarint(raw, i)
	if n == 0 {
		return nil, errors.New("invalid field#2 length")
	}
	i = n
	if int(bodyLen) > len(raw)-i {
		return nil, fmt.Errorf("field#2 length %d exceeds remaining %d", bodyLen, len(raw)-i)
	}
	body := raw[i : i+int(bodyLen)]

	// Check magic "RG\x01\x00"
	if len(body) < 4 || body[0] != 'R' || body[1] != 'G' || body[2] != 0x01 || body[3] != 0x00 {
		return nil, fmt.Errorf("bad magic in body: %x", body[:4])
	}

	// Layout: magic(4) + RSA(256) + IV(12) + CT + TAG(16)
	if len(body) < 4+256+12+16 {
		return nil, fmt.Errorf("body too short for envelope structure: %d", len(body))
	}
	rsaBlob := body[4 : 4+256]
	iv := body[4+256 : 4+256+12]
	ctAndTag := body[4+256+12:]
	innerCT := ctAndTag[:len(ctAndTag)-16]
	innerTAG := ctAndTag[len(ctAndTag)-16:]

	// RSA-OAEP-SHA512 decrypt the K_aes with our RIOT_KEY privkey
	kAes, err := rsa.DecryptOAEP(sha512.New(), nil, sess.RiotKey, rsaBlob, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decrypt of K_aes: %w", err)
	}
	if len(kAes) != 32 {
		return nil, fmt.Errorf("decrypted K_aes is %d bytes, expected 32", len(kAes))
	}

	// AES-GCM decrypt the inner
	innerPT, err := aesGcmDecrypt(kAes, iv, innerCT, innerTAG)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt of inner: %w", err)
	}

	res := &ParsedResponse{
		Action:         action,
		InnerCleartext: innerPT,
	}

	// Walk inner protobuf to extract useful fields
	_ = os.WriteFile(fmt.Sprintf("/tmp/riot_decrypted_inner_act%d.bin", action), innerPT, 0644)
	extractInnerFields(innerPT, res)

	return res, nil
}

// readVarint reads a protobuf varint starting at offset i.
// Returns (value, next_offset). next_offset == 0 means error.
func readVarint(buf []byte, i int) (uint64, int) {
	var v uint64
	var shift uint
	for {
		if i >= len(buf) {
			return 0, 0
		}
		b := buf[i]
		i++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, i
		}
		shift += 7
		if shift > 63 {
			return 0, 0
		}
	}
}

// extractInnerFields scans the decrypted inner for known patterns:
//   - "{e}<b64>" nested envelope marker (field#1 typically)
//   - ISO 8601 expiration strings
//   - PKIX DER pubkey (starts with "MIIBI...")
//   - 24-hex MongoDB ObjectIDs (anti-cheat tasks)
func extractInnerFields(inner []byte, out *ParsedResponse) {
	// Nested envelope: parse field#1 of the inner protobuf using its exact LEN.
	// Scanning by isBase64Char truncates when the b64 run ends on a non-alphabet
	// byte — observed losing 8 b64 chars (5B CT) in action=4/7 nested vs Nezur,
	// causing Riot reject + VAL-5. Use the protobuf length explicitly.
	{
		i := 0
		for i < len(inner) {
			tag, n := readVarint(inner, i)
			if n == 0 {
				break
			}
			fnum := tag >> 3
			wtype := tag & 7
			i = n
			if wtype == 0 {
				_, n2 := readVarint(inner, i)
				if n2 == 0 {
					break
				}
				i = n2
				continue
			}
			if wtype != 2 {
				break
			}
			ln, n2 := readVarint(inner, i)
			if n2 == 0 || int(ln) > len(inner)-n2 {
				break
			}
			val := inner[n2 : n2+int(ln)]
			i = n2 + int(ln)
			if fnum == 1 && len(val) > 3 && val[0] == '{' && val[1] == 'e' && val[2] == '}' {
				out.NestedEnvelopeB64 = string(val[3:])
				break
			}
		}
	}

	// PKIX DER pubkey: look for "MIIBI" prefix
	if idx := indexOf(inner, []byte("MIIBI")); idx >= 0 {
		end := idx
		for end < len(inner) && (isBase64Char(inner[end]) || inner[end] == '\n' || inner[end] == '\r') {
			end++
		}
		if end-idx > 300 {
			b64 := stripWhitespace(inner[idx:end])
			der, err := base64.StdEncoding.DecodeString(string(b64))
			if err == nil && len(der) > 250 {
				out.NewServerPubKey = der
			}
		}
	}

	// UUIDv4 extraction : fresh loyalty session IDs Riot pushes in responses.
	// Pattern: 8-4-4-4-12 hex chars. Nezur re-uses these as field#13 in next attestation.
	uuidRe := regexp.MustCompile(`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
	seenU := map[string]bool{}
	for _, m := range uuidRe.FindAllSubmatch(inner, -1) {
		s := string(m[1])
		if !seenU[s] {
			seenU[s] = true
			out.NewUUIDs = append(out.NewUUIDs, s)
		}
	}
	// Extract JWTs : start with eyJ (base64 of {"), at least 100 chars long
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{40,}`)
	seenJ := map[string]bool{}
	for _, m := range jwtRe.FindAll(inner, -1) {
		s := string(m)
		if !seenJ[s] && len(s) >= 200 {
			seenJ[s] = true
			out.NewJWTs = append(out.NewJWTs, s)
		}
	}
	// Extract Vanguard SIDs : || delimiter pattern (||1;...||6;...)
	sidRe := regexp.MustCompile(`\|\|1;[^|]{6,40}\|\|2;[^|]{6,80}\|\|3;[^|]{6,80}\|\|4[^|]*\|\|5;[^|]{4,40}\|\|6;[^|]{20,}`)
	seenS := map[string]bool{}
	for _, m := range sidRe.FindAll(inner, -1) {
		s := string(m)
		if !seenS[s] {
			seenS[s] = true
			out.NewSIDs = append(out.NewSIDs, s)
		}
	}

	// ISO 8601 expiration: regex match "YYYY-MM-DDTHH:MM:SSZ"
	isoRe := regexp.MustCompile(`\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\b`)
	if m := isoRe.FindSubmatch(inner); m != nil {
		out.ExpiresAt = string(m[1])
	}

	// Extract ObjectIDs : 24-char hex strings inside nested protobufs.
	// Response action=4/7 contains up to ~72 ObjectIDs each in pattern:
	//   0a 18 [24 hex chars] 10 ...
	// (field#1 LEN=24 inside a task entry). Also covers direct f#8 ObjectIDs.
	seen := map[string]bool{}
	for i := 0; i < len(inner)-26; i++ {
		// Match: 0a 18 [24 hex chars ASCII]
		if inner[i] == 0x0a && inner[i+1] == 0x18 {
			payload := inner[i+2 : i+26]
			ok := true
			for _, c := range payload {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					ok = false; break
				}
			}
			if ok {
				oid := string(payload)
				if !seen[oid] {
					seen[oid] = true
					out.PendingChecks = append(out.PendingChecks, oid)
				}
			}
		}
	}
	// Also catch 32-char ObjectIDs in field#8
	for i := 0; i < len(inner)-34; i++ {
		if inner[i] == 0x42 && inner[i+1] == 0x20 {  // field#8 LEN=32
			payload := inner[i+2 : i+34]
			ok := true
			for _, c := range payload {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					ok = false; break
				}
			}
			if ok {
				oid := string(payload)
				if !seen[oid] {
					seen[oid] = true
					out.PendingChecks = append(out.PendingChecks, oid)
				}
			}
		}
	}
}

// indexOf returns the first index of needle in haystack, or -1.
func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func isBase64Char(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '='
}

func stripWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			out = append(out, c)
		}
	}
	return out
}

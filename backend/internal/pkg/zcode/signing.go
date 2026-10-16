// Package zcode implements the account transport observed in ZCode 3.15.3.
// Successful signing does not itself establish billing or discount eligibility.
package zcode

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	Version       = "3.15.3"
	Origin        = "https://api.z.ai"
	HandshakePath = "/api/paas/c1f3a7e2/v2/client"
)

// Credential is transient signing input. Never log or serialize its fields.
type Credential struct {
	ID     string
	Secret string
	Value  string
	Field  string
}

// ParseCredential checks the protocol shape, not the JWT signature or entitlement.
func ParseCredential(value string) (Credential, error) {
	if value == "" || len(value) > 16384 || strings.ContainsAny(value, "\r\n") {
		return Credential{}, errors.New("zcode: invalid signing credential")
	}
	p := strings.Split(value, ".")
	if len(p) == 2 && strings.TrimSpace(p[0]) != "" && strings.TrimSpace(p[1]) != "" {
		return Credential{ID: p[0], Secret: p[1], Value: value, Field: "apiKey"}, nil
	}
	if len(p) == 3 && p[2] != "" {
		var header struct {
			Alg      string `json:"alg"`
			Typ      string `json:"typ"`
			SignType string `json:"sign_type"`
		}
		var payload struct {
			TokenUse string `json:"token_use"`
			APIKey   string `json:"api_key"`
		}
		h, e1 := base64.RawURLEncoding.DecodeString(p[0])
		b, e2 := base64.RawURLEncoding.DecodeString(p[1])
		if e1 == nil && e2 == nil && json.Unmarshal(h, &header) == nil && json.Unmarshal(b, &payload) == nil &&
			header.Alg == "HS256" && header.Typ == "JWT" && header.SignType == "SIGN" &&
			payload.TokenUse == "project_access" && strings.TrimSpace(payload.APIKey) != "" {
			return Credential{ID: payload.APIKey, Secret: value, Value: value, Field: "accessToken"}, nil
		}
	}
	return Credential{}, errors.New("zcode: unsupported signing credential")
}

// derive is HKDF-SHA256 extract/expand for a single 32-byte output block.
func derive(secret, purpose string) []byte {
	extract := hmac.New(sha256.New, []byte("WD_CLIENT_SIGN_KDF_SALT"))
	_, _ = extract.Write([]byte(secret))
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(purpose))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func HandshakeProof(c Credential, ts, nonce string) string {
	key := derive(c.Secret, "getSignKey_hmac")
	defer clear(key)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("get_sign_key\n" + c.ID + "\n" + ts + "\n" + nonce))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func DecryptPrivateKey(c Credential, packed string) (ed25519.PrivateKey, error) {
	fail := errors.New("zcode: invalid encrypted signing key")
	if len(packed) > 16384 {
		return nil, fail
	}
	b, err := base64.StdEncoding.Strict().DecodeString(packed)
	if err != nil || len(b) <= 28 {
		return nil, fail
	}
	defer clear(b)
	key := derive(c.Secret, "ed25519_priv")
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fail
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fail
	}
	plain, err := gcm.Open(nil, b[:12], b[12:], []byte(c.ID))
	if err != nil {
		return nil, fail
	}
	defer clear(plain)
	der, err := base64.StdEncoding.Strict().DecodeString(string(plain))
	if err != nil {
		return nil, fail
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fail
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fail
	}
	return privateKey, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("zcode: random source failed")
	}
	return hex.EncodeToString(b), nil
}

func ProofOfWork(ctx context.Context, id, session, ts string) (string, error) {
	h := sha256.Sum256([]byte(id + "\nzcode\n" + session + "\n" + ts))
	prefix := hex.EncodeToString(h[:])[:32]
	nonce, err := randomHex(12)
	if err != nil {
		return "", err
	}
	for i := uint64(0); i <= 0xffffffff; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		candidate := nonce + fmt.Sprintf("%08x", i)
		sum := sha256.Sum256([]byte(prefix + "\n" + candidate))
		if sum[0] == 0 {
			return candidate, nil
		}
	}
	return "", errors.New("zcode: proof of work exhausted")
}

// SignRequest must run after header overrides and use the exact credential sent
// upstream. Callers own cache isolation, handshake and limited retry policy.
func SignRequest(req *http.Request, c Credential, key ed25519.PrivateKey, session string, now time.Time) error {
	if req == nil || req.URL == nil || req.URL.Scheme != "https" || req.URL.Host != "api.z.ai" || req.URL.User != nil {
		return errors.New("zcode: signing origin rejected")
	}
	if strings.TrimSpace(session) == "" || len(session) > 256 || strings.ContainsAny(session, "\r\n") {
		return errors.New("zcode: invalid model session")
	}
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("zcode: invalid signing key")
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	pow, err := ProofOfWork(req.Context(), c.ID, session, ts)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, []byte(c.ID+"\n"+ts+"\n"+Version+"\n"+session+"\n"+nonce))
	headers := map[string]string{
		"X-Client-Ts": ts, "X-Client-Version": Version, "X-Client-Sig": base64.StdEncoding.EncodeToString(sig),
		"X-Session-Id": session, "X-Client-Nonce": nonce, "X-App-Id": "zcode", "X-Client-Pow": pow,
		"User-Agent": "ZCode/" + Version, "X-ZCode-App-Version": Version,
	}
	// The gateway can preserve raw/lowercase header names. Header.Set alone
	// leaves those duplicates in place, allowing conflicting signature values.
	for existing := range req.Header {
		if strings.EqualFold(existing, "X-Client-Sign-Verified") {
			delete(req.Header, existing)
			continue
		}
		for name := range headers {
			if strings.EqualFold(existing, name) {
				delete(req.Header, existing)
				break
			}
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return nil
}

// SignatureRejected only recognizes the two observed explicit 401 reasons.
// Generic authentication failures must not cause automatic model replay.
func SignatureRejected(status int, body []byte) bool {
	if status != http.StatusUnauthorized || len(body) > 65536 {
		return false
	}
	var d struct {
		Msg    string `json:"msg"`
		Reason string `json:"reason"`
		Data   struct {
			Reason string `json:"reason"`
		} `json:"data"`
		Error struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &d) != nil {
		return false
	}
	for _, v := range []string{d.Msg, d.Reason, d.Data.Reason, d.Error.Reason, d.Error.Message} {
		if v == "VERIFY_SIGNATURE_INVALID" || v == "VERIFY_APIKEY_EXPIRED" {
			return true
		}
	}
	return false
}

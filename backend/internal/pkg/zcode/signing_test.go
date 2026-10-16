package zcode

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// The fixture was produced with the existing Node client and Node's independent
// HKDF/AES/PKCS8 implementations; it contains synthetic credentials only.
func TestNodeSigningParity(t *testing.T) {
	var f struct{ ID, Secret, TS, Nonce, Proof, PrivateCipher, PublicKey string }
	b, err := os.ReadFile("testdata/node-signing.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	c, err := ParseCredential(f.ID + "." + f.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if HandshakeProof(c, f.TS, f.Nonce) != f.Proof {
		t.Fatal("Node handshake proof mismatch")
	}
	key, err := DecryptPrivateKey(c, f.PrivateCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	der, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, Origin+"/api/anthropic/v1/messages", nil)
	req.Header.Set("X-Client-Sign-Verified", "untrusted")
	if err = SignRequest(req, c, key, "session-1", time.UnixMilli(1792180000123)); err != nil {
		t.Fatal(err)
	}
	h := req.Header
	sig, err := base64.StdEncoding.DecodeString(h.Get("X-Client-Sig"))
	if err != nil {
		t.Fatal(err)
	}
	message := c.ID + "\n" + h.Get("X-Client-Ts") + "\n" + Version + "\nsession-1\n" + h.Get("X-Client-Nonce")
	publicKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("fixture public key is not Ed25519")
	}
	if !ed25519.Verify(publicKey, []byte(message), sig) {
		t.Fatal("signature invalid")
	}
	prefix := sha256.Sum256([]byte(c.ID + "\nzcode\nsession-1\n" + h.Get("X-Client-Ts")))
	pow := sha256.Sum256([]byte(hex.EncodeToString(prefix[:])[:32] + "\n" + h.Get("X-Client-Pow")))
	if pow[0] != 0 {
		t.Fatal("invalid proof of work")
	}
	if h.Get("X-Client-Sign-Verified") != "" {
		t.Fatal("untrusted verification header retained")
	}
	c.ID = "another-account"
	if _, err := DecryptPrivateKey(c, f.PrivateCipher); err == nil {
		t.Fatal("accepted another account's encrypted key")
	}
}

func TestSigningBoundaries(t *testing.T) {
	for _, raw := range []string{"", "a", "a.", "a.b.c", "a.b\n"} {
		if _, err := ParseCredential(raw); err == nil {
			t.Fatalf("accepted malformed credential %q", raw)
		}
	}
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	pat := enc(`{"alg":"HS256","typ":"JWT","sign_type":"SIGN"}`) + "." + enc(`{"token_use":"project_access","api_key":"project-key"}`) + ".synthetic-signature"
	c, err := ParseCredential(pat)
	if err != nil || c.Secret != pat || c.ID != "project-key" || c.Field != "accessToken" {
		t.Fatal("PAT parsing failed")
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer clear(key)
	for _, url := range []string{"http://api.z.ai/x", "https://api.z.ai.evil/x", "https://api.z.ai:443/x", "https://user@api.z.ai/x"} {
		req, _ := http.NewRequest(http.MethodPost, url, nil)
		if SignRequest(req, c, key, "s", time.Now()) == nil {
			t.Fatalf("signed forbidden origin %s", url)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProofOfWork(ctx, "id", "s", "ts"); err == nil {
		t.Fatal("ignored cancellation")
	}
	if SignatureRejected(401, []byte(`{"error":{"message":"ordinary unauthorized"}}`)) {
		t.Fatal("generic 401 replay")
	}
	if !SignatureRejected(401, []byte(`{"error":{"reason":"VERIFY_SIGNATURE_INVALID"}}`)) {
		t.Fatal("missing signature rejection")
	}
	if SignatureRejected(429, []byte(`{"reason":"VERIFY_SIGNATURE_INVALID"}`)) {
		t.Fatal("rate limit replay")
	}
}

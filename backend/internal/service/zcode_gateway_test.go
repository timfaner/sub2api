package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestZCodeNativeBuilderSignsFinalRequest(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	ctx := context.Background()
	a, _ := r.GetByID(ctx, 1)
	session, err := p.codec.Session(a)
	if err != nil {
		t.Fatal(err)
	}
	session.PAT = zcodeTestPAT()
	session.PATExpiresAt = time.Now().Add(time.Hour)
	creds, err := p.codec.Credentials(1, session)
	if err != nil {
		t.Fatal(err)
	}
	r.account.Credentials = creds
	a, _ = r.GetByID(ctx, 1)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.keys[1] = zcodeKeyEntry{key: private, fingerprint: sha256.Sum256([]byte(session.PAT + "\ndirect")), used: time.Now()}
	s := &OpenAIGatewayService{zcodeTokenProvider: p}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	c.Request.Header.Set("Authorization", "Bearer downstream-only")
	c.Request.Header.Set("Cookie", "downstream-cookie")
	c.Request.Header.Set("session_id", "client-session")
	body := []byte(`{"model":"glm-5.3","messages":[{"role":"user","content":"hi"}],"max_tokens":32,"stream":true}`)
	token, err := s.resolveNativeAnthropicCredential(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	req, forwarded, err := s.buildNativeAnthropicUpstreamRequest(ctx, c, a, body, token, "https://api.z.ai/api/anthropic/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(req.Body)
	if err != nil || string(actual) != string(forwarded) {
		t.Fatal("body changed after builder")
	}
	if req.Header.Get("Authorization") != "Bearer "+session.PAT || req.Header.Get("X-Api-Key") != session.PAT || req.Header.Get("Cookie") != "" {
		t.Fatal("upstream credentials not isolated")
	}
	if req.Header.Get("X-App-Id") != "zcode" || req.Header.Get("User-Agent") != "ZCode/3.15.3" {
		t.Fatal("missing ZCode attribution")
	}
	h := req.Header
	message := strings.Join([]string{"key", h.Get("X-Client-Ts"), h.Get("X-Client-Version"), h.Get("X-Session-Id"), h.Get("X-Client-Nonce")}, "\n")
	sig, err := base64.StdEncoding.DecodeString(h.Get("X-Client-Sig"))
	if err != nil || !ed25519.Verify(public, []byte(message), sig) {
		t.Fatal("final signature invalid")
	}
	if _, _, err = s.buildNativeAnthropicUpstreamRequest(ctx, c, a, body, token, "https://other.example/v1/messages"); err == nil {
		t.Fatal("signed unexpected destination")
	}
}

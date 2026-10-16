package service

import (
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

func TestZCodeAccountPinsVerifiedTransport(t *testing.T) {
	a := &Account{Platform: PlatformZhipu, Type: AccountTypeOAuth, Credentials: map[string]any{
		"auth_method": "zcode", "api_protocol": "adaptive", "account_mode": "payg", "base_url": "https://other.example"}}
	if !a.IsZCodeOAuth() || a.GetAPIProtocol() != APIProtocolAnthropic || a.GetAccountMode() != AccountModeCoding {
		t.Fatal("incorrect account capabilities")
	}
	if a.GetAnthropicProtocolBaseURL() != "https://api.z.ai/api/anthropic" || a.GetOpenAIBaseURL() != "https://api.z.ai/api/anthropic" {
		t.Fatal("endpoint override escaped")
	}
	if a.GetOpenAIFormatBaseURL() != "" || a.GetCNProtocolBaseURL(APIProtocolChatCompletions) != "" {
		t.Fatal("unverified endpoint enabled")
	}
	a.Type = AccountTypeAPIKey
	if a.IsZCodeOAuth() || a.GetAPIProtocol() != APIProtocolAdaptive || a.GetAccountMode() != AccountModePayG || a.GetOpenAIBaseURL() != "https://other.example" {
		t.Fatal("API key behavior changed")
	}
}

func TestZCodeSessionCredentialsSurviveRestartAndRedaction(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("test-only-stable-secret", 3)}}
	codec, err := NewZCodeSessionCodec(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := zcode.Session{UserID: "owner", OAuthToken: "root-secret", BusinessToken: "business-secret", ProjectKeyID: "key", PAT: "pat-secret", PATExpiresAt: time.Now().Add(time.Hour)}
	creds, err := codec.Credentials(42, s)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSensitiveCredentialKey(zcodeSessionCredential) {
		t.Fatal("session exposed to management API")
	}
	if _, ok := creds["refresh_token"]; ok {
		t.Fatal("fabricated refresh credential")
	}
	merged := MergePreservingSensitiveCreds(creds, map[string]any{"auth_method": "zcode"})
	if merged[zcodeSessionCredential] != creds[zcodeSessionCredential] {
		t.Fatal("editing erased session")
	}
	restarted, err := NewZCodeSessionCodec(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &Account{ID: 42, Platform: PlatformZhipu, Type: AccountTypeOAuth, Credentials: creds}
	restored, err := restarted.Session(a)
	if err != nil || restored.OAuthToken != s.OAuthToken {
		t.Fatal("restart recovery failed", err)
	}
	a.ID = 43
	if _, err = restarted.Session(a); err == nil {
		t.Fatal("session moved to another account")
	}
}

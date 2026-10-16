package zcode

import (
	"strings"
	"testing"
	"time"
)

func TestVaultRestartAndAccountBinding(t *testing.T) {
	secret := strings.Repeat("test-only-stable-secret-", 3)
	v, err := NewVault(secret)
	if err != nil {
		t.Fatal(err)
	}
	s := Session{UserID: "owner", OAuthToken: "oauth-secret", BusinessToken: "business-secret", PAT: "pat-secret", PATExpiresAt: time.Unix(1792180000, 0)}
	sealed, err := v.Seal(42, s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, s.OAuthToken) {
		t.Fatal("plaintext session")
	}
	restarted, err := NewVault(secret)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restarted.Open(42, sealed)
	if err != nil || !restored.PATExpiresAt.Equal(s.PATExpiresAt) || restored.OAuthToken != s.OAuthToken || restored.UserID != s.UserID {
		t.Fatal("restart recovery failed", err)
	}
	if _, err = v.Open(43, sealed); err == nil {
		t.Fatal("accepted another account's session")
	}
	other, _ := NewVault(strings.Repeat("different-secret", 3))
	if _, err = other.Open(42, sealed); err == nil {
		t.Fatal("accepted wrong secret")
	}
	if _, err = v.Open(42, "zcode:v1:AAAA"); err == nil {
		t.Fatal("accepted truncated cipher")
	}
	if _, err = v.Open(42, `{"OAuthToken":"plaintext"}`); err == nil {
		t.Fatal("accepted plaintext fallback")
	}
	second, err := v.Seal(42, s)
	if err != nil || sealed == second {
		t.Fatal("nonce reuse")
	}
}

func TestVaultRejectsMissingStableSecret(t *testing.T) {
	for _, s := range []string{"", "short", strings.Repeat("0", 32)} {
		if _, err := NewVault(s); err == nil {
			t.Fatal("accepted missing secret")
		}
	}
}

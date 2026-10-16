package zcode

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func webTestSession() Session {
	return Session{OAuthToken: "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"owner"}`)) + ".signature", UserID: "zcode-owner", Project: Project{OrganizationID: "org", ProjectID: "project"}, ProjectKeyID: "key", PAT: "old-pat", BusinessToken: "old-business"}
}

func TestWebSessionBindingRejectsIdentityAndScopeChanges(t *testing.T) {
	for _, tt := range []struct {
		name, identity, project string
		status, calls           int
	}{
		{"guest", `{"id":"owner","role":"guest"}`, "project", 200, 1},
		{"other-user", `{"id":"other","role":"user"}`, "project", 200, 1},
		{"missing-role", `{"id":"owner"}`, "project", 200, 1},
		{"revoked", `{"private":"do-not-expose"}`, "project", 401, 1},
		{"redirect", `{}`, "project", 302, 1},
		{"other-project", `{"id":"owner","role":"user"}`, "other", 200, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			c := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				switch calls {
				case 1:
					return jsonResponse(tt.status, tt.identity), nil
				case 2:
					return jsonResponse(200, `{"code":200,"data":{"access_token":"business","expires_in":3600}}`), nil
				case 3:
					return jsonResponse(200, fmt.Sprintf(`{"code":200,"data":{"organizations":[{"organizationId":"org","projects":[{"projectId":%q,"projectType":1}]}]}}`, tt.project)), nil
				default:
					t.Fatal("unexpected request")
					return nil, nil
				}
			})})
			current := webTestSession()
			next, err := c.BindWebSession(context.Background(), current, "private-session")
			if err == nil || next != current || calls != tt.calls {
				t.Fatal("binding did not fail closed")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("error leaked upstream data")
			}
		})
	}
}

func TestWebSessionSurvivesVaultAndRenewsWithoutReplacingOAuth(t *testing.T) {
	now := time.Unix(1792180000, 0)
	calls := 0
	c := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/api/v1/auths/":
			if r.URL.Host != "chat.z.ai" || r.Header.Get("Authorization") != "Bearer private-session" {
				t.Fatal("wrong identity request")
			}
			return jsonResponse(200, `{"id":"owner","role":"user"}`), nil
		case "/api/auth/z/login":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"token":"private-session"}` {
				t.Fatal("wrong root credential")
			}
			return jsonResponse(200, `{"code":200,"data":{"access_token":"business","expires_in":3600}}`), nil
		case "/api/biz/customer/getCustomerInfo":
			return jsonResponse(200, `{"code":200,"data":{"organizations":[{"organizationId":"org","projects":[{"projectId":"project","projectType":1}]}]}}`), nil
		default:
			if !strings.HasSuffix(r.URL.Path, "/key/access_tokens") {
				t.Fatal("unexpected endpoint")
			}
			return jsonResponse(200, fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":600}}`, syntheticPAT(now.Unix()+600), now.Unix()+600)), nil
		}
	})})
	c.now = func() time.Time { return now }
	original := webTestSession()
	bound, err := c.BindWebSession(context.Background(), original, "private-session")
	if err != nil {
		t.Fatal(err)
	}
	if bound.OAuthToken != original.OAuthToken || bound.ZCodeJWT != original.ZCodeJWT || bound.WebSessionToken != "private-session" || calls != 3 {
		t.Fatal("original authorization changed")
	}
	vault, err := NewVault(strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.Seal(7, bound)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := vault.Open(7, sealed)
	if err != nil {
		t.Fatal(err)
	}
	restored.BusinessExpiresAt = now.Add(-time.Minute)
	renewed, err := c.Renew(context.Background(), restored, true)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.OAuthToken != original.OAuthToken || renewed.WebSessionToken != bound.WebSessionToken || !renewed.PATExpiresAt.After(now) || calls != 7 {
		t.Fatal("renewal lost bound authorization or skipped validation")
	}
}

func TestRevokedWebSessionDoesNotFallBackToOAuth(t *testing.T) {
	current := webTestSession()
	current.WebSessionToken = "revoked-session"
	calls := 0
	c := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(200, `{"id":"guest","role":"guest"}`), nil
	})})
	next, err := c.Renew(context.Background(), current, true)
	if err == nil || next != current || calls != 1 {
		t.Fatal("revoked session changed state or fell back")
	}
}

func TestWebSessionRejectsInvalidBindingBeforeNetwork(t *testing.T) {
	for _, token := range []string{"", "has space", "header\r\ninjection", strings.Repeat("x", 32769)} {
		c := NewClient(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid token reached network"); return nil, nil })})
		original := webTestSession()
		next, err := c.BindWebSession(context.Background(), original, token)
		if err == nil || next != original {
			t.Fatal("invalid binding accepted")
		}
	}
	for _, root := range []string{"", "opaque", "a.e30.b", "a.%%%%.b"} {
		c := NewClient(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("missing identity reached network")
			return nil, nil
		})})
		original := webTestSession()
		original.OAuthToken = root
		next, err := c.BindWebSession(context.Background(), original, "candidate")
		if err == nil || next != original {
			t.Fatal("unverifiable original identity accepted")
		}
	}
}

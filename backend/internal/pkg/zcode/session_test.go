package zcode

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRenewBusinessThenPATWithoutLosingRoot(t *testing.T) {
	now := time.Unix(1792180000, 0)
	current := Session{OAuthReportedExpiresIn: 7200, OAuthObservedAt: now.Add(-time.Hour), OAuthToken: "root", OAuthRefreshToken: "unproven-refresh", BusinessToken: "old-business", BusinessExpiresAt: now.Add(-time.Second),
		Project: Project{OrganizationID: "org", ProjectID: "project"}, ProjectKeyID: "key", PAT: "expired-pat", PATExpiresAt: now.Add(-time.Second)}
	calls := 0
	c := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			b, _ := io.ReadAll(r.Body)
			if r.URL.Path != "/api/auth/z/login" || string(b) != `{"token":"root"}` {
				t.Fatal("wrong business renewal")
			}
			return jsonResponse(200, `{"code":200,"data":{"access_token":"renewed-business","expires_in":3600}}`), nil
		}
		if calls != 2 || !strings.HasSuffix(r.URL.Path, "/key/access_tokens") || r.Header.Get("Authorization") != "Bearer renewed-business" {
			t.Fatal("incorrect PAT renewal")
		}
		return jsonResponse(200, fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":600}}`, syntheticPAT(now.Unix()+600), now.Unix()+600)), nil
	})})
	c.now = func() time.Time { return now }
	next, err := c.Renew(context.Background(), current, false)
	if err != nil {
		t.Fatal(err)
	}
	if next.OAuthReportedExpiresIn != 7200 || !next.OAuthObservedAt.Equal(current.OAuthObservedAt) || next.OAuthToken != "root" || next.OAuthRefreshToken != "unproven-refresh" || current.BusinessToken != "old-business" || next.BusinessToken != "renewed-business" {
		t.Fatal("lost or mutated session")
	}
	if _, err = c.Renew(context.Background(), next, false); err != nil || calls != 2 {
		t.Fatal("renewed fresh PAT")
	}
}

func TestFailedRootExchangePreservesPersistedState(t *testing.T) {
	current := Session{OAuthToken: "root", BusinessToken: "old", PAT: "old-pat"}
	calls := 0
	c := NewClient(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(401, `{"message":"private-upstream-data"}`), nil
	})})
	next, err := c.Renew(context.Background(), current, true)
	if err == nil || next != current || calls != 1 {
		t.Fatal("failed root renewal changed state or retried")
	}
}

package zcode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func syntheticPAT(exp int64) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256","typ":"JWT","sign_type":"SIGN"}`) + "." + enc(fmt.Sprintf(`{"token_use":"project_access","api_key":"named-key","exp":%d}`, exp)) + ".synthetic"
}

func TestLoginProjectPATFlow(t *testing.T) {
	now := time.Unix(1792180000, 0)
	steps := 0
	client := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		steps++
		body, _ := io.ReadAll(r.Body)
		switch steps {
		case 1:
			if r.URL.String() != authOrigin+"/api/v1/oauth/cli/init" || r.Method != "POST" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Fatal("invalid init")
			}
			return jsonResponse(200, fmt.Sprintf(`{"code":0,"data":{"flow_id":"flow","authorize_url":"https://chat.z.ai/api/oauth/authorize?state=server-state","expires_at":%d,"poll_interval_sec":2}}`, now.Unix()+300)), nil
		case 2:
			if r.URL.Path != "/api/v1/oauth/cli/poll/flow" {
				t.Fatal("invalid poll")
			}
			return jsonResponse(200, `{"code":0,"data":{"status":"ready","token":"zcode-jwt","zai":{"access_token":"original-oauth","refresh_token":"optional-refresh","expires_in":7200},"user":{"user_id":"owner"}}}`), nil
		case 3:
			if string(body) != `{"token":"original-oauth"}` {
				t.Fatal("original OAuth token not retained")
			}
			return jsonResponse(200, `{"success":true,"data":{"access_token":"business","expires_in":3600}}`), nil
		case 4:
			if r.Header.Get("Authorization") != "business" {
				t.Fatal("wrong project authorization")
			}
			return jsonResponse(200, `{"code":200,"data":{"organizations":[{"organizationId":"team-org","projects":[{"projectId":"team-project","projectType":2}]},{"organizationId":"personal-org","projects":[{"projectId":"personal-project","projectType":1}]}]}}`), nil
		case 5:
			if !strings.Contains(r.URL.Path, "/personal-org/projects/personal-project/api_keys") || r.Method != "GET" {
				t.Fatal("wrong project key path")
			}
			return jsonResponse(200, `{"code":200,"data":[]}`), nil
		case 6:
			if r.Method != "POST" || !strings.Contains(string(body), `"name":"zcode-api-key"`) {
				t.Fatal("wrong named key creation")
			}
			return jsonResponse(200, `{"code":200,"data":{"apiKey":"named-key","name":"zcode-api-key"}}`), nil
		case 7:
			if !strings.HasSuffix(r.URL.Path, "/named-key/access_tokens") || r.Header.Get("Authorization") != "Bearer business" || !strings.Contains(string(body), `"clientType":"zcode"`) {
				t.Fatal("wrong PAT exchange")
			}
			return jsonResponse(200, fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":600}}`, syntheticPAT(now.Unix()+500), now.Unix()+700)), nil
		default:
			t.Fatal("unexpected request")
			return nil, nil
		}
	})})
	client.now = func() time.Time { return now }
	ctx := context.Background()
	f, err := client.StartLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), f.PollingSecret) {
		t.Fatal("polling secret serialized")
	}
	a, err := client.PollLogin(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if a.Zai.AccessToken != "original-oauth" || a.Zai.RefreshToken != "optional-refresh" || a.Zai.ExpiresIn != 7200 || !a.ObservedAt.Equal(now) {
		t.Fatal("lost root credentials")
	}
	business, err := client.ExchangeBusinessToken(ctx, a.Zai.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !business.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("lost business expiry")
	}
	p, err := client.PersonalProject(ctx, business.Token)
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.EnsureProjectKey(ctx, business.Token, *p)
	if err != nil {
		t.Fatal(err)
	}
	pat, err := client.ProjectAccessToken(ctx, business.Token, *p, key)
	if err != nil {
		t.Fatal(err)
	}
	if !pat.ExpiresAt.Equal(now.Add(500 * time.Second)) {
		t.Fatal("did not choose earliest PAT expiry")
	}
	if steps != 7 {
		t.Fatal("incomplete flow")
	}
}

func TestNoCredentialRedirectAndSanitizedErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{302, `redirect`}, {401, `secret-in-response`}, {200, `not json secret-in-response`}, {200, `{"code":500,"data":{"token":"secret-in-response"}}`},
	} {
		calls := 0
		client := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := jsonResponse(tc.status, tc.body)
			resp.Header.Set("Location", "https://other.example/")
			return resp, nil
		})})
		_, err := client.ExchangeBusinessToken(context.Background(), "secret-input")
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsanitized or missing error", err)
		}
		if calls != 1 {
			t.Fatal("followed redirect")
		}
	}
}

func TestReuseNamedKeyAndRejectTeam(t *testing.T) {
	calls := 0
	c := NewClient(&http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" {
			t.Fatal("created duplicate key")
		}
		return jsonResponse(200, `{"code":200,"data":[{"apiKey":"existing","name":"zcode-api-key"}]}`), nil
	})})
	p := Project{OrganizationID: "org", ProjectID: "project"}
	key, err := c.EnsureProjectKey(context.Background(), "business", p)
	if err != nil || key != "existing" {
		t.Fatal(err)
	}
	p.Team = true
	if _, err = c.EnsureProjectKey(context.Background(), "business", p); err == nil {
		t.Fatal("implicitly supported team")
	}
	if calls != 1 {
		t.Fatal("unexpected network request")
	}
}

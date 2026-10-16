package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

func TestZCodeWebBindingRequiresConsentAndPreservesScheduling(t *testing.T) {
	for _, change := range []string{"none", "credentials", "proxy", "disabled"} {
		t.Run(change, func(t *testing.T) {
			p, r := newZCodeProviderTest(t)
			original, err := p.codec.Session(&r.account)
			if err != nil {
				t.Fatal(err)
			}
			original.OAuthToken = "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"owner"}`)) + ".signature"
			r.account.Credentials, err = p.codec.Credentials(1, original)
			if err != nil {
				t.Fatal(err)
			}
			r.account.Credentials["model_mapping"] = map[string]any{"alias": "glm-5.3"}
			r.account.Schedulable = false
			before := shallowCopyMap(r.account.Credentials)
			requests := 0
			p.clientFor = func(context.Context, *Account) (*zcode.Client, error) {
				return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
					requests++
					var body string
					switch req.URL.Path {
					case "/api/v1/auths/":
						body = `{"id":"owner","role":"user"}`
					case "/api/auth/z/login":
						body = `{"code":200,"data":{"access_token":"business-new","expires_in":3600}}`
					case "/api/biz/customer/getCustomerInfo":
						body = `{"code":200,"data":{"organizations":[{"organizationId":"org","projects":[{"projectId":"project","projectType":1}]}]}}`
					default:
						if !strings.HasSuffix(req.URL.Path, "/key/access_tokens") {
							t.Fatal("unexpected route")
						}
						body = fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":3600}}`, zcodeTestPAT(), time.Now().Add(time.Hour).Unix())
						switch change {
						case "credentials":
							r.account.Credentials["changed"] = true
						case "proxy":
							id := int64(2)
							r.account.ProxyID = &id
						case "disabled":
							r.account.Status = "disabled"
						}
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
				})}), nil
			}
			s := NewZCodeLoginService(p, &zcodeMemoryLoginStore{data: map[string]string{}})
			if err := s.BindWebSession(context.Background(), 1, 1, "native-secret", false); err == nil || requests != 0 || r.writes != 0 {
				t.Fatal("missing consent accepted")
			}
			err = s.BindWebSession(context.Background(), 1, 1, "native-secret", true)
			if change != "none" {
				if err == nil || r.writes != 0 {
					t.Fatal("concurrent change overwritten")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.account.Schedulable || r.account.Status != StatusActive || r.writes != 1 {
				t.Fatal("binding changed account state")
			}
			stored, err := p.codec.Session(&r.account)
			if err != nil {
				t.Fatal(err)
			}
			if stored.WebSessionToken != "native-secret" || stored.OAuthToken != original.OAuthToken || r.account.Credentials["zcode_web_session_bound"] != true || !reflect.DeepEqual(before["model_mapping"], r.account.Credentials["model_mapping"]) {
				t.Fatal("credential binding lost data")
			}
			raw, _ := json.Marshal(r.account.Credentials)
			if strings.Contains(string(raw), "native-secret") {
				t.Fatal("plaintext stored")
			}
		})
	}
}

func TestZCodeWebSessionRetryReasons(t *testing.T) {
	for _, tt := range []struct {
		stage, code string
		status      int
		reason      string
	}{
		{"business", "BUSINESS_REJECTED", 200, "root_authorization_rejected"},
		{"web_session", "IDENTITY_MISMATCH", 0, "root_authorization_rejected"},
		{"web_session", "PROJECT_MISMATCH", 0, "root_authorization_rejected"},
		{"web_session", "IDENTITY_REJECTED", 401, "root_authorization_rejected"},
		{"web_session", "IDENTITY_REJECTED", 503, "upstream_temporarily_unavailable"},
		{"web_session", "IDENTITY_UNAVAILABLE", 0, "upstream_temporarily_unavailable"},
	} {
		p, r := newZCodeProviderTest(t)
		p.recordRenewalFailure(context.Background(), &r.account, &zcode.APIError{Stage: tt.stage, Code: tt.code, Status: tt.status})
		if r.account.Credentials["zcode_retry_reason"] != tt.reason {
			t.Errorf("unexpected retry reason for %s %d", tt.code, tt.status)
		}
	}
}

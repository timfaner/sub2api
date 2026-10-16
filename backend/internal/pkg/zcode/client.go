package zcode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const authOrigin = "https://zcode.z.ai"
const responseLimit = 1 << 20

// APIError deliberately excludes upstream response text, URLs and credentials.
type APIError struct {
	Stage  string
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zcode: %s failed (%s, HTTP %d)", e.Stage, e.Code, e.Status)
}

type Client struct {
	http *http.Client
	now  func() time.Time
}

// NewClient preserves the caller's proxy/transport but forbids redirects to avoid
// leaking account credentials. The supplied client is never mutated.
func NewClient(client *http.Client) *Client {
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copy.Timeout = 30 * time.Second
	return &Client{http: &copy, now: time.Now}
}

type envelope struct {
	Code    json.RawMessage `json:"code"`
	Success *bool           `json:"success"`
	Data    json.RawMessage `json:"data"`
}

func (c *Client) call(ctx context.Context, stage, method, endpoint, authorization string, body any, out any) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || (u.Host != "api.z.ai" && u.Host != "zcode.z.ai") || u.User != nil {
		return &APIError{Stage: stage, Code: "ORIGIN_REJECTED"}
	}
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return &APIError{Stage: stage, Code: "INVALID_REQUEST"}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return &APIError{Stage: stage, Code: "INVALID_REQUEST"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &APIError{Stage: stage, Code: "NETWORK"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "HTTP_REJECTED"}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil || len(b) > responseLimit {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "RESPONSE_LIMIT"}
	}
	var e envelope
	if json.Unmarshal(b, &e) != nil {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "INVALID_JSON"}
	}
	code := string(e.Code)
	if e.Success != nil && !*e.Success || (code != "0" && code != "200" && code != `"0"` && code != `"200"` && !(stage == "business" && (code == "" || code == "null"))) {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "BUSINESS_REJECTED"}
	}
	if stage == "handshake" && code != "200" {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "BUSINESS_REJECTED"}
	}
	if len(e.Data) == 0 || bytes.Equal(e.Data, []byte("null")) || json.Unmarshal(e.Data, out) != nil {
		return &APIError{Stage: stage, Status: resp.StatusCode, Code: "INVALID_SCHEMA"}
	}
	return nil
}

// LoginFlow contains a server-only polling secret. Expose only URL and timing
// fields to administrators; bind ownership and consumption in the service layer.
type LoginFlow struct {
	ID              string `json:"flow_id"`
	AuthorizeURL    string `json:"authorize_url"`
	ExpiresAt       int64  `json:"expires_at"`
	IntervalSeconds int64  `json:"poll_interval_sec"`
	PollingSecret   string `json:"-"`
}

func (c *Client) StartLogin(ctx context.Context) (*LoginFlow, error) {
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	var f LoginFlow
	if err = c.call(ctx, "login_init", "POST", authOrigin+"/api/v1/oauth/cli/init", "Bearer "+secret, map[string]string{"provider": "zai"}, &f); err != nil {
		return nil, err
	}
	u, err := url.Parse(f.AuthorizeURL)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Host != "chat.z.ai" && u.Host != "z.ai" && u.Host != "zcode.z.ai") || u.Query().Get("state") == "" {
		return nil, &APIError{Stage: "login_init", Code: "UNTRUSTED_AUTHORIZE_URL"}
	}
	if !validSegment(f.ID) || f.IntervalSeconds < 1 || f.ExpiresAt-c.now().Unix() <= f.IntervalSeconds {
		return nil, &APIError{Stage: "login_init", Code: "INVALID_SCHEMA"}
	}
	f.PollingSecret = secret
	return &f, nil
}

// Authorization retains the original OAuth credential. Replacing it with the
// business token loses the only observed input to future business exchanges.
// Neither a returned refresh token nor ExpiresIn proves a usable refresh API.
type Authorization struct {
	ObservedAt time.Time `json:"observed_at,omitempty"`
	Status     string    `json:"status"`
	ZCodeJWT   string    `json:"token"`
	ExpiresIn  int64     `json:"expires_in"`
	Zai        struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	} `json:"zai"`
	User struct {
		ID   string `json:"user_id"`
		Name string `json:"name"`
	} `json:"user"`
}

func (c *Client) PollLogin(ctx context.Context, f *LoginFlow) (*Authorization, error) {
	if f == nil || !validSegment(f.ID) || f.PollingSecret == "" || c.now().Unix() >= f.ExpiresAt {
		return nil, &APIError{Stage: "login_poll", Code: "FLOW_EXPIRED"}
	}
	var a Authorization
	err := c.call(ctx, "login_poll", "GET", authOrigin+"/api/v1/oauth/cli/poll/"+url.PathEscape(f.ID), "Bearer "+f.PollingSecret, nil, &a)
	if err != nil {
		return nil, err
	}
	if a.Status == "pending" {
		return &a, nil
	}
	if a.Status == "failed" {
		return nil, &APIError{Stage: "login_poll", Code: "AUTHORIZATION_FAILED"}
	}
	if a.Status != "ready" || a.Zai.AccessToken == "" || a.ZCodeJWT == "" || a.User.ID == "" {
		return nil, &APIError{Stage: "login_poll", Code: "INVALID_SCHEMA"}
	}
	a.ObservedAt = c.now().UTC()
	return &a, nil
}

type BusinessToken struct {
	Token     string
	ExpiresAt time.Time
}

func (c *Client) ExchangeBusinessToken(ctx context.Context, oauth string) (*BusinessToken, error) {
	if strings.TrimSpace(oauth) == "" {
		return nil, &APIError{Stage: "business", Code: "OAUTH_REQUIRED"}
	}
	var d struct {
		Token      string `json:"access_token"`
		CamelToken string `json:"accessToken"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	start := c.now()
	if err := c.call(ctx, "business", "POST", Origin+"/api/auth/z/login", "", map[string]string{"token": oauth}, &d); err != nil {
		return nil, err
	}
	if d.Token == "" {
		d.Token = d.CamelToken
	}
	if d.Token == "" {
		return nil, &APIError{Stage: "business", Code: "INVALID_SCHEMA"}
	}
	expires := JWTExpiry(d.Token)
	if d.ExpiresIn > 0 && d.ExpiresIn < 365*24*60*60 {
		expires = earlier(expires, start.Add(time.Duration(d.ExpiresIn)*time.Second))
	}
	return &BusinessToken{Token: d.Token, ExpiresAt: expires}, nil
}

// JWTExpiry is an unverified expiry hint, never an authentication decision.
func JWTExpiry(token string) time.Time {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return time.Time{}
	}
	b, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return time.Time{}
	}
	var d struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &d) != nil || d.Exp <= 0 {
		return time.Time{}
	}
	return time.Unix(d.Exp, 0)
}
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}
func validSegment(s string) bool {
	return strings.TrimSpace(s) != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\r\n?#")
}

type Project struct {
	OrganizationID, OrganizationName, ProjectID, ProjectName string
	Team                                                     bool
}

func (c *Client) PersonalProject(ctx context.Context, business string) (*Project, error) {
	var d struct {
		Organizations []struct {
			ID       string `json:"organizationId"`
			Name     string `json:"organizationName"`
			Projects []struct {
				ID   string          `json:"projectId"`
				Name string          `json:"projectName"`
				Type json.RawMessage `json:"projectType"`
			} `json:"projects"`
		} `json:"organizations"`
	}
	if err := c.call(ctx, "projects", "GET", Origin+"/api/biz/customer/getCustomerInfo", business, nil, &d); err != nil {
		return nil, err
	}
	var selected *Project
	for _, o := range d.Organizations {
		if !validSegment(o.ID) {
			continue
		}
		var choice *Project
		for _, p := range o.Projects {
			if !validSegment(p.ID) || string(p.Type) == "2" || string(p.Type) == `"2"` {
				continue
			}
			if choice == nil || strings.Contains(p.Name, "默认项目") {
				choice = &Project{OrganizationID: o.ID, OrganizationName: o.Name, ProjectID: p.ID, ProjectName: p.Name}
			}
			if strings.Contains(p.Name, "默认项目") {
				break
			}
		}
		if choice != nil && (selected == nil || strings.Contains(o.Name, "默认机构")) {
			selected = choice
		}
		if choice != nil && strings.Contains(o.Name, "默认机构") {
			break
		}
	}
	if selected == nil {
		return nil, &APIError{Stage: "projects", Code: "PERSONAL_PROJECT_UNAVAILABLE"}
	}
	return selected, nil
}

func keyPath(p Project) (string, error) {
	if p.Team {
		return "", errors.New("zcode: team projects require explicit support")
	}
	if !validSegment(p.OrganizationID) || !validSegment(p.ProjectID) {
		return "", errors.New("zcode: invalid project")
	}
	return Origin + "/api/biz/v1/organization/" + url.PathEscape(p.OrganizationID) + "/projects/" + url.PathEscape(p.ProjectID) + "/api_keys", nil
}

// EnsureProjectKey always queries first, including after an uncertain POST.
// Service callers must serialize creation for the same account and project.
func (c *Client) EnsureProjectKey(ctx context.Context, business string, p Project) (string, error) {
	endpoint, err := keyPath(p)
	if err != nil {
		return "", err
	}
	type projectKey struct {
		ID   string `json:"apiKey"`
		Name string `json:"name"`
	}
	var keys []projectKey
	if err = c.call(ctx, "project_keys", "GET", endpoint, "Bearer "+business, nil, &keys); err != nil {
		return "", err
	}
	for _, k := range keys {
		if k.Name == "zcode-api-key" && validSegment(k.ID) {
			return k.ID, nil
		}
	}
	var key projectKey
	if err = c.call(ctx, "create_key", "POST", endpoint, "Bearer "+business, map[string]any{"name": "zcode-api-key", "usageScene": 1}, &key); err != nil {
		return "", err
	}
	if !validSegment(key.ID) {
		return "", &APIError{Stage: "create_key", Code: "INVALID_SCHEMA"}
	}
	return key.ID, nil
}

type ProjectToken struct {
	Token     string
	ExpiresAt time.Time
}

func (c *Client) ProjectAccessToken(ctx context.Context, business string, p Project, keyID string) (*ProjectToken, error) {
	endpoint, err := keyPath(p)
	if err != nil {
		return nil, err
	}
	if !validSegment(keyID) {
		return nil, &APIError{Stage: "project_token", Code: "INVALID_KEY"}
	}
	var d struct {
		AccessToken string `json:"accessToken"`
		TokenType   string `json:"tokenType"`
		ExpiresAt   int64  `json:"expiresAt"`
		ExpiresIn   int64  `json:"expiresIn"`
		Enable      *bool  `json:"enable"`
	}
	start := c.now()
	err = c.call(ctx, "project_token", "POST", endpoint+"/"+url.PathEscape(keyID)+"/access_tokens", "Bearer "+business, map[string]string{"clientType": "zcode", "clientVersion": Version}, &d)
	if err != nil {
		return nil, err
	}
	if d.AccessToken == "" || d.TokenType != "Bearer" || d.ExpiresAt <= start.Unix() || d.ExpiresIn <= 0 || d.ExpiresIn > 365*24*60*60 || (d.Enable != nil && !*d.Enable) {
		return nil, &APIError{Stage: "project_token", Code: "INVALID_SCHEMA"}
	}
	credential, err := ParseCredential(d.AccessToken)
	if err != nil {
		return nil, err
	}
	if credential.Field != "accessToken" {
		return nil, &APIError{Stage: "project_token", Code: "INVALID_PAT"}
	}
	expires := earlier(time.Unix(d.ExpiresAt, 0), start.Add(time.Duration(d.ExpiresIn)*time.Second))
	if jwt := JWTExpiry(d.AccessToken); !jwt.IsZero() {
		expires = earlier(expires, jwt)
	}
	if !expires.After(c.now()) {
		return nil, &APIError{Stage: "project_token", Code: "EXPIRED"}
	}
	return &ProjectToken{Token: d.AccessToken, ExpiresAt: expires}, nil
}

func (c *Client) SigningKey(ctx context.Context, credential Credential) (ed25519.PrivateKey, error) {
	ts := fmt.Sprint(c.now().UnixMilli())
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	var d struct {
		PrivateCipher string `json:"privateCipher"`
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := map[string]string{credential.Field: credential.Value, "nonce": nonce, "sig": HandshakeProof(credential, ts, nonce), "ts": ts}
	if err = c.call(ctx, "handshake", "POST", Origin+HandshakePath, credential.Value, body, &d); err != nil {
		return nil, err
	}
	return DecryptPrivateKey(credential, d.PrivateCipher)
}

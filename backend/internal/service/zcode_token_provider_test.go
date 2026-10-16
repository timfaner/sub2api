package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

type zcodeTestRepo struct {
	AccountRepository
	mu      sync.Mutex
	account Account
	writes  int
}

func (r *zcodeTestRepo) GetByID(context.Context, int64) (*Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.account
	a.Credentials = shallowCopyMap(a.Credentials)
	return &a, nil
}
func (r *zcodeTestRepo) UpdateZCodeCredentialsIfUnchanged(_ context.Context, id int64, before map[string]any, proxy *int64, next map[string]any) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.account.ID || !reflect.DeepEqual(before, r.account.Credentials) || !sameZCodeProxy(proxy, r.account.ProxyID) || !r.account.IsActive() {
		return false, nil
	}
	r.account.Credentials = shallowCopyMap(next)
	r.writes++
	return true, nil
}

type zcodeTestLease struct{ held atomic.Bool }

func (l *zcodeTestLease) Acquire(context.Context, string, time.Duration) (func(context.Context) error, bool, error) {
	if !l.held.CompareAndSwap(false, true) {
		return nil, false, nil
	}
	return func(context.Context) error { l.held.Store(false); return nil }, true, nil
}

type zcodeTestTransport func(*http.Request) (*http.Response, error)

func (f zcodeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func zcodeTestPAT() string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256","typ":"JWT","sign_type":"SIGN"}`) + "." + enc(fmt.Sprintf(`{"token_use":"project_access","api_key":"key","exp":%d}`, time.Now().Add(time.Hour).Unix())) + ".synthetic"
}
func newZCodeProviderTest(t *testing.T) (*ZCodeTokenProvider, *zcodeTestRepo) {
	t.Helper()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("test-secret-stable", 3)}}
	r := &zcodeTestRepo{}
	p := NewZCodeTokenProvider(r, nil, &zcodeTestLease{}, cfg)
	s := zcode.Session{UserID: "owner", OAuthToken: "root", BusinessToken: "business", BusinessExpiresAt: time.Now().Add(time.Hour), Project: zcode.Project{OrganizationID: "org", ProjectID: "project"}, ProjectKeyID: "key", PAT: "expired", PATExpiresAt: time.Now().Add(-time.Hour)}
	creds, err := p.codec.Credentials(1, s)
	if err != nil {
		t.Fatal(err)
	}
	r.account = Account{ID: 1, Platform: PlatformZhipu, Type: AccountTypeOAuth, Status: StatusActive, Credentials: creds}
	return p, r
}

func TestZCodeConcurrentRenewalPersistsOnce(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	pat := zcodeTestPAT()
	var requests atomic.Int32
	p.clientFor = func(context.Context, *Account) (*zcode.Client, error) {
		return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
			requests.Add(1)
			if !strings.HasSuffix(req.URL.Path, "/key/access_tokens") {
				t.Error("unexpected exchange")
			}
			body := fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":3600}}`, pat, time.Now().Add(time.Hour).Unix())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}), nil
	}
	a, _ := r.GetByID(context.Background(), 1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := p.GetAccessToken(context.Background(), a)
			if err != nil || got != pat {
				t.Errorf("token failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if requests.Load() != 1 || r.writes != 1 {
		t.Fatalf("duplicate refresh requests=%d writes=%d", requests.Load(), r.writes)
	}
	// A new provider instance must recover the refreshed token from encrypted DB
	// credentials, without a token cache, network request or interactive login.
	restarted := NewZCodeTokenProvider(r, nil, &zcodeTestLease{}, &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("test-secret-stable", 3)}})
	got, err := restarted.GetAccessToken(context.Background(), a)
	if err != nil || got != pat {
		t.Fatal("restart failed", err)
	}
}

func TestZCodeRenewalCannotOverwriteReauthorization(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	a, _ := r.GetByID(context.Background(), 1)
	p.clientFor = func(context.Context, *Account) (*zcode.Client, error) {
		return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
			r.mu.Lock()
			r.account.Credentials["login_generation"] = "new-login"
			r.mu.Unlock()
			body := fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":3600}}`, zcodeTestPAT(), time.Now().Add(time.Hour).Unix())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}), nil
	}
	if _, err := p.GetAccessToken(context.Background(), a); err == nil {
		t.Fatal("stale renewal accepted")
	}
	if r.writes != 0 || r.account.GetCredential("login_generation") != "new-login" {
		t.Fatal("overwrote new authorization")
	}
}

func TestZCodeRenewalBackoffSurvivesRestartAndClearsOnSuccess(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	ctx := context.Background()
	a, _ := r.GetByID(ctx, 1)
	var requests atomic.Int32
	var available atomic.Bool
	factory := func(context.Context, *Account) (*zcode.Client, error) {
		return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
			requests.Add(1)
			if !available.Load() {
				return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			}
			body := fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":3600}}`, zcodeTestPAT(), time.Now().Add(time.Hour).Unix())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}), nil
	}
	p.clientFor = factory
	if _, err := p.GetAccessToken(ctx, a); err == nil {
		t.Fatal("expected upstream failure")
	}
	fresh, _ := r.GetByID(ctx, 1)
	if !zcodeRetryPending(fresh) || fresh.GetCredentialAsInt64("zcode_retry_attempts") != 1 {
		t.Fatal("missing durable backoff")
	}
	original, _ := p.codec.Session(fresh)
	if original.OAuthToken != "root" || original.PAT != "expired" {
		t.Fatal("failure changed authorization")
	}
	restarted := NewZCodeTokenProvider(r, nil, &zcodeTestLease{}, &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("test-secret-stable", 3)}})
	restarted.clientFor = factory
	if _, err := restarted.GetAccessToken(ctx, a); err == nil {
		t.Fatal("expected backoff")
	}
	if requests.Load() != 1 {
		t.Fatal("restart bypassed persisted backoff")
	}
	r.mu.Lock()
	r.account.Credentials["zcode_retry_after"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	r.mu.Unlock()
	available.Store(true)
	if _, err := restarted.GetAccessToken(ctx, a); err != nil {
		t.Fatal(err)
	}
	fresh, _ = r.GetByID(ctx, 1)
	if _, ok := fresh.Credentials["zcode_retry_after"]; ok {
		t.Fatal("successful renewal kept backoff")
	}
	if _, ok := fresh.Credentials["zcode_retry_attempts"]; ok {
		t.Fatal("successful renewal kept attempts")
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected renewal count")
	}
}

func TestZCodeFailureCannotApplyBackoffToNewLogin(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	a, _ := r.GetByID(context.Background(), 1)
	p.clientFor = func(context.Context, *Account) (*zcode.Client, error) {
		return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
			r.mu.Lock()
			r.account.Credentials["zcode_login_completed"] = "new-flow"
			r.mu.Unlock()
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}), nil
	}
	if _, err := p.GetAccessToken(context.Background(), a); err == nil {
		t.Fatal("expected failure")
	}
	fresh, _ := r.GetByID(context.Background(), 1)
	if _, ok := fresh.Credentials["zcode_retry_after"]; ok {
		t.Fatal("stale failure changed new login")
	}
}

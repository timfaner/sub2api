package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

type zcodeMemoryLoginStore struct {
	mu   sync.Mutex
	data map[string]string
}

func (s *zcodeMemoryLoginStore) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", errors.New("missing")
	}
	return v, nil
}
func (s *zcodeMemoryLoginStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}
func (s *zcodeMemoryLoginStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

type zcodeKeyedLease struct {
	mu   sync.Mutex
	held map[string]bool
}

func (l *zcodeKeyedLease) Acquire(_ context.Context, key string, _ time.Duration) (func(context.Context) error, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[key] {
		return nil, false, nil
	}
	l.held[key] = true
	return func(context.Context) error { l.mu.Lock(); defer l.mu.Unlock(); delete(l.held, key); return nil }, true, nil
}
func (r *zcodeTestRepo) CompleteZCodeLoginIfUnchanged(_ context.Context, id int64, before map[string]any, proxy *int64, next map[string]any) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.account.ID || !reflect.DeepEqual(before, r.account.Credentials) || !sameZCodeProxy(proxy, r.account.ProxyID) || !r.account.IsActive() {
		return false, nil
	}
	if pending, _ := before["zcode_pending"].(bool); pending {
		r.account.Schedulable = true
	}
	r.account.Credentials = shallowCopyMap(next)
	r.writes++
	return true, nil
}

func newZCodeLoginTest(t *testing.T) (*ZCodeLoginService, *zcodeTestRepo, *zcodeMemoryLoginStore, *int) {
	t.Helper()
	p, r := newZCodeProviderTest(t)
	delete(r.account.Credentials, zcodeSessionCredential)
	r.account.Credentials["zcode_pending"] = true
	r.account.Schedulable = false
	p.lease = &zcodeKeyedLease{held: map[string]bool{}}
	requests := new(int)
	p.clientFor = func(context.Context, *Account) (*zcode.Client, error) {
		return zcode.NewClient(&http.Client{Transport: zcodeTestTransport(func(req *http.Request) (*http.Response, error) {
			*requests++
			var body string
			switch {
			case strings.HasSuffix(req.URL.Path, "/cli/init"):
				body = fmt.Sprintf(`{"code":0,"data":{"flow_id":"upstream-flow","authorize_url":"https://chat.z.ai/api/oauth/authorize?state=example","expires_at":%d,"poll_interval_sec":1}}`, time.Now().Add(5*time.Minute).Unix())
			case strings.Contains(req.URL.Path, "/cli/poll/"):
				body = `{"code":0,"data":{"status":"ready","token":"zcode-secret","zai":{"access_token":"oauth-root-secret"},"user":{"user_id":"owner"}}}`
			case req.URL.Path == "/api/auth/z/login":
				body = `{"code":200,"data":{"access_token":"business-secret","expires_in":3600}}`
			case strings.HasSuffix(req.URL.Path, "/getCustomerInfo"):
				body = `{"code":200,"data":{"organizations":[{"organizationId":"org","projects":[{"projectId":"project","projectType":1}]}]}}`
			case strings.HasSuffix(req.URL.Path, "/api_keys"):
				body = `{"code":200,"data":[{"apiKey":"key","name":"zcode-api-key"}]}`
			case strings.HasSuffix(req.URL.Path, "/access_tokens"):
				body = fmt.Sprintf(`{"code":200,"data":{"accessToken":%q,"tokenType":"Bearer","expiresAt":%d,"expiresIn":3600}}`, zcodeTestPAT(), time.Now().Add(time.Hour).Unix())
			default:
				t.Errorf("unexpected route %s", req.URL.Path)
				body = `{"code":500}`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}), nil
	}
	store := &zcodeMemoryLoginStore{data: map[string]string{}}
	return NewZCodeLoginService(p, store), r, store, requests
}

func TestZCodeLoginOwnsAndConsumesAuthorization(t *testing.T) {
	s, r, store, requests := newZCodeLoginTest(t)
	ctx := context.Background()
	start, err := s.Start(ctx, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if start.Status != "pending" || r.account.Schedulable {
		t.Fatal("pending account enabled")
	}
	before := *requests
	if _, err = s.Poll(ctx, 8, 1, start.FlowID); err == nil {
		t.Fatal("another administrator consumed login")
	}
	if *requests != before {
		t.Fatal("foreign owner reached upstream")
	}
	ready, err := s.Poll(ctx, 7, 1, start.FlowID)
	if err != nil || ready.Status != "ready" {
		t.Fatal("completion failed", err)
	}
	if !r.account.Schedulable {
		t.Fatal("completed account not enabled")
	}
	session, err := s.provider.codec.Session(&r.account)
	if err != nil || session.OAuthToken != "oauth-root-secret" {
		t.Fatal("root credential not persisted", err)
	}
	before = *requests
	writes := r.writes
	if _, err = s.Poll(ctx, 7, 1, start.FlowID); err != nil {
		t.Fatal("idempotent completion failed", err)
	}
	if *requests != before || r.writes != writes {
		t.Fatal("replayed completed authorization")
	}
	for _, sealed := range store.data {
		if strings.Contains(sealed, "secret") {
			t.Fatal("cache contains plaintext credentials")
		}
	}
}

func TestZCodeNewLoginInvalidatesEarlierAttempt(t *testing.T) {
	s, _, _, requests := newZCodeLoginTest(t)
	ctx := context.Background()
	first, err := s.Start(ctx, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Start(ctx, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	before := *requests
	if _, err = s.Poll(ctx, 7, 1, first.FlowID); err == nil {
		t.Fatal("stale flow accepted")
	}
	if *requests != before {
		t.Fatal("stale flow performed upstream work")
	}
	if err = s.Cancel(ctx, 7, 1, second.FlowID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Poll(ctx, 7, 1, second.FlowID); err == nil {
		t.Fatal("cancelled flow accepted")
	}
}

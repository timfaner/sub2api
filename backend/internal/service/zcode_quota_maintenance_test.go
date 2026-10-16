package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (r *zcodeTestRepo) UpdateExtra(context.Context, int64, map[string]any) error { return nil }

type zcodeQuotaUpstream struct {
	HTTPUpstream
	request *http.Request
}

func (u *zcodeQuotaUpstream) Do(r *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.request = r
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":200,"data":{"limits":[]}}`))}, nil
}

func TestZCodeQuotaUsesPATAndPersonalScope(t *testing.T) {
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
	// A personal project has an organization too. Legacy team heuristics must
	// not change this account's quota pool, even when old metadata remains.
	creds["zhipu_organization"] = "personal-org"
	r.account.Credentials = creds
	a, _ = r.GetByID(ctx, 1)
	u := &zcodeQuotaUpstream{}
	s := NewCNProviderQuotaService(r, nil, u, nil)
	s.zcodeTokenProvider = p
	result, err := s.QueryUsageForAccount(ctx, a)
	if err != nil || !result.Success {
		t.Fatal("quota query failed", err)
	}
	if u.request.URL.Host != "api.z.ai" || u.request.URL.Query().Get("type") != "" || u.request.Header.Get("bigmodel-organization") != "" {
		t.Fatal("wrong quota scope")
	}
	if u.request.Header.Get("Authorization") != session.PAT {
		t.Fatal("quota not using active PAT")
	}
}

type zcodeMaintenanceRepo struct {
	*zcodeTestRepo
	options OAuthRefreshPageOptions
	calls   int
}

func (r *zcodeMaintenanceRepo) ListOAuthRefreshCandidatePage(_ context.Context, o OAuthRefreshPageOptions) (*OAuthRefreshCandidatePage, error) {
	r.options = o
	r.calls++
	return &OAuthRefreshCandidatePage{Accounts: []Account{r.account}, NextAfterID: r.account.ID}, nil
}

func TestZCodeMaintenanceDoesNotRequireFakeRefreshToken(t *testing.T) {
	p, r := newZCodeProviderTest(t)
	r.account.Credentials["expires_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	pager := &zcodeMaintenanceRepo{zcodeTestRepo: r}
	p.repo = pager
	if next := p.refreshZCodePageCycle(context.Background(), 0); next != 0 {
		t.Fatal("did not finish scan")
	}
	if pager.calls != 1 || pager.options.RequireRefreshToken || len(pager.options.Platforms) != 1 || pager.options.Platforms[0] != PlatformZhipu {
		t.Fatal("wrong maintenance eligibility")
	}
}

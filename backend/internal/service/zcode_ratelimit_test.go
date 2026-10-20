//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestZCode429RequestRateLimitDoesNotBorrowQuotaReset(t *testing.T) {
	reset5h := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	repo := &rateLimit429AccountRepoStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID: 6, Platform: PlatformZhipu, Type: AccountTypeOAuth,
		Credentials: map[string]any{"auth_method": "zcode", "account_mode": AccountModeCoding},
		Extra: map[string]any{
			"zhipu_5h_reset_at":     reset5h.Format(time.RFC3339),
			"zhipu_weekly_reset_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
	}
	body := []byte(`{"error":{"code":"1302","message":"[1302][Rate limit reached for requests][request]","type":"rate_limit_error"}}`)

	svc.handle429(context.Background(), account, http.Header{}, body)

	require.Equal(t, 1, repo.rateLimitCalls)
	require.WithinDuration(t, time.Now().Add(5*time.Second), repo.lastRateLimitReset, time.Second)
}

func TestZCode429QuotaCodesUseMatchingWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fiveHour, weekly := now.Add(time.Hour), now.Add(72*time.Hour)
	for _, tc := range []struct {
		name, code string
		want       time.Time
	}{
		{"five hour", "1308", fiveHour},
		{"weekly", "1310", weekly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &rateLimit429AccountRepoStub{}
			svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
			account := &Account{
				ID: 6, Platform: PlatformZhipu, Type: AccountTypeOAuth,
				Credentials: map[string]any{"auth_method": "zcode", "account_mode": AccountModeCoding},
				Extra: map[string]any{
					"zhipu_5h_reset_at":     fiveHour.Format(time.RFC3339),
					"zhipu_weekly_reset_at": weekly.Format(time.RFC3339),
				},
			}
			svc.handle429(context.Background(), account, http.Header{}, []byte(`{"error":{"code":"`+tc.code+`"}}`))
			require.Equal(t, 1, repo.rateLimitCalls)
			require.WithinDuration(t, tc.want, repo.lastRateLimitReset, time.Second)
		})
	}
}

func TestZCode429RequestRateLimitHonorsRetryAfter(t *testing.T) {
	repo := &rateLimit429AccountRepoStub{}
	svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{ID: 6, Platform: PlatformZhipu, Type: AccountTypeOAuth,
		Credentials: map[string]any{"auth_method": "zcode", "account_mode": AccountModeCoding}}
	svc.handle429(context.Background(), account, http.Header{"Retry-After": []string{"12"}}, []byte(`{"error":{"code":"1302"}}`))
	require.Equal(t, 1, repo.rateLimitCalls)
	require.WithinDuration(t, time.Now().Add(12*time.Second), repo.lastRateLimitReset, time.Second)
}

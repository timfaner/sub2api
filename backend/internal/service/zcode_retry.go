package service

import (
	"context"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

// Retry state is durable and uses the same compare-and-swap as credentials, so
// process restarts and multiple workers cannot hammer an unavailable auth API.
func zcodeRetryPending(a *Account) bool {
	until := a.GetCredentialAsTime("zcode_retry_after")
	return until != nil && until.After(time.Now())
}
func clearZCodeRetry(next map[string]any) {
	delete(next, "zcode_retry_after")
	delete(next, "zcode_retry_attempts")
	delete(next, "zcode_retry_reason")
}
func (p *ZCodeTokenProvider) recordRenewalFailure(ctx context.Context, a *Account, cause error) {
	var api *zcode.APIError
	// Cancellation, local configuration and database failures are not upstream
	// rejections and must not create a durable authorization cooldown.
	if ctx.Err() != nil || !errors.As(cause, &api) {
		return
	}
	store, ok := p.repo.(ZCodeCredentialRepository)
	if !ok {
		return
	}
	attempts := a.GetCredentialAsInt64("zcode_retry_attempts") + 1
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 6 {
		attempts = 6
	}
	delay := 30 * time.Second * time.Duration(1<<uint(attempts-1))
	if delay > 15*time.Minute {
		delay = 15 * time.Minute
	}
	reason := "upstream_temporarily_unavailable"
	if api.Stage == "business" && (api.Status == 401 || api.Status == 403) {
		reason = "root_authorization_rejected"
	}
	next := shallowCopyMap(a.Credentials)
	next["zcode_retry_after"] = time.Now().Add(delay).UTC().Format(time.RFC3339)
	next["zcode_retry_attempts"] = attempts
	next["zcode_retry_reason"] = reason
	// A failure to store backoff must not replace the original sanitized cause.
	// CAS also prevents an old failure from marking a newly authorized account.
	_, _ = store.UpdateZCodeCredentialsIfUnchanged(ctx, a.ID, a.Credentials, a.ProxyID, next)
}

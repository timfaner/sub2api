package service

import (
	"context"
	"log/slog"
	"time"
)

// runMaintenance shares the refresh service lifecycle but uses its own bounded
// candidate scan. A ZCode session is not a conventional refresh_token document.
func (p *ZCodeTokenProvider) runMaintenance(ctx context.Context, stop <-chan struct{}) {
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var after int64
	for {
		cycle, cancel := context.WithTimeout(ctx, 40*time.Second)
		after = p.refreshZCodePageCycle(cycle, after)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func (p *ZCodeTokenProvider) refreshZCodePageCycle(ctx context.Context, after int64) int64 {
	pager, ok := p.repo.(OAuthRefreshCandidatePager)
	if !ok {
		return after
	}
	for ctx.Err() == nil {
		page, err := pager.ListOAuthRefreshCandidatePage(ctx, OAuthRefreshPageOptions{
			Platforms: []string{PlatformZhipu}, AfterID: after, Limit: 100, ActiveOnly: true,
			RequireRefreshToken: false, ExcludeRetryCooldown: true,
		})
		if err != nil {
			slog.Warn("zcode.refresh_scan_failed")
			return after
		}
		if page == nil {
			return after
		}
		for i := range page.Accounts {
			if ctx.Err() != nil {
				return after
			}
			a := &page.Accounts[i]
			if a.ID <= after {
				continue
			}
			after = a.ID
			if !a.IsZCodeOAuth() || a.GetCredential("zcode_session") == "" || zcodeRetryPending(a) {
				continue
			}
			// Metadata can only avoid unnecessary proactive work. The request
			// path always decrypts and checks the actual persisted token expiry.
			if expires := a.GetCredentialAsTime("expires_at"); expires != nil && time.Until(*expires) > 3*time.Minute {
				continue
			}
			if _, err = p.GetAccessToken(ctx, a); err != nil {
				// Provider errors are sanitized; never print account documents.
				slog.Warn("zcode.refresh_failed", "account_id", a.ID, "error", err)
			}
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return after
			case <-timer.C:
			}
		}
		if !page.HasMore {
			return 0
		}
		if page.NextAfterID < after || page.NextAfterID == 0 {
			return after
		}
		if page.NextAfterID == after && len(page.Accounts) == 0 {
			return after
		}
		after = page.NextAfterID
	}
	return after
}

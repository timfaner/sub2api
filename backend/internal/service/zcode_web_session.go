package service

import (
	"context"
	"fmt"
	"time"
)

// BindWebSession changes only credentials. Unlike initial login completion it
// must never enable scheduling, including when the administrator disabled it.
func (s *ZCodeLoginService) BindWebSession(ctx context.Context, owner, id int64, token string, consent bool) error {
	if !consent {
		return loginError("ZCODE_WEB_SESSION_CONSENT_REQUIRED", "explicit authorization for broader web session access is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := s.account(ctx, owner, id); err != nil {
		return err
	}
	return s.withLease(ctx, fmt.Sprintf("zcode:%d", id), func() error {
		a, err := s.account(ctx, owner, id)
		if err != nil {
			return err
		}
		if a.GetCredential("zcode_login_id") != "" {
			return loginError("ZCODE_LOGIN_BUSY", "finish or cancel the current OAuth authorization first")
		}
		current, err := s.provider.codec.Session(a)
		if err != nil {
			return loginError("ZCODE_OAUTH_REQUIRED", "complete official OAuth authorization before binding a web session")
		}
		client, err := s.provider.clientFor(ctx, a)
		if err != nil {
			return err
		}
		bound, err := client.BindWebSession(ctx, current, token)
		if err != nil {
			return err
		}
		bound, err = client.Renew(ctx, bound, true)
		if err != nil {
			return err
		}
		credentials, err := s.provider.codec.Credentials(id, bound)
		if err != nil {
			return err
		}
		next := MergeCredentials(a.Credentials, credentials)
		clearZCodeRetry(next)
		store, ok := s.provider.repo.(ZCodeCredentialRepository)
		if !ok {
			return loginError("ZCODE_LOGIN_STORAGE", "conditional account storage is unavailable")
		}
		applied, err := store.UpdateZCodeCredentialsIfUnchanged(ctx, id, a.Credentials, a.ProxyID, next)
		if err != nil || !applied {
			return loginError("ZCODE_LOGIN_CHANGED", "account changed during verification; binding was not saved")
		}
		s.provider.InvalidateSigningKey(id)
		return nil
	})
}

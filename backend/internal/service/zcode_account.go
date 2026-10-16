package service

import (
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

const zcodeSessionCredential = "zcode_session"

func (a *Account) IsZCodeOAuth() bool {
	return a != nil && a.Platform == PlatformZhipu && a.Type == AccountTypeOAuth && a.GetCredential("auth_method") == "zcode"
}

// ZCodeSessionCodec keeps all account and project credentials in one encrypted
// field. Public metadata is sufficient for scheduling, but never authentication.
type ZCodeSessionCodec struct{ vault *zcode.Vault }

func NewZCodeSessionCodec(cfg *config.Config) (*ZCodeSessionCodec, error) {
	if cfg == nil {
		return nil, errors.New("zcode: application configuration is required")
	}
	vault, err := zcode.NewVault(cfg.JWT.Secret)
	if err != nil {
		return nil, err
	}
	return &ZCodeSessionCodec{vault: vault}, nil
}

func (c *ZCodeSessionCodec) Credentials(accountID int64, session zcode.Session) (map[string]any, error) {
	if c == nil || c.vault == nil {
		return nil, errors.New("zcode: session encryption is not configured")
	}
	if session.UserID == "" || session.OAuthToken == "" || session.BusinessToken == "" || session.Project.Team || session.ProjectKeyID == "" || session.PAT == "" || session.PATExpiresAt.IsZero() {
		return nil, errors.New("zcode: incomplete personal account session")
	}
	sealed, err := c.vault.Seal(accountID, session)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"auth_method": "zcode", "account_mode": AccountModeCoding, "api_protocol": APIProtocolAnthropic,
		"zcode_plan_type": "personal", "zcode_site": "zai", zcodeSessionCredential: sealed,
		"expires_at": session.PATExpiresAt.UTC().Format(time.RFC3339),
	}, nil
}

func (c *ZCodeSessionCodec) Session(account *Account) (zcode.Session, error) {
	if c == nil || c.vault == nil || !account.IsZCodeOAuth() {
		return zcode.Session{}, errors.New("zcode: account session is unavailable")
	}
	session, err := c.vault.Open(account.ID, account.GetCredential(zcodeSessionCredential))
	if err != nil {
		return zcode.Session{}, err
	}
	if session.UserID == "" || session.Project.Team {
		return zcode.Session{}, errors.New("zcode: invalid account session scope")
	}
	return session, nil
}

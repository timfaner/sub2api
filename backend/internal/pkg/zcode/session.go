package zcode

import (
	"context"
	"errors"
	"time"
)

// Session is server-only state. The integration layer must encrypt persistence,
// exclude it from API responses, and commit renewal with a credential-version
// comparison. It deliberately retains the original authorization separately.
type Session struct {
	UserID            string
	OAuthToken        string
	OAuthRefreshToken string
	// Reported lifetime is evidence, not a verified renewal guarantee.
	OAuthReportedExpiresIn int64
	OAuthObservedAt        time.Time
	ZCodeJWT               string
	BusinessToken          string
	BusinessExpiresAt      time.Time
	Project                Project
	ProjectKeyID           string
	PAT                    string
	PATExpiresAt           time.Time
}

// PreparePersonal performs the observed login-to-PAT sequence. Account binding,
// single-use login completion and serialized key creation belong to the service.
func (c *Client) PreparePersonal(ctx context.Context, a Authorization) (Session, error) {
	if a.Status != "ready" || a.Zai.AccessToken == "" || a.User.ID == "" {
		return Session{}, &APIError{Stage: "prepare", Code: "AUTHORIZATION_REQUIRED"}
	}
	b, err := c.ExchangeBusinessToken(ctx, a.Zai.AccessToken)
	if err != nil {
		return Session{}, err
	}
	p, err := c.PersonalProject(ctx, b.Token)
	if err != nil {
		return Session{}, err
	}
	key, err := c.EnsureProjectKey(ctx, b.Token, *p)
	if err != nil {
		return Session{}, err
	}
	pat, err := c.ProjectAccessToken(ctx, b.Token, *p, key)
	if err != nil {
		return Session{}, err
	}
	return Session{UserID: a.User.ID, OAuthToken: a.Zai.AccessToken, OAuthRefreshToken: a.Zai.RefreshToken, ZCodeJWT: a.ZCodeJWT,
		OAuthReportedExpiresIn: a.Zai.ExpiresIn, OAuthObservedAt: a.ObservedAt,
		BusinessToken: b.Token, BusinessExpiresAt: b.ExpiresAt, Project: *p, ProjectKeyID: key, PAT: pat.Token, PATExpiresAt: pat.ExpiresAt}, nil
}

// Renew refreshes derived credentials without touching caller state. It does NOT
// claim to renew the root OAuth token: no root-refresh endpoint was established
// in the supplied ZCode artifact. Long-lived operation still requires live proof
// that the retained authorization can continue exchanging business credentials.
// Callers must coalesce concurrent renewals and persist only if scope is current.
func (c *Client) Renew(ctx context.Context, current Session, force bool) (Session, error) {
	if !force && current.PAT != "" && current.PATExpiresAt.After(c.now().Add(3*time.Minute)) {
		return current, nil
	}
	next := current
	exchanged := false
	exchange := func() error {
		if next.OAuthToken == "" {
			return &APIError{Stage: "renew", Code: "ROOT_AUTHORIZATION_MISSING"}
		}
		b, err := c.ExchangeBusinessToken(ctx, next.OAuthToken)
		if err != nil {
			return err
		}
		next.BusinessToken = b.Token
		next.BusinessExpiresAt = b.ExpiresAt
		exchanged = true
		return nil
	}
	if next.BusinessToken == "" || next.BusinessExpiresAt.IsZero() || !next.BusinessExpiresAt.After(c.now().Add(5*time.Minute)) {
		if err := exchange(); err != nil {
			return current, err
		}
	}
	pat, err := c.ProjectAccessToken(ctx, next.BusinessToken, next.Project, next.ProjectKeyID)
	var upstream *APIError
	if !exchanged && errors.As(err, &upstream) && (upstream.Status == 401 || upstream.Status == 403) {
		if err = exchange(); err != nil {
			return current, err
		}
		pat, err = c.ProjectAccessToken(ctx, next.BusinessToken, next.Project, next.ProjectKeyID)
	}
	if err != nil {
		return current, err
	}
	next.PAT = pat.Token
	next.PATExpiresAt = pat.ExpiresAt
	return next, nil
}

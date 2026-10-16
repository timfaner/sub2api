package zcode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// BindWebSession is an explicit authorization expansion for an already verified
// OAuth account. Callers must obtain consent, encrypt the returned state, and
// compare-and-swap against the account used for this check. It is not a login
// fallback and does not imply the web session can never expire or be revoked.
func (c *Client) BindWebSession(ctx context.Context, current Session, token string) (Session, error) {
	b, err := c.webSessionBusiness(ctx, current, token)
	if err != nil {
		return current, err
	}
	next := current
	next.WebSessionToken = token
	next.BusinessToken = b.Token
	next.BusinessExpiresAt = b.ExpiresAt
	return next, nil
}

func (c *Client) webSessionBusiness(ctx context.Context, current Session, token string) (*BusinessToken, error) {
	fail := func(code string) (*BusinessToken, error) {
		return nil, &APIError{Stage: "web_session", Code: code}
	}
	if token == "" || len(token) > 32768 || strings.ContainsAny(token, " \t\r\n") || current.Project.Team {
		return fail("INVALID_AUTHORIZATION")
	}
	// This claim is only an identity comparison with a previously authenticated,
	// encrypted OAuth session, never proof that a new bearer token is authentic.
	parts := strings.Split(current.OAuthToken, ".")
	if len(parts) != 3 {
		return fail("ORIGINAL_IDENTITY_UNAVAILABLE")
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	var original struct {
		Sub string `json:"sub"`
	}
	if err != nil || json.Unmarshal(claims, &original) != nil || original.Sub == "" {
		return fail("ORIGINAL_IDENTITY_UNAVAILABLE")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chat.z.ai/api/v1/auths/", nil)
	if err != nil {
		return fail("INVALID_REQUEST")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fail("IDENTITY_UNAVAILABLE")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fail("IDENTITY_REJECTED")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	var identity struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if err != nil || len(body) > responseLimit || json.Unmarshal(body, &identity) != nil {
		return fail("INVALID_IDENTITY")
	}
	// The endpoint may return HTTP 200 with a newly created guest identity for an
	// invalid bearer. Only the observed authenticated-user role is supported.
	if identity.Role != "user" || identity.ID != original.Sub {
		return fail("IDENTITY_MISMATCH")
	}
	business, err := c.ExchangeBusinessToken(ctx, token)
	if err != nil {
		return nil, err
	}
	project, err := c.PersonalProject(ctx, business.Token)
	if err != nil {
		return nil, err
	}
	if project.OrganizationID != current.Project.OrganizationID || project.ProjectID != current.Project.ProjectID {
		return fail("PROJECT_MISMATCH")
	}
	return business, nil
}

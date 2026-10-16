package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *OpenAIGatewayService) resolveNativeAnthropicCredential(ctx context.Context, a *Account) (string, error) {
	if a.IsZCodeOAuth() {
		if s.zcodeTokenProvider == nil {
			return "", errors.New("zcode: credential provider is not configured")
		}
		return s.zcodeTokenProvider.GetAccessToken(ctx, a)
	}
	key := strings.TrimSpace(a.GetOpenAIProtocolAPIKey())
	if key == "" {
		return "", fmt.Errorf("account %d missing api_key", a.ID)
	}
	return key, nil
}

func (s *OpenAIGatewayService) signZCodeNativeRequest(ctx context.Context, c *gin.Context, a *Account, req *http.Request, token string) error {
	if s.zcodeTokenProvider == nil {
		return errors.New("zcode: signing provider is not configured")
	}
	session := uuid.NewString()
	if c != nil && c.Request != nil {
		inbound := c.GetHeader("session_id")
		if inbound == "" {
			inbound = c.GetHeader("x-session-id")
		}
		if inbound != "" && len(inbound) <= 256 {
			session = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("zcode:%d:%s", a.ID, inbound))).String()
		}
	}
	return s.zcodeTokenProvider.Sign(ctx, a, req, token, session)
}

// Only an explicit pre-stream signature rejection can replay the model request.
// Error bodies are restored for the normal gateway failure/usage handling.
func (s *OpenAIGatewayService) doNativeAnthropicUpstream(req *http.Request, proxyURL string, a *Account) (*http.Response, error) {
	resp, err := s.doOpenAIUpstream(req, proxyURL, a)
	if err != nil || !a.IsZCodeOAuth() || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	if resp.Body == nil {
		return resp, nil
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if readErr != nil {
		resp.Body.Close()
		return nil, errors.New("zcode: cannot read upstream authentication response")
	}
	resp.Body = &zcodeReplayBody{Reader: io.MultiReader(bytes.NewReader(body), resp.Body), closer: resp.Body}
	if !zcode.SignatureRejected(resp.StatusCode, body) || req.GetBody == nil || s.zcodeTokenProvider == nil {
		return resp, nil
	}
	s.zcodeTokenProvider.InvalidateSigningKey(a.ID)
	next := req.Clone(req.Context())
	next.Body, err = req.GetBody()
	if err != nil {
		return resp, nil
	}
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	err = s.zcodeTokenProvider.Sign(req.Context(), a, next, token, req.Header.Get("X-Session-Id"))
	if err != nil {
		next.Body.Close()
		resp.Body.Close()
		return nil, err
	}
	resp.Body.Close()
	return s.doOpenAIUpstream(next, proxyURL, a)
}

type zcodeReplayBody struct {
	io.Reader
	closer io.Closer
}

func (b *zcodeReplayBody) Close() error { return b.closer.Close() }

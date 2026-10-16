package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZCodeModelsUseCurrentPATAndFixedVerifiedEndpoint(t *testing.T) {
	p, repo := newZCodeProviderTest(t)
	session, err := p.codec.Session(&repo.account)
	require.NoError(t, err)
	session.PAT = zcodeTestPAT()
	session.PATExpiresAt = time.Now().Add(time.Hour)
	repo.account.Credentials, err = p.codec.Credentials(1, session)
	require.NoError(t, err)
	repo.account.Credentials["base_url"] = "https://untrusted.example"
	repo.account.Credentials["api_key"] = "must-not-use"
	req, err := buildZCodeModelsRequest(context.Background(), &repo.account, p)
	require.NoError(t, err)
	require.Equal(t, "https://api.z.ai/api/coding/paas/v4/models", req.URL.String())
	require.Equal(t, "Bearer "+session.PAT, req.Header.Get("Authorization"))
	require.Equal(t, http.MethodGet, req.Method)
	admin := &AccountTestService{openaiGatewayService: &OpenAIGatewayService{zcodeTokenProvider: p}}
	adminReq, err := admin.buildUpstreamModelsRequest(context.Background(), &repo.account)
	require.NoError(t, err)
	require.Equal(t, req.URL.String(), adminReq.URL.String())
	require.Equal(t, req.Header.Get("Authorization"), adminReq.Header.Get("Authorization"))
}

func TestZCodeZhipuModelCatalogIsGroupScopedAndAuthoritative(t *testing.T) {
	a := *newCodexModelsAPIKeyTestAccount("https://models.example/v1")
	a.Platform = PlatformZhipu
	a.Credentials["api_protocol"] = APIProtocolChatCompletions
	repo := codexModelsVisibilityAccountRepo{byGroup: map[int64][]Account{4: {a}, 9: {{ID: 99, Platform: PlatformOpenAI}}}}
	calls := 0
	svc := newCodexModelsAPIKeyTestService(&codexModelsHTTPUpstreamStub{do: func(req *http.Request, _ string, id int64, _ int) (*http.Response, error) {
		calls++
		require.Equal(t, a.ID, id)
		require.Equal(t, "Bearer sk-upstream", req.Header.Get("Authorization"))
		return ordinaryModelsUpstreamResponse(`{"object":"list","data":[{"id":"glm-upstream-new"},{"id":"glm-5.3"}]}`), nil
	}})
	svc.accountRepo = repo
	response, err := svc.FetchZhipuModelsList(context.Background(), &Group{ID: 4, Platform: PlatformZhipu}, "")
	require.NoError(t, err)
	require.Contains(t, string(response.Body), `"id":"glm-upstream-new"`)
	require.Contains(t, string(response.Body), `"owned_by":"zhipu"`)
	require.NotContains(t, string(response.Body), "claude")
	cached, err := svc.FetchZhipuModelsList(context.Background(), &Group{ID: 4, Platform: PlatformZhipu}, response.ETag)
	require.NoError(t, err)
	require.True(t, cached.NotModified)
	require.Equal(t, 1, calls)
	empty, err := svc.FetchZhipuModelsList(context.Background(), &Group{ID: 9, Platform: PlatformZhipu}, "")
	require.NoError(t, err)
	require.JSONEq(t, `{"object":"list","data":[]}`, string(empty.Body))
	require.Equal(t, 1, calls, "another platform must not contribute a catalog")
}

func TestZCodeZhipuModelCatalogFailureDoesNotInventDefaults(t *testing.T) {
	a := *newCodexModelsAPIKeyTestAccount("https://models.example/v1")
	a.Platform = PlatformZhipu
	svc := newCodexModelsAPIKeyTestService(&codexModelsHTTPUpstreamStub{do: func(*http.Request, string, int64, int) (*http.Response, error) {
		return ordinaryModelsUpstreamResponse(`{"error":"unavailable"}`), nil
	}})
	svc.accountRepo = codexModelsVisibilityAccountRepo{byGroup: map[int64][]Account{4: {a}}}
	response, err := svc.FetchZhipuModelsList(context.Background(), &Group{ID: 4, Platform: PlatformZhipu}, "")
	require.Error(t, err)
	require.Nil(t, response)
}

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayZhipuModelsUseUpstreamForBothClients(t *testing.T) {
	gin.SetMode(gin.TestMode)
	account := service.Account{ID: 1, Platform: service.PlatformZhipu, Type: service.AccountTypeAPIKey,
		Credentials: map[string]any{"api_key": "test", "base_url": "https://models.example/v1"}}
	repo := &gatewayModelsAccountRepoStub{byGroup: map[int64][]service.Account{4: {account}}}
	h := newGatewayModelsHandlerForTest(repo)
	upstream := &codexModelsFailoverHTTPUpstream{firstBody: `{"data":[{"id":"glm-live-new"},{"id":"glm-5.3"}]}`}
	h.openAIGatewayService = service.NewOpenAIGatewayService(repo,
		nil, nil, nil, nil, nil, nil, &config.Config{RunMode: config.RunModeSimple}, nil, nil, nil, nil, nil,
		upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	for _, codex := range []bool{false, true} {
		for _, groupID := range []int64{4, 9} {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{Group: &service.Group{ID: groupID, Platform: service.PlatformZhipu}})
			var ids []string
			if codex {
				h.CodexModels(c)
				var body codexModelsResponseForTest
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				for _, model := range body.Models {
					ids = append(ids, model.Slug)
				}
			} else {
				h.Models(c)
				var body gatewayModelsResponseForTest
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				ids = modelIDsForTest(body.Data)
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			if groupID == 4 {
				require.ElementsMatch(t, []string{"glm-live-new", "glm-5.3"}, ids)
			} else {
				require.Empty(t, ids)
			}
		}
	}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models/unknown", nil)
	c.Params = gin.Params{{Key: "model", Value: "unknown"}}
	c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{Group: &service.Group{ID: 4, Platform: service.PlatformZhipu}})
	h.Models(c)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

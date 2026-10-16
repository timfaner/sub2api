package handler

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *GatewayHandler) fetchZhipuModels(c *gin.Context, group *service.Group, etag string) (*service.OpenAIModelsResponse, bool) {
	if h.openAIGatewayService == nil {
		writeOpenAIModelsError(c, http.StatusServiceUnavailable, "upstream_error", "Zhipu model discovery is unavailable")
		return nil, false
	}
	response, err := h.openAIGatewayService.FetchZhipuModelsList(c.Request.Context(), group, etag)
	if c.Request.Context().Err() != nil {
		return nil, false
	}
	if err != nil {
		writeOpenAIModelsError(c, http.StatusBadGateway, "upstream_error", "Unable to retrieve the Zhipu upstream model catalogue")
		return nil, false
	}
	return response, true
}

func (h *GatewayHandler) zhipuModels(c *gin.Context, group *service.Group) {
	etag := c.GetHeader("If-None-Match")
	if c.Param("model") != "" {
		etag = ""
	}
	response, ok := h.fetchZhipuModels(c, group, etag)
	if ok {
		writeOpenAIModelsResponse(c, response)
	}
}

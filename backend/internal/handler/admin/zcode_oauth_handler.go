package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type ZCodeOAuthHandler struct{ login *service.ZCodeLoginService }

func NewZCodeOAuthHandler(login *service.ZCodeLoginService) *ZCodeOAuthHandler {
	return &ZCodeOAuthHandler{login: login}
}

func zcodeLoginScope(c *gin.Context) (int64, int64, bool) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Error(c, 401, "administrator authentication required")
		return 0, 0, false
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.Error(c, 400, "invalid account id")
		return 0, 0, false
	}
	return subject.UserID, id, true
}
func (h *ZCodeOAuthHandler) Start(c *gin.Context) {
	owner, id, ok := zcodeLoginScope(c)
	if !ok {
		return
	}
	result, err := h.login.Start(c.Request.Context(), owner, id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *ZCodeOAuthHandler) Poll(c *gin.Context) {
	owner, id, ok := zcodeLoginScope(c)
	if !ok {
		return
	}
	result, err := h.login.Poll(c.Request.Context(), owner, id, c.Param("flow"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
func (h *ZCodeOAuthHandler) Cancel(c *gin.Context) {
	owner, id, ok := zcodeLoginScope(c)
	if !ok {
		return
	}
	if err := h.login.Cancel(c.Request.Context(), owner, id, c.Param("flow")); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"status": "cancelled"})
}

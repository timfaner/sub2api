package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

func TestZCodeWebSessionRequestBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name, id, body string
		authenticated  bool
		status         int
	}{
		{"unauthenticated", "1", `{"token":"credential-canary","consent":true}`, false, 401},
		{"invalid-account", "not-an-id", `{"token":"credential-canary","consent":true}`, true, 400},
		{"malformed", "1", `{"token":"credential-canary"`, true, 400},
		{"empty", "1", `{"token":"","consent":true}`, true, 400},
		{"oversized", "1", `{"token":"` + strings.Repeat("credential-canary", 3000) + `","consent":true}`, true, 400},
		{"missing-consent", "1", `{"token":"credential-canary"}`, true, 409},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			if tt.authenticated {
				r.Use(func(c *gin.Context) {
					c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 1})
					c.Next()
				})
			}
			h := NewZCodeOAuthHandler(nil)
			r.POST("/accounts/:id/zcode/web-session", h.BindWebSession)
			req := httptest.NewRequest(http.MethodPost, "/accounts/"+tt.id+"/zcode/web-session", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d", w.Code, tt.status)
			}
			if strings.Contains(w.Body.String(), "credential-canary") {
				t.Fatal("credential reflected in error")
			}
		})
	}
}

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestZCodeTokenCountingDoesNotSendCredentialsUpstream(t *testing.T) {
	a := &Account{ID: 1, Platform: PlatformZhipu, Type: AccountTypeOAuth, Credentials: map[string]any{"auth_method": "zcode"}}
	// No token provider or transport: accidental upstream dispatch must fail.
	s := &OpenAIGatewayService{}
	for _, test := range []struct {
		name      string
		body      string
		responses bool
	}{
		{"anthropic", `{"model":"glm-5.3","messages":[{"role":"user","content":"hello"}],"max_tokens":10}`, false},
		{"responses", `{"model":"glm-5.3","input":"hello"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/count", bytes.NewBufferString(test.body))
			var err error
			if test.responses {
				err = s.ForwardResponsesInputTokens(context.Background(), c, a, []byte(test.body))
			} else {
				err = s.ForwardCountTokensAsAnthropic(context.Background(), c, a, []byte(test.body), "")
			}
			if err != nil || rec.Code != http.StatusOK {
				t.Fatalf("count failed: %v status=%d", err, rec.Code)
			}
			var result map[string]any
			if err = json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			n, ok := result["input_tokens"].(float64)
			if !ok || n < 1 {
				t.Fatal("missing positive local estimate")
			}
		})
	}
}

func TestZCodeModelDiscoveryRejectsUnverifiedEndpoint(t *testing.T) {
	a := &Account{ID: 1, Platform: PlatformZhipu, Type: AccountTypeOAuth, Credentials: map[string]any{"auth_method": "zcode"}}
	req, err := (&AccountTestService{}).buildUpstreamModelsRequest(context.Background(), a)
	var unsupported *UpstreamModelSyncError
	if req != nil || !errors.As(err, &unsupported) || unsupported.Kind != UpstreamModelSyncErrorUnsupported {
		t.Fatal("model discovery must not fall back to OpenAI")
	}
}

func TestZCodeGenericUsageNeverUsesClaudeOAuth(t *testing.T) {
	a := &Account{ID: 1, Platform: PlatformZhipu, Type: AccountTypeOAuth, Credentials: map[string]any{"auth_method": "zcode"}}
	if a.CanGetUsage() {
		t.Fatal("ZCode must use its provider quota endpoint")
	}
	_, err := (&AccountUsageService{}).GetUsageForAccount(context.Background(), a)
	if err == nil {
		t.Fatal("generic usage must reject ZCode without contacting Claude")
	}
}

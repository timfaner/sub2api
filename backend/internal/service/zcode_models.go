package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
)

// Verified with a real personal ZCode PAT. Discovery is a read-only standard
// catalog endpoint; it does not use a model inference request or fallback key.
func buildZCodeModelsRequest(ctx context.Context, account *Account, provider *ZCodeTokenProvider) (*http.Request, error) {
	if provider == nil || !account.IsZCodeOAuth() {
		return nil, errors.New("ZCode model discovery credentials are unavailable")
	}
	token, err := provider.GetAccessToken(ctx, account)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zcode.Origin+"/api/coding/paas/v4/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// FetchZhipuModelsList unions the real catalogs of this group's eligible Zhipu
// accounts. Raw account catalogs are cached independently by the existing
// credential/proxy-aware cache; group policy is always applied afterwards.
// An empty catalog is authoritative. An upstream failure is never replaced by
// Claude defaults or an incomplete successful list.
func (s *OpenAIGatewayService) FetchZhipuModelsList(ctx context.Context, group *Group, etag string) (*OpenAIModelsResponse, error) {
	if s == nil || s.accountRepo == nil || group == nil || group.Platform != PlatformZhipu {
		return nil, errors.New("Zhipu model discovery requires a Zhipu group")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	accounts, err := s.accountRepo.ListSchedulableByGroupID(ctx, group.ID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]json.RawMessage)
	for i := range accounts {
		a := &accounts[i]
		if a.Platform != PlatformZhipu {
			continue
		}
		response, err := s.FetchOpenAIModelsList(ctx, a)
		if err != nil {
			return nil, err
		}
		body, err := projectAccountModelAliases(response.Body, a, group, false)
		if err != nil {
			return nil, err
		}
		_, entries, err := modelCatalogEntries(body, "data")
		if err != nil {
			return nil, err
		}
		for _, raw := range entries {
			var entry map[string]json.RawMessage
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, err
			}
			var id string
			if err := json.Unmarshal(entry["id"], &id); err != nil {
				return nil, err
			}
			entry["owned_by"] = json.RawMessage(`"zhipu"`)
			encoded, err := json.Marshal(entry)
			if err != nil {
				return nil, err
			}
			byID[id] = encoded
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if group.ModelAllowlistEnabled() {
		ids = group.ModelAllowlist.FilterForListing(ids)
	}
	body, err := json.Marshal(struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}{"list", selectModelCatalogEntries(byID, ids)})
	if err != nil {
		return nil, err
	}
	response := &OpenAIModelsResponse{Body: body, ETag: codexModelsManifestBodyETag(body)}
	return openAIModelsResponseForClient(response, etag), nil
}

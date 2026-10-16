package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
	"github.com/google/uuid"
)

type ZCodeLoginStore interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, time.Duration) error
	Delete(context.Context, string) error
}
type ZCodeLoginRepository interface {
	CompleteZCodeLoginIfUnchanged(context.Context, int64, map[string]any, *int64, map[string]any) (bool, error)
}
type ZCodeLoginService struct {
	provider *ZCodeTokenProvider
	store    ZCodeLoginStore
}

func NewZCodeLoginService(p *ZCodeTokenProvider, store ZCodeLoginStore) *ZCodeLoginService {
	return &ZCodeLoginService{provider: p, store: store}
}

type ZCodeLoginView struct {
	FlowID       string `json:"flow_id"`
	Status       string `json:"status"`
	AuthorizeURL string `json:"authorize_url,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	PollInterval int64  `json:"poll_interval_sec,omitempty"`
}
type zcodeLoginRecord struct {
	Flow          zcode.LoginFlow
	PollingSecret string
	ProxyID       *int64
	NextPoll      int64
	Authorization *zcode.Authorization
	Prepared      *zcode.Session
	Completed     bool
	Deadline      int64
}

func loginError(code, message string) error {
	return infraerrors.New(http.StatusConflict, code, message)
}
func loginStoreKey(owner, account int64, id string) string {
	return fmt.Sprintf("%d:%d:%s", owner, account, id)
}

func (s *ZCodeLoginService) account(ctx context.Context, owner, id int64) (*Account, error) {
	if owner <= 0 || id <= 0 {
		return nil, loginError("ZCODE_LOGIN_OWNER_REQUIRED", "authenticated administrator and account are required")
	}
	if s == nil || s.provider == nil || s.provider.codec == nil || s.provider.configErr != nil || s.store == nil || s.provider.lease == nil {
		return nil, loginError("ZCODE_LOGIN_UNAVAILABLE", "ZCode login is not configured")
	}
	a, err := s.provider.repo.GetByID(ctx, id)
	if err != nil || a == nil || !a.IsZCodeOAuth() || !a.IsActive() {
		return nil, loginError("ZCODE_ACCOUNT_UNAVAILABLE", "ZCode account is missing or disabled")
	}
	return a, nil
}
func (s *ZCodeLoginService) save(ctx context.Context, owner, id int64, flowID string, r *zcodeLoginRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(b)
	sealed, err := s.provider.codec.vault.SealLogin(id, owner, flowID, b)
	if err != nil {
		return err
	}
	ttl := time.Until(time.Unix(r.Deadline, 0))
	if ttl <= 0 {
		return loginError("ZCODE_LOGIN_EXPIRED", "login session expired")
	}
	if err = s.store.Set(ctx, loginStoreKey(owner, id, flowID), sealed, ttl); err != nil {
		return loginError("ZCODE_LOGIN_STORAGE", "cannot save login progress")
	}
	return nil
}
func (s *ZCodeLoginService) read(ctx context.Context, owner, id int64, flowID string) (*zcodeLoginRecord, error) {
	if _, err := uuid.Parse(flowID); err != nil {
		return nil, loginError("ZCODE_LOGIN_EXPIRED", "login session is unavailable")
	}
	sealed, err := s.store.Get(ctx, loginStoreKey(owner, id, flowID))
	if err != nil {
		return nil, loginError("ZCODE_LOGIN_EXPIRED", "login session is unavailable")
	}
	b, err := s.provider.codec.vault.OpenLogin(id, owner, flowID, sealed)
	if err != nil {
		return nil, loginError("ZCODE_LOGIN_EXPIRED", "login session is unavailable")
	}
	defer clear(b)
	var r zcodeLoginRecord
	if json.Unmarshal(b, &r) != nil || time.Now().Unix() >= r.Deadline {
		return nil, loginError("ZCODE_LOGIN_EXPIRED", "login session expired")
	}
	r.Flow.PollingSecret = r.PollingSecret
	return &r, nil
}
func (s *ZCodeLoginService) withLease(ctx context.Context, key string, fn func() error) error {
	release, ok, err := s.provider.lease.Acquire(ctx, key, time.Minute)
	if err != nil || !ok || release == nil {
		return loginError("ZCODE_LOGIN_BUSY", "login operation is already running; retry shortly")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = release(cleanup)
	}()
	return fn()
}

func (s *ZCodeLoginService) Start(ctx context.Context, owner, id int64) (*ZCodeLoginView, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	a, err := s.account(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	client, err := s.provider.clientFor(ctx, a)
	if err != nil {
		return nil, err
	}
	f, err := client.StartLogin(ctx)
	if err != nil {
		return nil, err
	}
	flowID := uuid.NewString()
	r := &zcodeLoginRecord{Flow: *f, PollingSecret: f.PollingSecret, ProxyID: a.ProxyID, Deadline: f.ExpiresAt + 600}
	if err = s.save(ctx, owner, id, flowID, r); err != nil {
		return nil, err
	}
	store, ok := s.provider.repo.(ZCodeCredentialRepository)
	if !ok {
		return nil, loginError("ZCODE_LOGIN_STORAGE", "conditional account storage is unavailable")
	}
	next := shallowCopyMap(a.Credentials)
	next["zcode_login_id"] = flowID
	err = s.withLease(ctx, fmt.Sprintf("zcode:%d", id), func() error {
		applied, err := store.UpdateZCodeCredentialsIfUnchanged(ctx, id, a.Credentials, a.ProxyID, next)
		if err != nil || !applied {
			return loginError("ZCODE_LOGIN_CHANGED", "account changed; start authorization again")
		}
		return nil
	})
	if err != nil {
		_ = s.store.Delete(ctx, loginStoreKey(owner, id, flowID))
		return nil, loginError("ZCODE_LOGIN_CHANGED", "account changed; start authorization again")
	}
	return &ZCodeLoginView{FlowID: flowID, Status: "pending", AuthorizeURL: f.AuthorizeURL, ExpiresAt: f.ExpiresAt, PollInterval: f.IntervalSeconds}, nil
}

func (s *ZCodeLoginService) Poll(ctx context.Context, owner, id int64, flowID string) (*ZCodeLoginView, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, err := s.account(ctx, owner, id); err != nil {
		return nil, err
	}
	view := &ZCodeLoginView{FlowID: flowID, Status: "pending"}
	err := s.withLease(ctx, "zcode-login:"+loginStoreKey(owner, id, flowID), func() error {
		r, err := s.read(ctx, owner, id, flowID)
		if err != nil {
			return err
		}
		if r.Completed {
			view.Status = "ready"
			return nil
		}
		a, err := s.account(ctx, owner, id)
		if err != nil {
			return err
		}
		if a.GetCredential("zcode_login_completed") == flowID {
			r.Completed = true
			r.Prepared = nil
			r.Authorization = nil
			r.PollingSecret = ""
			r.Flow.PollingSecret = ""
			view.Status = "ready"
			return s.save(ctx, owner, id, flowID, r)
		}
		if a.GetCredential("zcode_login_id") != flowID || !sameZCodeProxy(a.ProxyID, r.ProxyID) {
			return loginError("ZCODE_LOGIN_CHANGED", "account or authorization attempt changed")
		}
		view.PollInterval = r.Flow.IntervalSeconds
		if time.Now().UnixMilli() < r.NextPoll {
			return nil
		}
		r.NextPoll = time.Now().Add(time.Duration(r.Flow.IntervalSeconds) * time.Second).UnixMilli()
		if err = s.save(ctx, owner, id, flowID, r); err != nil {
			return err
		}
		client, err := s.provider.clientFor(ctx, a)
		if err != nil {
			return err
		}
		if r.Authorization == nil {
			auth, err := client.PollLogin(ctx, &r.Flow)
			if err != nil {
				return err
			}
			if auth.Status == "pending" {
				return nil
			}
			r.Authorization = auth
			if err = s.save(ctx, owner, id, flowID, r); err != nil {
				return err
			}
		}
		return s.withLease(ctx, fmt.Sprintf("zcode:%d", id), func() error {
			fresh, err := s.account(ctx, owner, id)
			if err != nil {
				return err
			}
			if fresh.GetCredential("zcode_login_id") != flowID || !sameZCodeProxy(fresh.ProxyID, r.ProxyID) {
				return loginError("ZCODE_LOGIN_CHANGED", "account or authorization attempt changed")
			}
			if r.Prepared == nil {
				prepared, err := client.PreparePersonal(ctx, *r.Authorization)
				if err != nil {
					return err
				}
				r.Prepared = &prepared
				if err = s.save(ctx, owner, id, flowID, r); err != nil {
					return err
				}
			}
			if !r.Prepared.PATExpiresAt.After(time.Now().Add(time.Minute)) {
				refreshed, err := client.Renew(ctx, *r.Prepared, true)
				if err != nil {
					return err
				}
				r.Prepared = &refreshed
				if err = s.save(ctx, owner, id, flowID, r); err != nil {
					return err
				}
			}
			next, err := s.provider.codec.Credentials(id, *r.Prepared)
			if err != nil {
				return err
			}
			next = MergeCredentials(fresh.Credentials, next)
			clearZCodeRetry(next)
			delete(next, "zcode_login_id")
			delete(next, "zcode_pending")
			next["zcode_login_completed"] = flowID
			store, ok := s.provider.repo.(ZCodeLoginRepository)
			if !ok {
				return loginError("ZCODE_LOGIN_STORAGE", "login completion storage is unavailable")
			}
			applied, err := store.CompleteZCodeLoginIfUnchanged(ctx, id, fresh.Credentials, fresh.ProxyID, next)
			if err != nil || !applied {
				return loginError("ZCODE_LOGIN_CHANGED", "account changed while completing authorization; retry status")
			}
			s.provider.InvalidateSigningKey(id)
			r.Completed = true
			r.Prepared = nil
			r.Authorization = nil
			r.PollingSecret = ""
			r.Flow.PollingSecret = ""
			view.Status = "ready"
			return s.save(ctx, owner, id, flowID, r)
		})
	})
	return view, err
}

func (s *ZCodeLoginService) Cancel(ctx context.Context, owner, id int64, flowID string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.account(ctx, owner, id); err != nil {
		return err
	}
	return s.withLease(ctx, "zcode-login:"+loginStoreKey(owner, id, flowID), func() error {
		if _, err := s.read(ctx, owner, id, flowID); err != nil {
			return err
		}
		a, err := s.account(ctx, owner, id)
		if err != nil {
			return err
		}
		if a.GetCredential("zcode_login_id") == flowID {
			store, ok := s.provider.repo.(ZCodeCredentialRepository)
			if !ok {
				return loginError("ZCODE_LOGIN_STORAGE", "conditional account storage is unavailable")
			}
			next := shallowCopyMap(a.Credentials)
			delete(next, "zcode_login_id")
			applied, err := store.UpdateZCodeCredentialsIfUnchanged(ctx, id, a.Credentials, a.ProxyID, next)
			if err != nil || !applied {
				return loginError("ZCODE_LOGIN_CHANGED", "account changed; retry cancellation")
			}
		}
		if err = s.store.Delete(ctx, loginStoreKey(owner, id, flowID)); err != nil {
			return loginError("ZCODE_LOGIN_STORAGE", "cannot clear login session")
		}
		return nil
	})
}

package service

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
	"github.com/Wei-Shaw/sub2api/internal/pkg/zcode"
	"golang.org/x/sync/singleflight"
)

// Ownership-aware release is required: a late caller must never delete a newer
// worker's lease after its own lease has expired.
type ZCodeRefreshLease interface {
	Acquire(ctx context.Context, key string, ttl time.Duration) (release func(context.Context) error, acquired bool, err error)
}

type ZCodeCredentialRepository interface {
	UpdateZCodeCredentialsIfUnchanged(ctx context.Context, id int64, expected map[string]any, proxyID *int64, next map[string]any) (bool, error)
}

type zcodeKeyEntry struct {
	key         ed25519.PrivateKey
	fingerprint [32]byte
	used        time.Time
}
type ZCodeTokenProvider struct {
	repo       AccountRepository
	proxyRepo  ProxyRepository
	lease      ZCodeRefreshLease
	codec      *ZCodeSessionCodec
	configErr  error
	clientFor  func(context.Context, *Account) (*zcode.Client, error)
	mu         sync.Mutex
	keys       map[int64]zcodeKeyEntry
	handshakes singleflight.Group
}

func NewZCodeTokenProvider(repo AccountRepository, proxyRepo ProxyRepository, lease ZCodeRefreshLease, cfg *config.Config) *ZCodeTokenProvider {
	codec, err := NewZCodeSessionCodec(cfg)
	p := &ZCodeTokenProvider{repo: repo, proxyRepo: proxyRepo, lease: lease, codec: codec, configErr: err, keys: make(map[int64]zcodeKeyEntry)}
	p.clientFor = p.protocolClient
	return p
}

func (p *ZCodeTokenProvider) protocolClient(ctx context.Context, a *Account) (*zcode.Client, error) {
	proxyURL := ""
	if a.ProxyID != nil {
		if p.proxyRepo == nil {
			return nil, errors.New("zcode: configured proxy repository is unavailable")
		}
		proxy, err := p.proxyRepo.GetByID(ctx, *a.ProxyID)
		if err != nil || proxy == nil || !proxy.IsActive() || proxy.IsExpired(time.Now()) {
			return nil, errors.New("zcode: configured proxy is unavailable")
		}
		proxyURL = proxy.URL()
	}
	h, err := httpclient.GetClient(httpclient.Options{ProxyURL: proxyURL, Timeout: 30 * time.Second, ValidateResolvedIP: true})
	if err != nil {
		return nil, errors.New("zcode: cannot configure upstream transport")
	}
	return zcode.NewClient(h), nil
}

func sameZCodeProxy(a, b *int64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (p *ZCodeTokenProvider) load(ctx context.Context, selected *Account) (*Account, zcode.Session, error) {
	if p == nil || p.repo == nil || p.configErr != nil || p.codec == nil {
		return nil, zcode.Session{}, errors.New("zcode: credential provider is not configured")
	}
	if !selected.IsZCodeOAuth() {
		return nil, zcode.Session{}, errors.New("zcode: wrong account type")
	}
	fresh, err := p.repo.GetByID(ctx, selected.ID)
	if err != nil {
		return nil, zcode.Session{}, errors.New("zcode: cannot read current account")
	}
	if fresh == nil || fresh.ID != selected.ID || !fresh.IsZCodeOAuth() || !fresh.IsActive() || !sameZCodeProxy(fresh.ProxyID, selected.ProxyID) {
		return nil, zcode.Session{}, errors.New("zcode: account changed or disabled")
	}
	session, err := p.codec.Session(fresh)
	return fresh, session, err
}

func (p *ZCodeTokenProvider) GetAccessToken(ctx context.Context, selected *Account) (string, error) {
	_, session, err := p.current(ctx, selected, false)
	if err != nil {
		return "", err
	}
	return session.PAT, nil
}

func (p *ZCodeTokenProvider) current(ctx context.Context, selected *Account, force bool) (*Account, zcode.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		fresh, session, err := p.load(ctx, selected)
		if err != nil {
			return nil, zcode.Session{}, err
		}
		if !force && session.PAT != "" && time.Until(session.PATExpiresAt) > 3*time.Minute {
			return fresh, session, nil
		}
		if zcodeRetryPending(fresh) {
			return nil, zcode.Session{}, errors.New("zcode: credential renewal is waiting for retry")
		}
		if p.lease == nil {
			return nil, zcode.Session{}, errors.New("zcode: refresh coordination is not configured")
		}
		release, acquired, err := p.lease.Acquire(ctx, "zcode:"+strconv.FormatInt(selected.ID, 10), time.Minute)
		if err != nil {
			return nil, zcode.Session{}, errors.New("zcode: refresh coordination unavailable")
		}
		if acquired {
			if release == nil {
				return nil, zcode.Session{}, errors.New("zcode: refresh lease has no owner")
			}
			func() {
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = release(cleanup)
				}()
				fresh, session, err = p.renewLocked(ctx, selected, force)
			}()
			return fresh, session, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, zcode.Session{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *ZCodeTokenProvider) renewLocked(ctx context.Context, selected *Account, force bool) (*Account, zcode.Session, error) {
	fresh, session, err := p.load(ctx, selected)
	if err != nil {
		return nil, zcode.Session{}, err
	}
	if !force && session.PAT != "" && time.Until(session.PATExpiresAt) > 3*time.Minute {
		return fresh, session, nil
	}
	if zcodeRetryPending(fresh) {
		return nil, zcode.Session{}, errors.New("zcode: credential renewal is waiting for retry")
	}
	store, ok := p.repo.(ZCodeCredentialRepository)
	if !ok {
		return nil, zcode.Session{}, errors.New("zcode: conditional credential persistence is unavailable")
	}
	client, err := p.clientFor(ctx, fresh)
	if err != nil {
		return nil, zcode.Session{}, err
	}
	renewed, err := client.Renew(ctx, session, true)
	if err != nil {
		p.recordRenewalFailure(ctx, fresh, err)
		return nil, zcode.Session{}, err
	}
	next, err := p.codec.Credentials(fresh.ID, renewed)
	if err != nil {
		return nil, zcode.Session{}, err
	}
	next = MergeCredentials(fresh.Credentials, next)
	clearZCodeRetry(next)
	next["_token_version"] = time.Now().UnixMilli()
	applied, err := store.UpdateZCodeCredentialsIfUnchanged(ctx, fresh.ID, fresh.Credentials, fresh.ProxyID, next)
	if err != nil {
		return nil, zcode.Session{}, errors.New("zcode: cannot persist renewed credentials")
	}
	if !applied {
		return nil, zcode.Session{}, errors.New("zcode: authorization changed during renewal")
	}
	p.InvalidateSigningKey(fresh.ID)
	// Read durable state again so a concurrent revocation or reauthorization is
	// never overwritten by the older in-memory session returned by the upstream.
	durable, current, err := p.load(ctx, selected)
	if err != nil {
		return nil, zcode.Session{}, err
	}
	if current.PAT == "" || !current.PATExpiresAt.After(time.Now()) {
		return nil, zcode.Session{}, errors.New("zcode: durable project token is expired")
	}
	return durable, current, nil
}

func (p *ZCodeTokenProvider) InvalidateSigningKey(id int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.keys[id]; ok {
		clear(e.key)
		delete(p.keys, id)
	}
}

// Sign never trusts a caller-supplied bearer without checking the current durable
// account. A copied key is used outside the cache lock to avoid zeroing races.
func (p *ZCodeTokenProvider) Sign(ctx context.Context, a *Account, req *http.Request, token, sessionID string) error {
	fresh, session, err := p.load(ctx, a)
	if err != nil {
		return err
	}
	if token == "" || token != session.PAT || !session.PATExpiresAt.After(time.Now()) {
		return errors.New("zcode: project credential changed before signing")
	}
	credential, err := zcode.ParseCredential(token)
	if err != nil {
		return err
	}
	proxyScope := "direct"
	if fresh.ProxyID != nil {
		proxyScope = strconv.FormatInt(*fresh.ProxyID, 10)
	}
	fingerprint := sha256.Sum256([]byte(token + "\n" + proxyScope))
	key, err := p.signingKey(ctx, fresh, credential, fingerprint)
	if err != nil {
		return err
	}
	defer clear(key)
	// Handshake may take seconds; check the account once more before model send.
	_, latest, err := p.load(ctx, a)
	if err != nil {
		return err
	}
	if latest.PAT != token {
		return errors.New("zcode: credential changed during signing handshake")
	}
	if err = zcode.SignRequest(req, credential, key, sessionID, time.Now()); err != nil {
		return err
	}
	for name := range req.Header {
		if stringsEqualAuthHeader(name) {
			delete(req.Header, name)
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Api-Key", token)
	return nil
}

func stringsEqualAuthHeader(s string) bool {
	return http.CanonicalHeaderKey(s) == "Authorization" || http.CanonicalHeaderKey(s) == "X-Api-Key" || http.CanonicalHeaderKey(s) == "Cookie" || http.CanonicalHeaderKey(s) == "X-Goog-Api-Key"
}

func (p *ZCodeTokenProvider) signingKey(ctx context.Context, a *Account, c zcode.Credential, fingerprint [32]byte) (ed25519.PrivateKey, error) {
	p.mu.Lock()
	if e, ok := p.keys[a.ID]; ok && e.fingerprint == fingerprint {
		key := append(ed25519.PrivateKey(nil), e.key...)
		p.mu.Unlock()
		return key, nil
	}
	p.mu.Unlock()
	// Singleflight's result is only a completion signal; key slices are copied
	// under the mutex for each waiter, never shared and zeroed concurrently.
	result := p.handshakes.DoChan(fmt.Sprintf("%d:%x", a.ID, fingerprint), func() (any, error) {
		client, err := p.clientFor(ctx, a)
		if err != nil {
			return nil, err
		}
		key, err := client.SigningKey(ctx, c)
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if old, ok := p.keys[a.ID]; ok {
			clear(old.key)
		}
		if len(p.keys) >= 256 {
			var oldestID int64
			var oldest time.Time
			for id, e := range p.keys {
				if oldest.IsZero() || e.used.Before(oldest) {
					oldestID = id
					oldest = e.used
				}
			}
			e := p.keys[oldestID]
			clear(e.key)
			delete(p.keys, oldestID)
		}
		p.keys[a.ID] = zcodeKeyEntry{key: key, fingerprint: fingerprint, used: time.Now()}
		return nil, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return nil, r.Err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.keys[a.ID]
	if !ok || e.fingerprint != fingerprint {
		return nil, errors.New("zcode: signing scope changed")
	}
	return append(ed25519.PrivateKey(nil), e.key...), nil
}

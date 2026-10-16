package repository

import (
	"context"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type zcodeRefreshLease struct{ rdb *redis.Client }

func NewZCodeRefreshLease(rdb *redis.Client) service.ZCodeRefreshLease {
	return &zcodeRefreshLease{rdb: rdb}
}

func (l *zcodeRefreshLease) Acquire(ctx context.Context, key string, ttl time.Duration) (func(context.Context) error, bool, error) {
	if l == nil || l.rdb == nil {
		return nil, false, errors.New("zcode: lease store unavailable")
	}
	key = "oauth:zcode:lease:" + key
	owner := uuid.NewString()
	ok, err := l.rdb.SetNX(ctx, key, owner, ttl).Result()
	if err != nil || !ok {
		return nil, false, err
	}
	return func(ctx context.Context) error {
		return l.rdb.Eval(ctx, `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`, []string{key}, owner).Err()
	}, true, nil
}

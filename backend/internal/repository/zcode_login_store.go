package repository

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

type zcodeLoginStore struct{ rdb *redis.Client }

func NewZCodeLoginStore(rdb *redis.Client) service.ZCodeLoginStore { return &zcodeLoginStore{rdb: rdb} }
func (s *zcodeLoginStore) Get(ctx context.Context, key string) (string, error) {
	return s.rdb.Get(ctx, "oauth:zcode:login:"+key).Result()
}
func (s *zcodeLoginStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.rdb.Set(ctx, "oauth:zcode:login:"+key, value, ttl).Err()
}
func (s *zcodeLoginStore) Delete(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, "oauth:zcode:login:"+key).Err()
}

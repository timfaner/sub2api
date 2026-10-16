package repository

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestZCodeExpiredLeaseCannotReleaseNewOwner(t *testing.T) {
	r := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: r.Addr()})
	defer client.Close()
	l := NewZCodeRefreshLease(client)
	ctx := context.Background()
	oldRelease, ok, err := l.Acquire(ctx, "account", time.Minute)
	if err != nil || !ok {
		t.Fatal("acquire failed", err)
	}
	if _, ok, err = l.Acquire(ctx, "account", time.Minute); err != nil || ok {
		t.Fatal("duplicate lease")
	}
	r.FastForward(2 * time.Minute)
	newRelease, ok, err := l.Acquire(ctx, "account", time.Minute)
	if err != nil || !ok {
		t.Fatal("new owner failed", err)
	}
	if err = oldRelease(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err = l.Acquire(ctx, "account", time.Minute); err != nil || ok {
		t.Fatal("old release erased newer owner")
	}
	if err = newRelease(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err = l.Acquire(ctx, "account", time.Minute); err != nil || !ok {
		t.Fatal("owner release failed")
	}
}

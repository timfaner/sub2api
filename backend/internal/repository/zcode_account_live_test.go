package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// This opt-in test exercises the actual PostgreSQL statement in a disposable
// schema. It never migrates or truncates existing application tables.
func TestZCodePostgresCredentialCAS(t *testing.T) {
	dsn := os.Getenv("SUB2API_ZCODE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SUB2API_ZCODE_TEST_DATABASE_URL to run real PostgreSQL verification")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	ctx := context.Background()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, admin.Close()) }()
	schema := "zcode_test_" + uuid.New().String()[:8]
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	defer func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	_, err = db.ExecContext(ctx, `CREATE TABLE accounts (
 id bigint PRIMARY KEY, credentials jsonb NOT NULL, proxy_id bigint,
 platform text NOT NULL DEFAULT 'zhipu', type text NOT NULL DEFAULT 'oauth',
 status text NOT NULL DEFAULT 'active', deleted_at timestamptz,
 updated_at timestamptz DEFAULT NOW(), schedulable boolean NOT NULL DEFAULT false);
 CREATE TABLE scheduler_outbox (id bigserial PRIMARY KEY,event_type text NOT NULL,
 account_id bigint,group_id bigint,payload jsonb)`)
	require.NoError(t, err)
	repo := &accountRepository{sql: db}
	initial := map[string]any{"auth_method": "zcode", "zcode_pending": true}
	next := map[string]any{"auth_method": "zcode", "zcode_session": "encrypted-new-session"}
	reset := func() {
		_, err := db.ExecContext(ctx, "TRUNCATE accounts,scheduler_outbox")
		require.NoError(t, err)
		b, _ := json.Marshal(initial)
		_, err = db.ExecContext(ctx, "INSERT INTO accounts(id,credentials) VALUES (1,$1::jsonb)", string(b))
		require.NoError(t, err)
	}
	t.Run("only one concurrent completion wins", func(t *testing.T) {
		reset()
		var wg sync.WaitGroup
		results := make(chan bool, 2)
		failures := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, e := repo.CompleteZCodeLoginIfUnchanged(ctx, 1, initial, nil, next)
				results <- ok
				failures <- e
			}()
		}
		wg.Wait()
		close(results)
		close(failures)
		wins := 0
		for ok := range results {
			if ok {
				wins++
			}
		}
		for e := range failures {
			require.NoError(t, e)
		}
		require.Equal(t, 1, wins)
		var enabled bool
		var events int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT schedulable FROM accounts WHERE id=1").Scan(&enabled))
		require.True(t, enabled)
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scheduler_outbox").Scan(&events))
		require.Equal(t, 1, events)
	})
	t.Run("reauthorization preserves operator pause", func(t *testing.T) {
		reset()
		b, _ := json.Marshal(next)
		_, err := db.ExecContext(ctx, "UPDATE accounts SET credentials=$1::jsonb", string(b))
		require.NoError(t, err)
		replacement := map[string]any{"auth_method": "zcode", "zcode_session": "encrypted-replacement"}
		ok, err := repo.CompleteZCodeLoginIfUnchanged(ctx, 1, next, nil, replacement)
		require.NoError(t, err)
		require.True(t, ok)
		var enabled bool
		require.NoError(t, db.QueryRowContext(ctx, "SELECT schedulable FROM accounts WHERE id=1").Scan(&enabled))
		require.False(t, enabled)
	})
	for name, change := range map[string]string{
		"proxy changed": "UPDATE accounts SET proxy_id=9",
		"disabled":      "UPDATE accounts SET status='disabled'",
		"newer login":   "UPDATE accounts SET credentials=credentials || '{\"zcode_login_id\":\"new-flow\"}'::jsonb",
		"deleted":       "UPDATE accounts SET deleted_at=NOW()",
	} {
		t.Run(name, func(t *testing.T) {
			reset()
			_, err := db.ExecContext(ctx, change)
			require.NoError(t, err)
			ok, err := repo.UpdateZCodeCredentialsIfUnchanged(ctx, 1, initial, nil, next)
			require.NoError(t, err)
			require.False(t, ok)
			var events int
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scheduler_outbox").Scan(&events))
			require.Zero(t, events)
		})
	}
	t.Run("outbox failure rolls back credentials", func(t *testing.T) {
		reset()
		_, err := db.ExecContext(ctx, "ALTER TABLE scheduler_outbox ADD CONSTRAINT reject_event CHECK (account_id < 0)")
		require.NoError(t, err)
		defer func() {
			_, err := db.ExecContext(ctx, "ALTER TABLE scheduler_outbox DROP CONSTRAINT reject_event")
			require.NoError(t, err)
		}()
		ok, err := repo.CompleteZCodeLoginIfUnchanged(ctx, 1, initial, nil, next)
		require.Error(t, err)
		require.False(t, ok)
		var pending, enabled bool
		require.NoError(t, db.QueryRowContext(ctx, "SELECT (credentials->>'zcode_pending')::boolean,schedulable FROM accounts WHERE id=1").Scan(&pending, &enabled))
		require.True(t, pending)
		require.False(t, enabled)
	})
}

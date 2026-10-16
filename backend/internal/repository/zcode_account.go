package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Publish the credential replacement and scheduler invalidation atomically.
// A stale refresh may not overwrite a new login, proxy change or account disable.
func (r *accountRepository) UpdateZCodeCredentialsIfUnchanged(ctx context.Context, id int64, expected map[string]any, proxyID *int64, next map[string]any) (bool, error) {
	return r.updateZCodeCredentials(ctx, id, expected, proxyID, next, false)
}

func (r *accountRepository) CompleteZCodeLoginIfUnchanged(ctx context.Context, id int64, expected map[string]any, proxyID *int64, next map[string]any) (bool, error) {
	return r.updateZCodeCredentials(ctx, id, expected, proxyID, next, true)
}

func (r *accountRepository) updateZCodeCredentials(ctx context.Context, id int64, expected map[string]any, proxyID *int64, next map[string]any, complete bool) (bool, error) {
	if r == nil || r.sql == nil {
		return false, errors.New("zcode: credential repository unavailable")
	}
	before, err := json.Marshal(normalizeJSONMap(expected))
	if err != nil {
		return false, err
	}
	after, err := json.Marshal(normalizeJSONMap(next))
	if err != nil {
		return false, err
	}
	result, err := r.sql.ExecContext(ctx, `
	WITH updated AS (
	 UPDATE accounts SET credentials=$1::jsonb, updated_at=NOW(),
     schedulable=CASE WHEN $8 AND credentials->>'zcode_pending'='true' THEN TRUE ELSE schedulable END
	 WHERE id=$2 AND deleted_at IS NULL AND platform=$3 AND type=$4
	 AND status='active' AND credentials->>'auth_method'='zcode'
	 AND credentials=$5::jsonb AND proxy_id IS NOT DISTINCT FROM $6
	 RETURNING id
	)
	INSERT INTO scheduler_outbox (event_type,account_id,group_id,payload)
	SELECT $7,id,NULL,NULL FROM updated`, string(after), id, service.PlatformZhipu, service.AccountTypeOAuth, string(before), proxyID, service.SchedulerOutboxEventAccountChanged, complete)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, id)
	return true, nil
}

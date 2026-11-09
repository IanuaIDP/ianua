-- The one channel of one account of one tenant.
SELECT id, account_id, integration, secret_sealed, setup, status, remote, lapses_at,
    history_cursor, created_at, updated_at
FROM workflow_account_channels
WHERE tenant_id = $1 AND account_id = $2

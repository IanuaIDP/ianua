-- One channel of one tenant, by the id its address names.
SELECT id, account_id, integration, secret_sealed, setup, status, remote, lapses_at,
    history_cursor, created_at, updated_at
FROM workflow_account_channels
WHERE tenant_id = $1 AND id = $2

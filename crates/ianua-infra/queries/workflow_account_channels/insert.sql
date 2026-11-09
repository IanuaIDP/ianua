-- Keeps a new channel, unless its account already has one, so two publishes
-- at once make one.
INSERT INTO workflow_account_channels
    (id, tenant_id, account_id, integration, secret_sealed, setup, status, remote, lapses_at,
     history_cursor, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, account_id) DO NOTHING

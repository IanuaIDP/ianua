-- Saves a change to one channel already kept.
UPDATE workflow_account_channels SET
    secret_sealed = $3,
    status = $4,
    remote = $5,
    lapses_at = $6,
    history_cursor = $7,
    updated_at = $8
WHERE tenant_id = $1 AND id = $2

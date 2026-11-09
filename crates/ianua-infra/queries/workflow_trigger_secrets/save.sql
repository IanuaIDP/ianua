-- Keeps a webhook secret: a new one is added, a known one takes its new
-- digest and who replaced it. Its workflow and when it was first issued
-- never change. Another secret of the same workflow refuses it.
INSERT INTO workflow_trigger_secrets
    (id, tenant_id, workflow_id, secret_hash, issued_by, created_at, secret_changed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    secret_hash = EXCLUDED.secret_hash,
    issued_by = EXCLUDED.issued_by,
    secret_changed_at = EXCLUDED.secret_changed_at
WHERE workflow_trigger_secrets.tenant_id = EXCLUDED.tenant_id

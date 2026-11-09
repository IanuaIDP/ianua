-- Keeps a webhook subscription: a new one is added, a known one of the
-- same tenant takes the new values. Its tenant, its maker and its creation
-- time never change.
INSERT INTO webhook_subscriptions
    (id, tenant_id, url, signing_secret_sealed, previous_secret_sealed, previous_secret_until,
     event_types, status, description, retry, created_by_kind, created_by_id,
     consecutive_failures, last_delivered_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (id) DO UPDATE SET
    url = EXCLUDED.url,
    signing_secret_sealed = EXCLUDED.signing_secret_sealed,
    previous_secret_sealed = EXCLUDED.previous_secret_sealed,
    previous_secret_until = EXCLUDED.previous_secret_until,
    event_types = EXCLUDED.event_types,
    status = EXCLUDED.status,
    description = EXCLUDED.description,
    retry = EXCLUDED.retry,
    consecutive_failures = EXCLUDED.consecutive_failures,
    last_delivered_at = EXCLUDED.last_delivered_at,
    updated_at = EXCLUDED.updated_at
WHERE webhook_subscriptions.tenant_id = EXCLUDED.tenant_id

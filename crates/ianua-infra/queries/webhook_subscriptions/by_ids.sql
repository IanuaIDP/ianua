-- The webhook subscriptions of a tenant with the given ids.
SELECT id, url, signing_secret_sealed, previous_secret_sealed, previous_secret_until,
       event_types, status, description, retry, created_by_kind, created_by_id,
       consecutive_failures, last_delivered_at, created_at, updated_at
FROM webhook_subscriptions
WHERE tenant_id = $1 AND id = ANY($2)

-- The active webhook subscriptions of a tenant that list the given event
-- type, oldest first. A tenant holds few webhooks, so the active ones are
-- read by status and their lists checked.
SELECT id, url, signing_secret_sealed, previous_secret_sealed, previous_secret_until,
       event_types, status, description, retry, created_by_kind, created_by_id,
       consecutive_failures, last_delivered_at, created_at, updated_at
FROM webhook_subscriptions
WHERE tenant_id = $1 AND status = 'active' AND $2::text = ANY(event_types)
ORDER BY created_at, id

-- Keeps the body of a message sent to a webhook subscription of the
-- tenant. Keeping one already kept under its id changes nothing, and a
-- subscription that is gone, or another tenant's, keeps nothing.
INSERT INTO webhook_messages (id, tenant_id, subscription_id, event_type, payload)
SELECT $3::uuid, subscription.tenant_id, subscription.id, $4::text, $5::bytea
FROM webhook_subscriptions subscription
WHERE subscription.tenant_id = $1 AND subscription.id = $2
ON CONFLICT (id) DO NOTHING

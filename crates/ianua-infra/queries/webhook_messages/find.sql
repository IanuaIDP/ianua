-- One message kept for a webhook subscription of a tenant.
SELECT id, subscription_id, event_type, payload
FROM webhook_messages
WHERE tenant_id = $1 AND subscription_id = $2 AND id = $3

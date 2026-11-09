-- One try at sending a message to a webhook subscription of a tenant.
SELECT id, subscription_id, message_id, event_type, status, response_code, duration_ms,
       attempt_number, attempted_at
FROM webhook_deliveries
WHERE tenant_id = $1 AND subscription_id = $2 AND id = $3

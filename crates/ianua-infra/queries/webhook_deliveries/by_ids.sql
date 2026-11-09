-- The tries at sending webhook messages of a tenant with the given ids.
SELECT id, subscription_id, message_id, event_type, status, response_code, duration_ms,
       attempt_number, attempted_at
FROM webhook_deliveries
WHERE tenant_id = $1 AND id = ANY($2)

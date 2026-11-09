-- The signal deliveries of a tenant with the given ids.
SELECT id, stream_id, signal_id, signal_type, status, response_code, duration_ms,
       attempt_number, attempted_at
FROM signal_deliveries
WHERE tenant_id = $1 AND id = ANY($2)

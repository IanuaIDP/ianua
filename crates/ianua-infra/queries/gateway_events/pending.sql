-- The oldest events in the gateway's inbox, as the gateway sealed them,
-- locked for this drain; another drain passes over them.
SELECT id, tenant_id, event_type, subject, payload, seal
FROM gateway_events
ORDER BY written_at, id
LIMIT $1
FOR UPDATE SKIP LOCKED

-- The tenant's audit stream with the given id.
SELECT id, name, destination, events, state, state_since, failures, pause_reason, created_at,
       updated_at
FROM audit_streams
WHERE tenant_id = $1 AND id = $2

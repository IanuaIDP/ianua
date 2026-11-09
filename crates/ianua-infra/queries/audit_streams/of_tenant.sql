-- Every audit stream of the tenant, oldest first.
SELECT id, name, destination, events, state, state_since, failures, pause_reason, created_at,
       updated_at
FROM audit_streams
WHERE tenant_id = $1
ORDER BY created_at, id

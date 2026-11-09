-- The delegation requests one agent of a tenant made, newest first,
-- answered or not.
SELECT id, agent_id, asked_of_kind, asked_of_id, asked_of_person, granted, limits, reason,
       state, delegation_id, decided_at, created_at, expires_at, updated_at
FROM delegation_requests
WHERE tenant_id = $1 AND agent_id = $2
ORDER BY created_at DESC, id DESC

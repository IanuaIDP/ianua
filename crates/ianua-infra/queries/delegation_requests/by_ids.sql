-- The delegation requests of a tenant with the given ids.
SELECT id, agent_id, asked_of_kind, asked_of_id, asked_of_person, granted, limits, reason,
       state, delegation_id, decided_at, created_at, expires_at, updated_at
FROM delegation_requests
WHERE tenant_id = $1 AND id = ANY($2)

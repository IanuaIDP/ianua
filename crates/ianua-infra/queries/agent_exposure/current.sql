-- The mark of one agent of a tenant, if it has touched anything.
SELECT level
FROM agent_exposure
WHERE tenant_id = $1 AND agent_id = $2

-- The names of a tenant's agents with the given ids, for the audit trail to name them by.
SELECT id, name
FROM agents
WHERE tenant_id = $1 AND id = ANY($2)

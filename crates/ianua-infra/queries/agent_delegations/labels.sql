-- The names of a tenant's delegations with the given ids, where they were given one, for the audit trail to name them by.
SELECT id, name
FROM agent_delegations
WHERE tenant_id = $1 AND id = ANY($2)

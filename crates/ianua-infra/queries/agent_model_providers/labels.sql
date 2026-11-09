-- The names of a tenant's model providers with the given ids, for the audit trail to name them by.
SELECT id, name
FROM agent_model_providers
WHERE tenant_id = $1 AND id = ANY($2)

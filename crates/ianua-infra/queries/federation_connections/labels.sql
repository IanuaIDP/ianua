-- The provider names of a tenant's federation connections with the given ids, for the audit trail to name them by.
SELECT id, provider_name AS name
FROM federation_connections
WHERE tenant_id = $1 AND id = ANY($2)

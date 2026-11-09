-- The names of a tenant's OAuth clients with the given ids, for the audit trail to name them by.
SELECT id, name
FROM oauth_clients
WHERE tenant_id = $1 AND id = ANY($2)

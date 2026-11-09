-- The names of a tenant's roles with the given ids, for the audit trail to name them by.
SELECT id, name
FROM roles
WHERE tenant_id = $1 AND id = ANY($2)

-- The names of a tenant's groups with the given ids, for the audit trail to name them by.
SELECT id, name
FROM groups
WHERE tenant_id = $1 AND id = ANY($2)

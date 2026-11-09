-- The names of a tenant's consumers with the given ids, for the audit trail to name them by.
SELECT id, name
FROM consumers
WHERE tenant_id = $1 AND id = ANY($2)

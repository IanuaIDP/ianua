-- The names and addresses of a tenant's users with the given ids, for the audit trail to name them by.
SELECT id, display_name, email
FROM users
WHERE tenant_id = $1 AND id = ANY($2)

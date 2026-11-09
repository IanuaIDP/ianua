-- The roles of a tenant with the given ids.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND id = ANY($2)

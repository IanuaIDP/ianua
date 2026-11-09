-- The role of a tenant with the given name.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND name = $2

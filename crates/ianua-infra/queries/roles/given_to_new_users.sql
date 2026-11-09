-- The roles of a tenant every new user gets, oldest first.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND is_default
ORDER BY created_at, id

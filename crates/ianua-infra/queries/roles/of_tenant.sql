-- Every role of a tenant, oldest first.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1
ORDER BY created_at, id

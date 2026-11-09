-- The roles of a tenant holding any of the given built-in permissions: the
-- only roles that can make someone an administrator.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND system_permissions && $2::text[]
ORDER BY created_at, id

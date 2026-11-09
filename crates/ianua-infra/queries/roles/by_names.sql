-- The requested names resolved within one tenant.
SELECT id, name, system_permissions, custom_permissions, is_default, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND name = ANY($2::text[])

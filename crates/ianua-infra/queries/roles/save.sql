-- Keeps a role: a new one is added, a known one takes the new values. Its
-- tenant and creation time never change.
INSERT INTO roles
    (id, tenant_id, name, system_permissions, custom_permissions, is_default,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    system_permissions = EXCLUDED.system_permissions,
    custom_permissions = EXCLUDED.custom_permissions,
    is_default = EXCLUDED.is_default,
    updated_at = EXCLUDED.updated_at
WHERE roles.tenant_id = EXCLUDED.tenant_id

-- Keeps a resource type: a new one is added, a known one takes the new
-- values. Its tenant and creation time never change.
INSERT INTO resource_types
    (id, tenant_id, key, display_name, description, actions, data_class, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    key = EXCLUDED.key,
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    actions = EXCLUDED.actions,
    data_class = EXCLUDED.data_class,
    updated_at = EXCLUDED.updated_at
WHERE resource_types.tenant_id = EXCLUDED.tenant_id

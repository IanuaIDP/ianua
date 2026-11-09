-- Keeps an event schema without its versions: a new one is added, a known
-- one of the same tenant takes the new values. Its tenant, its machine
-- name, its format, its maker and its creation time never change.
INSERT INTO event_schemas
    (id, tenant_id, name, schema_name, description, format, compatibility, created_by_kind,
     created_by_id, created_by_person, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    compatibility = EXCLUDED.compatibility,
    updated_at = EXCLUDED.updated_at
WHERE event_schemas.tenant_id = EXCLUDED.tenant_id

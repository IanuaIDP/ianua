-- The event schema of a tenant with the given machine name, without its
-- versions.
SELECT id, name, schema_name, description, format, compatibility, created_by_kind,
       created_by_id, created_by_person, created_at, updated_at
FROM event_schemas
WHERE tenant_id = $1 AND schema_name = $2

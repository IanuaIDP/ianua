-- The event schemas of a tenant with the given ids, without their
-- versions.
SELECT id, name, schema_name, description, format, compatibility, created_by_kind,
       created_by_id, created_by_person, created_at, updated_at
FROM event_schemas
WHERE tenant_id = $1 AND id = ANY($2)

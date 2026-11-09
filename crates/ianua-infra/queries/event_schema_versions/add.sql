-- Adds new versions to an event schema of a tenant, all in one statement.
-- A published version never changes, so one already kept stays as it is.
INSERT INTO event_schema_versions (tenant_id, schema_id, version, definition, created_at)
SELECT $1, $2, added.version, added.definition, added.created_at
FROM UNNEST($3::bigint[], $4::text[], $5::timestamptz[]) AS added (version, definition, created_at)
ON CONFLICT (tenant_id, schema_id, version) DO NOTHING

-- Every version of the event schemas of a tenant with the given ids, each
-- schema's in the order of its numbers.
SELECT schema_id, version, definition, created_at
FROM event_schema_versions
WHERE tenant_id = $1 AND schema_id = ANY($2)
ORDER BY schema_id, version

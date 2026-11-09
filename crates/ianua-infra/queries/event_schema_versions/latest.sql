-- The number of the latest version an event schema of a tenant holds, or 0
-- for a schema not kept yet.
SELECT coalesce(max(version), 0) AS "latest!"
FROM event_schema_versions
WHERE tenant_id = $1 AND schema_id = $2

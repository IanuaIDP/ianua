-- A clone, by its id.
SELECT id, tenant_id, source_tenant_id, organization_id, parts, copied, state, failure,
       ended_at, started_at
FROM tenant_clones
WHERE id = $1

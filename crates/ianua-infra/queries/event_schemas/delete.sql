-- Removes an event schema of the tenant for good, with every version of
-- it.
DELETE FROM event_schemas
WHERE tenant_id = $1 AND id = $2

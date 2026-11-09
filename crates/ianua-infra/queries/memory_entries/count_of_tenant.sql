-- How many texts one tenant's memories hold together.
SELECT count(*) AS "count!" FROM memory_entries WHERE tenant_id = $1
